/*
	Copyright (c) 2013-2014 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Tabby nor the names of its contributors may be
	  used to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "lyra.h"
#include "blake2.h"
#include "SecureEqual.hpp"

// PBKDF parameters
static const int PBKDF_SALT_SIZE = 16;	// 16 bytes; changing this requires editing code
static const int PBKDF_ROW_SIZE = 64;	// Number of 64-byte hash blocks per matrix row
static const int PBKDF_T_COST = 2;		// Fixed T recommended by Solar Designer
// See: http://www.openwall.com/lists/crypt-dev/2014/01/13/1
static const int PBKDF_M_COST = 3000;	// Number of 4KB rows to allocate => 12MB
// M_cost chosen to take ~100 milliseconds on a modern laptop

// Generate a client secret and server password verifier from account data
// Returns -2 to indicate a recoverable error (read more on that case below)
// Returns other non-zero values on unrecoverable errors
// Returns 0 on success
static int generate_password_verifier(const char salt[PBKDF_SALT_SIZE],
	const void *username, int username_len,
	const void *realm, int realm_len,
	const void *password, int password_len,
	char client_secret[32], char password_verifier[64])
{
	blake2b_state B;

	if (!salt || !username || username_len < 1 ||
		!password || password_len < 1 || !password_verifier) {
		return -1;
	}

	// pw = BLAKE2(username, realm, password)
	char *pw = password_verifier; // Reuse buffer
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)username, username_len)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)" : ", 3)) {
		return -1;
	}
	// Realm is optional
	if (realm && realm_len > 0) {
		if (blake2b_update(&B, (const u8 *)realm, realm_len)) {
			return -1;
		}
		if (blake2b_update(&B, (const u8 *)" : ", 3)) {
			return -1;
		}
	}
	if (blake2b_update(&B, (const u8 *)password, password_len)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)pw, 64)) {
		return -1;
	}

	// Erase hash state
	CAT_SECURE_OBJCLR(B);

	// v = Lyra(salt, pw)
	char *v = password_verifier;
	if (lyra((u8 *)pw, 64, (const u8 *)salt, PBKDF_SALT_SIZE,
			 PBKDF_T_COST, PBKDF_ROW_SIZE, PBKDF_M_COST, 64, (u8 *)v)) {
		return -1;
	}

	// v = v (mod q) for uniform distribution
	snowshoe_mod_q(v, v);

	// If client secret is requested,
	if (client_secret) {
		// Copy it out
		memcpy(client_secret, v, 32);
	}

	// password_verifier = vG
	if (snowshoe_mul_gen(v, password_verifier, 0)) {
		// This is a recoverable error - Simply change the salt and try again.
		// However this is so unlikely that it may never ever actually happen.
		// Caller can check for this and try again.
		return -2;
	}

	return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

/*
	tabby_password(
		C,
		username, username_len,
		realm, realm_len,
		password, password_len,
		password_verifier [OUT])

	This function generates a random salt from the CSPRNG, then proceeds to
	securely hash the username, realm, password, and salt together with a
	password-based key derivation function (PBKDF).

	The output is the password_verifier.

	Packed data formats:

		Outputs:

			password_verifier	[80 bytes]
				V = vG			[64 bytes]
				Salt			[16 bytes]
*/

int tabby_password(tabby_client *C, const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, char password_verifier[80]) {
	client_internal *state = (client_internal *)C;

	char salt[PBKDF_SALT_SIZE];

	// If input is invalid,
	if (!C || !username || username_len < 1 ||
		!password || password_len < 1 || !password_verifier) {
		return -1;
	}

	int error;
	do {
		// Choose a new salt
		if (cymric_random(&state->rng, salt, PBKDF_SALT_SIZE)) {
			return -1;
		}

		// Attempt to generate a verifier from the input.
		// This can fail in some very rare cases, and sometimes the reaction
		// should be to generate a new salt and try again.
		error = generate_password_verifier(salt,
					username, username_len,
					realm, realm_len, // These can be 0 to skip the realm hash
					password, password_len,
					0, // Pass in 0 for client_secret - it is not needed
					password_verifier);

		// If unrecoverable error,
		if (error == -1) {
			return -1;
		}

		// Loop while recoverable
	} while (error == -2);

	// Copy salt to end of password verifier
	memcpy(password_verifier + 64, salt, PBKDF_SALT_SIZE);

	return 0;
}

/*
	tabby_password_challenge(
		S,
		password_verifier [IN],
		challenge_secret [OUT],
		challenge [OUT])

	After the user has sent his username, the server runs this function
	to generate a password authentication challenge that the user must
	answer before being allowed access to the server.

	It generates a "challenge_secret" that is stored internally to the
	server to process the client's response to the challenge.  This
	must not be shared with the client.

	It also generates a "challenge" that should be sent to the client.

	If the client fails to login, then the server should run this function
	again rather than caching the results and reusing them.

	Packed data formats:

		Inputs:

			password_verifier	[80 bytes]
				V = vG			[64 bytes]
				Salt			[16 bytes]

		Outputs:

			challenge_secret	[288 bytes]
				E (extended)	[128 bytes]
				x				[32 bytes]
				V				[64 bytes]
				X' = X + E		[64 bytes]

			challenge			[80 bytes]
				X'				[64 bytes]
				Salt			[16 bytes]
*/

int tabby_password_challenge(tabby_server *S, const char password_verifier[80], char challenge_secret[288], char challenge[80]) {
	server_internal *state = (server_internal *)S;

	// If invalid input,
	if (!S || !password_verifier || !challenge_secret || !challenge) {
		return -1;
	}

	// e = BLAKE2(V, salt)
	char *e = challenge_secret;
	if (blake2b((u8 *)e, password_verifier, 0, 32, 72, 0)) {
		return -1;
	}

	// E = Elligator(e)
	char *E = challenge_secret;
	if (snowshoe_elligator(e, E)) {
		return -1;
	}

	// X' = xG + E
	char *Xp = challenge_secret + 224;
	char *x = challenge_secret + 128;
	do {
		// Chose a random 512-bit x
		if (cymric_random(&state->rng, x, 64)) {
			return -1;
		}

		// x = x (mod q) for uniform distribution
		snowshoe_mod_q(x, x);

		// Retry while resulting point is invalid
	} while (snowshoe_elligator_encrypt(x, E, Xp));

	// Store V
	char *V = challenge_secret + 160;
	memcpy(V, password_verifier, 64);

	// Generate challenge
	const char *salt = password_verifier + 64;
	memcpy(challenge, Xp, 64);
	memcpy(challenge + 64, salt, PBKDF_SALT_SIZE);

	return 0;
}

/*
	tabby_password_client_proof(
		C,
		username, username_len,
		realm, realm_len,
		password, password_len,
		challenge [IN],
		server_public [IN],
		server_verifier [OUT],
		client_proof [OUT])

	Now that the server has provided a challenge the client must answer with
	a proof of knowledge of the password.  This function will hash the password
	similar to tabby_password(), except that the salt is provided as part of
	the server's challenge.

	Packed data formats:

		Inputs:

			challenge			[80 bytes]
				X'				[64 bytes]
				Salt			[16 bytes]

			server_public		[64 bytes]
				SP = Server's Public Key

		Outputs:

			client_proof		[96 bytes]
				Y' = Y + E		[64 bytes]
				CPROOF			[32 bytes]

			server_verifier		[32 bytes]
				SPROOF			[32 bytes]
*/

int tabby_password_client_proof(tabby_client *C, const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, const char challenge[80], const char server_public[64], char server_verifier[32], char client_proof[96]) {
	client_internal *state = (client_internal *)C;

	char E[128 + 64 + 64];
	blake2b_state B;

	// If invalid input,
	if (!C || !username || username_len < 1 || !password || password_len < 1 ||
		!challenge || !server_public || !server_verifier || !client_proof) {
		return -1;
	}

	// Generate client secret and password verifier from account data
	const char *salt = challenge + 64;
	char *client_secret = E + 128 + 64;
	char *password_verifier = E;

	// Note that the "recoverable" error should never happen here, so any error is a failure
	if (generate_password_verifier(salt,
					username, username_len,
					realm, realm_len, // These can be 0 to skip the realm hash
					password, password_len,
					client_secret, password_verifier)) {
		return -1;
	}

	// Set salt in verifier
	memcpy(password_verifier + 64, salt, PBKDF_SALT_SIZE);

	// e = BLAKE2(V, salt)
	char *e = E;
	if (blake2b((u8 *)e, password_verifier, 0, 32, 72, 0)) {
		return -1;
	}

	// E = Elligator(e)
	if (snowshoe_elligator(e, E)) {
		return -1;
	}

	const char *Xp = challenge;
	char *Yp = client_proof;
	char *Z = E + 128;
	char *a = server_verifier;
	do {
		// Chose a random 512-bit y
		char *y = E + 128;
		if (cymric_random(&state->rng, y, 64)) {
			return -1;
		}

		// y = y (mod q) for uniform distribution
		snowshoe_mod_q(y, y);

		// Y' = Y + E
		if (snowshoe_elligator_encrypt(y, E, Yp)) {
			continue;
		}

		// h = H(X', Y')
		char *h = E + 128 + 64;
		if (blake2b_init(&B, 64)) {
			return -1;
		}
		if (blake2b_update(&B, (const u8 *)Xp, 64)) {
			return -1;
		}
		if (blake2b_update(&B, (const u8 *)Yp, 64)) {
			return -1;
		}
		if (blake2b_final(&B, (u8 *)h, 64)) {
			return -1;
		}

		// h = h (mod q) for uniform distribution
		snowshoe_mod_q(h, h);

		// a = vh + y (mod q)
		const char *v = client_secret;
		snowshoe_mul_mod_q(v, h, y, a);

		// X = (X' - E)
		// Z = aX
	} while (snowshoe_elligator_secret(a, Xp, E, 0, 0, Z));

	// PROOF = BLAKE2(E, SP, Z)
	char *proof = E + 128 + 64;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)E, 128)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Xp, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Yp, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)server_public, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Z, 64)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)proof, 64)) {
		return -1;
	}

	// CPROOF = Low 32 bytes of PROOF
	memcpy(client_proof + 64, proof, 32);

	// SPROOF = High 32 bytes of PROOF
	memcpy(server_verifier, proof + 32, 32);

	CAT_SECURE_OBJCLR(E);

	return 0;
}

/*
	tabby_password_server_proof(
		S,
		client_proof [IN],
		challenge_secret [IN],
		server_proof [OUT])

	After the client provides proof, the server uses this function to check
	the proof and to generate its own proof of knowledge.

	Packed data formats:

		Inputs:

			client_proof		[96 bytes]
				Y' = Y + E		[64 bytes]
				CPROOF			[32 bytes]

			challenge_secret	[288 bytes]
				E (extended)	[128 bytes]
				x				[32 bytes]
				V				[64 bytes]
				X' = X + E		[64 bytes]

		Outputs:

			server_proof		[32 bytes]
				SPROOF			[32 bytes]
*/

int tabby_password_server_proof(tabby_server *S, const char client_proof[96], const char challenge_secret[288], char server_proof[32]) {
	server_internal *state = (server_internal *)S;

	char Z[64];
	blake2b_state B;

	// If invalid input,
	if (!S || !client_proof || !challenge_secret || !server_proof) {
		return -1;
	}

	// h = H(X', Y')
	const char *Xp = challenge_secret + 224;
	const char *Yp = client_proof;
	char *h = Z;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Xp, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Yp, 64)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)h, 64)) {
		return -1;
	}

	// h = h (mod q) for uniform distribution
	snowshoe_mod_q(h, h);

	// b = xh (mod q)
	const char *x = challenge_secret + 128;
	char *b = Z;
	snowshoe_mul_mod_q(x, h, 0, b);

	// Y = Y' - E
	// Z = xY + bV
	const char *E = challenge_secret;
	const char *V = challenge_secret + 160;
	if (snowshoe_elligator_secret(x, Yp, E, b, V, Z)) {
		return -1;
	}

	// PROOF = BLAKE2(E, SP, Z)
	char *proof = Z;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)E, 128)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Xp, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Yp, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)state->public_key, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)Z, 64)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)proof, 64)) {
		return -1;
	}

	// Recover CPROOF from client data
	const char *cproof = client_proof + 64;
	if (!SecureEqual(cproof, proof, 32)) {
		return -1;
	}

	// SPROOF = High 32 bytes of PROOF
	memcpy(server_proof, proof + 32, 32);

	return 0;
}

/*
	tabby_password_check_server(
		server_verifier [IN]
		server_proof [IN])

	The server sent its proof of knowledge and now the client calls this function
	to verify it.  This function only has to do a constant-time memory comparison.
*/

int tabby_password_check_server(const char server_verifier[32], const char server_proof[32]) {
	// If invalid input,
	if (!server_verifier || !server_proof) {
		return -1;
	}

	// If they do not match,
	if (!SecureEqual(server_verifier, server_proof, 32)) {
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

