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

#include <iostream>
using namespace std;

#include "lyra.h"
#include "blake2.h"
#include "SecureEqual.hpp"

// PBKDF parameters
static const int PBKDF_ROW_SIZE = 64;	// Number of 64-byte hash blocks per matrix row
static const int PBKDF_M_COST = 8;		// Number of 4KB rows to allocate => 32KB
static const int PBKDF_T_COST = 1000;	// Number of iterations for 90 milliseconds on laptop

// Generate a client secret and server password verifier from account data
// Returns -2 to indicate a recoverable error (read more on that case below)
// Returns other non-zero values on unrecoverable errors
// Returns 0 on success
static int generate_password_verifier(const char salt[8],
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

	// v = Lyra(chosen salt, pw)
	char *v = password_verifier;
	if (lyra((u8 *)pw, 64, (const u8 *)salt, 8,
			 PBKDF_T_COST, PBKDF_ROW_SIZE, PBKDF_M_COST, 64, (u8 *)v)) {
		return -1;
	}

	// v = v mod q
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

int tabby_password(tabby_client *C, const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, char password_verifier[72]) {
	client_internal *state = (client_internal *)C;

	char salt[8];

	// If input is invalid,
	if (!C || !username || username_len < 1 ||
		!password || password_len < 1 || !password_verifier) {
		return -1;
	}

	int error;
	do {
		// Choose a new salt
		if (cymric_random(&state->rng, salt, 8)) {
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
	memcpy(password_verifier + 64, salt, 8);

	return 0;
}

int tabby_password_challenge(tabby_server *S, const char password_verifier[72], char challenge_secret[224], char challenge[72]) {
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
	char *x = challenge_secret + 128;
	do {
		// Chose a random x
		if (cymric_random(&state->rng, x, 32)) {
			return -1;
		}

		// Retry while resulting point is invalid
	} while (snowshoe_elligator_encrypt(x, E, challenge));

	// Store V
	char *V = challenge_secret + 160;
	memcpy(V, password_verifier, 64);

	// Add salt to challenge
	memcpy(challenge + 64, password_verifier + 64, 8);

	return 0;
}

int tabby_password_client_proof(tabby_client *C, const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, const char challenge[72], const char server_public[64], char server_verifier[32], char client_proof[96]) {
	client_internal *state = (client_internal *)C;

	char E[128 + 64 + 64];

	// If invalid input,
	if (!C || !username || username_len < 1 || !password || password_len < 1 ||
		!challenge || !server_public || !server_verifier || !client_proof) {
		return -1;
	}

	// Generate client secret and password verifier from account data
	const char *salt = challenge + 64;
	char *client_secret = client_proof;
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
	memcpy(password_verifier + 64, salt, 8);

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
	const char *v = client_secret;
	char *y = server_verifier;
	char *vy = server_verifier;
	char *Y = client_proof;
	char *Z = E + 128;
	do {
		// Chose a random y
		if (cymric_random(&state->rng, y, 32)) {
			return -1;
		}

		// vy = v + y (mod q)
		snowshoe_add_mod_q(v, y, vy);

		// Y' = Y + E
		if (snowshoe_elligator_encrypt(y, E, Y)) {
			continue;
		}

		// X = (X' - E)
		// Z = (v*h + y)X
	} while (snowshoe_elligator_secret(vy, Xp, E, 0, Z));

	for (int ii = 0; ii < 64; ++ii) {
		cout << (int)Z[ii];
	}
	cout << endl;

	// PROOF = BLAKE2(E, SP, Z)
	char *proof = E + 128 + 64;
	blake2b_state B;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)E, 128)) {
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

int tabby_password_server_proof(tabby_server *S, const char client_proof[96], const char challenge_secret[224], char server_proof[32]) {
	server_internal *state = (server_internal *)S;

	char Z[64];

	// If invalid input,
	if (!S || !client_proof || !challenge_secret || !server_proof) {
		return -1;
	}

	// Y = Y' - E
	// Z = x(V + Y)
	const char *Yp = client_proof;
	const char *E = challenge_secret;
	const char *x = challenge_secret + 128;
	const char *V = challenge_secret + 160;
	if (snowshoe_elligator_secret(x, Yp, E, V, Z)) {
		return -1;
	}

	for (int ii = 0; ii < 64; ++ii) {
		cout << (int)Z[ii];
	}
	cout << endl;

	// PROOF = BLAKE2(E, SP, Z)
	char *proof = Z;
	blake2b_state B;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)E, 128)) {
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

