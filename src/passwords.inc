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

#include "lyra/lyra.h"
#include "blake2/blake2.h"
#include "SecureEqual.hpp"

// PBKDF parameters
static const PBKDF_ROW_SIZE = 64;	// Number of 64-byte hash blocks per matrix row
static const PBKDF_M_COST = 2500;	// Number of 4KB rows to allocate => 10 MB
static const PBKDF_T_COST = 4000;	// Number of iterations < 100 ms on desktop

#ifdef __cplusplus
extern "C" {
#endif

int tabby_password(tabby_client *C, const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, char client_secret[32], char password_verifier[72]) {
	client_internal *state = (client_internal *)C;
	char *v = password_verifier; // Reuse output buffer for temporary space
	blake2b_state B;
	char salt[8];

	// If input is invalid,
	if (!C || !username || username_len < 1 ||
		!password || password_len < 1 || !password_verifier) {
		return -1;
	}

	do {
		// Choose a new salt
		if (cymric_random(&state->rng, salt, 8)) {
			return -1;
		}

		// pw = BLAKE2(username, realm, password)
		char *pw = v; // Reuse buffer
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

		// v = Lyra(chosen salt, pw)
		if (lyra(pw, 64, salt, 8, PBKDF_T_COST, PBKDF_ROW_SIZE, PBKDF_M_COST, 64, v)) {
			return -1;
		}

		// v = v mod q
		snowshoe_mod_q(v, v);

		// If client_secret is requested,
		if (client_secret) {
			// Copy it from v
			memcpy(client_secret, v, 32);
		}

		// password_verifier = vG
	} while (snowshoe_mul_gen(v, password_verifier, 0));

	// Copy salt to end of password verifier
	memcpy(password_verifier + 64, salt, 8);

	CAT_SECURE_OBJCLR(B);

	return 0;
}

int tabby_password_challenge(tabby_server *S, const char password_verifier[72], char challenge_secret[160], char challenge[104]) {
	server_internal *state = (server_internal *)S;

	// If invalid input,
	if (!username || username_len < 1 || !password_verifier ||
		!challenge_secret || !challenge) {
		return -1;
	}

	// e = BLAKE2(V, salt)
	char *e = challenge_secret;
	if (blake2b(e, password_verifier, 0, 32, 72, 0)) {
		return -1;
	}

	// E = Elligator(e)
	char *E = challenge_secret;
	if (snowshoe_elligator(e, E)) {
		return -1;
	}

	// SN = Random 32 byte nonce
	char *SN = challenge + 64 + 8;
	if (cymric_random(&state->rng, SN, 32)) {
		return -1;
	}

	// Add salt to challenge
	memcpy(challenge + 64, password_verifier + 64, 8);

	// X' = xG + E
	char *x = challenge_secret + 128;
	do {
		// Chose a random x
		if (cymric_random(&state->rng, x, 32)) {
			return -1;
		}

		// Retry while resulting point is invalid
	} while (snowshoe_elligator_encrypt(x, E, challenge));

	return 0;
}

int tabby_password_client_proof(tabby_client *C, const char challenge[104], const char client_secret[32], const char password_verifier[72], char server_verifier[32], char client_proof[104]) {
	// If invalid input,
	if (!C || !challenge || !client_secret || !password_verifier ||
		!server_verifier || !client_proof) {
		return -1;
	}

	// e = BLAKE2(V, salt)
	char *e = client_proof;
	if (blake2b(e, password_verifier, 0, 32, 72, 0)) {
		return -1;
	}

	// E = Elligator(e)
	char E[128];
	if (snowshoe_elligator(e, E)) {
		return -1;
	}

	// CN = Random 32 byte nonce
	char *CN = client_proof + 64 + 32;
	if (cymric_random(&state->rng, SN, 32)) {
		return -1;
	}

	// X = (C - E)
	// Z = (v*h + y)X
	const char *C = challenge;
	const char *v = client_secret;
	char *y = server_verifier;
	char *vy = client_proof;
	char *Z = client_proof;
	const char *V = password_verifier;
	do {
		// Chose a random y
		if (cymric_random(&state->rng, y, 32)) {
			return -1;
		}

		// vy = v + y (mod q)
		snowshoe_add_mod_q(v, y, vy);

		// While resulting point is invalid,
	} while (snowshoe_elligator_secret(vy, C, E, V, Z));

	return 0;
}

int tabby_password_server_proof(tabby_server *S, const char client_proof[32], const char challenge_secret[160], char server_proof[32]) {
	// If invalid input,
	if (!S || !client_proof || !challenge_secret || !server_proof) {
		return -1;
	}

	// TODO

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

