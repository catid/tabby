/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

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

#include "tabby.h"
#include "snowshoe.h"
#include "cymric.h"
#include "blake2.h"

#include "Platform.hpp"
using namespace cat;

static bool m_initialized = false;

typedef struct {
	cymric_rng rng;
	char private_key[32];
	char public_key[64];
	char nonce[32];
	u32 flag;
} client_internal;

typedef struct {
	cymric_rng rng;
	char sign_key[32];
	char private_key[32];
	char public_key[64];
	char private_ephemeral[32];
	char public_ephemeral[64];
	u32 flag;

	// Rekey thread data:
	char private_rekey[32];
	char public_rekey[64];
	cymric_rng rng_rekey;
	volatile u32 flag_rekey;
} server_internal;

static const u32 FLAG_INIT = 0x11223344;
static const u32 FLAG_NEED_REKEY = 1;
static const u32 FLAG_REKEY_DONE = 2;

static void generate_key(cymric_rng *rng, char private_key[32], char public_key[64]) {
	char key[64];

	do {
		cymric_random(rng, key, 64);

		snowshoe_mod_q(key, private_key);
	} while (snowshoe_mul_gen(private_key, public_key));

	// Note that snowshoe will validate the private key for us

	CAT_SECURE_CLR(key, sizeof(key));
}

#ifdef __cplusplus
extern "C" {
#endif

int _tabby_init(int expected_version) {
	if (expected_version != TABBY_VERSION) {
		return -1;
	}

	if (sizeof(server_internal) > sizeof(tabby_server)) {
		return -1;
	}

	if (sizeof(client_internal) > sizeof(tabby_client)) {
		return -1;
	}

	m_initialized = true;
	return 0;
}

int tabby_server_gen(tabby_server *S, const void *seed, int seed_bytes) {
	server_internal *state = (server_internal *)S;

	if (!S) {
		return -1;
	}

	cymric_seed(&state->rng, seed, seed_bytes);

	generate_key(&state->rng, state->private_key, state->public_key);
	generate_key(&state->rng, state->private_ephemeral, state->public_ephemeral);

	cymric_random(&state->rng, state->sign_key, 32);

	state->flag = FLAG_INIT;
	state->flag_rekey = FLAG_NEED_REKEY;

	return 0;
}

int tabby_client_gen(tabby_client *C, const void *seed, int seed_bytes, char client_request[96]) {
	client_internal *state = (client_internal *)C;

	if (!C || !client_request) {
		return -1;
	}

	cymric_seed(&state->rng, seed, seed_bytes);

	generate_key(&state->rng, state->private_key, state->public_key);

	cymric_random(&state->rng, state->nonce, 32);

	memcpy(client_request, state->public_key, 64);
	memcpy(client_request + 64, state->nonce, 32);

	state->flag = FLAG_INIT;

	return 0;
}

int tabby_client_rekey(const tabby_client *existing, tabby_client *C, const void *seed, int seed_bytes, char client_request[96]) {
	client_internal *old_state = (client_internal *)existing;
	client_internal *state = (client_internal *)C;

	if (!existing || !C || !client_request || state->flag != FLAG_INIT) {
		return -1;
	}

	cymric_derive(&state->rng, &old_state->rng, seed, seed_bytes);

	memcpy(state->private_key, old_state->private_key, 32);
	memcpy(state->public_key, old_state->public_key, 64);

	cymric_random(&state->rng, state->nonce, 32);

	memcpy(client_request, state->public_key, 64);
	memcpy(client_request + 64, state->nonce, 32);

	state->flag = FLAG_INIT;

	return 0;
}

int tabby_get_public_key(tabby_server *S, char public_key[64]) {
	server_internal *state = (server_internal *)S;

	if (!S || !public_key || state->flag != FLAG_INIT) {
		return -1;
	}

	memcpy(public_key, state->public_key, 64);

	return 0;
}

int tabby_server_save(tabby_server *S, char server_data[64]) {
	server_internal *state = (server_internal *)S;

	if (!S || !server_data || state->flag != FLAG_INIT) {
		return -1;
	}

	memcpy(server_data, state->private_key, 32);
	memcpy(server_data + 32, state->sign_key, 32);

	return 0;
}

int tabby_server_load(tabby_server *S, const void *seed, int seed_bytes, const char server_data[64]) {
	server_internal *state = (server_internal *)S;

	if (!S || !server_data) {
		return -1;
	}

	memcpy(state->private_key, server_data, 32);
	memcpy(state->sign_key, server_data + 32, 32);

	if (snowshoe_mul_gen(state->private_key, state->public_key)) {
		return -1;
	}

	cymric_seed(&state->rng, seed, seed_bytes);

	generate_key(&state->rng, state->private_ephemeral, state->public_ephemeral);

	state->flag = FLAG_INIT;
	state->flag_rekey = FLAG_NEED_REKEY;

	return 0;
}

int tabby_sign(tabby_server *S, const void *message, int bytes, char signature[96]) {
	server_internal *state = (server_internal *)S;

	if (!m_initialized) {
		return -1;
	}

	if (state->flag != FLAG_INIT) {
		return -1;
	}

	if (!state || !message || bytes <= 0 || !signature) {
		return -1;
	}

	// r = BLAKE2(sign_key, M) mod q
	char r[64];
	if (blake2b((u8*)r, message, state->sign_key, 64, bytes, 32)) {
		return -1;
	}
	snowshoe_mod_q(r, r);

	// R = rG
	char *R = signature;
	if (snowshoe_mul_gen(r, R)) {
		return -1;
	}

	// t = BLAKE2(SP, R, M) mod q
	char t[64];
	blake2b_state B;
	blake2b_init(&B, 64);
	blake2b_update(&B, (const u8 *)state->public_key, 64);
	blake2b_update(&B, (const u8 *)R, 64);
	blake2b_update(&B, (const u8 *)message, bytes);
	blake2b_final(&B, (u8 *)t, 64);
	snowshoe_mod_q(t, t);

	// s = r + t*SS (mod q)
	char *s = signature + 64;
	snowshoe_mul_mod_q(t, state->private_key, r, s);

	CAT_SECURE_CLR(r, sizeof(r));
	CAT_SECURE_CLR(t, sizeof(t));

	return 0;
}

int tabby_verify(const void *message, int bytes, const char public_key[64], char signature[96]) {
	if (!m_initialized) {
		return -1;
	}

	if (!public_key || !message || bytes <= 0 || !signature) {
		return -1;
	}

	// t = BLAKE2(SP, R, M) mod q
	char *R = signature;
	char t[64];
	blake2b_state B;
	blake2b_init(&B, 64);
	blake2b_update(&B, (const u8 *)public_key, 64);
	blake2b_update(&B, (const u8 *)R, 64);
	blake2b_update(&B, (const u8 *)message, bytes);
	blake2b_final(&B, (u8 *)t, 64);
	snowshoe_mod_q(t, t);

	// u = sG - tSP
	char u[64];
	char *s = signature + 64;
	snowshoe_neg(public_key, u);
	if (snowshoe_simul_gen(s, t, u, u)) {
		return -1;
	}

	// 4*R ?= u
	if (snowshoe_equals4(u, R)) {
		return -1;
	}

	// No need to clear sensitive data from memory here: It is all public knowledge

	return 0;
}

int tabby_server_rekey(tabby_server *S, const void *seed, int seed_bytes) {
	server_internal *state = (server_internal *)S;

	if (!m_initialized) {
		return -1;
	}

	if (state->flag != FLAG_INIT) {
		return -1;
	}

	// If a new key is requested,
	if (state->flag_rekey == FLAG_NEED_REKEY) {
		CAT_FENCE_COMPILER;

		// Copy RNG state
		memcpy(&state->rng_rekey, &state->rng, sizeof(state->rng_rekey));

		// Seed new RNG
		cymric_seed(&state->rng_rekey, seed, seed_bytes);

		// Generate ephemeral key pair
		generate_key(&state->rng_rekey, state->private_rekey, state->public_rekey);

		CAT_FENCE_COMPILER;

		// Flag rekey complete
		state->flag_rekey = FLAG_REKEY_DONE;
	}

	return 0;
}

int tabby_server_handshake(tabby_server *S, const char client_request[96], char server_response[128], char secret_key[32]) {
	server_internal *state = (server_internal *)S;

	if (!m_initialized) {
		return -1;
	}

	if (state->flag != FLAG_INIT) {
		return -1;
	}

	if (!state || !client_request || !server_response || !secret_key) {
		return -1;
	}

	// If rekeying is complete,
	if (state->flag_rekey == FLAG_REKEY_DONE) {
		CAT_FENCE_COMPILER;

		// Copy over the generated ephemeral key pair
		memcpy(state->private_ephemeral, state->private_rekey, 32);
		memcpy(state->public_ephemeral, state->public_rekey, 64);

		// Copy over the new RNG state
		memcpy(&state->rng, &state->rng_rekey, sizeof(state->rng));

		CAT_FENCE_COMPILER;

		// Allow thread to rekey again
		state->flag_rekey = FLAG_NEED_REKEY;
	}

	char T[64+64];
	char *H = T + 64;
	char h[32];
	char e[32];
	char *nonce = server_response + 64;
	const char *client_public = client_request;
	const char *client_nonce = client_request + 64;
	char z;

	do {
		do {
			// Generate server nonce SN
			cymric_random(&state->rng, nonce, 32);

			// H = BLAKE2(CP, CN, EP, SP, SN)
			blake2b_state B;
			blake2b_init(&B, 64);
			blake2b_update(&B, (const u8 *)client_public, 64);
			blake2b_update(&B, (const u8 *)client_nonce, 32);
			blake2b_update(&B, (const u8 *)state->public_ephemeral, 64);
			blake2b_update(&B, (const u8 *)state->public_key, 64);
			blake2b_update(&B, (const u8 *)nonce, 32);
			blake2b_final(&B, (u8 *)H, 64);

			// h = H mod q
			snowshoe_mod_q(H, h);

			// If h == 0, choose a new SN and start over.
			z = 0;
			for (int ii = 0; ii < 32; ++ii) {
				z |= h[ii];
			}
		} while (!z);

		// e = h * SS + ES (mod q)
		snowshoe_mul_mod_q(h, state->private_key, state->private_ephemeral, e);

		// If e == 0, choose a new SN and start over.
		z = 0;
		for (int ii = 0; ii < 32; ++ii) {
			z |= h[ii];
		}
	} while (!z);

	// T = e * SP
	if (snowshoe_mul(e, client_public, T)) {
		return -1;
	}

	// k = BLAKE2(T, H)
	char k[64];
	if (blake2b((u8 *)k, T, 0, 64, 128, 0)) {
		return -1;
	}

	// Secret key = low 32 bytes of k
	memcpy(secret_key, k, 32);

	// Write server ephemeral public key
	memcpy(server_response, state->public_ephemeral, 64);

	// PROOF = high 32 bytes of k
	memcpy(server_response + 32 + 64, k + 32, 32);

	CAT_SECURE_CLR(T, sizeof(T));
	CAT_SECURE_CLR(h, sizeof(h));
	CAT_SECURE_CLR(e, sizeof(e));
	CAT_SECURE_CLR(&z, sizeof(z));

	return 0;
}

int tabby_client_handshake(tabby_client *C, const char server_public_key[64], const char server_response[128], char secret_key[32]) {
	client_internal *state = (client_internal *)C;

	if (!m_initialized) {
		return -1;
	}

	if (state->flag != FLAG_INIT) {
		return -1;
	}

	if (!state || !server_public_key || !server_response || !secret_key) {
		return -1;
	}

	char T[64+64];
	char *H = T + 64;
	char h[32];
	char k[64];
	char *d = k;
	const char *EP = server_response;
	const char *SN = server_response + 64;
	const char *PROOF = server_response + 96;

	// H = BLAKE2(CP, CN, EP, SP, SN)
	blake2b_state B;
	blake2b_init(&B, 64);
	blake2b_update(&B, (const u8 *)state->public_key, 64);
	blake2b_update(&B, (const u8 *)state->nonce, 32);
	blake2b_update(&B, (const u8 *)EP, 64);
	blake2b_update(&B, (const u8 *)server_public_key, 64);
	blake2b_update(&B, (const u8 *)SN, 32);
	blake2b_final(&B, (u8 *)H, 64);

	// h = H mod q
	snowshoe_mod_q(H, h);

	// If h == 0, choose a new SN and start over.
	char z = 0;
	for (int ii = 0; ii < 32; ++ii) {
		z |= h[ii];
	}
	if (!z) {
		return -1;
	}

	// d = h * CS (mod q)
	snowshoe_mul_mod_q(h, state->private_key, 0, d);

	// Validate that d != 0
	z = 0;
	for (int ii = 0; ii < 32; ++ii) {
		z |= d[ii];
	}
	if (!z) {
		return -1;
	}

	// T = CS * EP + d * SP
	if (snowshoe_simul(state->private_key, EP, d, server_public_key, T)) {
		return -1;
	}

	// k = BLAKE2(T, H)
	if (blake2b((u8 *)k, T, 0, 64, 128, 0)) {
		return -1;
	}

	// Verify the high 32 bytes of k matches PROOF
	z = 0;
	for (int ii = 0; ii < 32; ++ii) {
		z |= PROOF[ii] ^ k[32 + ii];
	}
	if (z) {
		return -1;
	}

	// Session key is the low 32 bytes of k
	memcpy(secret_key, k, 32);

	CAT_SECURE_CLR(T, sizeof(T));
	CAT_SECURE_CLR(h, sizeof(h));
	CAT_SECURE_CLR(k, sizeof(k));
	CAT_SECURE_CLR(&z, sizeof(z));

	return 0;
}

void tabby_erase(void *object, int bytes) {
	if (object && bytes > 0) {
		CAT_SECURE_CLR(object, bytes);
	}
}

#ifdef __cplusplus
}
#endif

