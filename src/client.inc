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

typedef struct {
	// Key/nonce generator
	cymric_rng rng;

	// Generated/loaded private key
	char private_key[32];

	// Corresponding public key
	char public_key[64];

	// Nonce generated for this connection
	char nonce[32];

	// Flag indicating initialization for error checking
	u32 flag;
} client_internal;

#ifdef __cplusplus
extern "C" {
#endif

int tabby_client_gen(tabby_client *C, const void *seed, int seed_bytes, char client_request[96]) {
	client_internal *state = (client_internal *)C;

	// Input validation
	if (!C || !client_request) {
		return -1;
	}

	// Reseed the generator
	if (cymric_seed(&state->rng, seed, seed_bytes)) {
		return -1;
	}

	// Generate the client's ephemeral key pair
	if (generate_key(&state->rng, state->private_key, state->public_key)) {
		return -1;
	}

	// Note that Cymric will hash its internal state after each
	// random number it generates, so if the state is discovered
	// for a later number it is hard to go backwards, but if the
	// state is discovered for an earlier number it is easier to
	// go forwards.  So any public info should be generated last
	// to mitigate problems that should never occur anyway.

	// Generate a random nonce
	if (cymric_random(&state->rng, state->nonce, 32)) {
		return -1;
	}

	// Construct the request object, which is:
	// (client public key[64]) (client nonce[32])
	memcpy(client_request, state->public_key, 64);
	memcpy(client_request + 64, state->nonce, 32);

	// Flag the object as initialized for sanity checking later
	state->flag = FLAG_INIT;

	return 0;
}

int tabby_client_rekey(const tabby_client *existing, tabby_client *C, const void *seed, int seed_bytes, char client_request[96]) {
	client_internal *old_state = (client_internal *)existing;
	client_internal *state = (client_internal *)C;

	// Input validation
	if (!existing || !C || !client_request || old_state->flag != FLAG_INIT) {
		return -1;
	}

	// Derive a new generator from the old one, which does not reseed.
	// This is this main point of using tabby_client_rekey() instead of
	// tabby_client_gen() because the rekeying does not consume more
	// /dev/random randomness and avoids blocking.
	if (cymric_derive(&state->rng, &old_state->rng, seed, seed_bytes)) {
		return -1;
	}

	// Generate the client's ephemeral key pair
	if (generate_key(&state->rng, state->private_key, state->public_key)) {
		return -1;
	}

	// Generate a new random client nonce.
	// This is the main result of rekeying, and it makes it impossible
	// for a malicious server to replay a previously recorded session
	// with a legitimate server and arrive at the same session key.
	if (cymric_random(&state->rng, state->nonce, 32)) {
		return -1;
	}

	// Fill the client request object
	memcpy(client_request, state->public_key, 64);
	memcpy(client_request + 64, state->nonce, 32);

	// Set the initialized flag for sanity checking later
	state->flag = FLAG_INIT;

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

	char T[64+64+32];
	char *H = T + 64;
	char *h = T + 64+64;
	char *d = h;
	char *k = T;
	const char *EP = server_response;
	const char *SN = server_response + 64;
	const char *PROOF = server_response + 96;

	// H = BLAKE2(CP, CN, EP, SP, SN)
	blake2b_state B;
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)state->public_key, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)state->nonce, 32)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)EP, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)server_public_key, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)SN, 32)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)H, 64)) {
		return -1;
	}

	// h = H mod q
	snowshoe_mod_q(H, h);

	// Validate h != 0.
	if (is_zero(h)) {
		return -1;
	}

	// d = h * CS (mod q)
	snowshoe_mul_mod_q(h, state->private_key, 0, d);

	// Validate that d != 0
	if (is_zero(d)) {
		return -1;
	}

	// T = CS * EP + d * SP
	if (snowshoe_simul(state->private_key, EP, d, server_public_key, T)) {
		return -1;
	}

	// k = BLAKE2(T, H)
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)T, 128)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)k, 64)) {
		return -1;
	}

	// Verify the high 32 bytes of k matches PROOF
	if (!is_equal(PROOF, k + 32)) {
		return -1;
	}

	// Session key is the low 32 bytes of k
	memcpy(secret_key, k, 32);

	CAT_SECURE_OBJCLR(T);
	CAT_SECURE_OBJCLR(B);

	return 0;
}

#ifdef __cplusplus
}
#endif


