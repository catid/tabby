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

#include "tabby.h"
#include "snowshoe.h"
#include "cymric.h"
#include "blake2.h"

#include "Platform.hpp"
#include "SecureErase.hpp"
using namespace cat;

static bool m_initialized = false;

// Valid flag values
static const u32 FLAG_INIT = 0x11223344;

// Check if x == 0 in constant-time
static bool is_zero(const char x[32]) {
	const u64 *k = (const u64 *)x;
	const u64 zero = k[0] | k[1] | k[2] | k[3];
	const u32 z = (u32)(zero | (zero >> 32));
	return z == 0;
}

// Check if x == y in constant-time
static bool is_equal(const char x[32], const char y[32]) {
	const u64 *k = (const u64 *)x;
	const u64 *l = (const u64 *)y;
	const u64 zero = (k[0] ^ l[0]) | (k[1] ^ l[1]) | (k[2] ^ l[2]) | (k[3] ^ l[3]);
	const u32 z = (u32)(zero | (zero >> 32));
	return z == 0;
}

static int generate_key(cymric_rng *rng, char private_key[32], char public_key[64]) {
	// Reuse public key buffer for 64 bytes of private key material
	char *key = public_key;

	// For each attempt,
	do {
		// If Cymric was not able to generate a random value,
		if (cymric_random(rng, key, 64)) {
			// Give up
			return -1;
		}

		// Reduce 512-bit key material modulo Snowshoe q to produce
		// a private key uniformly distributed in the range 0..q-1.
		// Uniformity is verified experimentally; see `docs/fold.cpp`.

		// This is not what is needed exactly, since 0 is an invalid
		// private key.  But it is passed to snowshoe_mul_gen(), which
		// will validate the key, and it will error out if the rare 0
		// case occurs.

		snowshoe_mod_q(key, private_key);

		// Some other implentations of ECC have a faster key generation
		// process where they will just mask some bits (e.g. Ed25519)
		// on a random input, which gives away a few bits of security
		// in return for faster and deterministic key generation.

		// Tabby's approach offers a higher security level, which makes
		// up for the "security level bits" lost by using an efficient
		// endomorphism to speed up curve math, and is not much slower
		// in practice (<2% overhead) than masking.  And key generation
		// is rarely a bottleneck in practice.

		// Using keys uniformly distributed in 1..q-1 is important
		// for Tabby because later on the private keys are combined as
		// `k = k1 * H + k2` similar to EdDSA.  If k1 or k2 are biased
		// due to masking bits, then the resulting value `k` has a
		// large bias according to some 18-bit simulations.  So to avoid
		// this problem, strong uniformly-distributed keys are used.
	} while (snowshoe_mul_gen(private_key, public_key, 0));

	return 0;
}

#include "server.inc"
#include "client.inc"
#include "sign.inc"

#ifdef __cplusplus
extern "C" {
#endif

int _tabby_init(int expected_version) {
	// If ABI compatibility is uncertain,
	if (expected_version != TABBY_VERSION) {
		return -1;
	}

	// If the internal version of the server structure is bigger
	// than the one that the user sees,
	if (sizeof(server_internal) > sizeof(tabby_server)) {
		return -1;
	}

	// If the internal version of the client structure is bigger
	// than the one that the user sees,
	if (sizeof(client_internal) > sizeof(tabby_client)) {
		return -1;
	}

	// If Cymric cannot initialize,
	if (cymric_init()) {
		return -1;
	}

	// If Snowshoe cannot initialize,
	if (snowshoe_init()) {
		return -1;
	}

	// Flag initialized true so we can do sanity checks later
	m_initialized = true;
	return 0;
}

void tabby_erase(void *object, int bytes) {
	// If input is valid,
	if CAT_LIKELY(object && bytes > 0) {
		// Securely erase the input
		cat_secure_erase(object, bytes);
	}
}

#ifdef __cplusplus
}
#endif

