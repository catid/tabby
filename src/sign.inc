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

#ifdef __cplusplus
extern "C" {
#endif

int tabby_sign(tabby_server *S, const void *message, int bytes, char signature[96]) {
	server_internal *state = (server_internal *)S;

	// If library is not initialized,
	if (!m_initialized) {
		return -1;
	}

	// If input is invalid or server object is not initialized,
	if (!state || !message || bytes <= 0 || !signature || state->flag != FLAG_INIT) {
		return -1;
	}

	// Hash the signature key with the message to produce a random value,
	// rather than generating a random value, which is a trick recommended
	// by the Ed25519 paper.

	blake2b_state B;

	// r = BLAKE2(sign_key, M) mod q
	char r[64];
	if (blake2b_init_key(&B, 64, state->sign_key, 32)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)message, bytes)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)r, 64)) {
		return -1;
	}
	snowshoe_mod_q(r, r);

	// This produces a random value in 0...q-1, which is very unlikely
	// to be zero.  As implemented, the signature will fail in this case.
	// This means that a very small number of messages cannot be signed,
	// but it is incredibly unlikely to ever happen.

	// R = rG
	char *R = signature;
	if (snowshoe_mul_gen(r, R, 1)) {
		return -1;
	}

	// Hash the public key, R, and the message together and reduce the
	// 512-bit result modulo q.  This is H(R,A,M) from Ed25519.

	// t = BLAKE2(SP, R, M) mod q
	char t[64];
	if (blake2b_init(&B, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)state->public_key, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)R, 64)) {
		return -1;
	}
	if (blake2b_update(&B, (const u8 *)message, bytes)) {
		return -1;
	}
	if (blake2b_final(&B, (u8 *)t, 64)) {
		return -1;
	}
	snowshoe_mod_q(t, t);

	// Combine the two uniformly distributed keys with the private key:

	// s = r + t*SS (mod q)
	char *s = signature + 64;
	snowshoe_mul_mod_q(t, state->private_key, r, s);

	CAT_SECURE_OBJCLR(r);
	CAT_SECURE_OBJCLR(t);
	CAT_SECURE_OBJCLR(B);

	return 0;
}

int tabby_verify(const void *message, int bytes, const char public_key[64], const char signature[96]) {
	// If library is not initialized,
	if (!m_initialized) {
		return -1;
	}

	// If input is invalid,
	if (!public_key || !message || bytes <= 0 || !signature) {
		return -1;
	}

	// Reconstruct the same hash as on the server.  This is H(R,A,M) from Ed25519.

	// t = BLAKE2(SP, R, M) mod q
	const char *R = signature;
	char t[64];
	blake2b_state B;
	blake2b_init(&B, 64);
	blake2b_update(&B, (const u8 *)public_key, 64);
	blake2b_update(&B, (const u8 *)R, 64);
	blake2b_update(&B, (const u8 *)message, bytes);
	blake2b_final(&B, (u8 *)t, 64);
	snowshoe_mod_q(t, t);

	// Negate the public key and perform a simultaneous multiplication as in Ed25519
	// to check the signature.

	// u = sG - tSP
	char u[64];
	const char *s = signature + 64;
	snowshoe_neg(public_key, u);
	if (snowshoe_simul_gen(s, t, u, u)) {
		return -1;
	}

	// Check if the points match.  This does not need to be done in constant-time.

	const u64 *X = (const u64 *)u;
	const u64 *Y = (const u64 *)R;
	for (int ii = 0; ii < 8; ++ii) {
		if (X[ii] != Y[ii]) {
			return -1;
		}
	}

	// No need to clear sensitive data from memory here: It is all public knowledge

	return 0;
}

#ifdef __cplusplus
}
#endif

