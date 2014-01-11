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

#include "lyra/lyra.h"

#ifdef __cplusplus
extern "C" {
#endif

static const PBKDF_M_COST = 2500;	// Number of 4KB rows to allocate => 10 MB
static const PBKDF_T_COST = 4000;	// Number of iterations < 100 ms on desktop

int tabby_password_verifier(const char salt[8], const void *username, int username_len, const void *realm, int realm_len, const void *password, int password_len, char client_secret[32], char password_verifier[72]) {
	char v[32];

	// If Lyra fails,
	if (PHS(v, 32, in, inlen, salt, 8, PBKDF_T_COST, PBKDF_M_COST)) {
		// Not recoverable (indicates a problem with the library)
		return -1;
	}

	return 0;
}

int tabby_password_server_challenge(const void *username, int username_len, const char password_verifier[72], char challenge_secret[160], char challenge[72]) {
}

int tabby_password_client_proof(const char challenge[72], const char client_secret[32], const char password_verifier[72], char server_verifier[32], char client_proof[72]) {
}

int tabby_password_server_proof(const char client_proof[32], const char challenge_secret[160], char server_proof[32]) {
}

int tabby_password_check_server_proof(const char server_verifier[32], const char server_proof[32]) {
}

#ifdef __cplusplus
}
#endif

