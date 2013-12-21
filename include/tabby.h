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

#ifndef CAT_TABBY_HPP
#define CAT_TABBY_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define TABBY_VERSION 2

/*
 * Verify binary compatibility with the Tabby API on startup.
 *
 * Example:
 * 	if (tabby_init()) throw "Update tabby static library";
 *
 * Returns 0 on success.
 * Returns non-zero if the API level does not match.
 */
extern int _tabby_init(int expected_version);
#define tabby_init() _tabby_init(TABBY_VERSION)


//// Client

// Opaque client state object
typedef struct {
	char internal[200];
} tabby_client;

/*
 * Generate a Tabby client object
 *
 * You may optionally provide extra random number data as a seed to improve
 * the quality of the generated keys; otherwise pass NULL for seed.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_client_gen(tabby_client *C, const void *seed, int seed_bytes, char client_request[96]);

/*
 * Derive a new Tabby client object from an old one
 *
 * This reuses data from the old Tabby client object to speed up initialization.
 *
 * This function is also useful for resetting a Tabby client object to connect
 * again by setting existing == C.
 *
 * You may optionally provide extra random number data as a seed to improve
 * the quality of the generated keys; otherwise pass NULL for seed.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_client_rekey(const tabby_client *existing, tabby_client *C, const void *seed, int seed_bytes, char client_request[96]);

/*
 * Process server response
 *
 * This is the first place where the server's public key is introduced
 * on the client side.  The server's response is processed, and either
 * a secret key is derived that will match the one on the server, or
 * the function will error out on invalid data from the server.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_client_handshake(tabby_client *C, const char server_public_key[64], const char server_response[128], char secret_key[32]);


//// Server

// Opaque server state object
typedef struct {
	char internal[464];
} tabby_server;

/*
 * Generate a Tabby server object
 *
 * You may optionally provide extra random number data as a seed to improve
 * the quality of the generated keys; otherwise pass NULL for seed.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_gen(tabby_server *S, const void *seed, int seed_bytes);

/*
 * Rekey a Tabby server object
 *
 * This should be done no more often than once per minute, and optimally
 * from a separate thread since it can take a minute to complete.
 *
 * You may optionally provide extra random number data as a seed to improve
 * the quality of the generated keys; otherwise pass NULL for seed.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_rekey(tabby_server *S, const void *seed, int seed_bytes);

/*
 * Returns the public key for a Tabby server object
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_get_public_key(tabby_server *S, char public_key[64]);

/*
 * Save a Tabby server object
 *
 * The server data includes the long-term private key of the server,
 * and it should be stored in a safe place.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_save_secret(tabby_server *S, char server_data[64]);

/*
 * Load a Tabby server object
 *
 * You may optionally provide extra random number data as a seed to improve
 * the quality of the generated keys; otherwise pass NULL for seed.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_load_secret(tabby_server *S, const void *seed, int seed_bytes, const char server_data[64]);

/*
 * Process client request
 *
 * This should be called to accept a new connection from a remote client.
 * The server response is filled by this function and should be delivered
 * to the remote client.
 *
 * It is the responsibility of the user to properly handle lost server
 * responses, where the client times out waiting for a response from the
 * server, and the server believes a session is established.  Ideally in
 * this case, the next time the client sends an identical request, the
 * server would send its response again without calling this function.
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_server_handshake(tabby_server *S, const char client_request[96], char server_response[128], char secret_key[32]);


//// Signatures

/*
 * Sign a message using EdDSA
 *
 * Returns 0 on success.
 * Returns non-zero if the input data is invalid.
 */
extern int tabby_sign(tabby_server *S, const void *message, int bytes, char signature[96]);

/*
 * Verify a message signed using EdDSA
 *
 * Returns 0 on success.
 * Returns non-zero if the server data is invalid.
 */
extern int tabby_verify(const void *message, int bytes, const char public_key[64], const char signature[96]);


//// Cleanup

/*
 * Securely erase an object from memory
 *
 * When you are done with any of the Tabby objects, including secret keys,
 * be sure to erase them with this function to avoid leaving it on the stack
 * or heap where it could be scooped up later.
 */
extern void tabby_erase(void *object, int bytes);

#ifdef __cplusplus
}
#endif

#endif // CAT_SNOWSHOE_HPP

