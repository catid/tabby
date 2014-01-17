/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Cymric nor the names of its contributors may be
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

#ifndef CAT_CYMRIC_HPP
#define CAT_CYMRIC_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define CYMRIC_VERSION 3

/*
 * Verify binary compatibility with the Cymric API on startup.
 *
 * Must be called before any other functions.
 *
 * Example:
 * 	assert(cymric_init());
 *
 * It returns 0 on success.
 * It returns non-zero if the linked API is incompatible.
 */
int _cymric_init(int expected_version);
#define cymric_init() _cymric_init(CYMRIC_VERSION)

typedef struct {
	char internal[68];
} cymric_rng;

/*
 * Seeds a random number generator R
 *
 * This function allows you to optionally pass in a seed buffer, which will
 * be used to improve the randomness of the generator.  To not specify a seed,
 * pass NULL or set bytes to 0.
 *
 * To reseed, call this function again with the same cymric_rng object, which
 * will mix the old cymric_rng state with new seed.
 *
 * WARNING: It may take a long time for this function to complete.  It will
 * block until it gathers enough entropy to satisfy the request, which can take
 * as long as 30 seconds.  Your app startup should block until it completes.
 *
 * To handle reseeding, copy the internal state of the RNG aside and run this
 * function in a separate thread on it.  After cymric_seed() completes, over-
 * write the internal state with the newly generated state.  It is important
 * to not seed in-place from another thread because cymric_random is not thread
 * safe and may discard the new seed.
 *
 * Preconditions:
 *	cymric_init() succeeded
 *
 * Returns 0 on success.
 * Returns non-zero on error; it is important to check for this failure.
 */
extern int cymric_seed(cymric_rng *R, const void *seed, int bytes);

/*
 * Generate random bytes from a previously-initialized generator R
 *
 * This function is not thread-safe.
 *
 * Preconditions:
 * 	R must have been produced by cymric_seed()
 *
 * Returns 0 on success.
 * Returns non-zero on error; it is important to check for this failure.
 */
extern int cymric_random(cymric_rng *R, void *buffer, int bytes);

/*
 * Derive a new random generator from an existing generator R
 *
 * This is useful for when you want to create a new generator for a different
 * thread without reseeding.  This avoids blocking waiting for new random data.
 *
 * This function is not thread-safe.
 *
 * Preconditions:
 * 	source must have been produced by cymric_seed()
 *
 * Returns 0 on success.
 * Returns non-zero on error; it is important to check for this failure.
 */
extern int cymric_derive(cymric_rng *R, cymric_rng *source, const void *seed, int bytes);


#ifdef __cplusplus
}
#endif

#endif // CAT_CYMRIC_HPP

