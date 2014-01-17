/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
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

#include "SecureErase.hpp"
using namespace cat;

#ifdef CAT_HAS_VECTOR_EXTENSIONS
typedef u64 vec_block __attribute__((ext_vector_type(4)));
#endif

#ifdef __cplusplus
extern "C" {
#endif

void cat_secure_erase(volatile void *data, int len) {
	// Calculate number of 64-bit words to erase, usually a multiple of 32 bytes
	int words = len >> 3;

	// Bulk erase blocks of 32 bytes at a time
#ifdef CAT_HAS_VECTOR_EXTENSIONS
	volatile u64 *word;
#ifdef CAT_WORD_64
	if (*(u64*)&data & 15) {
#else
	if (*(u32*)&data & 15) {
#endif
#endif
		word = (volatile u64 *)data;
		while (words >= 4) {
			word[0] = 0;
			word[1] = 0;
			word[2] = 0;
			word[3] = 0;
			words -= 4;
		}
#ifdef CAT_HAS_VECTOR_EXTENSIONS
	} else {
		// Usual case:
		volatile vec_block *block = (volatile vec_block *)data;
		while (words >= 4) {
			*block++ = 0;
			words -= 4;
		}
		word = (volatile u64 *)block;
	}
#endif // CAT_HAS_VECTOR_EXTENSIONS

	// Erase any remaining words
	while (words > 0) {
		*word++ = 0;
		--words;
	}

	// Erase odd numbers of words
	volatile char *ch = (volatile char *)word;
	switch (len & 7) {
	case 7:
		ch[6] = 0;
		//fall-thru
	case 6:
		ch[5] = 0;
		//fall-thru
	case 5:
		ch[4] = 0;
		//fall-thru
	case 4:
		*(volatile u32 *)ch = 0;
		break;
	case 3:
		ch[2] = 0;
		//fall-thru
	case 2:
		ch[1] = 0;
		//fall-thru
	case 1:
		ch[0] = 0;
		//fall-thru
	case 0:
	default:
		break;
	}
}

#ifdef __cplusplus
}
#endif

