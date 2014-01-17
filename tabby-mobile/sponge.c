/*
  Implementation of a sponge function that uses the F function from Blake 2

  Author: Leonardo de Campos Almeida
 */

#include <string.h>
#include <stdio.h>
#include "sponge.h"

/**
 Initializes the Sponge State. The first 512 bits are set to 0 and the remainder receives the value of Blake2 IV
*/
void initState(spongeState *state){
    memset(state->state, 0, 64);
    memcpy(state->state + 64, blake2b_IV, sizeof(blake2b_IV));
}

/**
 Execute full Blake's G function, with all 12 rounds
 Input:
    v - An array of 64-bit integers to be processed by Blake's G function
*/
static inline void blake2bLyra(uint64_t *v){
      ROUND_LYRA( 0 );
      ROUND_LYRA( 1 );
      ROUND_LYRA( 2 );
      ROUND_LYRA( 3 );
      ROUND_LYRA( 4 );
      ROUND_LYRA( 5 );
      ROUND_LYRA( 6 );
      ROUND_LYRA( 7 );
      ROUND_LYRA( 8 );
      ROUND_LYRA( 9 );
      ROUND_LYRA( 10 );
      ROUND_LYRA( 11 );
}

/**
 Executes a reduced version of Blake's G function with only one round
 Input:
    v - An array of 64-bit integers to be processed by Blake's G function
*/
static inline void reducedBlake2bLyra( uint64_t *v){
    ROUND_LYRA( 0 );
}

/**
 Perform a sponge absorb, using Blake's G function as the internal permutation
 Inputs:
 	 state - the sponge state
 	 in - array of unsigned chars to be absorbed
 	 inLen - length of the input array, in bits
 */
void absorb(spongeState *state, const unsigned char *in, unsigned int inLen){
	int fullBlocks = inLen/512;
	int countBlocks;
	int i;

	for (countBlocks = 0 ; countBlocks < fullBlocks ; countBlocks++){
		for(i = 0; i < 64 ; i++){
			state->state[i] ^= in[i + countBlocks*64];
		}
		blake2bLyra((uint64_t*)state->state);
	}
}

/**
 Performs a sponge Squeeze, using reduced Blake's G function as the internal permutation
 Inputs:
 	 state - the sponge state
 Outputs:
 	 out - array that will receive the data squeezed
 	 outLen - length of the output array, in bits
*/
void reducedSqueeze(spongeState *state, unsigned char *out, unsigned int outLen){
	int fullBlocks = outLen/512;
	int countBlocks;
	for (countBlocks = 0 ; countBlocks < fullBlocks ; countBlocks++){
		memcpy(out + (size_t)(countBlocks*64), state->state, 64);
		reducedBlake2bLyra((uint64_t*)state->state);
	}
}

/**
 Performs a sponge Squeeze, using Blake's G function as the internal permutation
 Inputs:
 	 state - the sponge state
 Outputs:
 	 out - array that will receive the data squeezed
 	 outLen - length of the output array, in bits
*/
void squeeze(spongeState *state, unsigned char *out, unsigned int outLen){
	int fullBlocks = outLen/512;
	int countBlocks;
	for (countBlocks = 0 ; countBlocks < fullBlocks ; countBlocks++){
		memcpy(out + (size_t)(countBlocks*64), state->state, 64);
		blake2bLyra((uint64_t*)state->state);
	}
}

/**
 Performs a sponge duplex operation, using Blake's G function as internal permutation
 Inputs:
 	 state - the sponge state
 	 in - array of unsigned chars
 	 inLen - length of the input array, in bits
 Outputs:
     out - array that will receive the data
 	 outLen - length of the output array, in bits
*/
void duplex(spongeState *state, const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen){
	int i;
	for(i = 0; i < 64 ; i++){
		state->state[i] ^= in[i];
	}
	blake2bLyra((uint64_t*)state->state);
	memcpy(out, state->state, 64);
}

/**
 Performs a sponge duplex operation, using reduced Blake's G function as internal permutation
 Inputs:
 	 state - the sponge state
 	 in - array of unsigned chars
 	 inLen - length of the input array, in bits
 Outputs:
     out - array that will receive the data
 	 outLen - length of the output array, in bits
*/
void reducedDuplex(spongeState *state, const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen){
	int i;
	for(i = 0; i < 64 ; i++){
		state->state[i] ^= in[i];
	}
	reducedBlake2bLyra((uint64_t*)state->state);
	memcpy(out, state->state, (outLen+7)/8);
}


