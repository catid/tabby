/**
 Implementation of Lyra.

 Author: Leonardo de Campos Almeida.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "lyra.h"
#include "sponge.h"


/**
 Executes Lyra based on the G function from Blake 2.

 Number of columns set to 64.

 Inputs:
 	 in - user password
 	 inlen - password size
 	 salt - salt
 	 saltlen - salt size
 	 t_cost - parameter to determine the processing time
 	 m_cost - number or rows of the inner matrix, determining the memory cost.
 	 outlen - derived key length
 Output:
 	 out - derived key
 */
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost){
	return lyra(in, inlen, salt, saltlen, t_cost, 64, m_cost, outlen, out);
}

/**
 Executes Lyra based on the G function from Blake 2.

 Inputs:
 	 pwd - user password
 	 pwdSize - password size
 	 salt - salt
 	 saltSize - salt size
 	 timeCost - parameter to determine the processing time
 	 nCols - number of columns of the inner matrix
 	 nRows - number or rows of the inner matrix
 	 kLen - derived key length
 Output:
 	 K - derived key
 */
int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int saltSize, int timeCost, int nCols, int nRows, int kLen, unsigned char *K){
	int bLen = 64;

	int ROW_SIZE = nCols * bLen;
	int BLEN_BITS = bLen * 8;

	int blocks = ceil((double)(pwdSize + saltSize)/(double)64);
	int inputSize = bLen * blocks;

	ALIGN unsigned char *in = calloc(sizeof in, (bLen));
	ALIGN unsigned char *temp = calloc(sizeof temp, (bLen));
	ALIGN unsigned char **M = malloc(sizeof(unsigned char*) * nRows);
	ALIGN unsigned char *spongeInput = calloc(sizeof spongeInput, inputSize);
	spongeState spongeState;
	int row;
	int i,j,c,k,count,l, r = 0;

	if(kLen > bLen){
		return -1;
	}

    /*
    Initializing the Sponge State
    */
	initState(&spongeState);

    /*
    Initializing the array with salt + password padded with 10b1
    */
	memcpy(spongeInput, salt, saltSize);
	memcpy(spongeInput + (size_t)saltSize, pwd, pwdSize);
	spongeInput[pwdSize + saltSize] = 0x80;
	spongeInput[inputSize - 1] = 1;

	/*
	Setup Phase
	*/
	absorb(&spongeState, spongeInput, BLEN_BITS);

	M[0] = malloc(sizeof(unsigned char) * (ROW_SIZE));
	reducedSqueeze(&spongeState, M[0], ROW_SIZE * 8);
	for (row = 1 ; row < nRows ; row++){
		M[row] = malloc(sizeof(unsigned char) * (ROW_SIZE));
		for(c = 0 ; c < nCols ; c++){
			int cBlen = bLen * c;
			memcpy(in, M[row - 1] + (size_t)(cBlen), bLen);
			reducedDuplex(&spongeState, in, BLEN_BITS, temp, BLEN_BITS);
			memcpy(M[row] + (size_t)(cBlen), temp, bLen);
		}
	}

	/*
	Wandering phase
	*/
	for (i = 0 ; i < timeCost ; i++){
		for (j = 0 ; j < nRows ; j++){
            for (c = 0 ; c < nCols ; c++){
				int cBlen = bLen * c;
            	memcpy(in, M[r] + (size_t)(cBlen), bLen);
				reducedDuplex(&spongeState, in, BLEN_BITS, temp, BLEN_BITS);
				k = cBlen;
				for (l = 0 ; l < bLen ; l++){
					M[r][k++] = in[l] ^ temp[l];
				}
			}
			memcpy(in, M[r] + (size_t)((bLen) * (c-1)), bLen);

			uint64_t* currentRow = (uint64_t*)M[r];
			int col = currentRow[nCols - 1] % nCols;

			memcpy(in, currentRow + (size_t)(col), 64);

			duplex(&spongeState, in, 64, temp, 64);
			uint64_t* nextRow = (uint64_t*)temp;
			r = nextRow[0] % nRows;
		}
	}

    /*
     Padding the salt
     */
	blocks = ceil((double)saltSize/(double)64);
	inputSize = bLen * blocks;

	memset(spongeInput, 0, inputSize);
	memcpy(spongeInput, salt, saltSize);
	spongeInput[saltSize] = 0x80;
	spongeInput[inputSize - 1] = 1;
	/*
	Finalizing phase.
	*/
	absorb(&spongeState, spongeInput, BLEN_BITS);
	squeeze(&spongeState, K, kLen * 8);

    /*
    Freeing the memory
    */
	free(temp);
	free(in);
	for (count = 0 ; count < nRows ; count++){
		free(M[count]);
	}
	free(M);
	free(spongeInput);

	return 0;
}

