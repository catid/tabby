#include <stddef.h>
#include <stdint.h>

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static uint32_t
U8TO32(const uint8_t *p) {
	return
		(((uint32_t)(p[0])      ) |
	     ((uint32_t)(p[1]) <<  8) |
         ((uint32_t)(p[2]) << 16) |
         ((uint32_t)(p[3]) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(uint8_t *p, uint32_t v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

/* 32 bit left rotate */
static uint32_t
ROTL32(uint32_t x, int k) {
	return ((x << k) | (x >> (32 - k))) & 0xffffffff;
}

/* "expand 32-byte k", as 4 little endian 32-bit unsigned integers */
static const uint32_t chacha_constants[4] = { 
	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

typedef struct chacha_state_t {
	uint8_t s[48];
	size_t rounds;
} chacha_state;

void
chacha_blocks_ref(chacha_state *state, const uint8_t *in, uint8_t *out, size_t bytes) {
	uint32_t x[16], j[12];
	uint32_t t;
	uint8_t *ctarget = out, tmp[64];
	size_t i, r;

	if (!bytes) return;

	j[0] = U8TO32(state->s + 0);
	j[1] = U8TO32(state->s + 4);
	j[2] = U8TO32(state->s + 8);
	j[3] = U8TO32(state->s + 12);
	j[4] = U8TO32(state->s + 16);
	j[5] = U8TO32(state->s + 20);
	j[6] = U8TO32(state->s + 24);
	j[7] = U8TO32(state->s + 28);
	j[8] = U8TO32(state->s + 32);
	j[9] = U8TO32(state->s + 36);
	j[10] = U8TO32(state->s + 40);
	j[11] = U8TO32(state->s + 44);

	r = state->rounds;

	for (;;) {
		if (bytes < 64) {
			if (in) {
				for (i = 0; i < bytes; i++) tmp[i] = in[i];
				in = tmp;
			}
			ctarget = out;
			out = tmp;
		}

		x[0] = chacha_constants[0];
		x[1] = chacha_constants[1];
		x[2] = chacha_constants[2];
		x[3] = chacha_constants[3];
		x[4] = j[0];
		x[5] = j[1];
		x[6] = j[2];
		x[7] = j[3];
		x[8] = j[4];
		x[9] = j[5];
		x[10] = j[6];
		x[11] = j[7];
		x[12] = j[8];
		x[13] = j[9];
		x[14] = j[10];
		x[15] = j[11];

		#define quarter(a,b,c,d) \
			a += b; t = d^a; d = ROTL32(t,16); \
			c += d; t = b^c; b = ROTL32(t,12); \
			a += b; t = d^a; d = ROTL32(t, 8); \
			c += d; t = b^c; b = ROTL32(t, 7);

		#define doubleround() \
			quarter( x[0], x[4], x[8],x[12]) \
			quarter( x[1], x[5], x[9],x[13]) \
			quarter( x[2], x[6],x[10],x[14]) \
			quarter( x[3], x[7],x[11],x[15]) \
			quarter( x[0], x[5],x[10],x[15]) \
			quarter( x[1], x[6],x[11],x[12]) \
			quarter( x[2], x[7], x[8],x[13]) \
			quarter( x[3], x[4], x[9],x[14])

		i = r;
		do {
			doubleround()
			i -= 2;
		} while (i);

		x[0] += chacha_constants[0];
		x[1] += chacha_constants[1];
		x[2] += chacha_constants[2];
		x[3] += chacha_constants[3];
		x[4] += j[0];
		x[5] += j[1];
		x[6] += j[2];
		x[7] += j[3];
		x[8] += j[4];
		x[9] += j[5];
		x[10] += j[6];
		x[11] += j[7];
		x[12] += j[8];
		x[13] += j[9];
		x[14] += j[10];
		x[15] += j[11];

		if (in) {
			U32TO8(out +  0,  x[0] ^ U8TO32(in +  0));
			U32TO8(out +  4,  x[1] ^ U8TO32(in +  4));
			U32TO8(out +  8,  x[2] ^ U8TO32(in +  8));
			U32TO8(out + 12,  x[3] ^ U8TO32(in + 12));
			U32TO8(out + 16,  x[4] ^ U8TO32(in + 16));
			U32TO8(out + 20,  x[5] ^ U8TO32(in + 20));
			U32TO8(out + 24,  x[6] ^ U8TO32(in + 24));
			U32TO8(out + 28,  x[7] ^ U8TO32(in + 28));
			U32TO8(out + 32,  x[8] ^ U8TO32(in + 32));
			U32TO8(out + 36,  x[9] ^ U8TO32(in + 36));
			U32TO8(out + 40, x[10] ^ U8TO32(in + 40));
			U32TO8(out + 44, x[11] ^ U8TO32(in + 44));
			U32TO8(out + 48, x[12] ^ U8TO32(in + 48));
			U32TO8(out + 52, x[13] ^ U8TO32(in + 52));
			U32TO8(out + 56, x[14] ^ U8TO32(in + 56));
			U32TO8(out + 60, x[15] ^ U8TO32(in + 60));
			in += 64;
		} else {
			U32TO8(out +  0,  x[0]);
			U32TO8(out +  4,  x[1]);
			U32TO8(out +  8,  x[2]);
			U32TO8(out + 12,  x[3]);
			U32TO8(out + 16,  x[4]);
			U32TO8(out + 20,  x[5]);
			U32TO8(out + 24,  x[6]);
			U32TO8(out + 28,  x[7]);
			U32TO8(out + 32,  x[8]);
			U32TO8(out + 36,  x[9]);
			U32TO8(out + 40, x[10]);
			U32TO8(out + 44, x[11]);
			U32TO8(out + 48, x[12]);
			U32TO8(out + 52, x[13]);
			U32TO8(out + 56, x[14]);
			U32TO8(out + 60, x[15]);
		}

		/* increment the 64 bit counter, split in to two 32 bit halves */
		j[8]++;
		if (!j[8])
			j[9]++;

		if (bytes <= 64) {
			if (bytes < 64) for (i = 0; i < bytes; i++) ctarget[i] = out[i];

			/* store the counter back to the state */
			U32TO8(state->s + 32, j[8]);
			U32TO8(state->s + 36, j[9]);
			return;
		}
		bytes -= 64;
		out += 64;
	}
}


void
hchacha_ref(const uint8_t key[32], const uint8_t iv[16], uint8_t out[32], size_t rounds) {
	uint32_t x[16];
	uint32_t t;

	x[0] = chacha_constants[0];
	x[1] = chacha_constants[1];
	x[2] = chacha_constants[2];
	x[3] = chacha_constants[3];
	x[4] = U8TO32(key + 0);
	x[5] = U8TO32(key + 4);
	x[6] = U8TO32(key + 8);
	x[7] = U8TO32(key + 12);
	x[8] = U8TO32(key + 16);
	x[9] = U8TO32(key + 20);
	x[10] = U8TO32(key + 24);
	x[11] = U8TO32(key + 28);
	x[12] = U8TO32(iv + 0);
	x[13] = U8TO32(iv + 4);
	x[14] = U8TO32(iv + 8);
	x[15] = U8TO32(iv + 12);

	do {
		doubleround()
		rounds -= 2;
	} while (rounds);

	/* indices for the chacha constant */
	U32TO8(out + 0, x[0]);
	U32TO8(out + 4, x[1]);
	U32TO8(out + 8, x[2]);
	U32TO8(out + 12, x[3]);

	/* indices for the iv */
	U32TO8(out + 16, x[12]);
	U32TO8(out + 20, x[13]);
	U32TO8(out + 24, x[14]);
	U32TO8(out + 28, x[15]);
}
