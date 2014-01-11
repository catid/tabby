#ifndef LYRA_H_
#define LYRA_H_

int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int saltSize, int timeCost, int blocksPerRow, int nRows, int kLen, unsigned char *K);

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#endif /* LYRA_H_ */

