#ifndef LYRA_H_
#define LYRA_H_

int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int saltSize, int timeCost, int blocksPerRow, int nRows, int kLen, unsigned char *K);

#endif /* LYRA_H_ */

