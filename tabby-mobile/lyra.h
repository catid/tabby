#ifndef LYRA_H_
#define LYRA_H_

#ifdef __cplusplus
extern "C" {
#endif

int lyra(const unsigned char *pwd, int pwdSize, const unsigned char *salt, int saltSize, int timeCost, int blocksPerRow, int nRows, int kLen, unsigned char *K);

#ifdef __cplusplus
}
#endif

#endif /* LYRA_H_ */

