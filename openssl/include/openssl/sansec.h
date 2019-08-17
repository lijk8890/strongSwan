#ifdef OPENSSL_WITH_SANSEC
#ifndef __SANSEC_H__
#define __SANSEC_H__

#ifdef __cplusplus
extern "C"
{
#endif

int sansec_random(unsigned char *in, unsigned int inlen);

int _SDF_GenerateRandom(void *hSessionHandle, unsigned char *in, unsigned int inlen);

#ifdef __cplusplus
}
#endif

#endif
#endif
