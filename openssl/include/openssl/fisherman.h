#ifdef OPENSSL_WITH_FISHERMAN
#ifndef __FISHERMAN_H__
#define __FISHERMAN_H__

#ifdef __cplusplus
extern "C"
{
#endif

int fisherman_random(unsigned char *in, unsigned int inlen);

int fisherman_sm2sign(unsigned char *dgst, unsigned int dgstlen, unsigned char *sig, unsigned int *siglen);

int fisherman_sm2verify(unsigned char *dgst, unsigned int dgstlen, unsigned char *sig, unsigned int siglen);

int fisherman_sm2encrypt(unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);

int fisherman_sm2decrypt(unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);

#ifdef __cplusplus
}
#endif

#endif
#endif
