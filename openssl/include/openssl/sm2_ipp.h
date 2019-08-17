#ifdef OPENSSL_WITH_INTEL
#ifndef __IPP_SM2_H__
#define __IPP_SM2_H__

#ifdef __cplusplus
extern "C"
{
#endif

int ipp_sm2_sign(unsigned char *dgst, int dgstlen, unsigned char *sig, int *siglen, unsigned char *prikey, int keylen);

int ipp_sm2_verify(unsigned char *dgst, int dgstlen, unsigned char *sig, int siglen, unsigned char *pubkey, int keylen);

int ipp_sm2_encrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen, unsigned char *pubkey, int keylen);

int ipp_sm2_decrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen, unsigned char *prikey, int keylen);

int ipp_sm2_compute_key(                                            \
    unsigned char *peer_id, int peer_id_len,                        \
    unsigned char *peer_pubkey, int peer_pubkey_len,                \
    unsigned char *peer_tmp_pubkey, int peer_tmp_pubkey_len,        \
    unsigned char *local_id, int local_id_len,                      \
    unsigned char *local_pubkey, int local_pubkey_len,              \
    unsigned char *local_prikey, int local_prikey_len,              \
    unsigned char *local_tmp_pubkey, int local_tmp_pubkey_len,      \
    unsigned char *local_tmp_prikey, int local_tmp_prikey_len,      \
    unsigned char *session_key, int session_key_len,                \
    int is_server                                                   \
    );

#ifdef __cplusplus
}
#endif

#endif
#endif
