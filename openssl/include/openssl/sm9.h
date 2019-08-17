#ifndef __SM9_H__
#define __SM9_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sms4.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifndef PRINT_HEX
#define PRINT_HEX(buf, len)                                                                         \
    do{                                                                                             \
        if(buf != NULL && len > 0)                                                                  \
        {                                                                                           \
            int loop = 0;                                                                           \
            for(loop = 0; loop < len; loop++)                                                       \
                printf("0x%02hhx%s", (unsigned char)buf[loop], (loop+1) % 16 != 0 ? ", " : ",\n");  \
            if(loop % 16 != 0) printf("\n");                                                        \
        }                                                                                           \
    }while(0);
#endif

#ifndef PRINT_STREAM
#define PRINT_STREAM(stream, length)                                                        \
    do{                                                                                     \
        int i;                                                                              \
        for(i = 0; i < length; i += 2)                                                      \
            printf("0x%c%c%s", stream[i], stream[i+1], (i+2) % 32 != 0 ? ", " : ",\n");     \
        if(i % 32 != 0) printf("\n");                                                       \
    }while(0);
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)

#define cpu_to_be16(v) (((v)<< 8) | ((v)>>8))
#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))
#define be16_to_cpu(v) cpu_to_be16(v)
#define be32_to_cpu(v) cpu_to_be32(v)
#else
#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)
#endif

#define SM9_BYTE_SIZE 32
#define SM9_BIT_SIZE 256

// 0x01: signature
// 0x02: keyexchange
// 0x03: encrypt
extern unsigned char hid[3];

// P2: 群G2的生成元
extern unsigned char sm9P2x1[32];
extern unsigned char sm9P2x2[32];

extern unsigned char sm9P2y1[32];
extern unsigned char sm9P2y2[32];

typedef enum {
    SM9_HID_SIGN    = 0x01,
    SM9_HID_EXCH    = 0x02,
    SM9_HID_ENC     = 0x03
}SM9_HID_st;

typedef enum {
    SM9_HASH1       = 0x01,
    SM9_HASH2       = 0x02
}SM9_HASH_st;

typedef struct
{
    BIGNUM *x;
    BIGNUM *y;
}BIGNUM_FP2;

typedef struct
{
    BIGNUM_FP2 *x;
    BIGNUM_FP2 *y;
}BIGNUM_FP4;

typedef struct
{
    BIGNUM_FP4 *x;
    BIGNUM_FP4 *y;
    BIGNUM_FP4 *z;
}BIGNUM_FP12;

typedef struct
{
    BIGNUM_FP2 *x;
    BIGNUM_FP2 *y;
    BIGNUM_FP2 *z;
}EC_POINT_FP2;


// SM9加密主密钥对
typedef struct SM9Cipher_Master_st
{
    BIGNUM *ke;                         // 加密主私钥
    EC_POINT *Ppube;                    // 加密主公钥
}SM9Cipher_Master;

// SM9加密用户密钥对
typedef struct SM9Cipher_User_st
{
    EC_POINT_FP2 *de;                   // 加密用户私钥
    ASN1_OCTET_STRING *id;              // 加密用户公钥
}SM9Cipher_User;

// SM9签名主密钥对
typedef struct SM9Signature_Master_st
{
    BIGNUM *ks;                         // 签名主私钥
    EC_POINT_FP2 *Ppubs;                // 签名主公钥
}SM9Signature_Master;

// SM9签名用户密钥对
typedef struct SM9Signature_User_st
{
    EC_POINT *ds;                       // 签名用户私钥
    ASN1_OCTET_STRING *id;              // 签名用户公钥
}SM9Signature_User;


// SM9加密数据
typedef struct SM9Cipher_st {
    ASN1_INTEGER *type;                 // 加密类型 0x00: sm3; 0x01: sm4-ecb; 0x02: sm4-cbc; 0x04: sm4-ofb; 0x08: sm4-cfb
    ASN1_OCTET_STRING *point;           // C1 G1元素
    ASN1_OCTET_STRING *hash;            // C3 杂凑值
    ASN1_OCTET_STRING *ciphertext;      // C2 密文
} SM9Cipher;
DECLARE_ASN1_FUNCTIONS(SM9Cipher);

// SM9签名数据
typedef struct SM9Signature_st {
    ASN1_OCTET_STRING *hash;            // h 杂凑值
    ASN1_OCTET_STRING *point;           // S G1元素
} SM9Signature;
DECLARE_ASN1_FUNCTIONS(SM9Signature);


int BN_set_hex(BIGNUM *r, unsigned char *hex, int hexlen);

int BN_fp2_hex(BIGNUM_FP2 *r, unsigned char *x, int xlen, unsigned char *y, int ylen);


void BN_fp2_print(BIGNUM_FP2 *a);

int BN_fp2_new(BIGNUM_FP2 **r);

int BN_fp2_free(BIGNUM_FP2 *r);

int BN_fp2_set_one(BIGNUM_FP2 *r);

int BN_fp2_set(BIGNUM_FP2 *r, BIGNUM *a, BIGNUM *b);


void BN_fp12_print(BIGNUM_FP12 *a);

int BN_fp12_new(BIGNUM_FP12 **r);

int BN_fp12_free(BIGNUM_FP12 *r);

int BN_fp12_set_one(BIGNUM_FP12 *r);

int BN_fp12_set_bn(BIGNUM_FP12 *r, BIGNUM *a);

int BN_fp12_mod_add(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM_FP12 *b, BIGNUM *m, BN_CTX *ctx);

int BN_fp12_mod_sub(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM_FP12 *b, BIGNUM *m, BN_CTX *ctx);

int BN_fp12_mod_mul(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM_FP12 *b, BIGNUM *m, BN_CTX *ctx);

int BN_fp12_mod_div(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM_FP12 *b, BIGNUM *m, BN_CTX *ctx);

// 平方
int BN_fp12_mod_sqr(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM *m, BN_CTX *ctx);

// 次方
int BN_fp12_mod_pow(BIGNUM_FP12 *r, BIGNUM_FP12 *a, BIGNUM *k, BIGNUM *m, BN_CTX *ctx);


int EC_POINT_fp12_get_affine_coordinates(EC_POINT_FP2 *p, BIGNUM_FP12 *x, BIGNUM_FP12 *y, BIGNUM *m, BN_CTX *ctx);

int EC_POINT_fp12_set_affine_coordinates(EC_POINT_FP2 *r, BIGNUM_FP12 *x, BIGNUM_FP12 *y, BIGNUM *m, BN_CTX *ctx);

int BN_fp12_to_bin(BIGNUM_FP12 *a, unsigned char to[384]);

int BN_fp12_from_bin(BIGNUM_FP12 *a, unsigned char from[384]);


void EC_POINT_fp2_print(EC_POINT_FP2 *p);

int EC_POINT_fp2_new(EC_POINT_FP2 **r);

int EC_POINT_fp2_free(EC_POINT_FP2 *p);

int EC_POINT_fp2_get_affine_coordinates(EC_POINT_FP2 *p, BIGNUM_FP2 *x, BIGNUM_FP2 *y);

int EC_POINT_fp2_set_affine_coordinates(EC_POINT_FP2 *r, BIGNUM_FP2 *x, BIGNUM_FP2 *y);

int EC_POINT_fp2_copy(EC_POINT_FP2 *r, EC_POINT_FP2 *p);

// r = 2 * p = p + p
int EC_POINT_fp2_mod_dbl(EC_POINT_FP2 *r, EC_POINT_FP2 *p, BIGNUM *m, BN_CTX *ctx);

// r = p + q
int EC_POINT_fp2_mod_add(EC_POINT_FP2 *r, EC_POINT_FP2 *p, EC_POINT_FP2 *q, BIGNUM *m, BN_CTX *ctx);

// 取反
int EC_POINT_fp2_mod_neg(EC_POINT_FP2 *r, EC_POINT_FP2 *p, BIGNUM *m, BN_CTX *ctx);

// r = p - q
int EC_POINT_fp2_mod_sub(EC_POINT_FP2 *r, EC_POINT_FP2 *p, EC_POINT_FP2 *q, BIGNUM *m, BN_CTX *ctx);

// 点 = 数 * 点
// r = k * p
int EC_POINT_fp2_mod_mul(EC_POINT_FP2 *r, EC_POINT_FP2 *p, BIGNUM *k, BIGNUM *m, BN_CTX *ctx);

int EC_POINT_fp2_get_generator(EC_POINT_FP2 *r);

int EC_POINT_fp2_to_bin(EC_POINT_FP2 *a, unsigned char to[129]);

int EC_POINT_fp2_from_bin(EC_POINT_FP2 *a, unsigned char from[129]);


// πq(x, y) = (x^q, y^q)
int openssl_sm9_frobenius(EC_POINT_FP2 *r, EC_POINT_FP2 *p, BIGNUM *m, BN_CTX *ctx);

// πq^2(x, y) = (x^(q^2), y^(q^2))
int openssl_sm9_frobenius_sqr(EC_POINT_FP2 *r, EC_POINT_FP2 *p, BIGNUM *m, BN_CTX *ctx);

// 切线 T == Q
// T = T + Q = 2 * T
int openssl_sm9_eval_dbl(BIGNUM_FP12 *r, EC_POINT_FP2 *t, BIGNUM *x, BIGNUM *y, BIGNUM *m, BN_CTX *ctx);

// 直线 T != Q
// T = T + Q
int openssl_sm9_eval_add(BIGNUM_FP12 *r, EC_POINT_FP2 *t, EC_POINT_FP2 *q, BIGNUM *x, BIGNUM *y, BIGNUM *m, BN_CTX *ctx);

int openssl_sm9_rate(BIGNUM_FP12 *f, EC_POINT_FP2 *Q, BIGNUM *x, BIGNUM *y, BIGNUM *a, BIGNUM *k, BIGNUM *p, BN_CTX *ctx);

int openssl_sm9_rate_pairing(BIGNUM_FP12 *f, EC_POINT_FP2 *Q, EC_POINT *P, BN_CTX *ctx);

int openssl_sm9_rate_test(void);


int openssl_sm9_hash1(const EVP_MD *md, unsigned char *zbuf, int zlen, BIGNUM *n, BIGNUM *hr);

int openssl_sm9_hash2(const EVP_MD *md, unsigned char *zbuf, int zlen, BIGNUM *n, BIGNUM *hr);

int openssl_sm9_kdf(const EVP_MD *md, unsigned char *in, int inlen, unsigned char *out, int outlen);


// 生成SM9加密主密钥对
int openssl_sm9_cipher_master_create(SM9Cipher_Master **master);

// 派生SM9加密用户私钥
int openssl_sm9_cipher_user_derive(SM9Cipher_Master *master, unsigned char *id, int idlen, SM9Cipher_User **user);

// 释放SM9加密用户私钥
int openssl_sm9_cipher_user_release(SM9Cipher_User *user);

// 销毁SM9加密主密钥对
int openssl_sm9_cipher_master_destroy(SM9Cipher_Master *master);

int openssl_sm9_encrypt(int type, unsigned char *in, int inlen, unsigned char *out, unsigned char *id, int idlen, EC_POINT *Ppube);

int openssl_sm9_decrypt(int type, unsigned char *in, int inlen, unsigned char *out, unsigned char *id, int idlen, EC_POINT_FP2 *de);

int openssl_sm9_enc_test(void);


// 生成SM9签名主密钥对
int openssl_sm9_sign_master_create(SM9Signature_Master **master);

// 派生SM9签名用户私钥
int openssl_sm9_sign_user_derive(SM9Signature_Master *master, unsigned char *id, int idlen, SM9Signature_User **user);

// 释放SM9签名用户私钥
int openssl_sm9_sign_user_release(SM9Signature_User *user);

// 销毁SM9签名主密钥对
int openssl_sm9_sign_master_destroy(SM9Signature_Master *master);

int openssl_sm9_sign(int type, unsigned char *dgst, int dgstlen, unsigned char *sign, int *signlen, EC_POINT_FP2 *Ppubs, EC_POINT *ds);

int openssl_sm9_verify(int type, unsigned char *dgst, int dgstlen, unsigned char *sign, int signlen, unsigned char *id, int idlen, EC_POINT_FP2 *Ppubs);

int openssl_sm9_sign_test(void);


// 派生SM9密钥交换用户私钥
int openssl_sm9_exch_user_derive(SM9Cipher_Master *master, unsigned char *id, int idlen, SM9Cipher_User **user);

// 释放SM9密钥交换用户私钥
int openssl_sm9_exch_user_release(SM9Cipher_User *user);

int openssl_sm9_generate_key(int type, unsigned char *peer_id, int peer_idlen, BIGNUM *self_r, EC_POINT *self_R, EC_POINT *Ppube);

int openssl_sm9_compute_key(int type, unsigned char *peer_id, int peer_idlen, EC_POINT *peer_R, unsigned char *self_id, int self_idlen, BIGNUM *self_r, EC_POINT *self_R, \
    EC_POINT_FP2 *self_de, EC_POINT *Ppube, int isServer, unsigned char *sk, int sklen);

int openssl_sm9_exch_test(void);

#endif
