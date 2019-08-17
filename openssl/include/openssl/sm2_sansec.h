#ifdef OPENSSL_WITH_SANSEC
#ifndef __SM2_SANSEC_H__
#define __SM2_SANSEC_H__

/**
 * @当前仅适用PCI卡1号容器
 * @奇数存签名私钥, 偶数存加密私钥
**/

#include "swsds.h"

int _SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucSignature, SGD_UINT32 *puiSignatureLength);

int _SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucPublicKey, SGD_UINT32 uiPublicKeyLength, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
    SGD_UCHAR *pucSignature, SGD_UINT32 uiSignatureLength);


int _SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucPublicKey, SGD_UINT32 uiPublicKeyLength, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, \
    SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLength);

int _SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, \
    SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);

#endif
#endif
