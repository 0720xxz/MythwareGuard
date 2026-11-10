/* crypto.h : RSA-2048 (OAEP-SHA256) helpers + base64, CNG based. */
#ifndef MWG_CRYPTO_H
#define MWG_CRYPTO_H

#include <windows.h>

BOOL  RsaGenerateKeyPair(BYTE **pub, DWORD *pubLen, BYTE **priv, DWORD *privLen);
BOOL  RsaEncrypt(const BYTE *pub, DWORD pubLen, const BYTE *in, DWORD inLen,
                 BYTE **out, DWORD *outLen);
BOOL  RsaDecrypt(const BYTE *priv, DWORD privLen, const BYTE *in, DWORD inLen,
                 BYTE **out, DWORD *outLen);
char *B64Encode(const BYTE *in, DWORD inLen);
BYTE *B64Decode(const char *in, DWORD *outLen);
void  CryptoFree(void *p);

#endif /* MWG_CRYPTO_H */
