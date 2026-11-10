/* crypto.c : RSA-2048 OAEP-SHA256 via CNG (bcrypt).
 *
 * RSA cannot encrypt an arbitrary-length record in one shot: with a 2048-bit
 * key and OAEP/SHA-256 the per-block ceiling is 190 bytes, and one event line
 * is longer than that. Payloads are therefore split into 190-byte chunks and
 * each chunk is encrypted on its own (same key, independent OAEP salts). The
 * collector walks the 256-byte ciphertext blocks and concatenates the pieces.
 */

#include "crypto.h"
#include <bcrypt.h>

static const BCRYPT_OAEP_PADDING_INFO g_oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };

void CryptoFree(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static void *AllocZero(SIZE_T n)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}

static DWORD RsaBlockSize(const BYTE *blob)
{
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    if (!blob) return 0;
    return h->BitLength / 8;
}

/* --------------------------------------------------------------------- */

BOOL RsaGenerateKeyPair(BYTE **pub, DWORD *pubLen, BYTE **priv, DWORD *privLen)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD need = 0;

    *pub = NULL;
    *priv = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptGenerateKeyPair(alg, &key, 2048, 0) != 0) goto fail;
    if (BCryptFinalizeKeyPair(key, 0) != 0) goto fail;

    if (BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &need, 0) != 0)
        goto fail;
    *pub = (BYTE *)AllocZero(need);
    if (!*pub) goto fail;
    if (BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, *pub, need, &need, 0) != 0)
        goto fail;
    *pubLen = need;

    need = 0;
    if (BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &need, 0) != 0)
        goto fail;
    *priv = (BYTE *)AllocZero(need);
    if (!*priv) goto fail;
    if (BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, *priv, need, &need, 0) != 0)
        goto fail;
    *privLen = need;

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return TRUE;

fail:
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CryptoFree(*pub);
    CryptoFree(*priv);
    *pub = NULL;
    *priv = NULL;
    return FALSE;
}

/* --------------------------------------------------------------------- */

BOOL RsaEncrypt(const BYTE *pub, DWORD pubLen, const BYTE *in, DWORD inLen,
                BYTE **out, DWORD *outLen)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD blockSize, maxChunk, nBlocks, i, off = 0;
    BYTE *buf = NULL;
    BOOL ok = FALSE;

    *out = NULL;
    *outLen = 0;
    if (!pub || !in || !inLen) return FALSE;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &key,
                            (PUCHAR)pub, pubLen, 0) != 0)
        goto done;

    blockSize = RsaBlockSize(pub);
    if (blockSize < 64 || blockSize > 1024) goto done;
    maxChunk = blockSize - 66;             /* OAEP/SHA-256 overhead */
    if (!maxChunk) goto done;

    nBlocks = (inLen + maxChunk - 1) / maxChunk;
    buf = (BYTE *)AllocZero((SIZE_T)nBlocks * blockSize);
    if (!buf) goto done;

    for (i = 0; i < nBlocks; i++) {
        DWORD chunk = inLen - off;
        DWORD written = 0;
        if (chunk > maxChunk) chunk = maxChunk;
        if (BCryptEncrypt(key, (PUCHAR)in + off, chunk, (PVOID)&g_oaep,
                          NULL, 0, buf + (SIZE_T)i * blockSize, blockSize,
                          &written, BCRYPT_PAD_OAEP) != 0)
            goto done;
        off += chunk;
    }
    *out = buf;
    *outLen = nBlocks * blockSize;
    buf = NULL;
    ok = TRUE;

done:
    CryptoFree(buf);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

BOOL RsaDecrypt(const BYTE *priv, DWORD privLen, const BYTE *in, DWORD inLen,
                BYTE **out, DWORD *outLen)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD blockSize, nBlocks, i, off = 0;
    BYTE *buf = NULL;
    BOOL ok = FALSE;

    *out = NULL;
    *outLen = 0;
    if (!priv || !in || !inLen) return FALSE;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPRIVATE_BLOB, &key,
                            (PUCHAR)priv, privLen, 0) != 0)
        goto done;

    blockSize = RsaBlockSize(priv);
    if (blockSize < 64 || inLen % blockSize) goto done;
    nBlocks = inLen / blockSize;

    buf = (BYTE *)AllocZero((SIZE_T)nBlocks * blockSize + 1);
    if (!buf) goto done;

    for (i = 0; i < nBlocks; i++) {
        DWORD written = 0;
        if (BCryptDecrypt(key, (PUCHAR)in + (SIZE_T)i * blockSize, blockSize,
                          (PVOID)&g_oaep, NULL, 0,
                          buf + off, nBlocks * blockSize - off,
                          &written, BCRYPT_PAD_OAEP) != 0)
            goto done;
        off += written;
    }
    buf[off] = 0;
    *out = buf;
    *outLen = off;
    buf = NULL;
    ok = TRUE;

done:
    CryptoFree(buf);
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* --------------------------------------------------------------------- */
/* base64 (transport encoding only)                                      */
/* --------------------------------------------------------------------- */

static const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *B64Encode(const BYTE *in, DWORD inLen)
{
    DWORD outLen = 4 * ((inLen + 2) / 3);
    char *out = (char *)AllocZero(outLen + 1);
    DWORD i, o = 0;

    if (!out) return NULL;
    for (i = 0; i + 2 < inLen; i += 3) {
        DWORD v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = kB64[(v >> 18) & 63];
        out[o++] = kB64[(v >> 12) & 63];
        out[o++] = kB64[(v >> 6) & 63];
        out[o++] = kB64[v & 63];
    }
    if (i < inLen) {
        DWORD v = in[i] << 16;
        DWORD rem = inLen - i;
        if (rem == 2) v |= in[i + 1] << 8;
        out[o++] = kB64[(v >> 18) & 63];
        out[o++] = kB64[(v >> 12) & 63];
        out[o++] = (rem == 2) ? kB64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return out;
}

static int B64Val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

BYTE *B64Decode(const char *in, DWORD *outLen)
{
    DWORD len, i, o = 0;
    BYTE *out;
    DWORD acc = 0;
    int bits = 0;

    *outLen = 0;
    if (!in) return NULL;
    len = (DWORD)strlen(in);
    out = (BYTE *)AllocZero(len + 4);
    if (!out) return NULL;

    for (i = 0; i < len; i++) {
        int v = B64Val(in[i]);
        if (v < 0) {
            if (in[i] == '=') break;
            continue;                       /* skip CR/LF/space */
        }
        acc = (acc << 6) | (DWORD)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (BYTE)((acc >> bits) & 0xFF);
        }
    }
    *outLen = o;
    return out;
}
