/* See src/Crypto/wolfCrypt.md */

#include "Aes.h"
#include "Sha2.h"
#include "../Common/Crypto.h"
#include <wolfssl/wolfcrypt/hmac.h>


AES_RETURN aes_init()
{
#if defined( AES_ERR_CHK )
    return EXIT_SUCCESS;
#else
    return;
#endif
}

AES_RETURN aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
{
    int ret = 0;

    ret = wc_AesInit(&cx->wc_enc_aes, NULL, INVALID_DEVID);

    if (key_len == 128 || key_len == 192 || key_len == 256)
        key_len = key_len/8;

    if (ret == 0) {
        ret = wc_AesSetKey(&cx->wc_enc_aes, key, key_len, NULL, AES_ENCRYPTION);
    }

#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif
}

AES_RETURN aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1])
{
    int ret = 0;

    ret = wc_AesInit(&cx->wc_dec_aes, NULL, INVALID_DEVID);

    if (key_len == 128 || key_len == 192 || key_len == 256)
        key_len = key_len/8;

    if (ret == 0) {
        ret = wc_AesSetKey(&cx->wc_dec_aes, key, key_len, NULL, AES_DECRYPTION);
    }

#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif
}

AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    return aes_encrypt_key(key, 128, cx);
}

AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    return aes_encrypt_key(key, 192, cx);
}

AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    return aes_encrypt_key(key, 256, cx);
}

AES_RETURN aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    return aes_decrypt_key(key, 128, cx);
}

AES_RETURN aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    return aes_decrypt_key(key, 192, cx);
}

AES_RETURN aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    return aes_decrypt_key(key, 256, cx);
}

AES_RETURN aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1])
{
    int ret = wc_AesEncryptDirect(&cx->wc_enc_aes, out, in);
#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif

}

AES_RETURN aes_decrypt(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1])
{
    int ret = wc_AesDecryptDirect(&cx->wc_dec_aes, out, in);
#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif

}

AES_RETURN xts_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
{
    int ret = 0;

    cx->wc_enc_xts.aes = cx->wc_enc_aes;

    ret = wc_AesInit(&cx->wc_enc_xts.tweak, NULL, INVALID_DEVID);

    if (key_len == 128 || key_len == 192 || key_len == 256)
        key_len = key_len/8;

    if (ret == 0) {
        ret = wc_AesSetKey(&cx->wc_enc_xts.tweak, key, key_len, NULL, AES_ENCRYPTION);
    }
#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif
}

AES_RETURN xts_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1])
{
    int ret = 0;

    cx->wc_dec_xts.aes = cx->wc_dec_aes;

    ret = wc_AesInit(&cx->wc_dec_xts.tweak, NULL, INVALID_DEVID);

    if (key_len == 128 || key_len == 192 || key_len == 256)
        key_len = key_len/8;

    if (ret == 0) {
        ret = wc_AesSetKey(&cx->wc_dec_xts.tweak, key, key_len, NULL, AES_ENCRYPTION);
    }

#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif
}

AES_RETURN xts_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    return xts_encrypt_key(key, 256, cx);
}

AES_RETURN xts_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    return xts_decrypt_key(key, 256, cx);
}

AES_RETURN xts_encrypt(const unsigned char *in, unsigned char *out, word64 length, word64 sector, const aes_encrypt_ctx cx[1])
{
    int ret = wc_AesXtsEncryptConsecutiveSectors(&cx->wc_enc_xts, out, in, length, sector, ENCRYPTION_DATA_UNIT_SIZE);

#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif

}

AES_RETURN xts_decrypt(const unsigned char *in, unsigned char *out, word64 length, word64 sector, const aes_decrypt_ctx cx[1])
{
    int ret = wc_AesXtsDecryptConsecutiveSectors(&cx->wc_dec_xts, out, in, length, sector, ENCRYPTION_DATA_UNIT_SIZE);

#if defined( AES_ERR_CHK )
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    return;
#endif
}


void sha256_begin(sha256_ctx* ctx)
{
    wc_InitSha256(ctx);
}

void sha256_hash(const unsigned char * source, uint_32t sourceLen, sha256_ctx *ctx)
{
    wc_Sha256Update(ctx, source, sourceLen);
}

void sha256_end(unsigned char * result, sha256_ctx* ctx)
{
    wc_Sha256Final(ctx, result);
}

void sha256(unsigned char * result, const unsigned char* source, uint_32t sourceLen)
{
    wc_Sha256 sha256;
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, source, sourceLen);
    wc_Sha256Final(&sha256, result);
    wc_Sha256Free(&sha256);
}

void sha512_begin(sha512_ctx* ctx)
{
    wc_InitSha512(ctx);
}

void sha512_hash(const unsigned char * source, uint_64t sourceLen, sha512_ctx *ctx)
{
    wc_Sha512Update(ctx, source, sourceLen);
}

void sha512_end(unsigned char * result, sha512_ctx* ctx)
{
    wc_Sha512Final(ctx, result);
}

void sha512(unsigned char * result, const unsigned char* source, uint_64t sourceLen)
{
    wc_Sha512 sha512;
    wc_InitSha512(&sha512);
    wc_Sha512Update(&sha512, source, sourceLen);
    wc_Sha512Final(&sha512, result);
    wc_Sha512Free(&sha512);
}

void derive_key_sha512 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen) {
    (void) iterations;
    wc_HKDF(WC_SHA512, (uint8*)pwd, (word32)pwd_len, (uint8*)salt, (word32)salt_len, NULL, 0, (uint8*)dk, (word32)dklen);
}

void derive_key_sha256 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen) {
    (void) iterations;
    wc_HKDF(WC_SHA256, (uint8*)pwd, (word32)pwd_len, (uint8*)salt, (word32)salt_len, NULL, 0, (uint8*)dk, (word32)dklen);
}
