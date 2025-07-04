/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_PKCS5
#define TC_HEADER_PKCS5

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef TC_WINDOWS_BOOT
/* output written to input_digest which must be at lease 32 bytes long */
void hmac_blake2s (unsigned char *key, int keylen, unsigned char *input_digest, int len);
void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 32 bytes long */
void hmac_sha256 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 64 bytes long */
void hmac_sha512 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* output written to d which must be at lease 64 bytes long */
void hmac_whirlpool (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_whirlpool (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

void hmac_streebog (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_streebog (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

int get_pkcs5_iteration_count (int pkcs5_prf_id, int pim, BOOL bBoot, int* pMemoryCost);
wchar_t *get_pkcs5_prf_name (int pkcs5_prf_id);

void derive_key_argon2(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, uint32 memcost, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);
void get_argon2_params(int pim, int* pIterations, int* pMemcost);

/* OpenADP Ocrypt distributed key derivation */
void derive_key_ocrypt(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation);

/* Global variables for Ocrypt metadata handling */
extern unsigned char* g_ocrypt_metadata;
extern int g_ocrypt_metadata_len;

/* Ocrypt volume operations */
#if defined(TC_WINDOWS) || defined(_WIN32)
int ocrypt_create_volume_with_metadata(HANDLE device, BOOL bBackupHeader);
int ocrypt_open_volume_with_metadata(HANDLE device, const unsigned char *pwd, int pwd_len, unsigned char *dk, int dklen, BOOL bBackupHeader);
#else
int ocrypt_create_volume_with_metadata(void* device, int bBackupHeader);
int ocrypt_open_volume_with_metadata(void* device, const unsigned char *pwd, int pwd_len, unsigned char *dk, int dklen, int bBackupHeader);
#endif
void ocrypt_cleanup_metadata(void);
void ocrypt_reset_secret_cache(void);
int ocrypt_single_recovery(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, unsigned char *dk, int dklen);

/* Helper function to load Ocrypt metadata from volume header into global variables */
void ocrypt_load_metadata_if_available(BOOL bDevice, void* fileHandle, BOOL bBackupHeader);

/* check if given PRF supported.*/
typedef enum
{
   PRF_BOOT_NO = 0,
   PRF_BOOT_MBR,
   PRF_BOOT_GPT
} PRF_BOOT_TYPE;

int is_pkcs5_prf_supported (int pkcs5_prf_id, PRF_BOOT_TYPE bootType);
#else // TC_WINDOWS_BOOT
/* output written to input_digest which must be at lease 32 bytes long */
void hmac_blake2s (unsigned char *key, int keylen, unsigned char *input_digest, int len);
void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen);

/* output written to d which must be at lease 32 bytes long */
void hmac_sha256 (unsigned char *k, int lk, unsigned char *d, int ld);
void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen);

#endif

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_PKCS5
