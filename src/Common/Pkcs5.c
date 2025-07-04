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

#include "Tcdefs.h"
#if !defined(_UEFI)
#include <memory.h>
#include <stdlib.h>
#endif
// Add include for Linux file operations
#ifndef _WIN32
#include <unistd.h>
#include <stdint.h>
#endif
#include "blake2.h"
#ifndef TC_WINDOWS_BOOT
#include "Sha2.h"
#include "Whirlpool.h"
#include "cpu.h"
#include "misc.h"
#else
#pragma optimize ("t", on)
#include <string.h>
#if defined( _MSC_VER )
#  ifndef DEBUG
#    pragma intrinsic( memcpy )
#    pragma intrinsic( memset )
#  endif
#endif
#include "Sha2Small.h"
#endif
#include "Pkcs5.h"
#include "Crypto.h"
#include "Random.h"
#include "OcryptWrapper.h"
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

// Global variables for Ocrypt metadata handling
unsigned char* g_ocrypt_metadata = NULL;
int g_ocrypt_metadata_len = 0;

// Global variables for external file handle access (set during volume operations)
char* g_current_volume_path = NULL;

// Global variables for header-based metadata access
static void* g_current_file_handle = NULL;
static int g_current_is_device = 0;

// Global variables for Ocrypt secret caching (to avoid double recovery)
static unsigned char g_cached_long_term_secret[32];
static BOOL g_secret_generated = FALSE;
static char g_cached_user_id[33]; // Track which user_id the cached secret belongs to
static int g_recovery_call_count = 0; // Track how many times we've been called for this volume
static unsigned char g_cached_derived_key[256]; // Cache the final derived key
static int g_cached_derived_key_len = 0;
static BOOL g_recovery_successful = FALSE; // Track if recovery succeeded for this user_id

// Function declarations
int save_ocrypt_metadata_to_file(const char* volume_path, const unsigned char* metadata, int metadata_len);
int load_ocrypt_metadata_from_file(const char* volume_path, unsigned char** metadata_out, int* metadata_len_out);
void set_current_volume_path(const char* volume_path);
int detect_ocrypt_magic_string(const char* volume_path);
int write_ocrypt_magic_string(void* fileHandle, int bBackupHeader);

// New header-based metadata functions
void set_current_file_handle(void* fileHandle, int isDevice);
int save_ocrypt_metadata_to_header(const unsigned char* metadata, int metadata_len);
int load_ocrypt_metadata_from_header(unsigned char** metadata_out, int* metadata_len_out);
int load_user_id_from_metadata(char* user_id_out, int user_id_out_size);

// NEW: Proper single-recovery Ocrypt function that uses version byte system
int ocrypt_single_recovery(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, unsigned char *dk, int dklen);

// Volume header constants (needed for all platforms)
#define TC_VOLUME_HEADER_SIZE					(64 * 1024L)
#define TC_VOLUME_HEADER_EFFECTIVE_SIZE			512
#define TC_UNUSED_HEADER_SPACE_OFFSET			TC_VOLUME_HEADER_EFFECTIVE_SIZE
#define TC_UNUSED_HEADER_SPACE_SIZE				(TC_VOLUME_HEADER_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE)

// Constants for magic string and dual metadata system
#define TC_OCRYPT_MAGIC_STRING					"OCRYPT1.0\0\0\0\0\0\0\0"	// 16 bytes
#define TC_OCRYPT_MAGIC_OFFSET					0		// Magic string at byte 512 (relative to unused space)
#define TC_OCRYPT_MAGIC_SIZE					16		// 16 bytes for magic string
#define TC_METADATA_VERSION_OFFSET				16		// Version byte at byte 528 (relative to unused space)
#define TC_METADATA_VERSION_SIZE				1		// 1 byte for version
#define TC_METADATA_EVEN_OFFSET					17		// Even metadata starts at byte 529 (relative to unused space)
#define TC_METADATA_ODD_OFFSET					16401	// Odd metadata starts at byte 16913 (relative to unused space)
#define TC_MAX_METADATA_SIZE					16384	// 16KB per metadata copy
#define TC_METADATA_EVEN_VERSION				0		// Even metadata is current
#define TC_METADATA_ODD_VERSION					1		// Odd metadata is current

// Implementation of metadata read/write functions  
#if defined(_WIN32) && !defined(TC_WINDOWS_BOOT) && !defined(DEVICE_DRIVER) && !defined(_UEFI)

int WriteOcryptMetadata(int device, void* fileHandle, const char *metadata, unsigned long metadataSize, int bBackupHeader)
{
    HANDLE hFile = (HANDLE)fileHandle;
    LARGE_INTEGER offset;
    DWORD bytesWritten;
    unsigned char currentVersion = 0;
    unsigned char newVersion;
    DWORD actualBytesRead;
    
    if (!metadata || metadataSize == 0 || metadataSize > TC_MAX_METADATA_SIZE) {
        return FALSE;
    }
    
    // Calculate base offset for unused header space
    LONGLONG baseOffset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET) : 
        TC_UNUSED_HEADER_SPACE_OFFSET;
    
    // First, read current version to determine which copy to write
    offset.QuadPart = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }
    
    // Read current version (ignore errors - default to 0 if not readable)
    ReadFile(hFile, &currentVersion, TC_METADATA_VERSION_SIZE, &actualBytesRead, NULL);
    
    // Determine new version and target offset
    if (currentVersion == TC_METADATA_EVEN_VERSION) {
        newVersion = TC_METADATA_ODD_VERSION;
        offset.QuadPart = baseOffset + TC_METADATA_ODD_OFFSET;
    } else {
        newVersion = TC_METADATA_EVEN_VERSION;
        offset.QuadPart = baseOffset + TC_METADATA_EVEN_OFFSET;
    }
    
    // Write new metadata to the target location
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }
    
    // Write metadata size (4 bytes)
    DWORD metadataSize32 = (DWORD)metadataSize;
    if (!WriteFile(hFile, &metadataSize32, sizeof(metadataSize32), &bytesWritten, NULL) || 
        bytesWritten != sizeof(metadataSize32)) {
        return FALSE;
    }
    
    // Write metadata content
    if (!WriteFile(hFile, metadata, metadataSize, &bytesWritten, NULL) || 
        bytesWritten != metadataSize) {
        return FALSE;
    }
    
    // Flush to ensure data is written
    FlushFileBuffers(hFile);
    
    // Finally, atomically update the version byte
    offset.QuadPart = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }
    
    if (!WriteFile(hFile, &newVersion, TC_METADATA_VERSION_SIZE, &bytesWritten, NULL) || 
        bytesWritten != TC_METADATA_VERSION_SIZE) {
        return FALSE;
    }
    
    FlushFileBuffers(hFile);
    return TRUE;
}

int ReadOcryptMetadata(int device, void* fileHandle, char *metadataBuffer, unsigned long bufferSize, unsigned long *metadataSize, int bBackupHeader)
{
    HANDLE hFile = (HANDLE)fileHandle;
    LARGE_INTEGER offset;
    DWORD bytesRead;
    DWORD storedSize;
    unsigned char currentVersion = 0;
    
    if (!metadataBuffer || !metadataSize || bufferSize == 0) {
        return FALSE;
    }
    
    *metadataSize = 0;
    
    // Calculate base offset for unused header space
    LONGLONG baseOffset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET) : 
        TC_UNUSED_HEADER_SPACE_OFFSET;
    
    // First, read the version byte to determine which metadata copy to read
    offset.QuadPart = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }
    
    if (!ReadFile(hFile, &currentVersion, TC_METADATA_VERSION_SIZE, &bytesRead, NULL) || 
        bytesRead != TC_METADATA_VERSION_SIZE) {
        // No version byte found - no metadata present
        return TRUE;
    }
    
    // Determine which metadata copy to read based on version
    if (currentVersion == TC_METADATA_EVEN_VERSION) {
        offset.QuadPart = baseOffset + TC_METADATA_EVEN_OFFSET;
    } else if (currentVersion == TC_METADATA_ODD_VERSION) {
        offset.QuadPart = baseOffset + TC_METADATA_ODD_OFFSET;
    } else {
        // Invalid version - no metadata present
        return TRUE;
    }
    
    // Seek to the appropriate metadata location
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }
    
    // Read metadata size (4 bytes)
    if (!ReadFile(hFile, &storedSize, sizeof(storedSize), &bytesRead, NULL) || 
        bytesRead != sizeof(storedSize)) {
        return FALSE;
    }
    
    // Validate size
    if (storedSize == 0 || storedSize > TC_MAX_METADATA_SIZE || storedSize > bufferSize) {
        return FALSE;
    }
    
    // Read metadata content
    if (!ReadFile(hFile, metadataBuffer, storedSize, &bytesRead, NULL) || 
        bytesRead != storedSize) {
        return FALSE;
    }
    
    *metadataSize = storedSize;
    return TRUE;
}

#else

// Non-Windows implementation (Linux, etc.)
int WriteOcryptMetadata(int device, void* fileHandle, const char *metadata, unsigned long metadataSize, int bBackupHeader)
{
    int fd = (int)(intptr_t)fileHandle;
    off_t offset;
    unsigned char currentVersion = 0;
    unsigned char newVersion;
    
    fprintf(stderr, "[DEBUG] WriteOcryptMetadata called: fd=%d, metadataSize=%lu, bBackupHeader=%d\n", 
            fd, metadataSize, bBackupHeader);
    fflush(stderr);
    
    if (!metadata || metadataSize == 0 || metadataSize > TC_MAX_METADATA_SIZE) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: Invalid parameters\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    // Calculate base offset for unused header space
    off_t baseOffset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET) : 
        TC_UNUSED_HEADER_SPACE_OFFSET;
    
    // First, read current version to determine which copy to write
    offset = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: lseek to version failed\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    // Read current version (ignore errors - default to 0 if not readable)
    ssize_t read_result = read(fd, &currentVersion, TC_METADATA_VERSION_SIZE);
    if (read_result < 0) {
        // Read failed, use default version
        currentVersion = TC_METADATA_EVEN_VERSION;
    }
    
    // Determine new version and target offset
    if (currentVersion == TC_METADATA_EVEN_VERSION) {
        newVersion = TC_METADATA_ODD_VERSION;
        offset = baseOffset + TC_METADATA_ODD_OFFSET;
    } else {
        newVersion = TC_METADATA_EVEN_VERSION;
        offset = baseOffset + TC_METADATA_EVEN_OFFSET;
    }
    
    fprintf(stderr, "[DEBUG] WriteOcryptMetadata: currentVersion=%d, newVersion=%d, offset=%ld\n", 
            currentVersion, newVersion, (long)offset);
    fflush(stderr);
    
    // Write new metadata to the target location
    if (lseek(fd, offset, SEEK_SET) != offset) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: lseek to metadata failed\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    // Write metadata size (4 bytes)
    uint32_t metadataSize32 = (uint32_t)metadataSize;
    if (write(fd, &metadataSize32, sizeof(metadataSize32)) != sizeof(metadataSize32)) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: Failed to write size\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    // Write metadata content
    if (write(fd, metadata, metadataSize) != (ssize_t)metadataSize) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: Failed to write metadata\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    // Flush to ensure data is written
    fsync(fd);
    
    // Finally, atomically update the version byte
    offset = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: lseek to version update failed\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    if (write(fd, &newVersion, TC_METADATA_VERSION_SIZE) != TC_METADATA_VERSION_SIZE) {
        fprintf(stderr, "[DEBUG] WriteOcryptMetadata: Failed to write version\n");
        fflush(stderr);
        return 0; // FALSE
    }
    
    fsync(fd);
    
    fprintf(stderr, "[DEBUG] WriteOcryptMetadata: SUCCESS - wrote %lu bytes at offset %ld with version %d\n", 
            metadataSize, (long)(baseOffset + (newVersion == TC_METADATA_EVEN_VERSION ? TC_METADATA_EVEN_OFFSET : TC_METADATA_ODD_OFFSET)), newVersion);
    fflush(stderr);
    return 1; // TRUE
}

int ReadOcryptMetadata(int device, void* fileHandle, char *metadataBuffer, unsigned long bufferSize, unsigned long *metadataSize, int bBackupHeader)
{
    int fd = (int)(intptr_t)fileHandle;
    off_t offset;
    uint32_t storedSize;
    unsigned char currentVersion = 0;
    
    if (!metadataBuffer || !metadataSize || bufferSize == 0) {
        return 0; // FALSE
    }
    
    *metadataSize = 0;
    
    // Calculate base offset for unused header space
    off_t baseOffset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET) : 
        TC_UNUSED_HEADER_SPACE_OFFSET;
    
    // First, read the version byte to determine which metadata copy to read
    offset = baseOffset + TC_METADATA_VERSION_OFFSET;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return 0; // FALSE
    }
    
    if (read(fd, &currentVersion, TC_METADATA_VERSION_SIZE) != TC_METADATA_VERSION_SIZE) {
        // No version byte found - no metadata present
        return 1; // TRUE but no metadata
    }
    
    // Determine which metadata copy to read based on version
    if (currentVersion == TC_METADATA_EVEN_VERSION) {
        offset = baseOffset + TC_METADATA_EVEN_OFFSET;
    } else if (currentVersion == TC_METADATA_ODD_VERSION) {
        offset = baseOffset + TC_METADATA_ODD_OFFSET;
    } else {
        // Invalid version - no metadata present
        return 1; // TRUE but no metadata
    }
    
    // Seek to the appropriate metadata location
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return 0; // FALSE
    }
    
    // Read metadata size (4 bytes)
    if (read(fd, &storedSize, sizeof(storedSize)) != sizeof(storedSize)) {
        return 0; // FALSE
    }
    
    // Validate size
    if (storedSize == 0 || storedSize > TC_MAX_METADATA_SIZE || storedSize > bufferSize) {
        return 0; // FALSE
    }
    
    // Read metadata content
    if (read(fd, metadataBuffer, storedSize) != (ssize_t)storedSize) {
        return 0; // FALSE
    }
    
    *metadataSize = storedSize;
    return 1; // TRUE
}

#endif

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_SHA2)

typedef struct hmac_sha256_ctx_struct
{
	sha256_ctx ctx;
	sha256_ctx inner_digest_ctx; /*pre-computed inner digest context */
	sha256_ctx outer_digest_ctx; /*pre-computed outer digest context */
	unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the SHA256 hash */
	unsigned char u[SHA256_DIGESTSIZE];
} hmac_sha256_ctx;

void hmac_sha256_internal
(
	unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_sha256_ctx* hmac /* HMAC-SHA256 context which holds temporary variables */
)
{
	sha256_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha256_ctx));

	sha256_hash (d, ld, ctx);

	sha256_end (d, ctx); /* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha256_ctx));

	sha256_hash (d, SHA256_DIGESTSIZE, ctx);

	sha256_end (d, ctx); /* d = outer digest */
}

#ifndef TC_WINDOWS_BOOT
void hmac_sha256
(
	unsigned char *k,    /* secret key */
	int lk,    /* length of the key in bytes */
	unsigned char *d,    /* data */
	int ld    /* length of data in bytes */
)
{
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = sha256(key), as per HMAC specifications. */
	if (lk > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash (k, lk, &tctx);
		sha256_end (key, &tctx);

		k = key;
		lk = SHA256_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA256_BLOCKSIZE - lk);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA256_BLOCKSIZE - lk);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	hmac_sha256_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_sha256 (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_sha256_ctx* hmac
#ifndef TC_WINDOWS_BOOT
	, long volatile *pAbortKeyDerivation
#endif
)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
	uint32 c;
	int i;	

#ifdef TC_WINDOWS_BOOT
	/* In bootloader mode, least significant bit of iterations is a boolean (TRUE for boot derivation mode, FALSE otherwise)
	 * and the most significant 16 bits hold the pim value
	 * This enables us to save code space needed for implementing other features.
	 */
	c = iterations >> 16;
	i = ((int) iterations) & 0x01;
	if (i)
		c = (c == 0)? 200000 : c << 11;
	else
		c = (c == 0)? 500000 : 15000 + c * 1000;
#else
	c = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
#ifdef TC_WINDOWS_BOOT
    /* specific case of 16-bit bootloader: b is a 16-bit integer that is always < 256 */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (unsigned char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_sha256_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA256_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
#ifndef TC_WINDOWS_BOOT
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation == 1)
			return; // Abort derivation
#endif
		hmac_sha256_internal (k, SHA256_DIGESTSIZE, hmac);
		for (i = 0; i < SHA256_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_sha256 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen
#ifndef TC_WINDOWS_BOOT
	, long volatile *pAbortKeyDerivation
#endif
)
{	
	hmac_sha256_ctx hmac;
	sha256_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	unsigned char key[SHA256_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha256(pwd), as per HMAC specifications. */
	if (pwd_len > SHA256_BLOCKSIZE)
	{
		sha256_ctx tctx;

		sha256_begin (&tctx);
		sha256_hash (pwd, pwd_len, &tctx);
		sha256_end (key, &tctx);

		pwd = key;
		pwd_len = SHA256_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}
#endif

	if (dklen % SHA256_DIGESTSIZE)
	{
		l = 1 + dklen / SHA256_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA256_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA256_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha256_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha256_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA256_BLOCKSIZE - pwd_len);

	sha256_hash (buf, SHA256_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
#ifndef TC_WINDOWS_BOOT
		derive_u_sha256 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
			goto cancelled;
#else
		derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
#endif
		memcpy (dk, hmac.u, SHA256_DIGESTSIZE);
		dk += SHA256_DIGESTSIZE;
	}

	/* last block */
#ifndef TC_WINDOWS_BOOT
	derive_u_sha256 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
		goto cancelled;
#else
	derive_u_sha256 (salt, salt_len, iterations, b, &hmac);
#endif
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
#ifndef TC_WINDOWS_BOOT
cancelled:
#endif
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
#ifndef TC_WINDOWS_BOOT
	burn (key, sizeof(key));
#endif
}

#endif

#ifndef TC_WINDOWS_BOOT

typedef struct hmac_sha512_ctx_struct
{
	sha512_ctx ctx;
	sha512_ctx inner_digest_ctx; /*pre-computed inner digest context */
	sha512_ctx outer_digest_ctx; /*pre-computed outer digest context */
	unsigned char k[SHA512_BLOCKSIZE]; /* enough to hold (salt_len + 4) and also the SHA512 hash */
	unsigned char u[SHA512_DIGESTSIZE];
} hmac_sha512_ctx;

void hmac_sha512_internal
(
	unsigned char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld,			/* length of data in bytes */
	  hmac_sha512_ctx* hmac
)
{
	sha512_ctx* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (sha512_ctx));

	sha512_hash (d, ld, ctx);

	sha512_end (d, ctx);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (sha512_ctx));

	sha512_hash (d, SHA512_DIGESTSIZE, ctx);

	sha512_end (d, ctx);
}

void hmac_sha512
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
 	  unsigned char *d,		/* data and also output buffer of at least 64 bytes */
	  int ld			/* length of data in bytes */	  
)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif

    /* If the key is longer than the hash algorithm block size,
	   let key = sha512(key), as per HMAC specifications. */
	if (lk > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash (k, lk, &tctx);
		sha512_end (key, &tctx);

		k = key;
		lk = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, SHA512_BLOCKSIZE - lk);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, SHA512_BLOCKSIZE - lk);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	hmac_sha512_internal (d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

static void derive_u_sha512 (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_sha512_ctx* hmac, long volatile *pAbortKeyDerivation)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_sha512_internal (k, salt_len + 4, hmac);
	memcpy (u, k, SHA512_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation == 1)
			return; // Abort derivation
		hmac_sha512_internal (k, SHA512_DIGESTSIZE, hmac);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}


void derive_key_sha512 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation)
{
	hmac_sha512_ctx hmac;
	sha512_ctx* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
	unsigned char key[SHA512_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif

    /* If the password is longer than the hash algorithm block size,
	   let pwd = sha512(pwd), as per HMAC specifications. */
	if (pwd_len > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash (pwd, pwd_len, &tctx);
		sha512_end (key, &tctx);

		pwd = key;
		pwd_len = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % SHA512_DIGESTSIZE)
	{
		l = 1 + dklen / SHA512_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA512_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA512_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	sha512_begin (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	sha512_begin (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, SHA512_BLOCKSIZE - pwd_len);

	sha512_hash (buf, SHA512_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_sha512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
			goto cancelled;
		memcpy (dk, hmac.u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	derive_u_sha512 (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation == 1)
		goto cancelled;
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

#endif // TC_WINDOWS_BOOT

#if !defined(TC_WINDOWS_BOOT) || defined(TC_WINDOWS_BOOT_BLAKE2S)

typedef struct hmac_blake2s_ctx_struct
{
	blake2s_state ctx;
	blake2s_state inner_digest_ctx; /*pre-computed inner digest context */
	blake2s_state outer_digest_ctx; /*pre-computed outer digest context */
	unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Blake2s hash */
	unsigned char u[BLAKE2S_DIGESTSIZE];
} hmac_blake2s_ctx;

void hmac_blake2s_internal
(
	unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_blake2s_ctx* hmac /* HMAC-BLAKE2S context which holds temporary variables */
)
{
	blake2s_state* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (blake2s_state));

	blake2s_update (ctx, d, ld);

	blake2s_final (ctx, d); /* d = inner digest */

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (blake2s_state));

	blake2s_update (ctx, d, BLAKE2S_DIGESTSIZE);

	blake2s_final (ctx, d); /* d = outer digest */
}

#ifndef TC_WINDOWS_BOOT
void hmac_blake2s
(
	unsigned char *k,    /* secret key */
	int lk,    /* length of the key in bytes */
	unsigned char *d,    /* data */
	int ld    /* length of data in bytes */
)
{
	hmac_blake2s_ctx hmac;
	blake2s_state* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[BLAKE2S_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the key is longer than the hash algorithm block size,
	   let key = blake2s(key), as per HMAC specifications. */
	if (lk > BLAKE2S_BLOCKSIZE)
	{
		blake2s_state tctx;

		blake2s_init (&tctx);
		blake2s_update (&tctx, k, lk);
		blake2s_final (&tctx, key);

		k = key;
		lk = BLAKE2S_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	blake2s_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, BLAKE2S_BLOCKSIZE - lk);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	blake2s_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, BLAKE2S_BLOCKSIZE - lk);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	hmac_blake2s_internal(d, ld, &hmac);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
	burn(key, sizeof(key));
}
#endif

static void derive_u_blake2s (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_blake2s_ctx* hmac
#ifndef TC_WINDOWS_BOOT
	, volatile long *pAbortKeyDerivation
#endif
)
{
	unsigned char* k = hmac->k;
	unsigned char* u = hmac->u;
	uint32 c;
	int i;	

#ifdef TC_WINDOWS_BOOT
	/* In bootloader mode, least significant bit of iterations is a boolean (TRUE for boot derivation mode, FALSE otherwise)
	 * and the most significant 16 bits hold the pim value
	 * This enables us to save code space needed for implementing other features.
	 */
	c = iterations >> 16;
	i = ((int) iterations) & 0x01;
	if (i)
		c = (c == 0)? 200000 : c << 11;
	else
		c = (c == 0)? 500000 : 15000 + c * 1000;
#else
	c = iterations;
#endif

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	
	/* big-endian block number */
#ifdef TC_WINDOWS_BOOT
    /* specific case of 16-bit bootloader: b is a 16-bit integer that is always < 256 */
	memset (&k[salt_len], 0, 3);
	k[salt_len + 3] = (unsigned char) b;
#else
    b = bswap_32 (b);
    memcpy (&k[salt_len], &b, 4);
#endif	

	hmac_blake2s_internal (k, salt_len + 4, hmac);
	memcpy (u, k, BLAKE2S_DIGESTSIZE);

	/* remaining iterations */
	while (c > 1)
	{
#ifndef TC_WINDOWS_BOOT
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
#endif
		hmac_blake2s_internal (k, BLAKE2S_DIGESTSIZE, hmac);
		for (i = 0; i < BLAKE2S_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
		c--;
	}
}


void derive_key_blake2s (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen
#ifndef TC_WINDOWS_BOOT
	, volatile long *pAbortKeyDerivation
#endif
)
{	
	hmac_blake2s_ctx hmac;
	blake2s_state* ctx;
	unsigned char* buf = hmac.k;
	int b, l, r;
#ifndef TC_WINDOWS_BOOT
	unsigned char key[BLAKE2S_DIGESTSIZE];
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
    /* If the password is longer than the hash algorithm block size,
	   let pwd = blake2s(pwd), as per HMAC specifications. */
	if (pwd_len > BLAKE2S_BLOCKSIZE)
	{
		blake2s_state tctx;

		blake2s_init (&tctx);
		blake2s_update (&tctx, pwd, pwd_len);
		blake2s_final (&tctx, key);

		pwd = key;
		pwd_len = BLAKE2S_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}
#endif

	if (dklen % BLAKE2S_DIGESTSIZE)
	{
		l = 1 + dklen / BLAKE2S_DIGESTSIZE;
	}
	else
	{
		l = dklen / BLAKE2S_DIGESTSIZE;
	}

	r = dklen - (l - 1) * BLAKE2S_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	blake2s_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, BLAKE2S_BLOCKSIZE - pwd_len);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	blake2s_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, BLAKE2S_BLOCKSIZE - pwd_len);

	blake2s_update (ctx, buf, BLAKE2S_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
#ifndef TC_WINDOWS_BOOT
		derive_u_blake2s (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
#else
		derive_u_blake2s (salt, salt_len, iterations, b, &hmac);
#endif
		memcpy (dk, hmac.u, BLAKE2S_DIGESTSIZE);
		dk += BLAKE2S_DIGESTSIZE;
	}

	/* last block */
#ifndef TC_WINDOWS_BOOT
	derive_u_blake2s (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
#else
	derive_u_blake2s (salt, salt_len, iterations, b, &hmac);
#endif
	memcpy (dk, hmac.u, r);

#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS (saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
#ifndef TC_WINDOWS_BOOT
	burn (key, sizeof(key));
#endif
}

#endif

#ifndef TC_WINDOWS_BOOT

typedef struct hmac_whirlpool_ctx_struct
{
	WHIRLPOOL_CTX ctx;
	WHIRLPOOL_CTX inner_digest_ctx; /*pre-computed inner digest context */
	WHIRLPOOL_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Whirlpool hash */
	unsigned char u[WHIRLPOOL_DIGESTSIZE];
} hmac_whirlpool_ctx;

void hmac_whirlpool_internal
(
	unsigned char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_whirlpool_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	WHIRLPOOL_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add (d, ld, ctx);

	WHIRLPOOL_finalize (ctx, d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (WHIRLPOOL_CTX));

	WHIRLPOOL_add (d, WHIRLPOOL_DIGESTSIZE, ctx);

	WHIRLPOOL_finalize (ctx, d);
}

void hmac_whirlpool
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	unsigned char* buf = hmac.k;
	int b;
	unsigned char key[WHIRLPOOL_DIGESTSIZE];
    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add (k, lk, &tctx);
		WHIRLPOOL_finalize (&tctx, key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, WHIRLPOOL_BLOCKSIZE - lk);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	hmac_whirlpool_internal(d, ld, &hmac);

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_whirlpool (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_whirlpool_ctx* hmac, volatile long *pAbortKeyDerivation)
{
	unsigned char* u = hmac->u;
	unsigned char* k = hmac->k;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_whirlpool_internal (k, salt_len + 4, hmac);
	memcpy (u, k, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
		hmac_whirlpool_internal (k, WHIRLPOOL_DIGESTSIZE, hmac);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_whirlpool (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_whirlpool_ctx hmac;
	WHIRLPOOL_CTX* ctx;
	unsigned char* buf = hmac.k;
	unsigned char key[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;
    /* If the password is longer than the hash algorithm block size,
	   let pwd = whirlpool(pwd), as per HMAC specifications. */
	if (pwd_len > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add (pwd, pwd_len, &tctx);
		WHIRLPOOL_finalize (&tctx, key);

		pwd = key;
		pwd_len = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % WHIRLPOOL_DIGESTSIZE)
	{
		l = 1 + dklen / WHIRLPOOL_DIGESTSIZE;
	}
	else
	{
		l = dklen / WHIRLPOOL_DIGESTSIZE;
	}

	r = dklen - (l - 1) * WHIRLPOOL_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	WHIRLPOOL_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	WHIRLPOOL_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, WHIRLPOOL_BLOCKSIZE - pwd_len);

	WHIRLPOOL_add (buf, WHIRLPOOL_BLOCKSIZE, ctx);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_whirlpool (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	derive_u_whirlpool (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}


typedef struct hmac_streebog_ctx_struct
{
	STREEBOG_CTX ctx;
	STREEBOG_CTX inner_digest_ctx; /*pre-computed inner digest context */
	STREEBOG_CTX outer_digest_ctx; /*pre-computed outer digest context */
	CRYPTOPP_ALIGN_DATA(16) unsigned char k[PKCS5_SALT_SIZE + 4]; /* enough to hold (salt_len + 4) and also the Streebog hash */
	unsigned char u[STREEBOG_DIGESTSIZE];
} hmac_streebog_ctx;

void hmac_streebog_internal
(
	  unsigned char *d,		/* input/output data. d pointer is guaranteed to be at least 64-bytes long */
	  int ld,		/* length of input data in bytes */
	  hmac_streebog_ctx* hmac /* HMAC-Whirlpool context which holds temporary variables */
)
{
	STREEBOG_CTX* ctx = &(hmac->ctx);

	/**** Restore Precomputed Inner Digest Context ****/

	memcpy (ctx, &(hmac->inner_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, d, ld);

	STREEBOG_finalize (ctx, d);

	/**** Restore Precomputed Outer Digest Context ****/

	memcpy (ctx, &(hmac->outer_digest_ctx), sizeof (STREEBOG_CTX));

	STREEBOG_add (ctx, d, STREEBOG_DIGESTSIZE);

	STREEBOG_finalize (ctx, d);
}

void hmac_streebog
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* input data. d pointer is guaranteed to be at least 32-bytes long */
	  int ld		/* length of data in bytes */
)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	unsigned char* buf = hmac.k;
	int b;
	CRYPTOPP_ALIGN_DATA(16) unsigned char key[STREEBOG_DIGESTSIZE];
    /* If the key is longer than the hash algorithm block size,
	   let key = streebog(key), as per HMAC specifications. */
	if (lk > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, k, lk);
		STREEBOG_finalize (&tctx, key);

		k = key;
		lk = STREEBOG_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	STREEBOG_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x36);
	memset (&buf[lk], 0x36, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < lk; ++b)
		buf[b] = (unsigned char) (k[b] ^ 0x5C);
	memset (&buf[lk], 0x5C, STREEBOG_BLOCKSIZE - lk);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	hmac_streebog_internal(d, ld, &hmac);

	/* Prevent leaks */
	burn(&hmac, sizeof(hmac));
}

static void derive_u_streebog (const unsigned char *salt, int salt_len, uint32 iterations, int b, hmac_streebog_ctx* hmac, volatile long *pAbortKeyDerivation)
{
	unsigned char* u = hmac->u;
	unsigned char* k = hmac->k;
	uint32 c, i;

	/* iteration 1 */
	memcpy (k, salt, salt_len);	/* salt */
	/* big-endian block number */
    b = bswap_32 (b);
	memcpy (&k[salt_len], &b, 4);

	hmac_streebog_internal (k, salt_len + 4, hmac);
	memcpy (u, k, STREEBOG_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		// CANCELLATION CHECK: Check every 1024 iterations
		if (pAbortKeyDerivation && (c & 1023) == 0 && *pAbortKeyDerivation)
			return; // Abort derivation
		hmac_streebog_internal (k, STREEBOG_DIGESTSIZE, hmac);
		for (i = 0; i < STREEBOG_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
		}
	}
}

void derive_key_streebog (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
	hmac_streebog_ctx hmac;
	STREEBOG_CTX* ctx;
	unsigned char* buf = hmac.k;
	unsigned char key[STREEBOG_DIGESTSIZE];
	int b, l, r;
    /* If the password is longer than the hash algorithm block size,
	   let pwd = streebog(pwd), as per HMAC specifications. */
	if (pwd_len > STREEBOG_BLOCKSIZE)
	{
		STREEBOG_CTX tctx;

		STREEBOG_init (&tctx);
		STREEBOG_add (&tctx, pwd, pwd_len);
		STREEBOG_finalize (&tctx, key);

		pwd = key;
		pwd_len = STREEBOG_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	if (dklen % STREEBOG_DIGESTSIZE)
	{
		l = 1 + dklen / STREEBOG_DIGESTSIZE;
	}
	else
	{
		l = dklen / STREEBOG_DIGESTSIZE;
	}

	r = dklen - (l - 1) * STREEBOG_DIGESTSIZE;

	/**** Precompute HMAC Inner Digest ****/

	ctx = &(hmac.inner_digest_ctx);
	STREEBOG_init (ctx);

	/* Pad the key for inner digest */
	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x36);
	memset (&buf[pwd_len], 0x36, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/**** Precompute HMAC Outer Digest ****/

	ctx = &(hmac.outer_digest_ctx);
	STREEBOG_init (ctx);

	for (b = 0; b < pwd_len; ++b)
		buf[b] = (unsigned char) (pwd[b] ^ 0x5C);
	memset (&buf[pwd_len], 0x5C, STREEBOG_BLOCKSIZE - pwd_len);

	STREEBOG_add (ctx, buf, STREEBOG_BLOCKSIZE);

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_streebog (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
		// Check if the derivation was aborted
		if (pAbortKeyDerivation && *pAbortKeyDerivation)
			goto cancelled;
		memcpy (dk, hmac.u, STREEBOG_DIGESTSIZE);
		dk += STREEBOG_DIGESTSIZE;
	}

	/* last block */
	derive_u_streebog (salt, salt_len, iterations, b, &hmac, pAbortKeyDerivation);
	// Check if the derivation was aborted (in case of only one block)
	if (pAbortKeyDerivation && *pAbortKeyDerivation)
		goto cancelled;
	memcpy (dk, hmac.u, r);
cancelled:
	/* Prevent possible leaks. */
	burn (&hmac, sizeof(hmac));
	burn (key, sizeof(key));
}

wchar_t *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{
	case SHA512:	
		return L"HMAC-SHA-512";

	case SHA256:	
		return L"HMAC-SHA-256";

	case BLAKE2S:	
		return L"HMAC-BLAKE2s-256";

	case WHIRLPOOL:	
		return L"HMAC-Whirlpool";

	case STREEBOG:
		return L"HMAC-STREEBOG";

	case ARGON2:
		return L"Argon2";

	case OCRYPT:
		return L"Ocrypt";

	default:		
		return L"(Unknown)";
	}
}



int get_pkcs5_iteration_count(int pkcs5_prf_id, int pim, BOOL bBoot, int* pMemoryCost)
{
	int iteration_count = 0;
	*pMemoryCost = 0;

	if (pim >= 0)
	{
		switch (pkcs5_prf_id)
		{
		case BLAKE2S:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case SHA512:
			iteration_count = (pim == 0) ? 500000 : 15000 + pim * 1000;
			break;

		case WHIRLPOOL:
			iteration_count = (pim == 0) ? 500000 : 15000 + pim * 1000;
			break;

		case SHA256:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case STREEBOG:
			if (pim == 0)
				iteration_count = bBoot ? 200000 : 500000;
			else
				iteration_count = bBoot ? pim * 2048 : 15000 + pim * 1000;
			break;

		case ARGON2:
			get_argon2_params (pim, &iteration_count, pMemoryCost);
			break;

		case OCRYPT:
			// Ocrypt doesn't use iterations for security, it uses distributed cryptography
			// PIM is ignored since security comes from the distributed servers
			iteration_count = 1;
			break;

		default:
			TC_THROW_FATAL_EXCEPTION; // Unknown/wrong ID
		}
	}

	return iteration_count;
}

int is_pkcs5_prf_supported (int pkcs5_prf_id, PRF_BOOT_TYPE bootType)
{
   if (pkcs5_prf_id == 0) // auto-detection always supported
      return 1;

   if (  (bootType == PRF_BOOT_MBR && pkcs5_prf_id != BLAKE2S && pkcs5_prf_id != SHA256)
		|| (bootType != PRF_BOOT_MBR && (pkcs5_prf_id < FIRST_PRF_ID || pkcs5_prf_id > LAST_PRF_ID))
		)
      return 0;
   // we don't support Argon2 or Ocrypt in pre-boot authentication
   if ((bootType == PRF_BOOT_MBR || bootType == PRF_BOOT_GPT) && (pkcs5_prf_id == ARGON2 || pkcs5_prf_id == OCRYPT))
      return 0;	
   return 1;

}

void derive_key_argon2(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, uint32 memcost, unsigned char *dk, int dklen, volatile long *pAbortKeyDerivation)
{
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
	XSTATE_SAVE SaveState;
	if (IsCpuIntel() && HasSAVX())
		saveStatus = KeSaveExtendedProcessorState(XSTATE_MASK_GSSE, &SaveState);
#endif
	if (0 != argon2id_hash_raw(
		iterations, // number of iterations
		memcost, // memory cost in KiB
		1, // parallelism factor (number of threads)
		pwd, pwd_len, // password and its length
		salt, salt_len, // salt and its length
		dk, dklen,// derived key and its length
		pAbortKeyDerivation 
	))
	{
		// If the Argon2 derivation fails, we fill the derived key with zeroes
		memset(dk, 0, dklen);
	}
#if defined (DEVICE_DRIVER) && !defined(_M_ARM64)
	if (NT_SUCCESS(saveStatus))
		KeRestoreExtendedProcessorState(&SaveState);
#endif
}

/**
 * get_argon2_params
 * 
 * This function calculates the memory cost (in KiB) and time cost (iterations) for 
 * the Argon2id key derivation function based on the Personal Iteration Multiplier (PIM) value.
 * 
 * Parameters:
 *   - pim: The Personal Iteration Multiplier (PIM), which controls the memory and time costs.
 *          If pim < 0, it is clamped to 0.
 *          If pim == 0, the default value of 12 is used.
 *   - pIterations: Pointer to an integer where the calculated time cost (iterations) will be stored.
 *   - pMemcost: Pointer to an integer where the calculated memory cost (in KiB) will be stored.
 * 
 * Formulas:
 *   - Memory Cost (m_cost) in MiB:
 *     m_cost(pim) = min(64 MiB + (pim - 1) * 32 MiB, 1024 MiB)
 *     This formula increases the memory cost by 32 MiB for each increment of PIM, starting from 64 MiB.
 *     The memory cost is capped at 1024 MiB when PIM reaches 31 or higher.
 *     The result is converted to KiB before being stored in *pMemcost:
 *     *pMemcost = m_cost(pim) * 1024
 * 
 *   - Time Cost (t_cost) in iterations:
 *     If PIM <= 31:
 *        t_cost(pim) = 3 + floor((pim - 1) / 3)
 *     If PIM > 31:
 *        t_cost(pim) = 13 + (pim - 31)
 *     This formula increases the time cost by 1 iteration for every 3 increments of PIM when PIM <= 31.
 *     For PIM > 31, the time cost increases by 1 iteration for each increment in PIM.
 *     The calculated time cost is stored in *pIterations.
 * 
 * Example:
 *   - For PIM = 12:
 *     Memory Cost = 64 + (12 - 1) * 32 = 416 MiB (425,984 KiB)
 *     Time Cost = 3 + floor((12 - 1) / 3) = 6 iterations
 * 
 *   - For PIM = 31:
 *     Memory Cost = 64 + (31 - 1) * 32 = 1024 MiB (capped)
 *     Time Cost = 3 + floor((31 - 1) / 3) = 13 iterations
 * 
 *   - For PIM = 32:
 *     Memory Cost = 1024 MiB (capped)
 *     Time Cost = 13 + (32 - 31) = 14 iterations
 * 
 */
void get_argon2_params(int pim, int* pIterations, int* pMemcost)
{
    // Ensure PIM is at least 0
    if (pim < 0)
    {
        pim = 0;
    }

	// Default PIM value is 12
	// which leads to 416 MiB memory cost and 6 iterations
	if (pim == 0)
	{
		pim = 12;
	}

    // Compute the memory cost (m_cost) in MiB
    int m_cost_mib = 64 + (pim - 1) * 32;

    // Cap the memory cost at 1024 MiB
    if (m_cost_mib > 1024)
    {
        m_cost_mib = 1024;
    }

    // Convert memory cost to KiB for Argon2
    *pMemcost = m_cost_mib * 1024; // m_cost in KiB

    // Compute the time cost (t_cost)
    if (pim <= 31)
    {
        *pIterations = 3 + ((pim - 1) / 3);
    }
    else
    {
        *pIterations = 13 + (pim - 31);
    }
}

#endif //!TC_WINDOWS_BOOT

/* OpenADP Ocrypt distributed key derivation */
void derive_key_ocrypt(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, uint32 iterations, unsigned char *dk, int dklen, long volatile *pAbortKeyDerivation)
{
    fprintf(stderr, "[DEBUG] *** derive_key_ocrypt called! pwd_len=%d, dklen=%d ***\n", pwd_len, dklen);
    fflush(stderr);
    
    // MAGIC STRING DETECTION: Only attempt Ocrypt if this is an Ocrypt volume
    if (g_current_volume_path) {
        int is_ocrypt_volume = detect_ocrypt_magic_string(g_current_volume_path);
        fprintf(stderr, "[DEBUG] Magic string detection for %s: %s\n", 
               g_current_volume_path, is_ocrypt_volume ? "OCRYPT VOLUME" : "NOT OCRYPT VOLUME");
        fflush(stderr);
        
        if (!is_ocrypt_volume) {
            fprintf(stderr, "[DEBUG] NOT an Ocrypt volume - skipping Ocrypt PRF and returning failure\n");
            fflush(stderr);
            // Set dk to zero and return - this will cause the PRF to fail gracefully
            if (dk && dklen > 0) {
                memset(dk, 0, dklen);
            }
            return;
        }
        
        fprintf(stderr, "[DEBUG] CONFIRMED: This IS an Ocrypt volume - proceeding with Ocrypt PRF\n");
        fflush(stderr);
    } else {
        fprintf(stderr, "[DEBUG] Warning: No volume path available for magic string detection\n");
        fflush(stderr);
    }
    
    // Handle NULL abort pointer gracefully
    long volatile localAbort = 0;
    if (pAbortKeyDerivation == NULL) {
        pAbortKeyDerivation = &localAbort;
        fprintf(stderr, "[DEBUG] derive_key_ocrypt: NULL abort pointer, using local variable\n");
        fflush(stderr);
    }
    
    if (pwd_len > 300) {
        fprintf(stderr, "[DEBUG] derive_key_ocrypt: Password too long (%d bytes), truncating to 300\n", pwd_len);
        pwd_len = 300;
    }
    
    // Debug output
    fprintf(stderr, "[DEBUG] derive_key_ocrypt called with password length: %d\n", pwd_len);
    fflush(stderr);
    
    // Convert password to null-terminated string
    char password[512];
    int password_len = pwd_len;
    if (password_len > 511) password_len = 511;
    memcpy(password, pwd, password_len);
    password[password_len] = '\0';
    
    // Generate a deterministic user ID for this volume (each volume gets unique ID)
    char user_id[64];
    unsigned char random_bytes[16];
    int i;
    
    // Generate deterministic user_id per volume (same for both primary and backup headers)
    // Use password as seed for deterministic user_id generation
    { sha256_ctx ctx; sha256_begin(&ctx); sha256_hash(pwd, pwd_len, &ctx); sha256_end(random_bytes, &ctx); }
    for (i = 0; i < 16; i++) {
        sprintf(user_id + (i * 2), "%02x", random_bytes[i]);
    }
    user_id[32] = '\0';
    
    // More debug output
    fprintf(stderr, "[DEBUG] user_id='%.16s...', current_volume_path=%s\n", user_id, 
            g_current_volume_path ? g_current_volume_path : "NULL");
    fflush(stderr);
    
    const char* app_id = "veracrypt";
    const int max_guesses = 10; // Allow 10 PIN attempts
    
    // Generate random long-term secret that will be protected by Ocrypt (same for both headers)
    unsigned char long_term_secret[32];
    
    g_recovery_call_count++;
    fprintf(stderr, "[DEBUG] derive_key_ocrypt call #%d for this volume operation\n", g_recovery_call_count);
    fflush(stderr);
    
    // Check if we already have a cached secret for this user_id
    BOOL use_cached_secret = FALSE;
    if (g_secret_generated && strcmp(g_cached_user_id, user_id) == 0) {
        use_cached_secret = TRUE;
        fprintf(stderr, "[DEBUG] Reusing cached secret for same user_id (avoiding double recovery)\n");
        fflush(stderr);
    }
    
    if (!use_cached_secret) {
        // Generate new secret or this is a different user_id
        // Use OpenADP's cryptographically secure random number generation via OpenSSL
        if (ocrypt_random_bytes(g_cached_long_term_secret, 32) == 0) {
            // Random generation successful
            fprintf(stderr, "[DEBUG] Generated 32 bytes of cryptographically secure random data via OpenSSL\n");
            fflush(stderr);
        } else {
            // Fallback to hash-based derivation if RNG fails
            sha256_ctx ctx;
            sha256_begin(&ctx);
            sha256_hash(pwd, pwd_len, &ctx);
            sha256_hash(salt, salt_len, &ctx);
            sha256_end(g_cached_long_term_secret, &ctx);
            fprintf(stderr, "[DEBUG] Warning: OpenSSL RNG failed, used fallback key derivation\n");
            fflush(stderr);
        }
        
        // Cache this user_id
        strncpy(g_cached_user_id, user_id, 32);
        g_cached_user_id[32] = '\0';
        g_secret_generated = TRUE;
        
        fprintf(stderr, "[DEBUG] Generated new cryptographically secure random long-term secret for user_id=%.16s...\n", user_id);
        fflush(stderr);
    }
    
    memcpy(long_term_secret, g_cached_long_term_secret, 32);
    
    // Use the new single-recovery function that implements proper version byte logic
    fprintf(stderr, "[DEBUG] Attempting single recovery using version byte system\n");
    fflush(stderr);
    
    int recovery_result = ocrypt_single_recovery(pwd, pwd_len, salt, salt_len, dk, dklen);
    if (recovery_result == 1) {
        // Recovery successful - we're done!
        fprintf(stderr, "[DEBUG] Single recovery successful - skipping registration\n");
        fflush(stderr);
        burn(long_term_secret, sizeof(long_term_secret));
        return;
    }
    
    // Recovery failed or no metadata found - try registration for new volumes
    fprintf(stderr, "[DEBUG] Single recovery failed - attempting registration for new volume\n");
    fflush(stderr);
    
    // Try registration (for new volumes) since recovery failed
    {
        // Try to register the secret with Ocrypt (for new volume creation)
        unsigned char* metadata_out = NULL;
        int metadata_len_out = 0;
        
        int register_result = ocrypt_register_secret(
            user_id,
            app_id,
            long_term_secret,
            32, // long_term_secret length
            password,
            max_guesses,
            &metadata_out,
            &metadata_len_out
        );
        
        if (register_result == 0 && metadata_out != NULL) {
            // Registration successful - this is a new volume being created
            // Store metadata in global variables for VolumeCreator to use
            
            fprintf(stderr, "[DEBUG] Ocrypt registration SUCCESSFUL! Storing %d bytes of metadata in global variables\n", metadata_len_out);
            fflush(stderr);
            
            // Clean up any existing global metadata
            ocrypt_cleanup_metadata();
            
            // Store the new metadata in global variables
            g_ocrypt_metadata_len = metadata_len_out;
            g_ocrypt_metadata = (unsigned char*)malloc(g_ocrypt_metadata_len);
            if (g_ocrypt_metadata) {
                memcpy(g_ocrypt_metadata, metadata_out, g_ocrypt_metadata_len);
                fprintf(stderr, "[DEBUG] Successfully stored %d bytes in global metadata variables\n", g_ocrypt_metadata_len);
            } else {
                fprintf(stderr, "[DEBUG] Failed to allocate memory for global metadata\n");
                g_ocrypt_metadata_len = 0;
            }
            fflush(stderr);
            
            // Clean up the temporary metadata
            ocrypt_free_memory(metadata_out);
            
            // Derive the actual volume key from the random long-term secret
            fprintf(stderr, "[DEBUG] ====== REGISTRATION SECRET (FOR COMPARISON) ======\n");
            fprintf(stderr, "[DEBUG] REGISTRATION: long_term_secret = ");
            for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", long_term_secret[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "[DEBUG] REGISTRATION: salt = ");
            for (int i = 0; i < (salt_len < 32 ? salt_len : 32); i++) fprintf(stderr, "%02x", salt[i]);
            fprintf(stderr, "\n");
            fflush(stderr);
            
            // Derive header encryption key from long-term secret + salt (not volume data key)
            // Use PBKDF2-like expansion to generate required key length for XTS mode
            {
                int remaining = dklen;
                int offset = 0;
                int round = 0;
                
                while (remaining > 0) {
                    sha256_ctx ctx;
                    sha256_begin(&ctx);
                    sha256_hash(long_term_secret, 32, &ctx);
                    sha256_hash(salt, salt_len, &ctx);
                    sha256_hash((const unsigned char*)&round, sizeof(round), &ctx);
                    const char* header_context = "VeraCrypt Header Key";
                    sha256_hash((const unsigned char*)header_context, strlen(header_context), &ctx);
                    
                    unsigned char round_key[32];
                    sha256_end(round_key, &ctx);
                    
                    int copy_len = remaining > 32 ? 32 : remaining;
                    memcpy(dk + offset, round_key, copy_len);
                    
                    offset += copy_len;
                    remaining -= copy_len;
                    round++;
                }
            }
            
            fprintf(stderr, "[DEBUG] REGISTRATION: derived HEADER ENCRYPTION key = ");
            for (int i = 0; i < (dklen < 32 ? dklen : 32); i++) fprintf(stderr, "%02x", dk[i]);
            fprintf(stderr, "\n");
            fprintf(stderr, "[DEBUG] ==========================================\n");
            fflush(stderr);
        } else {
            // Both registration and recovery failed - generate a fallback key
            // This shouldn't happen in normal operation, but provides a fallback
            fprintf(stderr, "[DEBUG] Ocrypt registration FAILED! register_result=%d\n", register_result);
            fflush(stderr);
            
            { sha256_ctx ctx; sha256_begin(&ctx); sha256_hash(pwd, pwd_len, &ctx); sha256_hash(salt, salt_len, &ctx); sha256_end(dk, &ctx); }
            
            // Clean up if there was partial allocation
            if (metadata_out) {
                ocrypt_free_memory(metadata_out);
            }
        }
    }
    
    // Clear sensitive data
    burn(long_term_secret, sizeof(long_term_secret));
    burn(password, sizeof(password));
}

// Function to handle Ocrypt volume creation - stores metadata in header
#if defined(TC_WINDOWS) || defined(_WIN32)
int ocrypt_create_volume_with_metadata(HANDLE device, BOOL bBackupHeader)
#else
int ocrypt_create_volume_with_metadata(void* device, int bBackupHeader)
#endif
{
    if (g_ocrypt_metadata == NULL || g_ocrypt_metadata_len == 0) {
        return -1; // No metadata to store
    }
    
    // Convert metadata to JSON string
    char metadata_json[TC_MAX_METADATA_SIZE];
    if (g_ocrypt_metadata_len >= TC_MAX_METADATA_SIZE) {
        return -2; // Metadata too large
    }
    
    memcpy(metadata_json, g_ocrypt_metadata, g_ocrypt_metadata_len);
    metadata_json[g_ocrypt_metadata_len] = '\0';
    
    // Store the metadata in the unused header space
#if defined(TC_WINDOWS) || defined(_WIN32)
    BOOL result = WriteOcryptMetadata(FALSE, device, metadata_json, g_ocrypt_metadata_len, bBackupHeader);
    return result ? 0 : -3;
#else
    // Linux implementation
    int result = WriteOcryptMetadata(FALSE, device, metadata_json, g_ocrypt_metadata_len, bBackupHeader);
    return result ? 0 : -3;
#endif
}

// Function to handle Ocrypt volume opening - retrieves and uses metadata  
#if defined(TC_WINDOWS) || defined(_WIN32)
int ocrypt_open_volume_with_metadata(HANDLE device, const unsigned char *pwd, int pwd_len, unsigned char *dk, int dklen, BOOL bBackupHeader)
#else
int ocrypt_open_volume_with_metadata(void* device, const unsigned char *pwd, int pwd_len, unsigned char *dk, int dklen, int bBackupHeader)
#endif
{
#if defined(TC_WINDOWS) || defined(_WIN32)
    char metadata_buffer[TC_MAX_METADATA_SIZE];
    DWORD metadata_size = 0;
    
    // Try to read Ocrypt metadata from volume header
    BOOL read_result = ReadOcryptMetadata(FALSE, device, metadata_buffer, sizeof(metadata_buffer), &metadata_size, bBackupHeader);
    
    if (!read_result || metadata_size == 0) {
        return -1; // No metadata found or read failed
    }
    
    // Convert password to null-terminated string
    char password[512];
    int password_len = pwd_len;
    if (password_len > 511) password_len = 511;
    memcpy(password, pwd, password_len);
    password[password_len] = '\0';
    
    // Recover the secret using Ocrypt
    unsigned char* secret_out = NULL;
    int secret_len_out = 0;
    int remaining_guesses_out = 0;
    unsigned char* updated_metadata_out = NULL;
    int updated_metadata_len_out = 0;
    
    int recover_result = ocrypt_recover_secret(
        (const unsigned char*)metadata_buffer,
        metadata_size,
        password,
        &secret_out,
        &secret_len_out,
        &remaining_guesses_out,
        &updated_metadata_out,
        &updated_metadata_len_out
    );
    
    if (recover_result != 0 || secret_out == NULL) {
        // Clean up
        if (secret_out) ocrypt_free_memory(secret_out);
        if (updated_metadata_out) ocrypt_free_memory(updated_metadata_out);
        burn(password, sizeof(password));
        return -2; // Recovery failed
    }
    
    // Derive header encryption key from the recovered secret (not volume data key)
    // Use PBKDF2-like expansion to generate required key length for XTS mode
    if (secret_len_out >= 32) {
        // Get salt from parameters for header key derivation
        const unsigned char* salt_ptr = (const unsigned char*)metadata_buffer; // Use metadata as additional entropy
        int salt_len_local = (int)metadata_size > 32 ? 32 : (int)metadata_size;
        
        int remaining = dklen;
        int offset = 0;
        int round = 0;
        
        while (remaining > 0) {
            sha256_ctx ctx;
            sha256_begin(&ctx);
            sha256_hash(secret_out, secret_len_out, &ctx);
            sha256_hash(salt_ptr, salt_len_local, &ctx);
            sha256_hash((const unsigned char*)&round, sizeof(round), &ctx);
            const char* header_context = "VeraCrypt Header Key";
            sha256_hash((const unsigned char*)header_context, strlen(header_context), &ctx);
            
            unsigned char round_key[32];
            sha256_end(round_key, &ctx);
            
            int copy_len = remaining > 32 ? 32 : remaining;
            memcpy(dk + offset, round_key, copy_len);
            
            offset += copy_len;
            remaining -= copy_len;
            round++;
        }
    } else {
        // Fallback: use the secret directly (padded/truncated to required length)
        memset(dk, 0, dklen);
        memcpy(dk, secret_out, secret_len_out < dklen ? secret_len_out : dklen);
    }
    
    // Update metadata if it changed (e.g., guess count updated)
    if (updated_metadata_out && updated_metadata_len_out > 0) {
        if (updated_metadata_len_out < TC_MAX_METADATA_SIZE) {
            WriteOcryptMetadata(FALSE, device, (const char*)updated_metadata_out, updated_metadata_len_out, bBackupHeader);
        }
    }
    
    // Clean up
    ocrypt_free_memory(secret_out);
    if (updated_metadata_out) ocrypt_free_memory(updated_metadata_out);
    burn(password, sizeof(password));
    
    return 0; // Success
#else
    // Linux implementation
    char metadata_buffer[TC_MAX_METADATA_SIZE];
    unsigned long metadata_size = 0;
    
    // Try to read Ocrypt metadata from volume header
    int read_result = ReadOcryptMetadata(FALSE, device, metadata_buffer, sizeof(metadata_buffer), &metadata_size, bBackupHeader);
    
    if (!read_result || metadata_size == 0) {
        return -1; // No metadata found or read failed
    }
    
    // Convert password to null-terminated string
    char password[512];
    int password_len = pwd_len;
    if (password_len > 511) password_len = 511;
    memcpy(password, pwd, password_len);
    password[password_len] = '\0';
    
    // Recover the secret using Ocrypt
    unsigned char* secret_out = NULL;
    int secret_len_out = 0;
    int remaining_guesses_out = 0;
    unsigned char* updated_metadata_out = NULL;
    int updated_metadata_len_out = 0;
    
    int recover_result = ocrypt_recover_secret(
        (const unsigned char*)metadata_buffer,
        metadata_size,
        password,
        &secret_out,
        &secret_len_out,
        &remaining_guesses_out,
        &updated_metadata_out,
        &updated_metadata_len_out
    );
    
    if (recover_result != 0 || secret_out == NULL) {
        // Clean up
        if (secret_out) ocrypt_free_memory(secret_out);
        if (updated_metadata_out) ocrypt_free_memory(updated_metadata_out);
        burn(password, sizeof(password));
        return -2; // Recovery failed
    }
    
    // Derive the volume key from the recovered secret
    if (secret_len_out >= 32) {
        // Hash the recovered secret to create the volume key
        sha256_ctx ctx;
        sha256_begin(&ctx);
        sha256_hash(secret_out, secret_len_out, &ctx);
        sha256_end(dk, &ctx);
    } else {
        // Fallback: use the secret directly (padded/truncated to required length)
        memset(dk, 0, dklen);
        memcpy(dk, secret_out, secret_len_out < dklen ? secret_len_out : dklen);
    }
    
    // Update metadata if it changed (e.g., guess count updated)
    if (updated_metadata_out && updated_metadata_len_out > 0) {
        if (updated_metadata_len_out < TC_MAX_METADATA_SIZE) {
            WriteOcryptMetadata(FALSE, device, (const char*)updated_metadata_out, updated_metadata_len_out, bBackupHeader);
        }
    }
    
    // Clean up
    ocrypt_free_memory(secret_out);
    if (updated_metadata_out) ocrypt_free_memory(updated_metadata_out);
    burn(password, sizeof(password));
    
    return 0; // Success
#endif
}

// Function to clean up global Ocrypt metadata
void ocrypt_cleanup_metadata()
{
    if (g_ocrypt_metadata) {
        ocrypt_free_memory(g_ocrypt_metadata);
        g_ocrypt_metadata = NULL;
        g_ocrypt_metadata_len = 0;
    }
}

// Reset the cached long-term secret for new volume operations
void ocrypt_reset_secret_cache()
{
    g_secret_generated = FALSE;
    memset(g_cached_long_term_secret, 0, 32);
    memset(g_cached_user_id, 0, 33);
    g_recovery_call_count = 0;
    memset(g_cached_derived_key, 0, 256);
    g_cached_derived_key_len = 0;
    g_recovery_successful = FALSE;
    fprintf(stderr, "[DEBUG] Reset Ocrypt secret cache for new volume operation\n");
    fflush(stderr);
}

// Helper function to load Ocrypt metadata from volume header
// Should be called after ReadEffectiveVolumeHeader and before ReadVolumeHeader
void ocrypt_load_metadata_if_available(BOOL bDevice, void* fileHandle, BOOL bBackupHeader)
{
#if defined(_WIN32) && !defined(TC_WINDOWS_BOOT) && !defined(DEVICE_DRIVER) && !defined(_UEFI)
    // Clean up any existing metadata first
    ocrypt_cleanup_metadata();
    
    char metadata_buffer[TC_MAX_METADATA_SIZE];
    DWORD metadata_size = 0;
    
    // Try to read Ocrypt metadata from volume header
    BOOL read_result = ReadOcryptMetadata(FALSE, (HANDLE)fileHandle, metadata_buffer, sizeof(metadata_buffer), &metadata_size, bBackupHeader);
    
    if (read_result && metadata_size > 0) {
        // Successfully read metadata - store it in global variables
        g_ocrypt_metadata_len = (int)metadata_size;
        g_ocrypt_metadata = (unsigned char*)malloc(g_ocrypt_metadata_len);
        if (g_ocrypt_metadata) {
            memcpy(g_ocrypt_metadata, metadata_buffer, g_ocrypt_metadata_len);
        } else {
            g_ocrypt_metadata_len = 0;
        }
    }
#elif !defined(TC_WINDOWS_BOOT) && !defined(DEVICE_DRIVER) && !defined(_UEFI)
    // Linux implementation
    // Clean up any existing metadata first
    ocrypt_cleanup_metadata();
    
    char metadata_buffer[TC_MAX_METADATA_SIZE];
    unsigned long metadata_size = 0;
    
    fprintf(stderr, "[DEBUG] ocrypt_load_metadata_if_available: Loading metadata from volume header\n");
    fflush(stderr);
    
    // Try to read Ocrypt metadata from volume header
    int read_result = ReadOcryptMetadata(FALSE, fileHandle, metadata_buffer, sizeof(metadata_buffer), &metadata_size, bBackupHeader);
    
    if (read_result && metadata_size > 0) {
        // Successfully read metadata - store it in global variables
        g_ocrypt_metadata_len = (int)metadata_size;
        g_ocrypt_metadata = (unsigned char*)malloc(g_ocrypt_metadata_len);
        if (g_ocrypt_metadata) {
            memcpy(g_ocrypt_metadata, metadata_buffer, g_ocrypt_metadata_len);
            fprintf(stderr, "[DEBUG] ocrypt_load_metadata_if_available: Successfully loaded %d bytes of metadata\n", g_ocrypt_metadata_len);
            fflush(stderr);
        } else {
            g_ocrypt_metadata_len = 0;
            fprintf(stderr, "[DEBUG] ocrypt_load_metadata_if_available: Failed to allocate memory for metadata\n");
            fflush(stderr);
        }
    } else {
        fprintf(stderr, "[DEBUG] ocrypt_load_metadata_if_available: No metadata found or read failed\n");
        fflush(stderr);
    }
#endif
}

// Function to save Ocrypt metadata to external file with backup
int save_ocrypt_metadata_to_file(const char* volume_path, const unsigned char* metadata, int metadata_len)
{
    if (!volume_path || !metadata || metadata_len <= 0) {
        return 0; // FALSE
    }
    
    // Create metadata filename: volume_path + ".metadata.json"
    char metadata_path[2048];
    char backup_path[2048];
    snprintf(metadata_path, sizeof(metadata_path), "%s.metadata.json", volume_path);
    snprintf(backup_path, sizeof(backup_path), "%s.metadata.json.old", volume_path);
    
    fprintf(stderr, "[DEBUG] Saving Ocrypt metadata to file: %s (%d bytes)\n", metadata_path, metadata_len);
    fflush(stderr);
    
    // Create backup of existing metadata file if it exists
    FILE* existing_file = fopen(metadata_path, "rb");
    if (existing_file) {
        fclose(existing_file);
        
        // Copy existing file to backup
        FILE* src = fopen(metadata_path, "rb");
        FILE* dst = fopen(backup_path, "wb");
        
        if (src && dst) {
            char buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fprintf(stderr, "[DEBUG] Created backup: %s\n", backup_path);
            fflush(stderr);
        }
        
        if (src) fclose(src);
        if (dst) fclose(dst);
    }
    
    // Write new metadata
    FILE* file = fopen(metadata_path, "wb");
    if (!file) {
        fprintf(stderr, "[DEBUG] Failed to create metadata file: %s\n", metadata_path);
        fflush(stderr);
        return 0; // FALSE
    }
    
    size_t written = fwrite(metadata, 1, metadata_len, file);
    fclose(file);
    
    if (written != (size_t)metadata_len) {
        fprintf(stderr, "[DEBUG] Failed to write complete metadata: wrote %zu of %d bytes\n", written, metadata_len);
        fflush(stderr);
        return 0; // FALSE
    }
    
    fprintf(stderr, "[DEBUG] Successfully saved %d bytes of metadata to %s\n", metadata_len, metadata_path);
    fflush(stderr);
    return 1; // TRUE
}

// Function to load Ocrypt metadata from external file
int load_ocrypt_metadata_from_file(const char* volume_path, unsigned char** metadata_out, int* metadata_len_out)
{
    if (!volume_path || !metadata_out || !metadata_len_out) {
        return 0; // FALSE
    }
    
    *metadata_out = NULL;
    *metadata_len_out = 0;
    
    // Create metadata filename: volume_path + ".metadata.json"
    char metadata_path[2048];
    snprintf(metadata_path, sizeof(metadata_path), "%s.metadata.json", volume_path);
    
    fprintf(stderr, "[DEBUG] Loading Ocrypt metadata from file: %s\n", metadata_path);
    fflush(stderr);
    
    FILE* file = fopen(metadata_path, "rb");
    if (!file) {
        fprintf(stderr, "[DEBUG] Metadata file not found: %s\n", metadata_path);
        fflush(stderr);
        return 0; // FALSE - not an error, just no metadata
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > TC_MAX_METADATA_SIZE * 10) {
        fprintf(stderr, "[DEBUG] Invalid metadata file size: %ld bytes\n", file_size);
        fflush(stderr);
        fclose(file);
        return 0; // FALSE
    }
    
    // Allocate memory and read file
    *metadata_out = (unsigned char*)malloc(file_size);
    if (!*metadata_out) {
        fprintf(stderr, "[DEBUG] Failed to allocate memory for metadata\n");
        fflush(stderr);
        fclose(file);
        return 0; // FALSE
    }
    
    size_t read_bytes = fread(*metadata_out, 1, file_size, file);
    fclose(file);
    
    if (read_bytes != (size_t)file_size) {
        fprintf(stderr, "[DEBUG] Failed to read complete metadata: read %zu of %ld bytes\n", read_bytes, file_size);
        fflush(stderr);
        free(*metadata_out);
        *metadata_out = NULL;
        return 0; // FALSE
    }
    
    *metadata_len_out = (int)file_size;
    fprintf(stderr, "[DEBUG] Successfully loaded %d bytes of metadata from %s\n", *metadata_len_out, metadata_path);
    fflush(stderr);
    return 1; // TRUE
}

// Function to set the current volume path for metadata operations
void set_current_volume_path(const char* volume_path)
{
    // Free any existing path
    if (g_current_volume_path) {
        free(g_current_volume_path);
        g_current_volume_path = NULL;
    }
    
    // Make a copy of the new path
    if (volume_path) {
        size_t len = strlen(volume_path);
        g_current_volume_path = (char*)malloc(len + 1);
        if (g_current_volume_path) {
            strcpy(g_current_volume_path, volume_path);
            fprintf(stderr, "[DEBUG] set_current_volume_path: Copied path '%s'\n", g_current_volume_path);
            fflush(stderr);
        } else {
            fprintf(stderr, "[DEBUG] set_current_volume_path: Failed to allocate memory for path\n");
            fflush(stderr);
        }
    }
}

// Header-based metadata helper functions
void set_current_file_handle(void* fileHandle, int isDevice)
{
    g_current_file_handle = fileHandle;
    g_current_is_device = isDevice;
    fprintf(stderr, "[DEBUG] set_current_file_handle: handle=%p, isDevice=%d\n", fileHandle, isDevice);
    fflush(stderr);
}

int save_ocrypt_metadata_to_header(const unsigned char* metadata, int metadata_len)
{
    if (!g_current_file_handle) {
        fprintf(stderr, "[DEBUG] save_ocrypt_metadata_to_header: No file handle set\n");
        fflush(stderr);
        return 0;
    }
    
    if (!metadata || metadata_len <= 0 || metadata_len > TC_MAX_METADATA_SIZE) {
        fprintf(stderr, "[DEBUG] save_ocrypt_metadata_to_header: Invalid parameters (len=%d)\n", metadata_len);
        fflush(stderr);
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] save_ocrypt_metadata_to_header: Saving %d bytes to header\n", metadata_len);
    fflush(stderr);
    
    // Write to both primary and backup headers
    int result1 = WriteOcryptMetadata(g_current_is_device, g_current_file_handle, (const char*)metadata, metadata_len, 0); // Primary
    int result2 = WriteOcryptMetadata(g_current_is_device, g_current_file_handle, (const char*)metadata, metadata_len, 1); // Backup
    
    if (result1 && result2) {
        fprintf(stderr, "[DEBUG] save_ocrypt_metadata_to_header: Successfully saved to both headers\n");
        fflush(stderr);
        return 1;
    } else {
        fprintf(stderr, "[DEBUG] save_ocrypt_metadata_to_header: Failed (primary=%d, backup=%d)\n", result1, result2);
        fflush(stderr);
        return 0;
    }
}

int load_ocrypt_metadata_from_header(unsigned char** metadata_out, int* metadata_len_out)
{
    if (!g_current_file_handle) {
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: No file handle set\n");
        fflush(stderr);
        return 0;
    }
    
    if (!metadata_out || !metadata_len_out) {
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: Invalid output parameters\n");
        fflush(stderr);
        return 0;
    }
    
    // Allocate buffer for reading metadata
    char* buffer = (char*)malloc(TC_MAX_METADATA_SIZE);
    if (!buffer) {
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: Memory allocation failed\n");
        fflush(stderr);
        return 0;
    }
    
    // Try to read from primary header first
    unsigned long metadataSize = 0;
    int result = ReadOcryptMetadata(g_current_is_device, g_current_file_handle, buffer, TC_MAX_METADATA_SIZE, &metadataSize, 0);
    
    if (!result || metadataSize == 0) {
        // Try backup header
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: Primary header failed, trying backup\n");
        fflush(stderr);
        result = ReadOcryptMetadata(g_current_is_device, g_current_file_handle, buffer, TC_MAX_METADATA_SIZE, &metadataSize, 1);
    }
    
    if (!result || metadataSize == 0) {
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: No metadata found in headers\n");
        fflush(stderr);
        free(buffer);
        *metadata_out = NULL;
        *metadata_len_out = 0;
        return 0;
    }
    
    // Allocate exact size for output
    *metadata_out = (unsigned char*)malloc(metadataSize);
    if (!*metadata_out) {
        fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: Output allocation failed\n");
        fflush(stderr);
        free(buffer);
        return 0;
    }
    
    memcpy(*metadata_out, buffer, metadataSize);
    *metadata_len_out = (int)metadataSize;
    
    fprintf(stderr, "[DEBUG] load_ocrypt_metadata_from_header: Successfully loaded %d bytes from header\n", *metadata_len_out);
    fflush(stderr);
    
    free(buffer);
    return 1;
}

int load_user_id_from_metadata(char* user_id_out, int user_id_out_size)
{
    if (user_id_out == NULL || user_id_out_size < 33) {
        return 0;
    }
    
    // Load metadata from header
    unsigned char* metadata = NULL;
    int metadata_len = 0;
    
    if (load_ocrypt_metadata_from_header(&metadata, &metadata_len) == 0) {
        return 0;
    }
    
    // Parse JSON to extract user_id
    // Simple JSON parsing - look for "user_id":"value"
    char* metadata_str = (char*)metadata;
    char* user_id_start = strstr(metadata_str, "\"user_id\":");
    if (user_id_start == NULL) {
        ocrypt_free_memory(metadata);
        return 0;
    }
    
    // Find the start of the user_id value (after the quote)
    char* value_start = strchr(user_id_start + 10, '"');
    if (value_start == NULL) {
        ocrypt_free_memory(metadata);
        return 0;
    }
    value_start++; // Skip the quote
    
    // Find the end of the user_id value
    char* value_end = strchr(value_start, '"');
    if (value_end == NULL) {
        ocrypt_free_memory(metadata);
        return 0;
    }
    
    // Extract user_id (should be exactly 32 hex characters)
    int user_id_len = value_end - value_start;
    if (user_id_len != 32) {
        ocrypt_free_memory(metadata);
        return 0;
    }
    
    // Copy the user_id
    memcpy(user_id_out, value_start, 32);
    user_id_out[32] = '\0';
    
    ocrypt_free_memory(metadata);
    return 1;
}

// NEW: Proper single-recovery Ocrypt function that uses version byte system
int ocrypt_single_recovery(const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, unsigned char *dk, int dklen)
{
    fprintf(stderr, "[DEBUG] *** ocrypt_single_recovery called! pwd_len=%d, dklen=%d ***\n", pwd_len, dklen);
    fflush(stderr);
    
    if (pwd_len > 300) {
        fprintf(stderr, "[DEBUG] ocrypt_single_recovery: Password too long (%d bytes), truncating to 300\n", pwd_len);
        pwd_len = 300;
    }
    
    // Convert password to null-terminated string
    char password[512];
    int password_len = pwd_len;
    if (password_len > 511) password_len = 511;
    memcpy(password, pwd, password_len);
    password[password_len] = '\0';
    
    // Generate deterministic user_id per volume (same for both primary and backup headers)
    char user_id[33];
    unsigned char random_bytes[16];
    { sha256_ctx ctx; sha256_begin(&ctx); sha256_hash(pwd, pwd_len, &ctx); sha256_end(random_bytes, &ctx); }
    for (int i = 0; i < 16; i++) {
        sprintf(user_id + (i * 2), "%02x", random_bytes[i]);
    }
    user_id[32] = '\0';
    
    fprintf(stderr, "[DEBUG] user_id='%.16s...', current_volume_path=%s\n", user_id, 
            g_current_volume_path ? g_current_volume_path : "NULL");
    fflush(stderr);
    
    // Check if we already have a successful recovery cached for this user_id and dklen
    if (g_recovery_successful && strcmp(g_cached_user_id, user_id) == 0 && g_cached_derived_key_len == dklen) {
        fprintf(stderr, "[DEBUG] Using cached recovery result (avoiding double recovery)\n");
        fflush(stderr);
        memcpy(dk, g_cached_derived_key, dklen);
        return 1; // Success
    }
    
    if (!g_current_file_handle) {
        fprintf(stderr, "[DEBUG] No file handle available for metadata access\n");
        fflush(stderr);
        return 0; // Failure
    }
    
    // STEP 1: Read the version byte to determine which metadata is newer
    int fd = (int)(intptr_t)g_current_file_handle;
    off_t baseOffset = TC_UNUSED_HEADER_SPACE_OFFSET; // For primary header
    unsigned char currentVersion = 0;
    
    fprintf(stderr, "[DEBUG] Reading version byte from offset %ld\n", (long)(baseOffset + TC_METADATA_VERSION_OFFSET));
    fflush(stderr);
    
    if (lseek(fd, baseOffset + TC_METADATA_VERSION_OFFSET, SEEK_SET) == -1) {
        fprintf(stderr, "[DEBUG] Failed to seek to version byte\n");
        fflush(stderr);
        return 0; // Failure
    }
    
    if (read(fd, &currentVersion, TC_METADATA_VERSION_SIZE) != TC_METADATA_VERSION_SIZE) {
        fprintf(stderr, "[DEBUG] No version byte found - no metadata present\n");
        fflush(stderr);
        return 0; // Failure - no metadata
    }
    
    // STEP 2: Determine which metadata copy to read based on version
    off_t metadataOffset;
    if (currentVersion == TC_METADATA_EVEN_VERSION) {
        metadataOffset = baseOffset + TC_METADATA_EVEN_OFFSET;
        fprintf(stderr, "[DEBUG] Reading EVEN metadata (version 0) at offset %ld\n", (long)metadataOffset);
    } else if (currentVersion == TC_METADATA_ODD_VERSION) {
        metadataOffset = baseOffset + TC_METADATA_ODD_OFFSET;
        fprintf(stderr, "[DEBUG] Reading ODD metadata (version 1) at offset %ld\n", (long)metadataOffset);
    } else {
        fprintf(stderr, "[DEBUG] Invalid version byte %d - no valid metadata\n", currentVersion);
        fflush(stderr);
        return 0; // Failure
    }
    fflush(stderr);
    
    // STEP 3: Read the metadata size and content from the newer copy
    if (lseek(fd, metadataOffset, SEEK_SET) != metadataOffset) {
        fprintf(stderr, "[DEBUG] Failed to seek to metadata at offset %ld\n", (long)metadataOffset);
        fflush(stderr);
        return 0; // Failure
    }
    
    uint32_t storedSize;
    if (read(fd, &storedSize, sizeof(storedSize)) != sizeof(storedSize)) {
        fprintf(stderr, "[DEBUG] Failed to read metadata size\n");
        fflush(stderr);
        return 0; // Failure
    }
    
    if (storedSize == 0 || storedSize > TC_MAX_METADATA_SIZE) {
        fprintf(stderr, "[DEBUG] Invalid metadata size: %u\n", storedSize);
        fflush(stderr);
        return 0; // Failure
    }
    
    // Allocate buffer and read metadata
    unsigned char* metadata = (unsigned char*)malloc(storedSize);
    if (!metadata) {
        fprintf(stderr, "[DEBUG] Failed to allocate memory for metadata\n");
        fflush(stderr);
        return 0; // Failure
    }
    
    if (read(fd, metadata, storedSize) != (ssize_t)storedSize) {
        fprintf(stderr, "[DEBUG] Failed to read metadata content\n");
        fflush(stderr);
        free(metadata);
        return 0; // Failure
    }
    
    fprintf(stderr, "[DEBUG] Successfully read %u bytes of metadata\n", storedSize);
    fflush(stderr);
    
    // STEP 4: Do Ocrypt recovery ONCE with the newer metadata
    unsigned char* secret_out = NULL;
    int secret_len_out = 0;
    int remaining_guesses_out = 0;
    unsigned char* updated_metadata_out = NULL;
    int updated_metadata_len_out = 0;
    
    fprintf(stderr, "[DEBUG] Attempting Ocrypt recovery with password\n");
    fflush(stderr);
    
    int recover_result = ocrypt_recover_secret(
        metadata,
        storedSize,
        password,
        &secret_out,
        &secret_len_out,
        &remaining_guesses_out,
        &updated_metadata_out,
        &updated_metadata_len_out
    );
    
    free(metadata); // Clean up original metadata
    
    if (recover_result != 0 || secret_out == NULL) {
        fprintf(stderr, "[DEBUG] Ocrypt recovery FAILED! result=%d, remaining_guesses=%d\n", 
               recover_result, remaining_guesses_out);
        fflush(stderr);
        
        // Clean up
        if (secret_out) ocrypt_free_memory(secret_out);
        if (updated_metadata_out) ocrypt_free_memory(updated_metadata_out);
        return 0; // Failure
    }
    
    fprintf(stderr, "[DEBUG] Ocrypt recovery SUCCESSFUL! secret_len=%d, remaining_guesses=%d\n", 
           secret_len_out, remaining_guesses_out);
    fflush(stderr);
    
    // STEP 5: Derive the volume key from the recovered secret
    fprintf(stderr, "[DEBUG] ====== RECOVERY SECRET COMPARISON ======\n");
    fprintf(stderr, "[DEBUG] RECOVERY: secret_out = ");
    for (int i = 0; i < (secret_len_out < 32 ? secret_len_out : 32); i++) fprintf(stderr, "%02x", secret_out[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[DEBUG] RECOVERY: salt = ");
    for (int i = 0; i < (salt_len < 32 ? salt_len : 32); i++) fprintf(stderr, "%02x", salt[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[DEBUG] Compare with REGISTRATION secret above!\n");
    fflush(stderr);
    
    // Derive header encryption key from the recovered secret (not volume data key)
    // Use PBKDF2-like expansion to generate required key length for XTS mode
    if (secret_len_out >= 32) {
        int remaining = dklen;
        int offset = 0;
        int round = 0;
        
        while (remaining > 0) {
            sha256_ctx ctx;
            sha256_begin(&ctx);
            sha256_hash(secret_out, secret_len_out, &ctx);
            sha256_hash(salt, salt_len, &ctx);
            sha256_hash((const unsigned char*)&round, sizeof(round), &ctx);
            const char* header_context = "VeraCrypt Header Key";
            sha256_hash((const unsigned char*)header_context, strlen(header_context), &ctx);
            
            unsigned char round_key[32];
            sha256_end(round_key, &ctx);
            
            int copy_len = remaining > 32 ? 32 : remaining;
            memcpy(dk + offset, round_key, copy_len);
            
            offset += copy_len;
            remaining -= copy_len;
            round++;
        }
        
        fprintf(stderr, "[DEBUG] RECOVERY: derived HEADER ENCRYPTION key = ");
        for (int i = 0; i < (dklen < 32 ? dklen : 32); i++) fprintf(stderr, "%02x", dk[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "[DEBUG] ==========================================\n");
        fflush(stderr);
    } else {
        // Fallback: use the secret directly (padded/truncated to required length)
        memset(dk, 0, dklen);
        memcpy(dk, secret_out, secret_len_out < dklen ? secret_len_out : dklen);
        
        fprintf(stderr, "[DEBUG] RECOVERY: using secret directly (padded) = ");
        for (int i = 0; i < (dklen < 32 ? dklen : 32); i++) fprintf(stderr, "%02x", dk[i]);
        fprintf(stderr, "\n");
        fflush(stderr);
    }
    
    // Cache the successful recovery result
    if (dklen <= 256) {
        memcpy(g_cached_derived_key, dk, dklen);
        g_cached_derived_key_len = dklen;
        strncpy(g_cached_user_id, user_id, 32);
        g_cached_user_id[32] = '\0';
        g_recovery_successful = TRUE;
        fprintf(stderr, "[DEBUG] Cached recovery result for future use\n");
        fflush(stderr);
    }
    
         // STEP 6: If metadata was updated, write it to the OTHER slot and toggle version byte ATOMICALLY
     if (updated_metadata_out && updated_metadata_len_out > 0) {
         fprintf(stderr, "[DEBUG] Writing updated metadata to alternate slot (atomic rollback-safe operation)\n");
         fflush(stderr);
         
         // Determine the target offset (opposite of current)
         off_t targetOffset;
         unsigned char newVersion;
         if (currentVersion == TC_METADATA_EVEN_VERSION) {
             targetOffset = baseOffset + TC_METADATA_ODD_OFFSET;
             newVersion = TC_METADATA_ODD_VERSION;
         } else {
             targetOffset = baseOffset + TC_METADATA_EVEN_OFFSET;
             newVersion = TC_METADATA_EVEN_VERSION;
         }
         
         // STEP 6A: First write updated metadata to alternate slot
         if (lseek(fd, targetOffset, SEEK_SET) == targetOffset) {
             uint32_t writeSize = (uint32_t)updated_metadata_len_out;
             if (write(fd, &writeSize, sizeof(writeSize)) == sizeof(writeSize) &&
                 write(fd, updated_metadata_out, updated_metadata_len_out) == updated_metadata_len_out) {
                 
                 // STEP 6B: Ensure metadata is written to disk before toggling version byte
                 fsync(fd);
                 fprintf(stderr, "[DEBUG] Updated metadata written to alternate slot, now toggling version byte\n");
                 fflush(stderr);
                 
                 // STEP 6C: ONLY NOW toggle the version byte (atomic operation)
                 if (lseek(fd, baseOffset + TC_METADATA_VERSION_OFFSET, SEEK_SET) == baseOffset + TC_METADATA_VERSION_OFFSET &&
                     write(fd, &newVersion, TC_METADATA_VERSION_SIZE) == TC_METADATA_VERSION_SIZE) {
                     
                     fsync(fd); // Ensure version byte is committed
                     fprintf(stderr, "[DEBUG] SUCCESS: Atomically updated metadata and toggled version byte to %d\n", newVersion);
                     fprintf(stderr, "[DEBUG] Next recovery will use the updated metadata with rollback safety\n");
                     fflush(stderr);
                 } else {
                     fprintf(stderr, "[DEBUG] CRITICAL: Failed to toggle version byte - metadata updated but not active\n");
                     fprintf(stderr, "[DEBUG] Next recovery will still use old metadata (rollback safety preserved)\n");
                     fflush(stderr);
                 }
             } else {
                 fprintf(stderr, "[DEBUG] Failed to write updated metadata to alternate slot\n");
                 fflush(stderr);
             }
         } else {
             fprintf(stderr, "[DEBUG] Failed to seek to alternate metadata slot\n");
             fflush(stderr);
         }
     }
    
    // Clean up
    ocrypt_free_memory(secret_out);
    if (updated_metadata_out) {
        ocrypt_free_memory(updated_metadata_out);
    }
    
    return 1; // Success
}

// Magic string detection function
int detect_ocrypt_magic_string(const char* volume_path) {
    if (!volume_path) {
        return 0; // Not an Ocrypt volume
    }
    
#ifdef _WIN32
    HANDLE hFile = CreateFileA(volume_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0; // Cannot open file
    }
    
    LARGE_INTEGER offset;
    offset.QuadPart = TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET;
    
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return 0; // Cannot seek
    }
    
    unsigned char magic_buffer[TC_OCRYPT_MAGIC_SIZE];
    DWORD bytesRead;
    
    if (!ReadFile(hFile, magic_buffer, TC_OCRYPT_MAGIC_SIZE, &bytesRead, NULL) || 
        bytesRead != TC_OCRYPT_MAGIC_SIZE) {
        CloseHandle(hFile);
        return 0; // Cannot read magic string
    }
    
    CloseHandle(hFile);
    
    // Check for "OCRYPT" at the beginning of the magic string
    if (memcmp(magic_buffer, "OCRYPT", 6) == 0) {
        return 1; // This is an Ocrypt volume
    }
    
    return 0; // Not an Ocrypt volume
#else
    // Unix implementation
    int fd = open(volume_path, O_RDONLY);
    if (fd == -1) {
        return 0; // Cannot open file
    }
    
    off_t offset = TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        close(fd);
        return 0; // Cannot seek
    }
    
    unsigned char magic_buffer[TC_OCRYPT_MAGIC_SIZE];
    if (read(fd, magic_buffer, TC_OCRYPT_MAGIC_SIZE) != TC_OCRYPT_MAGIC_SIZE) {
        close(fd);
        return 0; // Cannot read magic string
    }
    
    close(fd);
    
    // Check for "OCRYPT" at the beginning of the magic string
    if (memcmp(magic_buffer, "OCRYPT", 6) == 0) {
        return 1; // This is an Ocrypt volume
    }
    
    return 0; // Not an Ocrypt volume
#endif
}

// Magic string writing function
int write_ocrypt_magic_string(void* fileHandle, int bBackupHeader) {
    if (!fileHandle) {
        return 0; // Invalid handle
    }
    
#ifdef _WIN32
    HANDLE hFile = (HANDLE)fileHandle;
    LARGE_INTEGER offset;
    DWORD bytesWritten;
    
    // Calculate offset (absolute position in file)
    offset.QuadPart = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET) : 
        (TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET);
    
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return 0; // Cannot seek
    }
    
    // Write the magic string
    if (!WriteFile(hFile, TC_OCRYPT_MAGIC_STRING, TC_OCRYPT_MAGIC_SIZE, &bytesWritten, NULL) || 
        bytesWritten != TC_OCRYPT_MAGIC_SIZE) {
        return 0; // Cannot write magic string
    }
    
    // Write initial version byte (EVEN version = 0)
    offset.QuadPart = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET + TC_METADATA_VERSION_OFFSET) : 
        (TC_UNUSED_HEADER_SPACE_OFFSET + TC_METADATA_VERSION_OFFSET);
    
    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
        return 0; // Cannot seek to version byte
    }
    
    unsigned char initialVersion = TC_METADATA_EVEN_VERSION;
    if (!WriteFile(hFile, &initialVersion, TC_METADATA_VERSION_SIZE, &bytesWritten, NULL) || 
        bytesWritten != TC_METADATA_VERSION_SIZE) {
        return 0; // Cannot write version byte
    }
    
    FlushFileBuffers(hFile);
    return 1; // Success
#else
    // Unix implementation
    int fd = (int)(uintptr_t)fileHandle;
    
    // Calculate offset (absolute position in file)
    off_t offset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET) : 
        (TC_UNUSED_HEADER_SPACE_OFFSET + TC_OCRYPT_MAGIC_OFFSET);
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return 0; // Cannot seek
    }
    
    // Write the magic string
    if (write(fd, TC_OCRYPT_MAGIC_STRING, TC_OCRYPT_MAGIC_SIZE) != TC_OCRYPT_MAGIC_SIZE) {
        return 0; // Cannot write magic string
    }
    
    // Write initial version byte (EVEN version = 0)
    offset = bBackupHeader ? 
        (65536 + TC_UNUSED_HEADER_SPACE_OFFSET + TC_METADATA_VERSION_OFFSET) : 
        (TC_UNUSED_HEADER_SPACE_OFFSET + TC_METADATA_VERSION_OFFSET);
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return 0; // Cannot seek to version byte
    }
    
    unsigned char initialVersion = TC_METADATA_EVEN_VERSION;
    if (write(fd, &initialVersion, TC_METADATA_VERSION_SIZE) != TC_METADATA_VERSION_SIZE) {
        return 0; // Cannot write version byte
    }
    
    fsync(fd);
    return 1; // Success
#endif
}
