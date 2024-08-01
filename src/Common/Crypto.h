/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is 
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is 
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses' 
 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

/* Update the following when adding a new cipher or EA:

   Crypto.h:
     ID #define
     MAX_EXPANDED_KEY #define

   Crypto.c:
     Ciphers[]
     EncryptionAlgorithms[]
     CipherInit()
     EncipherBlock()
     DecipherBlock()

*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include "Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Encryption data unit size, which may differ from the sector size and must always be 512
#define ENCRYPTION_DATA_UNIT_SIZE	512

// Size of the salt (in bytes)
#define PKCS5_SALT_SIZE				64

// Size of the volume header area containing concatenated master key(s) and secondary key(s) (XTS mode)
#define MASTER_KEYDATA_SIZE			256

// The first PRF to try when mounting
#define FIRST_PRF_ID		1	

// Hash algorithms (pseudorandom functions). 
enum
{
	SHA512 = FIRST_PRF_ID,
	WHIRLPOOL,
	SHA256,
	BLAKE2S,
	STREEBOG,
	HASH_ENUM_END_ID
};

// The last PRF to try when mounting and also the number of implemented PRFs
#define LAST_PRF_ID			(HASH_ENUM_END_ID - 1)	

#define BLAKE2S_BLOCKSIZE		64
#define BLAKE2S_DIGESTSIZE		32

#define SHA256_BLOCKSIZE		64
#define SHA256_DIGESTSIZE		32

#define SHA512_BLOCKSIZE		128
#define SHA512_DIGESTSIZE		64

#define WHIRLPOOL_BLOCKSIZE		64
#define WHIRLPOOL_DIGESTSIZE	64

#define STREEBOG_BLOCKSIZE 64
#define STREEBOG_DIGESTSIZE 64

#define MAX_DIGESTSIZE			WHIRLPOOL_DIGESTSIZE

#define DEFAULT_HASH_ALGORITHM			FIRST_PRF_ID
#define DEFAULT_HASH_ALGORITHM_BOOT		SHA256

// The mode of operation used for newly created volumes and first to try when mounting
#define FIRST_MODE_OF_OPERATION_ID		1

// Modes of operation
enum
{
	/* If you add/remove a mode, update the following: GetMaxPkcs5OutSize(), EAInitMode() */

	XTS = FIRST_MODE_OF_OPERATION_ID,
	MODE_ENUM_END_ID
};


// The last mode of operation to try when mounting and also the number of implemented modes
#define LAST_MODE_OF_OPERATION		(MODE_ENUM_END_ID - 1)

// Ciphertext/plaintext block size for XTS mode (in bytes)
#define BYTES_PER_XTS_BLOCK			16

// Number of ciphertext/plaintext blocks per XTS data unit
#define BLOCKS_PER_XTS_DATA_UNIT	(ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK)


// Cipher IDs
enum
{
	NONE = 0,
	AES,
	SERPENT,			
	TWOFISH,
	CAMELLIA,
	KUZNYECHIK
};

typedef struct
{
	int Id;					// Cipher ID
#ifdef TC_WINDOWS_BOOT
	char *Name;				// Name
#else
	wchar_t *Name;			// Name
#endif
	int BlockSize;			// Block size (bytes)
	int KeySize;			// Key size (bytes)
	int KeyScheduleSize;	// Scheduled key size (bytes)
} Cipher;

typedef struct
{
	int Ciphers[4];			// Null terminated array of ciphers used by encryption algorithm
	int Modes[LAST_MODE_OF_OPERATION + 1];			// Null terminated array of modes of operation
#ifndef TC_WINDOWS_BOOT
	BOOL MbrSysEncEnabled;
#endif
	int FormatEnabled;
} EncryptionAlgorithm;

#ifndef TC_WINDOWS_BOOT
typedef struct
{
	int Id;					// Hash ID
	wchar_t *Name;				// Name
	BOOL Deprecated;
	BOOL SystemEncryption;	// Available for system encryption
} Hash;
#endif

// Maxium length of scheduled key
#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_AES)
#	define AES_KS				(sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx))
#else
#	define AES_KS				(sizeof(aes_context))
#endif
#define SERPENT_KS			(140 * 4)

#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE

#	ifdef TC_WINDOWS_BOOT_AES
#		define MAX_EXPANDED_KEY	AES_KS
#	elif defined (TC_WINDOWS_BOOT_SERPENT)
#		define MAX_EXPANDED_KEY	SERPENT_KS
#	elif defined (TC_WINDOWS_BOOT_TWOFISH)
#		define MAX_EXPANDED_KEY	TWOFISH_KS
#	elif defined (TC_WINDOWS_BOOT_CAMELLIA)
#		define MAX_EXPANDED_KEY	CAMELLIA_KS
#	endif

#else
#ifdef TC_WINDOWS_BOOT
#define MAX_EXPANDED_KEY	VC_MAX((AES_KS + SERPENT_KS + TWOFISH_KS), CAMELLIA_KS)
#else
#define MAX_EXPANDED_KEY	VC_MAX(VC_MAX(VC_MAX((AES_KS + SERPENT_KS + TWOFISH_KS), CAMELLIA_KS + KUZNYECHIK_KS + SERPENT_KS), KUZNYECHIK_KS + TWOFISH_KS), AES_KS + KUZNYECHIK_KS)
#endif
#endif

#ifdef DEBUG
#	define PRAND_DISK_WIPE_PASSES	3
#else
#	define PRAND_DISK_WIPE_PASSES	256
#endif

/* specific value for volume header wipe used only when drive is fully wiped. */
#define PRAND_HEADER_WIPE_PASSES	3

#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_AES)
#	include "Aes.h"
#else
#	include "AesSmall.h"
#endif

#include "Aes_hw_cpu.h"
#if !defined (TC_WINDOWS_BOOT) && !defined (_UEFI)
#	include "SerpentFast.h"
#else
#	include "Serpent.h"
#endif
#include "Twofish.h"

#include "blake2.h"
#ifndef TC_WINDOWS_BOOT
#	include "Sha2.h"
#	include "Whirlpool.h"
#	include "Streebog.h"
#	include "kuznyechik.h"
#	include "Camellia.h"
#if !defined (_UEFI)
#   include "chachaRng.h"
#   ifdef _WIN64
#   include "t1ha.h"
#   endif
#endif
#else
#	include "CamelliaSmall.h"
#endif

#include "GfMul.h"
#include "Password.h"

#ifndef TC_WINDOWS_BOOT

#include "config.h"

typedef struct keyInfo_t
{
	int noIterations;					/* Number of times to iterate (PKCS-5) */
	int keyLength;						/* Length of the key */
	uint64 dummy;						/* Dummy field to ensure 16-byte alignment of this structure */
	__int8 salt[PKCS5_SALT_SIZE];		/* PKCS-5 salt */
	CRYPTOPP_ALIGN_DATA(16) __int8 master_keydata[MASTER_KEYDATA_SIZE];		/* Concatenated master primary and secondary key(s) (XTS mode). For LRW (deprecated/legacy), it contains the tweak key before the master key(s). For CBC (deprecated/legacy), it contains the IV seed before the master key(s). */
	CRYPTOPP_ALIGN_DATA(16) __int8 userKey[MAX_PASSWORD];		/* Password (to which keyfiles may have been applied). WITHOUT +1 for the null terminator. */
} KEY_INFO, *PKEY_INFO;

#endif

typedef struct CRYPTO_INFO_t
{
	int ea;									/* Encryption algorithm ID */
	int mode;								/* Mode of operation (e.g., XTS) */
	int pkcs5;								/* PRF algorithm */

	unsigned __int8 ks[MAX_EXPANDED_KEY];	/* Primary key schedule (if it is a cascade, it conatins multiple concatenated keys) */
	unsigned __int8 ks2[MAX_EXPANDED_KEY];	/* Secondary key schedule (if cascade, multiple concatenated) for XTS mode. */

	BOOL hiddenVolume;						// Indicates whether the volume is mounted/mountable as hidden volume

#ifndef TC_WINDOWS_BOOT
	uint16 HeaderVersion;

#ifdef TC_WINDOWS_DRIVER
	unsigned __int8 master_keydata_hash[BLAKE2S_DIGESTSIZE];
#else
	CRYPTOPP_ALIGN_DATA(16) unsigned __int8 master_keydata[MASTER_KEYDATA_SIZE];	/* This holds the volume header area containing concatenated master key(s) and secondary key(s) (XTS mode). For LRW (deprecated/legacy), it contains the tweak key before the master key(s). For CBC (deprecated/legacy), it contains the IV seed before the master key(s). */
	CRYPTOPP_ALIGN_DATA(16) unsigned __int8 k2[MASTER_KEYDATA_SIZE];				/* For XTS, this contains the secondary key (if cascade, multiple concatenated). For LRW (deprecated/legacy), it contains the tweak key. For CBC (deprecated/legacy), it contains the IV seed. */
#endif

	int noIterations;	
	int volumePim;

	BOOL bProtectHiddenVolume;			// Indicates whether the volume contains a hidden volume to be protected against overwriting
	BOOL bHiddenVolProtectionAction;		// TRUE if a write operation has been denied by the driver in order to prevent the hidden volume from being overwritten (set to FALSE upon volume mount).
	
	uint64 volDataAreaOffset;		// Absolute position, in bytes, of the first data sector of the volume.

	uint64 hiddenVolumeSize;		// Size of the hidden volume excluding the header (in bytes). Set to 0 for standard volumes.
	uint64 hiddenVolumeOffset;	// Absolute position, in bytes, of the first hidden volume data sector within the host volume (provided that there is a hidden volume within). This must be set for all hidden volumes; in case of a normal volume, this variable is only used when protecting a hidden volume within it.
	uint64 hiddenVolumeProtectedSize;

	BOOL bPartitionInInactiveSysEncScope;	// If TRUE, the volume is a partition located on an encrypted system drive and mounted without pre-boot authentication.

	UINT64_STRUCT FirstDataUnitNo;			// First data unit number of the volume. This is 0 for file-hosted and non-system partition-hosted volumes. For partitions within key scope of system encryption this reflects real physical offset within the device (this is used e.g. when such a partition is mounted as a regular volume without pre-boot authentication).

	uint16 RequiredProgramVersion;
	BOOL LegacyVolume;

	uint32 SectorSize;

	BOOL bVulnerableMasterKey; // TRUE if XTS primary key is identical to secondary key (i.e. the volume is vulnerable to attack on XTS mode)

#endif // !TC_WINDOWS_BOOT

	UINT64_STRUCT VolumeSize;

	UINT64_STRUCT EncryptedAreaStart;
	UINT64_STRUCT EncryptedAreaLength;

	uint32 HeaderFlags;

} CRYPTO_INFO, *PCRYPTO_INFO;

#if defined(_WIN32) || defined(_UEFI)

#pragma pack (push)
#pragma pack(1)

typedef struct BOOT_CRYPTO_HEADER_t
{
	__int16 ea;									/* Encryption algorithm ID */
	__int16 mode;								/* Mode of operation (e.g., XTS) */
	__int16 pkcs5;								/* PRF algorithm */

} BOOT_CRYPTO_HEADER, *PBOOT_CRYPTO_HEADER;

#pragma pack (pop)

#endif

PCRYPTO_INFO crypto_open (void);
#ifndef TC_WINDOWS_BOOT
void crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen);
void crypto_eraseKeys (PCRYPTO_INFO cryptoInfo);
#endif
void crypto_close (PCRYPTO_INFO cryptoInfo);

int CipherGetBlockSize (int cipher);
int CipherGetKeySize (int cipher);
int CipherGetKeyScheduleSize (int cipher);
BOOL CipherSupportsIntraDataUnitParallelization (int cipher);

#ifndef TC_WINDOWS_BOOT
const wchar_t * CipherGetName (int cipher);
#endif

int CipherInit (int cipher, unsigned char *key, unsigned char *ks);
#ifndef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
int EAInit (int ea, unsigned char *key, unsigned char *ks);
#else
int EAInit (unsigned char *key, unsigned char *ks);
#endif
BOOL EAInitMode (PCRYPTO_INFO ci, unsigned char* key2);
void EncipherBlock(int cipher, void *data, void *ks);
void DecipherBlock(int cipher, void *data, void *ks);
#ifndef TC_WINDOWS_BOOT
void EncipherBlocks (int cipher, void *dataPtr, void *ks, size_t blockCount);
void DecipherBlocks (int cipher, void *dataPtr, void *ks, size_t blockCount);
#endif

int EAGetFirst ();
int EAGetCount (void);
int EAGetNext (int previousEA);
#ifndef TC_WINDOWS_BOOT
wchar_t * EAGetName (wchar_t *buf, size_t bufLen, int ea, int guiDisplay);
int EAGetByName (wchar_t *name);
#endif
int EAGetKeySize (int ea);
int EAGetFirstMode (int ea);
int EAGetNextMode (int ea, int previousModeId);
#ifndef TC_WINDOWS_BOOT
wchar_t * EAGetModeName (int ea, int mode, BOOL capitalLetters);
#endif
int EAGetKeyScheduleSize (int ea);
int EAGetLargestKey ();
int EAGetLargestKeyForMode (int mode);

int EAGetCipherCount (int ea);
int EAGetFirstCipher (int ea);
int EAGetLastCipher (int ea);
int EAGetNextCipher (int ea, int previousCipherId);
int EAGetPreviousCipher (int ea, int previousCipherId);
#ifndef TC_WINDOWS_BOOT
int EAIsFormatEnabled (int ea);
int EAIsMbrSysEncEnabled (int ea);
#endif
BOOL EAIsModeSupported (int ea, int testedMode);


#ifndef TC_WINDOWS_BOOT
const wchar_t *HashGetName (int hash_algo_id);
#ifdef _WIN32
int HashGetIdByName (wchar_t *name);
#endif
Hash *HashGet (int id);
void HashGetName2 (wchar_t *buf, size_t bufLen, int hashId);
BOOL HashIsDeprecated (int hashId);
BOOL HashForSystemEncryption (int hashId);
int GetMaxPkcs5OutSize (void);
#endif


void EncryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, uint32 nbrUnits, PCRYPTO_INFO ci);
void EncryptDataUnitsCurrentThread (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
void DecryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, uint32 nbrUnits, PCRYPTO_INFO ci);
void DecryptDataUnitsCurrentThread (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
void EncryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo);
void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo);

#if defined(_WIN64) && !defined (_UEFI)
BOOL InitializeSecurityParameters(GetRandSeedFn rngCallback);
void ClearSecurityParameters();
#ifdef TC_WINDOWS_DRIVER
void VcProtectMemory (uint64 encID, unsigned char* pbData, size_t cbData, unsigned char* pbData2, size_t cbData2);
#else
void VcProtectMemory (uint64 encID, unsigned char* pbData, size_t cbData, 
							unsigned char* pbData2, size_t cbData2,
							unsigned char* pbData3, size_t cbData3,
							unsigned char* pbData4, size_t cbData4);
#endif
uint64 VcGetEncryptionID (PCRYPTO_INFO pCryptoInfo);
void VcProtectKeys (PCRYPTO_INFO pCryptoInfo, uint64 encID);
void VcUnprotectKeys (PCRYPTO_INFO pCryptoInfo, uint64 encID);
void EncryptDataUnitsCurrentThreadEx (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
void DecryptDataUnitsCurrentThreadEx (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
#else
#define EncryptDataUnitsCurrentThreadEx EncryptDataUnitsCurrentThread
#define DecryptDataUnitsCurrentThreadEx DecryptDataUnitsCurrentThread
#endif

BOOL IsAesHwCpuSupported ();
void EnableHwEncryption (BOOL enable);
BOOL IsHwEncryptionEnabled ();

BOOL IsCpuRngSupported ();
void EnableCpuRng (BOOL enable);
BOOL IsCpuRngEnabled ();

BOOL IsRamEncryptionSupported ();
void EnableRamEncryption (BOOL enable);
BOOL IsRamEncryptionEnabled ();

#ifdef __cplusplus
}
#endif

#endif		/* CRYPTO_H */
