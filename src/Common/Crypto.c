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

#include "Tcdefs.h"
#include "Crypto.h"
#include "Xts.h"
#include "Crc.h"
#include "Common/Endian.h"
#if !defined(_UEFI)
#include <string.h>
#ifndef TC_WINDOWS_BOOT
#include "EncryptionThreadPool.h"
#endif
#endif
#include "Volumes.h"
#include "cpu.h"

#pragma warning (disable:4706) // assignment within conditional expression
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

#ifndef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE

// Cipher configuration
static Cipher Ciphers[] =
{
//								Block Size	Key Size	Key Schedule Size
//	  ID		Name			(Bytes)		(Bytes)		(Bytes)
#ifdef TC_WINDOWS_BOOT
	{ AES,		"AES",			16,			32,			AES_KS				},
	{ SERPENT,	"Serpent",		16,			32,			140*4				},
	{ TWOFISH,	"Twofish",		16,			32,			TWOFISH_KS			},
#else
	{ AES,		L"AES",			16,			32,			AES_KS				},
	{ SERPENT,	L"Serpent",		16,			32,			140*4				},
	{ TWOFISH,	L"Twofish",		16,			32,			TWOFISH_KS			},
	{ CAMELLIA,	L"Camellia",	16,			32,			CAMELLIA_KS			},
#if defined(CIPHER_GOST89)
	{ GOST89,	L"GOST89",		16,			32,			GOST_KS },
#endif  // defined(CIPHER_GOST89)
	{ KUZNYECHIK,	L"Kuznyechik",16,		32,			KUZNYECHIK_KS },
#endif
	{ 0,		0,				0,			0,			0					}
};


// Encryption algorithm configuration
static EncryptionAlgorithm EncryptionAlgorithms[] =
{
	//  Cipher(s)                     Modes						FormatEnabled

#ifndef TC_WINDOWS_BOOT

	{ { 0,							0 }, { 0, 0},		0, 0 },	// Must be all-zero
	{ { AES,							0 }, { XTS, 0 },	1, 1 },
	{ { SERPENT,					0 }, { XTS, 0 },	1, 1 },
	{ { TWOFISH,					0 }, { XTS, 0 },	1, 1 },
	{ { CAMELLIA,					0 }, { XTS, 0 },	1, 1 },
#if defined(CIPHER_GOST89)
	{ { GOST89,						0 }, { XTS, 0 },	0, 0 },
#endif  // defined(CIPHER_GOST89)
	{ { KUZNYECHIK,				0 }, { XTS, 0 },	0, 1 },
	{ { TWOFISH, AES,				0 }, { XTS, 0 },	1, 1 },
	{ { SERPENT, TWOFISH, AES,	0 }, { XTS, 0 },	1, 1 },
	{ { AES, SERPENT,				0 }, { XTS, 0 },	1, 1 },
	{ { AES, TWOFISH, SERPENT,	0 }, { XTS, 0 },	1, 1 },
	{ { SERPENT, TWOFISH,		0 }, { XTS, 0 },	1, 1 },
	{ { 0,							0 }, { 0,    0},	0, 0 }		// Must be all-zero

#else // TC_WINDOWS_BOOT

	// Encryption algorithms available for boot drive encryption
	{ { 0,						0 }, { 0, 0 },		0 },	// Must be all-zero
	{ { AES,					0 }, { XTS, 0 },	1 },
	{ { SERPENT,				0 }, { XTS, 0 },	1 },
	{ { TWOFISH,				0 }, { XTS, 0 },	1 },
	{ { TWOFISH, AES,			0 }, { XTS, 0 },	1 },
	{ { SERPENT, TWOFISH, AES,	0 }, { XTS, 0 },	1 },
	{ { AES, SERPENT,			0 }, { XTS, 0 },	1 },
	{ { AES, TWOFISH, SERPENT,	0 }, { XTS, 0 },	1 },
	{ { SERPENT, TWOFISH,		0 }, { XTS, 0 },	1 },
	{ { 0,						0 }, { 0, 0 },		0 },	// Must be all-zero

#endif

};


#ifndef TC_WINDOWS_BOOT
// Hash algorithms
static Hash Hashes[] =
{	// ID				Name					Deprecated	System Encryption
	{ SHA512,		L"SHA-512",				FALSE,	FALSE },
	{ WHIRLPOOL,	L"Whirlpool",			FALSE,	FALSE },
	{ SHA256,		L"SHA-256",				FALSE,	TRUE },
	{ RIPEMD160,	L"RIPEMD-160",			TRUE,		TRUE },
	{ STREEBOG,		L"Streebog",	FALSE,	FALSE },
	{ 0, 0, 0 }
};
#endif

/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
int CipherInit (int cipher, unsigned char *key, unsigned __int8 *ks)
{
	int retVal = ERR_SUCCESS;

	switch (cipher)
	{
	case AES:
#ifndef TC_WINDOWS_BOOT
		if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ks) != EXIT_SUCCESS)
			return ERR_CIPHER_INIT_FAILURE;

		if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ks + sizeof(aes_encrypt_ctx))) != EXIT_SUCCESS)
			return ERR_CIPHER_INIT_FAILURE;
#else
		if (aes_set_key (key, (length_type) CipherGetKeySize(AES), (aes_context *) ks) != 0)
			return ERR_CIPHER_INIT_FAILURE;
#endif
		break;

	case SERPENT:
		serpent_set_key (key, ks);
		break;
		
	case TWOFISH:
		twofish_set_key ((TwofishInstance *)ks, (const u4byte *)key);
		break;

#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_CAMELLIA)
	case CAMELLIA:
		camellia_set_key (key, ks);
		break;
#endif

#if !defined(TC_WINDOWS_BOOT) 
#if defined(CIPHER_GOST89)
	case GOST89:
		gost_set_key(key, (gost_kds*)ks, 1);
		break;
#endif // && defined(CIPHER_GOST89)
	case KUZNYECHIK:
		kuznyechik_set_key(key, (kuznyechik_kds*)ks);
		break;
#endif // !defined(TC_WINDOWS_BOOT)

	default:
		// Unknown/wrong cipher ID
		return ERR_CIPHER_INIT_FAILURE;
	}

	return retVal;
}

void EncipherBlock(int cipher, void *data, void *ks)
{
	switch (cipher)
	{
	case AES:	
		// In 32-bit kernel mode, due to KeSaveFloatingPointState() overhead, AES instructions can be used only when processing the whole data unit.
#if (defined (_WIN64) || !defined (TC_WINDOWS_DRIVER)) && !defined (TC_WINDOWS_BOOT)
		if (IsAesHwCpuSupported())
			aes_hw_cpu_encrypt (ks, data);
		else
#endif
			aes_encrypt (data, data, ks);
		break;

	case TWOFISH:		twofish_encrypt (ks, data, data); break;
	case SERPENT:		serpent_encrypt (data, data, ks); break;
#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_CAMELLIA)
	case CAMELLIA:		camellia_encrypt (data, data, ks); break;
#endif
#if !defined(TC_WINDOWS_BOOT)
#if defined(CIPHER_GOST89)
	case GOST89:		gost_encrypt(data, data, ks, 1); break;
#endif // defined(CIPHER_GOST89)
	case KUZNYECHIK:		kuznyechik_encrypt_block(data, data, ks); break;
#endif // !defined(TC_WINDOWS_BOOT) 
	default:			TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
}

#ifndef TC_WINDOWS_BOOT

void EncipherBlocks (int cipher, void *dataPtr, void *ks, size_t blockCount)
{
	byte *data = dataPtr;
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
#endif

	if (cipher == AES
		&& (blockCount & (32 - 1)) == 0
		&& IsAesHwCpuSupported()
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		&& NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState))
#endif
		)
	{
		while (blockCount > 0)
		{
			aes_hw_cpu_encrypt_32_blocks (ks, data);

			data += 32 * 16;
			blockCount -= 32;
		}

#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	}
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined (_UEFI)
	else if (cipher == SERPENT
			&& (blockCount >= 4)
			&& HasSSE2()
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
			&& NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState))
#endif
		)
	{
		serpent_encrypt_blocks (data, data, blockCount, ks);
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	}
#endif
#if CRYPTOPP_BOOL_X64
   else if (cipher == TWOFISH)	{
			twofish_encrypt_blocks(ks, data, data, (uint32) blockCount);
	}
	else if (cipher == CAMELLIA)	{
			camellia_encrypt_blocks(ks, data, data, (uint32) blockCount);
	}
#endif
	else if (cipher == GOST89)	{
			gost_encrypt(data, data, ks, (int)blockCount);
	}
	else
	{
		size_t blockSize = CipherGetBlockSize (cipher);
		while (blockCount-- > 0)
		{
			EncipherBlock (cipher, data, ks);
			data += blockSize;
		}
	}
}

#endif // !TC_WINDOWS_BOOT

void DecipherBlock(int cipher, void *data, void *ks)
{
	switch (cipher)
	{
	case SERPENT:	serpent_decrypt (data, data, ks); break;
	case TWOFISH:	twofish_decrypt (ks, data, data); break;
#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_CAMELLIA)
	case CAMELLIA:	camellia_decrypt (data, data, ks); break;
#endif
#if !defined(TC_WINDOWS_BOOT)
#if defined(CIPHER_GOST89)
	case GOST89:	gost_decrypt(data, data, ks, 1); break;
#endif // defined(CIPHER_GOST89)
	case KUZNYECHIK:	kuznyechik_decrypt_block(data, data, ks); break;
#endif // !defined(TC_WINDOWS_BOOT)


#ifndef TC_WINDOWS_BOOT

	case AES:
#if defined (_WIN64) || !defined (TC_WINDOWS_DRIVER)
		if (IsAesHwCpuSupported())
			aes_hw_cpu_decrypt ((byte *) ks + sizeof (aes_encrypt_ctx), data);
		else
#endif
			aes_decrypt (data, data, (void *) ((char *) ks + sizeof(aes_encrypt_ctx)));
		break;

#else
	case AES:		aes_decrypt (data, data, ks); break;
#endif
	default:		TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
}

#ifndef TC_WINDOWS_BOOT

void DecipherBlocks (int cipher, void *dataPtr, void *ks, size_t blockCount)
{
	byte *data = dataPtr;
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
	KFLOATING_SAVE floatingPointState;
#endif

	if (cipher == AES
		&& (blockCount & (32 - 1)) == 0
		&& IsAesHwCpuSupported()
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		&& NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState))
#endif
		)
	{
		while (blockCount > 0)
		{
			aes_hw_cpu_decrypt_32_blocks ((byte *) ks + sizeof (aes_encrypt_ctx), data);

			data += 32 * 16;
			blockCount -= 32;
		}

#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	}
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined (_UEFI)
	else if (cipher == SERPENT
			&& (blockCount >= 4)
			&& HasSSE2()
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
			&& NT_SUCCESS (KeSaveFloatingPointState (&floatingPointState))
#endif
		)
	{
		serpent_decrypt_blocks (data, data, blockCount, ks);
#if defined (TC_WINDOWS_DRIVER) && !defined (_WIN64)
		KeRestoreFloatingPointState (&floatingPointState);
#endif
	}
#endif
#if CRYPTOPP_BOOL_X64
   else if (cipher == TWOFISH)	{
			twofish_decrypt_blocks(ks, data, data, (uint32) blockCount);
	}
	else if (cipher == CAMELLIA)	{
			camellia_decrypt_blocks(ks, data, data, (uint32) blockCount);
	}
#endif
	else if (cipher == GOST89)	{
			gost_decrypt(data, data, ks, (int)blockCount);
	}
	else
	{
		size_t blockSize = CipherGetBlockSize (cipher);
		while (blockCount-- > 0)
		{
			DecipherBlock (cipher, data, ks);
			data += blockSize;
		}
	}
}

#endif // !TC_WINDOWS_BOOT


// Ciphers support

Cipher *CipherGet (int id)
{
	int i;
	for (i = 0; Ciphers[i].Id != 0; i++)
		if (Ciphers[i].Id == id)
			return &Ciphers[i];

	return NULL;
}

#ifndef TC_WINDOWS_BOOT
const wchar_t *CipherGetName (int cipherId)
{
   Cipher* pCipher = CipherGet (cipherId);
   return  pCipher? pCipher -> Name : L"";
}

int CipherGetBlockSize (int cipherId)
{
   Cipher* pCipher = CipherGet (cipherId);
   return pCipher? pCipher -> BlockSize : 0;
}
#endif

int CipherGetKeySize (int cipherId)
{
#ifdef TC_WINDOWS_BOOT
	return CipherGet (cipherId) -> KeySize;
#else
   Cipher* pCipher = CipherGet (cipherId);
   return pCipher? pCipher -> KeySize : 0;
#endif
}

int CipherGetKeyScheduleSize (int cipherId)
{
#ifdef TC_WINDOWS_BOOT
	return CipherGet (cipherId) -> KeyScheduleSize;
#else
   Cipher* pCipher = CipherGet (cipherId);
   return pCipher? pCipher -> KeyScheduleSize : 0;
#endif
}

#ifndef TC_WINDOWS_BOOT

BOOL CipherSupportsIntraDataUnitParallelization (int cipher)
{
	return (cipher == AES && IsAesHwCpuSupported()) 
		|| (cipher == GOST89)
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined (_UEFI)
		|| (cipher == SERPENT && HasSSE2())
#endif
#if CRYPTOPP_BOOL_X64
		|| (cipher == TWOFISH)
		|| (cipher == CAMELLIA)
#endif
		;
}

#endif


// Encryption algorithms support

int EAGetFirst ()
{
	return 1;
}

#ifndef TC_WINDOWS_BOOT
// Returns number of EAs
int EAGetCount (void)
{
	int ea, count = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		count++;
	}
	return count;
}
#endif

int EAGetNext (int previousEA)
{
	int id = previousEA + 1;
	if (EncryptionAlgorithms[id].Ciphers[0] != 0) return id;
	return 0;
}


// Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal)
int EAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
	int c, retVal = ERR_SUCCESS;

	if (ea == 0)
		return ERR_CIPHER_INIT_FAILURE;

	for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
	{
		switch (CipherInit (c, key, ks))
		{
		case ERR_CIPHER_INIT_FAILURE:
			return ERR_CIPHER_INIT_FAILURE;

		case ERR_CIPHER_INIT_WEAK_KEY:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}

		key += CipherGetKeySize (c);
		ks += CipherGetKeyScheduleSize (c);
	}
	return retVal;
}


#ifndef TC_WINDOWS_BOOT

BOOL EAInitMode (PCRYPTO_INFO ci)
{
	switch (ci->mode)
	{
	case XTS:
		// Secondary key schedule
		if (EAInit (ci->ea, ci->k2, ci->ks2) != ERR_SUCCESS)
			return FALSE;

		/* Note: XTS mode could potentially be initialized with a weak key causing all blocks in one data unit
		on the volume to be tweaked with zero tweaks (i.e. 512 bytes of the volume would be encrypted in ECB
		mode). However, to create a TrueCrypt volume with such a weak key, each human being on Earth would have
		to create approximately 11,378,125,361,078,862 (about eleven quadrillion) TrueCrypt volumes (provided 
		that the size of each of the volumes is 1024 terabytes). */
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
	return TRUE;
}

static void EAGetDisplayName(wchar_t *buf, int ea, int i)
{
	wcscpy (buf, CipherGetName (i));
	if (i = EAGetPreviousCipher(ea, i))
	{
		wcscat (buf, L"(");
		EAGetDisplayName (&buf[wcslen(buf)], ea, i);
		wcscat (buf, L")");
	}
}

// Returns name of EA, cascaded cipher names are separated by hyphens
wchar_t *EAGetName (wchar_t *buf, int ea, int guiDisplay)
{
	if (guiDisplay)
	{
		EAGetDisplayName (buf, ea, EAGetLastCipher(ea));
	}
	else
	{
		int i = EAGetLastCipher(ea);
		wcscpy (buf, (i != 0) ? CipherGetName (i) : L"?");

		while (i = EAGetPreviousCipher(ea, i))
		{
			wcscat (buf, L"-");
			wcscat (buf, CipherGetName (i));
		}
	}
	return buf;
}


int EAGetByName (wchar_t *name)
{
	int ea = EAGetFirst ();
	wchar_t n[128];

	do
	{
		EAGetName(n, ea, 1);
#if defined(_UEFI)
		if (wcscmp(n, name) == 0)
#else
		if (_wcsicmp(n, name) == 0)
#endif
			return ea;
	}
	while (ea = EAGetNext (ea));

	return 0;
}

#endif // TC_WINDOWS_BOOT

// Returns sum of key sizes of all ciphers of the EA (in bytes)
int EAGetKeySize (int ea)
{
	int i = EAGetFirstCipher (ea);
	int size = CipherGetKeySize (i);

	while (i = EAGetNextCipher (ea, i))
	{
		size += CipherGetKeySize (i);
	}

	return size;
}


#ifndef TC_WINDOWS_BOOT

// Returns the first mode of operation of EA
int EAGetFirstMode (int ea)
{
	return (EncryptionAlgorithms[ea].Modes[0]);
}


int EAGetNextMode (int ea, int previousModeId)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Modes[i++])
	{
		if (c == previousModeId) 
			return EncryptionAlgorithms[ea].Modes[i];
	}

	return 0;
}

// Returns the name of the mode of operation of the whole EA
wchar_t *EAGetModeName (int ea, int mode, BOOL capitalLetters)
{
	switch (mode)
	{
	case XTS:

		return L"XTS";

	}
	return L"[unknown]";
}

#endif // TC_WINDOWS_BOOT


// Returns sum of key schedule sizes of all ciphers of the EA
int EAGetKeyScheduleSize (int ea)
{
	int i = EAGetFirstCipher(ea);
	int size = CipherGetKeyScheduleSize (i);

	while (i = EAGetNextCipher(ea, i))
	{
		size += CipherGetKeyScheduleSize (i);
	}

	return size;
}

#ifndef TC_WINDOWS_BOOT

// Returns number of ciphers in EA
int EAGetCipherCount (int ea)
{
	int i = 0;
	while (EncryptionAlgorithms[ea].Ciphers[i++]);

	return i - 1;
}

#endif

int EAGetFirstCipher (int ea)
{
	return EncryptionAlgorithms[ea].Ciphers[0];
}


int EAGetLastCipher (int ea)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++]);

	return EncryptionAlgorithms[ea].Ciphers[i - 2];
}


int EAGetNextCipher (int ea, int previousCipherId)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i];
	}

	return 0;
}


int EAGetPreviousCipher (int ea, int previousCipherId)
{
	int c, i = 0;

	if (EncryptionAlgorithms[ea].Ciphers[i++] == previousCipherId)
		return 0;

	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i - 2];
	}

	return 0;
}

#ifndef TC_WINDOWS_BOOT
int EAIsFormatEnabled (int ea)
{
	return EncryptionAlgorithms[ea].FormatEnabled;
}

int EAIsMbrSysEncEnabled (int ea)
{
	return EncryptionAlgorithms[ea].MbrSysEncEnabled;
}

// Returns TRUE if the mode of operation is supported for the encryption algorithm
BOOL EAIsModeSupported (int ea, int testedMode)
{
	int mode;

	for (mode = EAGetFirstMode (ea); mode != 0; mode = EAGetNextMode (ea, mode))
	{
		if (mode == testedMode)
			return TRUE;
	}
	return FALSE;
}

Hash *HashGet (int id)
{
	int i;
	for (i = 0; Hashes[i].Id != 0; i++)
		if (Hashes[i].Id == id)
			return &Hashes[i];

	return 0;
}

#ifdef _WIN32
int HashGetIdByName (wchar_t *name)
{
	int i;
	for (i = 0; Hashes[i].Id != 0; i++)
		if (_wcsicmp (Hashes[i].Name, name) == 0)
			return Hashes[i].Id;

	return 0;
}
#endif

const wchar_t *HashGetName (int hashId)
{
   Hash* pHash = HashGet(hashId);
   return pHash? pHash -> Name : L"";
}

void HashGetName2 (wchar_t *buf, int hashId)
{
   Hash* pHash = HashGet(hashId);
   if (pHash)
		wcscpy(buf, pHash -> Name);
	else
		buf[0] = L'\0';
}

BOOL HashIsDeprecated (int hashId)
{
   Hash* pHash = HashGet(hashId);
   return pHash? pHash -> Deprecated : FALSE;

}

BOOL HashForSystemEncryption (int hashId)
{
   Hash* pHash = HashGet(hashId);
   return pHash? pHash -> SystemEncryption : FALSE;

}

// Returns the largest key size needed by an EA for the specified mode of operation
int EAGetLargestKeyForMode (int mode)
{
	int ea, key = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		if (!EAIsModeSupported (ea, mode))
			continue;

		if (EAGetKeySize (ea) >= key)
			key = EAGetKeySize (ea);
	}
	return key;
}

// Returns the maximum number of bytes necessary to be generated by the PBKDF2 (PKCS #5)
int GetMaxPkcs5OutSize (void)
{
	int size = 32;

	size = VC_MAX (size, EAGetLargestKeyForMode (XTS) * 2);	// Sizes of primary + secondary keys

	return size;
}

#endif


#endif // TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE


#ifdef TC_WINDOWS_BOOT

static byte CryptoInfoBufferInUse = 0;
CRYPTO_INFO CryptoInfoBuffer;

#endif

PCRYPTO_INFO crypto_open ()
{
#ifndef TC_WINDOWS_BOOT

	/* Do the crt allocation */
	PCRYPTO_INFO cryptoInfo = (PCRYPTO_INFO) TCalloc (sizeof (CRYPTO_INFO));
	if (cryptoInfo == NULL)
		return NULL;

	memset (cryptoInfo, 0, sizeof (CRYPTO_INFO));

#if !defined(DEVICE_DRIVER) && !defined(_UEFI)
	VirtualLock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif

	cryptoInfo->ea = -1;
	return cryptoInfo;

#else // TC_WINDOWS_BOOT

#if 0
	if (CryptoInfoBufferInUse)
		TC_THROW_FATAL_EXCEPTION;
#endif
	CryptoInfoBufferInUse = 1;
	return &CryptoInfoBuffer;

#endif // TC_WINDOWS_BOOT
}

#ifndef TC_WINDOWS_BOOT
void crypto_loadkey (PKEY_INFO keyInfo, char *lpszUserKey, int nUserKeyLen)
{
	keyInfo->keyLength = nUserKeyLen;
	burn (keyInfo->userKey, sizeof (keyInfo->userKey));
	memcpy (keyInfo->userKey, lpszUserKey, nUserKeyLen);
}
#endif

void crypto_close (PCRYPTO_INFO cryptoInfo)
{
#ifndef TC_WINDOWS_BOOT

	if (cryptoInfo != NULL)
	{
		burn (cryptoInfo, sizeof (CRYPTO_INFO));
#if !defined(DEVICE_DRIVER) && !defined(_UEFI)
		VirtualUnlock (cryptoInfo, sizeof (CRYPTO_INFO));
#endif
		TCfree (cryptoInfo);
	}

#else // TC_WINDOWS_BOOT

	burn (&CryptoInfoBuffer, sizeof (CryptoInfoBuffer));
	CryptoInfoBufferInUse = FALSE;

#endif // TC_WINDOWS_BOOT
}


#ifndef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE



// EncryptBuffer
//
// buf:  data to be encrypted; the start of the buffer is assumed to be aligned with the start of a data unit.
// len:  number of bytes to encrypt; must be divisible by the block size (for cascaded ciphers, divisible 
//       by the largest block size used within the cascade)
void EncryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	switch (cryptoInfo->mode)
	{
	case XTS:
		{
			unsigned __int8 *ks = cryptoInfo->ks;
			unsigned __int8 *ks2 = cryptoInfo->ks2;
			UINT64_STRUCT dataUnitNo;
			int cipher;

			// When encrypting/decrypting a buffer (typically a volume header) the sequential number
			// of the first XTS data unit in the buffer is always 0 and the start of the buffer is
			// always assumed to be aligned with the start of a data unit.
			dataUnitNo.LowPart = 0;
			dataUnitNo.HighPart = 0;

			for (cipher = EAGetFirstCipher (cryptoInfo->ea);
				cipher != 0;
				cipher = EAGetNextCipher (cryptoInfo->ea, cipher))
			{
				EncryptBufferXTS (buf, len, &dataUnitNo, 0, ks, ks2, cipher);

				ks += CipherGetKeyScheduleSize (cipher);
				ks2 += CipherGetKeyScheduleSize (cipher);
			}
		}
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
}


// buf:			data to be encrypted
// unitNo:		sequential number of the data unit with which the buffer starts
// nbrUnits:	number of data units in the buffer
void EncryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, uint32 nbrUnits, PCRYPTO_INFO ci)
#if !defined(TC_WINDOWS_BOOT) && !defined(_UEFI)
{
	EncryptionThreadPoolDoWork (EncryptDataUnitsWork, buf, structUnitNo, nbrUnits, ci);
}

void EncryptDataUnitsCurrentThread (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
#endif // !TC_WINDOWS_BOOT
{
	int ea = ci->ea;
	unsigned __int8 *ks = ci->ks;
	unsigned __int8 *ks2 = ci->ks2;
	int cipher;

	switch (ci->mode)
	{
	case XTS:
		for (cipher = EAGetFirstCipher (ea); cipher != 0; cipher = EAGetNextCipher (ea, cipher))
		{
			EncryptBufferXTS (buf,
				nbrUnits * ENCRYPTION_DATA_UNIT_SIZE,
				structUnitNo,
				0,
				ks,
				ks2,
				cipher);

			ks += CipherGetKeyScheduleSize (cipher);
			ks2 += CipherGetKeyScheduleSize (cipher);
		}
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
}

// DecryptBuffer
//
// buf:  data to be decrypted; the start of the buffer is assumed to be aligned with the start of a data unit.
// len:  number of bytes to decrypt; must be divisible by the block size (for cascaded ciphers, divisible 
//       by the largest block size used within the cascade)
void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	switch (cryptoInfo->mode)
	{
	case XTS:
		{
			unsigned __int8 *ks = cryptoInfo->ks + EAGetKeyScheduleSize (cryptoInfo->ea);
			unsigned __int8 *ks2 = cryptoInfo->ks2 + EAGetKeyScheduleSize (cryptoInfo->ea);
			UINT64_STRUCT dataUnitNo;
			int cipher;

			// When encrypting/decrypting a buffer (typically a volume header) the sequential number
			// of the first XTS data unit in the buffer is always 0 and the start of the buffer is
			// always assumed to be aligned with the start of the data unit 0.
			dataUnitNo.LowPart = 0;
			dataUnitNo.HighPart = 0;

			for (cipher = EAGetLastCipher (cryptoInfo->ea);
				cipher != 0;
				cipher = EAGetPreviousCipher (cryptoInfo->ea, cipher))
			{
				ks -= CipherGetKeyScheduleSize (cipher);
				ks2 -= CipherGetKeyScheduleSize (cipher);

				DecryptBufferXTS (buf, len, &dataUnitNo, 0, ks, ks2, cipher);
			}
		}
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
}

// buf:			data to be decrypted
// unitNo:		sequential number of the data unit with which the buffer starts
// nbrUnits:	number of data units in the buffer
void DecryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, uint32 nbrUnits, PCRYPTO_INFO ci)
#if !defined(TC_WINDOWS_BOOT) && !defined(_UEFI)
{
	EncryptionThreadPoolDoWork (DecryptDataUnitsWork, buf, structUnitNo, nbrUnits, ci);
}

void DecryptDataUnitsCurrentThread (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
#endif // !TC_WINDOWS_BOOT
{
	int ea = ci->ea;
	unsigned __int8 *ks = ci->ks;
	unsigned __int8 *ks2 = ci->ks2;
	int cipher;


	switch (ci->mode)
	{
	case XTS:
		ks += EAGetKeyScheduleSize (ea);
		ks2 += EAGetKeyScheduleSize (ea);

		for (cipher = EAGetLastCipher (ea); cipher != 0; cipher = EAGetPreviousCipher (ea, cipher))
		{
			ks -= CipherGetKeyScheduleSize (cipher);
			ks2 -= CipherGetKeyScheduleSize (cipher);

			DecryptBufferXTS (buf,
				nbrUnits * ENCRYPTION_DATA_UNIT_SIZE,
				structUnitNo,
				0,
				ks,
				ks2,
				cipher);
		}
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
}


#else // TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE


#if !defined (TC_WINDOWS_BOOT_AES) && !defined (TC_WINDOWS_BOOT_SERPENT) && !defined (TC_WINDOWS_BOOT_TWOFISH) && !defined (TC_WINDOWS_BOOT_CAMELLIA)
#error No cipher defined
#endif

void EncipherBlock(int cipher, void *data, void *ks)
{
#ifdef TC_WINDOWS_BOOT_AES
	if (IsAesHwCpuSupported())
		aes_hw_cpu_encrypt ((byte *) ks, data);
	else
		aes_encrypt (data, data, ks); 
#elif defined (TC_WINDOWS_BOOT_SERPENT)
	serpent_encrypt (data, data, ks);
#elif defined (TC_WINDOWS_BOOT_TWOFISH)
	twofish_encrypt (ks, data, data);
#elif defined (TC_WINDOWS_BOOT_CAMELLIA)
	camellia_encrypt (data, data, ks);
#endif
}

void DecipherBlock(int cipher, void *data, void *ks)
{
#ifdef TC_WINDOWS_BOOT_AES
	if (IsAesHwCpuSupported())
		aes_hw_cpu_decrypt ((byte *) ks + sizeof (aes_encrypt_ctx) + 14 * 16, data);
	else
		aes_decrypt (data, data, (aes_decrypt_ctx *) ((byte *) ks + sizeof(aes_encrypt_ctx))); 
#elif defined (TC_WINDOWS_BOOT_SERPENT)
	serpent_decrypt (data, data, ks);
#elif defined (TC_WINDOWS_BOOT_TWOFISH)
	twofish_decrypt (ks, data, data);
#elif defined (TC_WINDOWS_BOOT_CAMELLIA)
	camellia_decrypt (data, data, ks);
#endif
}


#ifdef TC_WINDOWS_BOOT_AES

int EAInit (unsigned char *key, unsigned __int8 *ks)
{
	aes_init();

	if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ks) != EXIT_SUCCESS)
		return ERR_CIPHER_INIT_FAILURE;
	if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ks + sizeof (aes_encrypt_ctx))) != EXIT_SUCCESS)
		return ERR_CIPHER_INIT_FAILURE;

	return ERR_SUCCESS;
}

#endif


void EncryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT dataUnitNo;
	dataUnitNo.LowPart = 0; dataUnitNo.HighPart = 0;
	EncryptBufferXTS (buf, len, &dataUnitNo, 0, cryptoInfo->ks, cryptoInfo->ks2, 1);
}

void EncryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
{
	EncryptBufferXTS (buf, nbrUnits * ENCRYPTION_DATA_UNIT_SIZE, structUnitNo, 0, ci->ks, ci->ks2, 1);
}

void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT dataUnitNo;
	dataUnitNo.LowPart = 0; dataUnitNo.HighPart = 0;
	DecryptBufferXTS (buf, len, &dataUnitNo, 0, cryptoInfo->ks, cryptoInfo->ks2, 1);
}

void DecryptDataUnits (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
{
	DecryptBufferXTS (buf, nbrUnits * ENCRYPTION_DATA_UNIT_SIZE, structUnitNo, 0, ci->ks, ci->ks2, 1);
}

#endif // TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE


#if !defined (TC_WINDOWS_BOOT) || defined (TC_WINDOWS_BOOT_AES)

static BOOL HwEncryptionDisabled = FALSE;

BOOL IsAesHwCpuSupported ()
{
#ifdef TC_WINDOWS_BOOT_AES
	static BOOL state = FALSE;
	static BOOL stateValid = FALSE;

	if (!stateValid)
	{
		state = is_aes_hw_cpu_supported() ? TRUE : FALSE;
		stateValid = TRUE;
	}

	return state && !HwEncryptionDisabled;
#else
	return (HasAESNI() && !HwEncryptionDisabled)? TRUE : FALSE;
#endif
}

void EnableHwEncryption (BOOL enable)
{
#if defined (TC_WINDOWS_BOOT)
	if (enable)
		aes_hw_cpu_enable_sse();
#endif

	HwEncryptionDisabled = !enable;
}

BOOL IsHwEncryptionEnabled ()
{
	return !HwEncryptionDisabled;
}

#endif // !TC_WINDOWS_BOOT
