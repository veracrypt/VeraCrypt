/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#ifndef TC_WINDOWS_BOOT
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "EncryptionThreadPool.h"
#endif

#include <stddef.h>
#include <string.h>
#include <io.h>

#ifndef DEVICE_DRIVER
#include "Random.h"
#endif

#include "Crc.h"
#include "Crypto.h"
#include "Endian.h"
#include "Volumes.h"
#include "Pkcs5.h"


/* Volume header v5 structure (used since TrueCrypt 7.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'VERA'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		16		Reserved (must contain zeroes)
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes, valid if field 70 >= 0x600 or flag bit 0 == 1)
// 108		8		Byte offset of the start of the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 116		8		Size of the encrypted area within the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 124		4		Flags: bit 0 set = system encryption; bit 1 set = non-system in-place encryption, bits 2-31 are reserved (set to zero)
// 128		4		Sector size in bytes
// 132		120		Reserved (must contain zeroes)
// 252		4		CRC-32 checksum of the (decrypted) bytes 64-251
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v4 structure (used by TrueCrypt 6.x): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		16		Reserved (must contain zeroes)
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes, valid if field 70 >= 0x600 or flag bit 0 == 1)
// 108		8		Byte offset of the start of the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 116		8		Size of the encrypted area within the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 124		4		Flags: bit 0 set = system encryption; bit 1 set = non-system in-place encryption, bits 2-31 are reserved
// 128		124		Reserved (must contain zeroes)
// 252		4		CRC-32 checksum of the (decrypted) bytes 64-251
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v3 structure (used by TrueCrypt 5.x): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes)
// 108		8		Start byte offset of the encrypted area of the volume
// 116		8		Size of the encrypted area of the volume in bytes
// 124		132		Reserved (must contain zeroes)
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v2 structure (used before TrueCrypt 5.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		156		Reserved (must contain zeroes)
// 256		32		For LRW (deprecated/legacy), secondary key
//					For CBC (deprecated/legacy), data used to generate IV and whitening values
// 288		224		Master key(s)



uint16 GetHeaderField16 (byte *header, int offset)
{
	return BE16 (*(uint16 *) (header + offset));
}


uint32 GetHeaderField32 (byte *header, int offset)
{
	return BE32 (*(uint32 *) (header + offset));
}


UINT64_STRUCT GetHeaderField64 (byte *header, int offset)
{
	UINT64_STRUCT uint64Struct;

#ifndef TC_NO_COMPILER_INT64
	uint64Struct.Value = BE64 (*(uint64 *) (header + offset));
#else
	uint64Struct.HighPart = BE32 (*(uint32 *) (header + offset));
	uint64Struct.LowPart = BE32 (*(uint32 *) (header + offset + 4));
#endif
	return uint64Struct;
}


#ifndef TC_WINDOWS_BOOT

typedef struct
{
	char DerivedKey[MASTER_KEYDATA_SIZE];
	BOOL Free;
	LONG KeyReady;
	int Pkcs5Prf;
} KeyDerivationWorkItem;


BOOL ReadVolumeHeaderRecoveryMode = FALSE;

int ReadVolumeHeader (BOOL bBoot, char *encryptedHeader, Password *password, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo)
{
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	KEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	char dk[MASTER_KEYDATA_SIZE];
	int enqPkcs5Prf, pkcs5_prf;
	uint16 headerVersion;
	int status = ERR_PARAMETER_INCORRECT;
	int primaryKeyOffset;

	TC_EVENT keyDerivationCompletedEvent;
	TC_EVENT noOutstandingWorkItemEvent;
	KeyDerivationWorkItem *keyDerivationWorkItems;
	KeyDerivationWorkItem *item;
	int pkcs5PrfCount = LAST_PRF_ID - FIRST_PRF_ID + 1;
	size_t encryptionThreadCount = GetEncryptionThreadCount();
	size_t queuedWorkItems = 0;
	LONG outstandingWorkItemCount = 0;
	int i;

	if (retHeaderCryptoInfo != NULL)
	{
		cryptoInfo = retHeaderCryptoInfo;
	}
	else
	{
		cryptoInfo = *retInfo = crypto_open ();
		if (cryptoInfo == NULL)
			return ERR_OUTOFMEMORY;
	}

	if (encryptionThreadCount > 1)
	{
		keyDerivationWorkItems = TCalloc (sizeof (KeyDerivationWorkItem) * pkcs5PrfCount);
		if (!keyDerivationWorkItems)
			return ERR_OUTOFMEMORY;

		for (i = 0; i < pkcs5PrfCount; ++i)
			keyDerivationWorkItems[i].Free = TRUE;

#ifdef DEVICE_DRIVER
		KeInitializeEvent (&keyDerivationCompletedEvent, SynchronizationEvent, FALSE);
		KeInitializeEvent (&noOutstandingWorkItemEvent, SynchronizationEvent, TRUE);
#else
		keyDerivationCompletedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
		if (!keyDerivationCompletedEvent)
		{
			TCfree (keyDerivationWorkItems);
			return ERR_OUTOFMEMORY;
		}

		noOutstandingWorkItemEvent = CreateEvent (NULL, FALSE, TRUE, NULL);
		if (!noOutstandingWorkItemEvent)
		{
			CloseHandle (keyDerivationCompletedEvent);
			TCfree (keyDerivationWorkItems);
			return ERR_OUTOFMEMORY;
		}
#endif
	}
		
#ifndef DEVICE_DRIVER
	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));
#endif

	crypto_loadkey (&keyInfo, password->Text, (int) password->Length);

	// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
	memcpy (keyInfo.salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);

	// Test all available PKCS5 PRFs
	for (enqPkcs5Prf = FIRST_PRF_ID; enqPkcs5Prf <= LAST_PRF_ID || queuedWorkItems > 0; ++enqPkcs5Prf)
	{
		BOOL lrw64InitDone = FALSE;		// Deprecated/legacy
		BOOL lrw128InitDone = FALSE;	// Deprecated/legacy

		if (encryptionThreadCount > 1)
		{
			// Enqueue key derivation on thread pool
			if (queuedWorkItems < encryptionThreadCount && enqPkcs5Prf <= LAST_PRF_ID)
			{
				for (i = 0; i < pkcs5PrfCount; ++i)
				{
					item = &keyDerivationWorkItems[i];
					if (item->Free)
					{
						item->Free = FALSE;
						item->KeyReady = FALSE;
						item->Pkcs5Prf = enqPkcs5Prf;

						EncryptionThreadPoolBeginKeyDerivation (&keyDerivationCompletedEvent, &noOutstandingWorkItemEvent,
							&item->KeyReady, &outstandingWorkItemCount, enqPkcs5Prf, keyInfo.userKey,
							keyInfo.keyLength, keyInfo.salt, get_pkcs5_iteration_count (enqPkcs5Prf, bBoot), item->DerivedKey);
						
						++queuedWorkItems;
						break;
					}
				}

				if (enqPkcs5Prf < LAST_PRF_ID)
					continue;
			}
			else
				--enqPkcs5Prf;

			// Wait for completion of a key derivation
			while (queuedWorkItems > 0)
			{
				for (i = 0; i < pkcs5PrfCount; ++i)
				{
					item = &keyDerivationWorkItems[i];
					if (!item->Free && InterlockedExchangeAdd (&item->KeyReady, 0) == TRUE)
					{
						pkcs5_prf = item->Pkcs5Prf;
						keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, bBoot);
						memcpy (dk, item->DerivedKey, sizeof (dk));

						item->Free = TRUE;
						--queuedWorkItems;
						goto KeyReady;
					}
				}

				if (queuedWorkItems > 0)
					TC_WAIT_EVENT (keyDerivationCompletedEvent);
			}
			continue;
KeyReady:	;
		}
		else
		{
			pkcs5_prf = enqPkcs5Prf;
			keyInfo.noIterations = get_pkcs5_iteration_count (enqPkcs5Prf, bBoot);

			switch (pkcs5_prf)
			{
			case RIPEMD160:
				derive_key_ripemd160 (TRUE, keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
					PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
				break;

			case SHA512:
				derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
					PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
				break;

			case SHA1:
				// Deprecated/legacy
				derive_key_sha1 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
					PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
				break;

			case WHIRLPOOL:
				derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
					PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
				break;

			default:		
				// Unknown/wrong ID
				TC_THROW_FATAL_EXCEPTION;
			} 
		}

		// Test all available modes of operation
		for (cryptoInfo->mode = FIRST_MODE_OF_OPERATION_ID;
			cryptoInfo->mode <= LAST_MODE_OF_OPERATION;
			cryptoInfo->mode++)
		{
			switch (cryptoInfo->mode)
			{
			case LRW:
			case CBC:
			case INNER_CBC:
			case OUTER_CBC:

				// For LRW (deprecated/legacy), copy the tweak key 
				// For CBC (deprecated/legacy), copy the IV/whitening seed 
				memcpy (cryptoInfo->k2, dk, LEGACY_VOL_IV_SIZE);
				primaryKeyOffset = LEGACY_VOL_IV_SIZE;
				break;

			default:
				primaryKeyOffset = 0;
			}

			// Test all available encryption algorithms
			for (cryptoInfo->ea = EAGetFirst ();
				cryptoInfo->ea != 0;
				cryptoInfo->ea = EAGetNext (cryptoInfo->ea))
			{
				int blockSize;

				if (!EAIsModeSupported (cryptoInfo->ea, cryptoInfo->mode))
					continue;	// This encryption algorithm has never been available with this mode of operation

				blockSize = CipherGetBlockSize (EAGetFirstCipher (cryptoInfo->ea));

				status = EAInit (cryptoInfo->ea, dk + primaryKeyOffset, cryptoInfo->ks);
				if (status == ERR_CIPHER_INIT_FAILURE)
					goto err;

				// Init objects related to the mode of operation

				if (cryptoInfo->mode == XTS)
				{
					// Copy the secondary key (if cascade, multiple concatenated)
					memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));

					// Secondary key schedule
					if (!EAInitMode (cryptoInfo))
					{
						status = ERR_MODE_INIT_FAILED;
						goto err;
					}
				}
				else if (cryptoInfo->mode == LRW
					&& (blockSize == 8 && !lrw64InitDone || blockSize == 16 && !lrw128InitDone))
				{
					// Deprecated/legacy

					if (!EAInitMode (cryptoInfo))
					{
						status = ERR_MODE_INIT_FAILED;
						goto err;
					}

					if (blockSize == 8)
						lrw64InitDone = TRUE;
					else if (blockSize == 16)
						lrw128InitDone = TRUE;
				}

				// Copy the header for decryption
				memcpy (header, encryptedHeader, sizeof (header));

				// Try to decrypt header 

				DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

				// Magic 'TRUE'
				if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x56455241)
					continue;

				// Header version
				headerVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION);
				
				if (headerVersion > VOLUME_HEADER_VERSION)
				{
					status = ERR_NEW_VERSION_REQUIRED;
					goto err;
				}

				// Check CRC of the header fields
				if (!ReadVolumeHeaderRecoveryMode
					&& headerVersion >= 4
					&& GetHeaderField32 (header, TC_HEADER_OFFSET_HEADER_CRC) != GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
					continue;

				// Required program version
				cryptoInfo->RequiredProgramVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_REQUIRED_VERSION);
				cryptoInfo->LegacyVolume = cryptoInfo->RequiredProgramVersion < 0x10b;

				// Check CRC of the key set
				if (!ReadVolumeHeaderRecoveryMode
					&& GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != GetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
					continue;

				// Now we have the correct password, cipher, hash algorithm, and volume type

				// Check the version required to handle this volume
				if (cryptoInfo->RequiredProgramVersion > VERSION_NUM)
				{
					status = ERR_NEW_VERSION_REQUIRED;
					goto err;
				}

				// Header version
				cryptoInfo->HeaderVersion = headerVersion;

				// Volume creation time (legacy)
				cryptoInfo->volume_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_CREATION_TIME).Value;

				// Header creation time (legacy)
				cryptoInfo->header_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_MODIFICATION_TIME).Value;

				// Hidden volume size (if any)
				cryptoInfo->hiddenVolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE).Value;

				// Hidden volume status
				cryptoInfo->hiddenVolume = (cryptoInfo->hiddenVolumeSize != 0);

				// Volume size
				cryptoInfo->VolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_SIZE);
				
				// Encrypted area size and length
				cryptoInfo->EncryptedAreaStart = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_START);
				cryptoInfo->EncryptedAreaLength = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH);

				// Flags
				cryptoInfo->HeaderFlags = GetHeaderField32 (header, TC_HEADER_OFFSET_FLAGS);

				// Sector size
				if (headerVersion >= 5)
					cryptoInfo->SectorSize = GetHeaderField32 (header, TC_HEADER_OFFSET_SECTOR_SIZE);
				else
					cryptoInfo->SectorSize = TC_SECTOR_SIZE_LEGACY;

				if (cryptoInfo->SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
					|| cryptoInfo->SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
					|| cryptoInfo->SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
				{
					status = ERR_PARAMETER_INCORRECT;
					goto err;
				}

				// Preserve scheduled header keys if requested			
				if (retHeaderCryptoInfo)
				{
					if (retInfo == NULL)
					{
						cryptoInfo->pkcs5 = pkcs5_prf;
						cryptoInfo->noIterations = keyInfo.noIterations;
						goto ret;
					}

					cryptoInfo = *retInfo = crypto_open ();
					if (cryptoInfo == NULL)
					{
						status = ERR_OUTOFMEMORY;
						goto err;
					}

					memcpy (cryptoInfo, retHeaderCryptoInfo, sizeof (*cryptoInfo));
				}

				// Master key data
				memcpy (keyInfo.master_keydata, header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE);
				memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

				// PKCS #5
				memcpy (cryptoInfo->salt, keyInfo.salt, PKCS5_SALT_SIZE);
				cryptoInfo->pkcs5 = pkcs5_prf;
				cryptoInfo->noIterations = keyInfo.noIterations;

				// Init the cipher with the decrypted master key
				status = EAInit (cryptoInfo->ea, keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
				if (status == ERR_CIPHER_INIT_FAILURE)
					goto err;

				switch (cryptoInfo->mode)
				{
				case LRW:
				case CBC:
				case INNER_CBC:
				case OUTER_CBC:

					// For LRW (deprecated/legacy), the tweak key
					// For CBC (deprecated/legacy), the IV/whitening seed
					memcpy (cryptoInfo->k2, keyInfo.master_keydata, LEGACY_VOL_IV_SIZE);
					break;

				default:
					// The secondary master key (if cascade, multiple concatenated)
					memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));

				}

				if (!EAInitMode (cryptoInfo))
				{
					status = ERR_MODE_INIT_FAILED;
					goto err;
				}

				status = ERR_SUCCESS;
				goto ret;
			}
		}
	}
	status = ERR_PASSWORD_WRONG;

err:
	if (cryptoInfo != retHeaderCryptoInfo)
	{
		crypto_close(cryptoInfo);
		*retInfo = NULL; 
	}

ret:
	burn (&keyInfo, sizeof (keyInfo));
	burn (dk, sizeof(dk));

#ifndef DEVICE_DRIVER
	VirtualUnlock (&keyInfo, sizeof (keyInfo));
	VirtualUnlock (&dk, sizeof (dk));
#endif

	if (encryptionThreadCount > 1)
	{
		TC_WAIT_EVENT (noOutstandingWorkItemEvent);

		burn (keyDerivationWorkItems, sizeof (KeyDerivationWorkItem) * pkcs5PrfCount);
		TCfree (keyDerivationWorkItems);

#ifndef DEVICE_DRIVER
		CloseHandle (keyDerivationCompletedEvent);
		CloseHandle (noOutstandingWorkItemEvent);
#endif
	}

	return status;
}

#else // TC_WINDOWS_BOOT

int ReadVolumeHeader (BOOL bBoot, char *header, Password *password, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo)
{
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	char dk[32 * 2];			// 2 * 256-bit key
	char masterKey[32 * 2];
#else
	char dk[32 * 2 * 3];		// 6 * 256-bit key
	char masterKey[32 * 2 * 3];
#endif

	PCRYPTO_INFO cryptoInfo;
	int status;

	if (retHeaderCryptoInfo != NULL)
		cryptoInfo = retHeaderCryptoInfo;
	else
		cryptoInfo = *retInfo = crypto_open ();

	// PKCS5 PRF
	derive_key_ripemd160 (TRUE, password->Text, (int) password->Length, header + HEADER_SALT_OFFSET,
		PKCS5_SALT_SIZE, bBoot ? 16384 : 32767, dk, sizeof (dk));

	// Mode of operation
	cryptoInfo->mode = FIRST_MODE_OF_OPERATION_ID;

	// Test all available encryption algorithms
	for (cryptoInfo->ea = EAGetFirst (); cryptoInfo->ea != 0; cryptoInfo->ea = EAGetNext (cryptoInfo->ea))
	{
		status = EAInit (cryptoInfo->ea, dk, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;

		// Secondary key schedule
		EAInit (cryptoInfo->ea, dk + EAGetKeySize (cryptoInfo->ea), cryptoInfo->ks2);

		// Try to decrypt header 
		DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);
		
		// Check magic 'TRUE' and CRC-32 of header fields and master keydata
		if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x56455241
			|| (GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION) >= 4 && GetHeaderField32 (header, TC_HEADER_OFFSET_HEADER_CRC) != GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
			|| GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != GetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
		{
			EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);
			continue;
		}

		// Header decrypted
		status = 0;

		// Hidden volume status
		cryptoInfo->VolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE);
		cryptoInfo->hiddenVolume = (cryptoInfo->VolumeSize.LowPart != 0 || cryptoInfo->VolumeSize.HighPart != 0);

		// Volume size
		cryptoInfo->VolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_SIZE);

		// Encrypted area size and length
		cryptoInfo->EncryptedAreaStart = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_START);
		cryptoInfo->EncryptedAreaLength = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH);

		// Flags
		cryptoInfo->HeaderFlags = GetHeaderField32 (header, TC_HEADER_OFFSET_FLAGS);

		memcpy (masterKey, header + HEADER_MASTER_KEYDATA_OFFSET, sizeof (masterKey));
		EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		if (retHeaderCryptoInfo)
			goto ret;

		// Init the encryption algorithm with the decrypted master key
		status = EAInit (cryptoInfo->ea, masterKey, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;

		// The secondary master key (if cascade, multiple concatenated)
		EAInit (cryptoInfo->ea, masterKey + EAGetKeySize (cryptoInfo->ea), cryptoInfo->ks2);
		goto ret;
	}

	status = ERR_PASSWORD_WRONG;

err:
	if (cryptoInfo != retHeaderCryptoInfo)
	{
		crypto_close(cryptoInfo);
		*retInfo = NULL; 
	}

ret:
	burn (dk, sizeof(dk));
	burn (masterKey, sizeof(masterKey));
	return status;
}

#endif // TC_WINDOWS_BOOT


#if !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)

#ifdef VOLFORMAT
#	include "../Format/TcFormat.h"
#	include "Dlgcode.h"
#endif

// Creates a volume header in memory
int CreateVolumeHeaderInMemory (BOOL bBoot, char *header, int ea, int mode, Password *password,
		   int pkcs5_prf, char *masterKeydata, PCRYPTO_INFO *retInfo,
		   unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
		   unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode)
{
	unsigned char *p = (unsigned char *) header;
	static KEY_INFO keyInfo;

	int nUserKeyLen = password->Length;
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	static char dk[MASTER_KEYDATA_SIZE];
	int x;
	int retVal = 0;
	int primaryKeyOffset;

	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	memset (header, 0, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));

	/* Encryption setup */

	if (masterKeydata == NULL)
	{
		// We have no master key data (creating a new volume) so we'll use the TrueCrypt RNG to generate them

		int bytesNeeded;

		switch (mode)
		{
		case LRW:
		case CBC:
		case INNER_CBC:
		case OUTER_CBC:

			// Deprecated/legacy modes of operation
			bytesNeeded = LEGACY_VOL_IV_SIZE + EAGetKeySize (ea);

			// In fact, this should never be the case since volumes being newly created are not
			// supposed to use any deprecated mode of operation.
			TC_THROW_FATAL_EXCEPTION;
			break;

		default:
			bytesNeeded = EAGetKeySize (ea) * 2;	// Size of primary + secondary key(s)
		}

		if (!RandgetBytes (keyInfo.master_keydata, bytesNeeded, TRUE))
			return ERR_CIPHER_INIT_WEAK_KEY;
	}
	else
	{
		// We already have existing master key data (the header is being re-encrypted)
		memcpy (keyInfo.master_keydata, masterKeydata, MASTER_KEYDATA_SIZE);
	}

	// User key 
	memcpy (keyInfo.userKey, password->Text, nUserKeyLen);
	keyInfo.keyLength = nUserKeyLen;
	keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, bBoot);

	// User selected encryption algorithm
	cryptoInfo->ea = ea;

	// Mode of operation
	cryptoInfo->mode = mode;

	// Salt for header key derivation
	if (!RandgetBytes (keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
		return ERR_CIPHER_INIT_WEAK_KEY; 

	// PBKDF2 (PKCS5) is used to derive primary header key(s) and secondary header key(s) (XTS) from the password/keyfiles
	switch (pkcs5_prf)
	{
	case SHA512:
		derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case SHA1:
		// Deprecated/legacy
		derive_key_sha1 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case RIPEMD160:
		derive_key_ripemd160 (TRUE, keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	case WHIRLPOOL:
		derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
			PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
		break;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	} 

	/* Header setup */

	// Salt
	mputBytes (p, keyInfo.salt, PKCS5_SALT_SIZE);	

	// Magic
	mputLong (p, 0x56455241);

	// Header version
	mputWord (p, VOLUME_HEADER_VERSION);
	cryptoInfo->HeaderVersion = VOLUME_HEADER_VERSION;

	// Required program version to handle this volume
	mputWord (p, requiredProgramVersion != 0 ? requiredProgramVersion : TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION);

	// CRC of the master key data
	x = GetCrc32(keyInfo.master_keydata, MASTER_KEYDATA_SIZE);
	mputLong (p, x);

	// Reserved fields
	p += 2 * 8;

	// Size of hidden volume (if any)
	cryptoInfo->hiddenVolumeSize = hiddenVolumeSize;
	mputInt64 (p, cryptoInfo->hiddenVolumeSize);

	cryptoInfo->hiddenVolume = cryptoInfo->hiddenVolumeSize != 0;

	// Volume size
	cryptoInfo->VolumeSize.Value = volumeSize;
	mputInt64 (p, volumeSize);

	// Encrypted area start
	cryptoInfo->EncryptedAreaStart.Value = encryptedAreaStart;
	mputInt64 (p, encryptedAreaStart);

	// Encrypted area size
	cryptoInfo->EncryptedAreaLength.Value = encryptedAreaLength;
	mputInt64 (p, encryptedAreaLength);

	// Flags
	cryptoInfo->HeaderFlags = headerFlags;
	mputLong (p, headerFlags);

	// Sector size
	if (sectorSize < TC_MIN_VOLUME_SECTOR_SIZE
		|| sectorSize > TC_MAX_VOLUME_SECTOR_SIZE
		|| sectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		TC_THROW_FATAL_EXCEPTION;
	}

	cryptoInfo->SectorSize = sectorSize;
	mputLong (p, sectorSize);

	// CRC of the header fields
	x = GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
	p = header + TC_HEADER_OFFSET_HEADER_CRC;
	mputLong (p, x);

	// The master key data
	memcpy (header + HEADER_MASTER_KEYDATA_OFFSET, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);


	/* Header encryption */

	switch (mode)
	{
	case LRW:
	case CBC:
	case INNER_CBC:
	case OUTER_CBC:

		// For LRW (deprecated/legacy), the tweak key
		// For CBC (deprecated/legacy), the IV/whitening seed
		memcpy (cryptoInfo->k2, dk, LEGACY_VOL_IV_SIZE);
		primaryKeyOffset = LEGACY_VOL_IV_SIZE;
		break;

	default:
		// The secondary key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
		primaryKeyOffset = 0;
	}

	retVal = EAInit (cryptoInfo->ea, dk + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		return retVal;

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
		return ERR_OUTOFMEMORY;


	// Encrypt the entire header (except the salt)
	EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET,
		HEADER_ENCRYPTED_DATA_SIZE,
		cryptoInfo);


	/* cryptoInfo setup for further use (disk format) */

	// Init with the master key(s) 
	retVal = EAInit (cryptoInfo->ea, keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		return retVal;

	memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

	switch (cryptoInfo->mode)
	{
	case LRW:
	case CBC:
	case INNER_CBC:
	case OUTER_CBC:

		// For LRW (deprecated/legacy), the tweak key
		// For CBC (deprecated/legacy), the IV/whitening seed
		memcpy (cryptoInfo->k2, keyInfo.master_keydata, LEGACY_VOL_IV_SIZE);
		break;

	default:
		// The secondary master key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
	}

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
		return ERR_OUTOFMEMORY;


#ifdef VOLFORMAT
	if (showKeys && !bInPlaceEncNonSys)
	{
		BOOL dots3 = FALSE;
		int i, j;

		j = EAGetKeySize (ea);

		if (j > NBR_KEY_BYTES_TO_DISPLAY)
		{
			dots3 = TRUE;
			j = NBR_KEY_BYTES_TO_DISPLAY;
		}

		MasterKeyGUIView[0] = 0;
		for (i = 0; i < j; i++)
		{
			char tmp2[8] = {0};
			sprintf (tmp2, "%02X", (int) (unsigned char) keyInfo.master_keydata[i + primaryKeyOffset]);
			strcat (MasterKeyGUIView, tmp2);
		}

		HeaderKeyGUIView[0] = 0;
		for (i = 0; i < NBR_KEY_BYTES_TO_DISPLAY; i++)
		{
			char tmp2[8];
			sprintf (tmp2, "%02X", (int) (unsigned char) dk[primaryKeyOffset + i]);
			strcat (HeaderKeyGUIView, tmp2);
		}

		if (dots3)
		{
			DisplayPortionsOfKeys (hHeaderKey, hMasterKey, HeaderKeyGUIView, MasterKeyGUIView, !showKeys);
		}
		else
		{
			SendMessage (hMasterKey, WM_SETTEXT, 0, (LPARAM) MasterKeyGUIView);
			SendMessage (hHeaderKey, WM_SETTEXT, 0, (LPARAM) HeaderKeyGUIView);
		}
	}
#endif	// #ifdef VOLFORMAT

	burn (dk, sizeof(dk));
	burn (&keyInfo, sizeof (keyInfo));

	*retInfo = cryptoInfo;
	return 0;
}


BOOL ReadEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, byte *header, DWORD *bytesRead)
{
#if TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#error TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#endif

	byte sectorBuffer[TC_MAX_VOLUME_SECTOR_SIZE];
	DISK_GEOMETRY geometry;

	if (!device)
		return ReadFile (fileHandle, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE, bytesRead, NULL);

	if (!DeviceIoControl (fileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof (geometry), bytesRead, NULL))
		return FALSE;

	if (geometry.BytesPerSector > sizeof (sectorBuffer) || geometry.BytesPerSector < TC_MIN_VOLUME_SECTOR_SIZE)
	{
		SetLastError (ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (!ReadFile (fileHandle, sectorBuffer, max (TC_VOLUME_HEADER_EFFECTIVE_SIZE, geometry.BytesPerSector), bytesRead, NULL))
		return FALSE;

	memcpy (header, sectorBuffer, min (*bytesRead, TC_VOLUME_HEADER_EFFECTIVE_SIZE));
	
	if (*bytesRead > TC_VOLUME_HEADER_EFFECTIVE_SIZE)
		*bytesRead = TC_VOLUME_HEADER_EFFECTIVE_SIZE;

	return TRUE;
}


BOOL WriteEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, byte *header)
{
#if TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#error TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#endif

	byte sectorBuffer[TC_MAX_VOLUME_SECTOR_SIZE];
	DWORD bytesDone;
	DISK_GEOMETRY geometry;

	if (!device)
	{
		if (!WriteFile (fileHandle, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE, &bytesDone, NULL))
			return FALSE;

		if (bytesDone != TC_VOLUME_HEADER_EFFECTIVE_SIZE)
		{
			SetLastError (ERROR_INVALID_PARAMETER);
			return FALSE;
		}

		return TRUE;
	}

	if (!DeviceIoControl (fileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof (geometry), &bytesDone, NULL))
		return FALSE;

	if (geometry.BytesPerSector > sizeof (sectorBuffer) || geometry.BytesPerSector < TC_MIN_VOLUME_SECTOR_SIZE)
	{
		SetLastError (ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (geometry.BytesPerSector != TC_VOLUME_HEADER_EFFECTIVE_SIZE)
	{
		LARGE_INTEGER seekOffset;

		if (!ReadFile (fileHandle, sectorBuffer, geometry.BytesPerSector, &bytesDone, NULL))
			return FALSE;

		if (bytesDone != geometry.BytesPerSector)
		{
			SetLastError (ERROR_INVALID_PARAMETER);
			return FALSE;
		}

		seekOffset.QuadPart = -(int) bytesDone;
		if (!SetFilePointerEx (fileHandle, seekOffset, NULL, FILE_CURRENT))
			return FALSE;
	}

	memcpy (sectorBuffer, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

	if (!WriteFile (fileHandle, sectorBuffer, geometry.BytesPerSector, &bytesDone, NULL))
		return FALSE;

	if (bytesDone != geometry.BytesPerSector)
	{
		SetLastError (ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	return TRUE;
}


// Writes randomly generated data to unused/reserved header areas.
// When bPrimaryOnly is TRUE, then only the primary header area (not the backup header area) is filled with random data.
// When bBackupOnly is TRUE, only the backup header area (not the primary header area) is filled with random data.
int WriteRandomDataToReservedHeaderAreas (HANDLE dev, CRYPTO_INFO *cryptoInfo, uint64 dataAreaSize, BOOL bPrimaryOnly, BOOL bBackupOnly)
{
	char temporaryKey[MASTER_KEYDATA_SIZE];
	char originalK2[MASTER_KEYDATA_SIZE];

	byte buf[TC_VOLUME_HEADER_GROUP_SIZE];

	LARGE_INTEGER offset;
	int nStatus = ERR_SUCCESS;
	DWORD dwError;
	DWORD bytesDone;
	BOOL backupHeaders = bBackupOnly;

	if (bPrimaryOnly && bBackupOnly)
		TC_THROW_FATAL_EXCEPTION;

	memcpy (originalK2, cryptoInfo->k2, sizeof (cryptoInfo->k2));

	while (TRUE)
	{
		// Temporary keys
		if (!RandgetBytes (temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE)
			|| !RandgetBytes (cryptoInfo->k2, sizeof (cryptoInfo->k2), FALSE))
		{
			nStatus = ERR_PARAMETER_INCORRECT; 
			goto final_seq;
		}

		nStatus = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (nStatus != ERR_SUCCESS)
			goto final_seq;

		if (!EAInitMode (cryptoInfo))
		{
			nStatus = ERR_MODE_INIT_FAILED;
			goto final_seq;
		}

		offset.QuadPart = backupHeaders ? dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE : TC_VOLUME_HEADER_OFFSET;

		if (!SetFilePointerEx (dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto final_seq;
		}

		if (!ReadFile (dev, buf, sizeof (buf), &bytesDone, NULL))
		{
			nStatus = ERR_OS_ERROR;
			goto final_seq;
		}

		if (bytesDone < TC_VOLUME_HEADER_EFFECTIVE_SIZE)
		{
			SetLastError (ERROR_INVALID_PARAMETER);
			nStatus = ERR_OS_ERROR;
			goto final_seq;
		}

		EncryptBuffer (buf + TC_VOLUME_HEADER_EFFECTIVE_SIZE, sizeof (buf) - TC_VOLUME_HEADER_EFFECTIVE_SIZE, cryptoInfo);

		if (!SetFilePointerEx (dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto final_seq;
		}

		if (!WriteFile (dev, buf, sizeof (buf), &bytesDone, NULL))
		{
			nStatus = ERR_OS_ERROR;
			goto final_seq;
		}

		if (bytesDone != sizeof (buf))
		{
			nStatus = ERR_PARAMETER_INCORRECT;
			goto final_seq;
		}

		if (backupHeaders || bPrimaryOnly)
			break;

		backupHeaders = TRUE;
	}

	memcpy (cryptoInfo->k2, originalK2, sizeof (cryptoInfo->k2));

	nStatus = EAInit (cryptoInfo->ea, cryptoInfo->master_keydata, cryptoInfo->ks);
	if (nStatus != ERR_SUCCESS)
		goto final_seq;

	if (!EAInitMode (cryptoInfo))
	{
		nStatus = ERR_MODE_INIT_FAILED;
		goto final_seq;
	}

final_seq:

	dwError = GetLastError();

	burn (temporaryKey, sizeof (temporaryKey));
	burn (originalK2, sizeof (originalK2));

	if (nStatus != ERR_SUCCESS)
		SetLastError (dwError);

	return nStatus;
}

#endif // !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)
