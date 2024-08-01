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
#if !defined(_UEFI)
#if !defined(TC_WINDOWS_BOOT) 
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
#else
#include "cpu.h"
#endif
#endif // !defined(_UEFI)

#include "Crc.h"
#include "Crypto.h"
#include "Endian.h"
#include "Volumes.h"
#include "Pkcs5.h"

#if defined(_WIN32) && !defined(_UEFI)
#include <Strsafe.h>
#include "../Boot/Windows/BootCommon.h"
#endif

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
// 64		4		ASCII string 'VERA'
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
// 64		4		ASCII string 'VERA'
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
// 64		4		ASCII string 'VERA'
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



uint16 GetHeaderField16 (uint8 *header, int offset)
{
	return BE16 (*(uint16 *) (header + offset));
}


uint32 GetHeaderField32 (uint8 *header, int offset)
{
	return BE32 (*(uint32 *) (header + offset));
}


UINT64_STRUCT GetHeaderField64 (uint8 *header, int offset)
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

int ReadVolumeHeader (BOOL bBoot, char *encryptedHeader, Password *password, int selected_pkcs5_prf, int pim, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo)
{
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	unsigned char* keyInfoBuffer = NULL;
	int keyInfoBufferSize = sizeof (KEY_INFO) + 16;
	size_t keyInfoBufferOffset;
	PKEY_INFO keyInfo;
	PCRYPTO_INFO cryptoInfo;
	CRYPTOPP_ALIGN_DATA(16) char dk[MASTER_KEYDATA_SIZE];
	int enqPkcs5Prf, pkcs5_prf;
	uint16 headerVersion;
	int status = ERR_PARAMETER_INCORRECT;
	int primaryKeyOffset;
	int pkcs5PrfCount = LAST_PRF_ID - FIRST_PRF_ID + 1;
#if !defined(_UEFI)
	TC_EVENT *keyDerivationCompletedEvent = NULL;
	TC_EVENT *noOutstandingWorkItemEvent = NULL;
	KeyDerivationWorkItem *keyDerivationWorkItems = NULL;
	int keyDerivationWorkItemsSize = 0;
	KeyDerivationWorkItem *item;
	size_t encryptionThreadCount = GetEncryptionThreadCount();
	LONG *outstandingWorkItemCount = NULL;
	int i;
#endif
	size_t queuedWorkItems = 0;

	// allocate 16-bytes aligned buffer to hold KEY_INFO in a portable way
	keyInfoBuffer = TCalloc(keyInfoBufferSize);
	if (!keyInfoBuffer)
		return ERR_OUTOFMEMORY;
	keyInfoBufferOffset = 16 - (((uint64) keyInfoBuffer) % 16);
	keyInfo = (PKEY_INFO) (keyInfoBuffer + keyInfoBufferOffset);

#if !defined(DEVICE_DRIVER) && !defined(_UEFI)
	VirtualLock (keyInfoBuffer, keyInfoBufferSize);
#endif

	// if no PIM specified, use default value
	if (pim < 0)
		pim = 0;

	if (retHeaderCryptoInfo != NULL)
	{
		cryptoInfo = retHeaderCryptoInfo;
	}
	else
	{
      if (!retInfo)
         return ERR_PARAMETER_INCORRECT;

		cryptoInfo = *retInfo = crypto_open ();
		if (cryptoInfo == NULL)
			return ERR_OUTOFMEMORY;
	}
#if !defined(_UEFI)
	/* use thread pool only if no PRF was specified */
	if ((selected_pkcs5_prf == 0) && (encryptionThreadCount > 1))
	{
		keyDerivationCompletedEvent = TCalloc (sizeof (TC_EVENT));
		if (!keyDerivationCompletedEvent)
			return ERR_OUTOFMEMORY;

		noOutstandingWorkItemEvent = TCalloc (sizeof (TC_EVENT));
		if (!noOutstandingWorkItemEvent)
		{
			TCfree(keyDerivationCompletedEvent);
			return ERR_OUTOFMEMORY;
		}

		outstandingWorkItemCount = TCalloc (sizeof (LONG));
		if (!outstandingWorkItemCount)
		{
			TCfree(keyDerivationCompletedEvent);
			TCfree(noOutstandingWorkItemEvent);
			return ERR_OUTOFMEMORY;
		}

		keyDerivationWorkItemsSize = sizeof (KeyDerivationWorkItem) * pkcs5PrfCount;
		keyDerivationWorkItems = TCalloc (keyDerivationWorkItemsSize);
		if (!keyDerivationWorkItems)
		{
			TCfree(keyDerivationCompletedEvent);
			TCfree(noOutstandingWorkItemEvent);
			TCfree(outstandingWorkItemCount);
			return ERR_OUTOFMEMORY;
		}

		for (i = 0; i < pkcs5PrfCount; ++i)
			keyDerivationWorkItems[i].Free = TRUE;

		*outstandingWorkItemCount = 0;
#ifdef DEVICE_DRIVER
		KeInitializeEvent (keyDerivationCompletedEvent, SynchronizationEvent, FALSE);
		KeInitializeEvent (noOutstandingWorkItemEvent, SynchronizationEvent, TRUE);
#else
		*keyDerivationCompletedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
		if (!*keyDerivationCompletedEvent)
		{
			TCfree (keyDerivationWorkItems);
			TCfree(keyDerivationCompletedEvent);
			TCfree(noOutstandingWorkItemEvent);
			TCfree(outstandingWorkItemCount);
			return ERR_OUTOFMEMORY;
		}

		*noOutstandingWorkItemEvent = CreateEvent (NULL, FALSE, TRUE, NULL);
		if (!*noOutstandingWorkItemEvent)
		{
			CloseHandle (*keyDerivationCompletedEvent);
			TCfree (keyDerivationWorkItems);
			TCfree(keyDerivationCompletedEvent);
			TCfree(noOutstandingWorkItemEvent);
			TCfree(outstandingWorkItemCount);
			return ERR_OUTOFMEMORY;
		}

		VirtualLock (keyDerivationWorkItems, keyDerivationWorkItemsSize);
#endif
	}

#if !defined(DEVICE_DRIVER) 
	VirtualLock (&dk, sizeof (dk));
	VirtualLock (&header, sizeof (header));
#endif
#endif //  !defined(_UEFI)

	crypto_loadkey (keyInfo, password->Text, (int) password->Length);

	// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
	memcpy (keyInfo->salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);

	// Test all available PKCS5 PRFs
	for (enqPkcs5Prf = FIRST_PRF_ID; enqPkcs5Prf <= LAST_PRF_ID || queuedWorkItems > 0; ++enqPkcs5Prf)
	{
		// if a PRF is specified, we skip all other PRFs
		if (selected_pkcs5_prf != 0 && enqPkcs5Prf != selected_pkcs5_prf)
			continue;

#if !defined(_UEFI)
		if ((selected_pkcs5_prf == 0) && (encryptionThreadCount > 1))
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

						EncryptionThreadPoolBeginKeyDerivation (keyDerivationCompletedEvent, noOutstandingWorkItemEvent,
							&item->KeyReady, outstandingWorkItemCount, enqPkcs5Prf, keyInfo->userKey,
							keyInfo->keyLength, keyInfo->salt, get_pkcs5_iteration_count (enqPkcs5Prf, pim, bBoot), item->DerivedKey);

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
						keyInfo->noIterations = get_pkcs5_iteration_count (pkcs5_prf, pim, bBoot);
						memcpy (dk, item->DerivedKey, sizeof (dk));

						item->Free = TRUE;
						--queuedWorkItems;
						goto KeyReady;
					}
				}

				if (queuedWorkItems > 0)
					TC_WAIT_EVENT (*keyDerivationCompletedEvent);
			}
			continue;
KeyReady:	;
		}
		else
#endif // !defined(_UEFI)
		{
			pkcs5_prf = enqPkcs5Prf;
			keyInfo->noIterations = get_pkcs5_iteration_count (enqPkcs5Prf, pim, bBoot);

			switch (pkcs5_prf)
			{
			case SHA512:
				derive_key_sha512 (keyInfo->userKey, keyInfo->keyLength, keyInfo->salt,
					PKCS5_SALT_SIZE, keyInfo->noIterations, dk, GetMaxPkcs5OutSize());
				break;

			case SHA256:
				derive_key_sha256 (keyInfo->userKey, keyInfo->keyLength, keyInfo->salt,
					PKCS5_SALT_SIZE, keyInfo->noIterations, dk, GetMaxPkcs5OutSize());
				break;

                #ifndef WOLFCRYPT_BACKEND
                        case BLAKE2S:
				derive_key_blake2s (keyInfo->userKey, keyInfo->keyLength, keyInfo->salt,
					PKCS5_SALT_SIZE, keyInfo->noIterations, dk, GetMaxPkcs5OutSize());
				break;

	                case WHIRLPOOL:
				derive_key_whirlpool (keyInfo->userKey, keyInfo->keyLength, keyInfo->salt,
					PKCS5_SALT_SIZE, keyInfo->noIterations, dk, GetMaxPkcs5OutSize());
				break;


                        case STREEBOG:
				derive_key_streebog(keyInfo->userKey, keyInfo->keyLength, keyInfo->salt,
					PKCS5_SALT_SIZE, keyInfo->noIterations, dk, GetMaxPkcs5OutSize());
				break;
                #endif	
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
#ifndef TC_WINDOWS_DRIVER
					// Copy the secondary key (if cascade, multiple concatenated)
					memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
#endif
					// Secondary key schedule
					if (!EAInitMode (cryptoInfo, dk + EAGetKeySize (cryptoInfo->ea)))
					{
						status = ERR_MODE_INIT_FAILED;
						goto err;
					}
				}
				else
				{
					continue;
				}

				// Copy the header for decryption
				memcpy (header, encryptedHeader, sizeof (header));

				// Try to decrypt header

				DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

				// Magic 'VERA'
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
#if 0
				// Volume creation time (legacy)
				cryptoInfo->volume_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_CREATION_TIME).Value;

				// Header creation time (legacy)
				cryptoInfo->header_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_MODIFICATION_TIME).Value;
#endif
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
						cryptoInfo->noIterations = keyInfo->noIterations;
						cryptoInfo->volumePim = pim;
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
				memcpy (keyInfo->master_keydata, header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE);
#ifdef TC_WINDOWS_DRIVER
				{
					blake2s_state ctx;
#ifndef _WIN64
					NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
					KFLOATING_SAVE floatingPointState;	
					if (HasSSE2())
						saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
					blake2s_init (&ctx);
					blake2s_update (&ctx, keyInfo->master_keydata, MASTER_KEYDATA_SIZE);
					blake2s_update (&ctx, header, sizeof(header));
					blake2s_final (&ctx, cryptoInfo->master_keydata_hash);
					burn(&ctx, sizeof (ctx));
#ifndef _WIN64
					if (NT_SUCCESS (saveStatus))
						KeRestoreFloatingPointState (&floatingPointState);
#endif
				}
#else
				memcpy (cryptoInfo->master_keydata, keyInfo->master_keydata, MASTER_KEYDATA_SIZE);
#endif
				// PKCS #5
				cryptoInfo->pkcs5 = pkcs5_prf;
				cryptoInfo->noIterations = keyInfo->noIterations;
				cryptoInfo->volumePim = pim;

				// Init the cipher with the decrypted master key
				status = EAInit (cryptoInfo->ea, keyInfo->master_keydata + primaryKeyOffset, cryptoInfo->ks);
				if (status == ERR_CIPHER_INIT_FAILURE)
					goto err;
#ifndef TC_WINDOWS_DRIVER
				// The secondary master key (if cascade, multiple concatenated)
				memcpy (cryptoInfo->k2, keyInfo->master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
#endif
				if (!EAInitMode (cryptoInfo, keyInfo->master_keydata + EAGetKeySize (cryptoInfo->ea)))
				{
					status = ERR_MODE_INIT_FAILED;
					goto err;
				}

				// check that first half of keyInfo.master_keydata is different from the second half. If they are the same return error
				if (memcmp (keyInfo->master_keydata, keyInfo->master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea)) == 0)
				{
					cryptoInfo->bVulnerableMasterKey = TRUE;
					if (retHeaderCryptoInfo)
						retHeaderCryptoInfo->bVulnerableMasterKey = TRUE;
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
	burn (dk, sizeof(dk));
	burn (header, sizeof(header));

#if !defined(DEVICE_DRIVER) && !defined(_UEFI)
	VirtualUnlock (&dk, sizeof (dk));
	VirtualUnlock (&header, sizeof (header));
#endif

#if !defined(_UEFI)
	if ((selected_pkcs5_prf == 0) && (encryptionThreadCount > 1))
	{
		EncryptionThreadPoolBeginReadVolumeHeaderFinalization (keyDerivationCompletedEvent, noOutstandingWorkItemEvent, outstandingWorkItemCount, 
			keyInfoBuffer, keyInfoBufferSize, 
			keyDerivationWorkItems, keyDerivationWorkItemsSize);
	}
	else
#endif
	{
		burn (keyInfo, sizeof (KEY_INFO));
#if !defined(DEVICE_DRIVER) && !defined(_UEFI)
		VirtualUnlock (keyInfoBuffer, keyInfoBufferSize);
#endif
		TCfree(keyInfoBuffer);
	}
	return status;
}

#if defined(_WIN32) && !defined(_UEFI)
void ComputeBootloaderFingerprint (uint8 *bootLoaderBuf, unsigned int bootLoaderSize, uint8* fingerprint)
{
	// compute Whirlpool+SHA512 fingerprint of bootloader including MBR
	// we skip user configuration fields:
	// TC_BOOT_SECTOR_PIM_VALUE_OFFSET = 400
	// TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET = 402
	//  => TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE = 4
	// TC_BOOT_SECTOR_USER_MESSAGE_OFFSET     = 406
	//  => TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH = 24
	// TC_BOOT_SECTOR_USER_CONFIG_OFFSET      = 438
	//
	// we have: TC_BOOT_SECTOR_USER_MESSAGE_OFFSET = TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE

#ifndef WOLFCRYPT_BACKEND
        WHIRLPOOL_CTX whirlpool;
	sha512_ctx sha2;

	WHIRLPOOL_init (&whirlpool);
	sha512_begin (&sha2);

	WHIRLPOOL_add (bootLoaderBuf, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &whirlpool);
	sha512_hash (bootLoaderBuf, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &sha2);

	WHIRLPOOL_add (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &whirlpool);
	sha512_hash (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &sha2);

	WHIRLPOOL_add (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, (bootLoaderSize - TC_SECTOR_SIZE_BIOS), &whirlpool);
	sha512_hash (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, (bootLoaderSize - TC_SECTOR_SIZE_BIOS), &sha2);

	WHIRLPOOL_finalize (&whirlpool, fingerprint);
	sha512_end (&fingerprint [WHIRLPOOL_DIGESTSIZE], &sha2);
#else
	sha512_ctx sha2_512;
	sha256_ctx sha2_256;

	sha512_begin (&sha2_512);
	sha256_begin (&sha2_256);

	sha512_hash (bootLoaderBuf, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &sha2_512);
	sha256_hash (bootLoaderBuf, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &sha2_256);

	sha512_hash (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &sha2_512);
	sha256_hash (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &sha2_256);

	sha512_hash (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, (bootLoaderSize - TC_SECTOR_SIZE_BIOS), &sha2_512);
	sha256_hash (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, (bootLoaderSize - TC_SECTOR_SIZE_BIOS), &sha2_256);

	sha512_end (&fingerprint, &sha2_512);
	sha256_end (&fingerprint [SHA512_DIGESTSIZE], &sha2_256);
	sha256_end (&fingerprint [SHA512_DIGESTSIZE + SHA256_DIGESTSIZE], &sha2_256);
#endif
}
#endif

#else // TC_WINDOWS_BOOT

int ReadVolumeHeader (BOOL bBoot, char *header, Password *password, int pim, PCRYPTO_INFO *retInfo, CRYPTO_INFO *retHeaderCryptoInfo)
{
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	char dk[32 * 2];			// 2 * 256-bit key
#else
	char dk[32 * 2 * 3];		// 6 * 256-bit key
#endif

	PCRYPTO_INFO cryptoInfo;
	int status = ERR_SUCCESS;
	uint32 iterations = pim;
	iterations <<= 16;
	iterations |= bBoot;

	if (retHeaderCryptoInfo != NULL)
		cryptoInfo = retHeaderCryptoInfo;
	else
		cryptoInfo = *retInfo = crypto_open ();

	// PKCS5 PRF
#ifdef TC_WINDOWS_BOOT_SHA2
	derive_key_sha256 (password->Text, (int) password->Length, header + HEADER_SALT_OFFSET,
		PKCS5_SALT_SIZE, iterations, dk, sizeof (dk));
#else
	derive_key_blake2s (password->Text, (int) password->Length, header + HEADER_SALT_OFFSET,
		PKCS5_SALT_SIZE, iterations, dk, sizeof (dk));
#endif

	// Mode of operation
	cryptoInfo->mode = FIRST_MODE_OF_OPERATION_ID;

#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	cryptoInfo->ea = 1;
#else
	// Test all available encryption algorithms
	for (cryptoInfo->ea = EAGetFirst (); cryptoInfo->ea != 0; cryptoInfo->ea = EAGetNext (cryptoInfo->ea))
#endif
	{
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	#if defined (TC_WINDOWS_BOOT_SERPENT) && !defined (WOLFCRYPT_BACKEND)
		serpent_set_key (dk, cryptoInfo->ks);
	#elif defined (TC_WINDOWS_BOOT_TWOFISH) && !defined (WOLFCRYPT_BACKEND)
		twofish_set_key ((TwofishInstance *) cryptoInfo->ks, (const u4byte *) dk);
	#elif defined (TC_WINDOWS_BOOT_CAMELLIA) && !defined (WOLFCRYPT_BACKEND)
		camellia_set_key (dk, cryptoInfo->ks);
	#else
		status = EAInit (dk, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;
	#endif
#else
		status = EAInit (cryptoInfo->ea, dk, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;
#endif
		// Secondary key schedule
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	#if defined (TC_WINDOWS_BOOT_SERPENT) && !defined (WOLFCRYPT_BACKEND)
		serpent_set_key (dk + 32, cryptoInfo->ks2);
	#elif defined (TC_WINDOWS_BOOT_TWOFISH) && !defined (WOLFCRYPT_BACKEND)
		twofish_set_key ((TwofishInstance *)cryptoInfo->ks2, (const u4byte *) (dk + 32));
	#elif defined (TC_WINDOWS_BOOT_CAMELLIA) && !defined (WOLFCRYPT_BACKEND)
		camellia_set_key (dk + 32, cryptoInfo->ks2);
	#else
		EAInit (dk + 32, cryptoInfo->ks2);
	#endif
#else
		EAInit (cryptoInfo->ea, dk + EAGetKeySize (cryptoInfo->ea), cryptoInfo->ks2);
#endif

		// Try to decrypt header
		DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		// Check magic 'VERA' and CRC-32 of header fields and master keydata
		if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x56455241
			|| (GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION) >= 4 && GetHeaderField32 (header, TC_HEADER_OFFSET_HEADER_CRC) != GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
			|| GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != GetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
		{
			EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
			status = ERR_PASSWORD_WRONG;
			goto err;
#else
			continue;
#endif
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

#ifdef TC_WINDOWS_BOOT_SHA2
		cryptoInfo->pkcs5 = SHA256;
#else
		cryptoInfo->pkcs5 = BLAKE2S;
#endif

		memcpy (dk, header + HEADER_MASTER_KEYDATA_OFFSET, sizeof (dk));
		EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		if (retHeaderCryptoInfo)
			goto ret;

		// Init the encryption algorithm with the decrypted master key
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	#if defined (TC_WINDOWS_BOOT_SERPENT) && !defined (WOLFCRYPT_BACKEND)
		serpent_set_key (dk, cryptoInfo->ks);
	#elif defined (TC_WINDOWS_BOOT_TWOFISH) && !defined (WOLFCRYPT_BACKEND)
		twofish_set_key ((TwofishInstance *) cryptoInfo->ks, (const u4byte *) dk);
	#elif defined (TC_WINDOWS_BOOT_CAMELLIA) && !defined (WOLFCRYPT_BACKEND)
		camellia_set_key (dk, cryptoInfo->ks);
	#else
		status = EAInit (dk, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;
	#endif
#else
		status = EAInit (cryptoInfo->ea, dk, cryptoInfo->ks);
		if (status == ERR_CIPHER_INIT_FAILURE)
			goto err;
#endif

		// The secondary master key (if cascade, multiple concatenated)
#ifdef TC_WINDOWS_BOOT_SINGLE_CIPHER_MODE
	#if defined (TC_WINDOWS_BOOT_SERPENT) && !defined (WOLFCRYPT_BACKEND)
		serpent_set_key (dk + 32, cryptoInfo->ks2);
	#elif defined (TC_WINDOWS_BOOT_TWOFISH) && !defined (WOLFCRYPT_BACKEND)
		twofish_set_key ((TwofishInstance *)cryptoInfo->ks2, (const u4byte *) (dk + 32));
	#elif defined (TC_WINDOWS_BOOT_CAMELLIA) && !defined (WOLFCRYPT_BACKEND)
		camellia_set_key (dk + 32, cryptoInfo->ks2);
	#else
		EAInit (dk + 32, cryptoInfo->ks2);
	#endif
#else
		EAInit (cryptoInfo->ea, dk + EAGetKeySize (cryptoInfo->ea), cryptoInfo->ks2);
#endif
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
	return status;
}

#endif // TC_WINDOWS_BOOT


#if !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)

#ifdef VOLFORMAT
#	include "../Format/TcFormat.h"
#	include "Dlgcode.h"
#endif

// Creates a volume header in memory
#if defined(_UEFI)
int CreateVolumeHeaderInMemory(BOOL bBoot, char *header, int ea, int mode, Password *password,
	int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
	unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
	unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode)
#else
int CreateVolumeHeaderInMemory (HWND hwndDlg, BOOL bBoot, char *header, int ea, int mode, Password *password,
		   int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
		   unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
		   unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode)
#endif // !defined(_UEFI)
{
	unsigned char *p = (unsigned char *) header;
	static CRYPTOPP_ALIGN_DATA(16) KEY_INFO keyInfo;

	int nUserKeyLen = password? password->Length : 0;
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	static char dk[MASTER_KEYDATA_SIZE];
	int x;
	int retVal = 0;
	int primaryKeyOffset;

	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	// if no PIM specified, use default value
	if (pim < 0)
		pim = 0;

	memset (header, 0, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
#if !defined(_UEFI)
	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));
#endif // !defined(_UEFI)

	/* Encryption setup */

	if (masterKeydata == NULL)
	{
		// We have no master key data (creating a new volume) so we'll use the TrueCrypt RNG to generate them

		int bytesNeeded;

		switch (mode)
		{

		default:
			bytesNeeded = EAGetKeySize (ea) * 2;	// Size of primary + secondary key(s)
		}

#if !defined(_UEFI)
		if (!RandgetBytes (hwndDlg, keyInfo.master_keydata, bytesNeeded, TRUE))
#else
		if (!RandgetBytes(keyInfo.master_keydata, bytesNeeded, TRUE))
#endif
		{
			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY;
			goto err;
		}

		// check that first half of keyInfo.master_keydata is different from the second half. If they are the same return error
		// cf CCSS,NSA comment at page 3: https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38e-initial-public-comments-2021.pdf
		if (memcmp (keyInfo.master_keydata, &keyInfo.master_keydata[bytesNeeded/2], bytesNeeded/2) == 0)
		{
			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY;
			goto err;
		}
	}
	else
	{
		// We already have existing master key data (the header is being re-encrypted)
		memcpy (keyInfo.master_keydata, masterKeydata, MASTER_KEYDATA_SIZE);
	}

	// User key
	if (password)
	{
		memcpy (keyInfo.userKey, password->Text, nUserKeyLen);
		keyInfo.keyLength = nUserKeyLen;
		keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, pim, bBoot);
	}
	else
	{
		keyInfo.keyLength = 0;
		keyInfo.noIterations = 0;
	}

	// User selected encryption algorithm
	cryptoInfo->ea = ea;

	// User selected PRF
	cryptoInfo->pkcs5 = pkcs5_prf;
	cryptoInfo->noIterations = keyInfo.noIterations;
	cryptoInfo->volumePim = pim;

	// Mode of operation
	cryptoInfo->mode = mode;

	// Salt for header key derivation
#if !defined(_UEFI)
	if (!RandgetBytes(hwndDlg, keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
#else
	if (!RandgetBytes(keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
#endif
	{
		crypto_close (cryptoInfo);
		retVal = ERR_CIPHER_INIT_WEAK_KEY; 
		goto err;
	}

	if (password)
	{
		// PBKDF2 (PKCS5) is used to derive primary header key(s) and secondary header key(s) (XTS) from the password/keyfiles
		switch (pkcs5_prf)
		{
		case SHA512:
			derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case SHA256:
			derive_key_sha256 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

        #ifndef WOLFCRYPT_BACKEND
		case BLAKE2S:
			derive_key_blake2s (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case WHIRLPOOL:
			derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case STREEBOG:
			derive_key_streebog(keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;
        #endif
		default:
			// Unknown/wrong ID
			crypto_close (cryptoInfo);
			TC_THROW_FATAL_EXCEPTION;
		}
	}
	else
	{
		// generate a random key
#if !defined(_UEFI)
		if (!RandgetBytes(hwndDlg, dk, GetMaxPkcs5OutSize(), !bWipeMode))
#else
		if (!RandgetBytes(dk, GetMaxPkcs5OutSize(), !bWipeMode))
#endif
		{
			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY; 
			goto err;
		}
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
		crypto_close (cryptoInfo);
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

#ifndef TC_WINDOWS_DRIVER
	// The secondary key (if cascade, multiple concatenated)
	memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
	primaryKeyOffset = 0;
#endif

	retVal = EAInit (cryptoInfo->ea, dk + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
	{
		crypto_close (cryptoInfo);
		goto err;
	}

	// Mode of operation
	if (!EAInitMode (cryptoInfo, dk + EAGetKeySize (cryptoInfo->ea)))
	{
		crypto_close (cryptoInfo);
		retVal = ERR_OUTOFMEMORY;
		goto err;
	}


	// Encrypt the entire header (except the salt)
	EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET,
		HEADER_ENCRYPTED_DATA_SIZE,
		cryptoInfo);


	/* cryptoInfo setup for further use (disk format) */

	// Init with the master key(s)
	retVal = EAInit (cryptoInfo->ea, keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
	{
		crypto_close (cryptoInfo);
		goto err;
	}

	memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

#ifndef TC_WINDOWS_DRIVER
	// The secondary master key (if cascade, multiple concatenated)
	memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
#endif

	// Mode of operation
	if (!EAInitMode (cryptoInfo, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea)))
	{
		crypto_close (cryptoInfo);
		retVal = ERR_OUTOFMEMORY;
		goto err;
	}


#ifdef VOLFORMAT
	if (!bInPlaceEncNonSys && (showKeys || (bBoot && !masterKeydata)))
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
			wchar_t tmp2[8] = {0};
			StringCchPrintfW (tmp2, ARRAYSIZE(tmp2), L"%02X", (int) (unsigned char) keyInfo.master_keydata[i + primaryKeyOffset]);
			StringCchCatW (MasterKeyGUIView, ARRAYSIZE(MasterKeyGUIView), tmp2);
		}

		HeaderKeyGUIView[0] = 0;
		for (i = 0; i < NBR_KEY_BYTES_TO_DISPLAY; i++)
		{
			wchar_t tmp2[8];
			StringCchPrintfW (tmp2, ARRAYSIZE(tmp2), L"%02X", (int) (unsigned char) dk[primaryKeyOffset + i]);
			StringCchCatW (HeaderKeyGUIView, ARRAYSIZE(HeaderKeyGUIView), tmp2);
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

	*retInfo = cryptoInfo;

err:
	burn (dk, sizeof(dk));
	burn (&keyInfo, sizeof (keyInfo));
#if !defined(_UEFI)
	VirtualUnlock (&keyInfo, sizeof (keyInfo));
	VirtualUnlock (&dk, sizeof (dk));
#endif // !defined(_UEFI)

	return 0;
}

#if !defined(_UEFI)
BOOL ReadEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, uint8 *header, DWORD *bytesRead)
{
#if TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#error TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#endif

	uint8 sectorBuffer[TC_MAX_VOLUME_SECTOR_SIZE];
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


BOOL WriteEffectiveVolumeHeader (BOOL device, HANDLE fileHandle, uint8 *header)
{
#if TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#error TC_VOLUME_HEADER_EFFECTIVE_SIZE > TC_MAX_VOLUME_SECTOR_SIZE
#endif

	uint8 sectorBuffer[TC_MAX_VOLUME_SECTOR_SIZE];
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
int WriteRandomDataToReservedHeaderAreas (HWND hwndDlg, HANDLE dev, CRYPTO_INFO *cryptoInfo, uint64 dataAreaSize, BOOL bPrimaryOnly, BOOL bBackupOnly)
{
	char temporaryKey[MASTER_KEYDATA_SIZE];
	char originalK2[MASTER_KEYDATA_SIZE];

	uint8 buf[TC_VOLUME_HEADER_GROUP_SIZE];

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
		if (!RandgetBytes (hwndDlg, temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE)
			|| !RandgetBytes (hwndDlg, cryptoInfo->k2, sizeof (cryptoInfo->k2), FALSE))
		{
			nStatus = ERR_PARAMETER_INCORRECT;
			goto final_seq;
		}

		nStatus = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (nStatus != ERR_SUCCESS)
			goto final_seq;

		if (!EAInitMode (cryptoInfo, cryptoInfo->k2))
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

		// encrypt random data instead of existing data for better entropy
		RandgetBytesFull (hwndDlg, buf + TC_VOLUME_HEADER_EFFECTIVE_SIZE, sizeof (buf) - TC_VOLUME_HEADER_EFFECTIVE_SIZE, FALSE, TRUE);

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

	if (!EAInitMode (cryptoInfo, cryptoInfo->k2))
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

#endif // !defined(_UEFI)
#endif // !defined (DEVICE_DRIVER) && !defined (TC_WINDOWS_BOOT)
