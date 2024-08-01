/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "TCdefs.h"
#include <ntddk.h>
#include <ntddvol.h>
#include <Ntstrsafe.h>
#include "Cache.h"
#include "Crc.h"
#include "Crypto.h"
#include "Apidrvr.h"
#include "EncryptedIoQueue.h"
#include "Common/Endian.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "Volumes.h"
#include "VolumeFilter.h"
#include "Wipe.h"
#include "DriveFilter.h"
#include "Boot/Windows/BootCommon.h"
#include "cpu.h"
#include "rdrand.h"
#include "chachaRng.h"

static BOOL DeviceFilterActive = FALSE;

BOOL BootArgsValid = FALSE;
BootArguments BootArgs;
uint8*  BootSecRegionData = NULL;
uint32 BootSecRegionSize = 0;
uint32 BootPkcs5 = 0;

static uint64 BootLoaderArgsPtr;
static BOOL BootDriveSignatureValid = FALSE;

static KMUTEX MountMutex;

static volatile BOOL BootDriveFound = FALSE;
static DriveFilterExtension *BootDriveFilterExtension = NULL;
static LARGE_INTEGER BootDriveLength;
static uint8 BootLoaderFingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE];

static BOOL CrashDumpEnabled = FALSE;
static BOOL HibernationEnabled = FALSE;

static BOOL LegacyHibernationDriverFilterActive = FALSE;
static uint8 *HibernationWriteBuffer = NULL;
static MDL *HibernationWriteBufferMdl = NULL;

static uint32 HibernationPreventionCount = 0;

static BootEncryptionSetupRequest SetupRequest;
static volatile BOOL SetupInProgress = FALSE;
PKTHREAD EncryptionSetupThread = NULL;
static volatile BOOL EncryptionSetupThreadAbortRequested;
static KSPIN_LOCK SetupStatusSpinLock;
static int64 SetupStatusEncryptedAreaEnd;
static BOOL TransformWaitingForIdle;
static NTSTATUS SetupResult;

static WipeDecoySystemRequest WipeDecoyRequest;
static volatile BOOL DecoySystemWipeInProgress = FALSE;
static volatile BOOL DecoySystemWipeThreadAbortRequested;
static KSPIN_LOCK DecoySystemWipeStatusSpinLock;
static int64 DecoySystemWipedAreaEnd;
PKTHREAD DecoySystemWipeThread = NULL;
static NTSTATUS DecoySystemWipeResult;

static uint64 BootArgsRegionsDefault[] = { EFI_BOOTARGS_REGIONS_DEFAULT };
static uint64 BootArgsRegionsEFI[] = { EFI_BOOTARGS_REGIONS_EFI };

NTSTATUS LoadBootArguments (BOOL bIsEfi)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS bootArgsAddr;
	uint8 *mappedBootArgs;
	uint8 *mappedCryptoInfo = NULL;
	uint16 bootLoaderArgsIndex;
	uint64* BootArgsRegionsPtr = bIsEfi? BootArgsRegionsEFI : BootArgsRegionsDefault;
	size_t BootArgsRegionsCount = bIsEfi? sizeof(BootArgsRegionsEFI)/ sizeof(BootArgsRegionsEFI[0]) : sizeof(BootArgsRegionsDefault)/ sizeof(BootArgsRegionsDefault[0]);

	KeInitializeMutex (&MountMutex, 0);
//	__debugbreak();
	for (bootLoaderArgsIndex = 0;
		bootLoaderArgsIndex < BootArgsRegionsCount && status != STATUS_SUCCESS;
		++bootLoaderArgsIndex)
	{
		bootArgsAddr.QuadPart = BootArgsRegionsPtr[bootLoaderArgsIndex] + TC_BOOT_LOADER_ARGS_OFFSET;
		Dump ("Checking BootArguments at 0x%x\n", bootArgsAddr.LowPart);

		mappedBootArgs = MmMapIoSpace (bootArgsAddr, sizeof (BootArguments), MmCached);
		if (!mappedBootArgs)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (TC_IS_BOOT_ARGUMENTS_SIGNATURE (mappedBootArgs))
		{
			BootArguments *bootArguments = (BootArguments *) mappedBootArgs;
			Dump ("BootArguments found at 0x%x\n", bootArgsAddr.LowPart);

			DumpMem (mappedBootArgs, sizeof (BootArguments));

			if (bootArguments->BootLoaderVersion == VERSION_NUM
				&& bootArguments->BootArgumentsCrc32 != GetCrc32 ((uint8 *) bootArguments, (int) ((uint8 *) &bootArguments->BootArgumentsCrc32 - (uint8 *) bootArguments)))
			{
				Dump ("BootArguments CRC incorrect\n");
				burn (mappedBootArgs, sizeof (BootArguments));
				MmUnmapIoSpace (mappedBootArgs, sizeof (BootArguments));
				mappedBootArgs = NULL;
				TC_BUG_CHECK (STATUS_CRC_ERROR);
			}

			// Sanity check: for valid boot argument, the password is less than 64 bytes long
			if (bootArguments->BootPassword.Length <= MAX_LEGACY_PASSWORD)
			{
				BootLoaderArgsPtr = BootArgsRegionsPtr[bootLoaderArgsIndex];

				BootArgs = *bootArguments;
				BootArgsValid = TRUE;
				burn (bootArguments, sizeof (*bootArguments));

				BootDriveSignatureValid = TRUE;

				Dump ("BootLoaderVersion = %x\n", (int) BootArgs.BootLoaderVersion);
				Dump ("HeaderSaltCrc32 = %x\n", (int) BootArgs.HeaderSaltCrc32);
				Dump ("CryptoInfoOffset = %x\n", (int) BootArgs.CryptoInfoOffset);
				Dump ("CryptoInfoLength = %d\n", (int) BootArgs.CryptoInfoLength);
				Dump ("HiddenSystemPartitionStart = %I64u\n", BootArgs.HiddenSystemPartitionStart);
				Dump ("DecoySystemPartitionStart = %I64u\n", BootArgs.DecoySystemPartitionStart);
				Dump ("Flags = %x\n", BootArgs.Flags);
				Dump ("BootDriveSignature = %x\n", BootArgs.BootDriveSignature);
				Dump ("BootArgumentsCrc32 = %x\n", BootArgs.BootArgumentsCrc32);

				// clear fingerprint
				burn (BootLoaderFingerprint, sizeof (BootLoaderFingerprint));
				MmUnmapIoSpace (mappedBootArgs, sizeof (BootArguments));
				mappedBootArgs = NULL;

				// Extra parameters? (pkcs5, hash)
				if (BootArgs.CryptoInfoLength > 0)
				{
					PHYSICAL_ADDRESS cryptoInfoAddress;
					cryptoInfoAddress.QuadPart = BootLoaderArgsPtr + BootArgs.CryptoInfoOffset;
					Dump ("CryptoInfo memory %x %d\n", cryptoInfoAddress.LowPart, BootArgs.CryptoInfoLength);

					mappedCryptoInfo = MmMapIoSpace (cryptoInfoAddress, BootArgs.CryptoInfoLength, MmCached);
					if (mappedCryptoInfo)
					{
						/* Get the parameters used for booting to speed up driver startup and avoid testing irrelevant PRFs */
						BOOT_CRYPTO_HEADER* pBootCryptoInfo = (BOOT_CRYPTO_HEADER*) mappedCryptoInfo;
						BootPkcs5 = pBootCryptoInfo->pkcs5; // save hash to speed up boot.

						BootSecRegionData = NULL;
						BootSecRegionSize = 0;

						// SecRegion data?
						if(BootArgs.CryptoInfoLength > (sizeof(BOOT_CRYPTO_HEADER) + sizeof(SECREGION_BOOT_PARAMS)) ) {
							uint32   crc;
							PHYSICAL_ADDRESS SecRegionAddress;
							SECREGION_BOOT_PARAMS* SecRegionParams = (SECREGION_BOOT_PARAMS*) (mappedCryptoInfo + sizeof(BOOT_CRYPTO_HEADER) + 2);
							uint8 *secRegionData = NULL;

							SecRegionAddress.QuadPart = SecRegionParams->Ptr;
							Dump ("SecRegion memory 0x%x %d\n", SecRegionAddress.LowPart, SecRegionParams->Size);
							// SecRegion correct?
							if( (SecRegionParams->Ptr != 0) && (SecRegionParams->Size > 0)) {
								crc = GetCrc32((uint8*)SecRegionParams, 12);
								if(crc == SecRegionParams->Crc) {
									Dump ("SecRegion crc ok\n");
									secRegionData = MmMapIoSpace (SecRegionAddress, SecRegionParams->Size, MmCached);
									if(secRegionData) {
										BootSecRegionData = TCalloc (SecRegionParams->Size);
										if(BootSecRegionData != NULL) {
											BootSecRegionSize = SecRegionParams->Size;
											memcpy(BootSecRegionData, secRegionData, SecRegionParams->Size);
										}
										burn (secRegionData, SecRegionParams->Size);
										MmUnmapIoSpace (secRegionData,  SecRegionParams->Size);
									}
								}
							}
						}
						// Erase boot loader scheduled keys
						burn (mappedCryptoInfo, BootArgs.CryptoInfoLength);
						MmUnmapIoSpace (mappedCryptoInfo, BootArgs.CryptoInfoLength);
						BootArgs.CryptoInfoLength = 0;
					}
					else
					{
						BootArgs.CryptoInfoLength = 0;
					}
				}
				status = STATUS_SUCCESS;
			}
			else
			{
				Dump ("BootArguments contains a password larger than maximum limit\n");
				burn (mappedBootArgs, sizeof (BootArguments));
				MmUnmapIoSpace (mappedBootArgs, sizeof (BootArguments));
				mappedBootArgs = NULL;
				TC_BUG_CHECK (STATUS_FAIL_CHECK);
			}
		}
		
		if (mappedBootArgs) {
			MmUnmapIoSpace (mappedBootArgs, sizeof (BootArguments));
		}
	}
	return status;
}


NTSTATUS DriveFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo)
{
	DriveFilterExtension *Extension = NULL;
	NTSTATUS status;
	PDEVICE_OBJECT filterDeviceObject = NULL;
	PDEVICE_OBJECT attachedDeviceObject;

	Dump ("DriveFilterAddDevice pdo=%p\n", pdo);

	attachedDeviceObject = IoGetAttachedDeviceReference (pdo);
	status = IoCreateDevice (driverObject, sizeof (DriveFilterExtension), NULL, attachedDeviceObject->DeviceType, 0, FALSE, &filterDeviceObject);

	ObDereferenceObject (attachedDeviceObject);

	if (!NT_SUCCESS (status))
	{
		filterDeviceObject = NULL;
		goto err;
	}

	Extension = (DriveFilterExtension *) filterDeviceObject->DeviceExtension;
	memset (Extension, 0, sizeof (DriveFilterExtension));

	status = IoAttachDeviceToDeviceStackSafe (filterDeviceObject, pdo, &(Extension->LowerDeviceObject)); 
	if (!NT_SUCCESS (status))
	{
		goto err;
	}

	if (!Extension->LowerDeviceObject)
	{
		status = STATUS_DEVICE_REMOVED;
		goto err;
	}

	Extension->IsDriveFilterDevice = Extension->Queue.IsFilterDevice = TRUE;
	Extension->DeviceObject = Extension->Queue.DeviceObject = filterDeviceObject;
	Extension->Pdo = pdo;
	
	Extension->Queue.LowerDeviceObject = Extension->LowerDeviceObject;
	IoInitializeRemoveLock (&Extension->Queue.RemoveLock, 'LRCV', 0, 0);

	Extension->ConfiguredEncryptedAreaStart = -1;
	Extension->ConfiguredEncryptedAreaEnd = -1;
	Extension->Queue.EncryptedAreaStart = -1;
	Extension->Queue.EncryptedAreaEnd = -1;
	Extension->Queue.EncryptedAreaEndUpdatePending = FALSE;

	filterDeviceObject->Flags |= Extension->LowerDeviceObject->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);
	filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DeviceFilterActive = TRUE;
	return status;

err:
	if (filterDeviceObject)
	{
		if (Extension && Extension->LowerDeviceObject)
			IoDetachDevice (Extension->LowerDeviceObject);

		IoDeleteDevice (filterDeviceObject);
	}

	return status;
}


static void DismountDrive (DriveFilterExtension *Extension, BOOL stopIoQueue)
{
	Dump ("Dismounting drive\n");
	ASSERT (Extension->DriveMounted);
	
	if (stopIoQueue && EncryptedIoQueueIsRunning (&Extension->Queue))
		EncryptedIoQueueStop (&Extension->Queue);

	crypto_close ((PCRYPTO_INFO) Extension->Queue.CryptoInfo);
	Extension->Queue.CryptoInfo = NULL;

	crypto_close ((PCRYPTO_INFO) Extension->HeaderCryptoInfo);
	Extension->HeaderCryptoInfo = NULL;

	Extension->DriveMounted = FALSE;

	Dump ("Drive dismount done!\n");
}

static void InvalidateVolumeKeys (EXTENSION *Extension)
{
	Dump ("Invalidating volume encryption keys\n");
	
	Extension->Queue.ThreadBlockReadWrite = TRUE;

	crypto_eraseKeys ((PCRYPTO_INFO) Extension->Queue.CryptoInfo);
	crypto_eraseKeys ((PCRYPTO_INFO) Extension->cryptoInfo);

	Dump ("Volume encryption keys invalidated!\n");
}

static void InvalidateDriveFilterKeys (DriveFilterExtension *Extension)
{
	Dump ("Invalidating drive filter encryption keys\n");
	ASSERT (Extension->DriveMounted);
	
	Extension->Queue.ThreadBlockReadWrite = TRUE;

	crypto_eraseKeys ((PCRYPTO_INFO) Extension->Queue.CryptoInfo);
	crypto_eraseKeys ((PCRYPTO_INFO) Extension->HeaderCryptoInfo);

	Dump ("Drive filter encryption keys invalidated!\n");
}

static void ComputeBootLoaderFingerprint(PDEVICE_OBJECT LowerDeviceObject, uint8* ioBuffer /* ioBuffer must be at least 512 bytes long */)
{
	NTSTATUS status;
	LARGE_INTEGER offset;
	WHIRLPOOL_CTX whirlpool;
	sha512_ctx sha2;
	ULONG bytesToRead, remainingBytes, bootloaderTotalSize = TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE;

	// clear fingerprint
	burn (BootLoaderFingerprint, sizeof (BootLoaderFingerprint));

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
	
	WHIRLPOOL_init (&whirlpool);
	sha512_begin (&sha2);
	// read the first 512 bytes
	offset.QuadPart = 0;

	status = TCReadDevice (LowerDeviceObject, ioBuffer, offset, TC_SECTOR_SIZE_BIOS);
	if (NT_SUCCESS (status))
	{
		NTSTATUS saveStatus = STATUS_INVALID_PARAMETER;
#ifdef _WIN64
		XSTATE_SAVE SaveState;
		if (IsCpuIntel() && HasSAVX())
			saveStatus = KeSaveExtendedProcessorStateVC(XSTATE_MASK_GSSE, &SaveState);
#else
		KFLOATING_SAVE floatingPointState;		
		if (HasISSE() || (HasSSSE3() && HasMMX()))
			saveStatus = KeSaveFloatingPointState (&floatingPointState);
#endif
		WHIRLPOOL_add (ioBuffer, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &whirlpool);
		WHIRLPOOL_add (ioBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &whirlpool);

		sha512_hash (ioBuffer, TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &sha2);
		sha512_hash (ioBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, (TC_BOOT_SECTOR_USER_CONFIG_OFFSET - (TC_BOOT_SECTOR_USER_MESSAGE_OFFSET + TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)), &sha2);

		// we has the reste of the bootloader, 512 bytes at a time
		offset.QuadPart = TC_SECTOR_SIZE_BIOS;
		remainingBytes = bootloaderTotalSize - TC_SECTOR_SIZE_BIOS;

		while (NT_SUCCESS (status) && (remainingBytes > 0))
		{
			bytesToRead = (remainingBytes >= TC_SECTOR_SIZE_BIOS)? TC_SECTOR_SIZE_BIOS : remainingBytes;
			status = TCReadDevice (LowerDeviceObject, ioBuffer, offset, bytesToRead);
			if (NT_SUCCESS (status))
			{
				remainingBytes -= bytesToRead;
				offset.QuadPart += bytesToRead;
				WHIRLPOOL_add (ioBuffer, bytesToRead, &whirlpool);
				sha512_hash (ioBuffer, bytesToRead, &sha2);
			}
			else
			{
				Dump ("TCReadDevice error %x during ComputeBootLoaderFingerprint call\n", status);
				break;
			}
		}

		if (NT_SUCCESS (status))
		{
			WHIRLPOOL_finalize (&whirlpool, BootLoaderFingerprint);
			sha512_end (&BootLoaderFingerprint [WHIRLPOOL_DIGESTSIZE], &sha2);
		}

		if (NT_SUCCESS (saveStatus))
#ifdef _WIN64
			KeRestoreExtendedProcessorStateVC(&SaveState);
#else
			KeRestoreFloatingPointState (&floatingPointState);
#endif
	}
	else
	{
		Dump ("TCReadDevice error %x during ComputeBootLoaderFingerprint call\n", status);
	}
}


static NTSTATUS MountDrive (DriveFilterExtension *Extension, Password *password, uint32 *headerSaltCrc32)
{
	BOOL hiddenVolume = (BootArgs.HiddenSystemPartitionStart != 0);
	int64 hiddenHeaderOffset = BootArgs.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;
	NTSTATUS status;
	LARGE_INTEGER offset;
	char *header;
	int pkcs5_prf = 0, pim = 0;
	PARTITION_INFORMATION_EX pi;
	BOOL bIsGPT = FALSE;

	Dump ("MountDrive pdo=%p\n", Extension->Pdo);
	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

	// Check disk MBR id and GPT ID if BootSecRegion is available to detect boot drive
	if (BootSecRegionData != NULL && BootSecRegionSize >= 1024) {
		uint8 mbr[TC_SECTOR_SIZE_BIOS];
		DCS_DISK_ENTRY_LIST* DeList = (DCS_DISK_ENTRY_LIST*)(BootSecRegionData + 512);
		offset.QuadPart = 0;
		status = TCReadDevice (Extension->LowerDeviceObject, mbr, offset, TC_SECTOR_SIZE_BIOS);

		if (NT_SUCCESS (status) && DeList->DE[DE_IDX_DISKID].DiskId.MbrID != *(uint32 *) (mbr + 0x1b8))
			return STATUS_UNSUCCESSFUL;

		offset.QuadPart = 512;
		status = TCReadDevice (Extension->LowerDeviceObject, mbr, offset, TC_SECTOR_SIZE_BIOS);
		if (NT_SUCCESS (status) && memcmp(&DeList->DE[DE_IDX_DISKID].DiskId.GptID, mbr + 0x38, sizeof(DCS_GUID)) != 0)
			return STATUS_UNSUCCESSFUL;

		header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
		if (!header)
			return STATUS_INSUFFICIENT_RESOURCES;
		// Copy header from SecRegion instead of read from disk
		memcpy(header, BootSecRegionData, 512);

		// Set SecRegion data for the disk (sectors to substitute to hide GPT table)
		Extension->Queue.SecRegionData = BootSecRegionData;
		Extension->Queue.SecRegionSize = BootSecRegionSize;
	} else {
		// Check boot drive signature first (header CRC search could fail if a user restored the header to a non-boot drive)
		if (BootDriveSignatureValid)
		{
			uint8 mbr[TC_SECTOR_SIZE_BIOS];

			offset.QuadPart = 0;
			status = TCReadDevice (Extension->LowerDeviceObject, mbr, offset, TC_SECTOR_SIZE_BIOS);

			if (NT_SUCCESS (status) && BootArgs.BootDriveSignature != *(uint32 *) (mbr + 0x1b8))
				return STATUS_UNSUCCESSFUL;
		}

		header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
		if (!header)
			return STATUS_INSUFFICIENT_RESOURCES;

		offset.QuadPart = hiddenVolume ? hiddenHeaderOffset : TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;
		Dump ("Reading volume header at %I64u\n", offset.QuadPart);

		status = TCReadDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
		if (!NT_SUCCESS (status))
		{
			Dump ("TCReadDevice error %x\n", status);
			goto ret;
		}
		Extension->Queue.SecRegionData = NULL;
		Extension->Queue.SecRegionSize = 0;
	}

	if (headerSaltCrc32)
	{
		uint32 saltCrc = GetCrc32 (header, PKCS5_SALT_SIZE);

		if (saltCrc != *headerSaltCrc32)
		{
			status = STATUS_UNSUCCESSFUL;
			goto ret;
		}

		Extension->VolumeHeaderSaltCrc32 = saltCrc;
	}

	Extension->HeaderCryptoInfo = crypto_open();
	if (!Extension->HeaderCryptoInfo)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	if (NT_SUCCESS(SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &pi, sizeof (pi))))
	{
		bIsGPT = (pi.PartitionStyle == PARTITION_STYLE_GPT)? TRUE : FALSE;
	}

	if (BootPkcs5 > 0)
	{
		/* Get the parameters used for booting to speed up driver startup and avoid testing irrelevant PRFs */
		Hash* pHash = HashGet(BootPkcs5);
		if (pHash && (bIsGPT || pHash->SystemEncryption))
			pkcs5_prf = BootPkcs5;
	}

	pim = (int) (BootArgs.Flags >> 16);

	if (ReadVolumeHeader (!hiddenVolume, header, password, pkcs5_prf, pim, &Extension->Queue.CryptoInfo, Extension->HeaderCryptoInfo) == 0)
	{
		// Header decrypted		
		status = STATUS_SUCCESS;
		Dump ("Header decrypted\n");

		if (Extension->HeaderCryptoInfo->bVulnerableMasterKey)
		{
			// The volume header master key is vulnerable
			Dump ("The volume header master key is vulnerable\n");
		}

		// calculate Fingerprint
		ComputeBootLoaderFingerprint (Extension->LowerDeviceObject, header);
			
		if (Extension->Queue.CryptoInfo->hiddenVolume)
		{
			int64 hiddenPartitionOffset = BootArgs.HiddenSystemPartitionStart;
			Dump ("Hidden volume start offset = %I64d\n", Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + hiddenPartitionOffset);
			
			Extension->HiddenSystem = TRUE;

			Extension->Queue.RemapEncryptedArea = TRUE;
			Extension->Queue.RemappedAreaOffset = hiddenPartitionOffset + Extension->Queue.CryptoInfo->EncryptedAreaStart.Value - BootArgs.DecoySystemPartitionStart;
			Extension->Queue.RemappedAreaDataUnitOffset = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value / ENCRYPTION_DATA_UNIT_SIZE - BootArgs.DecoySystemPartitionStart / ENCRYPTION_DATA_UNIT_SIZE;
			
			Extension->Queue.CryptoInfo->EncryptedAreaStart.Value = BootArgs.DecoySystemPartitionStart;
			
			if (Extension->Queue.CryptoInfo->VolumeSize.Value > hiddenPartitionOffset - BootArgs.DecoySystemPartitionStart)
			{
				// we have already erased boot loader scheduled keys
				TC_THROW_FATAL_EXCEPTION;
			}

			Dump ("RemappedAreaOffset = %I64d\n", Extension->Queue.RemappedAreaOffset);
			Dump ("RemappedAreaDataUnitOffset = %I64d\n", Extension->Queue.RemappedAreaDataUnitOffset);
		}
		else
		{
			Extension->HiddenSystem = FALSE;
			Extension->Queue.RemapEncryptedArea = FALSE;
		}

		Extension->ConfiguredEncryptedAreaStart = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value;
		Extension->ConfiguredEncryptedAreaEnd = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + Extension->Queue.CryptoInfo->VolumeSize.Value - 1;

		Extension->Queue.EncryptedAreaStart = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value;
		Extension->Queue.EncryptedAreaEnd = Extension->Queue.CryptoInfo->EncryptedAreaStart.Value + Extension->Queue.CryptoInfo->EncryptedAreaLength.Value - 1;

		if (Extension->Queue.CryptoInfo->EncryptedAreaLength.Value == 0)
		{
			Extension->Queue.EncryptedAreaStart = -1;
			Extension->Queue.EncryptedAreaEnd = -1;
		}

		Dump ("Loaded: ConfiguredEncryptedAreaStart=%I64d (%I64d)  ConfiguredEncryptedAreaEnd=%I64d (%I64d)\n", Extension->ConfiguredEncryptedAreaStart / 1024 / 1024, Extension->ConfiguredEncryptedAreaStart, Extension->ConfiguredEncryptedAreaEnd / 1024 / 1024, Extension->ConfiguredEncryptedAreaEnd);
		Dump ("Loaded: EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);

		// at this stage, we have already erased boot loader scheduled keys

		BootDriveFilterExtension = Extension;
		BootDriveFound = Extension->BootDrive = Extension->DriveMounted = Extension->VolumeHeaderPresent = TRUE;
		BootDriveFilterExtension->MagicNumber = TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER;

		// Try to load password cached if saved in SecRegion
		if (BootSecRegionData != NULL && BootSecRegionSize > 1024) {
			DCS_DISK_ENTRY_LIST* DeList = (DCS_DISK_ENTRY_LIST*)(BootSecRegionData + 512);
			uint32 crc;
			uint32 crcSaved;
			crcSaved = DeList->CRC32;
			DeList->CRC32 = 0;
			crc = GetCrc32((uint8*)DeList, 512);
			if(crc == crcSaved){
				if(DeList->DE[DE_IDX_PWDCACHE].Type == DE_PwdCache) {
					uint64 sector = 0;
					DCS_DEP_PWD_CACHE* pwdCache = (DCS_DEP_PWD_CACHE*)(BootSecRegionData + DeList->DE[DE_IDX_PWDCACHE].Sectors.Offset);
					DecryptDataUnits((unsigned char*)pwdCache, (UINT64_STRUCT*)&sector, 1, Extension->Queue.CryptoInfo);
					crcSaved = pwdCache->CRC;
					pwdCache->CRC = 0;
					crc = GetCrc32((unsigned char*)pwdCache, 512);
					if(crcSaved == crc && pwdCache->Count < CACHE_SIZE){
						uint32 i;
						for(i = 0; i<pwdCache->Count; ++i){
							if (CacheBootPassword && pwdCache->Pwd[i].Length > 0)	{
								int cachedPim = CacheBootPim? (int) (pwdCache->Pim[i]) : 0;
								AddLegacyPasswordToCache (&pwdCache->Pwd[i], cachedPim);
							}
						}
						burn(pwdCache, sizeof(*pwdCache));
					}
				}
			}
		}

		if (CacheBootPassword && BootArgs.BootPassword.Length > 0)
		{
			int cachedPim = CacheBootPim? pim : 0;
			AddLegacyPasswordToCache (&BootArgs.BootPassword, cachedPim);
		}

		burn (&BootArgs.BootPassword, sizeof (BootArgs.BootPassword));

		{
			STORAGE_DEVICE_NUMBER storageDeviceNumber;
			status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &storageDeviceNumber, sizeof (storageDeviceNumber));

			if (!NT_SUCCESS (status))
			{
				Dump ("Failed to get drive number - error %x\n", status);
				Extension->SystemStorageDeviceNumberValid = FALSE;
			}
			else
			{
				Extension->SystemStorageDeviceNumber = storageDeviceNumber.DeviceNumber;
				Extension->SystemStorageDeviceNumberValid = TRUE;
			}
		}

		status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &BootDriveLength, sizeof (BootDriveLength));
		
		if (!NT_SUCCESS (status))
		{
			Dump ("Failed to get drive length - error %x\n", status);
			BootDriveLength.QuadPart = 0;
			Extension->Queue.MaxReadAheadOffset.QuadPart = 0;
		}
		else
			Extension->Queue.MaxReadAheadOffset = BootDriveLength;

		/* encrypt keys */
#ifdef _WIN64
		if (IsRamEncryptionEnabled())
		{
			VcProtectKeys (Extension->HeaderCryptoInfo, VcGetEncryptionID (Extension->HeaderCryptoInfo));
			VcProtectKeys (Extension->Queue.CryptoInfo, VcGetEncryptionID (Extension->Queue.CryptoInfo));
		}
#endif
		
		status = EncryptedIoQueueStart (&Extension->Queue);
		if (!NT_SUCCESS (status))
			TC_BUG_CHECK (status);

		if (IsOSAtLeast (WIN_VISTA))
		{
			CrashDumpEnabled = TRUE;
			HibernationEnabled = TRUE;
#ifdef _WIN64
			if (IsRamEncryptionEnabled())
			{
				HibernationEnabled = FALSE;
			}
#endif
		}
		else if (!LegacyHibernationDriverFilterActive)
			StartLegacyHibernationDriverFilter();

		// Hidden system hibernation is not supported if an extra boot partition is present as the system is not allowed to update the boot partition
		if (IsHiddenSystemRunning() && (BootArgs.Flags & TC_BOOT_ARGS_FLAG_EXTRA_BOOT_PARTITION))
		{
			CrashDumpEnabled = FALSE;
			HibernationEnabled = FALSE;
		}
	}
	else
	{
		Dump ("Header not decrypted\n");
		crypto_close (Extension->HeaderCryptoInfo);
		Extension->HeaderCryptoInfo = NULL;

		status = STATUS_UNSUCCESSFUL;
	}

ret:
	TCfree (header);
	return status;
}


static NTSTATUS SaveDriveVolumeHeader (DriveFilterExtension *Extension)
{
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER offset;
	uint8 *header;

	header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!header)
		return STATUS_INSUFFICIENT_RESOURCES;

	offset.QuadPart = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;

	status = TCReadDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (status))
	{
		Dump ("TCReadDevice error %x", status);
		goto ret;
	}

	Dump ("Saving: ConfiguredEncryptedAreaStart=%I64d (%I64d)  ConfiguredEncryptedAreaEnd=%I64d (%I64d)\n", Extension->ConfiguredEncryptedAreaStart / 1024 / 1024, Extension->ConfiguredEncryptedAreaStart, Extension->ConfiguredEncryptedAreaEnd / 1024 / 1024, Extension->ConfiguredEncryptedAreaEnd);
	Dump ("Saving: EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);
	
	if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1
		|| Extension->Queue.EncryptedAreaEnd <= Extension->Queue.EncryptedAreaStart)
	{
		if (SetupRequest.SetupMode == SetupDecryption)
		{
			memset (header, 0, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			Extension->VolumeHeaderPresent = FALSE;
		}
	}
	else
	{
		uint32 headerCrc32;
		uint64 encryptedAreaLength = Extension->Queue.EncryptedAreaEnd + 1 - Extension->Queue.EncryptedAreaStart;
		uint8 *fieldPos = header + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
		PCRYPTO_INFO pCryptoInfo = Extension->HeaderCryptoInfo;
#ifdef _WIN64
		CRYPTO_INFO tmpCI;
		if (IsRamEncryptionEnabled())
		{
			memcpy (&tmpCI, pCryptoInfo, sizeof (CRYPTO_INFO));
			VcUnprotectKeys (&tmpCI, VcGetEncryptionID (pCryptoInfo));
			pCryptoInfo = &tmpCI;
		}
#endif

		DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, pCryptoInfo);

		if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x56455241)
		{
			Dump ("Header not decrypted");
			status = STATUS_UNKNOWN_REVISION;
			goto ret;
		}

		mputInt64 (fieldPos, encryptedAreaLength);

		headerCrc32 = GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
		fieldPos = header + TC_HEADER_OFFSET_HEADER_CRC;
		mputLong (fieldPos, headerCrc32);

		EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, pCryptoInfo);
#ifdef _WIN64
		if (IsRamEncryptionEnabled())
		{
			burn (&tmpCI, sizeof (CRYPTO_INFO));
		}
#endif
	}

	status = TCWriteDevice (Extension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (status))
	{
		Dump ("TCWriteDevice error %x", status);
		goto ret;
	}

ret:
	TCfree (header);
	return status;
}


static NTSTATUS PassIrp (PDEVICE_OBJECT deviceObject, PIRP irp)
{
	IoSkipCurrentIrpStackLocation (irp);
	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS PassFilteredIrp (PDEVICE_OBJECT deviceObject, PIRP irp, PIO_COMPLETION_ROUTINE completionRoutine, PVOID completionRoutineArg)
{
	IoCopyCurrentIrpStackLocationToNext (irp);

	if (completionRoutine)
		IoSetCompletionRoutine (irp, completionRoutine, completionRoutineArg, TRUE, TRUE, TRUE);

	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS OnDeviceUsageNotificationCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, DriveFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (!(Extension->LowerDeviceObject->Flags & DO_POWER_PAGABLE))
		filterDeviceObject->Flags &= ~DO_POWER_PAGABLE;

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static BOOL IsVolumeDevice (PDEVICE_OBJECT deviceObject)
{
	VOLUME_NUMBER volNumber;
	VOLUME_DISK_EXTENTS extents[2];
	NTSTATUS extentStatus = SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, extents, sizeof (extents));

	return NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_OFFLINE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_IO_CAPABLE, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_IS_PARTITION, NULL, 0,  NULL, 0))
		|| NT_SUCCESS (SendDeviceIoControlRequest (deviceObject, IOCTL_VOLUME_QUERY_VOLUME_NUMBER, NULL, 0, &volNumber, sizeof (volNumber)))
		|| NT_SUCCESS (extentStatus) || extentStatus == STATUS_BUFFER_OVERFLOW || extentStatus == STATUS_BUFFER_TOO_SMALL;
}


static void CheckDeviceTypeAndMount (DriveFilterExtension *filterExtension)
{
	if (BootArgsValid)
	{
		// Windows sometimes merges a removable drive PDO and its volume PDO to a single PDO having no volume interface (GUID_DEVINTERFACE_VOLUME).
		// Therefore, we need to test whether the device supports volume IOCTLs.
		if (VolumeClassFilterRegistered
			&& BootArgs.HiddenSystemPartitionStart != 0
			&& IsVolumeDevice (filterExtension->LowerDeviceObject))
		{
			Dump ("Drive and volume merged pdo=%p", filterExtension->Pdo);

			filterExtension->IsVolumeFilterDevice = TRUE;
			filterExtension->IsDriveFilterDevice = FALSE;
		}
		else
		{
			NTSTATUS status = KeWaitForMutexObject (&MountMutex, Executive, KernelMode, FALSE, NULL);
			if (!NT_SUCCESS (status))
				TC_BUG_CHECK (status);

			if (!BootDriveFound)
			{
				Password bootPass = {0};
				bootPass.Length = BootArgs.BootPassword.Length;
				memcpy (bootPass.Text, BootArgs.BootPassword.Text, BootArgs.BootPassword.Length);
				MountDrive (filterExtension, &bootPass, &BootArgs.HeaderSaltCrc32);
				burn (&bootPass, sizeof (bootPass));
			}

			KeReleaseMutex (&MountMutex, FALSE);
		}
	}
}


static VOID MountDriveWorkItemRoutine (PDEVICE_OBJECT deviceObject, DriveFilterExtension *filterExtension)
{
	CheckDeviceTypeAndMount (filterExtension);
	KeSetEvent (&filterExtension->MountWorkItemCompletedEvent, IO_NO_INCREMENT, FALSE);
}


static NTSTATUS OnStartDeviceCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, DriveFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (Extension->LowerDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
		filterDeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;

	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		CheckDeviceTypeAndMount (Extension);
	}
	else
	{
		PIO_WORKITEM workItem = IoAllocateWorkItem (filterDeviceObject);
		if (!workItem)
		{
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KeInitializeEvent (&Extension->MountWorkItemCompletedEvent, SynchronizationEvent, FALSE);
		IoQueueWorkItem (workItem, MountDriveWorkItemRoutine, DelayedWorkQueue, Extension); 

		KeWaitForSingleObject (&Extension->MountWorkItemCompletedEvent, Executive, KernelMode, FALSE, NULL);
		IoFreeWorkItem (workItem);
	}

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static NTSTATUS DispatchPnp (PDEVICE_OBJECT DeviceObject, PIRP Irp, DriveFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	switch (irpSp->MinorFunction)
	{
	case IRP_MN_START_DEVICE:
		Dump ("IRP_MN_START_DEVICE pdo=%p\n", Extension->Pdo);
		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnStartDeviceCompleted, Extension);


	case IRP_MN_DEVICE_USAGE_NOTIFICATION:
		Dump ("IRP_MN_DEVICE_USAGE_NOTIFICATION type=%d\n", (int) irpSp->Parameters.UsageNotification.Type);

		{
			PDEVICE_OBJECT attachedDevice = IoGetAttachedDeviceReference (DeviceObject);

			if (attachedDevice == DeviceObject || (attachedDevice->Flags & DO_POWER_PAGABLE))
				DeviceObject->Flags |= DO_POWER_PAGABLE;

			ObDereferenceObject (attachedDevice);
		}

		// Prevent creation of hibernation and crash dump files if required
		if (irpSp->Parameters.UsageNotification.InPath
			&& (
				(irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeDumpFile && !CrashDumpEnabled)
				|| (irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeHibernation && !HibernationEnabled)
				)
			)
		{
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);

			if (irpSp->Parameters.UsageNotification.Type == DeviceUsageTypeHibernation)
				++HibernationPreventionCount;

			Dump ("Preventing dump type=%d\n", (int) irpSp->Parameters.UsageNotification.Type);
			return TCCompleteIrp (Irp, STATUS_UNSUCCESSFUL, 0);
		}

		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnDeviceUsageNotificationCompleted, Extension);


	case IRP_MN_REMOVE_DEVICE:
		Dump ("IRP_MN_REMOVE_DEVICE pdo=%p\n", Extension->Pdo);

		IoReleaseRemoveLockAndWait (&Extension->Queue.RemoveLock, Irp);
		status = PassIrp (Extension->LowerDeviceObject, Irp);

		IoDetachDevice (Extension->LowerDeviceObject);

		if (Extension->DriveMounted)
			DismountDrive (Extension, TRUE);

		if (Extension->BootDrive)
		{
			BootDriveFound = FALSE;
			BootDriveFilterExtension = NULL;
		}

		IoDeleteDevice (DeviceObject);
		return status;


	default:
		status = PassIrp (Extension->LowerDeviceObject, Irp);
		IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	}
	return status;
}


static NTSTATUS DispatchPower (PDEVICE_OBJECT DeviceObject, PIRP Irp, DriveFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	Dump ("IRP_MJ_POWER minor=%d type=%d shutdown=%d\n", (int) irpSp->MinorFunction, (int) irpSp->Parameters.Power.Type, (int) irpSp->Parameters.Power.ShutdownType);

	if (SetupInProgress
		&& irpSp->MinorFunction == IRP_MN_SET_POWER
		&& irpSp->Parameters.Power.ShutdownType == PowerActionHibernate)
	{
		while (SendDeviceIoControlRequest (RootDeviceObject, TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP, NULL, 0, NULL, 0) == STATUS_INSUFFICIENT_RESOURCES);
	}

	// Dismount the system drive on shutdown on Windows 7 and later
	if (DriverShuttingDown
		&& EraseKeysOnShutdown
		&& IsOSAtLeast (WIN_7)
		&& Extension->BootDrive
		&& Extension->DriveMounted
		&& irpSp->MinorFunction == IRP_MN_SET_POWER
		&& irpSp->Parameters.Power.Type == DevicePowerState)
	{
		DismountDrive (Extension, TRUE);
#ifdef _WIN64
		ClearSecurityParameters ();
#endif
	}

	PoStartNextPowerIrp (Irp);

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	IoSkipCurrentIrpStackLocation (Irp);
	status = PoCallDriver (Extension->LowerDeviceObject, Irp);

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}

static NTSTATUS DispatchControl (PDEVICE_OBJECT DeviceObject, PIRP Irp, DriveFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	BOOL bBlockTrim = BlockSystemTrimCommand || IsHiddenSystemRunning();
	NTSTATUS status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
			Dump ("DriverFilter-DispatchControl: IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES\n");
			if (bBlockTrim)
			{
				PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
				DWORD inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
				if (inputLength >= sizeof (DEVICE_MANAGE_DATA_SET_ATTRIBUTES))
				{
					PDEVICE_MANAGE_DATA_SET_ATTRIBUTES pInputAttrs = (PDEVICE_MANAGE_DATA_SET_ATTRIBUTES) Irp->AssociatedIrp.SystemBuffer;
					DEVICE_DATA_MANAGEMENT_SET_ACTION action = pInputAttrs->Action;
					if (action == DeviceDsmAction_Trim)
					{
						Dump ("DriverFilter-DispatchControl: IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES - DeviceDsmAction_Trim.\n");

						if (bBlockTrim)
						{
							Dump ("DriverFilter-DispatchControl:: TRIM command blocked.\n");
							IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
							return TCCompleteDiskIrp (Irp, STATUS_SUCCESS, 0);
						}
					}
				}
			}
			break;
		case IOCTL_DISK_GROW_PARTITION:
			Dump ("DriverFilter-DispatchControl: IOCTL_DISK_GROW_PARTITION blocked\n");
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
			return TCCompleteDiskIrp (Irp, STATUS_UNSUCCESSFUL, 0);
			break;
	}

	status = PassIrp (Extension->LowerDeviceObject, Irp);
	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}


NTSTATUS DriveFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DriveFilterExtension *Extension = (DriveFilterExtension *) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS status;

	ASSERT (!Extension->bRootDevice && Extension->IsDriveFilterDevice);

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_READ:
	case IRP_MJ_WRITE:
		if (Extension->BootDrive)
		{
			status = EncryptedIoQueueAddIrp (&Extension->Queue, Irp);
			
			if (status != STATUS_PENDING)
				TCCompleteDiskIrp (Irp, status, 0);

			return status;
		}
		break;

	case IRP_MJ_PNP:
		return DispatchPnp (DeviceObject, Irp, Extension, irpSp);

	case IRP_MJ_POWER:
		return DispatchPower (DeviceObject, Irp, Extension, irpSp);

	case IRP_MJ_DEVICE_CONTROL:
		return DispatchControl (DeviceObject, Irp, Extension, irpSp);
	}

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	status = PassIrp (Extension->LowerDeviceObject, Irp);

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}

void EmergencyClearAllKeys (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	irp->IoStatus.Information = 0;

	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
	{
		irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	}
	else
	{
		int drive;
		for (drive = MIN_MOUNTED_VOLUME_DRIVE_NUMBER; drive <= MAX_MOUNTED_VOLUME_DRIVE_NUMBER; ++drive)
		{
			PDEVICE_OBJECT device = GetVirtualVolumeDeviceObject (drive);
			if (device)
			{
				PEXTENSION extension = (PEXTENSION) device->DeviceExtension;
				if (extension)
				{
					InvalidateVolumeKeys (extension);
				}
			}
		}

		if (BootDriveFound && BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted)
			InvalidateDriveFilterKeys (BootDriveFilterExtension);

#ifdef _WIN64
		ClearSecurityParameters();
#endif

		irp->IoStatus.Status = STATUS_SUCCESS;
	}
}

void ReopenBootVolumeHeader (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	LARGE_INTEGER offset;
	char *header;
	ReopenBootVolumeHeaderRequest *request = (ReopenBootVolumeHeaderRequest *) irp->AssociatedIrp.SystemBuffer;

	irp->IoStatus.Information = 0;

	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
	{
		irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		return;
	}

	if (!ValidateIOBufferSize (irp, sizeof (ReopenBootVolumeHeaderRequest), ValidateInput))
		return;

	if (!BootDriveFound || !BootDriveFilterExtension || !BootDriveFilterExtension->DriveMounted || !BootDriveFilterExtension->HeaderCryptoInfo
		|| request->VolumePassword.Length > MAX_LEGACY_PASSWORD
		|| request->pkcs5_prf < 0
		|| request->pkcs5_prf > LAST_PRF_ID
		|| request->pim < 0
		|| request->pim > 65535
		)
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		goto wipe;
	}

	header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!header)
	{
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		goto wipe;
	}

	if (BootDriveFilterExtension->HiddenSystem)
		offset.QuadPart = BootArgs.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;
	else
		offset.QuadPart = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;

	irp->IoStatus.Status = TCReadDevice (BootDriveFilterExtension->LowerDeviceObject, header, offset, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
	if (!NT_SUCCESS (irp->IoStatus.Status))
	{
		Dump ("TCReadDevice error %x\n", irp->IoStatus.Status);
		goto ret;
	}

#ifdef _WIN64
	if (IsRamEncryptionEnabled())
	{
		VcUnprotectKeys (BootDriveFilterExtension->HeaderCryptoInfo, VcGetEncryptionID (BootDriveFilterExtension->HeaderCryptoInfo));
	}
#endif

	if (ReadVolumeHeader (!BootDriveFilterExtension->HiddenSystem, header, &request->VolumePassword, request->pkcs5_prf, request->pim, NULL, BootDriveFilterExtension->HeaderCryptoInfo) == 0)
	{
		Dump ("Header reopened\n");
#ifdef _WIN64
		if (IsRamEncryptionEnabled())
		{
			VcProtectKeys (BootDriveFilterExtension->HeaderCryptoInfo, VcGetEncryptionID(BootDriveFilterExtension->HeaderCryptoInfo));
		}
#endif
		ComputeBootLoaderFingerprint (BootDriveFilterExtension->LowerDeviceObject, header);

		BootDriveFilterExtension->Queue.CryptoInfo->pkcs5 = BootDriveFilterExtension->HeaderCryptoInfo->pkcs5;
		BootDriveFilterExtension->Queue.CryptoInfo->noIterations = BootDriveFilterExtension->HeaderCryptoInfo->noIterations;
		BootDriveFilterExtension->Queue.CryptoInfo->volumePim = BootDriveFilterExtension->HeaderCryptoInfo->volumePim;

		irp->IoStatus.Status = STATUS_SUCCESS;
	}
	else
	{
		crypto_close (BootDriveFilterExtension->HeaderCryptoInfo);
		BootDriveFilterExtension->HeaderCryptoInfo = NULL;

		Dump ("Header not reopened\n");
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}

ret:
	TCfree (header);
wipe:
	burn (request, sizeof (*request));
}


// Legacy Windows XP/2003 hibernation dump filter

typedef NTSTATUS (*HiberDriverWriteFunctionA) (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3);
typedef NTSTATUS (*HiberDriverWriteFunctionB) (PLARGE_INTEGER writeOffset, PMDL dataMdl);

typedef struct
{
#ifdef _WIN64
	uint8 FieldPad1[64];
	HiberDriverWriteFunctionB WriteFunctionB;
	uint8 FieldPad2[56];
#else
	uint8 FieldPad1[48];
	HiberDriverWriteFunctionB WriteFunctionB;
	uint8 FieldPad2[32];
#endif
	HiberDriverWriteFunctionA WriteFunctionA;
	uint8 FieldPad3[24];
	LARGE_INTEGER PartitionStartOffset;
} HiberDriverContext;

typedef NTSTATUS (*HiberDriverEntry) (PVOID arg0, HiberDriverContext *hiberDriverContext);

typedef struct
{
	LIST_ENTRY ModuleList;
#ifdef _WIN64
	uint8 FieldPad1[32];
#else
	uint8 FieldPad1[16];
#endif
	PVOID ModuleBaseAddress;
	HiberDriverEntry ModuleEntryAddress;
#ifdef _WIN64
	uint8 FieldPad2[24];
#else
	uint8 FieldPad2[12];
#endif
	UNICODE_STRING ModuleName;
} ModuleTableItem;


#define TC_MAX_HIBER_FILTER_COUNT 3
static int LastHiberFilterNumber = 0;

static HiberDriverEntry OriginalHiberDriverEntries[TC_MAX_HIBER_FILTER_COUNT];
static HiberDriverWriteFunctionA OriginalHiberDriverWriteFunctionsA[TC_MAX_HIBER_FILTER_COUNT];
static HiberDriverWriteFunctionB OriginalHiberDriverWriteFunctionsB[TC_MAX_HIBER_FILTER_COUNT];

static LARGE_INTEGER HiberPartitionOffset;


static NTSTATUS HiberDriverWriteFunctionFilter (int filterNumber, PLARGE_INTEGER writeOffset, PMDL dataMdl, BOOL writeB, ULONG arg0WriteA, PVOID arg3WriteA)
{
	MDL *encryptedDataMdl = dataMdl;

	if (writeOffset && dataMdl && BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted)
	{
		ULONG dataLength = MmGetMdlByteCount (dataMdl);

		if (dataMdl->MappedSystemVa && dataLength > 0)
		{
			uint64 offset = HiberPartitionOffset.QuadPart + writeOffset->QuadPart;
			uint64 intersectStart;
			uint32 intersectLength;

			if (dataLength > TC_HIBERNATION_WRITE_BUFFER_SIZE)
				TC_BUG_CHECK (STATUS_BUFFER_OVERFLOW);

			if ((dataLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
				TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

			if ((offset & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
				TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

			GetIntersection (offset,
				dataLength,
				BootDriveFilterExtension->Queue.EncryptedAreaStart,
				BootDriveFilterExtension->Queue.EncryptedAreaEnd,
				&intersectStart,
				&intersectLength);

			if (intersectLength > 0)
			{
				UINT64_STRUCT dataUnit;
				dataUnit.Value = intersectStart / ENCRYPTION_DATA_UNIT_SIZE;

				memcpy (HibernationWriteBuffer, dataMdl->MappedSystemVa, dataLength);

				if (BootDriveFilterExtension->Queue.RemapEncryptedArea)
					dataUnit.Value += BootDriveFilterExtension->Queue.RemappedAreaDataUnitOffset;

				EncryptDataUnitsCurrentThreadEx (HibernationWriteBuffer + (intersectStart - offset),
					&dataUnit,
					intersectLength / ENCRYPTION_DATA_UNIT_SIZE,
					BootDriveFilterExtension->Queue.CryptoInfo);

				encryptedDataMdl = HibernationWriteBufferMdl;
				MmInitializeMdl (encryptedDataMdl, HibernationWriteBuffer, dataLength);
				encryptedDataMdl->MdlFlags = dataMdl->MdlFlags;
			}
		}
	}

	if (writeB)
		return (*OriginalHiberDriverWriteFunctionsB[filterNumber]) (writeOffset, encryptedDataMdl);
	
	return (*OriginalHiberDriverWriteFunctionsA[filterNumber]) (arg0WriteA, writeOffset, encryptedDataMdl, arg3WriteA);
}


static NTSTATUS HiberDriverWriteFunctionAFilter0 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (0, writeOffset, dataMdl, FALSE, arg0, arg3);
}

static NTSTATUS HiberDriverWriteFunctionAFilter1 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (1, writeOffset, dataMdl, FALSE, arg0, arg3);
}

static NTSTATUS HiberDriverWriteFunctionAFilter2 (ULONG arg0, PLARGE_INTEGER writeOffset, PMDL dataMdl, PVOID arg3)
{
	return HiberDriverWriteFunctionFilter (2, writeOffset, dataMdl, FALSE, arg0, arg3);
}


static NTSTATUS HiberDriverWriteFunctionBFilter0 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (0, writeOffset, dataMdl, TRUE, 0, NULL);
}

static NTSTATUS HiberDriverWriteFunctionBFilter1 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (1, writeOffset, dataMdl, TRUE, 0, NULL);
}

static NTSTATUS HiberDriverWriteFunctionBFilter2 (PLARGE_INTEGER writeOffset, PMDL dataMdl)
{
	return HiberDriverWriteFunctionFilter (2, writeOffset, dataMdl, TRUE, 0, NULL);
}


static NTSTATUS HiberDriverEntryFilter (int filterNumber, PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	BOOL filterInstalled = FALSE;
	NTSTATUS status;

	if (!OriginalHiberDriverEntries[filterNumber])
		return STATUS_UNSUCCESSFUL;

	status = (*OriginalHiberDriverEntries[filterNumber]) (arg0, hiberDriverContext);

	if (!NT_SUCCESS (status) || !hiberDriverContext)
		return status;

	if (SetupInProgress)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if (hiberDriverContext->WriteFunctionA)
	{
		Dump ("Filtering WriteFunctionA %d\n", filterNumber);
		OriginalHiberDriverWriteFunctionsA[filterNumber] = hiberDriverContext->WriteFunctionA;

		switch (filterNumber)
		{
		case 0: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter0; break;
		case 1: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter1; break;
		case 2: hiberDriverContext->WriteFunctionA = HiberDriverWriteFunctionAFilter2; break;
		default: TC_THROW_FATAL_EXCEPTION;
		}

		filterInstalled = TRUE;
	}

	if (hiberDriverContext->WriteFunctionB)
	{
		Dump ("Filtering WriteFunctionB %d\n", filterNumber);
		OriginalHiberDriverWriteFunctionsB[filterNumber] = hiberDriverContext->WriteFunctionB;

		switch (filterNumber)
		{
		case 0: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter0; break;
		case 1: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter1; break;
		case 2: hiberDriverContext->WriteFunctionB = HiberDriverWriteFunctionBFilter2; break;
		default: TC_THROW_FATAL_EXCEPTION;
		}

		filterInstalled = TRUE;
	}

	if (filterInstalled && hiberDriverContext->PartitionStartOffset.QuadPart != 0)
	{
		HiberPartitionOffset = hiberDriverContext->PartitionStartOffset;

		if (BootDriveFilterExtension->Queue.RemapEncryptedArea)
			hiberDriverContext->PartitionStartOffset.QuadPart += BootDriveFilterExtension->Queue.RemappedAreaOffset;
	}

	return STATUS_SUCCESS;
}


static NTSTATUS HiberDriverEntryFilter0 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (0, arg0, hiberDriverContext);
}


static NTSTATUS HiberDriverEntryFilter1 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (1, arg0, hiberDriverContext);
}


static NTSTATUS HiberDriverEntryFilter2 (PVOID arg0, HiberDriverContext *hiberDriverContext)
{
	return HiberDriverEntryFilter (2, arg0, hiberDriverContext);
}


static VOID LoadImageNotifyRoutine (PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo)
{
	ModuleTableItem *moduleItem;
	LIST_ENTRY *listEntry;
	KIRQL origIrql;

	if (!imageInfo || !imageInfo->SystemModeImage || !imageInfo->ImageBase || !TCDriverObject->DriverSection)
		return;

	moduleItem = *(ModuleTableItem **) TCDriverObject->DriverSection;
	if (!moduleItem || !moduleItem->ModuleList.Flink)
		return;

	// Search loaded system modules for hibernation driver
	origIrql = KeRaiseIrqlToDpcLevel();

	for (listEntry = moduleItem->ModuleList.Flink->Blink;
		listEntry && listEntry != TCDriverObject->DriverSection;
		listEntry = listEntry->Flink)
	{
		moduleItem = CONTAINING_RECORD (listEntry, ModuleTableItem, ModuleList);

		if (moduleItem && imageInfo->ImageBase == moduleItem->ModuleBaseAddress)
		{
			if (moduleItem->ModuleName.Buffer && moduleItem->ModuleName.Length >= 5 * sizeof (wchar_t))
			{
				if (memcmp (moduleItem->ModuleName.Buffer, L"hiber", 5 * sizeof (wchar_t)) == 0
					|| memcmp (moduleItem->ModuleName.Buffer, L"Hiber", 5 * sizeof (wchar_t)) == 0
					|| memcmp (moduleItem->ModuleName.Buffer, L"HIBER", 5 * sizeof (wchar_t)) == 0)
				{
					HiberDriverEntry filterEntry;

					switch (LastHiberFilterNumber)
					{
					case 0: filterEntry = HiberDriverEntryFilter0; break;
					case 1: filterEntry = HiberDriverEntryFilter1; break;
					case 2: filterEntry = HiberDriverEntryFilter2; break;
					default: TC_THROW_FATAL_EXCEPTION;
					}

					if (moduleItem->ModuleEntryAddress != filterEntry)
					{
						// Install filter
						OriginalHiberDriverEntries[LastHiberFilterNumber] = moduleItem->ModuleEntryAddress;
						moduleItem->ModuleEntryAddress = filterEntry;

						if (++LastHiberFilterNumber > TC_MAX_HIBER_FILTER_COUNT - 1)
							LastHiberFilterNumber = 0;
					}
				}
			}
			break;
		}
	}

	KeLowerIrql (origIrql);
}


void StartLegacyHibernationDriverFilter ()
{
	PHYSICAL_ADDRESS highestAcceptableWriteBufferAddr;
	NTSTATUS status;

	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);
	ASSERT (!IsOSAtLeast (WIN_VISTA));

	if (!TCDriverObject->DriverSection || !*(ModuleTableItem **) TCDriverObject->DriverSection)
		goto err;

	// All buffers required for hibernation must be allocated here
#ifdef _WIN64
	highestAcceptableWriteBufferAddr.QuadPart = 0x7FFffffFFFFULL;
#else
	highestAcceptableWriteBufferAddr.QuadPart = 0xffffFFFFULL;
#endif

	HibernationWriteBuffer = MmAllocateContiguousMemory (TC_HIBERNATION_WRITE_BUFFER_SIZE, highestAcceptableWriteBufferAddr);
	if (!HibernationWriteBuffer)
		goto err;

	HibernationWriteBufferMdl = IoAllocateMdl (HibernationWriteBuffer, TC_HIBERNATION_WRITE_BUFFER_SIZE, FALSE, FALSE, NULL);
	if (!HibernationWriteBufferMdl)
		goto err;

	MmBuildMdlForNonPagedPool (HibernationWriteBufferMdl);

	status = PsSetLoadImageNotifyRoutine (LoadImageNotifyRoutine);
	if (!NT_SUCCESS (status))
		goto err;

	LegacyHibernationDriverFilterActive = TRUE;
	CrashDumpEnabled = FALSE;
	HibernationEnabled = TRUE;
	return;

err:
	LegacyHibernationDriverFilterActive = FALSE;
	CrashDumpEnabled = FALSE;
	HibernationEnabled = FALSE;

	if (HibernationWriteBufferMdl)
	{
		IoFreeMdl (HibernationWriteBufferMdl);
		HibernationWriteBufferMdl = NULL;
	}

	if (HibernationWriteBuffer)
	{
		MmFreeContiguousMemory (HibernationWriteBuffer);
		HibernationWriteBuffer = NULL;
	}
}


static VOID SetupThreadProc (PVOID threadArg)
{
	DriveFilterExtension *Extension = BootDriveFilterExtension;

	LARGE_INTEGER offset;
	UINT64_STRUCT dataUnit;
	ULONG setupBlockSize = TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE;
	BOOL headerUpdateRequired = FALSE;
	int64 bytesWrittenSinceHeaderUpdate = 0;

	uint8 *buffer = NULL;
	uint8 *wipeBuffer = NULL;
	uint8 wipeRandChars[TC_WIPE_RAND_CHAR_COUNT];
	uint8 wipeRandCharsUpdate[TC_WIPE_RAND_CHAR_COUNT];
	
	KIRQL irql;
	NTSTATUS status;

	// generate real random values for wipeRandChars and 
	// wipeRandCharsUpdate instead of relying on uninitialized stack memory
	ChaCha20RngCtx rngCtx;
	uint8 pbSeed[CHACHA20RNG_KEYSZ + CHACHA20RNG_IVSZ];

	GetDriverRandomSeed (pbSeed, sizeof (pbSeed));
	ChaCha20RngInit (&rngCtx, pbSeed, GetDriverRandomSeed, 0);

	ChaCha20RngGetBytes (&rngCtx, wipeRandChars, TC_WIPE_RAND_CHAR_COUNT);
	ChaCha20RngGetBytes (&rngCtx, wipeRandCharsUpdate, TC_WIPE_RAND_CHAR_COUNT);

	burn (&rngCtx, sizeof (rngCtx));
	FAST_ERASE64 (pbSeed, sizeof (pbSeed));

	SetupResult = STATUS_UNSUCCESSFUL;

	// Make sure volume header can be updated
	if (Extension->HeaderCryptoInfo == NULL)
	{
		SetupResult = STATUS_INVALID_PARAMETER;
		goto ret;
	}

	buffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
	if (!buffer)
	{
		SetupResult = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	if (SetupRequest.SetupMode == SetupEncryption && SetupRequest.WipeAlgorithm != TC_WIPE_NONE)
	{
		wipeBuffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
		if (!wipeBuffer)
		{
			SetupResult = STATUS_INSUFFICIENT_RESOURCES;
			goto ret;
		}
	}

	while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 1000)))
	{
		if (EncryptionSetupThreadAbortRequested)
			goto abort;

		TransformWaitingForIdle = TRUE;
	}
	TransformWaitingForIdle = FALSE;

	switch (SetupRequest.SetupMode)
	{
	case SetupEncryption:
		Dump ("Encrypting...\n");
		if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1)
		{
			// Start encryption
			Extension->Queue.EncryptedAreaStart = Extension->ConfiguredEncryptedAreaStart;
			Extension->Queue.EncryptedAreaEnd = -1;
			offset.QuadPart = Extension->ConfiguredEncryptedAreaStart;
		}
		else
		{
			// Resume aborted encryption
			if (Extension->Queue.EncryptedAreaEnd == Extension->ConfiguredEncryptedAreaEnd)
				goto err;

			offset.QuadPart = Extension->Queue.EncryptedAreaEnd + 1;
		}

		break;

	case SetupDecryption:
		Dump ("Decrypting...\n");
		if (Extension->Queue.EncryptedAreaStart == -1 || Extension->Queue.EncryptedAreaEnd == -1)
		{
			SetupResult = STATUS_SUCCESS;
			goto abort;
		}

		offset.QuadPart = Extension->Queue.EncryptedAreaEnd + 1;
		break;

	default:
		goto err;
	}

	EncryptedIoQueueResumeFromHold (&Extension->Queue);
		
	Dump ("EncryptedAreaStart=%I64d\n", Extension->Queue.EncryptedAreaStart);
	Dump ("EncryptedAreaEnd=%I64d\n", Extension->Queue.EncryptedAreaEnd);
	Dump ("ConfiguredEncryptedAreaStart=%I64d\n", Extension->ConfiguredEncryptedAreaStart);
	Dump ("ConfiguredEncryptedAreaEnd=%I64d\n", Extension->ConfiguredEncryptedAreaEnd);
	Dump ("offset=%I64d\n", offset.QuadPart);
	Dump ("EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024);

	while (!EncryptionSetupThreadAbortRequested)
	{
		if (SetupRequest.SetupMode == SetupEncryption)
		{
			if (offset.QuadPart + setupBlockSize > Extension->ConfiguredEncryptedAreaEnd + 1)
				setupBlockSize = (ULONG) (Extension->ConfiguredEncryptedAreaEnd + 1 - offset.QuadPart);

			if (offset.QuadPart > Extension->ConfiguredEncryptedAreaEnd)
				break;
		}
		else
		{
			if (offset.QuadPart - setupBlockSize < Extension->Queue.EncryptedAreaStart)
				setupBlockSize = (ULONG) (offset.QuadPart - Extension->Queue.EncryptedAreaStart);

			offset.QuadPart -= setupBlockSize;

			if (setupBlockSize == 0 || offset.QuadPart < Extension->Queue.EncryptedAreaStart)
				break;
		}

		while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 500)))
		{
			if (EncryptionSetupThreadAbortRequested)
				goto abort;

			TransformWaitingForIdle = TRUE;
		}
		TransformWaitingForIdle = FALSE;

		status = TCReadDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("TCReadDevice error %x  offset=%I64d\n", status, offset.QuadPart);

			if (SetupRequest.ZeroUnreadableSectors && SetupRequest.SetupMode == SetupEncryption)
			{
				// Zero unreadable sectors
				uint64 zeroedSectorCount;

				status = ZeroUnreadableSectors (BootDriveFilterExtension->LowerDeviceObject, offset, setupBlockSize, &zeroedSectorCount);
				if (!NT_SUCCESS (status))
				{
					SetupResult = status;
					goto err;
				}

				// Retry read
				status = TCReadDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);
				if (!NT_SUCCESS (status))
				{
					SetupResult = status;
					goto err;
				}
			}
			else if (SetupRequest.DiscardUnreadableEncryptedSectors && SetupRequest.SetupMode == SetupDecryption)
			{
				// Discard unreadable encrypted sectors
				uint64 badSectorCount;

				status = ReadDeviceSkipUnreadableSectors (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize, &badSectorCount);
				if (!NT_SUCCESS (status))
				{
					SetupResult = status;
					goto err;
				}
			}
			else
			{
				SetupResult = status;
				goto err;
			}
		}

		dataUnit.Value = offset.QuadPart / ENCRYPTION_DATA_UNIT_SIZE;

		if (SetupRequest.SetupMode == SetupEncryption)
		{
			EncryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);

			if (SetupRequest.WipeAlgorithm != TC_WIPE_NONE)
			{
				uint8 wipePass;
				int wipePassCount = GetWipePassCount (SetupRequest.WipeAlgorithm);
				if (wipePassCount <= 0)
				{
					SetupResult = STATUS_INVALID_PARAMETER;
					goto err;
				}

				for (wipePass = 1; wipePass <= wipePassCount; ++wipePass)
				{
					if (!WipeBuffer (SetupRequest.WipeAlgorithm, wipeRandChars, wipePass, wipeBuffer, setupBlockSize))
					{
						ULONG i;
						for (i = 0; i < setupBlockSize; ++i)
						{
							wipeBuffer[i] = buffer[i] + wipePass;
						}

						EncryptDataUnits (wipeBuffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
						memcpy (wipeRandCharsUpdate, wipeBuffer, sizeof (wipeRandCharsUpdate)); 
					}

					status = TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, wipeBuffer, offset, setupBlockSize);
					if (!NT_SUCCESS (status))
					{
						// Undo failed write operation
						DecryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
						TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);

						SetupResult = status;
						goto err;
					}
				}

				memcpy (wipeRandChars, wipeRandCharsUpdate, sizeof (wipeRandCharsUpdate)); 
			}
		}
		else
		{
			DecryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
		}

		status = TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("TCWriteDevice error %x\n", status);

			// Undo failed write operation
			if (SetupRequest.SetupMode == SetupEncryption)
				DecryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);
			else
				EncryptDataUnits (buffer, &dataUnit, setupBlockSize / ENCRYPTION_DATA_UNIT_SIZE, Extension->Queue.CryptoInfo);

			TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, buffer, offset, setupBlockSize);

			SetupResult = status;
			goto err;
		}

		if (SetupRequest.SetupMode == SetupEncryption)
			offset.QuadPart += setupBlockSize;

		Extension->Queue.EncryptedAreaEndUpdatePending = TRUE;
		Extension->Queue.EncryptedAreaEnd = offset.QuadPart - 1;
		Extension->Queue.EncryptedAreaEndUpdatePending = FALSE;

		headerUpdateRequired = TRUE;

		EncryptedIoQueueResumeFromHold (&Extension->Queue);

		KeAcquireSpinLock (&SetupStatusSpinLock, &irql);
		SetupStatusEncryptedAreaEnd = Extension->Queue.EncryptedAreaEnd;
		KeReleaseSpinLock (&SetupStatusSpinLock, irql);

		// Update volume header
		bytesWrittenSinceHeaderUpdate += setupBlockSize;
		if (bytesWrittenSinceHeaderUpdate >= TC_ENCRYPTION_SETUP_HEADER_UPDATE_THRESHOLD)
		{
			status = SaveDriveVolumeHeader (Extension);
			ASSERT (NT_SUCCESS (status));
			if (NT_SUCCESS (status))
			{
				headerUpdateRequired = FALSE;
				bytesWrittenSinceHeaderUpdate = 0;
			}
		}
	}

abort:
	SetupResult = STATUS_SUCCESS;
err:

	if (Extension->Queue.EncryptedAreaEnd == -1)
		Extension->Queue.EncryptedAreaStart = -1;

	if (EncryptedIoQueueIsSuspended (&Extension->Queue))
		EncryptedIoQueueResumeFromHold (&Extension->Queue);

	if (SetupRequest.SetupMode == SetupDecryption && Extension->Queue.EncryptedAreaStart >= Extension->Queue.EncryptedAreaEnd)
	{
		while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 0)));

		Extension->ConfiguredEncryptedAreaStart = Extension->ConfiguredEncryptedAreaEnd = -1;
		Extension->Queue.EncryptedAreaStart = Extension->Queue.EncryptedAreaEnd = -1;

		EncryptedIoQueueResumeFromHold (&Extension->Queue);

		headerUpdateRequired = TRUE;
	}

	Dump ("Setup completed:  EncryptedAreaStart=%I64d (%I64d)  EncryptedAreaEnd=%I64d (%I64d)\n", Extension->Queue.EncryptedAreaStart / 1024 / 1024, Extension->Queue.EncryptedAreaStart, Extension->Queue.EncryptedAreaEnd / 1024 / 1024, Extension->Queue.EncryptedAreaEnd);

	if (headerUpdateRequired)
	{
		status = SaveDriveVolumeHeader (Extension);

		if (!NT_SUCCESS (status) && NT_SUCCESS (SetupResult))
			SetupResult = status;
	}

	if (SetupRequest.SetupMode == SetupDecryption && Extension->ConfiguredEncryptedAreaEnd == -1 && Extension->DriveMounted)
	{
		while (!RootDeviceControlMutexAcquireNoWait() && !EncryptionSetupThreadAbortRequested)
		{
			TCSleep (10);
		}

		// Disable hibernation (resume would fail due to a change in the system memory map)
		HibernationEnabled = FALSE;

		DismountDrive (Extension, FALSE);

		if (!EncryptionSetupThreadAbortRequested)
			RootDeviceControlMutexRelease();
	}

ret:
	if (buffer)
	{
		burn (buffer, TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
		TCfree (buffer);
	}
	if (wipeBuffer)
	{
		burn (wipeBuffer, TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
		TCfree (wipeBuffer);
	}

	burn (wipeRandChars, TC_WIPE_RAND_CHAR_COUNT);
	burn (wipeRandCharsUpdate, TC_WIPE_RAND_CHAR_COUNT);

	SetupInProgress = FALSE;
	PsTerminateSystemThread (SetupResult);
}


NTSTATUS StartBootEncryptionSetup (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	if (!UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (SetupInProgress || !BootDriveFound || !BootDriveFilterExtension
		|| !BootDriveFilterExtension->DriveMounted
		|| BootDriveFilterExtension->HiddenSystem
		|| irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof (BootEncryptionSetupRequest))
		return STATUS_INVALID_PARAMETER;

	if (EncryptionSetupThread)
		AbortBootEncryptionSetup();

	SetupRequest = *(BootEncryptionSetupRequest *) irp->AssociatedIrp.SystemBuffer;

	EncryptionSetupThreadAbortRequested = FALSE;
	KeInitializeSpinLock (&SetupStatusSpinLock);
	SetupStatusEncryptedAreaEnd = BootDriveFilterExtension ? BootDriveFilterExtension->Queue.EncryptedAreaEnd : -1;

	SetupInProgress = TRUE;
	status = TCStartThread (SetupThreadProc, DeviceObject, &EncryptionSetupThread);
	
	if (!NT_SUCCESS (status))
		SetupInProgress = FALSE;

	return status;
}


void GetBootDriveVolumeProperties (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (ValidateIOBufferSize (irp, sizeof (VOLUME_PROPERTIES_STRUCT), ValidateOutput))
	{
		DriveFilterExtension *Extension = BootDriveFilterExtension;
		VOLUME_PROPERTIES_STRUCT *prop = (VOLUME_PROPERTIES_STRUCT *) irp->AssociatedIrp.SystemBuffer;
		memset (prop, 0, sizeof (*prop));

		if (!BootDriveFound || !Extension || !Extension->DriveMounted)
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
		else
		{
			prop->hiddenVolume = Extension->Queue.CryptoInfo->hiddenVolume;
			prop->diskLength = Extension->ConfiguredEncryptedAreaEnd + 1 - Extension->ConfiguredEncryptedAreaStart;
			prop->ea = Extension->Queue.CryptoInfo->ea;
			prop->mode = Extension->Queue.CryptoInfo->mode;
			prop->pkcs5 = Extension->Queue.CryptoInfo->pkcs5;
			prop->pkcs5Iterations = Extension->Queue.CryptoInfo->noIterations;
			prop->volumePim = Extension->Queue.CryptoInfo->volumePim;
#if 0
			prop->volumeCreationTime = Extension->Queue.CryptoInfo->volume_creation_time;
			prop->headerCreationTime = Extension->Queue.CryptoInfo->header_creation_time;
#endif
			prop->volFormatVersion = Extension->Queue.CryptoInfo->LegacyVolume ? TC_VOLUME_FORMAT_VERSION_PRE_6_0 : TC_VOLUME_FORMAT_VERSION;

			prop->totalBytesRead = Extension->Queue.TotalBytesRead;
			prop->totalBytesWritten = Extension->Queue.TotalBytesWritten;

			irp->IoStatus.Information = sizeof (VOLUME_PROPERTIES_STRUCT);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
	}
}


void GetBootEncryptionStatus (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	/* IMPORTANT: Do NOT add any potentially time-consuming operations to this function. */

	if (ValidateIOBufferSize (irp, sizeof (BootEncryptionStatus), ValidateOutput))
	{
		DriveFilterExtension *Extension = BootDriveFilterExtension;
		BootEncryptionStatus *bootEncStatus = (BootEncryptionStatus *) irp->AssociatedIrp.SystemBuffer;
		memset (bootEncStatus, 0, sizeof (*bootEncStatus));

		if (BootArgsValid)
			bootEncStatus->BootLoaderVersion = BootArgs.BootLoaderVersion;

		bootEncStatus->DeviceFilterActive = DeviceFilterActive;
		bootEncStatus->SetupInProgress = SetupInProgress;
		bootEncStatus->SetupMode = SetupRequest.SetupMode;
		bootEncStatus->TransformWaitingForIdle = TransformWaitingForIdle;

		if (!BootDriveFound || !Extension || !Extension->DriveMounted)
		{
			bootEncStatus->DriveEncrypted = FALSE;
			bootEncStatus->DriveMounted = FALSE;
			bootEncStatus->VolumeHeaderPresent = FALSE;
		}
		else
		{
			bootEncStatus->DriveMounted = Extension->DriveMounted;
			bootEncStatus->VolumeHeaderPresent = Extension->VolumeHeaderPresent;
			bootEncStatus->DriveEncrypted = Extension->Queue.EncryptedAreaStart != -1;
			bootEncStatus->BootDriveLength = BootDriveLength;

			bootEncStatus->ConfiguredEncryptedAreaStart = Extension->ConfiguredEncryptedAreaStart;
			bootEncStatus->ConfiguredEncryptedAreaEnd = Extension->ConfiguredEncryptedAreaEnd;
			bootEncStatus->EncryptedAreaStart = Extension->Queue.EncryptedAreaStart;
			bootEncStatus->MasterKeyVulnerable = Extension->HeaderCryptoInfo->bVulnerableMasterKey;

			if (SetupInProgress)
			{
				KIRQL irql;
				KeAcquireSpinLock (&SetupStatusSpinLock, &irql);
				bootEncStatus->EncryptedAreaEnd = SetupStatusEncryptedAreaEnd;
				KeReleaseSpinLock (&SetupStatusSpinLock, irql);
			}
			else
				bootEncStatus->EncryptedAreaEnd = Extension->Queue.EncryptedAreaEnd;

			bootEncStatus->VolumeHeaderSaltCrc32 = Extension->VolumeHeaderSaltCrc32;
			bootEncStatus->HibernationPreventionCount = HibernationPreventionCount;
			bootEncStatus->HiddenSysLeakProtectionCount = HiddenSysLeakProtectionCount;

			bootEncStatus->HiddenSystem = Extension->HiddenSystem;
			
			if (Extension->HiddenSystem)
				bootEncStatus->HiddenSystemPartitionStart = BootArgs.HiddenSystemPartitionStart;
		}

		irp->IoStatus.Information = sizeof (BootEncryptionStatus);
		irp->IoStatus.Status = STATUS_SUCCESS;
	}
}


void GetBootLoaderVersion (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (ValidateIOBufferSize (irp, sizeof (uint16), ValidateOutput))
	{
		if (BootArgsValid)
		{
			*(uint16 *) irp->AssociatedIrp.SystemBuffer = BootArgs.BootLoaderVersion;
			irp->IoStatus.Information = sizeof (uint16);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
	}
}

void GetBootLoaderFingerprint (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (ValidateIOBufferSize (irp, sizeof (BootLoaderFingerprintRequest), ValidateOutput))
	{
		irp->IoStatus.Information = 0;
		if (BootArgsValid && BootDriveFound && BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted && BootDriveFilterExtension->HeaderCryptoInfo)
		{
			BootLoaderFingerprintRequest *bootLoaderFingerprint = (BootLoaderFingerprintRequest *) irp->AssociatedIrp.SystemBuffer;			

			/* compute the fingerprint again and check if it is the same as the one retrieved during boot */
			char *header = TCalloc (TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			if (!header)
			{
				irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			}
			else
			{
				memcpy (bootLoaderFingerprint->Fingerprint, BootLoaderFingerprint, sizeof (BootLoaderFingerprint));
				ComputeBootLoaderFingerprint (BootDriveFilterExtension->LowerDeviceObject, header);

				burn (header, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
				TCfree (header);

				if (0 == memcmp (bootLoaderFingerprint->Fingerprint, BootLoaderFingerprint, sizeof (BootLoaderFingerprint)))
				{
					irp->IoStatus.Information = sizeof (BootLoaderFingerprintRequest);
					irp->IoStatus.Status = STATUS_SUCCESS;
				}
				else
				{
					/* fingerprint mismatch.*/
					irp->IoStatus.Status = STATUS_INVALID_IMAGE_HASH;
				}
			}
		}
		else
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;			
		}
	}
}

void GetBootEncryptionAlgorithmName (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (ValidateIOBufferSize (irp, sizeof (GetBootEncryptionAlgorithmNameRequest), ValidateOutput))
	{
		if (BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted)
		{
			wchar_t BootEncryptionAlgorithmNameW[256];
			wchar_t BootPrfAlgorithmNameW[256];
			GetBootEncryptionAlgorithmNameRequest *request = (GetBootEncryptionAlgorithmNameRequest *) irp->AssociatedIrp.SystemBuffer;
			EAGetName (BootEncryptionAlgorithmNameW, 256, BootDriveFilterExtension->Queue.CryptoInfo->ea, 0);
			HashGetName2 (BootPrfAlgorithmNameW, 256, BootDriveFilterExtension->Queue.CryptoInfo->pkcs5);

			RtlStringCbPrintfA (request->BootEncryptionAlgorithmName, sizeof (request->BootEncryptionAlgorithmName), "%S", BootEncryptionAlgorithmNameW);
			RtlStringCbPrintfA (request->BootPrfAlgorithmName, sizeof (request->BootPrfAlgorithmName), "%S", BootPrfAlgorithmNameW);

			irp->IoStatus.Information = sizeof (GetBootEncryptionAlgorithmNameRequest);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
	}
}


NTSTATUS GetSetupResult()
{
	return SetupResult;
}


BOOL IsBootDriveMounted ()
{
	return BootDriveFilterExtension && BootDriveFilterExtension->DriveMounted;
}


BOOL IsBootEncryptionSetupInProgress ()
{
	return SetupInProgress;
}


BOOL IsHiddenSystemRunning ()
{
	return BootDriveFilterExtension && BootDriveFilterExtension->HiddenSystem;
}


DriveFilterExtension *GetBootDriveFilterExtension ()
{
	return BootDriveFilterExtension;
}


CRYPTO_INFO *GetSystemDriveCryptoInfo ()
{
	return BootDriveFilterExtension->Queue.CryptoInfo;
}


NTSTATUS AbortBootEncryptionSetup ()
{
	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (EncryptionSetupThread)
	{
		EncryptionSetupThreadAbortRequested = TRUE;

		TCStopThread (EncryptionSetupThread, NULL);
		EncryptionSetupThread = NULL;
	}

	return STATUS_SUCCESS;
}


static VOID DecoySystemWipeThreadProc (PVOID threadArg)
{
	DriveFilterExtension *Extension = BootDriveFilterExtension;

	LARGE_INTEGER offset;
	UINT64_STRUCT dataUnit;
	ULONG wipeBlockSize = TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE;

	CRYPTO_INFO *wipeCryptoInfo = NULL;
	uint8 *wipeBuffer = NULL;
	uint8 *wipeRandBuffer = NULL;
	uint8 wipeRandChars[TC_WIPE_RAND_CHAR_COUNT];
	int wipePass, wipePassCount;
	int ea = Extension->Queue.CryptoInfo->ea;

	KIRQL irql;
	NTSTATUS status;

	DecoySystemWipeResult = STATUS_UNSUCCESSFUL;

	wipeBuffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
	if (!wipeBuffer)
	{
		DecoySystemWipeResult = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}
	
	wipeRandBuffer = TCalloc (TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE);
	if (!wipeRandBuffer)
	{
		DecoySystemWipeResult = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	wipeCryptoInfo = crypto_open();
	if (!wipeCryptoInfo)
	{
		DecoySystemWipeResult = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	wipeCryptoInfo->ea = ea;
	wipeCryptoInfo->mode = Extension->Queue.CryptoInfo->mode;

	if (EAInit (ea, WipeDecoyRequest.WipeKey, wipeCryptoInfo->ks) != ERR_SUCCESS)
	{
		DecoySystemWipeResult = STATUS_INVALID_PARAMETER;
		goto ret;
	}
	
	if (!EAInitMode (wipeCryptoInfo, WipeDecoyRequest.WipeKey + EAGetKeySize (ea)))
	{
		DecoySystemWipeResult = STATUS_INVALID_PARAMETER;
		goto err;
	}

#ifdef _WIN64
	if (IsRamEncryptionEnabled ())
		VcProtectKeys (wipeCryptoInfo, VcGetEncryptionID (wipeCryptoInfo));
#endif

	EncryptDataUnits (wipeRandBuffer, &dataUnit, wipeBlockSize / ENCRYPTION_DATA_UNIT_SIZE, wipeCryptoInfo);
	memcpy (wipeRandChars, wipeRandBuffer, sizeof (wipeRandChars));

	burn (WipeDecoyRequest.WipeKey, sizeof (WipeDecoyRequest.WipeKey));

	offset.QuadPart = Extension->ConfiguredEncryptedAreaStart;
		
	Dump ("Wiping decoy system:  start offset = %I64d\n", offset.QuadPart);

	while (!DecoySystemWipeThreadAbortRequested)
	{
		if (offset.QuadPart + wipeBlockSize > Extension->ConfiguredEncryptedAreaEnd + 1)
			wipeBlockSize = (ULONG) (Extension->ConfiguredEncryptedAreaEnd + 1 - offset.QuadPart);

		if (offset.QuadPart > Extension->ConfiguredEncryptedAreaEnd)
			break;

		wipePassCount = GetWipePassCount (WipeDecoyRequest.WipeAlgorithm);
		if (wipePassCount <= 0)
		{
			DecoySystemWipeResult = STATUS_INVALID_PARAMETER;
			goto err;
		}

		for (wipePass = 1; wipePass <= wipePassCount; ++wipePass)
		{
			if (!WipeBuffer (WipeDecoyRequest.WipeAlgorithm, wipeRandChars, wipePass, wipeBuffer, wipeBlockSize))
			{
				dataUnit.Value = offset.QuadPart / ENCRYPTION_DATA_UNIT_SIZE;
				EncryptDataUnits (wipeRandBuffer, &dataUnit, wipeBlockSize / ENCRYPTION_DATA_UNIT_SIZE, wipeCryptoInfo);
				memcpy (wipeBuffer, wipeRandBuffer, wipeBlockSize);
			}

			while (!NT_SUCCESS (EncryptedIoQueueHoldWhenIdle (&Extension->Queue, 500)))
			{
				if (DecoySystemWipeThreadAbortRequested)
					goto abort;
			}

			status = TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, wipeBuffer, offset, wipeBlockSize);

			if (!NT_SUCCESS (status))
			{
				DecoySystemWipeResult = status;
				goto err;
			}

			EncryptedIoQueueResumeFromHold (&Extension->Queue);
		}

		offset.QuadPart += wipeBlockSize;

		KeAcquireSpinLock (&DecoySystemWipeStatusSpinLock, &irql);
		DecoySystemWipedAreaEnd = offset.QuadPart - 1;
		KeReleaseSpinLock (&DecoySystemWipeStatusSpinLock, irql);
	}

abort:
	DecoySystemWipeResult = STATUS_SUCCESS;
err:

	if (EncryptedIoQueueIsSuspended (&Extension->Queue))
		EncryptedIoQueueResumeFromHold (&Extension->Queue);

	Dump ("Wipe end: DecoySystemWipedAreaEnd=%I64d (%I64d)\n", DecoySystemWipedAreaEnd, DecoySystemWipedAreaEnd / 1024 / 1024);

ret:
	if (wipeCryptoInfo)
		crypto_close (wipeCryptoInfo);

	if (wipeRandBuffer)
		TCfree (wipeRandBuffer);

	if (wipeBuffer)
		TCfree (wipeBuffer);

	DecoySystemWipeInProgress = FALSE;
	PsTerminateSystemThread (DecoySystemWipeResult);
}


NTSTATUS StartDecoySystemWipe (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	WipeDecoySystemRequest *request;

	if (!UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (!IsHiddenSystemRunning()
		|| irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof (WipeDecoySystemRequest))
		return STATUS_INVALID_PARAMETER;

	if (DecoySystemWipeInProgress)
		return STATUS_SUCCESS;

	if (DecoySystemWipeThread)
		AbortDecoySystemWipe();

	request = (WipeDecoySystemRequest *) irp->AssociatedIrp.SystemBuffer;
	WipeDecoyRequest = *request;

	burn (request->WipeKey, sizeof (request->WipeKey));

	DecoySystemWipeThreadAbortRequested = FALSE;
	KeInitializeSpinLock (&DecoySystemWipeStatusSpinLock);
	DecoySystemWipedAreaEnd = BootDriveFilterExtension->ConfiguredEncryptedAreaStart;

	DecoySystemWipeInProgress = TRUE;
	status = TCStartThread (DecoySystemWipeThreadProc, DeviceObject, &DecoySystemWipeThread);
	
	if (!NT_SUCCESS (status))
		DecoySystemWipeInProgress = FALSE;

	return status;
}


BOOL IsDecoySystemWipeInProgress()
{
	return DecoySystemWipeInProgress;
}


void GetDecoySystemWipeStatus (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	if (ValidateIOBufferSize (irp, sizeof (DecoySystemWipeStatus), ValidateOutput))
	{
		DecoySystemWipeStatus *wipeStatus = (DecoySystemWipeStatus *) irp->AssociatedIrp.SystemBuffer;

		if (!IsHiddenSystemRunning())
		{
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			irp->IoStatus.Information = 0;
		}
		else
		{
			wipeStatus->WipeInProgress = DecoySystemWipeInProgress;
			wipeStatus->WipeAlgorithm = WipeDecoyRequest.WipeAlgorithm;

			if (DecoySystemWipeInProgress)
			{
				KIRQL irql;
				KeAcquireSpinLock (&DecoySystemWipeStatusSpinLock, &irql);
				wipeStatus->WipedAreaEnd = DecoySystemWipedAreaEnd;
				KeReleaseSpinLock (&DecoySystemWipeStatusSpinLock, irql);
			}
			else
				wipeStatus->WipedAreaEnd = DecoySystemWipedAreaEnd;
			
			irp->IoStatus.Information = sizeof (DecoySystemWipeStatus);
			irp->IoStatus.Status = STATUS_SUCCESS;
		}
	}
}


NTSTATUS GetDecoySystemWipeResult()
{
	return DecoySystemWipeResult;
}


NTSTATUS AbortDecoySystemWipe ()
{
	if (!IoIsSystemThread (PsGetCurrentThread()) && !UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (DecoySystemWipeThread)
	{
		DecoySystemWipeThreadAbortRequested = TRUE;

		TCStopThread (DecoySystemWipeThread, NULL);
		DecoySystemWipeThread = NULL;
	}

	return STATUS_SUCCESS;
}


uint64 GetBootDriveLength ()
{
	return BootDriveLength.QuadPart;
}


NTSTATUS WriteBootDriveSector (PIRP irp, PIO_STACK_LOCATION irpSp)
{
	WriteBootDriveSectorRequest *request;

	if (!UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	if (!BootDriveFilterExtension
		|| irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof (WriteBootDriveSectorRequest))
		return STATUS_INVALID_PARAMETER;

	request = (WriteBootDriveSectorRequest *) irp->AssociatedIrp.SystemBuffer;
	return TCWriteDevice (BootDriveFilterExtension->LowerDeviceObject, request->Data, request->Offset, sizeof (request->Data));
}
