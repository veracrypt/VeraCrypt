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

#include "TCdefs.h"
#include <wchar.h>
#include "Crypto.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "DriveFilter.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "VolumeFilter.h"

#include "Boot/Windows/BootCommon.h"

#include "Cache.h"

#if 0 && _DEBUG
#define EXTRA_INFO 1
#endif

#pragma warning( disable : 4127 )

#include <Ntstrsafe.h>

volatile BOOL ProbingHostDeviceForWrite = FALSE;


NTSTATUS TCOpenVolume (PDEVICE_OBJECT DeviceObject,
	       PEXTENSION Extension,
	       MOUNT_STRUCT *mount,
	       PWSTR pwszMountVolume,
	       BOOL bRawDevice)
{
	FILE_STANDARD_INFORMATION FileStandardInfo = { 0 };
	FILE_BASIC_INFORMATION FileBasicInfo;
	OBJECT_ATTRIBUTES oaFileAttributes;
	UNICODE_STRING FullFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	PCRYPTO_INFO cryptoInfoPtr = NULL;
	PCRYPTO_INFO tmpCryptoInfo = NULL;
	LARGE_INTEGER lDiskLength = { 0 };
	__int64 partitionStartingOffset = 0;
	int volumeType;
	char *readBuffer = 0;
	NTSTATUS ntStatus = 0;
	BOOL forceAccessCheck = !bRawDevice;
	BOOL disableBuffering = TRUE;
	BOOL exclusiveAccess = mount->bExclusiveAccess;
	/* when mounting with hidden volume protection, we cache the passwords after both outer and hidden volumes are mounted successfully*/
	BOOL bAutoCachePassword = mount->bProtectHiddenVolume? FALSE : mount->bCache;

	Extension->pfoDeviceFile = NULL;
	Extension->hDeviceFile = NULL;
	Extension->bTimeStampValid = FALSE;

	/* default value for storage alignment */
	Extension->HostMaximumTransferLength = 65536;
	Extension->HostMaximumPhysicalPages = 17;
	Extension->HostAlignmentMask = 0;

	/* default values for non-SSD drives */
	Extension->IncursSeekPenalty = TRUE;
	Extension->TrimEnabled = FALSE;

	Extension->DeviceNumber = (ULONG) -1;

	RtlInitUnicodeString (&FullFileName, pwszMountVolume);
	InitializeObjectAttributes (&oaFileAttributes, &FullFileName, OBJ_CASE_INSENSITIVE | (forceAccessCheck ? OBJ_FORCE_ACCESS_CHECK : 0) | OBJ_KERNEL_HANDLE, NULL, NULL);
	KeInitializeEvent (&Extension->keVolumeEvent, NotificationEvent, FALSE);

	if (Extension->SecurityClientContextValid)
	{
		ntStatus = SeImpersonateClientEx (&Extension->SecurityClientContext, NULL);
		if (!NT_SUCCESS (ntStatus))
			goto error;
	}

	mount->VolumeMountedReadOnlyAfterDeviceWriteProtected = FALSE;
	mount->VolumeMountedReadOnlyAfterPartialSysEnc = FALSE;
	mount->VolumeMasterKeyVulnerable = FALSE;

	// If we are opening a device, query its size first
	if (bRawDevice)
	{
		PARTITION_INFORMATION pi;
		PARTITION_INFORMATION_EX pix;
		LARGE_INTEGER diskLengthInfo;
		DISK_GEOMETRY_EX dg;
		STORAGE_PROPERTY_QUERY storagePropertyQuery = {0};
		uint8* dgBuffer;
		STORAGE_DEVICE_NUMBER storageDeviceNumber;

		ntStatus = IoGetDeviceObjectPointer (&FullFileName,
			FILE_READ_DATA | FILE_READ_ATTRIBUTES,
			&Extension->pfoDeviceFile,
			&Extension->pFsdDevice);

		if (!NT_SUCCESS (ntStatus))
			goto error;

		dgBuffer = TCalloc (256);
		if (!dgBuffer)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto error;
		}

		ntStatus = TCSendHostDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, (char *) dgBuffer, 256);
		if (!NT_SUCCESS (ntStatus))
		{
			DISK_GEOMETRY geo;
			ntStatus = TCSendHostDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_DRIVE_GEOMETRY, (char *) &geo, sizeof (geo));
			if (!NT_SUCCESS (ntStatus))
			{
				TCfree (dgBuffer);
				goto error;
			}
			memset (&dg, 0, sizeof (dg));
			memcpy (&dg.Geometry, &geo, sizeof (geo));
			dg.DiskSize.QuadPart = geo.Cylinders.QuadPart * geo.SectorsPerTrack * geo.TracksPerCylinder * geo.BytesPerSector;

			if (OsMajorVersion >= 6)
			{
				STORAGE_READ_CAPACITY storage = {0};
				NTSTATUS lStatus;

				storage.Version = sizeof (STORAGE_READ_CAPACITY);
				storage.Size = sizeof (STORAGE_READ_CAPACITY);
				lStatus = TCSendHostDeviceIoControlRequest (DeviceObject, Extension,
					IOCTL_STORAGE_READ_CAPACITY,
					(char*)  &storage, sizeof (STORAGE_READ_CAPACITY));
				if (	NT_SUCCESS(lStatus)
					&& (storage.Size == sizeof (STORAGE_READ_CAPACITY))
					)
				{
					dg.DiskSize.QuadPart = storage.DiskLength.QuadPart;
				}
			}
		}
		else
			memcpy (&dg, dgBuffer, sizeof (DISK_GEOMETRY_EX));

		TCfree (dgBuffer);

		if (NT_SUCCESS (TCSendHostDeviceIoControlRequest (DeviceObject, Extension,
					IOCTL_STORAGE_GET_DEVICE_NUMBER,
					(char*) &storageDeviceNumber, sizeof (storageDeviceNumber))))
		{
			Extension->DeviceNumber = storageDeviceNumber.DeviceNumber;
		}

		lDiskLength.QuadPart = dg.DiskSize.QuadPart;
		Extension->HostBytesPerSector = dg.Geometry.BytesPerSector;
		Extension->HostBytesPerPhysicalSector = dg.Geometry.BytesPerSector;

		/* IOCTL_STORAGE_QUERY_PROPERTY supported only on Vista and above */
		if (OsMajorVersion >= 6)
		{
			STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignmentDesc = {0};
			STORAGE_ADAPTER_DESCRIPTOR adapterDesc = {0};
			DEVICE_SEEK_PENALTY_DESCRIPTOR penaltyDesc = {0};
			DEVICE_TRIM_DESCRIPTOR trimDesc = {0};

			storagePropertyQuery.PropertyId = StorageAccessAlignmentProperty;
			storagePropertyQuery.QueryType = PropertyStandardQuery;

			alignmentDesc.Version = sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
			alignmentDesc.Size = sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);

			if (NT_SUCCESS (TCSendHostDeviceIoControlRequestEx (DeviceObject, Extension, IOCTL_STORAGE_QUERY_PROPERTY,
				(char*) &storagePropertyQuery, sizeof(storagePropertyQuery),
				(char *) &alignmentDesc, sizeof (alignmentDesc))))
			{
				Extension->HostBytesPerPhysicalSector = alignmentDesc.BytesPerPhysicalSector;
			}

			storagePropertyQuery.PropertyId = StorageAdapterProperty;
			adapterDesc.Version = sizeof (STORAGE_ADAPTER_DESCRIPTOR);
			adapterDesc.Size = sizeof (STORAGE_ADAPTER_DESCRIPTOR);

			if (NT_SUCCESS (TCSendHostDeviceIoControlRequestEx (DeviceObject, Extension, IOCTL_STORAGE_QUERY_PROPERTY,
				(char*) &storagePropertyQuery, sizeof(storagePropertyQuery),
				(char *) &adapterDesc, sizeof (adapterDesc))))
			{
				Extension->HostMaximumTransferLength = adapterDesc.MaximumTransferLength;
				Extension->HostMaximumPhysicalPages = adapterDesc.MaximumPhysicalPages;
				Extension->HostAlignmentMask = adapterDesc.AlignmentMask;
			}

			storagePropertyQuery.PropertyId = StorageDeviceSeekPenaltyProperty;
			penaltyDesc.Version = sizeof (DEVICE_SEEK_PENALTY_DESCRIPTOR);
			penaltyDesc.Size = sizeof (DEVICE_SEEK_PENALTY_DESCRIPTOR);

			if (NT_SUCCESS (TCSendHostDeviceIoControlRequestEx (DeviceObject, Extension, IOCTL_STORAGE_QUERY_PROPERTY,
				(char*) &storagePropertyQuery, sizeof(storagePropertyQuery),
				(char *) &penaltyDesc, sizeof (penaltyDesc))))
			{
				Extension->IncursSeekPenalty = penaltyDesc.IncursSeekPenalty;
			}

			storagePropertyQuery.PropertyId = StorageDeviceTrimProperty;
			trimDesc.Version = sizeof (DEVICE_TRIM_DESCRIPTOR);
			trimDesc.Size = sizeof (DEVICE_TRIM_DESCRIPTOR);

			if (NT_SUCCESS (TCSendHostDeviceIoControlRequestEx (DeviceObject, Extension, IOCTL_STORAGE_QUERY_PROPERTY,
				(char*) &storagePropertyQuery, sizeof(storagePropertyQuery),
				(char *) &trimDesc, sizeof (trimDesc))))
			{
				Extension->TrimEnabled = trimDesc.TrimEnabled;
			}
		}

		// Drive geometry is used only when IOCTL_DISK_GET_PARTITION_INFO fails
		if (NT_SUCCESS (TCSendHostDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_PARTITION_INFO_EX, (char *) &pix, sizeof (pix))))
		{
			lDiskLength.QuadPart = pix.PartitionLength.QuadPart;
			partitionStartingOffset = pix.StartingOffset.QuadPart;
		}
		// If IOCTL_DISK_GET_PARTITION_INFO_EX fails, switch to IOCTL_DISK_GET_PARTITION_INFO
		else if (NT_SUCCESS (TCSendHostDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_PARTITION_INFO, (char *) &pi, sizeof (pi))))
		{
			lDiskLength.QuadPart = pi.PartitionLength.QuadPart;
			partitionStartingOffset = pi.StartingOffset.QuadPart;
		}
		else if (NT_SUCCESS (TCSendHostDeviceIoControlRequest (DeviceObject, Extension, IOCTL_DISK_GET_LENGTH_INFO, &diskLengthInfo, sizeof (diskLengthInfo))))
		{
			lDiskLength = diskLengthInfo;
		}

		ProbingHostDeviceForWrite = TRUE;

		if (!mount->bMountReadOnly
			&& TCSendHostDeviceIoControlRequest (DeviceObject, Extension,
				IsHiddenSystemRunning() ? TC_IOCTL_DISK_IS_WRITABLE : IOCTL_DISK_IS_WRITABLE, NULL, 0) == STATUS_MEDIA_WRITE_PROTECTED)
		{
			mount->bMountReadOnly = TRUE;
			DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
			mount->VolumeMountedReadOnlyAfterDeviceWriteProtected = TRUE;
		}

		ProbingHostDeviceForWrite = FALSE;

		// Some Windows tools (e.g. diskmgmt, diskpart, vssadmin) fail or experience timeouts when there is a raw device
		// open for exclusive access. Therefore, exclusive access is used only for file-hosted volumes.
		// Applications requiring a consistent device image need to acquire exclusive write access first. This is prevented
		// when a device-hosted volume is mounted.

		exclusiveAccess = FALSE;
	}
	else
	{
		// Limit the maximum required buffer size
		if (mount->BytesPerSector > 128 * BYTES_PER_KB)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto error;
		}

		Extension->HostBytesPerSector = mount->BytesPerSector;
		Extension->HostBytesPerPhysicalSector = mount->BytesPerPhysicalSector;
		Extension->HostMaximumTransferLength = mount->MaximumTransferLength;
		Extension->HostMaximumPhysicalPages = mount->MaximumPhysicalPages;
		Extension->HostAlignmentMask = mount->AlignmentMask;

		if (Extension->HostBytesPerSector != TC_SECTOR_SIZE_FILE_HOSTED_VOLUME)
			disableBuffering = FALSE;
	}

	// Open the volume hosting file/device
	if (!mount->bMountReadOnly)
	{
		ntStatus = ZwCreateFile (&Extension->hDeviceFile,
			GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
			&oaFileAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL |
			FILE_ATTRIBUTE_SYSTEM,
			exclusiveAccess ? 0 : FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_RANDOM_ACCESS |
			FILE_WRITE_THROUGH |
			(disableBuffering ? FILE_NO_INTERMEDIATE_BUFFERING : 0) |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
	}

	/* 26-4-99 NT for some partitions returns this code, it is really a	access denied */
	if (ntStatus == 0xc000001b)
		ntStatus = STATUS_ACCESS_DENIED;

	mount->VolumeMountedReadOnlyAfterAccessDenied = FALSE;

	if (mount->bMountReadOnly || ntStatus == STATUS_ACCESS_DENIED)
	{
		ntStatus = ZwCreateFile (&Extension->hDeviceFile,
			GENERIC_READ | (!bRawDevice && mount->bPreserveTimestamp? FILE_WRITE_ATTRIBUTES : 0) | SYNCHRONIZE,
			&oaFileAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL |
			FILE_ATTRIBUTE_SYSTEM,
			exclusiveAccess ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_RANDOM_ACCESS |
			FILE_WRITE_THROUGH |
			(disableBuffering ? FILE_NO_INTERMEDIATE_BUFFERING : 0) |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (!NT_SUCCESS (ntStatus) && !bRawDevice && mount->bPreserveTimestamp)
		{
			/* try again without FILE_WRITE_ATTRIBUTES */
			ntStatus = ZwCreateFile (&Extension->hDeviceFile,
				GENERIC_READ | SYNCHRONIZE,
				&oaFileAttributes,
				&IoStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL |
				FILE_ATTRIBUTE_SYSTEM,
				exclusiveAccess ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN,
				FILE_RANDOM_ACCESS |
				FILE_WRITE_THROUGH |
				(disableBuffering ? FILE_NO_INTERMEDIATE_BUFFERING : 0) |
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);
		}

		if (NT_SUCCESS (ntStatus) && !mount->bMountReadOnly)
			mount->VolumeMountedReadOnlyAfterAccessDenied = TRUE;

		Extension->bReadOnly = TRUE;
		DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
	}
	else
		Extension->bReadOnly = FALSE;

	/* 26-4-99 NT for some partitions returns this code, it is really a
	access denied */
	if (ntStatus == 0xc000001b)
	{
		/* Partitions which return this code can still be opened with
		FILE_SHARE_READ but this causes NT problems elsewhere in
		particular if you do FILE_SHARE_READ NT will die later if
		anyone even tries to open the partition (or file for that
		matter...)  */
		ntStatus = STATUS_SHARING_VIOLATION;
	}

	if (!NT_SUCCESS (ntStatus))
	{
		goto error;
	}

	// If we have opened a file, query its size now
	if (bRawDevice == FALSE)
	{
		ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
			&IoStatusBlock,
			&FileBasicInfo,
			sizeof (FileBasicInfo),
			FileBasicInformation);

		if (NT_SUCCESS (ntStatus))
		{
			if (mount->bPreserveTimestamp)
			{
				Extension->fileCreationTime = FileBasicInfo.CreationTime;
				Extension->fileLastAccessTime = FileBasicInfo.LastAccessTime;
				Extension->fileLastWriteTime = FileBasicInfo.LastWriteTime;
				Extension->fileLastChangeTime = FileBasicInfo.ChangeTime;
				Extension->bTimeStampValid = TRUE;

				// we tell the system not to update LastAccessTime, LastWriteTime, and ChangeTime
				FileBasicInfo.CreationTime.QuadPart = 0;
				FileBasicInfo.LastAccessTime.QuadPart = -1;
				FileBasicInfo.LastWriteTime.QuadPart = -1;
				FileBasicInfo.ChangeTime.QuadPart = -1;

				ZwSetInformationFile (Extension->hDeviceFile,
					&IoStatusBlock,
					&FileBasicInfo,
					sizeof (FileBasicInfo),
					FileBasicInformation);
			}

			ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
				&IoStatusBlock,
				&FileStandardInfo,
				sizeof (FileStandardInfo),
				FileStandardInformation);
		}

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ZwQueryInformationFile failed while opening file: NTSTATUS 0x%08x\n",
				ntStatus);
			goto error;
		}

		lDiskLength.QuadPart = FileStandardInfo.EndOfFile.QuadPart;

		if (FileBasicInfo.FileAttributes & FILE_ATTRIBUTE_COMPRESSED)
		{
			Dump ("File \"%ls\" is marked as compressed - not supported!\n", pwszMountVolume);
			mount->nReturnCode = ERR_COMPRESSION_NOT_SUPPORTED;
			ntStatus = STATUS_SUCCESS;
			goto error;
		}

		ntStatus = ObReferenceObjectByHandle (Extension->hDeviceFile,
			FILE_ALL_ACCESS,
			*IoFileObjectType,
			KernelMode,
			&Extension->pfoDeviceFile,
			0);

		if (!NT_SUCCESS (ntStatus))
		{
			goto error;
		}

		/* Get the FSD device for the file (probably either NTFS or	FAT) */
		Extension->pFsdDevice = IoGetRelatedDeviceObject (Extension->pfoDeviceFile);
	}
	else
	{
		// Try to gain "raw" access to the partition in case there is a live filesystem on it (otherwise,
		// the NTFS driver guards hidden sectors and prevents mounting using a backup header e.g. after the user
		// accidentally quick-formats a dismounted partition-hosted TrueCrypt volume as NTFS).

		PFILE_OBJECT pfoTmpDeviceFile = NULL;

		if (NT_SUCCESS (ObReferenceObjectByHandle (Extension->hDeviceFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, &pfoTmpDeviceFile, NULL))
			&& pfoTmpDeviceFile != NULL)
		{
			TCFsctlCall (pfoTmpDeviceFile, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0);
			ObDereferenceObject (pfoTmpDeviceFile);
		}
	}

	// Check volume size
	if (lDiskLength.QuadPart < TC_MIN_VOLUME_SIZE_LEGACY || lDiskLength.QuadPart > TC_MAX_VOLUME_SIZE)
	{
		mount->nReturnCode = ERR_VOL_SIZE_WRONG;
		ntStatus = STATUS_SUCCESS;
		goto error;
	}

	Extension->DiskLength = lDiskLength.QuadPart;
	Extension->HostLength = lDiskLength.QuadPart;

	readBuffer = TCalloc (max (max (TC_VOLUME_HEADER_EFFECTIVE_SIZE, PAGE_SIZE), Extension->HostBytesPerSector));
	if (readBuffer == NULL)
	{
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	// Go through all volume types (e.g., normal, hidden)
	for (volumeType = TC_VOLUME_TYPE_NORMAL;
		volumeType < TC_VOLUME_TYPE_COUNT;
		volumeType++)
	{
		Dump ("Trying to open volume type %d\n", volumeType);

		/* Read the volume header */

		if (!mount->bPartitionInInactiveSysEncScope
			|| (mount->bPartitionInInactiveSysEncScope && volumeType == TC_VOLUME_TYPE_HIDDEN))
		{
			// Header of a volume that is not within the scope of system encryption, or
			// header of a system hidden volume (containing a hidden OS)

			LARGE_INTEGER headerOffset = {0};

			if (mount->UseBackupHeader && lDiskLength.QuadPart <= TC_TOTAL_VOLUME_HEADERS_SIZE)
				continue;

			switch (volumeType)
			{
			case TC_VOLUME_TYPE_NORMAL:
				headerOffset.QuadPart = mount->UseBackupHeader ? lDiskLength.QuadPart - TC_VOLUME_HEADER_GROUP_SIZE : TC_VOLUME_HEADER_OFFSET;
				break;

			case TC_VOLUME_TYPE_HIDDEN:
				if (lDiskLength.QuadPart <= TC_VOLUME_HEADER_GROUP_SIZE)
					continue;

				headerOffset.QuadPart = mount->UseBackupHeader ? lDiskLength.QuadPart - TC_HIDDEN_VOLUME_HEADER_OFFSET : TC_HIDDEN_VOLUME_HEADER_OFFSET;
				break;
			}

			Dump ("Reading volume header at %I64d\n", headerOffset.QuadPart);

			ntStatus = ZwReadFile (Extension->hDeviceFile,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			readBuffer,
			bRawDevice ? max (TC_VOLUME_HEADER_EFFECTIVE_SIZE, Extension->HostBytesPerSector) : TC_VOLUME_HEADER_EFFECTIVE_SIZE,
			&headerOffset,
			NULL);
		}
		else
		{
			// Header of a partition that is within the scope of system encryption

			WCHAR parentDrivePath [47+1] = {0};
			HANDLE hParentDeviceFile = NULL;
			UNICODE_STRING FullParentPath;
			OBJECT_ATTRIBUTES oaParentFileAttributes;
			LARGE_INTEGER parentKeyDataOffset;

			RtlStringCbPrintfW (parentDrivePath,
				sizeof (parentDrivePath),
				WIDE ("\\Device\\Harddisk%d\\Partition0"),
				mount->nPartitionInInactiveSysEncScopeDriveNo);

			Dump ("Mounting partition within scope of system encryption (reading key data from: %ls)\n", parentDrivePath);

			RtlInitUnicodeString (&FullParentPath, parentDrivePath);
			InitializeObjectAttributes (&oaParentFileAttributes, &FullParentPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,	NULL, NULL);

			ntStatus = ZwCreateFile (&hParentDeviceFile,
				GENERIC_READ | SYNCHRONIZE,
				&oaParentFileAttributes,
				&IoStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL |
				FILE_ATTRIBUTE_SYSTEM,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN,
				FILE_RANDOM_ACCESS |
				FILE_WRITE_THROUGH |
				FILE_NO_INTERMEDIATE_BUFFERING |
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);

			if (!NT_SUCCESS (ntStatus))
			{
				if (hParentDeviceFile != NULL)
					ZwClose (hParentDeviceFile);

				Dump ("Cannot open %ls\n", parentDrivePath);

				goto error;
			}

			parentKeyDataOffset.QuadPart = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;

			ntStatus = ZwReadFile (hParentDeviceFile,
				NULL,
				NULL,
				NULL,
				&IoStatusBlock,
				readBuffer,
				max (TC_VOLUME_HEADER_EFFECTIVE_SIZE, Extension->HostBytesPerSector),
				&parentKeyDataOffset,
				NULL);

			if (hParentDeviceFile != NULL)
				ZwClose (hParentDeviceFile);
		}

		if (!NT_SUCCESS (ntStatus) && ntStatus != STATUS_END_OF_FILE)
		{
			Dump ("Read failed: NTSTATUS 0x%08x\n", ntStatus);
			goto error;
		}

		if (ntStatus == STATUS_END_OF_FILE || IoStatusBlock.Information < TC_VOLUME_HEADER_EFFECTIVE_SIZE)
		{
			Dump ("Read didn't read enough data\n");

			// If FSCTL_ALLOW_EXTENDED_DASD_IO failed and there is a live filesystem on the partition, then the
			// filesystem driver may report EOF when we are reading hidden sectors (when the filesystem is
			// shorter than the partition). This can happen for example after the user quick-formats a dismounted
			// partition-hosted TrueCrypt volume and then tries to mount the volume using the embedded backup header.
			memset (readBuffer, 0, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
		}

		/* Attempt to recognize the volume (decrypt the header) */

		ReadVolumeHeaderRecoveryMode = mount->RecoveryMode;

		if ((volumeType == TC_VOLUME_TYPE_HIDDEN) && mount->bProtectHiddenVolume)
		{
			mount->nReturnCode = ReadVolumeHeaderWCache (
				FALSE,
				bAutoCachePassword,
				mount->bCachePim,
				readBuffer,
				&mount->ProtectedHidVolPassword,
				mount->ProtectedHidVolPkcs5Prf,
				mount->ProtectedHidVolPim,
				&tmpCryptoInfo);
		}
		else
		{
			mount->nReturnCode = ReadVolumeHeaderWCache (
				mount->bPartitionInInactiveSysEncScope && volumeType == TC_VOLUME_TYPE_NORMAL,
				bAutoCachePassword,
				mount->bCachePim,
				readBuffer,
				&mount->VolumePassword,
				mount->pkcs5_prf,
				mount->VolumePim,
				&Extension->cryptoInfo);
		}

		ReadVolumeHeaderRecoveryMode = FALSE;

		if (mount->nReturnCode == 0 || mount->nReturnCode == ERR_CIPHER_INIT_WEAK_KEY)
		{
			/* Volume header successfully decrypted */

			if (!Extension->cryptoInfo)
			{
				/* should never happen */
				mount->nReturnCode = ERR_OUTOFMEMORY;
				ntStatus = STATUS_SUCCESS;
				goto error;
			}

#ifdef _WIN64
			if (IsRamEncryptionEnabled() && (volumeType == TC_VOLUME_TYPE_NORMAL || !mount->bProtectHiddenVolume))
				VcProtectKeys (Extension->cryptoInfo, VcGetEncryptionID (Extension->cryptoInfo));
#endif

			Dump ("Volume header decrypted\n");
			Dump ("Required program version = %x\n", (int) Extension->cryptoInfo->RequiredProgramVersion);
			Dump ("Legacy volume = %d\n", (int) Extension->cryptoInfo->LegacyVolume);
			Dump ("Master key vulnerable = %d\n", (int) Extension->cryptoInfo->bVulnerableMasterKey);

			mount->VolumeMasterKeyVulnerable = Extension->cryptoInfo->bVulnerableMasterKey;

			if (IsHiddenSystemRunning() && !Extension->cryptoInfo->hiddenVolume)
			{
				Extension->bReadOnly = mount->bMountReadOnly = TRUE;
				HiddenSysLeakProtectionCount++;
			}

			Extension->cryptoInfo->bProtectHiddenVolume = FALSE;
			Extension->cryptoInfo->bHiddenVolProtectionAction = FALSE;

			Extension->cryptoInfo->bPartitionInInactiveSysEncScope = mount->bPartitionInInactiveSysEncScope;

			/* compute the ID of this volume: SHA-256 of the effective header */
			sha256 (Extension->volumeID, readBuffer, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

			if (volumeType == TC_VOLUME_TYPE_NORMAL)
			{
				if (mount->bPartitionInInactiveSysEncScope)
				{
					if (Extension->cryptoInfo->EncryptedAreaStart.Value > (unsigned __int64) partitionStartingOffset
						|| Extension->cryptoInfo->EncryptedAreaStart.Value + Extension->cryptoInfo->VolumeSize.Value <= (unsigned __int64) partitionStartingOffset)
					{
						// The partition is not within the key scope of system encryption
						mount->nReturnCode = ERR_PASSWORD_WRONG;
						ntStatus = STATUS_SUCCESS;
						goto error;
					}

					if (Extension->cryptoInfo->EncryptedAreaLength.Value != Extension->cryptoInfo->VolumeSize.Value)
					{
						// mount as readonly in case of partial system encryption
						Extension->bReadOnly = mount->bMountReadOnly = TRUE;
						mount->VolumeMountedReadOnlyAfterPartialSysEnc = TRUE;
					}
				}
				else if (Extension->cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC)
				{
					if (Extension->cryptoInfo->EncryptedAreaLength.Value != Extension->cryptoInfo->VolumeSize.Value)
					{
						// Non-system in-place encryption process has not been completed on this volume
						mount->nReturnCode = ERR_NONSYS_INPLACE_ENC_INCOMPLETE;
						ntStatus = STATUS_SUCCESS;
						goto error;
					}
				}
			}

			Extension->cryptoInfo->FirstDataUnitNo.Value = 0;

			if (Extension->cryptoInfo->hiddenVolume && IsHiddenSystemRunning())
			{
				// Prevent mount of a hidden system partition if the system hosted on it is currently running
				if (memcmp (Extension->cryptoInfo->master_keydata_hash, GetSystemDriveCryptoInfo()->master_keydata_hash, sizeof(Extension->cryptoInfo->master_keydata_hash)) == 0)
				{
					mount->nReturnCode = ERR_VOL_ALREADY_MOUNTED;
					ntStatus = STATUS_SUCCESS;
					goto error;
				}
			}

			switch (volumeType)
			{
			case TC_VOLUME_TYPE_NORMAL:

				Extension->cryptoInfo->hiddenVolume = FALSE;

				if (mount->bPartitionInInactiveSysEncScope)
				{
					Extension->cryptoInfo->volDataAreaOffset = 0;
					Extension->DiskLength = lDiskLength.QuadPart;
					Extension->cryptoInfo->FirstDataUnitNo.Value = partitionStartingOffset / ENCRYPTION_DATA_UNIT_SIZE;
				}
				else if (Extension->cryptoInfo->LegacyVolume)
				{
					Extension->cryptoInfo->volDataAreaOffset = TC_VOLUME_HEADER_SIZE_LEGACY;
					Extension->DiskLength = lDiskLength.QuadPart - TC_VOLUME_HEADER_SIZE_LEGACY;
				}
				else
				{
					Extension->cryptoInfo->volDataAreaOffset = Extension->cryptoInfo->EncryptedAreaStart.Value;
					Extension->DiskLength = Extension->cryptoInfo->VolumeSize.Value;
				}

				break;

			case TC_VOLUME_TYPE_HIDDEN:

				cryptoInfoPtr = mount->bProtectHiddenVolume ? tmpCryptoInfo : Extension->cryptoInfo;

				Extension->cryptoInfo->hiddenVolumeOffset = cryptoInfoPtr->EncryptedAreaStart.Value;

				Dump ("Hidden volume offset = %I64d\n", Extension->cryptoInfo->hiddenVolumeOffset);
				Dump ("Hidden volume size = %I64d\n", cryptoInfoPtr->hiddenVolumeSize);
				Dump ("Hidden volume end = %I64d\n", Extension->cryptoInfo->hiddenVolumeOffset + cryptoInfoPtr->hiddenVolumeSize - 1);

				// Validate the offset
				if (Extension->cryptoInfo->hiddenVolumeOffset % ENCRYPTION_DATA_UNIT_SIZE != 0)
				{
					mount->nReturnCode = ERR_VOL_SIZE_WRONG;
					ntStatus = STATUS_SUCCESS;
					goto error;
				}

				// If we are supposed to actually mount the hidden volume (not just to protect it)
				if (!mount->bProtectHiddenVolume)
				{
					Extension->DiskLength = cryptoInfoPtr->hiddenVolumeSize;
					Extension->cryptoInfo->hiddenVolume = TRUE;
					Extension->cryptoInfo->volDataAreaOffset = Extension->cryptoInfo->hiddenVolumeOffset;
				}
				else
				{
					// Hidden volume protection
					Extension->cryptoInfo->hiddenVolume = FALSE;
					Extension->cryptoInfo->bProtectHiddenVolume = TRUE;

					Extension->cryptoInfo->hiddenVolumeProtectedSize = tmpCryptoInfo->hiddenVolumeSize;

					Dump ("Hidden volume protection active: %I64d-%I64d (%I64d)\n", Extension->cryptoInfo->hiddenVolumeOffset, Extension->cryptoInfo->hiddenVolumeProtectedSize + Extension->cryptoInfo->hiddenVolumeOffset - 1, Extension->cryptoInfo->hiddenVolumeProtectedSize);
				}

				break;
			}

			Dump ("Volume data offset = %I64d\n", Extension->cryptoInfo->volDataAreaOffset);
			Dump ("Volume data size = %I64d\n", Extension->DiskLength);
			Dump ("Volume data end = %I64d\n", Extension->cryptoInfo->volDataAreaOffset + Extension->DiskLength - 1);

			if (Extension->DiskLength == 0)
			{
				Dump ("Incorrect volume size\n");
				continue;
			}

			// If this is a hidden volume, make sure we are supposed to actually
			// mount it (i.e. not just to protect it)
			if (volumeType == TC_VOLUME_TYPE_NORMAL || !mount->bProtectHiddenVolume)
			{
				// Validate sector size
				if (bRawDevice && Extension->cryptoInfo->SectorSize != Extension->HostBytesPerSector)
				{
					mount->nReturnCode = ERR_PARAMETER_INCORRECT;
					ntStatus = STATUS_SUCCESS;
					goto error;
				}

				// Calculate virtual volume geometry
				Extension->TracksPerCylinder = 1;
				Extension->SectorsPerTrack = 1;
				Extension->BytesPerSector = Extension->cryptoInfo->SectorSize;
				Extension->NumberOfCylinders = Extension->DiskLength / Extension->BytesPerSector;
				Extension->PartitionType = 0;

				Extension->bRawDevice = bRawDevice;

				memset (Extension->wszVolume, 0, sizeof (Extension->wszVolume));
				if ((wcslen (pwszMountVolume) > 8)  && (0 == memcmp (pwszMountVolume, WIDE ("\\??\\UNC\\"), 8 * sizeof (WCHAR))))
				{
					/* UNC path */
					RtlStringCbPrintfW (Extension->wszVolume,
						sizeof (Extension->wszVolume),
						WIDE ("\\??\\\\%s"),
						pwszMountVolume + 7);
				}
				else
				{
					RtlStringCbCopyW (Extension->wszVolume, sizeof(Extension->wszVolume),pwszMountVolume);
				}

				memset (Extension->wszLabel, 0, sizeof (Extension->wszLabel));
				RtlStringCbCopyW (Extension->wszLabel, sizeof(Extension->wszLabel), mount->wszLabel);
			}

			// If we are to protect a hidden volume we cannot exit yet, for we must also
			// decrypt the hidden volume header.
			if (!(volumeType == TC_VOLUME_TYPE_NORMAL && mount->bProtectHiddenVolume))
			{
				/* in case of mounting with hidden volume protection, we cache both passwords manually after bother outer and hidden volumes are mounted*/
				if (mount->bProtectHiddenVolume && mount->bCache)
				{
					AddPasswordToCache(&mount->VolumePassword, mount->VolumePim, mount->bCachePim);
					AddPasswordToCache(&mount->ProtectedHidVolPassword, mount->ProtectedHidVolPim, mount->bCachePim);
				}

				TCfree (readBuffer);

				if (tmpCryptoInfo != NULL)
				{
					crypto_close (tmpCryptoInfo);
					tmpCryptoInfo = NULL;
				}

				return STATUS_SUCCESS;
			}
		}
		else if ((mount->bProtectHiddenVolume && volumeType == TC_VOLUME_TYPE_NORMAL)
			  || mount->nReturnCode != ERR_PASSWORD_WRONG)
		{
			 /* If we are not supposed to protect a hidden volume, the only error that is
				tolerated is ERR_PASSWORD_WRONG (to allow mounting a possible hidden volume).

				If we _are_ supposed to protect a hidden volume, we do not tolerate any error
				(both volume headers must be successfully decrypted). */

			break;
		}
	}

	/* Failed due to some non-OS reason so we drop through and return NT
	   SUCCESS then nReturnCode is checked later in user-mode */

	if (mount->nReturnCode == ERR_OUTOFMEMORY)
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	else
		ntStatus = STATUS_SUCCESS;

error:
	if (mount->nReturnCode == ERR_SUCCESS)
		mount->nReturnCode = ERR_PASSWORD_WRONG;

	if (tmpCryptoInfo != NULL)
	{
		crypto_close (tmpCryptoInfo);
		tmpCryptoInfo = NULL;
	}

	if (Extension->cryptoInfo)
	{
		crypto_close (Extension->cryptoInfo);
		Extension->cryptoInfo = NULL;
	}

	if (Extension->bTimeStampValid)
	{
		RestoreTimeStamp (Extension);
	}

	/* Close the hDeviceFile */
	if (Extension->hDeviceFile != NULL)
		ZwClose (Extension->hDeviceFile);

	/* The cryptoInfo pointer is deallocated if the readheader routines
	   fail so there is no need to deallocate here  */

	/* Dereference the user-mode file object */
	if (Extension->pfoDeviceFile != NULL)
		ObDereferenceObject (Extension->pfoDeviceFile);

	/* Free the tmp IO buffers */
	if (readBuffer != NULL)
		TCfree (readBuffer);

	return ntStatus;
}

void TCCloseVolume (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	UNREFERENCED_PARAMETER (DeviceObject);	/* Remove compiler warning */

	if (Extension->hDeviceFile != NULL)
	{
		if (Extension->bRawDevice == FALSE
			&& Extension->bTimeStampValid)
		{
			RestoreTimeStamp (Extension);
		}
		ZwClose (Extension->hDeviceFile);
	}
	ObDereferenceObject (Extension->pfoDeviceFile);
	if (Extension->cryptoInfo)
	{
		crypto_close (Extension->cryptoInfo);
		Extension->cryptoInfo = NULL;
	}
}

typedef struct
{
	PDEVICE_OBJECT deviceObject; PEXTENSION Extension; ULONG ioControlCode; void *inputBuffer; int inputBufferSize; void *outputBuffer; int outputBufferSize;
	NTSTATUS Status;
	KEVENT WorkItemCompletedEvent;
} TCSendHostDeviceIoControlRequestExWorkItemArgs;

static VOID TCSendHostDeviceIoControlRequestExWorkItemRoutine (PDEVICE_OBJECT rootDeviceObject, TCSendHostDeviceIoControlRequestExWorkItemArgs *arg)
{
	arg->Status = TCSendHostDeviceIoControlRequestEx (arg->deviceObject, arg->Extension, arg->ioControlCode, arg->inputBuffer, arg->inputBufferSize, arg->outputBuffer, arg->outputBufferSize);
	KeSetEvent (&arg->WorkItemCompletedEvent, IO_NO_INCREMENT, FALSE);
}

NTSTATUS TCSendHostDeviceIoControlRequestEx (PDEVICE_OBJECT DeviceObject,
			       PEXTENSION Extension,
			       ULONG IoControlCode,
					 void *InputBuffer,
					 ULONG InputBufferSize,
			       void *OutputBuffer,
			       ULONG OutputBufferSize)
{
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS ntStatus;
	PIRP Irp;

	UNREFERENCED_PARAMETER(DeviceObject);	/* Remove compiler warning */

	if ((KeGetCurrentIrql() >= APC_LEVEL) || VC_KeAreAllApcsDisabled())
	{
		TCSendHostDeviceIoControlRequestExWorkItemArgs args;

		PIO_WORKITEM workItem = IoAllocateWorkItem (RootDeviceObject);
		if (!workItem)
			return STATUS_INSUFFICIENT_RESOURCES;

		args.deviceObject = DeviceObject;
		args.Extension = Extension;
		args.ioControlCode = IoControlCode;
		args.inputBuffer = InputBuffer;
		args.inputBufferSize = InputBufferSize;
		args.outputBuffer = OutputBuffer;
		args.outputBufferSize = OutputBufferSize;

		KeInitializeEvent (&args.WorkItemCompletedEvent, SynchronizationEvent, FALSE);
		IoQueueWorkItem (workItem, TCSendHostDeviceIoControlRequestExWorkItemRoutine, DelayedWorkQueue, &args);

		KeWaitForSingleObject (&args.WorkItemCompletedEvent, Executive, KernelMode, FALSE, NULL);
		IoFreeWorkItem (workItem);

		return args.Status;
	}

	KeClearEvent (&Extension->keVolumeEvent);

	Irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     Extension->pFsdDevice,
					     InputBuffer, InputBufferSize,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &Extension->keVolumeEvent,
					     &IoStatusBlock);

	if (Irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Disk device may be used by filesystem driver which needs file object
	IoGetNextIrpStackLocation (Irp) -> FileObject = Extension->pfoDeviceFile;

	ntStatus = IoCallDriver (Extension->pFsdDevice, Irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&Extension->keVolumeEvent, Executive, KernelMode, FALSE, NULL);
		ntStatus = IoStatusBlock.Status;
	}

	return ntStatus;
}

NTSTATUS TCSendHostDeviceIoControlRequest (PDEVICE_OBJECT DeviceObject,
			       PEXTENSION Extension,
			       ULONG IoControlCode,
			       void *OutputBuffer,
			       ULONG OutputBufferSize)
{
	return TCSendHostDeviceIoControlRequestEx (DeviceObject, Extension, IoControlCode, NULL, 0, OutputBuffer, OutputBufferSize);
}

NTSTATUS COMPLETE_IRP (PDEVICE_OBJECT DeviceObject,
	      PIRP Irp,
	      NTSTATUS IrpStatus,
	      ULONG_PTR IrpInformation)
{
	Irp->IoStatus.Status = IrpStatus;
	Irp->IoStatus.Information = IrpInformation;

	UNREFERENCED_PARAMETER (DeviceObject);	/* Remove compiler warning */

#if EXTRA_INFO
	if (!NT_SUCCESS (IrpStatus))
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP FAILING IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
	else
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
		Dump ("COMPLETE_IRP SUCCESS IRP %ls Flags 0x%08x vpb 0x%08x NTSTATUS 0x%08x\n", TCTranslateCode (irpSp->MajorFunction),
		      (ULONG) DeviceObject->Flags, (ULONG) DeviceObject->Vpb->Flags, IrpStatus);
	}
#endif
	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return IrpStatus;
}


static void RestoreTimeStamp (PEXTENSION Extension)
{
	NTSTATUS ntStatus;
	FILE_BASIC_INFORMATION FileBasicInfo;
	IO_STATUS_BLOCK IoStatusBlock;

	if (Extension->hDeviceFile != NULL
		&& Extension->bRawDevice == FALSE
		&& Extension->bReadOnly == FALSE
		&& Extension->bTimeStampValid)
	{
		ntStatus = ZwQueryInformationFile (Extension->hDeviceFile,
			&IoStatusBlock,
			&FileBasicInfo,
			sizeof (FileBasicInfo),
			FileBasicInformation);

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("ZwQueryInformationFile failed in RestoreTimeStamp: NTSTATUS 0x%08x\n",
				ntStatus);
		}
		else
		{
			FileBasicInfo.CreationTime = Extension->fileCreationTime;
			FileBasicInfo.LastAccessTime = Extension->fileLastAccessTime;
			FileBasicInfo.LastWriteTime = Extension->fileLastWriteTime;
			FileBasicInfo.ChangeTime = Extension->fileLastChangeTime;

			ntStatus = ZwSetInformationFile(
				Extension->hDeviceFile,
				&IoStatusBlock,
				&FileBasicInfo,
				sizeof (FileBasicInfo),
				FileBasicInformation);

			if (!NT_SUCCESS (ntStatus))
				Dump ("ZwSetInformationFile failed in RestoreTimeStamp: NTSTATUS 0x%08x\n",ntStatus);
		}
	}
}
