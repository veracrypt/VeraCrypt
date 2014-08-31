/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/


/* In this file, _WIN32_WINNT is defined as 0x0600 to make filesystem shrink available (Vista
or later). _WIN32_WINNT cannot be defined as 0x0600 for the entire user-space projects
because it breaks the main font app when the app is running on XP (likely an MS bug).
IMPORTANT: Due to this issue, functions in this file must not directly interact with GUI. */
#define TC_LOCAL_WIN32_WINNT_OVERRIDE	 1
#if (_WIN32_WINNT < 0x0600)
#	undef _WIN32_WINNT
#	define _WIN32_WINNT 0x0600
#endif


#include <stdlib.h>
#include <string.h>
#include <string>

#include "Tcdefs.h"
#include "Platform/Finally.h"

#include "Common.h"
#include "Crc.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Tcformat.h"
#include "Volumes.h"

#include "InPlace.h"

#include <Strsafe.h>

using namespace std;
using namespace VeraCrypt;

#define TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE	(2048 * BYTES_PER_KB)
#define TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE		(2 * TC_MAX_VOLUME_SECTOR_SIZE)
#define TC_NTFS_CONCEAL_CONSTANT	0xFF
#define TC_NONSYS_INPLACE_ENC_HEADER_UPDATE_INTERVAL	(64 * BYTES_PER_MB)
#define TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE			(TC_TOTAL_VOLUME_HEADERS_SIZE + TC_MIN_NTFS_FS_SIZE * 2)


// If the returned value is greater than 0, it is the desired volume size in NTFS sectors (not in bytes) 
// after shrinking has been performed. If there's any error, returns -1.
static __int64 NewFileSysSizeAfterShrink (HANDLE dev, const char *devicePath, int64 *totalClusterCount, DWORD *bytesPerCluster, BOOL silent)
{
	NTFS_VOLUME_DATA_BUFFER ntfsVolData;
	DWORD nBytesReturned;
	__int64 fileSysSize, desiredNbrSectors;

	// Filesystem size and sector size

	if (!DeviceIoControl (dev,
		FSCTL_GET_NTFS_VOLUME_DATA,
		NULL,
		0,
		(LPVOID) &ntfsVolData,
		sizeof (ntfsVolData),   
		&nBytesReturned,
		NULL))
	{
		if (!silent)
			handleWin32Error (MainDlg);

		return -1;
	}

	fileSysSize = ntfsVolData.NumberSectors.QuadPart * ntfsVolData.BytesPerSector;

	desiredNbrSectors = (fileSysSize - TC_TOTAL_VOLUME_HEADERS_SIZE) / ntfsVolData.BytesPerSector;

	if (desiredNbrSectors <= 0)
		return -1;
	
	if (totalClusterCount)
		*totalClusterCount = ntfsVolData.TotalClusters.QuadPart;
	if (bytesPerCluster)
		*bytesPerCluster = ntfsVolData.BytesPerCluster;

	return desiredNbrSectors;
}


BOOL CheckRequirementsForNonSysInPlaceEnc (const char *devicePath, BOOL silent)
{
	NTFS_VOLUME_DATA_BUFFER ntfsVolData;
	DWORD nBytesReturned;
	HANDLE dev;
	char szFileSysName [256];
	WCHAR devPath [MAX_PATH];
	char dosDev [TC_MAX_PATH] = {0};
	char devName [MAX_PATH] = {0};
	int driveLetterNo = -1;
	char szRootPath[4] = {0, ':', '\\', 0};
	__int64 deviceSize;
	int partitionNumber = -1, driveNumber = -1;


	/* ---------- Checks that do not require admin rights ----------- */


	/* Operating system */

	if (CurrentOSMajor < 6)
	{
		if (!silent)
			ShowInPlaceEncErrMsgWAltSteps ("OS_NOT_SUPPORTED_FOR_NONSYS_INPLACE_ENC", FALSE);

		return FALSE;
	}


	/* Volume type (must be a partition or a dynamic volume) */

	if (sscanf (devicePath, "\\Device\\HarddiskVolume%d", &partitionNumber) != 1
		&& sscanf (devicePath, "\\Device\\Harddisk%d\\Partition%d", &driveNumber, &partitionNumber) != 2)
	{
		if (!silent)
			Error ("INPLACE_ENC_INVALID_PATH");

		return FALSE;
	}

	if (partitionNumber == 0)
	{
		if (!silent)
			Warning ("RAW_DEV_NOT_SUPPORTED_FOR_INPLACE_ENC");

		return FALSE;
	}


	/* Admin rights */

	if (!IsAdmin())
	{
		// We rely on the wizard process to call us only when the whole wizard process has been elevated (so UAC 
		// status can be ignored). In case the IsAdmin() detection somehow fails, we allow the user to continue.

		if (!silent)
			Warning ("ADMIN_PRIVILEGES_WARN_DEVICES");
	}


	/* ---------- Checks that may require admin rights ----------- */


	/* Access to the partition */

	StringCbCopyA ((char *) devPath, sizeof(devPath), devicePath);
	ToUNICODE ((char *) devPath, sizeof(devPath));

	driveLetterNo = GetDiskDeviceDriveLetter (devPath);

	if (driveLetterNo >= 0)
		szRootPath[0] = (char) driveLetterNo + 'A';

	if (FakeDosNameForDevice (devicePath, dosDev, sizeof(dosDev), devName, sizeof(devName),FALSE) != 0)
	{
		if (!silent)
		{
			handleWin32Error (MainDlg);
			Error ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL");
		}
		return FALSE;
	}

	dev = OpenPartitionVolume (devName,
		FALSE,	// Do not require exclusive access
		TRUE,	// Require shared access (must be TRUE; otherwise, volume properties will not be possible to obtain)
		FALSE,	// Do not ask the user to confirm shared access (if exclusive fails)
		FALSE,	// Do not append alternative instructions how to encrypt the data (to applicable error messages)
		silent);	// Silent mode

	if (dev == INVALID_HANDLE_VALUE)
		return FALSE;


	/* File system type */

	GetVolumeInformation (szRootPath, NULL, 0, NULL, NULL, NULL, szFileSysName, sizeof(szFileSysName));

	if (strncmp (szFileSysName, "NTFS", 4))
	{
		// The previous filesystem type detection method failed (or it's not NTFS) -- try an alternative method

		if (!DeviceIoControl (dev,
			FSCTL_GET_NTFS_VOLUME_DATA,
			NULL,
			0,
			(LPVOID) &ntfsVolData,
			sizeof (ntfsVolData),   
			&nBytesReturned,
			NULL))
		{
			if (!silent)
			{
				// The filesystem is not NTFS or the filesystem type could not be determined (or the NTFS filesystem
				// is dismounted).

				if (IsDeviceMounted (devName))
					ShowInPlaceEncErrMsgWAltSteps ("ONLY_NTFS_SUPPORTED_FOR_NONSYS_INPLACE_ENC", FALSE);
				else
					Warning ("ONLY_MOUNTED_VOL_SUPPORTED_FOR_NONSYS_INPLACE_ENC");
			}

			CloseHandle (dev);
			return FALSE;
		}
	}


	/* Attempt to determine whether the filesystem can be safely shrunk */

	if (NewFileSysSizeAfterShrink (dev, devicePath, NULL, NULL, silent) == -1)
	{
		// Cannot determine whether shrinking is required
		if (!silent)
			ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL_ALT", TRUE);

		CloseHandle (dev);
		return FALSE;
	}


	/* Partition size */

	deviceSize = GetDeviceSize (devicePath);
	if (deviceSize < 0)
	{
		// Cannot determine the size of the partition
		if (!silent)
			Error ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL");

		CloseHandle (dev);
		return FALSE;
	}

	if (deviceSize < TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE)
	{
		// The partition is too small
		if (!silent)
		{
			ShowInPlaceEncErrMsgWAltSteps ("PARTITION_TOO_SMALL_FOR_NONSYS_INPLACE_ENC", FALSE);
		}

		CloseHandle (dev);
		return FALSE;
	}


	/* Free space on the filesystem */

	if (!DeviceIoControl (dev,
		FSCTL_GET_NTFS_VOLUME_DATA,
		NULL,
		0,
		(LPVOID) &ntfsVolData,
		sizeof (ntfsVolData),   
		&nBytesReturned,
		NULL))
	{
		if (!silent)
			ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL", TRUE);

		CloseHandle (dev);
		return FALSE;
	}

	if (ntfsVolData.FreeClusters.QuadPart * ntfsVolData.BytesPerCluster < TC_TOTAL_VOLUME_HEADERS_SIZE)
	{
		if (!silent)
			ShowInPlaceEncErrMsgWAltSteps ("NOT_ENOUGH_FREE_FILESYS_SPACE_FOR_SHRINK", TRUE);

		CloseHandle (dev);
		return FALSE;
	}


	/* Filesystem sector size */

	if (ntfsVolData.BytesPerSector > TC_MAX_VOLUME_SECTOR_SIZE
		|| ntfsVolData.BytesPerSector % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		if (!silent)
			ShowInPlaceEncErrMsgWAltSteps ("SECTOR_SIZE_UNSUPPORTED", TRUE);

		CloseHandle (dev);
		return FALSE;
	}


	CloseHandle (dev);
	return TRUE;
}


int EncryptPartitionInPlaceBegin (volatile FORMAT_VOL_PARAMETERS *volParams, volatile HANDLE *outHandle, WipeAlgorithmId wipeAlgorithm)
{
	SHRINK_VOLUME_INFORMATION shrinkVolInfo;
	signed __int64 sizeToShrinkTo;
	int nStatus = ERR_SUCCESS;
	PCRYPTO_INFO cryptoInfo = NULL;
	PCRYPTO_INFO cryptoInfo2 = NULL;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	char *header;
	char dosDev[TC_MAX_PATH] = {0};
	char devName[MAX_PATH] = {0};
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];
	uint64 dataAreaSize;
	__int64 deviceSize;
	LARGE_INTEGER offset;
	DWORD dwResult;

	SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PREPARING);


	if (!CheckRequirementsForNonSysInPlaceEnc (volParams->volumePath, FALSE))
		return ERR_DONT_REPORT;


	header = (char *) TCalloc (TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	if (!header)
		return ERR_OUTOFMEMORY;

	VirtualLock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

	deviceSize = GetDeviceSize (volParams->volumePath);
	if (deviceSize < 0)
	{
		// Cannot determine the size of the partition
		nStatus = ERR_PARAMETER_INCORRECT;
		goto closing_seq;
	}

	if (deviceSize < TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE)
	{
		ShowInPlaceEncErrMsgWAltSteps ("PARTITION_TOO_SMALL_FOR_NONSYS_INPLACE_ENC", TRUE);
		nStatus = ERR_DONT_REPORT;
		goto closing_seq;
	}

	dataAreaSize = GetVolumeDataAreaSize (volParams->hiddenVol, deviceSize);

	StringCbCopyA ((char *)deviceName, sizeof(deviceName), volParams->volumePath);
	ToUNICODE ((char *)deviceName, sizeof(deviceName));

	driveLetter = GetDiskDeviceDriveLetter (deviceName);


	if (FakeDosNameForDevice (volParams->volumePath, dosDev, sizeof(dosDev),devName, sizeof(devName),FALSE) != 0)
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}

	if (IsDeviceMounted (devName))
	{
		dev = OpenPartitionVolume (devName,
			FALSE,	// Do not require exclusive access (must be FALSE; otherwise, it will not be possible to dismount the volume or obtain its properties and FSCTL_ALLOW_EXTENDED_DASD_IO will fail too)
			TRUE,	// Require shared access (must be TRUE; otherwise, it will not be possible to dismount the volume or obtain its properties and FSCTL_ALLOW_EXTENDED_DASD_IO will fail too)
			FALSE,	// Do not ask the user to confirm shared access (if exclusive fails)
			FALSE,	// Do not append alternative instructions how to encrypt the data (to applicable error messages)
			FALSE);	// Non-silent mode

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_DONT_REPORT; 
			goto closing_seq;
		}
	}
	else
	{
		// The volume is not mounted so we can't work with the filesystem.
		Error ("ONLY_MOUNTED_VOL_SUPPORTED_FOR_NONSYS_INPLACE_ENC");
		nStatus = ERR_DONT_REPORT; 
		goto closing_seq;
	}


	/* Gain "raw" access to the partition (the NTFS driver guards hidden sectors). */

	if (!DeviceIoControl (dev,
		FSCTL_ALLOW_EXTENDED_DASD_IO,
		NULL,
		0,   
		NULL,
		0,
		&dwResult,
		NULL))
	{
		handleWin32Error (MainDlg);
		ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL_ALT", TRUE);
		nStatus = ERR_DONT_REPORT; 
		goto closing_seq;
	}



	/* Shrink the filesystem */

	int64 totalClusterCount;
	DWORD bytesPerCluster;

	sizeToShrinkTo = NewFileSysSizeAfterShrink (dev, volParams->volumePath, &totalClusterCount, &bytesPerCluster, FALSE);

	if (sizeToShrinkTo == -1)
	{
		ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL_ALT", TRUE);
		nStatus = ERR_DONT_REPORT; 
		goto closing_seq;
	}

	SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_RESIZING);

	memset (&shrinkVolInfo, 0, sizeof (shrinkVolInfo));

	shrinkVolInfo.ShrinkRequestType = ShrinkPrepare;
	shrinkVolInfo.NewNumberOfSectors = sizeToShrinkTo;

	if (!DeviceIoControl (dev,
		FSCTL_SHRINK_VOLUME,
		(LPVOID) &shrinkVolInfo,
		sizeof (shrinkVolInfo),   
		NULL,
		0,
		&dwResult,
		NULL))
	{
		handleWin32Error (MainDlg);
		ShowInPlaceEncErrMsgWAltSteps ("CANNOT_RESIZE_FILESYS", TRUE);
		nStatus = ERR_DONT_REPORT; 
		goto closing_seq;
	}

	BOOL clustersMovedBeforeVolumeEnd = FALSE;

	while (true)
	{
		shrinkVolInfo.ShrinkRequestType = ShrinkCommit;
		shrinkVolInfo.NewNumberOfSectors = 0;

		if (!DeviceIoControl (dev, FSCTL_SHRINK_VOLUME, &shrinkVolInfo, sizeof (shrinkVolInfo), NULL, 0, &dwResult, NULL))
		{
			// If there are any occupied clusters beyond the new desired end of the volume, the call fails with
			// ERROR_ACCESS_DENIED (STATUS_ALREADY_COMMITTED). 
			if (GetLastError () == ERROR_ACCESS_DENIED)
			{
				if (!clustersMovedBeforeVolumeEnd)
				{
					if (MoveClustersBeforeThreshold (dev, deviceName, totalClusterCount - (bytesPerCluster > TC_TOTAL_VOLUME_HEADERS_SIZE ? 1 : TC_TOTAL_VOLUME_HEADERS_SIZE / bytesPerCluster)))
					{
						clustersMovedBeforeVolumeEnd = TRUE;
						continue;
					}

					handleWin32Error (MainDlg);
				}
			}
			else
				handleWin32Error (MainDlg);

			ShowInPlaceEncErrMsgWAltSteps ("CANNOT_RESIZE_FILESYS", TRUE);
			nStatus = ERR_DONT_REPORT; 
			goto closing_seq;
		}

		break;
	}

	SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PREPARING);


	/* Gain exclusive access to the volume */

	nStatus = DismountFileSystem (dev,
		driveLetter,
		TRUE,
		TRUE,
		FALSE);

	if (nStatus != ERR_SUCCESS)
	{
		nStatus = ERR_DONT_REPORT; 
		goto closing_seq;
	}



	/* Create header backup on the partition. Until the volume is fully encrypted, the backup header will provide 
	us with the master key, encrypted range, and other data for pause/resume operations. We cannot create the 
	primary header until the entire partition is encrypted (because we encrypt backwards and the primary header 
	area is occuppied by data until the very end of the process). */

	// Prepare the backup header
	for (int wipePass = 0; wipePass < (wipeAlgorithm == TC_WIPE_NONE ? 1 : PRAND_HEADER_WIPE_PASSES); wipePass++)
	{
		nStatus = CreateVolumeHeaderInMemory (FALSE,
			header,
			volParams->ea,
			FIRST_MODE_OF_OPERATION_ID,
			volParams->password,
			volParams->pkcs5,
			wipePass == 0 ? NULL : (char *) cryptoInfo->master_keydata,
			&cryptoInfo,
			dataAreaSize,
			0,
			TC_VOLUME_DATA_OFFSET + dataAreaSize,	// Start of the encrypted area = the first byte of the backup heeader (encrypting from the end)
			0,	// No data is encrypted yet
			0,
			volParams->headerFlags | TC_HEADER_FLAG_NONSYS_INPLACE_ENC,
			volParams->sectorSize,
			wipeAlgorithm == TC_WIPE_NONE ? FALSE : (wipePass < PRAND_HEADER_WIPE_PASSES - 1));

		if (nStatus != 0)
			goto closing_seq;

		offset.QuadPart = TC_VOLUME_DATA_OFFSET + dataAreaSize;

		if (!SetFilePointerEx (dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		// Write the backup header to the partition
		if (!WriteEffectiveVolumeHeader (TRUE, dev, (byte *) header))
		{
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		// Fill the reserved sectors of the backup header area with random data
		nStatus = WriteRandomDataToReservedHeaderAreas (dev, cryptoInfo, dataAreaSize, FALSE, TRUE);

		if (nStatus != ERR_SUCCESS)
			goto closing_seq;
	}


	/* Now we will try to decrypt the backup header to verify it has been correctly written. */

	nStatus = OpenBackupHeader (dev, volParams->volumePath, volParams->password, &cryptoInfo2, NULL, deviceSize);

	if (nStatus != ERR_SUCCESS
		|| cryptoInfo->EncryptedAreaStart.Value != cryptoInfo2->EncryptedAreaStart.Value
		|| cryptoInfo2->EncryptedAreaStart.Value == 0)
	{
		if (nStatus == ERR_SUCCESS)
			nStatus = ERR_PARAMETER_INCORRECT;

		goto closing_seq;
	}

	// The backup header is valid so we know we should be able to safely resume in-place encryption 
	// of this partition even if the system/app crashes.



	/* Conceal the NTFS filesystem (by performing an easy-to-undo modification). This will prevent Windows 
	and apps from interfering with the volume until it has been fully encrypted. */

	nStatus = ConcealNTFS (dev);

	if (nStatus != ERR_SUCCESS)
		goto closing_seq;



	// /* If a drive letter is assigned to the device, remove it (so that users do not try to open it, which
	//would cause Windows to ask them if they want to format the volume and other dangerous things). */

	//if (driveLetter >= 0) 
	//{
	//	char rootPath[] = { driveLetter + 'A', ':', '\\', 0 };

	//	// Try to remove the assigned drive letter
	//	if (DeleteVolumeMountPoint (rootPath))
	//		driveLetter = -1;
	//}



	/* Update config files and app data */

	// In the config file, increase the number of partitions where in-place encryption is in progress

	SaveNonSysInPlaceEncSettings (1, wipeAlgorithm);


	// Add the wizard to the system startup sequence if appropriate

	if (!IsNonInstallMode ())
		ManageStartupSeqWiz (FALSE, "/prinplace");


	nStatus = ERR_SUCCESS;


closing_seq:

	dwError = GetLastError();

	if (cryptoInfo != NULL)
	{
		crypto_close (cryptoInfo);
		cryptoInfo = NULL;
	}

	if (cryptoInfo2 != NULL)
	{
		crypto_close (cryptoInfo2);
		cryptoInfo2 = NULL;
	}

	burn (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	VirtualUnlock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	TCfree (header);

	if (dosDev[0])
		RemoveFakeDosName (volParams->volumePath, dosDev);

	*outHandle = dev;

	if (nStatus != ERR_SUCCESS)
		SetLastError (dwError);

	return nStatus;
}


int EncryptPartitionInPlaceResume (HANDLE dev,
								   volatile FORMAT_VOL_PARAMETERS *volParams,
								   WipeAlgorithmId wipeAlgorithm,
								   volatile BOOL *bTryToCorrectReadErrors)
{
	PCRYPTO_INFO masterCryptoInfo = NULL, headerCryptoInfo = NULL, tmpCryptoInfo = NULL;
	UINT64_STRUCT unitNo;
	char *buf = NULL, *header = NULL;
	byte *wipeBuffer = NULL;
	byte wipeRandChars [TC_WIPE_RAND_CHAR_COUNT];
	byte wipeRandCharsUpdate [TC_WIPE_RAND_CHAR_COUNT];
	char dosDev[TC_MAX_PATH] = {0};
	char devName[MAX_PATH] = {0};
	WCHAR deviceName[MAX_PATH];
	int nStatus = ERR_SUCCESS;
	__int64 deviceSize;
	uint64 remainingBytes, lastHeaderUpdateDistance = 0, zeroedSectorCount = 0;
	uint32 workChunkSize;
	DWORD dwError, dwResult;
	BOOL bPause = FALSE, bEncryptedAreaSizeChanged = FALSE;
	LARGE_INTEGER offset;
	int sectorSize;
	int i;
	DWORD n;
	char *devicePath = volParams->volumePath;
	Password *password = volParams->password;
	DISK_GEOMETRY driveGeometry;


	bInPlaceEncNonSysResumed = TRUE;

	buf = (char *) TCalloc (TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE);
	if (!buf)
	{
		nStatus = ERR_OUTOFMEMORY;
		goto closing_seq;
	}

	header = (char *) TCalloc (TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	if (!header)
	{
		nStatus = ERR_OUTOFMEMORY;
		goto closing_seq;
	}

	VirtualLock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

	if (wipeAlgorithm != TC_WIPE_NONE)
	{
		wipeBuffer = (byte *) TCalloc (TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE);
		if (!wipeBuffer)
		{
			nStatus = ERR_OUTOFMEMORY;
			goto closing_seq;
		}
	}

	headerCryptoInfo = crypto_open();

	if (headerCryptoInfo == NULL)
	{
		nStatus = ERR_OUTOFMEMORY;
		goto closing_seq;
	}

	deviceSize = GetDeviceSize (devicePath);
	if (deviceSize < 0)
	{
		// Cannot determine the size of the partition
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		StringCbCopyA ((char *)deviceName, sizeof(deviceName), devicePath);
		ToUNICODE ((char *)deviceName, sizeof(deviceName));

		if (FakeDosNameForDevice (devicePath, dosDev, sizeof(dosDev),devName, sizeof(devName),FALSE) != 0)
		{
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		dev = OpenPartitionVolume (devName,
			FALSE,	// Do not require exclusive access
			FALSE,	// Do not require shared access
			TRUE,	// Ask the user to confirm shared access (if exclusive fails)
			FALSE,	// Do not append alternative instructions how to encrypt the data (to applicable error messages)
			FALSE);	// Non-silent mode

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_DONT_REPORT; 
			goto closing_seq;
		}
	}

	// This should never be needed, but is still performed for extra safety (without checking the result)
	DeviceIoControl (dev,
		FSCTL_ALLOW_EXTENDED_DASD_IO,
		NULL,
		0,   
		NULL,
		0,
		&dwResult,
		NULL);


	if (!DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &driveGeometry, sizeof (driveGeometry), &dwResult, NULL))
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}

	sectorSize = driveGeometry.BytesPerSector;


	nStatus = OpenBackupHeader (dev, devicePath, password, &masterCryptoInfo, headerCryptoInfo, deviceSize);

	if (nStatus != ERR_SUCCESS)
		goto closing_seq;



    remainingBytes = masterCryptoInfo->VolumeSize.Value - masterCryptoInfo->EncryptedAreaLength.Value;

	lastHeaderUpdateDistance = 0;


	ExportProgressStats (masterCryptoInfo->EncryptedAreaLength.Value, masterCryptoInfo->VolumeSize.Value);

	SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_ENCRYPTING);

	bFirstNonSysInPlaceEncResumeDone = TRUE;


	/* The in-place encryption core */

	while (remainingBytes > 0)
	{
		workChunkSize = (uint32) min (remainingBytes, TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE);

		if (workChunkSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			nStatus = ERR_PARAMETER_INCORRECT;
			goto closing_seq;
		}

		unitNo.Value = (remainingBytes - workChunkSize + TC_VOLUME_DATA_OFFSET) / ENCRYPTION_DATA_UNIT_SIZE;


		// Read the plaintext into RAM

inplace_enc_read:

		offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize - TC_VOLUME_DATA_OFFSET;

		if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0)
		{
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		if (ReadFile (dev, buf, workChunkSize, &n, NULL) == 0)
		{
			// Read error

			DWORD dwTmpErr = GetLastError ();

			if (IsDiskReadError (dwTmpErr) && !bVolTransformThreadCancel)
			{
				// Physical defect or data corruption

				if (!*bTryToCorrectReadErrors)
				{
					*bTryToCorrectReadErrors = (AskWarnYesNo ("ENABLE_BAD_SECTOR_ZEROING") == IDYES);
				}

				if (*bTryToCorrectReadErrors)
				{
					// Try to correct the read errors physically

					offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize - TC_VOLUME_DATA_OFFSET;

					nStatus = ZeroUnreadableSectors (dev, offset, workChunkSize, sectorSize, &zeroedSectorCount);

					if (nStatus != ERR_SUCCESS)
					{
						// Due to write errors, we can't correct the read errors
						nStatus = ERR_OS_ERROR;
						goto closing_seq;
					}

					goto inplace_enc_read;
				}
			}

			SetLastError (dwTmpErr);		// Preserve the original error code

			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		if (remainingBytes - workChunkSize < TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE)
		{
			// We reached the inital portion of the filesystem, which we had concealed (in order to prevent
			// Windows from interfering with the volume). Now we need to undo that modification. 

			for (i = 0; i < TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE - (remainingBytes - workChunkSize); i++)
				buf[i] ^= TC_NTFS_CONCEAL_CONSTANT;
		}


		// Encrypt the plaintext in RAM

		EncryptDataUnits ((byte *) buf, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, masterCryptoInfo);


		// If enabled, wipe the area to which we will write the ciphertext

		if (wipeAlgorithm != TC_WIPE_NONE)
		{
			byte wipePass;
			int wipePassCount = GetWipePassCount (wipeAlgorithm);

			if (wipePassCount <= 0)
			{
				SetLastError (ERROR_INVALID_PARAMETER);
				nStatus = ERR_PARAMETER_INCORRECT;
				goto closing_seq;
			}

			offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize;

			for (wipePass = 1; wipePass <= wipePassCount; ++wipePass)
			{
				if (!WipeBuffer (wipeAlgorithm, wipeRandChars, wipePass, wipeBuffer, workChunkSize))
				{
					ULONG i;
					for (i = 0; i < workChunkSize; ++i)
					{
						wipeBuffer[i] = buf[i] + wipePass;
					}

					EncryptDataUnits (wipeBuffer, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, masterCryptoInfo);
					memcpy (wipeRandCharsUpdate, wipeBuffer, sizeof (wipeRandCharsUpdate)); 
				}

				if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
					|| WriteFile (dev, wipeBuffer, workChunkSize, &n, NULL) == 0)
				{
					// Write error
					dwError = GetLastError();

					// Undo failed write operation
					if (workChunkSize > TC_VOLUME_DATA_OFFSET && SetFilePointerEx (dev, offset, NULL, FILE_BEGIN))
					{
						DecryptDataUnits ((byte *) buf, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, masterCryptoInfo);
						WriteFile (dev, buf + TC_VOLUME_DATA_OFFSET, workChunkSize - TC_VOLUME_DATA_OFFSET, &n, NULL);
					}

					SetLastError (dwError);
					nStatus = ERR_OS_ERROR;
					goto closing_seq;
				}
			}

			memcpy (wipeRandChars, wipeRandCharsUpdate, sizeof (wipeRandCharsUpdate)); 
		}


		// Write the ciphertext

		offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize;

		if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0)
		{
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}

		if (WriteFile (dev, buf, workChunkSize, &n, NULL) == 0)
		{
			// Write error
			dwError = GetLastError();

			// Undo failed write operation
			if (workChunkSize > TC_VOLUME_DATA_OFFSET && SetFilePointerEx (dev, offset, NULL, FILE_BEGIN))
			{
				DecryptDataUnits ((byte *) buf, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, masterCryptoInfo);
				WriteFile (dev, buf + TC_VOLUME_DATA_OFFSET, workChunkSize - TC_VOLUME_DATA_OFFSET, &n, NULL);
			}

			SetLastError (dwError);
			nStatus = ERR_OS_ERROR;
			goto closing_seq;
		}


		masterCryptoInfo->EncryptedAreaStart.Value -= workChunkSize;
		masterCryptoInfo->EncryptedAreaLength.Value += workChunkSize;

		remainingBytes -= workChunkSize;
		lastHeaderUpdateDistance += workChunkSize;

		bEncryptedAreaSizeChanged = TRUE;

		if (lastHeaderUpdateDistance >= TC_NONSYS_INPLACE_ENC_HEADER_UPDATE_INTERVAL)
		{
			nStatus = FastVolumeHeaderUpdate (dev, headerCryptoInfo, masterCryptoInfo, deviceSize);

			if (nStatus != ERR_SUCCESS)
				goto closing_seq;

			lastHeaderUpdateDistance = 0;
		}

		ExportProgressStats (masterCryptoInfo->EncryptedAreaLength.Value, masterCryptoInfo->VolumeSize.Value);

		if (bVolTransformThreadCancel)
		{
			bPause = TRUE;
			break;
		}
	}

	nStatus = FastVolumeHeaderUpdate (dev, headerCryptoInfo, masterCryptoInfo, deviceSize);


	if (nStatus != ERR_SUCCESS)
		goto closing_seq;


	if (!bPause)
	{
		/* The data area has been fully encrypted; create and write the primary volume header */

		SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_FINALIZING);

		for (int wipePass = 0; wipePass < (wipeAlgorithm == TC_WIPE_NONE ? 1 : PRAND_HEADER_WIPE_PASSES); wipePass++)
		{
			nStatus = CreateVolumeHeaderInMemory (FALSE,
				header,
				headerCryptoInfo->ea,
				headerCryptoInfo->mode,
				password,
				masterCryptoInfo->pkcs5,
				(char *) masterCryptoInfo->master_keydata,
				&tmpCryptoInfo,
				masterCryptoInfo->VolumeSize.Value,
				0,
				masterCryptoInfo->EncryptedAreaStart.Value,
				masterCryptoInfo->EncryptedAreaLength.Value,
				masterCryptoInfo->RequiredProgramVersion,
				masterCryptoInfo->HeaderFlags | TC_HEADER_FLAG_NONSYS_INPLACE_ENC,
				masterCryptoInfo->SectorSize,
				wipeAlgorithm == TC_WIPE_NONE ? FALSE : (wipePass < PRAND_HEADER_WIPE_PASSES - 1));

			if (nStatus != ERR_SUCCESS)
				goto closing_seq;


			offset.QuadPart = TC_VOLUME_HEADER_OFFSET;

			if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
				|| !WriteEffectiveVolumeHeader (TRUE, dev, (byte *) header))
			{
				nStatus = ERR_OS_ERROR;
				goto closing_seq;
			}

			// Fill the reserved sectors of the header area with random data
			nStatus = WriteRandomDataToReservedHeaderAreas (dev, headerCryptoInfo, masterCryptoInfo->VolumeSize.Value, TRUE, FALSE);

			if (nStatus != ERR_SUCCESS)
				goto closing_seq;
		}

		// Update the configuration files

		SaveNonSysInPlaceEncSettings (-1, wipeAlgorithm);



		SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_FINISHED);

		nStatus = ERR_SUCCESS;
	}
	else
	{
		// The process has been paused by the user or aborted by the wizard (e.g. on app exit)

		nStatus = ERR_USER_ABORT;

		SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PAUSED);
	}


closing_seq:

	dwError = GetLastError();

	if (bEncryptedAreaSizeChanged
		&& dev != INVALID_HANDLE_VALUE
		&& masterCryptoInfo != NULL
		&& headerCryptoInfo != NULL
		&& deviceSize > 0)
	{
		// Execution of the core loop may have been interrupted due to an error or user action without updating the header
		FastVolumeHeaderUpdate (dev, headerCryptoInfo, masterCryptoInfo, deviceSize);
	}

	if (masterCryptoInfo != NULL)
	{
		crypto_close (masterCryptoInfo);
		masterCryptoInfo = NULL;
	}

	if (headerCryptoInfo != NULL)
	{
		crypto_close (headerCryptoInfo);
		headerCryptoInfo = NULL;
	}

	if (tmpCryptoInfo != NULL)
	{
		crypto_close (tmpCryptoInfo);
		tmpCryptoInfo = NULL;
	}

	if (dosDev[0])
		RemoveFakeDosName (devicePath, dosDev);

	if (dev != INVALID_HANDLE_VALUE)
	{
		CloseHandle (dev);
		dev = INVALID_HANDLE_VALUE;
	}

	if (buf != NULL)
		TCfree (buf);

	if (header != NULL)
	{
		burn (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
		VirtualUnlock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
		TCfree (header);
	}

	if (wipeBuffer != NULL)
		TCfree (wipeBuffer);

	if (zeroedSectorCount > 0)
	{
		wchar_t msg[30000] = {0};
		wchar_t sizeStr[500] = {0};

		GetSizeString (zeroedSectorCount * sectorSize, sizeStr, sizeof(sizeStr));

		StringCbPrintfW (msg, sizeof(msg), 
			GetString ("ZEROED_BAD_SECTOR_COUNT"),
			zeroedSectorCount,
			sizeStr);

		WarningDirect (msg);
	}

	if (nStatus != ERR_SUCCESS && nStatus != ERR_USER_ABORT)
		SetLastError (dwError);

	return nStatus;
}


int FastVolumeHeaderUpdate (HANDLE dev, CRYPTO_INFO *headerCryptoInfo, CRYPTO_INFO *masterCryptoInfo, __int64 deviceSize)
{
	LARGE_INTEGER offset;
	DWORD n;
	int nStatus = ERR_SUCCESS;
	byte *header;
	DWORD dwError;
	uint32 headerCrc32;
	byte *fieldPos;

	header = (byte *) TCalloc (TC_VOLUME_HEADER_EFFECTIVE_SIZE);

	if (!header)
		return ERR_OUTOFMEMORY;

	VirtualLock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);


	fieldPos = (byte *) header + TC_HEADER_OFFSET_ENCRYPTED_AREA_START;

	offset.QuadPart = deviceSize - TC_VOLUME_HEADER_GROUP_SIZE;

	if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
		|| !ReadEffectiveVolumeHeader (TRUE, dev, header, &n) || n < TC_VOLUME_HEADER_EFFECTIVE_SIZE)
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}


	DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerCryptoInfo);

	if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x56455241)
	{
		nStatus = ERR_PARAMETER_INCORRECT;
		goto closing_seq;
	}

	mputInt64 (fieldPos, (masterCryptoInfo->EncryptedAreaStart.Value));
	mputInt64 (fieldPos, (masterCryptoInfo->EncryptedAreaLength.Value));


	headerCrc32 = GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
	fieldPos = (byte *) header + TC_HEADER_OFFSET_HEADER_CRC;
	mputLong (fieldPos, headerCrc32);

	EncryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerCryptoInfo);


	if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
		|| !WriteEffectiveVolumeHeader (TRUE, dev, header))
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}


closing_seq:

	dwError = GetLastError();

	burn (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	VirtualUnlock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	TCfree (header);

	if (nStatus != ERR_SUCCESS)
		SetLastError (dwError);

	return nStatus;
}


static HANDLE OpenPartitionVolume (const char *devName,
							 BOOL bExclusiveRequired,
							 BOOL bSharedRequired,
							 BOOL bSharedRequiresConfirmation,
							 BOOL bShowAlternativeSteps,
							 BOOL bSilent)
{
	HANDLE dev = INVALID_HANDLE_VALUE;
	int retryCount = 0;

	if (bExclusiveRequired)
		bSharedRequired = FALSE;

	if (bExclusiveRequired || !bSharedRequired)
	{
		// Exclusive access
		// Note that when exclusive access is denied, it is worth retrying (usually succeeds after a few tries).
		while (dev == INVALID_HANDLE_VALUE && retryCount++ < EXCL_ACCESS_MAX_AUTO_RETRIES)
		{
			dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);

			if (retryCount > 1)
				Sleep (EXCL_ACCESS_AUTO_RETRY_DELAY);
		}
	}

	if (dev == INVALID_HANDLE_VALUE)
	{
		if (bExclusiveRequired)
		{
			if (!bSilent)
			{
				handleWin32Error (MainDlg);

				if (bShowAlternativeSteps)
					ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL_ALT", TRUE);
				else
					Error ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL");
			}
			return INVALID_HANDLE_VALUE;
		}

		// Shared mode
		dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
		if (dev != INVALID_HANDLE_VALUE)
		{
			if (bSharedRequiresConfirmation 
				&& !bSilent
				&& AskWarnNoYes ("DEVICE_IN_USE_INPLACE_ENC") == IDNO)
			{
				CloseHandle (dev);
				return INVALID_HANDLE_VALUE;
			}
		}
		else
		{
			if (!bSilent)
			{
				handleWin32Error (MainDlg);

				if (bShowAlternativeSteps)
					ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL_ALT", TRUE);
				else
					Error ("INPLACE_ENC_CANT_ACCESS_OR_GET_INFO_ON_VOL");
			}
			return INVALID_HANDLE_VALUE;
		}
	}

	return dev;
}


static int DismountFileSystem (HANDLE dev,
					int driveLetter,
					BOOL bForcedAllowed,
					BOOL bForcedRequiresConfirmation,
					BOOL bSilent)
{
	int attempt;
	BOOL bResult;
	DWORD dwResult;

	CloseVolumeExplorerWindows (MainDlg, driveLetter);

	attempt = UNMOUNT_MAX_AUTO_RETRIES * 10;

	while (!(bResult = DeviceIoControl (dev, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL)) 
		&& attempt > 0)
	{
		Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		attempt--;
	}

	if (!bResult)
	{
		if (!bForcedAllowed)
		{
			if (!bSilent)
				ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_LOCK_OR_DISMOUNT_FILESYS", TRUE);

			return ERR_DONT_REPORT;
		}

		if (bForcedRequiresConfirmation
			&& !bSilent
			&& AskWarnYesNo ("VOL_LOCK_FAILED_OFFER_FORCED_DISMOUNT") == IDNO)
		{
			return ERR_DONT_REPORT;
		}
	}

	// Dismount the volume

	attempt = UNMOUNT_MAX_AUTO_RETRIES * 10;

	while (!(bResult = DeviceIoControl (dev, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL)) 
		&& attempt > 0)
	{
		Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		attempt--;
	}

	if (!bResult)
	{
		if (!bSilent)
			ShowInPlaceEncErrMsgWAltSteps ("INPLACE_ENC_CANT_LOCK_OR_DISMOUNT_FILESYS", TRUE);

		return ERR_DONT_REPORT; 
	}

	return ERR_SUCCESS; 
}


// Easy-to-undo modification applied to conceal the NTFS filesystem (to prevent Windows and apps from 
// interfering with it until the volume has been fully encrypted). Note that this function will precisely
// undo any modifications it made to the filesystem automatically if an error occurs when writing (including
// physical drive defects).
static int ConcealNTFS (HANDLE dev)
{
	char buf [TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE];
	DWORD nbrBytesProcessed, nbrBytesProcessed2;
	int i;
	LARGE_INTEGER offset;
	DWORD dwError;

	offset.QuadPart = 0;
 
	if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0)
		return ERR_OS_ERROR;

	if (ReadFile (dev, buf, TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE, &nbrBytesProcessed, NULL) == 0)
		return ERR_OS_ERROR;

	for (i = 0; i < TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE; i++)
		buf[i] ^= TC_NTFS_CONCEAL_CONSTANT;

	offset.QuadPart = 0;

	if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0)
		return ERR_OS_ERROR;

	if (WriteFile (dev, buf, TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE, &nbrBytesProcessed, NULL) == 0)
	{
		// One or more of the sectors is/are probably damaged and cause write errors.
		// We must undo the modifications we made.

		dwError = GetLastError();

		for (i = 0; i < TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE; i++)
			buf[i] ^= TC_NTFS_CONCEAL_CONSTANT;

		offset.QuadPart = 0;

		do
		{
			Sleep (1);
		}
		while (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
			|| WriteFile (dev, buf, TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE, &nbrBytesProcessed2, NULL) == 0);

		SetLastError (dwError);

		return ERR_OS_ERROR;
	}

	return ERR_SUCCESS;
}


void ShowInPlaceEncErrMsgWAltSteps (char *iniStrId, BOOL bErr)
{
	wchar_t msg[30000];

	StringCbCopyW (msg, sizeof(msg), GetString (iniStrId));

	StringCbCatW (msg, sizeof(msg), L"\n\n\n");
	StringCbCatW (msg, sizeof(msg), GetString ("INPLACE_ENC_ALTERNATIVE_STEPS"));

	if (bErr)
		ErrorDirect (msg);
	else
		WarningDirect (msg);
}


static void ExportProgressStats (__int64 bytesDone, __int64 totalSize)
{
	NonSysInplaceEncBytesDone = bytesDone;
	NonSysInplaceEncTotalSize = totalSize;
}


void SetNonSysInplaceEncUIStatus (int nonSysInplaceEncStatus)
{
	NonSysInplaceEncStatus = nonSysInplaceEncStatus;
}


BOOL SaveNonSysInPlaceEncSettings (int delta, WipeAlgorithmId newWipeAlgorithm)
{
	int count;
	char str[32];
	WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

	if (delta == 0)
		return TRUE;

	count = LoadNonSysInPlaceEncSettings (&savedWipeAlgorithm) + delta;

	if (count < 1)
	{
		RemoveNonSysInPlaceEncNotifications();
		return TRUE;
	}
	else
	{
		if (newWipeAlgorithm != TC_WIPE_NONE)
		{
			StringCbPrintfA (str, sizeof(str), "%d", (int) newWipeAlgorithm);

			SaveBufferToFile (str, GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE), strlen(str), FALSE);
		} 
		else if (FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE)))
		{
			remove (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE));
		}

		StringCbPrintfA (str, sizeof(str), "%d", count);

		return SaveBufferToFile (str, GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC), strlen(str), FALSE);
	}
}


// Repairs damaged sectors (i.e. those with read errors) by zeroing them. 
// Note that this operating fails if there are any write errors.
int ZeroUnreadableSectors (HANDLE dev, LARGE_INTEGER startOffset, int64 size, int sectorSize, uint64 *zeroedSectorCount)
{
	int nStatus;
	DWORD n;
	int64 sectorCount;
	LARGE_INTEGER workOffset;
	byte *sectorBuffer = NULL;
	DWORD dwError;

	workOffset.QuadPart = startOffset.QuadPart;

	sectorBuffer = (byte *) TCalloc (sectorSize);

	if (!sectorBuffer)
		return ERR_OUTOFMEMORY;

	if (SetFilePointerEx (dev, startOffset, NULL, FILE_BEGIN) == 0)
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}


	for (sectorCount = size / sectorSize; sectorCount > 0; --sectorCount)
	{
		if (ReadFile (dev, sectorBuffer, sectorSize, &n, NULL) == 0)
		{
			memset (sectorBuffer, 0, sectorSize);

			if (SetFilePointerEx (dev, workOffset, NULL, FILE_BEGIN) == 0)
			{
				nStatus = ERR_OS_ERROR;
				goto closing_seq;
			}

			if (WriteFile (dev, sectorBuffer, sectorSize, &n, NULL) == 0)
			{
				nStatus = ERR_OS_ERROR;
				goto closing_seq;
			}
			++(*zeroedSectorCount);
		}

		workOffset.QuadPart += n;
	}

	nStatus = ERR_SUCCESS;

closing_seq:

	dwError = GetLastError();

	if (sectorBuffer != NULL)
		TCfree (sectorBuffer);

	if (nStatus != ERR_SUCCESS)
		SetLastError (dwError);

	return nStatus;
}


static int OpenBackupHeader (HANDLE dev, const char *devicePath, Password *password, PCRYPTO_INFO *retMasterCryptoInfo, CRYPTO_INFO *headerCryptoInfo, __int64 deviceSize)
{
	LARGE_INTEGER offset;
	DWORD n;
	int nStatus = ERR_SUCCESS;
	char *header;
	DWORD dwError;

	header = (char *) TCalloc (TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	if (!header)
		return ERR_OUTOFMEMORY;

	VirtualLock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);



	offset.QuadPart = deviceSize - TC_VOLUME_HEADER_GROUP_SIZE;

	if (SetFilePointerEx (dev, offset, NULL, FILE_BEGIN) == 0
		|| !ReadEffectiveVolumeHeader (TRUE, dev, (byte *) header, &n) || n < TC_VOLUME_HEADER_EFFECTIVE_SIZE)
	{
		nStatus = ERR_OS_ERROR;
		goto closing_seq;
	}


	nStatus = ReadVolumeHeader (FALSE, header, password, retMasterCryptoInfo, headerCryptoInfo);
	if (nStatus != ERR_SUCCESS)
		goto closing_seq;


closing_seq:

	dwError = GetLastError();

	burn (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	VirtualUnlock (header, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
	TCfree (header);

	dwError = GetLastError();

	if (nStatus != ERR_SUCCESS)
		SetLastError (dwError);

	return nStatus;
}


static BOOL GetFreeClusterBeforeThreshold (HANDLE volumeHandle, int64 *freeCluster, int64 clusterThreshold)
{
	const int bitmapSize = 65536;
	byte bitmapBuffer[bitmapSize + sizeof (VOLUME_BITMAP_BUFFER)];
	VOLUME_BITMAP_BUFFER *bitmap = (VOLUME_BITMAP_BUFFER *) bitmapBuffer;
	STARTING_LCN_INPUT_BUFFER startLcn;
	startLcn.StartingLcn.QuadPart = 0;

	DWORD bytesReturned;
	while (DeviceIoControl (volumeHandle, FSCTL_GET_VOLUME_BITMAP, &startLcn, sizeof (startLcn), &bitmapBuffer, sizeof (bitmapBuffer), &bytesReturned, NULL)
		|| GetLastError() == ERROR_MORE_DATA)
	{
		for (int64 bitmapIndex = 0; bitmapIndex < min (bitmapSize, (bitmap->BitmapSize.QuadPart / 8)); ++bitmapIndex)
		{
			if (bitmap->StartingLcn.QuadPart + bitmapIndex * 8 >= clusterThreshold)
				goto err;

			if (bitmap->Buffer[bitmapIndex] != 0xff)
			{
				for (int bit = 0; bit < 8; ++bit)
				{
					if ((bitmap->Buffer[bitmapIndex] & (1 << bit)) == 0)
					{
						*freeCluster = bitmap->StartingLcn.QuadPart + bitmapIndex * 8 + bit;

						if (*freeCluster >= clusterThreshold)
							goto err;

						return TRUE;
					}
				}
			}
		}

		startLcn.StartingLcn.QuadPart += min (bitmapSize * 8, bitmap->BitmapSize.QuadPart);
	}
	
err:
	SetLastError (ERROR_DISK_FULL);
	return FALSE;
}


static BOOL MoveClustersBeforeThresholdInDir (HANDLE volumeHandle, const wstring &directory, int64 clusterThreshold)
{
	WIN32_FIND_DATAW findData;

	HANDLE findHandle = FindFirstFileW (((directory.size() <= 3 ? L"" : L"\\\\?\\") + directory + L"\\*").c_str(), &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
		return TRUE;	// Error ignored

	finally_do_arg (HANDLE, findHandle, { FindClose (finally_arg); });

	// Find all files and directories
	do
	{
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			wstring subDir = findData.cFileName;

			if (subDir == L"." || subDir == L"..")
				continue;

			if (!MoveClustersBeforeThresholdInDir (volumeHandle, directory + L"\\" + subDir, clusterThreshold))
				return FALSE;
		}

		DWORD access = FILE_READ_ATTRIBUTES;

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
			access = FILE_READ_DATA;

		HANDLE fsObject = CreateFileW ((directory + L"\\" + findData.cFileName).c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (fsObject == INVALID_HANDLE_VALUE)
			continue;

		finally_do_arg (HANDLE, fsObject, { CloseHandle (finally_arg); });

		STARTING_VCN_INPUT_BUFFER startVcn;
		startVcn.StartingVcn.QuadPart = 0;
		RETRIEVAL_POINTERS_BUFFER retPointers;
		DWORD bytesReturned;

		// Find clusters allocated beyond the threshold
		while (DeviceIoControl (fsObject, FSCTL_GET_RETRIEVAL_POINTERS, &startVcn, sizeof (startVcn), &retPointers, sizeof (retPointers), &bytesReturned, NULL)
			|| GetLastError() == ERROR_MORE_DATA)
		{
			if (retPointers.ExtentCount == 0)
				break;

			if (retPointers.Extents[0].Lcn.QuadPart != -1)
			{
				int64 extentStartCluster = retPointers.Extents[0].Lcn.QuadPart;
				int64 extentLen = retPointers.Extents[0].NextVcn.QuadPart - retPointers.StartingVcn.QuadPart;
				int64 extentEndCluster = extentStartCluster + extentLen - 1;

				if (extentEndCluster >= clusterThreshold)
				{
					// Move clusters before the threshold
					for (int64 movedCluster = max (extentStartCluster, clusterThreshold); movedCluster <= extentEndCluster; ++movedCluster)
					{
						for (int retry = 0; ; ++retry)
						{
							MOVE_FILE_DATA moveData;

							if (GetFreeClusterBeforeThreshold (volumeHandle, &moveData.StartingLcn.QuadPart, clusterThreshold))
							{
								moveData.FileHandle = fsObject;
								moveData.StartingVcn.QuadPart = movedCluster - extentStartCluster + retPointers.StartingVcn.QuadPart;
								moveData.ClusterCount = 1;

								if (DeviceIoControl (volumeHandle, FSCTL_MOVE_FILE, &moveData, sizeof (moveData), NULL, 0, &bytesReturned, NULL))
									break;
							}

							if (retry > 600)
								return FALSE;

							// There are possible race conditions as we work on a live filesystem
							Sleep (100);
						}
					}
				}
			}

			startVcn.StartingVcn = retPointers.Extents[0].NextVcn;
		}

	} while (FindNextFileW (findHandle, &findData));

	return TRUE;
}


BOOL MoveClustersBeforeThreshold (HANDLE volumeHandle, PWSTR volumeDevicePath, int64 clusterThreshold)
{
	int drive = GetDiskDeviceDriveLetter (volumeDevicePath);
	if (drive == -1)
	{
		SetLastError (ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	wstring volumeRoot = L"X:";
	volumeRoot[0] = L'A' + (wchar_t) drive;

	return MoveClustersBeforeThresholdInDir (volumeHandle, volumeRoot, clusterThreshold);
}
