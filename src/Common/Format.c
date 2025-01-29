/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"

#include "Common.h"
#include "Crypto.h"
#include "Fat.h"
#include "Format.h"
#include "Random.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"
#include "Format/FormatCom.h"
#include "Format/Tcformat.h"

#include <Strsafe.h>

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

int FormatWriteBufferSize = 1024 * 1024;
static uint32 FormatSectorSize = 0;


uint64 GetVolumeDataAreaSize (BOOL hiddenVolume, uint64 volumeSize)
{
	uint64 reservedSize;

	if (hiddenVolume)
	{
		// Reserve free space at the end of the host filesystem. FAT file system fills the last sector with
		// zeroes (marked as free; observed when quick format was performed using the OS format tool).
		// Therefore, when the outer volume is mounted with hidden volume protection, such write operations
		// (e.g. quick formatting the outer volume filesystem as FAT) would needlessly trigger hidden volume
		// protection.

#if TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE > 4096
#	error	TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE too large for very small volumes. Revise the code.
#endif

#if TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH < TC_MAX_VOLUME_SECTOR_SIZE
#	error	TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH too small.
#endif

		if (volumeSize < TC_VOLUME_SMALL_SIZE_THRESHOLD)
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE;
		else
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH; // Ensure size of a hidden volume larger than TC_VOLUME_SMALL_SIZE_THRESHOLD is a multiple of the maximum supported sector size
	}
	else
	{
		reservedSize = TC_TOTAL_VOLUME_HEADERS_SIZE;
	}

	if (volumeSize < reservedSize)
		return 0;

	return volumeSize - reservedSize;
}


int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo = NULL;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	unsigned char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	BOOL bInstantRetryOtherFilesys = FALSE;
	WCHAR dosDev[TC_MAX_PATH] = { 0 };
	WCHAR devName[MAX_PATH] = { 0 };
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];
	uint64 dataOffset, dataAreaSize;
	LARGE_INTEGER offset;
	BOOL bFailedRequiredDASD = FALSE;
	HWND hwndDlg = volParams->hwndDlg;
	CRYPTO_INFO tmpCI;
	PCRYPTO_INFO cryptoInfoBackup = NULL;

	FormatSectorSize = volParams->sectorSize;

	if (FormatSectorSize < TC_MIN_VOLUME_SECTOR_SIZE
		|| FormatSectorSize > TC_MAX_VOLUME_SECTOR_SIZE
		|| FormatSectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		Error ("SECTOR_SIZE_UNSUPPORTED", hwndDlg);
		return ERR_DONT_REPORT;
	}

	/* WARNING: Note that if Windows fails to format the volume as NTFS and the volume size is
	less than the maximum FAT size, the user is asked within this function whether he wants to instantly
	retry FAT format instead (to avoid having to re-create the whole container again). If the user
	answers yes, some of the input parameters are modified, the code below 'begin_format' is re-executed
	and some destructive operations that were performed during the first attempt must be (and are) skipped.
	Therefore, whenever adding or modifying any potentially destructive operations below 'begin_format',
	determine whether they (or their portions) need to be skipped during such a second attempt; if so,
	use the 'bInstantRetryOtherFilesys' flag to skip them. */

	if (volParams->hiddenVol)
	{
		dataOffset = volParams->hiddenVolHostSize - TC_VOLUME_HEADER_GROUP_SIZE - volParams->size;
	}
	else
	{
		if (volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE)
			return ERR_VOL_SIZE_WRONG;

		dataOffset = TC_VOLUME_DATA_OFFSET;
	}

	dataAreaSize = GetVolumeDataAreaSize (volParams->hiddenVol, volParams->size);

	num_sectors = dataAreaSize / FormatSectorSize;

	if (volParams->bDevice)
	{
		StringCchCopyW (deviceName, ARRAYSIZE(deviceName), volParams->volumePath);

		driveLetter = GetDiskDeviceDriveLetter (deviceName);
	}

	VirtualLock (header, sizeof (header));

	nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				     header,
				     volParams->ea,
					 FIRST_MODE_OF_OPERATION_ID,
				     volParams->password,
				     volParams->pkcs5,
					  volParams->pim,
					 NULL,
				     &cryptoInfo,
					 dataAreaSize,
					 volParams->hiddenVol ? dataAreaSize : 0,
					 dataOffset,
					 dataAreaSize,
					 0,
					 volParams->headerFlags,
					 FormatSectorSize,
					 FALSE);

	/* cryptoInfo sanity check to make Coverity happy eventhough it can't be NULL if nStatus = 0 */
	if ((nStatus != 0) || !cryptoInfo)
	{
		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus? nStatus : ERR_OUTOFMEMORY;
	}

	if (IsRamEncryptionEnabled ())
	{
		VcProtectKeys (cryptoInfo, VcGetEncryptionID (cryptoInfo));
	}

begin_format:

	if (volParams->bDevice)
	{
		/* Device-hosted volume */

		DWORD dwResult;
		int nPass;

		if (FakeDosNameForDevice (volParams->volumePath, dosDev, sizeof(dosDev), devName, sizeof(devName), FALSE) != 0)
			return ERR_OS_ERROR;

		if (IsDeviceMounted (devName))
		{
			if ((dev = DismountDrive (devName, volParams->volumePath)) == INVALID_HANDLE_VALUE)
			{
				Error ("FORMAT_CANT_UNMOUNT_FILESYS", hwndDlg);
				nStatus = ERR_DONT_REPORT;
				goto error;
			}

			/* Gain "raw" access to the partition (it contains a live filesystem and the filesystem driver
			would otherwise prevent us from writing to hidden sectors). */

			if (!DeviceIoControl (dev,
				FSCTL_ALLOW_EXTENDED_DASD_IO,
				NULL,
				0,
				NULL,
				0,
				&dwResult,
				NULL))
			{
				bFailedRequiredDASD = TRUE;
			}
		}
		else if (driveLetter == -1)
		{
			// Windows Vista doesn't allow overwriting sectors belonging to an unformatted partition
			// to which no drive letter has been assigned under the system. This problem can be worked
			// around by assigning a drive letter to the partition temporarily.

			wchar_t szDriveLetter[] = { L'A', L':', 0 };
			wchar_t rootPath[] = { L'A', L':', L'\\', 0 };
			wchar_t uniqVolName[MAX_PATH+1] = { 0 };
			int tmpDriveLetter = -1;
			BOOL bResult = FALSE;

			tmpDriveLetter = GetFirstAvailableDrive ();

			if (tmpDriveLetter != -1)
			{
				rootPath[0] += (wchar_t) tmpDriveLetter;
				szDriveLetter[0] += (wchar_t) tmpDriveLetter;

				if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, volParams->volumePath))
				{
					bResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

					DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
						szDriveLetter,
						volParams->volumePath);

					if (bResult
						&& SetVolumeMountPoint (rootPath, uniqVolName))
					{
						// The drive letter can be removed now
						DeleteVolumeMountPoint (rootPath);
					}
				}
			}
		}

		// For extra safety, we will try to gain "raw" access to the partition. Note that this should actually be
		// redundant because if the filesystem was mounted, we already tried to obtain DASD above. If we failed,
		// bFailedRequiredDASD was set to TRUE and therefore we will perform pseudo "quick format" below. However,
		// for extra safety, in case IsDeviceMounted() failed to detect a live filesystem, we will blindly
		// send FSCTL_ALLOW_EXTENDED_DASD_IO (possibly for a second time) without checking the result.

		DeviceIoControl (dev,
			FSCTL_ALLOW_EXTENDED_DASD_IO,
			NULL,
			0,
			NULL,
			0,
			&dwResult,
			NULL);


		// If DASD is needed but we failed to obtain it, perform open - 'quick format' - close - open
		// so that the filesystem driver does not prevent us from formatting hidden sectors.
		for (nPass = (bFailedRequiredDASD ? 0 : 1); nPass < 2; nPass++)
		{
			int retryCount;

			retryCount = 0;

			// Try exclusive access mode first
			// Note that when exclusive access is denied, it is worth retrying (usually succeeds after a few tries).
			while (dev == INVALID_HANDLE_VALUE && retryCount++ < EXCL_ACCESS_MAX_AUTO_RETRIES)
			{
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (retryCount > 1)
					Sleep (EXCL_ACCESS_AUTO_RETRY_DELAY);
			}

			if (dev == INVALID_HANDLE_VALUE)
			{
				// Exclusive access denied -- retry in shared mode
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if (dev != INVALID_HANDLE_VALUE)
				{
					if (!volParams->bForceOperation && (Silent || (IDNO == MessageBoxW (volParams->hwndDlg, GetString ("DEVICE_IN_USE_FORMAT"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))))
					{
						nStatus = ERR_DONT_REPORT;
						goto error;
					}
				}
				else
				{
					handleWin32Error (volParams->hwndDlg, SRC_POS);
					Error ("CANT_ACCESS_VOL", hwndDlg);
					nStatus = ERR_DONT_REPORT;
					goto error;
				}
			}

			if (volParams->hiddenVol || bInstantRetryOtherFilesys)
				break;	// The following "quick format" operation would damage the outer volume

			if (nPass == 0)
			{
				char buf [2 * TC_MAX_VOLUME_SECTOR_SIZE];
				DWORD bw;

				// Perform pseudo "quick format" so that the filesystem driver does not prevent us from
				// formatting hidden sectors
				memset (buf, 0, sizeof (buf));

				if (!WriteFile (dev, buf, sizeof (buf), &bw, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}

				FlushFileBuffers (dev);
				CloseHandle (dev);
				dev = INVALID_HANDLE_VALUE;
			}
		}

		if (DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL))
		{
			Error ("FORMAT_CANT_UNMOUNT_FILESYS", hwndDlg);
			nStatus = ERR_DONT_REPORT;
			goto error;
		}
	}
	else
	{
		/* File-hosted volume */
		BOOL speedupFileCreation = FALSE;
		BOOL delayedSpeedupFileCreation = FALSE;
		// speedup for file creation only makes sens when using quick format for non hidden volumes
		if (!volParams->hiddenVol && !bInstantRetryOtherFilesys && volParams->quickFormat && volParams->fastCreateFile)
		{
			// we set required privileges to speedup file creation before we create the file so that the file handle inherits the privileges
			if (!SetPrivilege(SE_MANAGE_VOLUME_NAME, TRUE))
			{
				DWORD dwLastError = GetLastError();
				if (!IsAdmin () && IsUacSupported ())
				{
					speedupFileCreation = TRUE;
					delayedSpeedupFileCreation = TRUE;
				}
				else if (Silent || (MessageBoxW(hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_MANAGE_VOLUME"), lpszTitle, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDNO))
				{
					SetLastError(dwLastError);
					nStatus = ERR_OS_ERROR;
					goto error;
				}
			}
			else
			{
				speedupFileCreation = TRUE;
			}
		}

		dev = CreateFile (volParams->volumePath, GENERIC_READ | GENERIC_WRITE,
			(volParams->hiddenVol || bInstantRetryOtherFilesys) ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, (volParams->hiddenVol || bInstantRetryOtherFilesys) ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
		else if (volParams->hiddenVol && bPreserveTimestamp)
		{
			// ensure that Last Access and Last Write timestamps are not modified
			ftLastAccessTime.dwHighDateTime = 0xFFFFFFFF;
			ftLastAccessTime.dwLowDateTime = 0xFFFFFFFF;

			SetFileTime (dev, NULL, &ftLastAccessTime, NULL);

			if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
				bTimeStampValid = FALSE;
			else
				bTimeStampValid = TRUE;
		}

		DisableFileCompression (dev);

		if (!volParams->hiddenVol && !bInstantRetryOtherFilesys)
		{
			LARGE_INTEGER volumeSize;
			volumeSize.QuadPart = dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

			if (volParams->sparseFileSwitch && volParams->quickFormat)
			{
				// Create as sparse file container
				DWORD tmp;
				if (!DeviceIoControl (dev, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &tmp, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}
			}

			if (!delayedSpeedupFileCreation)
			{
				// Preallocate the file
				if (!SetFilePointerEx (dev, volumeSize, NULL, FILE_BEGIN)
					|| !SetEndOfFile (dev))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}
			}

			if (speedupFileCreation)
			{
				// accelerate file creation by telling Windows not to fill all file content with zeros
				// this has security issues since it will put existing disk content into file container
				// We use this mechanism only when switch /fastCreateFile specific and when quick format
				// also specified and which is documented to have security issues.
				if (delayedSpeedupFileCreation)
				{
					// in case of delayed speedup we need to set the file size to a minimal value before performing the real preallocation through UAC
					LARGE_INTEGER minimalSize;
					DWORD dwOpStatus;
					// 16K
					minimalSize.QuadPart = 16 * 1024;
					if (!SetFilePointerEx (dev, minimalSize, NULL, FILE_BEGIN)
						|| !SetEndOfFile (dev))
					{
						nStatus = ERR_OS_ERROR;
						goto error;
					}

					FlushFileBuffers (dev);
					CloseHandle (dev);
					dev = INVALID_HANDLE_VALUE;

					dwOpStatus = UacFastFileCreation (volParams->hwndDlg, volParams->volumePath, volumeSize.QuadPart);
					if (dwOpStatus != 0)
					{
						SetLastError(dwOpStatus);
						nStatus = ERR_OS_ERROR;
						goto error;
					}

					// open again the file now that it was created
					dev = CreateFile (volParams->volumePath, GENERIC_READ | GENERIC_WRITE,
						0, NULL, OPEN_EXISTING, 0, NULL);
					if (dev == INVALID_HANDLE_VALUE)
					{
						nStatus = ERR_OS_ERROR;
						goto error;
					}
				}
				else if (!SetFileValidData (dev, volumeSize.QuadPart))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}
			}

			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

		}
	}

	if (volParams->hwndDlg && volParams->bGuiMode) KillTimer (volParams->hwndDlg, TIMER_ID_RANDVIEW);

	/* Volume header */

	// Hidden volume setup
	if (volParams->hiddenVol)
	{
		LARGE_INTEGER headerOffset;

		// Check hidden volume size
		if (volParams->hiddenVolHostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE || volParams->hiddenVolHostSize > TC_MAX_HIDDEN_VOLUME_HOST_SIZE)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Seek to hidden volume header location

		headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
	}
	else if (bInstantRetryOtherFilesys)
	{
		// The previous file system format failed and the user wants to try again with a different file system.
		// The volume header had been written successfully so we need to seek to the byte after the header.

		LARGE_INTEGER volDataOffset;
		volDataOffset.QuadPart = TC_VOLUME_DATA_OFFSET;
		if (!SetFilePointerEx ((HANDLE) dev, volDataOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
	}

	if (!bInstantRetryOtherFilesys)
	{
		// Write the volume header
		if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, header))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		// To prevent fragmentation, write zeroes to reserved header sectors which are going to be filled with random data
		if (!volParams->bDevice && !volParams->hiddenVol)
		{
			uint8 buf[TC_VOLUME_HEADER_GROUP_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE];
			DWORD bytesWritten;
			ZeroMemory (buf, sizeof (buf));

			if (!WriteFile (dev, buf, sizeof (buf), &bytesWritten, NULL))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (bytesWritten != sizeof (buf))
			{
				nStatus = ERR_PARAMETER_INCORRECT;
				goto error;
			}
		}
	}

	if (volParams->hiddenVol)
	{
		// Calculate data area position of hidden volume
		cryptoInfo->hiddenVolumeOffset = dataOffset;

		// Validate the offset
		if (dataOffset % FormatSectorSize != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		volParams->quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	/* Data area */
	startSector = dataOffset / FormatSectorSize;

	// Format filesystem

	switch (volParams->fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:
	case FILESYS_EXFAT:
	case FILESYS_REFS:

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		nStatus = FormatNoFs (hwndDlg, startSector, num_sectors, dev, cryptoInfo, volParams->quickFormat, volParams->bDevice);

		if (volParams->bDevice)
			StopFormatWriteThread();

		break;

	case FILESYS_FAT:
		if (num_sectors > 0xFFFFffff)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Calculate the fats, root dir etc
		ft.num_sectors = (unsigned int) (num_sectors);

#if TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#error TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#endif

		ft.sector_size = (uint16) FormatSectorSize;
		ft.cluster_size = volParams->clusterSize;
		memcpy (ft.volume_name, "NO NAME    ", 11);
		GetFatParams (&ft);
		*(volParams->realClusterSize) = ft.cluster_size * FormatSectorSize;

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		nStatus = FormatFat (hwndDlg, startSector, &ft, (void *) dev, cryptoInfo, volParams->quickFormat, volParams->bDevice);

		if (volParams->bDevice)
			StopFormatWriteThread();

		break;

	default:
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	if (nStatus != ERR_SUCCESS)
		goto error;

	// Write header backup
	offset.QuadPart = volParams->hiddenVol ? volParams->hiddenVolHostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET : dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

	if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if (IsRamEncryptionEnabled ())
	{
		VirtualLock (&tmpCI, sizeof (tmpCI));
		memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
		VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
		cryptoInfoBackup = cryptoInfo;
		cryptoInfo = &tmpCI;
	}

	nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
		header,
		volParams->ea,
		FIRST_MODE_OF_OPERATION_ID,
		volParams->password,
		volParams->pkcs5,
		volParams->pim,
		cryptoInfo->master_keydata,
		&cryptoInfo,
		dataAreaSize,
		volParams->hiddenVol ? dataAreaSize : 0,
		dataOffset,
		dataAreaSize,
		0,
		volParams->headerFlags,
		FormatSectorSize,
		FALSE);

	if (IsRamEncryptionEnabled ())
	{
		cryptoInfo = cryptoInfoBackup;
		burn (&tmpCI, sizeof (CRYPTO_INFO));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}

	if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, header))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	// Fill reserved header sectors (including the backup header area) with random data
	if (!volParams->hiddenVol)
	{
		BOOL bUpdateBackup = FALSE;

		if (IsRamEncryptionEnabled ())
		{
			VirtualLock (&tmpCI, sizeof (tmpCI));
			memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
			VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
			cryptoInfoBackup = cryptoInfo;
			cryptoInfo = &tmpCI;
		}

		nStatus = WriteRandomDataToReservedHeaderAreas (hwndDlg, dev, cryptoInfo, dataAreaSize, FALSE, FALSE);

		if (IsRamEncryptionEnabled ())
		{
			cryptoInfo = cryptoInfoBackup;
			burn (&tmpCI, sizeof (CRYPTO_INFO));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
		}

		if (nStatus != ERR_SUCCESS)
			goto error;

		// write fake hidden volume header to protect against attacks that use statistical entropy
		// analysis to detect presence of hidden volumes.
		
		while (TRUE)
		{
			PCRYPTO_INFO dummyInfo = NULL;
			LARGE_INTEGER hiddenOffset;

			hiddenOffset.QuadPart = bUpdateBackup ? dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE + TC_HIDDEN_VOLUME_HEADER_OFFSET: TC_HIDDEN_VOLUME_HEADER_OFFSET;

			nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				header,
				volParams->ea,
				FIRST_MODE_OF_OPERATION_ID,
				NULL,
				0,
				0,
				NULL,
				&dummyInfo,
				dataAreaSize,
				dataAreaSize,
				dataOffset,
				dataAreaSize,
				0,
				volParams->headerFlags,
				FormatSectorSize,
				FALSE);

			if (nStatus != ERR_SUCCESS)
				goto error;

			crypto_close (dummyInfo);

			if (!SetFilePointerEx ((HANDLE) dev, hiddenOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, header))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (bUpdateBackup)
				break;

			bUpdateBackup = TRUE;
		}
	}

#ifndef DEBUG
	if (volParams->quickFormat && volParams->fileSystem != FILESYS_NTFS && volParams->fileSystem != FILESYS_EXFAT && volParams->fileSystem != FILESYS_REFS)
		Sleep (500);	// User-friendly GUI
#endif

error:
	dwError = GetLastError();

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	if (dev != INVALID_HANDLE_VALUE)
	{
		if (!volParams->bDevice && !volParams->hiddenVol && nStatus != 0)
		{
			// Remove preallocated part before closing file handle if format failed
			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) == 0)
				SetEndOfFile (dev);
		}

		FlushFileBuffers (dev);

		if (bTimeStampValid)
			SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

		CloseHandle (dev);
		dev = INVALID_HANDLE_VALUE;
	}

	if (nStatus != 0)
	{
		SetLastError(dwError);
		goto fv_end;
	}

	if (volParams->fileSystem == FILESYS_NTFS || volParams->fileSystem == FILESYS_EXFAT || volParams->fileSystem == FILESYS_REFS)
	{
		// Quick-format volume as NTFS
		int driveNo = GetLastAvailableDrive ();
		MountOptions mountOptions;
		int retCode;
		int fsType = volParams->fileSystem;

		ZeroMemory (&mountOptions, sizeof (mountOptions));

		if (driveNo == -1)
		{
			if (!Silent)
			{
				MessageBoxW (volParams->hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
				MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			}

			nStatus = ERR_NO_FREE_DRIVES;
			goto fv_end;
		}

		mountOptions.ReadOnly = FALSE;
		mountOptions.Removable = TRUE; /* mount as removal media to allow formatting without admin rights */
		mountOptions.ProtectHiddenVolume = FALSE;
		mountOptions.PreserveTimestamp = bPreserveTimestamp;
		mountOptions.PartitionInInactiveSysEncScope = FALSE;
		mountOptions.UseBackupHeader = FALSE;

		if (MountVolume (volParams->hwndDlg, driveNo, volParams->volumePath, volParams->password, volParams->pkcs5, volParams->pim, FALSE, FALSE, TRUE, &mountOptions, Silent, TRUE) < 1)
		{
			if (!Silent)
			{
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_MOUNT_VOLUME"), lpszTitle, ICON_HAND);
				MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			}
			nStatus = ERR_VOL_MOUNT_FAILED;
			goto fv_end;
		}

		retCode = ExternalFormatFs (driveNo, volParams->clusterSize, fsType);
		if (retCode != 0)
		{

			/* fallback to using FormatEx function from fmifs.dll */
			if (!Silent && !IsAdmin () && IsUacSupported ())
				retCode = UacFormatFs (volParams->hwndDlg, driveNo, volParams->clusterSize, fsType);
			else
				retCode = FormatFs (driveNo, volParams->clusterSize, fsType, FALSE); /* no need to fallback to format.com since we have already tried it without elevation */
			
			if (retCode != 0)
			{
				wchar_t auxLine[2048];
				StringCbPrintfW (auxLine, sizeof(auxLine), GetString ("FORMATEX_API_FAILED"), FormatExGetMessage(retCode));
				ErrorDirect(auxLine, volParams->hwndDlg);
			}
		}

		if (retCode != 0)
		{
			if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent)
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_UNMOUNT_VOLUME"), lpszTitle, ICON_HAND);

			if (dataAreaSize <= TC_MAX_FAT_SECTOR_COUNT * FormatSectorSize)
			{
				if (AskErrYesNo ("FORMAT_NTFS_FAILED_ASK_FAT", hwndDlg) == IDYES)
				{
					// NTFS format failed and the user wants to try FAT format immediately
					volParams->fileSystem = FILESYS_FAT;
					bInstantRetryOtherFilesys = TRUE;
					volParams->quickFormat = TRUE;		// Volume has already been successfully TC-formatted
					volParams->clusterSize = 0;		// Default cluster size
					goto begin_format;
				}
			}
			else
				Error ("FORMAT_NTFS_FAILED", hwndDlg);

			nStatus = ERR_DONT_REPORT;
			goto fv_end;
		}

		if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent)
			MessageBoxW (volParams->hwndDlg, GetString ("CANT_UNMOUNT_VOLUME"), lpszTitle, ICON_HAND);
	}

fv_end:
	dwError = GetLastError();

	if (dosDev[0])
		RemoveFakeDosName (volParams->volumePath, dosDev);

	crypto_close (cryptoInfo);

	SetLastError (dwError);
	return nStatus;
}


int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, unsigned __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat, BOOL bDevice)
{
	int write_buf_cnt = 0;
	char sector[TC_MAX_VOLUME_SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	unsigned __int64 nSkipSectors = 128 * (unsigned __int64) BYTES_PER_MB / FormatSectorSize;
	DWORD bytesWritten;
	int retVal = 0;
	DWORD err;
	CRYPTOPP_ALIGN_DATA(16) char temporaryKey[MASTER_KEYDATA_SIZE];
	CRYPTOPP_ALIGN_DATA(16) char originalK2[MASTER_KEYDATA_SIZE];

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	CRYPTO_INFO tmpCI;

	// Seek to start sector
	startOffset.QuadPart = startSector * FormatSectorSize;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{
		return ERR_OS_ERROR;
	}

	write_buf = (char *)TCalloc (FormatWriteBufferSize);
	if (!write_buf)
		return ERR_OUTOFMEMORY;

	VirtualLock (temporaryKey, sizeof (temporaryKey));
	VirtualLock (originalK2, sizeof (originalK2));

	memset (sector, 0, sizeof (sector));

	if (IsRamEncryptionEnabled ())
	{
		VirtualLock (&tmpCI, sizeof (tmpCI));
		memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
		VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
		cryptoInfo = &tmpCI;
	}

	// Remember the original secondary key (XTS mode) before generating a temporary one
	memcpy (originalK2, cryptoInfo->k2, sizeof (cryptoInfo->k2));

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes. */

		// Temporary master key
		if (!RandgetBytes (hwndDlg, temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
			goto fail;

		// Temporary secondary key (XTS mode)
		if (!RandgetBytes (hwndDlg, cryptoInfo->k2, sizeof cryptoInfo->k2, FALSE))
			goto fail;

		retVal = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (retVal != ERR_SUCCESS)
			goto fail;

		if (!EAInitMode (cryptoInfo, cryptoInfo->k2))
		{
			retVal = ERR_MODE_INIT_FAILED;
			goto fail;
		}

		if (IsRamEncryptionEnabled ())
			VcProtectKeys (cryptoInfo, VcGetEncryptionID (cryptoInfo));

		while (num_sectors--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				cryptoInfo) == FALSE)
				goto fail;
		}

		if (UpdateProgressBar ((nSecNo - startSector) * FormatSectorSize))
			return FALSE;

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;
	}
	else if (!bDevice)
	{
		// Quick format: write a zeroed sector every 128 MiB, leaving other sectors untouched
		// This helps users visualize the progress of actual file creation while forcing Windows
		// to allocate the disk space of each 128 MiB chunk immediately, otherwise, Windows 
		// would delay the allocation until we write the backup header at the end of the volume which
		// would make the user think that the format process has stalled after progress bar reaches 100%.
		while (num_sectors >= nSkipSectors)
		{
			// seek to next sector to be written
			nSecNo += (nSkipSectors - 1);
			startOffset.QuadPart = nSecNo * FormatSectorSize;
			if (!MoveFilePointer ((HANDLE) dev, startOffset))
			{
				goto fail;
			}
			
			// sector array has been zeroed above
			if (!WriteFile ((HANDLE) dev, sector, FormatSectorSize, &bytesWritten, NULL) 
				|| bytesWritten != FormatSectorSize)
			{
				goto fail;
			}
			
			nSecNo++;
			num_sectors -= nSkipSectors;

			if (UpdateProgressBar ((nSecNo - startSector)* FormatSectorSize))
				goto fail;
		}
		
		nSecNo += num_sectors;
	}
	else
	{
		nSecNo += num_sectors;
	}

	UpdateProgressBar ((nSecNo - startSector) * FormatSectorSize);

	// Restore the original secondary key (XTS mode) in case NTFS format fails and the user wants to try FAT immediately
	memcpy (cryptoInfo->k2, originalK2, sizeof (cryptoInfo->k2));

	// Reinitialize the encryption algorithm and mode in case NTFS format fails and the user wants to try FAT immediately
	retVal = EAInit (cryptoInfo->ea, cryptoInfo->master_keydata, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		goto fail;
	if (!EAInitMode (cryptoInfo, cryptoInfo->k2))
	{
		retVal = ERR_MODE_INIT_FAILED;
		goto fail;
	}

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);
	if (IsRamEncryptionEnabled ())
	{
		burn (&tmpCI, sizeof (CRYPTO_INFO));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}

	return 0;

fail:
	err = GetLastError();

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);
	if (IsRamEncryptionEnabled ())
	{
		burn (&tmpCI, sizeof (CRYPTO_INFO));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}

	SetLastError (err);
	return (retVal ? retVal : ERR_OS_ERROR);
}


volatile BOOLEAN FormatExError;
volatile int FormatExErrorCommand;

LPCWSTR FormatExGetMessage (int command)
{
	static WCHAR h_szMsg[32];
	switch (command)
	{
	case FMIFS_DONE:
		return L"FORMAT_FINISHED";
	case FMIFS_STRUCTURE_PROGRESS:
		return L"FORMAT_STRUCTURE_PROGRESS";
	case FMIFS_MEDIA_WRITE_PROTECTED:
		return L"FORMAT_MEDIA_WRITE_PROTECTED";
	case FMIFS_INCOMPATIBLE_FILE_SYSTEM:
		return L"FORMAT_INCOMPATIBLE_FILE_SYSTEM";
	case FMIFS_ACCESS_DENIED:
		return L"FORMAT_ACCESS_DENIED";
	case FMIFS_VOLUME_IN_USE:
		return L"FORMAT_VOLUME_IN_USE";
	case FMIFS_CLUSTER_SIZE_TOO_SMALL:
		return L"FORMAT_CLUSTER_SIZE_TOO_SMALL";
	case FMIFS_CLUSTER_SIZE_TOO_BIG:
		return L"FORMAT_CLUSTER_SIZE_TOO_BIG";
	case FMIFS_VOLUME_TOO_SMALL:
		return L"FORMAT_VOLUME_TOO_SMALL";
	case FMIFS_VOLUME_TOO_BIG:
		return L"FORMAT_VOLUME_TOO_BIG";
	case FMIFS_NO_MEDIA_IN_DRIVE:
		return L"FORMAT_NO_MEDIA_IN_DRIVE";
	case FMIFS_DEVICE_NOT_READY:
		return L"FORMAT_DEVICE_NOT_READY";
	case FMIFS_BAD_LABEL:
		return L"FORMAT_BAD_LABEL";
	case FMIFS_CANT_QUICK_FORMAT:
		return L"FORMAT_CANT_QUICK_FORMAT";
	default:
		StringCbPrintfW (h_szMsg, sizeof(h_szMsg), L"0x%.8X", command);
		return h_szMsg;
	}	
}

BOOLEAN __stdcall FormatExCallback (int command, DWORD subCommand, PVOID parameter)
{
	if (FormatExError)
		return FALSE;

	switch(command) {
	case FMIFS_PROGRESS:
		break;
	case FMIFS_STRUCTURE_PROGRESS:
		break;
	case FMIFS_DONE:
		if(*(BOOLEAN*)parameter == FALSE) {
			FormatExError = TRUE;
		}
		break;
	case FMIFS_DONE_WITH_STRUCTURE:
		break;
	case FMIFS_INCOMPATIBLE_FILE_SYSTEM:
		FormatExError = TRUE;
		break;
	case FMIFS_ACCESS_DENIED:
		FormatExError = TRUE;
		break;
	case FMIFS_MEDIA_WRITE_PROTECTED:
		FormatExError = TRUE;
		break;
	case FMIFS_VOLUME_IN_USE:
		FormatExError = TRUE;
		break;
	case FMIFS_DEVICE_NOT_READY:
		FormatExError = TRUE;
		break;
	case FMIFS_CANT_QUICK_FORMAT:
		FormatExError = TRUE;
		break;
	case FMIFS_BAD_LABEL:
		FormatExError = TRUE;
		break;
	case FMIFS_OUTPUT:
		break;
	case FMIFS_CLUSTER_SIZE_TOO_BIG:
	case FMIFS_CLUSTER_SIZE_TOO_SMALL:
		FormatExError = TRUE;
		break;
	case FMIFS_VOLUME_TOO_BIG:
	case FMIFS_VOLUME_TOO_SMALL:
		FormatExError = TRUE;
		break;
	case FMIFS_NO_MEDIA_IN_DRIVE:
		FormatExError = TRUE;
		break;
	default:
		FormatExError = TRUE;
		break;
	}
	if (FormatExError)
	{
		FormatExErrorCommand = command;
	}
	return (FormatExError? FALSE : TRUE);
}

int FormatFs (int driveNo, int clusterSize, int fsType, BOOL bFallBackExternal)
{
	wchar_t dllPath[MAX_PATH] = {0};
	WCHAR dir[8] = { (WCHAR) driveNo + L'A', 0 };
	PFORMATEX FormatEx;
	HMODULE hModule;
	int i;
	WCHAR szFsFormat[16];
	WCHAR szLabel[2] = {0};
	switch (fsType)
	{
		case FILESYS_NTFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"NTFS");
			break;
		case FILESYS_EXFAT:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"EXFAT");
			break;
		case FILESYS_REFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"ReFS");
			break;
		default:
			return FALSE;
	}


	if (GetSystemDirectory (dllPath, MAX_PATH))
	{
		StringCchCatW(dllPath, ARRAYSIZE(dllPath), L"\\fmifs.dll");
	}
	else
		StringCchCopyW(dllPath, ARRAYSIZE(dllPath), L"C:\\Windows\\System32\\fmifs.dll");

	hModule = LoadLibrary (dllPath);

	if (hModule == NULL)
		return FALSE;

	if (!(FormatEx = (PFORMATEX) GetProcAddress (GetModuleHandle (L"fmifs.dll"), "FormatEx")))
	{
		FreeLibrary (hModule);
		return FALSE;
	}

	StringCchCatW (dir, ARRAYSIZE(dir), L":\\");

	FormatExError = TRUE;
	FormatExErrorCommand = 0;

	// Windows sometimes fails to format a volume (hosted on a removable medium) as NTFS.
	// It often helps to retry several times.
	for (i = 0; i < 50 && FormatExError; i++)
	{
		FormatExError = FALSE;
		FormatExErrorCommand = 0;
		FormatEx (dir, FMIFS_REMOVAL, szFsFormat, szLabel, TRUE, clusterSize * FormatSectorSize, FormatExCallback);
	}

	// The device may be referenced for some time after FormatEx() returns
	Sleep (4000);

	FreeLibrary (hModule);

	if (FormatExError && bFallBackExternal)
	{
		return ExternalFormatFs (driveNo, clusterSize, fsType);
	}

	return FormatExError? FormatExErrorCommand : 0;
}

int FormatNtfs (int driveNo, int clusterSize, BOOL bFallBackExternal)
{
	return FormatFs (driveNo, clusterSize, FILESYS_NTFS, bFallBackExternal);
}

/* call Windows format.com program to perform formatting */
int ExternalFormatFs (int driveNo, int clusterSize, int fsType)
{
	wchar_t exePath[MAX_PATH] = {0};
	WCHAR szFsFormat[16];
	TCHAR szCmdline[2 * MAX_PATH];
	STARTUPINFO siStartInfo;
	PROCESS_INFORMATION piProcInfo;
	BOOL bSuccess = FALSE; 
	int iRet = 0;

	switch (fsType)
	{
		case FILESYS_NTFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"NTFS");
			break;
		case FILESYS_EXFAT:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"exFAT");
			break;
		case FILESYS_REFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"ReFS");
			break;
		default:
			return FALSE;
	}

	if (GetSystemDirectory (exePath, MAX_PATH))
	{
		StringCchCatW(exePath, ARRAYSIZE(exePath), L"\\format.com");
	}
	else
		StringCchCopyW(exePath, ARRAYSIZE(exePath), L"C:\\Windows\\System32\\format.com");
	
	StringCbPrintf (szCmdline, sizeof(szCmdline), L"%s %c: /FS:%s /Q /X /V:\"\" /Y", exePath, (WCHAR) driveNo + L'A', szFsFormat);
	
	if (clusterSize)
	{
		WCHAR szSize[8];
		uint32 unitSize = (uint32) clusterSize * FormatSectorSize;
		if (unitSize <= 8192)
			StringCbPrintf (szSize, sizeof (szSize), L"%d", unitSize);
		else if (unitSize < BYTES_PER_MB)
		{
			StringCbPrintf (szSize, sizeof (szSize), L"%dK", unitSize / BYTES_PER_KB);
		}
		else
			StringCbPrintf (szSize, sizeof (szSize), L"%dM", unitSize / BYTES_PER_MB);

		StringCbCat (szCmdline, sizeof (szCmdline), L" /A:");
		StringCbCat (szCmdline, sizeof (szCmdline), szSize);
	}

 
   ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) ); 

   /* Set up members of the STARTUPINFO structure. 
	*/ 
   ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
   siStartInfo.cb = sizeof(STARTUPINFO); 
   siStartInfo.wShowWindow = SW_HIDE;
   siStartInfo.dwFlags |= STARTF_USESHOWWINDOW;
 
   /* Create the child process.      */
   bSuccess = CreateProcess(NULL, 
      szCmdline,     // command line 
      NULL,          // process security attributes 
      NULL,          // primary thread security attributes 
      TRUE,          // handles are inherited 
      0,             // creation flags 
      NULL,          // use parent's environment 
      NULL,          // use parent's current directory 
      &siStartInfo,  // STARTUPINFO pointer 
      &piProcInfo);  // receives PROCESS_INFORMATION 

   if (bSuccess)
   {
	   DWORD dwExitCode;

	   /* wait for the format process to finish */
	   WaitForSingleObject (piProcInfo.hProcess, INFINITE);

	   /* check if it was successfull */	   
	   if (GetExitCodeProcess (piProcInfo.hProcess, &dwExitCode))
	   {
		   iRet = (int) dwExitCode; /* dwExitCode will be 0 in case of success */
	   }
	   else
		   iRet = (int) GetLastError();

	   CloseHandle (piProcInfo.hThread);
	   CloseHandle (piProcInfo.hProcess);
   }
   else
   {
	   iRet = (int) GetLastError();
   }

   return iRet;
}

BOOL WriteSector (void *dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     unsigned __int64 *nSecNo, unsigned __int64 startSector, PCRYPTO_INFO cryptoInfo)
{
	static __int32 updateTime = 0;

	(*nSecNo)++;

	memcpy (write_buf + *write_buf_cnt, sector, FormatSectorSize);
	(*write_buf_cnt) += FormatSectorSize;

	if (*write_buf_cnt == FormatWriteBufferSize && !FlushFormatWriteBuffer (dev, write_buf, write_buf_cnt, nSecNo, cryptoInfo))
		return FALSE;

	if (GetTickCount () - updateTime > 25)
	{
		if (UpdateProgressBar ((*nSecNo - startSector) * FormatSectorSize))
			return FALSE;

		updateTime = GetTickCount ();
	}

	return TRUE;

}


static volatile BOOL WriteThreadRunning;
static volatile BOOL WriteThreadExitRequested;
static HANDLE WriteThreadHandle;

static uint8 *WriteThreadBuffer;
static HANDLE WriteBufferEmptyEvent;
static HANDLE WriteBufferFullEvent;

static volatile HANDLE WriteRequestHandle;
static volatile int WriteRequestSize;
static volatile DWORD WriteRequestResult;


static void __cdecl FormatWriteThreadProc (void *arg)
{
	DWORD bytesWritten;

	SetThreadPriority (GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	while (!WriteThreadExitRequested)
	{
		if (WaitForSingleObject (WriteBufferFullEvent, INFINITE) == WAIT_FAILED)
		{
			handleWin32Error (NULL, SRC_POS);
			break;
		}

		if (WriteThreadExitRequested)
			break;

		if (!WriteFile (WriteRequestHandle, WriteThreadBuffer, WriteRequestSize, &bytesWritten, NULL))
			WriteRequestResult = GetLastError();
		else
			WriteRequestResult = ERROR_SUCCESS;

		if (!SetEvent (WriteBufferEmptyEvent))
		{
			handleWin32Error (NULL, SRC_POS);
			break;
		}
	}

	WriteThreadRunning = FALSE;
	_endthread();
}


static BOOL StartFormatWriteThread ()
{
	DWORD sysErr;

	WriteBufferEmptyEvent = NULL;
	WriteBufferFullEvent = NULL;
	WriteThreadBuffer = NULL;

	WriteBufferEmptyEvent = CreateEvent (NULL, FALSE, TRUE, NULL);
	if (!WriteBufferEmptyEvent)
		goto err;

	WriteBufferFullEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!WriteBufferFullEvent)
		goto err;

	WriteThreadBuffer = TCalloc (FormatWriteBufferSize);
	if (!WriteThreadBuffer)
	{
		SetLastError (ERROR_OUTOFMEMORY);
		goto err;
	}

	WriteThreadExitRequested = FALSE;
	WriteRequestResult = ERROR_SUCCESS;

	WriteThreadHandle = (HANDLE) _beginthread (FormatWriteThreadProc, 0, NULL);
	if ((uintptr_t) WriteThreadHandle == -1L)
		goto err;

	WriteThreadRunning = TRUE;
	return TRUE;

err:
	sysErr = GetLastError();

	if (WriteBufferEmptyEvent)
		CloseHandle (WriteBufferEmptyEvent);
	if (WriteBufferFullEvent)
		CloseHandle (WriteBufferFullEvent);
	if (WriteThreadBuffer)
		TCfree (WriteThreadBuffer);

	SetLastError (sysErr);
	return FALSE;
}


static void StopFormatWriteThread ()
{
	if (WriteThreadRunning)
	{
		WaitForSingleObject (WriteBufferEmptyEvent, INFINITE);

		WriteThreadExitRequested = TRUE;
		SetEvent (WriteBufferFullEvent);

		WaitForSingleObject (WriteThreadHandle, INFINITE);
	}

	CloseHandle (WriteBufferEmptyEvent);
	CloseHandle (WriteBufferFullEvent);
	TCfree (WriteThreadBuffer);
}


BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT unitNo;
	DWORD bytesWritten;

	if (*write_buf_cnt == 0)
		return TRUE;

	unitNo.Value = (*nSecNo * FormatSectorSize - *write_buf_cnt) / ENCRYPTION_DATA_UNIT_SIZE;

	EncryptDataUnits (write_buf, &unitNo, *write_buf_cnt / ENCRYPTION_DATA_UNIT_SIZE, cryptoInfo);

	if (WriteThreadRunning)
	{
		if (WaitForSingleObject (WriteBufferEmptyEvent, INFINITE) == WAIT_FAILED)
			return FALSE;

		if (WriteRequestResult != ERROR_SUCCESS)
		{
			SetEvent (WriteBufferEmptyEvent);
			SetLastError (WriteRequestResult);
			return FALSE;
		}

		memcpy (WriteThreadBuffer, write_buf, *write_buf_cnt);
		WriteRequestHandle = dev;
		WriteRequestSize = *write_buf_cnt;

		if (!SetEvent (WriteBufferFullEvent))
			return FALSE;
	}
	else
	{
		if (!WriteFile ((HANDLE) dev, write_buf, *write_buf_cnt, &bytesWritten, NULL))
			return FALSE;
	}

	*write_buf_cnt = 0;
	return TRUE;
}
