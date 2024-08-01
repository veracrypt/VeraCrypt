/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 and also from the source code of extcv, which is Copyright (c) 2009-2010 Kih-Oskh
 or Copyright (c) 2012-2013 Josef Schneider <josef@netpage.dk>

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <time.h>
#include <math.h>
#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windowsx.h>
#include <stdio.h>

#include "Apidrvr.h"
#include "Volumes.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Pkcs5.h"
#include "Random.h"
#include "Progress.h"

#include "InitDataArea.h"
#include "ExpandVolume.h"
#include "Resource.h"
#include <strsafe.h>

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

#define DEBUG_EXPAND_VOLUME

#ifdef DEBUG_EXPAND_VOLUME
#define DebugAddProgressDlgStatus  AddProgressDlgStatus
#else
#define DebugAddProgressDlgStatus(a,b)
#endif


HWND hCurPage;		/* Handle to window with progress bar (used by FormatNoFs)*/
int nPbar;			/* Control ID of progress bar (used by FormatNoFs) */
volatile BOOL bVolTransformThreadCancel = FALSE; /* TRUE if the user cancels/pauses volume expansion */

// internal functions
static int UpdateVolumeHeaderHostSize (wchar_t *lpszVolume, Password *pVolumePassword, HWND hwndDlg, uint64 newHostSize, uint64 *pDataSize, BOOL initFreeSpace);
static int FsctlExtendVolume(wchar_t * szVolume, LONGLONG nTotalSectors );


/*
	MountVolTemp

	Mounts a trucrypt volume temporarily (using any free drive number)

	Parameters:

		hwndDlg : HWND
			[in] handle to parent window

		volumePath : char *
			[in] Pointer to a string that contains the volume path

		driveNo : int *
			[out] returns the drive number (0='A',...)

		password : Password *
			[in] Pointer to the volume password

	Return value:

		int with Truecrypt error code (ERR_SUCCESS on success)

*/
int MountVolTemp (HWND hwndDlg, wchar_t *volumePath, int *driveNo, Password *password, int pkcs5, int pim)
{
	MountOptions mountOptions;
	ZeroMemory (&mountOptions, sizeof (mountOptions));

	*driveNo = GetLastAvailableDrive ();

	if (*driveNo == -1)
	{
		*driveNo = -2;
		return ERR_NO_FREE_DRIVES;
	}

	mountOptions.ReadOnly = FALSE;
	mountOptions.Removable = ConfigReadInt ("MountVolumesRemovable", FALSE);
	mountOptions.ProtectHiddenVolume = FALSE;
	mountOptions.PreserveTimestamp = bPreserveTimestamp;
	mountOptions.PartitionInInactiveSysEncScope = FALSE;
	mountOptions.UseBackupHeader = FALSE;

	if (MountVolume (hwndDlg, *driveNo, volumePath, password, pkcs5, pim, FALSE, FALSE, TRUE, &mountOptions, FALSE, FALSE) < 1)
	{
		*driveNo = -3;
		return ERR_VOL_MOUNT_FAILED;
	}
	return 0;
}


/*
	FsctlExtendVolume

	Expands a volume by sending the FSCTL_EXTEND_VOLUME ioctl command to the volume

	Parameters:

		szVolume : char *
			[in] Pointer to a string that contains the volume GUID

		nTotalSectors : LONGLONG
			[in] specifies the total size of the volume, in sectors

	Return value:

		int with Truecrypt error code (ERR_SUCCESS on success)

	Remarks: only supported by NTFS and RAW file systems

*/
static int FsctlExtendVolume(wchar_t * szVolume, LONGLONG nTotalSectors )
{
	HANDLE hDevice;   // handle to the volume to be extended
	BOOL bResult;     // results flag
	DWORD nbytes;     // discard results
	DWORD dwError;
	int nStatus = ERR_OS_ERROR;

	hDevice = CreateFile(szVolume,
					GENERIC_READ,
					FILE_SHARE_READ |
					FILE_SHARE_WRITE,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
		goto error;

	bResult = DeviceIoControl(hDevice,
							FSCTL_EXTEND_VOLUME,
							&nTotalSectors, sizeof(nTotalSectors),
							NULL, 0,
							&nbytes,
							(LPOVERLAPPED) NULL);

	if (bResult)
		nStatus = ERR_SUCCESS;

error:

	dwError = GetLastError ();

	if (hDevice != INVALID_HANDLE_VALUE)
		CloseHandle (hDevice);

	SetLastError (dwError);

	return nStatus;
}


BOOL GetFileSystemType(const wchar_t *szFileName, enum EV_FileSystem *pFS)
{
	wchar_t szFS[256];
	wchar_t root[MAX_PATH];

	*pFS = EV_FS_TYPE_RAW;

	if (!GetVolumePathName (szFileName, root, ARRAYSIZE (root)))
		return FALSE;

	if ( GetVolumeInformation (root, NULL, 0, NULL, NULL, NULL, szFS, ARRAYSIZE(szFS)) )
	{
		if (!wcsncmp (szFS, L"NTFS", 4))
			*pFS = EV_FS_TYPE_NTFS;
		else if (!wcsncmp (szFS, L"FAT", 3)) // FAT16, FAT32
			*pFS = EV_FS_TYPE_FAT;
		else if (!_wcsnicmp (szFS, L"exFAT", 5)) // exFAT
			*pFS = EV_FS_TYPE_EXFAT;
		else
			*pFS = EV_FS_TYPE_RAW;
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

/*
	QueryVolumeInfo

	Retrieves the free disk space and file size limit on the truecrypt volume host

	Parameters:

		hwndDlg : HWND
			[in] handle to parent window

		lpszVolume : char *
			[in] Pointer to a string that contains the volume path

		pHostSizeFree : uint64 *
			[out] returns the free space available on the host (always zero for devices)

		pSizeLimitFS : uint64 *
			[out] returns the file size limit of the host file system

	Return value:

		int with TrueCrypt error code (ERR_SUCCESS on success)

*/
int QueryVolumeInfo (HWND hwndDlg, const wchar_t *lpszVolume, uint64 * pHostSizeFree, uint64 * pSizeLimitFS )
{
	int nStatus = ERR_OS_ERROR;
	wchar_t szDiskFile[TC_MAX_PATH], root[MAX_PATH];
	BOOL bDevice;
	enum EV_FileSystem fs;

	*pSizeLimitFS = (uint64)-1;

	CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), lpszVolume, &bDevice);

	if (bDevice)
	{
		*pHostSizeFree=0;
		return ERR_SUCCESS;
	}

	if (!GetVolumePathName (szDiskFile, root, ARRAYSIZE (root)))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if( ! GetDiskFreeSpaceEx (root,(PULARGE_INTEGER)pHostSizeFree,NULL,NULL) )
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if ( ! GetFileSystemType(root,&fs) )
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	/*	file size limits
		FAT16 / FAT32 :	4 GB minus 1 byte (2^32 bytes minus 1 byte)
		exFAT: 128 PiB − 1 byte
		NTFS :	Architecturally : 16 exabytes minus 1 KB (26^4 bytes minus 1 KB)
				Implementation (Windows Server 2008): 16 terabytes minus 64 KB (2^44 bytes minus 64 KB)
	*/
	switch (fs)
	{
	case EV_FS_TYPE_NTFS:
		*pSizeLimitFS = 16 * BYTES_PER_TB - 64 * BYTES_PER_KB;
		break;
	case EV_FS_TYPE_EXFAT:
		*pSizeLimitFS = 128 * BYTES_PER_PB - 1;
		break;
	case EV_FS_TYPE_FAT:
		*pSizeLimitFS = 4 * BYTES_PER_GB - 1;
		break;
	default:
		*pSizeLimitFS = (uint64)-1;
	}

	nStatus = ERR_SUCCESS;

error:

	return nStatus;
}

BOOL GetNtfsNumberOfSectors(wchar_t * rootPath, uint64 * pNumberOfSectors, DWORD *pBytesPerSector)
{
	HANDLE hDevice;
	BOOL bResult;
	DWORD nbytes, dwError;
	size_t len;
	NTFS_VOLUME_DATA_BUFFER ntfsvdb;
	wchar_t szVolumeGUID[128];

	// get volume name
	if (!GetVolumeNameForVolumeMountPoint(rootPath,szVolumeGUID,ARRAYSIZE(szVolumeGUID)))
	{
		return FALSE;
	}

	// strip trailing backslash from volume GUID (otherwise it means root dir)
	len = wcslen(szVolumeGUID);
	if (len>0)
		--len;
	if (szVolumeGUID[len]==L'\\')
		szVolumeGUID[len]=0;

	hDevice = CreateFile(szVolumeGUID,
					GENERIC_READ,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
		return (FALSE);

	bResult = DeviceIoControl(hDevice,
							FSCTL_GET_NTFS_VOLUME_DATA,
							 NULL, 0,
							&ntfsvdb, sizeof(ntfsvdb),
							&nbytes,
							(LPOVERLAPPED) NULL);

	if (bResult)
	{
		if (pNumberOfSectors)
			*pNumberOfSectors = ntfsvdb.NumberSectors.QuadPart;
		if (pBytesPerSector)
			*pBytesPerSector = ntfsvdb.BytesPerSector;
	}

	dwError = GetLastError ();
	CloseHandle(hDevice);
	SetLastError (dwError);

	return (bResult);
}


uint64 GetVolumeDataAreaSize (uint64 volumeSize, BOOL legacyVolume)
{
	uint64 reservedSize;

	if (legacyVolume)
		reservedSize = TC_VOLUME_HEADER_SIZE_LEGACY;
	else
		reservedSize = TC_TOTAL_VOLUME_HEADERS_SIZE;

	if (volumeSize < reservedSize)
		return 0;

	return volumeSize - reservedSize;
}


uint64 GetVolumeSizeByDataAreaSize (uint64 dataAreaSize, BOOL legacyVolume)
{
	uint64 reservedSize;

	if (legacyVolume)
		reservedSize = TC_VOLUME_HEADER_SIZE_LEGACY;
	else
		reservedSize = TC_TOTAL_VOLUME_HEADERS_SIZE;

	return dataAreaSize + reservedSize;
}


int ExtendFileSystem (HWND hwndDlg , wchar_t *lpszVolume, Password *pVolumePassword, int VolumePkcs5, int VolumePim, uint64 newDataAreaSize)
{
	wchar_t szVolumeGUID[128];
	int driveNo = -1;
	wchar_t rootPath[] = L"A:\\";
	enum EV_FileSystem fs;
	DWORD dwError;
	int nStatus = ERR_SUCCESS;
	DWORD BytesPerSector;

	// mount and resize file system

	DebugAddProgressDlgStatus (hwndDlg, GetString("EXPANDER_MOUNTING_VOLUME"));

	nStatus=MountVolTemp(hwndDlg, lpszVolume, &driveNo, pVolumePassword, VolumePkcs5, VolumePim);
	if (nStatus!=ERR_SUCCESS)
	{
		driveNo = -1;
		goto error;
	}

	rootPath[0] += driveNo;

	if ( !GetFileSystemType(rootPath,&fs) )
	{
		dwError = GetLastError();
		if (dwError == ERROR_UNRECOGNIZED_VOLUME)
		{
			// raw volume with unrecognized file system -> return with no error
			nStatus = ERR_SUCCESS;
			goto error;
		}
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if (fs != EV_FS_TYPE_RAW && fs != EV_FS_TYPE_NTFS )
	{
		// FsctlExtendVolume only supports NTFS and RAW -> return with no error
		nStatus = ERR_SUCCESS;
		goto error;
	}

	// Get volume GUID
	if (!GetVolumeNameForVolumeMountPoint(rootPath,szVolumeGUID,ARRAYSIZE(szVolumeGUID)))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}
	else
	{
		// strip trailing backslash from volume GUID (otherwise it means root dir)
		size_t len = wcslen(szVolumeGUID);
		if (len>0) --len;
		if (szVolumeGUID[len]==L'\\') szVolumeGUID[len]=0;
	}

	// Get Sector Size
	if ( !GetNtfsNumberOfSectors(rootPath, NULL, &BytesPerSector) )
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if ((BytesPerSector == 0) || (BytesPerSector > (DWORD)INT_MAX))
	{
		nStatus = ERR_SECTOR_SIZE_INCOMPATIBLE;
		goto error;
	}

	DebugAddProgressDlgStatus (hwndDlg, GetString("EXPANDER_EXTENDING_FILESYSTEM"));

	// extend volume
	nStatus = FsctlExtendVolume(szVolumeGUID, newDataAreaSize/BytesPerSector );

error:

	dwError = GetLastError();

	if (driveNo>=0)
	{
		DebugAddProgressDlgStatus (hwndDlg, GetString("EXPANDER_UNMOUNTING_VOLUME"));
		UnmountVolume (hwndDlg, driveNo, TRUE);
	}

	SetLastError (dwError);

	return nStatus;
}

/*
	ExpandVolume

	Sets the volume size in the volume header (and backup header) to a larger value,
	and resizes the filesystem within the volume (only NTFS supported)

	Parameters:

		hwndDlg : HWND
			[in] handle to progress dialog

		lpszVolume : char *
			[in] Pointer to a string that contains the path to the truecrypt volume

		pVolumePassword : Password *
			[in] Pointer to the volume password

		newHostSize : uint64
			[in] new value of the volume host size (can be zero for devices,
			     which means the volume should use all space of the host device)

		initFreeSpace : BOOL
			[in] if true, the new volume space will be initalized with random data

	Return value:

		int with Truecrypt error code (ERR_SUCCESS on success)

	Remarks: a lot of code is from TrueCrypt 'Common\Password.c' :: ChangePwd()

*/
static int ExpandVolume (HWND hwndDlg, wchar_t *lpszVolume, Password *pVolumePassword, int VolumePkcs5, int VolumePim, uint64 newHostSize, BOOL initFreeSpace, BOOL bQuickExpand)
{
	int nDosLinkCreated = 1, nStatus = ERR_OS_ERROR;
	wchar_t szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	wchar_t szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	DWORD bytesRead;
	BOOL bDevice;
	uint64 hostSize=0, newDataAreaSize, currentVolSize;
	DWORD HostSectorSize;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	LARGE_INTEGER headerOffset;
	BOOL backupHeader;
	uint8 *wipeBuffer = NULL;
	uint32 workChunkSize = TC_VOLUME_HEADER_GROUP_SIZE;
#ifdef _WIN64
	CRYPTO_INFO tmpCI;
	PCRYPTO_INFO cryptoInfoBackup = NULL;
	BOOL bIsRamEncryptionEnabled = IsRamEncryptionEnabled();
#endif

	if (pVolumePassword->Length == 0) return -1;

	WaitCursor ();

	CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		StringCchCopyW (szCFDevice, ARRAYSIZE(szCFDevice), szDiskFile);
	}
	else
	{
		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, sizeof(szDosDevice), szCFDevice, sizeof(szCFDevice), FALSE);

		if (nDosLinkCreated != 0) // note: nStatus == ERR_OS_ERROR
			goto error;
	}

	dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (dev == INVALID_HANDLE_VALUE)
		goto error;
	else if (!bDevice && bPreserveTimestamp)
	{
		// ensure that Last Access and Last Time timestamps are not modified
		// in order to preserve plausible deniability of hidden volumes (last password change time is stored in the volume header).
		ftLastAccessTime.dwHighDateTime = 0xFFFFFFFF;
		ftLastAccessTime.dwLowDateTime = 0xFFFFFFFF;

		SetFileTime (dev, NULL, &ftLastAccessTime, NULL);

		/* Remember the container modification/creation date and time, (used to reset file date and time of
		file-hosted volumes after password change (or attempt to), in order to preserve plausible deniability
		of hidden volumes (last password change time is stored in the volume header). */

		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
		{
			bTimeStampValid = FALSE;
			MessageBoxW (hwndDlg, GetString ("GETFILETIME_FAILED_PW"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
		}
		else
			bTimeStampValid = TRUE;
	}

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			goto error;
		}
		else
		{
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = GetPartitionInfo (lpszVolume, &diskInfo);

			if (bResult)
			{
				hostSize = diskInfo.PartitionLength.QuadPart;
				HostSectorSize = TC_SECTOR_SIZE_FILE_HOSTED_VOLUME; //TO DO: get the real host disk sector size
			}
			else
			{
				BYTE dgBuffer[256];

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
					dgBuffer, sizeof (dgBuffer), &dwResult, NULL);

				if (!bResult)
				{
					DISK_GEOMETRY geo;
					if (DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, (LPVOID) &geo, sizeof (geo), &dwResult, NULL))
					{
						hostSize = geo.Cylinders.QuadPart * geo.SectorsPerTrack * geo.TracksPerCylinder * geo.BytesPerSector;
						HostSectorSize = geo.BytesPerSector;

						if (CurrentOSMajor >= 6)
						{
							STORAGE_READ_CAPACITY storage = {0};

							storage.Version = sizeof (STORAGE_READ_CAPACITY);
							storage.Size = sizeof (STORAGE_READ_CAPACITY);
							if (DeviceIoControl (dev, IOCTL_STORAGE_READ_CAPACITY, NULL, 0, (LPVOID) &storage, sizeof (storage), &dwResult, NULL)
								&& (dwResult >= sizeof (storage))
								&& (storage.Size == sizeof (STORAGE_READ_CAPACITY))
								)
							{
								hostSize = storage.DiskLength.QuadPart;
							}
						}
					}
					else
					{
						goto error;
					}
				}
				else
				{
					hostSize = ((PDISK_GEOMETRY_EX) dgBuffer)->DiskSize.QuadPart;
					HostSectorSize = ((PDISK_GEOMETRY_EX) dgBuffer)->Geometry.BytesPerSector;
				}
			}

			if (hostSize == 0)
			{
				nStatus = ERR_VOL_SIZE_WRONG;
				goto error;
			}
		}
	}
	else
	{
		LARGE_INTEGER fileSize;
		if (!GetFileSizeEx (dev, &fileSize))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		hostSize = fileSize.QuadPart;
		HostSectorSize = TC_SECTOR_SIZE_FILE_HOSTED_VOLUME; //TO DO: get the real host disk sector size
	}

	if (Randinit ())
	{
		if (CryptoAPILastError == ERROR_SUCCESS)
			nStatus = ERR_RAND_INIT_FAILED;
		else
			nStatus = ERR_CAPI_INIT_FAILED;
		goto error;
	}


	// Seek the volume header
	headerOffset.QuadPart = TC_VOLUME_HEADER_OFFSET;

	if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	/* Read in volume header */
	if (!ReadEffectiveVolumeHeader (bDevice, dev, buffer, &bytesRead))
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	if (bytesRead != sizeof (buffer))
	{
		// Windows may report EOF when reading sectors from the last cluster of a device formatted as NTFS
		memset (buffer, 0, sizeof (buffer));
	}

	/* Try to decrypt the header */

	nStatus = ReadVolumeHeader (FALSE, buffer, pVolumePassword, VolumePkcs5, VolumePim, &cryptoInfo, NULL);
	if (nStatus == ERR_CIPHER_INIT_WEAK_KEY)
		nStatus = 0;	// We can ignore this error here

	// if the volume master key is vulnerable, print a warning to inform the user
	if (cryptoInfo->bVulnerableMasterKey)
	{
		DebugAddProgressDlgStatus(hwndDlg, GetString ("ERR_XTS_MASTERKEY_VULNERABLE_SHORT"));
	}

	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

#ifdef _WIN64
	if (bIsRamEncryptionEnabled)
	{
		VcProtectKeys (cryptoInfo, VcGetEncryptionID (cryptoInfo));
	}
#endif

	if (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)
	{
		nStatus = ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG;
		goto error;
	}

	if (bDevice && newHostSize == 0)
	{
		// this means we shall take all host space as new volume size
		newHostSize = hostSize;
	}

	if ( newHostSize % cryptoInfo->SectorSize != 0  || newHostSize > TC_MAX_VOLUME_SIZE || (bDevice && newHostSize > hostSize) )
	{
		// 1. must be multiple of sector size
		// 2. truecrypt volume size limit
		// 3. for devices volume size can't be larger than host size
		cryptoInfo = NULL;
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	newDataAreaSize = GetVolumeDataAreaSize (newHostSize, cryptoInfo->LegacyVolume);

	if (cryptoInfo->LegacyVolume)
	{
		if (bDevice)
		{
			if (initFreeSpace)
			{
				// unsupported
				cryptoInfo = NULL;
				nStatus = ERR_PARAMETER_INCORRECT;
				goto error;
			}
			else
			{
				// note: dummy value (only used for parameter checks)
				cryptoInfo->VolumeSize.Value = newDataAreaSize - TC_MINVAL_FS_EXPAND;
			}
		}
		else
		{
			cryptoInfo->VolumeSize.Value = GetVolumeDataAreaSize (hostSize, TRUE);
		}
	}

	currentVolSize = GetVolumeSizeByDataAreaSize (cryptoInfo->VolumeSize.Value, cryptoInfo->LegacyVolume);

	if ( newDataAreaSize < cryptoInfo->VolumeSize.Value + TC_MINVAL_FS_EXPAND )
	{
		// shrinking a volume or enlarging by less then TC_MINVAL_FS_EXPAND is not allowed
		cryptoInfo = NULL;
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	InitProgressBar ( newHostSize, currentVolSize, FALSE, FALSE, FALSE, TRUE);

	if (bVolTransformThreadCancel)
	{
		SetLastError(0);
		nStatus = ERR_USER_ABORT;
		goto error;
	}

	if (!bDevice) {
		LARGE_INTEGER liNewSize;

		liNewSize.QuadPart=(LONGLONG)newHostSize;

		if (hostSize != newHostSize)
		{
			// Preallocate the file
			if (!SetFilePointerEx (dev, liNewSize, NULL, FILE_BEGIN)
				|| !SetEndOfFile (dev))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (bQuickExpand)
			{
				if (!SetFileValidData (dev, liNewSize.QuadPart))
				{
					DebugAddProgressDlgStatus(hwndDlg, L"Warning: Failed to perform Quick Expand. Continuing with standard expanding...\r\n");
				}
			}

			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
		else
		{
			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}

	if (initFreeSpace)
	{
		uint64 startSector;
		int64 num_sectors;

		// fill new space with random data
		startSector = currentVolSize/HostSectorSize ;
		num_sectors = (newHostSize/HostSectorSize) - startSector;

		if (bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		DebugAddProgressDlgStatus(hwndDlg, GetString ("EXPANDER_WRITING_RANDOM_DATA"));

		SetFormatSectorSize(HostSectorSize);
		nStatus = FormatNoFs (hwndDlg, startSector, num_sectors, dev, cryptoInfo, FALSE);

		dwError = GetLastError();
		StopFormatWriteThread();
		SetLastError (dwError);
	}
	else
	{
		UpdateProgressBar(newHostSize);
	}

	if (nStatus != ERR_SUCCESS)
	{
		dwError = GetLastError();
		DebugAddProgressDlgStatus(hwndDlg, L"Error: failed to write random data ...\r\n");
		if ( !bDevice ) {
			// restore original size of the container file
			LARGE_INTEGER liOldSize;
			liOldSize.QuadPart=(LONGLONG)hostSize;
			if (!SetFilePointerEx (dev, liOldSize, NULL, FILE_BEGIN) || !SetEndOfFile (dev))
			{
				DebugAddProgressDlgStatus(hwndDlg, L"Warning: failed to restore original size of the container file\r\n");
			}
		}
		SetLastError (dwError);
		goto error;
	}

	RandSetHashFunction (cryptoInfo->pkcs5);

	// Re-encrypt the volume header forn non-legacy volumes: backup header first
	backupHeader = TRUE;
	headerOffset.QuadPart = TC_VOLUME_HEADER_OFFSET + newHostSize - TC_VOLUME_HEADER_GROUP_SIZE;

	/* note: updating the header is not neccessary for legay volumes */
	while ( !cryptoInfo->LegacyVolume )
	{
		if (backupHeader)
			DebugAddProgressDlgStatus(hwndDlg, GetString("EXPANDER_WRITING_ENCRYPTED_BACKUP"));
		else
			DebugAddProgressDlgStatus(hwndDlg, GetString("EXPANDER_WRITING_ENCRYPTED_PRIMARY"));

#ifdef _WIN64
		if (bIsRamEncryptionEnabled)
		{
			VirtualLock (&tmpCI, sizeof (CRYPTO_INFO));
			memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
			VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
			cryptoInfoBackup = cryptoInfo;
			cryptoInfo = &tmpCI;
		}
#endif

		// Prepare new volume header
		nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
			buffer,
			cryptoInfo->ea,
			cryptoInfo->mode,
			pVolumePassword,
			cryptoInfo->pkcs5,
			VolumePim,
			(char*)(cryptoInfo->master_keydata),
			&ci,
			newDataAreaSize,
			0, // hiddenVolumeSize
			cryptoInfo->EncryptedAreaStart.Value,
			newDataAreaSize,
			cryptoInfo->RequiredProgramVersion,
			cryptoInfo->HeaderFlags,
			cryptoInfo->SectorSize,
			FALSE ); // use slow poll

#ifdef _WIN64
		if (bIsRamEncryptionEnabled)
		{
			cryptoInfo = cryptoInfoBackup;
			burn (&tmpCI, sizeof (CRYPTO_INFO));
			VirtualUnlock (&tmpCI, sizeof (CRYPTO_INFO));
		}
#endif

		if (ci != NULL)
			crypto_close (ci);

		if (nStatus != 0)
			goto error;

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (!WriteEffectiveVolumeHeader (bDevice, dev, buffer))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if ( ( backupHeader && !initFreeSpace )
			|| ( bDevice
				&& !cryptoInfo->LegacyVolume
				&& !cryptoInfo->hiddenVolume
				&& cryptoInfo->HeaderVersion == 4	// BUG in TrueCrypt: doing this only for v4 make no sense
				&& (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
				&& (cryptoInfo->HeaderFlags & ~TC_HEADER_FLAG_NONSYS_INPLACE_ENC) == 0 )
			)
		{
			//DebugAddProgressDlgStatus(hwndDlg, L"WriteRandomDataToReservedHeaderAreas() ...\r\n");
			PCRYPTO_INFO dummyInfo = NULL;
			LARGE_INTEGER hiddenOffset;

#ifdef _WIN64
			if (bIsRamEncryptionEnabled)
			{
				VirtualLock (&tmpCI, sizeof (CRYPTO_INFO));
				memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
				VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
				cryptoInfoBackup = cryptoInfo;
				cryptoInfo = &tmpCI;
			}
#endif

			nStatus = WriteRandomDataToReservedHeaderAreas (hwndDlg, dev, cryptoInfo, newDataAreaSize, !backupHeader, backupHeader);
#ifdef _WIN64
			if (bIsRamEncryptionEnabled)
			{
				cryptoInfo = cryptoInfoBackup;
				burn (&tmpCI, sizeof (CRYPTO_INFO));
				VirtualUnlock (&tmpCI, sizeof (CRYPTO_INFO));
			}
#endif
			if (nStatus != ERR_SUCCESS)
				goto error;

			// write fake hidden volume header to protect against attacks that use statistical entropy
			// analysis to detect presence of hidden volumes
			hiddenOffset.QuadPart = headerOffset.QuadPart + TC_HIDDEN_VOLUME_HEADER_OFFSET;

			nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				buffer,
				cryptoInfo->ea,
				cryptoInfo->mode,
				NULL,
				0,
				0,
				NULL,
				&dummyInfo,
				newDataAreaSize,
				newDataAreaSize, // hiddenVolumeSize
				cryptoInfo->EncryptedAreaStart.Value,
				newDataAreaSize,
				cryptoInfo->RequiredProgramVersion,
				cryptoInfo->HeaderFlags,
				cryptoInfo->SectorSize,
				FALSE ); // use slow poll

			if (nStatus != ERR_SUCCESS)
				goto error;

			crypto_close (dummyInfo);

			if (!SetFilePointerEx ((HANDLE) dev, hiddenOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (bDevice, dev, buffer))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}

		FlushFileBuffers (dev);

		if (!backupHeader)
			break;

		backupHeader = FALSE;
		headerOffset.QuadPart = TC_VOLUME_HEADER_OFFSET; // offset for main header
	}

	/* header successfully updated */
	nStatus = ERR_SUCCESS;

	if (bVolTransformThreadCancel)
	{
		nStatus = ERR_USER_ABORT;
		goto error;
	}

	/* wipe old backup header */
	if ( !cryptoInfo->LegacyVolume )
	{
		uint8 wipeRandChars [TC_WIPE_RAND_CHAR_COUNT];
		uint8 wipeRandCharsUpdate [TC_WIPE_RAND_CHAR_COUNT];
		uint8 wipePass;
		UINT64_STRUCT unitNo;
		LARGE_INTEGER offset;
		WipeAlgorithmId wipeAlgorithm = TC_WIPE_35_GUTMANN;

		if (	!RandgetBytes (hwndDlg, wipeRandChars, TC_WIPE_RAND_CHAR_COUNT, TRUE)
			|| !RandgetBytes (hwndDlg, wipeRandCharsUpdate, TC_WIPE_RAND_CHAR_COUNT, TRUE)
			)
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		DebugAddProgressDlgStatus(hwndDlg, GetString("EXPANDER_WIPING_OLD_HEADER"));

		wipeBuffer = (uint8 *) TCalloc (workChunkSize);
		if (!wipeBuffer)
		{
			nStatus = ERR_OUTOFMEMORY;
			goto error;
		}

		offset.QuadPart = currentVolSize - TC_VOLUME_HEADER_GROUP_SIZE;
		unitNo.Value = offset.QuadPart;

		for (wipePass = 1; wipePass <= GetWipePassCount (wipeAlgorithm); ++wipePass)
		{
			if (!WipeBuffer (wipeAlgorithm, wipeRandChars, wipePass, wipeBuffer, workChunkSize))
			{
				ULONG i;
				for (i = 0; i < workChunkSize; ++i)
				{
					wipeBuffer[i] = wipePass;
				}

				EncryptDataUnits (wipeBuffer, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, cryptoInfo);
				memcpy (wipeRandCharsUpdate, wipeBuffer, sizeof (wipeRandCharsUpdate));
			}

			if ( !SetFilePointerEx (dev, offset, NULL, FILE_BEGIN)
				|| _lwrite ((HFILE)dev, (LPCSTR)wipeBuffer, workChunkSize) == HFILE_ERROR
				)
			{
				// Write error
				DebugAddProgressDlgStatus(hwndDlg, L"Warning: Failed to wipe old backup header\r\n");
				MessageBoxW (hwndDlg, L"WARNING: Failed to wipe old backup header!\n\nIt may be possible to use the current volume password to decrypt the old backup header even after a future password change.\n", lpszTitle, MB_OK | MB_ICONEXCLAMATION);
				if (wipePass == 1)
					continue; // retry once
				// non-critical error - it's better to continue
				nStatus = ERR_SUCCESS;
				goto error;
			}
			FlushFileBuffers(dev);
			// we don't check FlushFileBuffers() return code, because it fails for devices
			// (same implementation in password.c - a bug or not ???)
		}

		burn (wipeRandChars, TC_WIPE_RAND_CHAR_COUNT);
		burn (wipeRandCharsUpdate, TC_WIPE_RAND_CHAR_COUNT);
	}

error:
	dwError = GetLastError ();

	if (wipeBuffer)
	{
		burn (wipeBuffer, workChunkSize);
		TCfree (wipeBuffer);
		wipeBuffer = NULL;
	}

	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	if (bTimeStampValid)
	{
		// Restore the container timestamp (to preserve plausible deniability of possible hidden volume).
		if (SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			MessageBoxW (hwndDlg, GetString ("SETFILETIME_FAILED_PW"), lpszTitle, MB_OK | MB_ICONEXCLAMATION);
	}

	if (dev != INVALID_HANDLE_VALUE)
		CloseHandle ((HANDLE) dev);

	if (nDosLinkCreated == 0)
		RemoveFakeDosName (szDiskFile, szDosDevice);

	RandStop (FALSE);

	if (bVolTransformThreadCancel)
		nStatus = ERR_USER_ABORT;

	SetLastError (dwError);

	if (nStatus == ERR_SUCCESS)
	{
		nStatus = ExtendFileSystem (hwndDlg, lpszVolume, pVolumePassword, VolumePkcs5, VolumePim, newDataAreaSize);
	}

	return nStatus;
}



void __cdecl volTransformThreadFunction (void *pExpandDlgParam)
{
	int nStatus;
	EXPAND_VOL_THREAD_PARAMS *pParam=(EXPAND_VOL_THREAD_PARAMS *)pExpandDlgParam;
	HWND hwndDlg = (HWND) pParam->hwndDlg;

	nStatus = ExpandVolume (hwndDlg, (wchar_t*)pParam->szVolumeName, pParam->pVolumePassword,
		pParam->VolumePkcs5, pParam->VolumePim, pParam->newSize, pParam->bInitFreeSpace, pParam->bQuickExpand );

	if (nStatus!=ERR_SUCCESS && nStatus!=ERR_USER_ABORT)
			handleError (hwndDlg, nStatus, SRC_POS);

	bVolTransformThreadCancel = FALSE;

	PostMessage (hwndDlg, TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED, 0, nStatus);

	_endthread ();
}
