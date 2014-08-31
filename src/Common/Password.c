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

#include "Crypto.h"
#include "Volumes.h"
#include "Password.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Pkcs5.h"
#include "Endian.h"
#include "Random.h"

#include <io.h>

void VerifyPasswordAndUpdate (HWND hwndDlg, HWND hButton, HWND hPassword,
			 HWND hVerify, unsigned char *szPassword,
			 char *szVerify,
			 BOOL keyFilesEnabled)
{
	char szTmp1[MAX_PASSWORD + 1];
	char szTmp2[MAX_PASSWORD + 1];
	int k = GetWindowTextLength (hPassword);
	BOOL bEnable = FALSE;

	if (hwndDlg);		/* Remove warning */

	GetWindowText (hPassword, szTmp1, sizeof (szTmp1));
	GetWindowText (hVerify, szTmp2, sizeof (szTmp2));

	if (strcmp (szTmp1, szTmp2) != 0)
		bEnable = FALSE;
	else
	{
		if (k >= MIN_PASSWORD || keyFilesEnabled)
			bEnable = TRUE;
		else
			bEnable = FALSE;
	}

	if (szPassword != NULL)
		memcpy (szPassword, szTmp1, sizeof (szTmp1));

	if (szVerify != NULL)
		memcpy (szVerify, szTmp2, sizeof (szTmp2));

	burn (szTmp1, sizeof (szTmp1));
	burn (szTmp2, sizeof (szTmp2));

	EnableWindow (hButton, bEnable);
}


BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw)
{
	int i, len;
	
	if (hPassword == NULL)
	{
		if (ptrPw)
		{
			unsigned char *pw;
			len = ptrPw->Length;
			pw = (unsigned char *) ptrPw->Text;

			for (i = 0; i < len; i++)
			{
				if (pw[i] >= 0x7f || pw[i] < 0x20)	// A non-ASCII or non-printable character?
					return FALSE;
			}
		}
		else
			return FALSE;
	}
	else
	{
		wchar_t s[MAX_PASSWORD + 1];
		len = GetWindowTextLength (hPassword);

		if (len > MAX_PASSWORD)
			return FALSE; 

		GetWindowTextW (hPassword, s, sizeof (s) / sizeof (wchar_t));

		for (i = 0; i < len; i++)
		{
			if (s[i] >= 0x7f || s[i] < 0x20)	// A non-ASCII or non-printable character?
				break;
		}

		burn (s, sizeof(s));

		if (i < len)
			return FALSE; 
	}

	return TRUE;
}


BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem)
{
	if (GetWindowTextLength (hwndItem) < PASSWORD_LEN_WARNING)
	{
#ifndef _DEBUG
		if (MessageBoxW (hwndDlg, GetString ("PASSWORD_LENGTH_WARNING"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES)
			return FALSE;
#endif
	}
	return TRUE;
}

int ChangePwd (const char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, int wipePassCount, HWND hwndDlg)
{
	int nDosLinkCreated = 1, nStatus = ERR_OS_ERROR;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	DWORD bytesRead;
	BOOL bDevice;
	unsigned __int64 hostSize = 0;
	int volumeType;
	int wipePass;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	LARGE_INTEGER headerOffset;
	BOOL backupHeader;
	DISK_GEOMETRY driveInfo;

	if (oldPassword->Length == 0 || newPassword->Length == 0) return -1;

	if (wipePassCount <= 0)
	{
      nStatus = ERR_PARAMETER_INCORRECT;
      handleError (hwndDlg, nStatus);
      return nStatus;
	}

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus);
      return nStatus;
   }

	WaitCursor ();

	CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		strcpy (szCFDevice, szDiskFile);
	}
	else
	{
		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, sizeof(szDosDevice), szCFDevice, sizeof(szCFDevice),FALSE);
		
		if (nDosLinkCreated != 0)
			goto error;
	}

	dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (dev == INVALID_HANDLE_VALUE) 
		goto error;

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

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
				&driveInfo, sizeof (driveInfo), &dwResult, NULL);

			if (!bResult)
				goto error;

			bResult = GetPartitionInfo (lpszVolume, &diskInfo);

			if (bResult)
			{
				hostSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				hostSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
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
	}

	if (Randinit ())
		goto error;

	if (!bDevice && bPreserveTimestamp)
	{
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	for (volumeType = TC_VOLUME_TYPE_NORMAL; volumeType < TC_VOLUME_TYPE_COUNT; volumeType++)
	{
		// Seek the volume header
		switch (volumeType)
		{
		case TC_VOLUME_TYPE_NORMAL:
			headerOffset.QuadPart = TC_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN:
			if (TC_HIDDEN_VOLUME_HEADER_OFFSET + TC_VOLUME_HEADER_SIZE > hostSize)
				continue;

			headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN_LEGACY:
			if (bDevice && driveInfo.BytesPerSector != TC_SECTOR_SIZE_LEGACY)
				continue;

			headerOffset.QuadPart = hostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY;
			break;
		}

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

		nStatus = ReadVolumeHeader (FALSE, buffer, oldPassword, &cryptoInfo, NULL);
		if (nStatus == ERR_CIPHER_INIT_WEAK_KEY)
			nStatus = 0;	// We can ignore this error here

		if (nStatus == ERR_PASSWORD_WRONG)
		{
			continue;		// Try next volume type
		}
		else if (nStatus != 0)
		{
			cryptoInfo = NULL;
			goto error;
		}
		else 
			break;
	}

	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	if (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)
	{
		nStatus = ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG;
		goto error;
	}

	// Change the PKCS-5 PRF if requested by user
	if (pkcs5 != 0)
		cryptoInfo->pkcs5 = pkcs5;

	RandSetHashFunction (cryptoInfo->pkcs5);

	NormalCursor();
	UserEnrichRandomPool (hwndDlg);
	EnableElevatedCursorChange (hwndDlg);
	WaitCursor();

	/* Re-encrypt the volume header */ 
	backupHeader = FALSE;

	while (TRUE)
	{
		/* The header will be re-encrypted wipePassCount times to prevent adversaries from using 
		techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
		to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
		times (ideally, 35 times) using non-random patterns and pseudorandom data. However, as users might
		impatiently interupt the process (etc.) we will not use the Gutmann's patterns but will write the
		valid re-encrypted header, i.e. pseudorandom data, and there will be many more passes than Guttman
		recommends. During each pass we will write a valid working header. Each pass will use the same master
		key, and also the same header key, secondary key (XTS), etc., derived from the new password. The only
		item that will be different for each pass will be the salt. This is sufficient to cause each "version"
		of the header to differ substantially and in a random manner from the versions written during the
		other passes. */

		for (wipePass = 0; wipePass < wipePassCount; wipePass++)
		{
			// Prepare new volume header
			nStatus = CreateVolumeHeaderInMemory (FALSE,
				buffer,
				cryptoInfo->ea,
				cryptoInfo->mode,
				newPassword,
				cryptoInfo->pkcs5,
				cryptoInfo->master_keydata,
				&ci,
				cryptoInfo->VolumeSize.Value,
				(volumeType == TC_VOLUME_TYPE_HIDDEN || volumeType == TC_VOLUME_TYPE_HIDDEN_LEGACY) ? cryptoInfo->hiddenVolumeSize : 0,
				cryptoInfo->EncryptedAreaStart.Value,
				cryptoInfo->EncryptedAreaLength.Value,
				cryptoInfo->RequiredProgramVersion,
				cryptoInfo->HeaderFlags,
				cryptoInfo->SectorSize,
				wipePass < wipePassCount - 1);

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

			if (bDevice
				&& !cryptoInfo->LegacyVolume
				&& !cryptoInfo->hiddenVolume
				&& cryptoInfo->HeaderVersion == 4
				&& (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
				&& (cryptoInfo->HeaderFlags & ~TC_HEADER_FLAG_NONSYS_INPLACE_ENC) == 0)
			{
				nStatus = WriteRandomDataToReservedHeaderAreas (dev, cryptoInfo, cryptoInfo->VolumeSize.Value, !backupHeader, backupHeader);
				if (nStatus != ERR_SUCCESS)
					goto error;
			}

			FlushFileBuffers (dev);
		}

		if (backupHeader || cryptoInfo->LegacyVolume)
			break;
			
		backupHeader = TRUE;
		headerOffset.QuadPart += hostSize - TC_VOLUME_HEADER_GROUP_SIZE;
	}

	/* Password successfully changed */
	nStatus = 0;

error:
	dwError = GetLastError ();

	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	if (bTimeStampValid)
		SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

	if (dev != INVALID_HANDLE_VALUE)
		CloseHandle ((HANDLE) dev);

	if (nDosLinkCreated == 0)
		RemoveFakeDosName (szDiskFile, szDosDevice);

	RandStop (FALSE);
	NormalCursor ();

	SetLastError (dwError);

	if (nStatus == ERR_OS_ERROR && dwError == ERROR_ACCESS_DENIED
		&& bDevice
		&& !UacElevated
		&& IsUacSupported ())
		return nStatus;

	if (nStatus != 0)
		handleError (hwndDlg, nStatus);

	return nStatus;
}

