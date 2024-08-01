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
#include "Volumes.h"
#include "Password.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Pkcs5.h"
#include "Endian.h"
#include "Random.h"

#include <io.h>
#include <strsafe.h>

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

void VerifyPasswordAndUpdate (HWND hwndDlg, HWND hButton, HWND hPassword,
			 HWND hVerify, unsigned char *szPassword,
			 char *szVerify,
			 BOOL keyFilesEnabled)
{
	wchar_t szTmp1[MAX_PASSWORD + 1];
	wchar_t szTmp2[MAX_PASSWORD + 1];
	char szTmp1Utf8[MAX_PASSWORD + 1];
	char szTmp2Utf8[MAX_PASSWORD + 1];
	int k = GetWindowTextLength (hPassword);
	BOOL bEnable = FALSE;
	int utf8Len1, utf8Len2;

	UNREFERENCED_PARAMETER (hwndDlg);		/* Remove warning */

	GetWindowText (hPassword, szTmp1, ARRAYSIZE (szTmp1));
	GetWindowText (hVerify, szTmp2, ARRAYSIZE (szTmp2));

	utf8Len1 = WideCharToMultiByte (CP_UTF8, 0, szTmp1, -1, szTmp1Utf8, MAX_PASSWORD + 1, NULL, NULL);
	utf8Len2 = WideCharToMultiByte (CP_UTF8, 0, szTmp2, -1, szTmp2Utf8, MAX_PASSWORD + 1, NULL, NULL);

	if (wcscmp (szTmp1, szTmp2) != 0)
		bEnable = FALSE;
	else if (utf8Len1 <= 0)
		bEnable = FALSE;
	else
	{
		if (k >= MIN_PASSWORD || keyFilesEnabled)
			bEnable = TRUE;
		else
			bEnable = FALSE;
	}

	if (szPassword != NULL)
	{
		if (utf8Len1 > 0)
			memcpy (szPassword, szTmp1Utf8, sizeof (szTmp1Utf8));
		else
			szPassword [0] = 0;
	}

	if (szVerify != NULL)
	{
		if (utf8Len2 > 0)
			memcpy (szVerify, szTmp2Utf8, sizeof (szTmp2Utf8));
		else
			szVerify [0] = 0;
	}

	burn (szTmp1, sizeof (szTmp1));
	burn (szTmp2, sizeof (szTmp2));
	burn (szTmp1Utf8, sizeof (szTmp1Utf8));
	burn (szTmp2Utf8, sizeof (szTmp2Utf8));

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

		if (len > (bUseLegacyMaxPasswordLength? MAX_LEGACY_PASSWORD: MAX_PASSWORD))
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


BOOL CheckPasswordLength (HWND hwndDlg, unsigned __int32 passwordLength, int pim, BOOL bForBoot, int bootPRF, BOOL bSkipPasswordWarning, BOOL bSkipPimWarning)
{
	BOOL bootPimCondition = (bForBoot && (bootPRF != SHA512 && bootPRF != WHIRLPOOL))? TRUE : FALSE;
	BOOL bCustomPimSmall = ((pim != 0) && (pim < (bootPimCondition? 98 : 485)))? TRUE : FALSE;
	if (passwordLength < PASSWORD_LEN_WARNING)
	{
		if (bCustomPimSmall)
		{
			Error (bootPimCondition? "BOOT_PIM_REQUIRE_LONG_PASSWORD": "PIM_REQUIRE_LONG_PASSWORD", hwndDlg);
			return FALSE;
		}

#ifndef _DEBUG
		if (!bSkipPasswordWarning && (MessageBoxW (hwndDlg, GetString ("PASSWORD_LENGTH_WARNING"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES))
			return FALSE;
#endif
	}
#ifndef _DEBUG
	else if (bCustomPimSmall)
	{
		if (!bSkipPimWarning && AskWarnNoYes ("PIM_SMALL_WARNING", hwndDlg) != IDYES)
			return FALSE;
	}
#endif

	if ((pim != 0) && (pim > (bootPimCondition? 98 : 485)))
	{
		// warn that mount/boot will take more time
		Warning ("PIM_LARGE_WARNING", hwndDlg);

	}
	return TRUE;
}

int ChangePwd (const wchar_t *lpszVolume, Password *oldPassword, int old_pkcs5, int old_pim, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg)
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
	unsigned __int64 hostSize = 0;
	int volumeType;
	int wipePass;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	LARGE_INTEGER headerOffset;
	BOOL backupHeader;

	if (oldPassword->Length == 0 || newPassword->Length == 0) return -1;

	if (wipePassCount <= 0)
	{
      nStatus = ERR_PARAMETER_INCORRECT;
      handleError (hwndDlg, nStatus, SRC_POS);
      return nStatus;
	}

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus, SRC_POS);
      return nStatus;
   }

	WaitCursor ();

	CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		StringCchCopyW (szCFDevice, ARRAYSIZE(szCFDevice), szDiskFile);
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
	else if (!bDevice && bPreserveTimestamp)
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

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		if (dev == INVALID_HANDLE_VALUE)
		{
			goto error;
		}
		else
		{
			BYTE dgBuffer[256];
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
				dgBuffer, sizeof (dgBuffer), &dwResult, NULL);

			if (!bResult)
			{
				DISK_GEOMETRY geo;
				if (DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, (LPVOID) &geo, sizeof (geo), &dwResult, NULL))
				{
					((PDISK_GEOMETRY_EX) dgBuffer)->DiskSize.QuadPart = geo.Cylinders.QuadPart * geo.SectorsPerTrack * geo.TracksPerCylinder * geo.BytesPerSector;

					if (CurrentOSMajor >= 6)
					{
						STORAGE_READ_CAPACITY storage = {0};

						storage.Version = sizeof (STORAGE_READ_CAPACITY);
						storage.Size = sizeof (STORAGE_READ_CAPACITY);
						if (DeviceIoControl (dev, IOCTL_STORAGE_READ_CAPACITY, NULL, 0, (LPVOID) &storage, sizeof (storage), &bytesRead, NULL)
							&& (bytesRead >= sizeof (storage))
							&& (storage.Size == sizeof (STORAGE_READ_CAPACITY))
							)
						{
							((PDISK_GEOMETRY_EX) dgBuffer)->DiskSize.QuadPart = storage.DiskLength.QuadPart;
						}
					}
				}
				else
				{
					goto error;
				}

			}

			bResult = GetPartitionInfo (lpszVolume, &diskInfo);

			if (bResult)
			{
				hostSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				hostSize = ((PDISK_GEOMETRY_EX) dgBuffer)->DiskSize.QuadPart;
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
	{
		if (CryptoAPILastError == ERROR_SUCCESS)
			nStatus = ERR_RAND_INIT_FAILED;
		else
			nStatus = ERR_CAPI_INIT_FAILED;
		goto error;
	}

	SetRandomPoolEnrichedByUserStatus (FALSE); /* force the display of the random enriching dialog */


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

		nStatus = ReadVolumeHeader (FALSE, buffer, oldPassword, old_pkcs5, old_pim, &cryptoInfo, NULL);
		if (nStatus == ERR_CIPHER_INIT_WEAK_KEY)
			nStatus = 0;	// We can ignore this error here

		// if the XTS master key is vulnerable, return error and do not allow the user to change the password since the master key will not be changed
		if (cryptoInfo->bVulnerableMasterKey)
			nStatus = ERR_XTS_MASTERKEY_VULNERABLE;

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
			nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				buffer,
				cryptoInfo->ea,
				cryptoInfo->mode,
				newPassword,
				cryptoInfo->pkcs5,
				pim,
				cryptoInfo->master_keydata,
				&ci,
				cryptoInfo->VolumeSize.Value,
				(volumeType == TC_VOLUME_TYPE_HIDDEN) ? cryptoInfo->hiddenVolumeSize : 0,
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
				PCRYPTO_INFO dummyInfo = NULL;
				LARGE_INTEGER hiddenOffset;

				nStatus = WriteRandomDataToReservedHeaderAreas (hwndDlg, dev, cryptoInfo, cryptoInfo->VolumeSize.Value, !backupHeader, backupHeader);
				if (nStatus != ERR_SUCCESS)
					goto error;

				// write fake hidden volume header to protect against attacks that use statistical entropy
				// analysis to detect presence of hidden volumes
				hiddenOffset.QuadPart = backupHeader ? cryptoInfo->VolumeSize.Value + TC_VOLUME_HEADER_GROUP_SIZE + TC_HIDDEN_VOLUME_HEADER_OFFSET: TC_HIDDEN_VOLUME_HEADER_OFFSET;

				nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
					buffer,
					cryptoInfo->ea,
					cryptoInfo->mode,
					NULL,
					0,
					0,
					NULL,
					&dummyInfo,
					cryptoInfo->VolumeSize.Value,
					cryptoInfo->VolumeSize.Value,
					cryptoInfo->EncryptedAreaStart.Value,
					cryptoInfo->EncryptedAreaLength.Value,
					cryptoInfo->RequiredProgramVersion,
					cryptoInfo->HeaderFlags,
					cryptoInfo->SectorSize,
					wipePass < wipePassCount - 1);

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
		handleError (hwndDlg, nStatus, SRC_POS);

	return nStatus;
}

