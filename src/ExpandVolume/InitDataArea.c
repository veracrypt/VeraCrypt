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

#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"

#include "Common.h"
#include "Crypto.h"
#include "Random.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"

#include "InitDataArea.h"

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

int FormatWriteBufferSize = 1024 * 1024;
static uint32 FormatSectorSize = 0;

void SetFormatSectorSize(uint32 sector_size)
{
	FormatSectorSize = sector_size;
}

int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[TC_MAX_VOLUME_SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	int retVal = 0;
	DWORD err;
	CRYPTOPP_ALIGN_DATA(16) char temporaryKey[MASTER_KEYDATA_SIZE];
	CRYPTOPP_ALIGN_DATA(16) char originalK2[MASTER_KEYDATA_SIZE];

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;
#ifdef _WIN64
	CRYPTO_INFO tmpCI;
#endif

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

#ifdef _WIN64
	if (IsRamEncryptionEnabled ())
	{
		VirtualLock (&tmpCI, sizeof (tmpCI));
		memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
		VcUnprotectKeys (&tmpCI, VcGetEncryptionID (cryptoInfo));
		cryptoInfo = &tmpCI;
	}
#endif

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

#ifdef _WIN64
		if (IsRamEncryptionEnabled ())
			VcProtectKeys (cryptoInfo, VcGetEncryptionID (cryptoInfo));
#endif

		while (num_sectors--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo,
				cryptoInfo) == FALSE)
				goto fail;
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;
	}
	else
		nSecNo = num_sectors;

	UpdateProgressBar (nSecNo * FormatSectorSize);

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
#ifdef _WIN64
	if (IsRamEncryptionEnabled ())
	{
		burn (&tmpCI, sizeof (CRYPTO_INFO));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}
#endif

	return 0;

fail:
	err = GetLastError();

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);
#ifdef _WIN64
	if (IsRamEncryptionEnabled ())
	{
		burn (&tmpCI, sizeof (CRYPTO_INFO));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}
#endif

	SetLastError (err);
	return (retVal ? retVal : ERR_OS_ERROR);
}


BOOL WriteSector (void *dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	static __int32 updateTime = 0;

	(*nSecNo)++;

	memcpy (write_buf + *write_buf_cnt, sector, FormatSectorSize);
	(*write_buf_cnt) += FormatSectorSize;

	if (*write_buf_cnt == FormatWriteBufferSize && !FlushFormatWriteBuffer (dev, write_buf, write_buf_cnt, nSecNo, cryptoInfo))
		return FALSE;

	if (GetTickCount () - updateTime > 25)
	{
		if (UpdateProgressBar (*nSecNo * FormatSectorSize))
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


BOOL StartFormatWriteThread ()
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


void StopFormatWriteThread ()
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
