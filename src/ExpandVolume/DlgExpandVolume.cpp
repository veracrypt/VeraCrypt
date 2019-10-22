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
// #include "../Mount/Mount.h"

#include "../Common/Dictionary.h"
#include "../Common/Common.h"
#include "../Common/Resource.h"
#include "../Common/SecurityToken.h"
#include "../Common/Progress.h"

#include "ExpandVolume.h"
#include "Resource.h"

// TO DO: display sector sizes different than 512 bytes
#define SECTOR_SIZE_MSG                     512

#define TIMER_ID_RANDVIEW								0xff
#define TIMER_INTERVAL_RANDVIEW							50

BOOL bSeManageVolumeNameSet = FALSE;

// see definition of enum EV_FileSystem
const wchar_t * szFileSystemStr[4] = {L"RAW",L"FAT",L"NTFS",L"EXFAT"};

// prototypes for internal functions
BOOL CALLBACK ExpandVolSizeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK ExpandVolProgressDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);

namespace VeraCryptExpander
{
/* defined in WinMain.c, referenced by ExpandVolumeWizard() */
int ExtcvAskVolumePassword (HWND hwndDlg, const wchar_t* fileName, Password *password, int *pkcs5, int *pim, BOOL* truecryptMode, char *titleStringId, BOOL enableMountOptions);
}


int GetSpaceString(wchar_t *dest, size_t cbDest, uint64 size, BOOL bDevice)
{
	const wchar_t * szFmtBytes = L"%.0lf %s";
	const wchar_t * szFmtOther = L"%.2lf %s";
	const wchar_t * SuffixStr[] = {L"Byte", L"KB", L"MB", L"GB", L"TB"};
	const uint64 Muliplier[] = {1, BYTES_PER_KB, BYTES_PER_MB, BYTES_PER_GB, BYTES_PER_TB};
	const int nMaxSuffix = sizeof(Muliplier)/sizeof(uint64) - 1;
	int i;

	for (i=1; i<=nMaxSuffix && size>Muliplier[i]; i++) ;

	--i;

	if (bDevice) {
		wchar_t szTemp[512];

		if (StringCbPrintfW(szTemp, sizeof(szTemp),i?szFmtOther:szFmtBytes, size/(double)Muliplier[i], SuffixStr[i]) < 0 )
			return -1;

		return StringCbPrintfW(dest, cbDest, L"%I64u sectors (%s)", size/SECTOR_SIZE_MSG , szTemp);
	}

	return StringCbPrintfW(dest, cbDest,i?szFmtOther:szFmtBytes, size/(double)Muliplier[i], SuffixStr[i]);
}

void SetCurrentVolSize(HWND hwndDlg, uint64 size)
{
	const uint64 Muliplier[] = {BYTES_PER_KB, BYTES_PER_MB, BYTES_PER_GB, BYTES_PER_TB};
	const int IdRadioBtn[] = {IDC_KB, IDC_MB, IDC_GB, IDC_TB};
	const int nMaxSuffix = sizeof(Muliplier)/sizeof(uint64) - 1;
	int i;
	wchar_t szTemp[256];

	for (i=1; i<=nMaxSuffix && size>Muliplier[i]; i++) ;

	--i;

	SendDlgItemMessage (hwndDlg, IdRadioBtn[i], BM_SETCHECK, BST_CHECKED, 0);
	StringCbPrintfW(szTemp,sizeof(szTemp),L"%I64u",size/Muliplier[i]);
	SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTemp);
}

uint64 GetSizeBoxMultiplier(HWND hwndDlg)
{
	const uint64 Muliplier[] = {BYTES_PER_KB, BYTES_PER_MB, BYTES_PER_GB, BYTES_PER_TB};
	const int IdRadioBtn[] = {IDC_KB, IDC_MB, IDC_GB, IDC_TB};
	const int nMaxSuffix = sizeof(Muliplier)/sizeof(uint64) - 1;
	int i;

	for (i=nMaxSuffix; i>0 && !IsButtonChecked (GetDlgItem (hwndDlg, IdRadioBtn[i])); --i) ;

	return Muliplier[i];
}

void HandleQuickExpanddCheckBox (HWND hwndDlg)
{
	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_INIT_NEWSPACE)))
	{
		EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKEXPAND), FALSE);
		SendDlgItemMessage (hwndDlg, IDC_QUICKEXPAND, BM_SETCHECK, BST_UNCHECKED, 0);
	}
	else
	{
		EnableWindow (GetDlgItem (hwndDlg, IDC_QUICKEXPAND), TRUE);
	}
}


BOOL CALLBACK ExpandVolSizeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static EXPAND_VOL_THREAD_PARAMS *pVolExpandParam;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			wchar_t szTemp[4096];

			pVolExpandParam = (EXPAND_VOL_THREAD_PARAMS*)lParam;

			EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), !pVolExpandParam->bIsDevice);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KB), !pVolExpandParam->bIsDevice);
			EnableWindow (GetDlgItem (hwndDlg, IDC_MB), !pVolExpandParam->bIsDevice);
			EnableWindow (GetDlgItem (hwndDlg, IDC_GB), !pVolExpandParam->bIsDevice);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TB), !pVolExpandParam->bIsDevice);

			EnableWindow (GetDlgItem (hwndDlg, IDC_INIT_NEWSPACE),
				!(pVolExpandParam->bIsLegacy && pVolExpandParam->bIsDevice));
			SendDlgItemMessage (hwndDlg, IDC_INIT_NEWSPACE, BM_SETCHECK,
				pVolExpandParam->bInitFreeSpace ? BST_CHECKED : BST_UNCHECKED, 0);

			if (!pVolExpandParam->bIsDevice)
				SetCurrentVolSize(hwndDlg,pVolExpandParam->oldSize);

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_HELP), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);

			GetSpaceString(szTemp,sizeof(szTemp),pVolExpandParam->oldSize,pVolExpandParam->bIsDevice);

			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_OLDSIZE), szTemp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_NAME), pVolExpandParam->szVolumeName);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_FILE_SYSTEM), szFileSystemStr[pVolExpandParam->FileSystem]);

			if (pVolExpandParam->bIsDevice)
			{
				GetSpaceString(szTemp,sizeof(szTemp),pVolExpandParam->newSize,TRUE);
			}
			else
			{
				wchar_t szHostFreeStr[256];

				SetWindowText (GetDlgItem (hwndDlg, IDT_NEW_SIZE), L"");
				GetSpaceString(szHostFreeStr,sizeof(szHostFreeStr),pVolExpandParam->hostSizeFree,FALSE);
				StringCbPrintfW (szTemp,sizeof(szTemp),L"%s available on host drive", szHostFreeStr);

				if (!pVolExpandParam->bDisableQuickExpand)
				{
					ShowWindow (GetDlgItem (hwndDlg, IDC_QUICKEXPAND), SW_SHOW);
					HandleQuickExpanddCheckBox (hwndDlg);
				}
			}

			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_NEWSIZE), szTemp);

			// set help text
			if (pVolExpandParam->bIsDevice)
			{
				StringCbPrintfW (szTemp,sizeof(szTemp),L"This is a device-based VeraCrypt volume.\n\nThe new volume size will be choosen automatically as the size of the host device.");
				if (pVolExpandParam->bIsLegacy)
					StringCbCatW(szTemp,sizeof(szTemp),L" Note: filling the new space with random data is not supported for legacy volumes.");
			}
			else
			{
				StringCbPrintfW (szTemp, sizeof(szTemp),L"Please specify the new size of the VeraCrypt volume (must be at least %I64u KB larger than the current size).",TC_MINVAL_FS_EXPAND/1024);
			}
			SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), szTemp);			

		}
		return 0;


	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			wchar_t szTemp[4096];

			pVolExpandParam->bInitFreeSpace = IsButtonChecked (GetDlgItem (hwndDlg, IDC_INIT_NEWSPACE));
			pVolExpandParam->bQuickExpand = IsButtonChecked (GetDlgItem (hwndDlg, IDC_QUICKEXPAND));
			if (!pVolExpandParam->bIsDevice) // for devices new size is set by calling function
			{
				GetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTemp, ARRAYSIZE (szTemp));
				pVolExpandParam->newSize = _wtoi64(szTemp) * GetSizeBoxMultiplier(hwndDlg);
			}

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_INIT_NEWSPACE && !pVolExpandParam->bDisableQuickExpand)
		{
			HandleQuickExpanddCheckBox (hwndDlg);
			return 1;
		}

		if (lw == IDC_QUICKEXPAND  && IsButtonChecked (GetDlgItem (hwndDlg, IDC_QUICKEXPAND)))
		{
			// If quick expand selected, then we warn about security issue
			if (MessageBoxW (hwndDlg, L"WARNING: You should use Quick Expand only in the following cases:\n\n1) The device where the file container is located contains no sensitive data and you do not need plausible deniability.\n2) The device where the file container is located has already been securely and fully encrypted.\n\nAre you sure you want to use Quick Expand?",
				lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2) == IDNO)
			{
				SendDlgItemMessage (hwndDlg, IDC_QUICKEXPAND, BM_SETCHECK, BST_UNCHECKED, 0);
				return 1;
			}
		}

		return 0;
	}

	return 0;
}


extern "C" void AddProgressDlgStatus(HWND hwndDlg, const wchar_t* szText)
{
	HWND hwndCtrl;

	hwndCtrl = GetDlgItem (hwndDlg,IDC_BOX_STATUS);
	SendMessage(hwndCtrl,EM_REPLACESEL,FALSE,(LPARAM)szText);
	SendMessage(hwndCtrl,EM_SCROLLCARET,0,0);
}


extern "C" void SetProgressDlgStatus(HWND hwndDlg, const wchar_t* szText)
{
	HWND hwndCtrl;

	hwndCtrl = GetDlgItem (hwndDlg,IDC_BOX_STATUS);
	SendMessage(hwndCtrl,EM_SETSEL,0,-1);
	SendMessage(hwndCtrl,EM_REPLACESEL,FALSE,(LPARAM)szText);
	SendMessage(hwndCtrl,EM_SCROLLCARET,0,0);
}


BOOL CALLBACK ExpandVolProgressDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static EXPAND_VOL_THREAD_PARAMS *pProgressDlgParam;
	static BOOL bVolTransformStarted = FALSE;
	static BOOL showRandPool = TRUE;
	static unsigned char randPool[16];
	static unsigned char maskRandPool [16];
	static BOOL bUseMask = FALSE;
	static DWORD mouseEntropyGathered = 0xFFFFFFFF;
	static DWORD mouseEventsInitialCount = 0;
	/* max value of entropy needed to fill all random pool = 8 * RNG_POOL_SIZE = 2560 bits */
	static const DWORD maxEntropyLevel = RNG_POOL_SIZE * 8;
	static HWND hEntropyBar = NULL;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			wchar_t szOldHostSize[512], szNewHostSize[512];
			HCRYPTPROV hRngProv;

			pProgressDlgParam = (EXPAND_VOL_THREAD_PARAMS*)lParam;
			bVolTransformStarted = FALSE;
			showRandPool = FALSE;

			hCurPage = hwndDlg;
			nPbar = IDC_PROGRESS_BAR;

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
			VirtualLock (maskRandPool, sizeof(maskRandPool));

			mouseEntropyGathered = 0xFFFFFFFF;
			mouseEventsInitialCount = 0;
			bUseMask = FALSE;
			if (CryptAcquireContext (&hRngProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
			{
				if (CryptGenRandom (hRngProv, sizeof (maskRandPool), maskRandPool))
					bUseMask = TRUE;
				CryptReleaseContext (hRngProv, 0);
			}

			GetSpaceString(szOldHostSize,sizeof(szOldHostSize),pProgressDlgParam->oldSize,pProgressDlgParam->bIsDevice);
			GetSpaceString(szNewHostSize,sizeof(szNewHostSize),pProgressDlgParam->newSize,pProgressDlgParam->bIsDevice);

			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_OLDSIZE), szOldHostSize);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_NEWSIZE), szNewHostSize);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_NAME), pProgressDlgParam->szVolumeName);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_FILE_SYSTEM), szFileSystemStr[pProgressDlgParam->FileSystem]);
			SetWindowText (GetDlgItem (hwndDlg, IDC_EXPAND_VOLUME_INITSPACE), pProgressDlgParam->bInitFreeSpace?L"Yes":L"No");

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_STATUS), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);

			SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

			// set status text
			if ( !pProgressDlgParam->bInitFreeSpace && pProgressDlgParam->bIsLegacy )
			{
				showRandPool = FALSE;
				EnableWindow (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), FALSE);
				SetDlgItemText(hwndDlg, IDC_BOX_STATUS, L"Click 'Continue' to expand the volume.");
			}
			else
			{
				SetDlgItemText(hwndDlg, IDC_BOX_STATUS, L"IMPORTANT: Move your mouse as randomly as possible within this window. The longer you move it, the better. This significantly increases the cryptographic strength of the encryption keys. Then click 'Continue' to expand the volume.");
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS), BM_SETCHECK, BST_UNCHECKED, 0);
			hEntropyBar = GetDlgItem (hwndDlg, IDC_ENTROPY_BAR);
			SendMessage (hEntropyBar, PBM_SETRANGE32, 0, maxEntropyLevel);
			SendMessage (hEntropyBar, PBM_SETSTEP, 1, 0);
			SetTimer (hwndDlg, TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);
		}
		return 0;
	case TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED:
		{
			int nStatus = (int)lParam;

			NormalCursor ();
			if (nStatus != 0)
			{
				if ( nStatus != ERR_USER_ABORT )
					AddProgressDlgStatus (hwndDlg, L"Error: volume expansion failed.");
				else
					AddProgressDlgStatus (hwndDlg, L"Error: operation aborted by user.");
			}
			else
			{
				AddProgressDlgStatus (hwndDlg, L"Finished. Volume successfully expanded.");
			}

			SetWindowText (GetDlgItem (hwndDlg, IDOK), L"Exit");
			EnableWindow (GetDlgItem (hwndDlg, IDOK), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
		}
		return 1;

	case WM_TIMER:

		switch (wParam)
		{
		case TIMER_ID_RANDVIEW:
			{
				wchar_t szRndPool[64] = {0};
				DWORD mouseEventsCounter;

				RandpeekBytes (hwndDlg, randPool, sizeof (randPool),&mouseEventsCounter);

				ProcessEntropyEstimate (hEntropyBar, &mouseEventsInitialCount, mouseEventsCounter, maxEntropyLevel, &mouseEntropyGathered);

				if (showRandPool)
					StringCbPrintfW (szRndPool, sizeof(szRndPool), L"%08X%08X%08X%08X",
						*((DWORD*) (randPool + 12)), *((DWORD*) (randPool + 8)), *((DWORD*) (randPool + 4)), *((DWORD*) (randPool)));
				else if (bUseMask)
				{
					for (int i = 0; i < 16; i++)
					{
						wchar_t tmp2[3];
						unsigned char tmpByte = randPool[i] ^ maskRandPool[i];
						tmp2[0] = (wchar_t) (((tmpByte >> 4) % 6) + L'*');
						tmp2[1] = (wchar_t) (((tmpByte & 0x0F) % 6) + L'*');
						tmp2[2] = 0;
						StringCbCatW (szRndPool, sizeof(szRndPool), tmp2);
					}
				}
				else
				{
					wmemset (szRndPool, L'*', 32);
				}

				SetWindowText (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), szRndPool);

				burn (randPool, sizeof(randPool));
				burn (szRndPool, sizeof(szRndPool));
			}
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDC_DISPLAY_POOL_CONTENTS)
		{
			showRandPool = IsButtonChecked (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS));
			return 1;
		}
		if (lw == IDCANCEL)
		{
			if (bVolTransformStarted)
			{
				if (MessageBoxW (hwndDlg, L"Warning: Volume expansion is in progress!\n\nStopping now may result in a damaged volume.\n\nDo you really want to cancel?", lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON2) == IDNO)
					return 1;

				// tell the volume transform thread to terminate
				bVolTransformThreadCancel = TRUE;
			}
			NormalCursor ();
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			if (bVolTransformStarted)
			{
				// TransformThreadFunction finished -> OK button is now exit
				NormalCursor ();
				EndDialog (hwndDlg, lw);
			}
			else
			{
				showRandPool = FALSE;
				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);
				EnableWindow (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
				SetProgressDlgStatus (hwndDlg, L"Starting volume expansion ...\r\n");
				bVolTransformStarted = TRUE;
				pProgressDlgParam->hwndDlg = hwndDlg;
				if ( _beginthread (volTransformThreadFunction, 0, pProgressDlgParam) == -1L )
				{
					handleError (hwndDlg, ERR_OS_ERROR, SRC_POS);
					EndDialog (hwndDlg, lw);
				}
				WaitCursor();
			}
			return 1;
		}

		return 0;

	case WM_NCDESTROY:
		burn (randPool, sizeof (randPool));
		burn (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
		burn (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
		burn (maskRandPool, sizeof(maskRandPool));
		return 0;
	}

	return 0;
}


typedef struct
{
	OpenVolumeContext *context;
	const wchar_t *volumePath;
	Password *password;
	int pkcs5_prf;
	int pim;
	BOOL truecryptMode;
	BOOL write;
	BOOL preserveTimestamps;
	BOOL useBackupHeader;
	int* nStatus;
} OpenVolumeThreadParam;

void CALLBACK OpenVolumeWaitThreadProc(void* pArg, HWND hwndDlg)
{
	OpenVolumeThreadParam* pThreadParam = (OpenVolumeThreadParam*) pArg;

	*(pThreadParam)->nStatus = OpenVolume(pThreadParam->context, pThreadParam->volumePath, pThreadParam->password, pThreadParam->pkcs5_prf,
		pThreadParam->pim, pThreadParam->truecryptMode, pThreadParam->write, pThreadParam->preserveTimestamps, pThreadParam->useBackupHeader);
}

/*
	ExpandVolumeWizard

	Expands a trucrypt volume (wizard for user interface)

	Parameters:

		hwndDlg : HWND
			[in] handle to parent window (if any)

		szVolume : char *
			[in] Pointer to a string with the volume name (e.g. '\Device\Harddisk0\Partition1' or 'C:\topsecret.tc')

	Return value:

		none

*/
void ExpandVolumeWizard (HWND hwndDlg, wchar_t *lpszVolume)
{
	int nStatus = ERR_OS_ERROR;
	wchar_t szTmp[4096];
	Password VolumePassword;
	int VolumePkcs5 = 0, VolumePim = -1;
	uint64 hostSize, volSize, hostSizeFree, maxSizeFS;
	BOOL bIsDevice, bIsLegacy;
	DWORD dwError;
	int driveNo;
	enum EV_FileSystem volFSType;
	wchar_t rootPath[] = L"A:\\";

	switch (IsSystemDevicePath (lpszVolume, hwndDlg, TRUE))
	{
	case 1:
	case 2:
		MessageBoxW (hwndDlg, L"A VeraCrypt system volume can't be expanded.", lpszTitle, MB_OK|MB_ICONEXCLAMATION);
		goto ret;
	}

	EnableElevatedCursorChange (hwndDlg);
	WaitCursor();

	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST", hwndDlg);
		goto ret;
	}

	if (Randinit() != ERR_SUCCESS) {
		if (CryptoAPILastError == ERROR_SUCCESS)
			nStatus = ERR_RAND_INIT_FAILED;
		else
			nStatus = ERR_CAPI_INIT_FAILED;
		goto error;
	}

	NormalCursor();

	// Ask the user if there is a hidden volume
	char *volTypeChoices[] = {0, "DOES_VOLUME_CONTAIN_HIDDEN", "VOLUME_CONTAINS_HIDDEN", "VOLUME_DOES_NOT_CONTAIN_HIDDEN", "IDCANCEL", 0};
	switch (AskMultiChoice ((void **) volTypeChoices, FALSE, hwndDlg))
	{
	case 1:
		MessageBoxW (hwndDlg, L"An outer volume containing a hidden volume can't be expanded, because this destroys the hidden volume.", lpszTitle, MB_OK|MB_ICONEXCLAMATION);
		goto ret;

	case 2:
		break;

	default:
		nStatus = ERR_SUCCESS;
		goto ret;
	}

	WaitCursor();

	nStatus = QueryVolumeInfo(hwndDlg,lpszVolume,&hostSizeFree,&maxSizeFS);

	if (nStatus!=ERR_SUCCESS)
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	NormalCursor();

	while (TRUE)
	{
		OpenVolumeContext expandVol;
		BOOL truecryptMode = FALSE;

		if (!VeraCryptExpander::ExtcvAskVolumePassword (hwndDlg, lpszVolume, &VolumePassword, &VolumePkcs5, &VolumePim, &truecryptMode, "ENTER_NORMAL_VOL_PASSWORD", FALSE))
		{
			goto ret;
		}

		EnableElevatedCursorChange (hwndDlg);
		WaitCursor();

		if (KeyFilesEnable && FirstKeyFile)
			KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, lpszVolume);


		OpenVolumeThreadParam threadParam;
		threadParam.context = &expandVol;
		threadParam.volumePath = lpszVolume;
		threadParam.password = &VolumePassword;
		threadParam.pkcs5_prf = VolumePkcs5;
		threadParam.pim = VolumePim;
		threadParam.truecryptMode = FALSE;
		threadParam.write = FALSE;
		threadParam.preserveTimestamps = bPreserveTimestamp;
		threadParam.useBackupHeader = FALSE;
		threadParam.nStatus = &nStatus;

		ShowWaitDialog (hwndDlg, TRUE, OpenVolumeWaitThreadProc, &threadParam);

		NormalCursor ();

		dwError = GetLastError();

		if (nStatus == ERR_SUCCESS)
		{
			bIsDevice = expandVol.IsDevice;
			bIsLegacy = expandVol.CryptoInfo->LegacyVolume;
			hostSize = expandVol.HostSize;
			VolumePkcs5 = expandVol.CryptoInfo->pkcs5;
			if ( bIsLegacy )
			{
				if ( bIsDevice )
					volSize = 0; // updated later
				else
					volSize = hostSize;
			}
			else
			{
				volSize = GetVolumeSizeByDataAreaSize (expandVol.CryptoInfo->VolumeSize.Value, bIsLegacy);
			}
			CloseVolume (&expandVol);
			break;
		}
		else if (nStatus != ERR_PASSWORD_WRONG)
		{
			SetLastError (dwError);
			goto error;
		}

		NormalCursor();

		handleError (hwndDlg, nStatus, SRC_POS);
	}

	WaitCursor();

	// auto mount the volume to check the file system type
	nStatus=MountVolTemp(hwndDlg, lpszVolume, &driveNo, &VolumePassword, VolumePkcs5, VolumePim);

	if (nStatus != ERR_SUCCESS)
		goto error;

	rootPath[0] += driveNo;

	if ( !GetFileSystemType(rootPath,&volFSType) )
		volFSType = EV_FS_TYPE_RAW;

	if ( bIsLegacy && bIsDevice && volFSType == EV_FS_TYPE_NTFS )
	{
		uint64 NumberOfSectors;
		DWORD BytesPerSector;

		if ( !GetNtfsNumberOfSectors(rootPath, &NumberOfSectors, &BytesPerSector) )
			nStatus = ERR_OS_ERROR;

		// NTFS reported size does not include boot sector copy at volume end
		volSize = ( NumberOfSectors + 1 ) * BytesPerSector;
	}

	UnmountVolume (hwndDlg, driveNo, TRUE);

	NormalCursor();

	if (nStatus != ERR_SUCCESS)
		goto error;

	if ( bIsDevice && bIsLegacy && volFSType != EV_FS_TYPE_NTFS )
	{
		MessageBoxW (hwndDlg,
			L"Expanding a device hosted legacy volume with no NTFS file system\n"
			L"is unsupported.\n"
			L"Note that expanding the VeraCrypt volume itself is not neccessary\n"
			L"for legacy volumes.\n",
			lpszTitle, MB_OK|MB_ICONEXCLAMATION);
		goto ret;
	}

	// check if there is enough free space on host device/drive to expand the volume
	if ( (bIsDevice && hostSize < volSize + TC_MINVAL_FS_EXPAND) || (!bIsDevice && hostSizeFree < TC_MINVAL_FS_EXPAND) )
	{
		MessageBoxW (hwndDlg, L"Not enough free space to expand the volume", lpszTitle, MB_OK|MB_ICONEXCLAMATION);
		goto ret;
	}

	if (!bIsDevice && hostSize != volSize ) {
		// there is some junk data at the end of the volume
		if (MessageBoxW (hwndDlg, L"Warning: The container file is larger than the VeraCrypt volume area. The data after the VeraCrypt volume area will be overwritten.\n\nDo you want to continue?", lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON2) == IDNO)
			goto ret;
	}

	switch (volFSType)
	{
	case EV_FS_TYPE_NTFS:
		break;
	case EV_FS_TYPE_FAT:
		if (MessageBoxW (hwndDlg,L"Warning: The VeraCrypt volume contains a FAT file system!\n\nOnly the VeraCrypt volume itself will be expanded, but not the file system.\n\nDo you want to continue?",
			lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON2) == IDNO)
			goto ret;
		break;
	case EV_FS_TYPE_EXFAT:
		if (MessageBoxW (hwndDlg,L"Warning: The VeraCrypt volume contains an exFAT file system!\n\nOnly the VeraCrypt volume itself will be expanded, but not the file system.\n\nDo you want to continue?",
			lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON2) == IDNO)
			goto ret;
		break;
	default:
		if (MessageBoxW (hwndDlg,L"Warning: The VeraCrypt volume contains an unknown or no file system!\n\nOnly the VeraCrypt volume itself will be expanded, the file system remains unchanged.\n\nDo you want to continue?",
			lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON2) == IDNO)
			goto ret;
	}

	EXPAND_VOL_THREAD_PARAMS VolExpandParam;

	VolExpandParam.bInitFreeSpace = (bIsLegacy && bIsDevice) ? FALSE:TRUE;
	VolExpandParam.bQuickExpand = FALSE;
	VolExpandParam.bDisableQuickExpand = bIsDevice;
	VolExpandParam.szVolumeName = lpszVolume;
	VolExpandParam.FileSystem = volFSType;
	VolExpandParam.pVolumePassword = &VolumePassword;
	VolExpandParam.VolumePkcs5 = VolumePkcs5;
	VolExpandParam.VolumePim = VolumePim;
	VolExpandParam.bIsDevice = bIsDevice;
	VolExpandParam.bIsLegacy = bIsLegacy;
	VolExpandParam.oldSize = bIsDevice ? volSize : hostSize;
	VolExpandParam.newSize = hostSize;
	VolExpandParam.hostSizeFree = hostSizeFree;

	// disable Quick Expand if the file is sparse or compressed
	if (!bIsDevice)
	{
		DWORD dwFileAttrib = GetFileAttributesW (lpszVolume);
		if (INVALID_FILE_ATTRIBUTES != dwFileAttrib)
		{
			if (dwFileAttrib & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE))
				VolExpandParam.bDisableQuickExpand = TRUE;
		}
	}

	while (1)
	{
		uint64 newVolumeSize;

		if (IDCANCEL == DialogBoxParamW (hInst,
			MAKEINTRESOURCEW (IDD_SIZE_DIALOG), hwndDlg,
			(DLGPROC) ExpandVolSizeDlgProc, (LPARAM) &VolExpandParam))
		{
			goto ret;
		}

		newVolumeSize = VolExpandParam.newSize;

		if ( !bIsDevice )
		{
			if ( (newVolumeSize < hostSize + TC_MINVAL_FS_EXPAND) && ((hostSize == volSize) || (newVolumeSize != hostSize) || ((hostSize - volSize) < TC_MINVAL_FS_EXPAND)))
			{
				StringCbPrintfW(szTmp,sizeof(szTmp),L"New volume size too small, must be at least %I64u kB larger than the current size.",TC_MINVAL_FS_EXPAND/BYTES_PER_KB);
				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_OK | MB_ICONEXCLAMATION );
				continue;
			}

			if ( newVolumeSize - hostSize > hostSizeFree )
			{
				StringCbPrintfW(szTmp,sizeof(szTmp),L"New volume size too large, not enough space on host drive.");
				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_OK | MB_ICONEXCLAMATION );
				continue;
			}

			if ( newVolumeSize>maxSizeFS )
			{
				StringCbPrintfW(szTmp,sizeof(szTmp),L"Maximum file size of %I64u MB on host drive exceeded.",maxSizeFS/BYTES_PER_MB);
				MessageBoxW (hwndDlg, L"!\n",lpszTitle, MB_OK | MB_ICONEXCLAMATION );
				continue;
			}

			if (VolExpandParam.bQuickExpand && !bSeManageVolumeNameSet)
			{
				if (!SetPrivilege (SE_MANAGE_VOLUME_NAME, TRUE))
				{
					MessageBoxW (hwndDlg, L"Error: Failed to get necessary privileges to enable Quick Expand!\nPlease uncheck Quick Expand option and try again.",lpszTitle, MB_OK | MB_ICONEXCLAMATION );
					VolExpandParam.bQuickExpand = FALSE;
					continue;
				}

				bSeManageVolumeNameSet = TRUE;
			}
		}

		if ( newVolumeSize > TC_MAX_VOLUME_SIZE )
		{
			// note: current limit TC_MAX_VOLUME_SIZE is 1 PetaByte
			StringCbPrintfW(szTmp,sizeof(szTmp),L"Maximum VeraCrypt volume size of %I64u TB exceeded!\n",TC_MAX_VOLUME_SIZE/BYTES_PER_TB);
			MessageBoxW (hwndDlg, szTmp,lpszTitle, MB_OK | MB_ICONEXCLAMATION );
			if (bIsDevice)
				break; // TODO: ask to limit volume size to TC_MAX_VOLUME_SIZE
			continue;
		}

		break;
	}

	VolExpandParam.oldSize = volSize;

	// start progress dialog
	DialogBoxParamW (hInst,	MAKEINTRESOURCEW (IDD_EXPAND_PROGRESS_DLG), hwndDlg,
		(DLGPROC) ExpandVolProgressDlgProc, (LPARAM) &VolExpandParam );

ret:
	nStatus = ERR_SUCCESS;

error:

	if (nStatus != 0)
		handleError (hwndDlg, nStatus, SRC_POS);

	burn (&VolumePassword, sizeof (VolumePassword));

	RestoreDefaultKeyFilesParam();
	RandStop (FALSE);
	NormalCursor();

	return;
}

