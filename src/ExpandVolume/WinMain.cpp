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
#include "cpu.h"

#include <time.h>
#include <math.h>
#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windowsx.h>

#include "Apidrvr.h"
#include "BootEncryption.h"
#include "Cmdline.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Combo.h"
#include "Keyfiles.h"
#include "Language.h"
#include "../Mount/MainCom.h"
#include "../Mount/Mount.h"
#include "Pkcs5.h"
#include "Random.h"
#include "Registry.h"
#include "Resource.h"
#include "Password.h"
#include "Xml.h"
#include "../Boot/Windows/BootCommon.h"
#include "../Common/Dictionary.h"
#include "../Common/Common.h"
#include "../Common/Resource.h"
#include "../Common/SecurityToken.h"
#include "../Platform/Finally.h"
#include "../Platform/ForEach.h"
#include <Strsafe.h>

#include "ExpandVolume.h"

using namespace VeraCrypt;

const wchar_t szExpandVolumeInfo[] =
L":: VeraCrypt Expander ::\n\nExpand a VeraCrypt volume on the fly without reformatting\n\n\n\
All kind of volumes (container files, disks and partitions) formatted with \
NTFS are supported. The only condition is that there must be enough free \
space on the host drive or host device of the VeraCrypt volume.\n\n\
Do not use this software to expand an outer volume containing a hidden \
volume, because this destroys the hidden volume!\n\
";

enum timer_ids
{
	TIMER_ID_MAIN = 0xff,
	TIMER_ID_KEYB_LAYOUT_GUARD
};

enum hidden_os_read_only_notif_mode
{
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE = 0,
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_COMPACT,
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_DISABLED
};

#define TIMER_INTERVAL_MAIN					500
#define TIMER_INTERVAL_KEYB_LAYOUT_GUARD	10

namespace VeraCryptExpander
{

BOOL bExplore = FALSE;				/* Display explorer window after mount */
BOOL bBeep = FALSE;					/* Donot beep after mount */
wchar_t szFileName[TC_MAX_PATH+1];		/* Volume to mount */
wchar_t szDriveLetter[3];				/* Drive Letter to mount */
wchar_t commandLineDrive = 0;
BOOL bCacheInDriver = FALSE;		/* Cache any passwords we see */
BOOL bCacheInDriverDefault = FALSE;
BOOL bHistoryCmdLine = FALSE;		/* History control is always disabled */
BOOL bCloseDismountedWindows=TRUE;	/* Close all open explorer windows of dismounted volume */
BOOL bWipeCacheOnExit = FALSE;		/* Wipe password from chace on exit */
BOOL bWipeCacheOnAutoDismount = TRUE;
BOOL bEnableBkgTask = FALSE;
BOOL bCloseBkgTaskWhenNoVolumes = FALSE;
BOOL bDismountOnLogOff = TRUE;
BOOL bDismountOnScreenSaver = TRUE;
BOOL bDismountOnPowerSaving = FALSE;
BOOL bForceAutoDismount = TRUE;
BOOL bForceMount = FALSE;			/* Mount volume even if host file/device already in use */
BOOL bForceUnmount = FALSE;			/* Unmount volume even if it cannot be locked */
BOOL bWipe = FALSE;					/* Wipe driver passwords */
BOOL bAuto = FALSE;					/* Do everything without user input */
BOOL bAutoMountDevices = FALSE;		/* Auto-mount devices */
BOOL bAutoMountFavorites = FALSE;
BOOL bPlaySoundOnHotkeyMountDismount = TRUE;
BOOL bDisplayMsgBoxOnHotkeyDismount = FALSE;
BOOL bHibernationPreventionNotified = FALSE;	/* TRUE if the user has been notified that hibernation was prevented (system encryption) during the session. */
BOOL bHiddenSysLeakProtNotifiedDuringSession = FALSE;	/* TRUE if the user has been notified during the session that unencrypted filesystems and non-hidden VeraCrypt volumes are mounted as read-only under hidden OS. */
BOOL CloseSecurityTokenSessionsAfterMount = FALSE;

BOOL MultipleMountOperationInProgress = FALSE;

BOOL Quit = FALSE;					/* Exit after processing command line */
BOOL ComServerMode = FALSE;
BOOL UsePreferences = TRUE;

int HiddenSysLeakProtectionNotificationStatus = TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE;
int MaxVolumeIdleTime = -120;
int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = -1;		/* Item number of selected drive */

int cmdUnmountDrive = -2;			/* Volume drive letter to unmount (-1 = all) */
Password VolumePassword;			/* Password used for mounting volumes */
Password CmdVolumePassword;			/* Password passed from command line */
BOOL CmdVolumePasswordValid = FALSE;
MountOptions mountOptions;
MountOptions defaultMountOptions;
KeyFile *FirstCmdKeyFile;

HBITMAP hbmLogoBitmapRescaled = NULL;
wchar_t OrigKeyboardLayout [8+1] = L"00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */

static KeyFilesDlgParam				hidVolProtKeyFilesParam;
VOLUME_NOTIFICATIONS_LIST	VolumeNotificationsList;

static int bPrebootPasswordDlgMode = FALSE;

static void localcleanup (void)
{
	// Wipe command line
	char *c = GetCommandLineA ();
	wchar_t *wc = GetCommandLineW ();
	burn(c, strlen (c));
	burn(wc, wcslen (wc) * sizeof (wchar_t));

	/* Delete buffered bitmaps (if any) */
	if (hbmLogoBitmapRescaled != NULL)
	{
		DeleteObject ((HGDIOBJ) hbmLogoBitmapRescaled);
		hbmLogoBitmapRescaled = NULL;
	}

	/* These items should have already been cleared by the functions that used them, but we're going to
	clear them for extra security. */
	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
	burn (&mountOptions, sizeof (mountOptions));
	burn (&defaultMountOptions, sizeof (defaultMountOptions));
	burn (&szFileName, sizeof(szFileName));

	/* Cleanup common code resources */
	cleanup ();

	RandStop (TRUE);
}


void EndMainDlg (HWND hwndDlg)
{
	if (!bHistory)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), L"");
	}

	EndDialog (hwndDlg, 0);
}

BOOL CALLBACK MountOptionsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// dummy (referenced by PasswordDlgProc() )
	return FALSE;
}
BOOL TCBootLoaderOnInactiveSysEncDrive (void)
{
	// dummy (referenced by Dlgcode.c)
	return FALSE;
}

BOOL CheckSysEncMountWithoutPBA (const char *devicePath, BOOL quiet)
{
	// dummy (referenced by Dlgcode.c)
	return FALSE;
}

static void InitMainDialog (HWND hwndDlg)
{
	/* Call the common dialog init code */
	InitDialog (hwndDlg);
	LocalizeDialog (hwndDlg, NULL);

	SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, TC_MAX_PATH, 0);
	SetWindowTextW (hwndDlg, lpszTitle);

	SendMessage (GetDlgItem (hwndDlg, IDC_INFOEXPAND), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
	SetWindowText (GetDlgItem (hwndDlg, IDC_INFOEXPAND), szExpandVolumeInfo);

	// Resize the logo bitmap if the user has a non-default DPI
	if (ScreenDPI != USER_DEFAULT_SCREEN_DPI
		&& hbmLogoBitmapRescaled == NULL)	// If not re-called (e.g. after language pack change)
	{
		hbmLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_LOGO_288DPI),
			GetDlgItem (hwndDlg, IDC_LOGO),
			0, 0, 0, 0, FALSE, TRUE);
	}

	EnableDisableButtons (hwndDlg);
}

void EnableDisableButtons (HWND hwndDlg)
{
	HWND hOKButton = GetDlgItem (hwndDlg, IDOK);
	WORD x;

	x = LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST)));

	EnableWindow (hOKButton, TRUE);

}

BOOL VolumeSelected (HWND hwndDlg)
{
	return (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0);
}


void LoadSettings (HWND hwndDlg)
{
	WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

	LoadSysEncSettings ();

	if (LoadNonSysInPlaceEncSettings (&savedWipeAlgorithm) != 0)
		bInPlaceEncNonSysPending = TRUE;

	// If the config file has already been loaded during this session
	if (ConfigBuffer != NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
	}

	// Options
	bExplore =						ConfigReadInt ("OpenExplorerWindowAfterMount", FALSE);
	bCloseDismountedWindows =		ConfigReadInt ("CloseExplorerWindowsOnDismount", TRUE);

	bHistory =						ConfigReadInt ("SaveVolumeHistory", FALSE);

	bCacheInDriverDefault = bCacheInDriver = ConfigReadInt ("CachePasswords", FALSE);
	bWipeCacheOnExit =				ConfigReadInt ("WipePasswordCacheOnExit", FALSE);
	bWipeCacheOnAutoDismount =		ConfigReadInt ("WipeCacheOnAutoDismount", TRUE);

	bStartOnLogon =					ConfigReadInt ("StartOnLogon", FALSE);
	bMountDevicesOnLogon =			ConfigReadInt ("MountDevicesOnLogon", FALSE);
	bMountFavoritesOnLogon =		ConfigReadInt ("MountFavoritesOnLogon", FALSE);

	bEnableBkgTask =				ConfigReadInt ("EnableBackgroundTask", TRUE);
	bCloseBkgTaskWhenNoVolumes =	ConfigReadInt ("CloseBackgroundTaskOnNoVolumes", FALSE);

	bDismountOnLogOff =				ConfigReadInt ("DismountOnLogOff", TRUE);
	bDismountOnPowerSaving =		ConfigReadInt ("DismountOnPowerSaving", FALSE);
	bDismountOnScreenSaver =		ConfigReadInt ("DismountOnScreenSaver", FALSE);
	bForceAutoDismount =			ConfigReadInt ("ForceAutoDismount", TRUE);
	MaxVolumeIdleTime =				ConfigReadInt ("MaxVolumeIdleTime", -60);

	HiddenSectorDetectionStatus =	ConfigReadInt ("HiddenSectorDetectionStatus", 0);

	defaultKeyFilesParam.EnableKeyFiles = ConfigReadInt ("UseKeyfiles", FALSE);

	bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = ConfigReadInt ("PreserveTimestamps", TRUE);
	bShowDisconnectedNetworkDrives = ConfigReadInt ("ShowDisconnectedNetworkDrives", FALSE);
	bHideWaitingDialog = ConfigReadInt ("HideWaitingDialog", FALSE);
	bUseSecureDesktop = ConfigReadInt ("UseSecureDesktop", FALSE);
	bUseLegacyMaxPasswordLength = ConfigReadInt ("UseLegacyMaxPasswordLength", FALSE);
	defaultMountOptions.Removable =	ConfigReadInt ("MountVolumesRemovable", FALSE);
	defaultMountOptions.ReadOnly =	ConfigReadInt ("MountVolumesReadOnly", FALSE);
	defaultMountOptions.ProtectHiddenVolume = FALSE;
	defaultMountOptions.PartitionInInactiveSysEncScope = FALSE;
	defaultMountOptions.RecoveryMode = FALSE;
	defaultMountOptions.UseBackupHeader =  FALSE;

	mountOptions = defaultMountOptions;

	CloseSecurityTokenSessionsAfterMount = ConfigReadInt ("CloseSecurityTokenSessionsAfterMount", 0);

	{
		char szTmp[TC_MAX_PATH] = {0};
		WideCharToMultiByte (CP_UTF8, 0, SecurityTokenLibraryPath, -1, szTmp, sizeof (szTmp), NULL, NULL);
		ConfigReadString ("SecurityTokenLibrary", "", szTmp, sizeof (szTmp) - 1);
		MultiByteToWideChar (CP_UTF8, 0, szTmp, -1, SecurityTokenLibraryPath, ARRAYSIZE (SecurityTokenLibraryPath));

		if (SecurityTokenLibraryPath[0])
			InitSecurityTokenLibrary(hwndDlg);
	}

	/* we don't load the history */
}


BOOL SelectItem (HWND hTree, wchar_t nLetter)
{
	int i;
	LVITEM item;

	for (i = 0; i < ListView_GetItemCount(hTree); i++)
	{
		memset(&item, 0, sizeof(LVITEM));
		item.mask = LVIF_PARAM;
		item.iItem = i;

		if (ListView_GetItem (hTree, &item) == FALSE)
			return FALSE;
		else
		{
			if (HIWORD (item.lParam) == nLetter)
			{
				memset(&item, 0, sizeof(LVITEM));
				item.state = LVIS_FOCUSED|LVIS_SELECTED;
				item.stateMask = LVIS_FOCUSED|LVIS_SELECTED;
				item.mask = LVIF_STATE;
				item.iItem = i;
				SendMessage(hTree, LVM_SETITEMSTATE, i, (LPARAM) &item);
				return TRUE;
			}
		}
	}

	return TRUE;
}



LPARAM
GetSelectedLong (HWND hTree)
{
	int hItem = ListView_GetSelectionMark (hTree);
	LVITEM item;

	if (nSelectedDriveIndex >= 0)
		hItem = nSelectedDriveIndex;

	memset(&item, 0, sizeof(LVITEM));
	item.mask = LVIF_PARAM;
	item.iItem = hItem;

	if (ListView_GetItem (hTree, &item) == FALSE)
		return MAKELONG (0xffff, 0xffff);
	else
		return item.lParam;
}

LPARAM
GetItemLong (HWND hTree, int itemNo)
{
	LVITEM item;

	memset(&item, 0, sizeof(LVITEM));
	item.mask = LVIF_PARAM;
	item.iItem = itemNo;

	if (ListView_GetItem (hTree, &item) == FALSE)
		return MAKELONG (0xffff, 0xffff);
	else
		return item.lParam;
}

static wchar_t PasswordDlgVolume[MAX_PATH + 1] = {0};
static BOOL PasswordDialogDisableMountOptions;
static char *PasswordDialogTitleStringId;

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK ExtcvPasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static Password *szXPwd;
	static int *pkcs5;
	static int *pim;
	static BOOL* truecryptMode;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			int i, nIndex;
			szXPwd = ((PasswordDlgParam *) lParam) -> password;
			pkcs5 = ((PasswordDlgParam *) lParam) -> pkcs5;
			pim = ((PasswordDlgParam *) lParam) -> pim;
			truecryptMode = ((PasswordDlgParam *) lParam) -> truecryptMode;
			LocalizeDialog (hwndDlg, "IDD_PASSWORD_DLG");
			DragAcceptFiles (hwndDlg, TRUE);

			if (PasswordDialogTitleStringId)
			{
				SetWindowTextW (hwndDlg, GetString (PasswordDialogTitleStringId));
			}
			else if (wcslen (PasswordDlgVolume) > 0)
			{
				wchar_t s[1024];
				const int maxVisibleLen = 40;

				if (wcslen (PasswordDlgVolume) > maxVisibleLen)
				{
					wstring volStr = PasswordDlgVolume;
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), (L"..." + volStr.substr (volStr.size() - maxVisibleLen - 1)).c_str());
				}
				else
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), PasswordDlgVolume);

				SetWindowTextW (hwndDlg, s);
			}

			/* Populate the PRF algorithms list */
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex =(int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex, (LPARAM) i);
			}

			/* make autodetection the default */
			SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

			ToNormalPwdField (hwndDlg, IDC_PASSWORD);
			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PIM), EM_LIMITTEXT, MAX_PIM, 0);

			SetPim (hwndDlg, IDC_PIM, *pim);

			/* make PIM field visible if a PIM value has been explicitely specified */
			if (*pim > 0)
			{
				ShowWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), SW_SHOW);
			}

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);

			mountOptions.PartitionInInactiveSysEncScope = bPrebootPasswordDlgMode;

			if (bPrebootPasswordDlgMode)
			{
				SendMessage (hwndDlg, TC_APPMSG_PREBOOT_PASSWORD_MODE, 0, 0);
			}

			if (PasswordDialogDisableMountOptions)
			{
				EnableWindow (GetDlgItem (hwndDlg, IDC_CACHE), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_MOUNT_OPTIONS), FALSE);
			}

			/* No support for mounting TrueCrypt volumes */
			SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRUECRYPT_MODE), FALSE);

			if (!SetForegroundWindow (hwndDlg) && (FavoriteMountOnArrivalInProgress))
			{
				SetWindowPos (hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

				FLASHWINFO flash;
				flash.cbSize = sizeof (flash);
				flash.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
				flash.dwTimeout = 0;
				flash.hwnd = hwndDlg;
				flash.uCount = 0;

				FlashWindowEx (&flash);

				SetWindowPos (hwndDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			}
		}
		return 0;

	case TC_APPMSG_PREBOOT_PASSWORD_MODE:
		{
			/* No support for mounting TrueCrypt system partition */
			SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRUECRYPT_MODE), FALSE);

			/* Repopulate the PRF algorithms list with algorithms that support system encryption */
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			int i, nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			BOOL bIsGPT = FALSE;
			try
			{
				BootEncryption BootEncObj (hwndDlg);
				bIsGPT = BootEncObj.GetSystemDriveConfiguration().SystemPartition.IsGPT;
			}
			catch (...) {}

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				if (bIsGPT || HashForSystemEncryption(i))
				{
					nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
					SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex, (LPARAM) i);
				}
			}

			/* make autodetection the default */
			SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

			ToBootPwdField (hwndDlg, IDC_PASSWORD);

			// Attempt to wipe the password stored in the input field buffer
			wchar_t tmp[MAX_PASSWORD+1];
			wmemset (tmp, L'X', MAX_PASSWORD);
			tmp [MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), L"");

			StringCbPrintfW (OrigKeyboardLayout, sizeof(OrigKeyboardLayout),L"%08X", (DWORD) GetKeyboardLayout (NULL) & 0xFFFF);

			DWORD keybLayout = (DWORD) LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

			if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
			{
				Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", hwndDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			if (SetTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
			{
				Error ("CANNOT_SET_TIMER", hwndDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			if (GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD))
			{
				// simulate hiding password
				SetCheckBox (hwndDlg, IDC_SHOW_PASSWORD, FALSE);

				HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD, IDC_PASSWORD, IDC_PIM);
			}

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), FALSE);

			SetPim (hwndDlg, IDC_PIM, *pim);

			bPrebootPasswordDlgMode = TRUE;
		}
		return 1;

	case WM_TIMER:
		switch (wParam)
		{
		case TIMER_ID_KEYB_LAYOUT_GUARD:
			if (bPrebootPasswordDlgMode)
			{
				DWORD keybLayout = (DWORD) GetKeyboardLayout (NULL);

				if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
				{
					// Keyboard layout is not standard US

					// Attempt to wipe the password stored in the input field buffer
					wchar_t tmp[MAX_PASSWORD+1];
					wmemset (tmp, L'X', MAX_PASSWORD);
					tmp [MAX_PASSWORD] = 0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), L"");

					keybLayout = (DWORD) LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", hwndDlg);
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}

					wchar_t szTmp [4096];
					StringCbCopyW (szTmp, sizeof(szTmp), GetString ("KEYB_LAYOUT_CHANGE_PREVENTED"));
					StringCbCatW (szTmp, sizeof(szTmp), L"\n\n");
					StringCbCatW (szTmp, sizeof(szTmp), GetString ("KEYB_LAYOUT_SYS_ENC_EXPLANATION"));
					MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
				}
			}
			return 1;
		}
		return 0;

	case WM_COMMAND:

		if (lw == IDC_MOUNT_OPTIONS)
		{
			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
				(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions);

			if (!bPrebootPasswordDlgMode && mountOptions.PartitionInInactiveSysEncScope)
				SendMessage (hwndDlg, TC_APPMSG_PREBOOT_PASSWORD_MODE, 0, 0);

			return 1;
		}

		if (lw == IDC_PIM_ENABLE)
		{
			ShowWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), SW_HIDE);
			ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), SW_SHOW);

			SetFocus (GetDlgItem (hwndDlg, IDC_PIM));
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD)
		{
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD, IDC_PASSWORD, IDC_PIM);
			return 1;
		}

		if (lw == IDC_KEY_FILES)
		{
			KeyFilesDlgParam param;
			param.EnableKeyFiles = KeyFilesEnable;
			param.FirstKeyFile = FirstKeyFile;

			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &param))
			{
				KeyFilesEnable = param.EnableKeyFiles;
				FirstKeyFile = param.FirstKeyFile;

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
			}

			return 1;
		}

		if (lw == IDC_KEYFILES_ENABLE)
		{
			KeyFilesEnable = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE);

			return 1;
		}

		if (lw == IDCANCEL || lw == IDOK)
		{
			wchar_t tmp[MAX_PASSWORD+1];

			if (lw == IDOK)
			{
				BOOL bTrueCryptMode = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE);
				int iMaxPasswordLength = (bUseLegacyMaxPasswordLength || bTrueCryptMode)? MAX_LEGACY_PASSWORD : MAX_PASSWORD;
				if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
					KeyFilesApply (hwndDlg, &mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, PasswordDlgVolume);

				if (GetPassword (hwndDlg, IDC_PASSWORD, (LPSTR) szXPwd->Text, iMaxPasswordLength + 1, bTrueCryptMode, TRUE))
					szXPwd->Length = (unsigned __int32) (strlen ((char *) szXPwd->Text));
				else
					return 1;

				bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));
				*pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);
				*truecryptMode = bTrueCryptMode;

				*pim = GetPim (hwndDlg, IDC_PIM, 0);

				/* check that PRF is supported in TrueCrypt Mode */
				if (	(*truecryptMode)
					&& ((!is_pkcs5_prf_supported(*pkcs5, TRUE, PRF_BOOT_NO)) || (mountOptions.ProtectHiddenVolume && !is_pkcs5_prf_supported(mountOptions.ProtectedHidVolPkcs5Prf, TRUE, PRF_BOOT_NO)))
					)
				{
					Error ("ALGO_NOT_SUPPORTED_FOR_TRUECRYPT_MODE", hwndDlg);
					return 1;
				}

				if (	(*truecryptMode)
					&&	(*pim != 0)
					)
				{
					Error ("PIM_NOT_SUPPORTED_FOR_TRUECRYPT_MODE", hwndDlg);
					return 1;
				}
			}

			// Attempt to wipe password stored in the input field buffer
			wmemset (tmp, L'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);

			if (hidVolProtKeyFilesParam.FirstKeyFile != NULL)
			{
				KeyFileRemoveAll (&hidVolProtKeyFilesParam.FirstKeyFile);
				hidVolProtKeyFilesParam.EnableKeyFiles = FALSE;
			}

			if (bPrebootPasswordDlgMode)
			{
				KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);

				// Restore the original keyboard layout
				if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL)
					Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT", hwndDlg);
			}

			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;

	case WM_CONTEXTMENU:
		{
			RECT buttonRect;
			GetWindowRect (GetDlgItem (hwndDlg, IDC_KEY_FILES), &buttonRect);

			if (LOWORD (lParam) >= buttonRect.left && LOWORD (lParam) <= buttonRect.right
				&& HIWORD (lParam) >= buttonRect.top && HIWORD (lParam) <= buttonRect.bottom)
			{
				// The "Keyfiles" button has been right-clicked

				KeyFilesDlgParam param;
				param.EnableKeyFiles = KeyFilesEnable;
				param.FirstKeyFile = FirstKeyFile;

				POINT popupPos;
				popupPos.x = buttonRect.left + 2;
				popupPos.y = buttonRect.top + 2;

				if (KeyfilesPopupMenu (hwndDlg, popupPos, &param))
				{
					KeyFilesEnable = param.EnableKeyFiles;
					FirstKeyFile = param.FirstKeyFile;
					SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
				}
			}
		}
		break;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			int i = 0, count = DragQueryFile (hdrop, 0xFFFFFFFF, NULL, 0);

			while (count-- > 0)
			{
				KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
				if (kf)
				{
					DragQueryFile (hdrop, i++, kf->FileName, ARRAYSIZE (kf->FileName));
					FirstKeyFile = KeyFileAdd (FirstKeyFile, kf);
					KeyFilesEnable = TRUE;
				}
			}

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);
			DragFinish (hdrop);
		}
		return 1;
	}

	return 0;
}

void SaveSettings (HWND hwndDlg)
{
	// dummy
}

int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume)
{
	// dummy
	return 0;
}

int RestoreVolumeHeader (HWND hwndDlg, char *lpszVolume)
{
	// dummy
	return 0;
}

int ExtcvAskVolumePassword (HWND hwndDlg, const wchar_t* fileName, Password *password, int *pkcs5, int *pim, BOOL* truecryptMode, char *titleStringId, BOOL enableMountOptions)
{
	INT_PTR result;
	PasswordDlgParam dlgParam;

	PasswordDialogTitleStringId = titleStringId;
	PasswordDialogDisableMountOptions = !enableMountOptions;

	dlgParam.password = password;
	dlgParam.pkcs5 = pkcs5;
	dlgParam.pim = pim;
	dlgParam.truecryptMode = truecryptMode;

	StringCbCopyW (PasswordDlgVolume, sizeof(PasswordDlgVolume), fileName);

	result = SecureDesktopDialogBoxParam (hInst,
		MAKEINTRESOURCEW (IDD_PASSWORD_DLG), hwndDlg,
		(DLGPROC) ExtcvPasswordDlgProc, (LPARAM) &dlgParam);

	if (result != IDOK)
	{
		password->Length = 0;
		*pkcs5 = 0;
		*pim = 0;
		*truecryptMode = FALSE;
		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
		burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));
	}

	return result == IDOK;
}

// GUI actions

static BOOL SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, "OPEN_VOL_TITLE", szFileName, bHistory, FALSE, NULL) == FALSE)
		return FALSE;

	AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
	VeraCryptExpander::EnableDisableButtons (hwndDlg);
	SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
	return TRUE;
}

static BOOL SelectPartition (HWND hwndDlg)
{
	RawDevicesDlgParam param;
	param.pszFileName = szFileName;
	INT_PTR nResult = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) & param);
	if (nResult == IDOK)
	{
		AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
		VeraCryptExpander::EnableDisableButtons (hwndDlg);
		SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		return TRUE;
	}

	return FALSE;
}


/* Except in response to the WM_INITDIALOG and WM_ENDSESSION messages, the dialog box procedure
   should return nonzero if it processes a message, and zero if it does not. */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static UINT taskBarCreatedMsg;
	WORD lw = LOWORD (wParam);

	switch (uMsg)
	{

	case WM_INITDIALOG:
		{
			int exitCode = 0;

			MainDlg = hwndDlg;

			// Set critical default options in case UsePreferences is false
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = TRUE;
			bShowDisconnectedNetworkDrives = FALSE;
			bHideWaitingDialog = FALSE;
			bUseSecureDesktop = FALSE;
			bUseLegacyMaxPasswordLength = FALSE;

			if (UsePreferences)
			{
				// General preferences
				VeraCryptExpander::LoadSettings (hwndDlg);

				// Keyfiles
				LoadDefaultKeyFilesParam ();
				RestoreDefaultKeyFilesParam ();
			}

			InitMainDialog (hwndDlg);

			// Quit
			if (Quit)
			{
				exit (exitCode);
			}

			Silent = FALSE;
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_ENDSESSION:
		VeraCryptExpander::EndMainDlg (hwndDlg);
		localcleanup ();
		return 0;

	case WM_COMMAND:

		if (lw == IDCANCEL || lw == IDC_EXIT)
		{
			VeraCryptExpander::EndMainDlg (hwndDlg);
			return 1;
		}

		if ( lw == IDOK )
		{
			if (!VeraCryptExpander::VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
			}
			else
			{
				wchar_t fileName[MAX_PATH];
				GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), fileName, ARRAYSIZE (fileName));
				ExpandVolumeWizard(hwndDlg, fileName);
			}
			return 1;
		}

		if (lw == IDM_ABOUT )
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}

		if (lw == IDM_HOMEPAGE )
		{
			ArrowWaitCursor ();
			ShellExecute (NULL, L"open", L"https://www.veracrypt.fr", NULL, NULL, SW_SHOWNORMAL);
			Sleep (200);
			NormalCursor ();

			return 1;
		}

		if (lw == IDC_SELECT_FILE)
		{
			SelectContainer (hwndDlg);
			return 1;
		}

		if (lw == IDC_SELECT_DEVICE)
		{
			SelectPartition (hwndDlg);
			return 1;
		}

		return 0;

	case WM_CLOSE:
		VeraCryptExpander::EndMainDlg (hwndDlg);
		return 1;

	default:
		;
	}

	return 0;
}

}


int WINAPI wWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, wchar_t *lpszCommandLine, int nCmdShow)
{
	int status;
	atexit (VeraCryptExpander::localcleanup);
	SetProcessShutdownParameters (0x100, 0);

	VirtualLock (&VeraCryptExpander::VolumePassword, sizeof (VeraCryptExpander::VolumePassword));
	VirtualLock (&VeraCryptExpander::CmdVolumePassword, sizeof (VeraCryptExpander::CmdVolumePassword));
	VirtualLock (&VeraCryptExpander::mountOptions, sizeof (VeraCryptExpander::mountOptions));
	VirtualLock (&VeraCryptExpander::defaultMountOptions, sizeof (VeraCryptExpander::defaultMountOptions));
	VirtualLock (&VeraCryptExpander::szFileName, sizeof(VeraCryptExpander::szFileName));

	InitApp (hInstance, lpszCommandLine);

	/* application title */
	lpszTitle = L"VeraCrypt Expander";

	DetectX86Features ();

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL, SRC_POS);
		else
			handleError (NULL, status, SRC_POS);

		AbortProcess ("NODRIVER");
	}

	/* Create the main dialog box */
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_MOUNT_DLG), NULL, (DLGPROC) VeraCryptExpander::MainDialogProc,
			(LPARAM) lpszCommandLine);

	/* Terminate */
	return 0;
}
