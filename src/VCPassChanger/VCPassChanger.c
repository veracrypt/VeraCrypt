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
#include "cpu.h"

#include <time.h>
#include <math.h>
#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <shlobj.h>
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
#include "VCPassChanger.h"
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
#include "../Setup/SelfExtract.h"
#include "../Common/EncryptionThreadPool.h"

#include <Strsafe.h>
#include <InitGuid.h>
#include <devguid.h>
#include <intrin.h>
#include <shellapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Comctl32.lib")

#pragma intrinsic(_InterlockedCompareExchange, _InterlockedExchange)

using namespace VeraCrypt;

#define TIMER_INTERVAL_MAIN					500
#define TIMER_INTERVAL_KEYB_LAYOUT_GUARD	10
#define TIMER_INTERVAL_UPDATE_DEVICE_LIST	1000
#define TIMER_INTERVAL_CHECK_FOREGROUND		500

BOOL bExplore = FALSE;				/* Display explorer window after mount */
BOOL bBeep = FALSE;					/* Donot beep after mount */
wchar_t szFileName[TC_MAX_PATH+1];		/* Volume to mount */
wchar_t szDriveLetter[3];				/* Drive Letter to mount */
wchar_t commandLineDrive = 0;
BOOL bCacheInDriver = FALSE;		/* Cache any passwords we see */
BOOL bCacheInDriverDefault = FALSE;
BOOL bCacheDuringMultipleMount = FALSE;
BOOL bCmdCacheDuringMultipleMount = FALSE;
BOOL bIncludePimInCache = FALSE;
BOOL bTryEmptyPasswordWhenKeyfileUsed = FALSE;
BOOL bCmdTryEmptyPasswordWhenKeyfileUsed = FALSE;
BOOL bCmdTryEmptyPasswordWhenKeyfileUsedValid = FALSE;
BOOL bHistoryCmdLine = FALSE;		/* History control is always disabled */
BOOL bUseDifferentTrayIconIfVolMounted = TRUE;
BOOL bCloseDismountedWindows=TRUE;	/* Close all open explorer windows of dismounted volume */
BOOL bWipeCacheOnExit = FALSE;		/* Wipe password from chace on exit */
BOOL bWipeCacheOnAutoDismount = TRUE;
BOOL bEnableBkgTask = FALSE;
BOOL bCloseBkgTaskWhenNoVolumes = FALSE;
BOOL bDismountOnLogOff = TRUE;
BOOL bDismountOnSessionLocked = TRUE;
BOOL bDismountOnScreenSaver = TRUE;
BOOL bDismountOnPowerSaving = FALSE;
BOOL bForceAutoDismount = TRUE;
BOOL bForceMount = FALSE;			/* Mount volume even if host file/device already in use */
BOOL bForceUnmount = FALSE;			/* Unmount volume even if it cannot be locked */
BOOL bWipe = FALSE;					/* Wipe driver passwords */
BOOL bAuto = FALSE;					/* Do everything without user input */
BOOL LogOn = FALSE;
BOOL bAutoMountDevices = FALSE;		/* Auto-mount devices */
BOOL bAutoMountFavorites = FALSE;
BOOL bPlaySoundOnSuccessfulHkDismount = TRUE;
BOOL bDisplayBalloonOnSuccessfulHkDismount = TRUE;
BOOL bHibernationPreventionNotified = FALSE;	/* TRUE if the user has been notified that hibernation was prevented (system encryption) during the session. */
BOOL bHiddenSysLeakProtNotifiedDuringSession = FALSE;	/* TRUE if the user has been notified during the session that unencrypted filesystems and non-hidden TrueCrypt volumes are mounted as read-only under hidden OS. */
BOOL CloseSecurityTokenSessionsAfterMount = FALSE;

BOOL Quit = FALSE;					/* Exit after processing command line */
BOOL ComServerMode = FALSE;
BOOL ServiceMode = FALSE;
BOOL UsePreferences = TRUE;

BOOL bSystemIsGPT = FALSE;
wchar_t szDefaultRescueDiskName[TC_MAX_PATH+1];
wchar_t szRescueDiskExtension[4];

int MaxVolumeIdleTime = -120;
int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = -1;		/* Item number of selected drive */

BOOL CmdSelectDevice = FALSE;		/* indicate if Select Device dialog should be triggered automatically on startup */

int cmdUnmountDrive = -2;			/* Volume drive letter to unmount (-1 = all) */
Password VolumePassword;			/* Password used for mounting volumes */
Password CmdVolumePassword;			/* Password passed from command line */
int VolumePkcs5 = 0;
int CmdVolumePkcs5 = 0;
int VolumePim = -1;
int CmdVolumePim = -1;
int DefaultVolumePkcs5 = 0;
BOOL VolumeTrueCryptMode = FALSE;
BOOL CmdVolumeTrueCryptMode = FALSE;
BOOL DefaultVolumeTrueCryptMode = FALSE;
BOOL CmdVolumePasswordValid = FALSE;
MountOptions CmdMountOptions;
BOOL CmdMountOptionsValid = FALSE;
MountOptions mountOptions;
MountOptions defaultMountOptions;
KeyFile *FirstCmdKeyFile = NULL;

HBITMAP hbmLogoBitmapRescaled = NULL;
wchar_t OrigKeyboardLayout [8+1] = L"00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */

static KeyFilesDlgParam				hidVolProtKeyFilesParam = {0};

static BOOL MainWindowHidden = FALSE;
static int pwdChangeDlgMode	= PCDM_CHANGE_PASSWORD;
static int bSysEncPwdChangeDlgMode = FALSE;
static int bPrebootPasswordDlgMode = FALSE;
static int NoCmdLineArgs;


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
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
	burn (&mountOptions, sizeof (mountOptions));
	burn (&defaultMountOptions, sizeof (defaultMountOptions));
	burn (szFileName, sizeof(szFileName));

	KeyFileRemoveAll (&FirstCmdKeyFile);
	KeyFileRemoveAll (&hidVolProtKeyFilesParam.FirstKeyFile);

	/* Cleanup common code resources */
	cleanup ();

	RandStop (TRUE);
}


void EndMainDlg (HWND hwndDlg)
{

	SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), L"");

	EndDialog (hwndDlg, 0);
}

HICON LoadShieldIcon()
{
    SHSTOCKICONINFO sii = {sizeof(sii)};
    if (SUCCEEDED(SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON | SHGSI_SMALLICON, &sii)))
    {
        return sii.hIcon;
    }
    return NULL;
}

// thread to send a message to the main dialog to simulate click on the Select Device button
void SelectDeviceThreadProc(void* pArg)
{
	HWND hwndDlg = (HWND) pArg;
	Sleep(250);
	PostMessage(hwndDlg, WM_COMMAND, IDC_SELECT_DEVICE, 0);
}

static void InitMainDialog (HWND hwndDlg)
{
	MENUITEMINFOW info;
	wchar_t *str;
	int i;

	if (!Silent)
	{
		/* Call the common dialog init code */
		InitDialog (hwndDlg);
		LocalizeDialog (hwndDlg, NULL);

		SetWindowLongPtrW (hwndDlg, DWLP_USER, (LONG_PTR) (IsAdmin() ? TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES : 0));

		DragAcceptFiles (hwndDlg, TRUE);

		SendMessageW (GetDlgItem (hwndDlg, IDC_VOLUME), EM_LIMITTEXT, TC_MAX_PATH, 0);
		SetWindowTextW (hwndDlg, (IsAdmin() && !IsBuiltInAdmin() && IsUacSupported()) ? (wstring (lpszTitle) + L" [" + GetString ("ADMINISTRATOR") + L"]").c_str() : lpszTitle);

		// add UAC shield icon to the IDC_SELECT_DEVICE button if UAC is enabled and application is not running as admin
		if (IsUacSupported() && !(IsAdmin() && !IsBuiltInAdmin()))
		{
			BUTTON_IMAGELIST bil = {0};
			bil.himl = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 1);
			HICON hIcon = LoadShieldIcon();
			if (hIcon)
			{
				ImageList_AddIcon(bil.himl, hIcon);
				DestroyIcon(hIcon);  // Clean up the icon after adding it to the image list
				
				bil.margin.left = 5;
				bil.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;

				SendMessage(GetDlgItem(hwndDlg, IDC_SELECT_DEVICE), BCM_SETIMAGELIST, 0, (LPARAM)&bil);
			}
		}

		// Help file name
		InitHelpFileName();

		// Localize menu strings
		for (i = 40001; str = (wchar_t *)GetDictionaryValueByInt (i); i++)
		{
			info.cbSize = sizeof (info);
			info.fMask = MIIM_TYPE;
			info.fType = MFT_STRING;
			info.dwTypeData = str;
			info.cch = (UINT) wcslen (str);

			SetMenuItemInfoW (GetMenu (hwndDlg), i, FALSE,  &info);
		}
	}

	if (NeedPeriodicDeviceListUpdate)
	{
		// initialize the list of devices available for mounting as early as possible
		UpdateMountableHostDeviceList ();
	}

	{
		// Resize the logo bitmap if the user has a non-default DPI
		if (ScreenDPI != USER_DEFAULT_SCREEN_DPI
			&& hbmLogoBitmapRescaled == NULL)	// If not re-called (e.g. after language pack change)
		{
			hbmLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_LOGO_288DPI),
				GetDlgItem (hwndDlg, IDC_LOGO),
				0, 0, 0, 0, FALSE, TRUE);
		}

		// Ensure bottom buttons are visible if the user sets a large font size
		RECT mainRectScreen, boxRectScreen;
		ULONG mainHeigth, mainWidth, correctHeigth;
		GetWindowRect (hwndDlg, &mainRectScreen);
		GetWindowRect (GetDlgItem (hwndDlg, IDC_LOWER_BOX), &boxRectScreen);

		mainHeigth = mainRectScreen.bottom - mainRectScreen.top;
		mainWidth = mainRectScreen.right - mainRectScreen.left;
		correctHeigth =  boxRectScreen.bottom - mainRectScreen.top + CompensateYDPI (5);

		if (mainHeigth < correctHeigth)
		{
			SetWindowPos (hwndDlg, NULL, 0, 0, mainWidth, correctHeigth , SWP_NOACTIVATE | SWP_NOZORDER  | SWP_NOMOVE);
		}
	}

	if (CmdSelectDevice)
	{
		CmdSelectDevice = FALSE;
		// start a thread to simulate click on the Select Device button
		_beginthread(SelectDeviceThreadProc, 0, hwndDlg);
	}
}


BOOL VolumeSelected (HWND hwndDlg)
{
	return (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0);
}

void GetVolumePath (HWND hwndDlg, LPWSTR szPath, int nMaxCount)
{
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szPath, nMaxCount);
	CorrectFileName (szPath);
}


void LoadSettingsAndCheckModified (HWND hwndDlg, BOOL bOnlyCheckModified, BOOL* pbSettingsModified, BOOL* pbHistoryModified)
{
	char langid[6] = {0};
	if (!bOnlyCheckModified)
	{
	   EnableHwEncryption ((ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? FALSE : TRUE);
	   EnableCpuRng ((ReadDriverConfigurationFlags() & VC_DRIVER_CONFIG_ENABLE_CPU_RNG) ? TRUE : FALSE);
	}

	WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

	if (!bOnlyCheckModified)
		LoadSysEncSettings ();

	if (!bOnlyCheckModified && LoadNonSysInPlaceEncSettings (&savedWipeAlgorithm) != 0)
		bInPlaceEncNonSysPending = TRUE;

	// If the config file has already been loaded during this session
	if (ConfigBuffer != NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
	}

	ConfigReadCompareInt ("UseKeyfiles", FALSE, &defaultKeyFilesParam.EnableKeyFiles, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("PreserveTimestamps", TRUE, &defaultMountOptions.PreserveTimestamp, bOnlyCheckModified, pbSettingsModified);
	if (!bOnlyCheckModified)
		bPreserveTimestamp = defaultMountOptions.PreserveTimestamp;

	ConfigReadCompareInt ("UseSecureDesktop", FALSE, &bUseSecureDesktop, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("UseLegacyMaxPasswordLength", FALSE, &bUseLegacyMaxPasswordLength, bOnlyCheckModified, pbSettingsModified);

	if (!bOnlyCheckModified)
	{
		defaultMountOptions.ProtectHiddenVolume = FALSE;
		defaultMountOptions.ProtectedHidVolPkcs5Prf = 0;
		defaultMountOptions.ProtectedHidVolPim = 0;
		defaultMountOptions.PartitionInInactiveSysEncScope = FALSE;
		defaultMountOptions.RecoveryMode = FALSE;
		defaultMountOptions.UseBackupHeader =  FALSE;

		mountOptions = defaultMountOptions;
	}

	ConfigReadCompareInt ("CloseSecurityTokenSessionsAfterMount", 0, &CloseSecurityTokenSessionsAfterMount, bOnlyCheckModified, pbSettingsModified);

	// Drive letter - command line arg overrides registry
	if (!bOnlyCheckModified && bHistory && szDriveLetter[0] == 0)
	{
		char szTmp[3] = {0};
		ConfigReadString ("LastSelectedDrive", "", szTmp, sizeof (szTmp));
		MultiByteToWideChar (CP_UTF8, 0, szTmp, -1, szDriveLetter, ARRAYSIZE (szDriveLetter));
	}

	{
		char szTmp[MAX_PATH];
		WideCharToMultiByte (CP_UTF8, 0, SecurityTokenLibraryPath, -1, szTmp, MAX_PATH, NULL, NULL);
		ConfigReadCompareString ("SecurityTokenLibrary", "", szTmp, sizeof (szTmp) - 1, bOnlyCheckModified, pbSettingsModified);
		MultiByteToWideChar (CP_UTF8, 0, szTmp, -1, SecurityTokenLibraryPath, ARRAYSIZE (SecurityTokenLibraryPath));
		if (!bOnlyCheckModified && SecurityTokenLibraryPath[0])
		{
			InitSecurityTokenLibrary(hwndDlg);
		}
	}

	if (bOnlyCheckModified)
	{
		if (!IsNonInstallMode ())
		{
			ConfigReadString ("Language", "", langid, sizeof (langid));
			// when installed, if no preferred language set by user, English is set default
			//
			if (langid [0] == 0)
				StringCbCopyA (langid, sizeof(langid), "en");

			if (pbSettingsModified && strcmp (langid, GetPreferredLangId ()))
				*pbSettingsModified = TRUE;
		}
		else
		{
			StringCbCopyA (langid, sizeof(langid), GetPreferredLangId ());
			ConfigReadCompareString ("Language", "", langid, sizeof (langid), TRUE, pbSettingsModified);
		}
	}


}

void LoadSettings ( HWND hwndDlg )
{
	LoadSettingsAndCheckModified (hwndDlg, FALSE, NULL, NULL);
}


static void PasswordChangeEnable (HWND hwndDlg, int button, int passwordId, BOOL keyFilesEnabled,
								  int newPasswordId, int newVerifyId, BOOL newKeyFilesEnabled)
{
	char password[MAX_PASSWORD + 1];
	char newPassword[MAX_PASSWORD + 1];
	char newVerify[MAX_PASSWORD + 1];
	wchar_t tmp[MAX_PASSWORD + 1];
	BOOL bEnable = TRUE;
	int passwordUtf8Len, newPasswordUtf8Len, newVerifyUtf8Len;

	GetWindowText (GetDlgItem (hwndDlg, passwordId), tmp, ARRAYSIZE (tmp));
	passwordUtf8Len = WideCharToMultiByte (CP_UTF8, 0, tmp, -1, password, sizeof (password), NULL, NULL);

	if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
		newKeyFilesEnabled = keyFilesEnabled;

	switch (pwdChangeDlgMode)
	{
	case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
	case PCDM_ADD_REMOVE_VOL_KEYFILES:
	case PCDM_CHANGE_PKCS5_PRF:
		memcpy (newPassword, password, sizeof (newPassword));
		memcpy (newVerify, password, sizeof (newVerify));
		newPasswordUtf8Len = passwordUtf8Len;
		newVerifyUtf8Len = passwordUtf8Len;
		break;

	default:
		GetWindowText (GetDlgItem (hwndDlg, newPasswordId), tmp, ARRAYSIZE (tmp));
		newPasswordUtf8Len = WideCharToMultiByte (CP_UTF8, 0, tmp, -1, newPassword, sizeof (newPassword), NULL, NULL);
		GetWindowText (GetDlgItem (hwndDlg, newVerifyId), tmp, ARRAYSIZE (tmp));
		newVerifyUtf8Len = WideCharToMultiByte (CP_UTF8, 0, tmp, -1, newVerify, sizeof (newVerify), NULL, NULL);

	}

	if (passwordUtf8Len <= 0 || (!keyFilesEnabled && ((passwordUtf8Len - 1) < MIN_PASSWORD)))
		bEnable = FALSE;
	else if (strcmp (newPassword, newVerify) != 0)
		bEnable = FALSE;
	else if ((newPasswordUtf8Len <= 0) || (!newKeyFilesEnabled && ((newPasswordUtf8Len - 1) < MIN_PASSWORD)))
		bEnable = FALSE;

	burn (password, sizeof (password));
	burn (newPassword, sizeof (newPassword));
	burn (newVerify, sizeof (newVerify));
	burn (tmp, sizeof (tmp));

	EnableWindow (GetDlgItem (hwndDlg, button), bEnable);
}

// implementation for support of change password operation in wait dialog mechanism

typedef struct
{
	Password *oldPassword;
	int old_pkcs5;
	int old_pim;
	Password *newPassword;
	int pkcs5;
	int pim;
	int wipePassCount;
	BOOL truecryptMode;
	int* pnStatus;
} ChangePwdThreadParam;

void CALLBACK ChangePwdWaitThreadProc(void* pArg, HWND hwndDlg)
{
	ChangePwdThreadParam* pThreadParam = (ChangePwdThreadParam*) pArg;


	{
		// Non-system

		*pThreadParam->pnStatus = ChangePwd (szFileName, pThreadParam->oldPassword, pThreadParam->old_pkcs5, pThreadParam->old_pim, pThreadParam->truecryptMode, pThreadParam->newPassword, pThreadParam->pkcs5, pThreadParam->pim, pThreadParam->wipePassCount, hwndDlg);

	}
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PasswordChangeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static KeyFilesDlgParam newKeyFilesParam;
	static BOOL PimValueChangedWarning = FALSE;
	static int* NewPimValuePtr = NULL;

	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LPARAM nIndex, nSelectedIndex = 0;
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_OLD_PRF_ID);
			int i;
			WipeAlgorithmId headerWipeMode = TC_WIPE_3_DOD_5220;
			int EffectiveVolumePkcs5 = CmdVolumePkcs5;
			BOOL EffectiveVolumeTrueCryptMode = CmdVolumeTrueCryptMode;
			int EffectiveVolumePim = CmdVolumePim;

			/* Priority is given to command line parameters
			 * Default values used only when nothing specified in command line
			 */
			if (EffectiveVolumePkcs5 == 0)
				EffectiveVolumePkcs5 = DefaultVolumePkcs5;
			if (!EffectiveVolumeTrueCryptMode)
				EffectiveVolumeTrueCryptMode = DefaultVolumeTrueCryptMode;

			NewPimValuePtr = (int*) lParam;

			PimValueChangedWarning = FALSE;

			ZeroMemory (&newKeyFilesParam, sizeof (newKeyFilesParam));
			if (NewPimValuePtr)
			{
				/* we are in the case of a volume. Store its name to use it in the key file dialog
				 * this will help avoid using the current container file as a key file
				 */
				StringCbCopyW (newKeyFilesParam.VolumeFileName, sizeof (newKeyFilesParam.VolumeFileName), szFileName);
			}

			SetWindowTextW (hwndDlg, GetString ("IDD_PASSWORDCHANGE_DLG"));
			LocalizeDialog (hwndDlg, "IDD_PASSWORDCHANGE_DLG");

			ToNormalPwdField (hwndDlg, IDC_OLD_PASSWORD);
			ToNormalPwdField (hwndDlg, IDC_PASSWORD);
			ToNormalPwdField (hwndDlg, IDC_VERIFY);
			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PIM), EM_LIMITTEXT, MAX_PIM, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PIM), EM_LIMITTEXT, MAX_PIM, 0);
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);

			SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), TRUE);

			/* Add PRF algorithm list for current password */
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				if (i == EffectiveVolumePkcs5)
				{
					nSelectedIndex = nIndex;
				}
			}

			SendMessage (hComboBox, CB_SETCURSEL, nSelectedIndex, 0);

			/* check TrueCrypt Mode if it was set as default*/
			SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, EffectiveVolumeTrueCryptMode);

			/* set default PIM if set in the command line*/
			if (EffectiveVolumePim > 0)
			{
				SetCheckBox (hwndDlg, IDC_PIM_ENABLE, TRUE);
				ShowWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDT_OLD_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_OLD_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_OLD_PIM_HELP), SW_SHOW);
				SetPim (hwndDlg, IDC_OLD_PIM, EffectiveVolumePim);
			}

			/* Add PRF algorithm list for new password */
			hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("UNCHANGED"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				if (!HashIsDeprecated (i))
				{
					nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
					SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				}
			}

			SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

			PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE, FALSE, TRUE);
			SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &headerWipeMode);

			switch (pwdChangeDlgMode)
			{
			case PCDM_CHANGE_PKCS5_PRF:
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_CHANGE_PKCS5_PRF"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_CHANGE_PKCS5_PRF");
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				break;

			case PCDM_ADD_REMOVE_VOL_KEYFILES:
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_ADD_REMOVE_VOL_KEYFILES"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_ADD_REMOVE_VOL_KEYFILES");
				newKeyFilesParam.EnableKeyFiles = TRUE;
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), FALSE);
				break;

			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
				newKeyFilesParam.EnableKeyFiles = FALSE;
				SetWindowTextW (hwndDlg, GetString ("IDD_PCDM_REMOVE_ALL_KEYFILES_FROM_VOL"));
				LocalizeDialog (hwndDlg, "IDD_PCDM_REMOVE_ALL_KEYFILES_FROM_VOL");
				KeyFilesEnable = TRUE;
				SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_KEYFILES), TRUE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_VERIFY), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), FALSE);
				break;

			case PCDM_CHANGE_PASSWORD:
			default:
				// NOP
				break;
			};

			CheckCapsLock (hwndDlg, FALSE);
			
			if (!bSecureDesktopOngoing)
			{
				PasswordEditDropTarget* pTarget = new PasswordEditDropTarget ();
				if (pTarget->Register (hwndDlg))
				{
					SetWindowLongPtr (hwndDlg, DWLP_USER, (LONG_PTR) pTarget);
				}
				else
					delete pTarget;
			}

			return 0;
		}

	case WM_CTLCOLORSTATIC:
		{
			if (PimValueChangedWarning && ((HWND)lParam == GetDlgItem(hwndDlg, IDC_PIM_HELP)) )
			{
				// we're about to draw the static
				// set the text colour in (HDC)lParam
				SetBkMode((HDC)wParam,TRANSPARENT);
				SetTextColor((HDC)wParam, RGB(255,0,0));
				// NOTE: per documentation as pointed out by selbie, GetSolidBrush would leak a GDI handle.
				return (BOOL)GetSysColorBrush(COLOR_MENU);
			}
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			// Attempt to wipe passwords stored in the input field buffers
			wchar_t tmp[MAX_PASSWORD+1];
			wmemset (tmp, L'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);
			RestoreDefaultKeyFilesParam ();

			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (hw == EN_CHANGE)
		{
			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY,
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);

			if ((lw == IDC_OLD_PIM) && IsWindowEnabled (GetDlgItem (hwndDlg, IDC_PIM)))
			{
				wchar_t tmp[MAX_PIM+1] = {0};
				GetDlgItemText (hwndDlg, IDC_OLD_PIM, tmp, MAX_PIM + 1);
				SetDlgItemText (hwndDlg, IDC_PIM, tmp);
			}

			if (lw == IDC_PIM)
			{
				if(GetPim (hwndDlg, IDC_OLD_PIM, 0) != GetPim (hwndDlg, IDC_PIM, 0))
				{
					PimValueChangedWarning = TRUE;
					SetDlgItemTextW (hwndDlg, IDC_PIM_HELP, GetString (bSysEncPwdChangeDlgMode? "PIM_SYSENC_CHANGE_WARNING" : "PIM_CHANGE_WARNING"));
				}
				else
				{
					PimValueChangedWarning = FALSE;
					SetDlgItemTextW (hwndDlg, IDC_PIM_HELP, (wchar_t *) GetDictionaryValueByInt (IDC_PIM_HELP));
				}
			}

			return 1;
		}

		if (lw == IDC_PIM_ENABLE)
		{
			ShowWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), SW_HIDE);
			ShowWindow (GetDlgItem( hwndDlg, IDT_OLD_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_OLD_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_OLD_PIM_HELP), SW_SHOW);

			// check also the "Use PIM" for the new password if it is enabled
			if (IsWindowEnabled (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE)))
			{
				SetCheckBox (hwndDlg, IDC_NEW_PIM_ENABLE, TRUE);

				ShowWindow (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE), SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), SW_SHOW);
			}

			SetFocus (GetDlgItem (hwndDlg, IDC_OLD_PIM));

			return 1;
		}

		if (lw == IDC_NEW_PIM_ENABLE)
		{
			ShowWindow (GetDlgItem (hwndDlg, IDC_NEW_PIM_ENABLE), SW_HIDE);
			ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), SW_SHOW);
			ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), SW_SHOW);

			SetFocus (GetDlgItem (hwndDlg, IDC_PIM));

			return 1;
		}

		if (lw == IDC_KEYFILES)
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

				SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, KeyFilesEnable);
			}

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY,
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);

			return 1;
		}


		if (lw == IDC_NEW_KEYFILES)
		{

			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &newKeyFilesParam))
			{
				SetCheckBox (hwndDlg, IDC_ENABLE_NEW_KEYFILES, newKeyFilesParam.EnableKeyFiles);

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (hwndDlg, IDOK), GetDlgItem (hwndDlg, IDC_PASSWORD),
					GetDlgItem (hwndDlg, IDC_VERIFY), NULL, NULL,
					newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);
			}

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY,
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);

			return 1;
		}

		if (lw == IDC_ENABLE_KEYFILES)
		{
			KeyFilesEnable = GetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES);

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY,
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);

			return 1;
		}

		if (lw == IDC_ENABLE_NEW_KEYFILES)
		{
			newKeyFilesParam.EnableKeyFiles = GetCheckBox (hwndDlg, IDC_ENABLE_NEW_KEYFILES);

			PasswordChangeEnable (hwndDlg, IDOK,
				IDC_OLD_PASSWORD,
				KeyFilesEnable && FirstKeyFile != NULL,
				IDC_PASSWORD, IDC_VERIFY,
				newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL);

			return 1;
		}

		if (hw == CBN_SELCHANGE)
		{
			switch (lw)
			{
			case IDC_PKCS5_PRF_ID:
				break;
			}
			return 1;

		}

		if (lw == IDC_TRUECRYPT_MODE)
		{
			BOOL bEnablePim = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE) ? FALSE: TRUE;
			EnableWindow (GetDlgItem (hwndDlg, IDT_OLD_PIM), bEnablePim);
			EnableWindow (GetDlgItem (hwndDlg, IDC_OLD_PIM), bEnablePim);
			EnableWindow (GetDlgItem (hwndDlg, IDC_OLD_PIM_HELP), bEnablePim);
		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_ORI)
		{
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_ORI, IDC_OLD_PASSWORD, IDC_OLD_PIM);
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_NEW)
		{
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW, IDC_PASSWORD, IDC_VERIFY);
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW, IDC_PIM, 0);
			return 1;
		}

		if (lw == IDOK)
		{
			HWND hParent = GetParent (hwndDlg);
			Password oldPassword;
			Password newPassword;
			WipeAlgorithmId headerWiperMode = (WipeAlgorithmId) SendMessage (
				GetDlgItem (hwndDlg, IDC_WIPE_MODE),
				CB_GETITEMDATA,
				SendMessage (GetDlgItem (hwndDlg, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
				0);
			int nStatus;
			int old_pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_OLD_PRF_ID), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_OLD_PRF_ID), CB_GETCURSEL, 0, 0), 0);
			int pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);
			BOOL truecryptMode = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE);

			int old_pim = GetPim (hwndDlg, IDC_OLD_PIM, 0);
			int pim = GetPim (hwndDlg, IDC_PIM, 0);
			int iMaxPasswordLength = (bUseLegacyMaxPasswordLength || truecryptMode)? MAX_LEGACY_PASSWORD : MAX_PASSWORD;

			if (truecryptMode && !is_pkcs5_prf_supported (old_pkcs5, TRUE, PRF_BOOT_NO))
			{
				Error ("ALGO_NOT_SUPPORTED_FOR_TRUECRYPT_MODE", hwndDlg);
				return 1;
			}
			else if (truecryptMode && (old_pim != 0))
			{
				Error ("PIM_NOT_SUPPORTED_FOR_TRUECRYPT_MODE", hwndDlg);
				return 1;
			}

			if (pim > MAX_PIM_VALUE)
			{
				SetFocus (GetDlgItem(hwndDlg, IDC_PIM));
				Error ("PIM_TOO_BIG", hwndDlg);
				return 1;
			}

			if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
			{
				newKeyFilesParam.EnableKeyFiles = KeyFilesEnable;
			}
			else if (!(newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL)
				&& pwdChangeDlgMode == PCDM_CHANGE_PASSWORD)
			{
				int bootPRF = 0;
				if (!CheckPasswordLength (hwndDlg, GetWindowTextLength(GetDlgItem (hwndDlg, IDC_PASSWORD)), pim, bSysEncPwdChangeDlgMode, bootPRF, FALSE, FALSE))
					return 1;
			}

			GetVolumePath (hParent, szFileName, ARRAYSIZE (szFileName));

			if (GetPassword (hwndDlg, IDC_OLD_PASSWORD, (LPSTR) oldPassword.Text, iMaxPasswordLength + 1, truecryptMode, TRUE))
				oldPassword.Length = (unsigned __int32) strlen ((char *) oldPassword.Text);
			else
			{
				return 1;
			}

			switch (pwdChangeDlgMode)
			{
			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			case PCDM_ADD_REMOVE_VOL_KEYFILES:
			case PCDM_CHANGE_PKCS5_PRF:
				memcpy (newPassword.Text, oldPassword.Text, sizeof (newPassword.Text));
				newPassword.Length = (unsigned __int32) strlen ((char *) oldPassword.Text);
				pim = old_pim;
				break;

			default:
				if (GetPassword (hwndDlg, IDC_PASSWORD, (LPSTR) newPassword.Text, iMaxPasswordLength + 1, FALSE, TRUE))
					newPassword.Length = (unsigned __int32) strlen ((char *) newPassword.Text);
				else
					return 1;
			}

			WaitCursor ();

			if (KeyFilesEnable)
				KeyFilesApply (hwndDlg, &oldPassword, FirstKeyFile, szFileName);

			if (newKeyFilesParam.EnableKeyFiles)
			{
				if (!KeyFilesApply (hwndDlg, &newPassword, pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF ? FirstKeyFile : newKeyFilesParam.FirstKeyFile, szFileName))
				{
					nStatus = ERR_DONT_REPORT;
					goto err;
				}
			}

			ChangePwdThreadParam changePwdParam;
			changePwdParam.oldPassword = &oldPassword;
			changePwdParam.old_pkcs5 = old_pkcs5;
			changePwdParam.old_pim = old_pim;
			changePwdParam.newPassword = &newPassword;
			changePwdParam.pkcs5 = pkcs5;
			changePwdParam.pim = pim;
			changePwdParam.wipePassCount = GetWipePassCount(headerWiperMode);
			changePwdParam.pnStatus = &nStatus;
			changePwdParam.truecryptMode = truecryptMode;

			ShowWaitDialog(hwndDlg, TRUE, ChangePwdWaitThreadProc, &changePwdParam);

err:
			// notify the caller in case the PIM has changed
			if (NewPimValuePtr)
			{
				if (pim != old_pim)
					*NewPimValuePtr = pim;
				else
					*NewPimValuePtr = -1;
			}

			burn (&oldPassword, sizeof (oldPassword));
			burn (&newPassword, sizeof (newPassword));
			burn (&old_pim, sizeof(old_pim));
			burn (&pim, sizeof(pim));

			NormalCursor ();

			if (nStatus == 0)
			{
				// Attempt to wipe passwords stored in the input field buffers
				wchar_t tmp[MAX_PASSWORD+1];
				wmemset (tmp, L'X', MAX_PASSWORD);
				tmp[MAX_PASSWORD] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
				SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);

				KeyFileRemoveAll (&newKeyFilesParam.FirstKeyFile);
				RestoreDefaultKeyFilesParam ();

				EndDialog (hwndDlg, IDOK);
			}
			return 1;
		}
		return 0;

	case WM_NCDESTROY:
		{
			/* unregister drap-n-drop support */
			PasswordEditDropTarget* pTarget = (PasswordEditDropTarget*) GetWindowLongPtr (hwndDlg, DWLP_USER);
			if (pTarget)
			{
				SetWindowLongPtr (hwndDlg, DWLP_USER, (LONG_PTR) 0);
				pTarget->Revoke ();
				pTarget->Release();
			}
		}
		return 0;
	}

	return 0;
}


static void ChangePassword (HWND hwndDlg)
{
	INT_PTR result;
	int newPimValue = -1;

	GetVolumePath (hwndDlg, szFileName, ARRAYSIZE (szFileName));

	if (!TranslateVolumeID (hwndDlg, szFileName, ARRAYSIZE (szFileName)))
	{
		return;
	}

	if (IsMountedVolume (szFileName))
	{
		Warning (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF ? "MOUNTED_NO_PKCS5_PRF_CHANGE" : "MOUNTED_NOPWCHANGE", hwndDlg);
		return;
	}

	if (!VolumePathExists (szFileName))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		return;
	}

	bSysEncPwdChangeDlgMode = FALSE;

	result = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_PASSWORDCHANGE_DLG), hwndDlg,
		(DLGPROC) PasswordChangeDlgProc, (LPARAM) &newPimValue);

	if (result == IDOK)
	{
		switch (pwdChangeDlgMode)
		{
		case PCDM_CHANGE_PKCS5_PRF:
			Info ("PKCS5_PRF_CHANGED", hwndDlg);
			break;

		case PCDM_ADD_REMOVE_VOL_KEYFILES:
		case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			Info ("KEYFILE_CHANGED", hwndDlg);
			break;

		case PCDM_CHANGE_PASSWORD:
		default:
			{
				Info ("PASSWORD_CHANGED", hwndDlg);
			}
		}
	}
}


BOOL SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, "OPEN_VOL_TITLE", szFileName, bHistory, FALSE, NULL) == FALSE)
		return FALSE;

	SetDlgItemTextW (hwndDlg, IDC_VOLUME, szFileName);
	return TRUE;
}

BOOL SelectPartition (HWND hwndDlg)
{
	RawDevicesDlgParam param;
	param.pszFileName = szFileName;
	INT_PTR nResult = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) & param);
	if (nResult == IDOK)
	{
		SetDlgItemTextW (hwndDlg, IDC_VOLUME, szFileName);
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
	WORD hw = HIWORD (wParam);

	switch (uMsg)
	{

	case WM_INITDIALOG:
		{

			MainDlg = hwndDlg;

			// Set critical default options in case UsePreferences is false
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = TRUE;
			bShowDisconnectedNetworkDrives = FALSE;
			bHideWaitingDialog = FALSE;
			bUseSecureDesktop = FALSE;
			bUseLegacyMaxPasswordLength = FALSE;

			ResetWrongPwdRetryCount ();

			ExtractCommandLine (hwndDlg, (wchar_t *) lParam);

			if (Silent && !Quit)
				Silent = FALSE;

			if (UsePreferences)
			{
				// General preferences
				LoadSettings (hwndDlg);


				// Keyfiles
				LoadDefaultKeyFilesParam ();
				RestoreDefaultKeyFilesParam ();
			}

			if (EnableMemoryProtection)
			{
				/* Protect this process memory from being accessed by non-admin users */
				EnableProcessProtection ();
			}

			if (CmdMountOptionsValid)
				mountOptions = CmdMountOptions;

			InitMainDialog (hwndDlg);


			Silent = FALSE;

			AllowMessageInUIPI (taskBarCreatedMsg);

			ResetCurrentDirectory ();
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_HELP:
		OpenPageHelp (hwndDlg, 0);
		return 1;

	case WM_ENDSESSION:
		EndMainDlg (hwndDlg);
		localcleanup ();
		return 0;

	case WM_ERASEBKGND:
		return 0;

	case WM_COMMAND:

		if (lw == IDCANCEL || lw == IDC_EXIT)
		{
			EndMainDlg (hwndDlg);
			return 1;
		}

		if (lw == IDHELP || lw == IDM_HELP)
		{
			OpenPageHelp (hwndDlg, 0);
			return 1;
		}

		if (lw == IDM_ABOUT || lw == IDC_LOGO)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}

		if (lw == IDC_SELECT_FILE || lw == IDM_SELECT_FILE)
		{
			SelectContainer (hwndDlg);
			return 1;
		}

		if (lw == IDC_SELECT_DEVICE || lw == IDM_SELECT_DEVICE)
		{
			// if we are not running as admin, restart the app with admin privileges using LaunchElevatedProcess and exit
			if (!IsAdmin() && IsUacSupported())
			{
				wchar_t modPath[MAX_PATH];
				GetModuleFileName(NULL, modPath, ARRAYSIZE(modPath));
				if (LaunchElevatedProcess(NULL, modPath, L"/select", FALSE))
					exit(0);
				else
					return 1;
			}
			SelectPartition (hwndDlg);
			return 1;
		}

		if (lw == IDC_VOLUME_TOOLS)
		{
			/* Volume Tools popup menu */

			int menuItem;
			HMENU popup = CreatePopupMenu ();
			RECT rect;

			AppendMenuW (popup, MF_STRING, IDM_CHANGE_PASSWORD, GetString ("IDM_CHANGE_PASSWORD"));
			AppendMenuW (popup, MF_STRING, IDM_CHANGE_HEADER_KEY_DERIV_ALGO, GetString ("IDM_CHANGE_HEADER_KEY_DERIV_ALGO"));
			AppendMenu (popup, MF_SEPARATOR, 0, L"");
			AppendMenuW (popup, MF_STRING, IDM_ADD_REMOVE_VOL_KEYFILES, GetString ("IDM_ADD_REMOVE_VOL_KEYFILES"));
			AppendMenuW (popup, MF_STRING, IDM_REMOVE_ALL_KEYFILES_FROM_VOL, GetString ("IDM_REMOVE_ALL_KEYFILES_FROM_VOL"));

			GetWindowRect (GetDlgItem (hwndDlg, IDC_VOLUME_TOOLS), &rect);

			menuItem = TrackPopupMenu (popup,
				TPM_RETURNCMD | TPM_LEFTBUTTON,
				rect.left + 2,
				rect.top + 2,
				0,
				hwndDlg,
				NULL);

			DestroyMenu (popup);

			switch (menuItem)
			{
			case IDM_CHANGE_PASSWORD:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PASSWORD;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_CHANGE_HEADER_KEY_DERIV_ALGO:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PKCS5_PRF;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_ADD_REMOVE_VOL_KEYFILES:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					pwdChangeDlgMode = PCDM_ADD_REMOVE_VOL_KEYFILES;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_REMOVE_ALL_KEYFILES_FROM_VOL:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					pwdChangeDlgMode = PCDM_REMOVE_ALL_KEYFILES_FROM_VOL;
					ChangePassword (hwndDlg);
				}
				break;

			default:
				SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
				break;
			}
			return 1;
		}

		return 0;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			DragQueryFile (hdrop, 0, szFileName, ARRAYSIZE (szFileName));
			DragFinish (hdrop);

			SetDlgItemTextW (hwndDlg, IDC_VOLUME, szFileName);
		}
		return 1;

	case WM_COPYDATA:
		{
			PCOPYDATASTRUCT cd = (PCOPYDATASTRUCT)lParam;
			if (memcmp (&cd->dwData, WM_COPY_SET_VOLUME_NAME, 4) == 0)
			{
				if (cd->cbData > 0)
				{
					((wchar_t *) cd->lpData)[(cd->cbData / sizeof (wchar_t)) - 1] = 0;
					SetDlgItemTextW (hwndDlg, IDC_VOLUME, (wchar_t *)cd->lpData);
				}
			}
		}
		return 1;

	case WM_CLOSE:
		EndMainDlg (hwndDlg);
		return 1;

	default:
		break;
	}

	return 0;
}

void ExtractCommandLine (HWND hwndDlg, wchar_t *lpszCommandLine)
{
	wchar_t **lpszCommandLineArgs = NULL;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */
	wchar_t CmdRawPassword[MAX_PASSWORD + 1]; /* Raw value of password passed from command line */

	/* Defaults */
	mountOptions.PreserveTimestamp = TRUE;

	/* Extract command line arguments */
	NoCmdLineArgs = nNoCommandLineArgs = Win32CommandLine (&lpszCommandLineArgs);

	/* Extract command line arguments */
	NoCmdLineArgs = nNoCommandLineArgs = Win32CommandLine (&lpszCommandLineArgs);

	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			enum
			{
				OptionQuit,
				OptionSelectDevice,
			};

			argument args[]=
			{
				{ OptionQuit,					L"/quit",			L"/q", FALSE },
				{ OptionSelectDevice,			L"/select",			NULL, FALSE },
			};

			argumentspec as;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);

			switch (GetArgumentID (&as, lpszCommandLineArgs[i]))
			{
			case OptionQuit:
				{
					wchar_t szTmp[32] = {0};

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp (szTmp, L"UAC")) // Used to indicate non-install elevation
							break;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionSelectDevice:
				CmdSelectDevice = TRUE;
				break;

				// no option = file name if there is only one argument
			default:
				{
					AbortProcess ("COMMAND_LINE_ERROR");
				}
			}
		}
	}


	burn (CmdRawPassword, sizeof (CmdRawPassword));

	/* Free up the command line arguments */
	while (--nNoCommandLineArgs >= 0)
	{
		free (lpszCommandLineArgs[nNoCommandLineArgs]);
	}

	if (lpszCommandLineArgs)
		free (lpszCommandLineArgs);
}

int WINAPI wWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, wchar_t *lpszCommandLine, int nCmdShow)
{

	int status;
	atexit (localcleanup);
	SetProcessShutdownParameters (0x100, 0);

	VirtualLock (&VolumePassword, sizeof (VolumePassword));
	VirtualLock (&CmdVolumePassword, sizeof (CmdVolumePassword));
	VirtualLock (&mountOptions, sizeof (mountOptions));
	VirtualLock (&defaultMountOptions, sizeof (defaultMountOptions));
	VirtualLock (&szFileName, sizeof(szFileName));	

	DetectX86Features ();

	InitApp (hInstance, lpszCommandLine);

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = L"VeraCrypt Password Changer";

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
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
			(LPARAM) lpszCommandLine);

	FinalizeApp ();
	/* Terminate */
	return 0;
}


