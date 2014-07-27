/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2012 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

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
#include "Favorites.h"
#include "Hotkeys.h"
#include "Keyfiles.h"
#include "Language.h"
#include "MainCom.h"
#include "Mount.h"
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

using namespace VeraCrypt;

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

BootEncryption			*BootEncObj = NULL;
BootEncryptionStatus	BootEncStatus;
BootEncryptionStatus	RecentBootEncStatus;

BOOL bExplore = FALSE;				/* Display explorer window after mount */
BOOL bBeep = FALSE;					/* Donot beep after mount */
char szFileName[TC_MAX_PATH+1];		/* Volume to mount */
char szDriveLetter[3];				/* Drive Letter to mount */
char commandLineDrive = 0;
BOOL bCacheInDriver = FALSE;		/* Cache any passwords we see */
BOOL bCacheInDriverDefault = FALSE;
BOOL bHistoryCmdLine = FALSE;		/* History control is always disabled */
BOOL bUseDifferentTrayIconIfVolMounted = TRUE;
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
BOOL LogOn = FALSE;
BOOL bAutoMountDevices = FALSE;		/* Auto-mount devices */
BOOL bAutoMountFavorites = FALSE;
BOOL bPlaySoundOnSuccessfulHkDismount = TRUE;
BOOL bDisplayBalloonOnSuccessfulHkDismount = TRUE;
BOOL bHibernationPreventionNotified = FALSE;	/* TRUE if the user has been notified that hibernation was prevented (system encryption) during the session. */
BOOL bHiddenSysLeakProtNotifiedDuringSession = FALSE;	/* TRUE if the user has been notified during the session that unencrypted filesystems and non-hidden TrueCrypt volumes are mounted as read-only under hidden OS. */
BOOL CloseSecurityTokenSessionsAfterMount = FALSE;
BOOL DisableSystemCrashDetection = FALSE;
BOOL SystemCrashDetected = FALSE;

BOOL Quit = FALSE;					/* Exit after processing command line */
BOOL ComServerMode = FALSE;
BOOL ServiceMode = FALSE;
BOOL UsePreferences = TRUE;

int HiddenSysLeakProtectionNotificationStatus = TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE;
int MaxVolumeIdleTime = -120;
int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = -1;		/* Item number of selected drive */

int cmdUnmountDrive = 0;			/* Volume drive letter to unmount (-1 = all) */
Password VolumePassword;			/* Password used for mounting volumes */
Password CmdVolumePassword;			/* Password passed from command line */
BOOL CmdVolumePasswordValid = FALSE;
MountOptions CmdMountOptions;
BOOL CmdMountOptionsValid = FALSE;
MountOptions mountOptions;
MountOptions defaultMountOptions;
KeyFile *FirstCmdKeyFile;

HBITMAP hbmLogoBitmapRescaled = NULL;
char OrigKeyboardLayout [8+1] = "00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */ 
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */ 

static KeyFilesDlgParam				hidVolProtKeyFilesParam;

static MOUNT_LIST_STRUCT	LastKnownMountList;
VOLUME_NOTIFICATIONS_LIST	VolumeNotificationsList;	
static DWORD				LastKnownLogicalDrives;

static HANDLE TaskBarIconMutex = NULL;
static BOOL MainWindowHidden = FALSE;
static int pwdChangeDlgMode	= PCDM_CHANGE_PASSWORD;
static int bSysEncPwdChangeDlgMode = FALSE;
static int bPrebootPasswordDlgMode = FALSE;
static int NoCmdLineArgs;
static BOOL CmdLineVolumeSpecified;
static int LastDriveListVolumeColumnWidth;

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
	burn (szFileName, sizeof(szFileName));

	/* Cleanup common code resources */
	cleanup ();

	if (BootEncObj != NULL)
	{
		delete BootEncObj;
		BootEncObj = NULL;
	}

	RandStop (TRUE);
}

void RefreshMainDlg (HWND hwndDlg)
{
	int drive = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))));

	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME), bHistory);
	LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), drive);
	EnableDisableButtons (hwndDlg);
}

void EndMainDlg (HWND hwndDlg)
{
	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME), bHistory);
	
	if (UsePreferences) 
		SaveSettings (hwndDlg);

	if (bWipeCacheOnExit)
	{
		DWORD dwResult;
		DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	if (!bHistory)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), "");
		ClearHistory (GetDlgItem (hwndDlg, IDC_VOLUME));
	}

	if (TaskBarIconMutex != NULL)
	{
		MainWindowHidden = TRUE;
		ShowWindow (hwndDlg, SW_HIDE);
	}
	else
	{
		KillTimer (hwndDlg, TIMER_ID_MAIN);
		TaskBarIconRemove (hwndDlg);
		EndDialog (hwndDlg, 0);
	}
}

static void InitMainDialog (HWND hwndDlg)
{
	MENUITEMINFOW info;
	char *popupTexts[] = {"MENU_VOLUMES", "MENU_SYSTEM_ENCRYPTION", "MENU_FAVORITES", "MENU_TOOLS", "MENU_SETTINGS", "MENU_HELP", "MENU_WEBSITE", 0};
	wchar_t *str;
	int i;

	/* Call the common dialog init code */
	InitDialog (hwndDlg);
	LocalizeDialog (hwndDlg, NULL);

	SetWindowLongPtr (hwndDlg, DWLP_USER, (LONG_PTR) (IsAdmin() ? TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES : 0));

	DragAcceptFiles (hwndDlg, TRUE);

	SendMessage (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, TC_MAX_PATH, 0);
	SetWindowTextW (hwndDlg, (IsAdmin() && !IsBuiltInAdmin() && IsUacSupported() && !IsNonInstallMode()) ? (wstring (lpszTitle) + L" [" + GetString ("ADMINISTRATOR") + L"]").c_str() : lpszTitle);

	// Help file name
	InitHelpFileName();

	// Localize menu strings
	for (i = 40001; str = (wchar_t *)GetDictionaryValueByInt (i); i++)
	{
		info.cbSize = sizeof (info);
		info.fMask = MIIM_TYPE;
		info.fType = MFT_STRING;
		info.dwTypeData = str;
		info.cch = wcslen (str);

		SetMenuItemInfoW (GetMenu (hwndDlg), i, FALSE,  &info); 
	}

	for (i = 0; popupTexts[i] != 0; i++)
	{
		str = GetString (popupTexts[i]);

		info.cbSize = sizeof (info);
		info.fMask = MIIM_TYPE;

		if (strcmp (popupTexts[i], "MENU_WEBSITE") == 0)
			info.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
		else
			info.fType = MFT_STRING;

		if (strcmp (popupTexts[i], "MENU_FAVORITES") == 0)
			FavoriteVolumesMenu = GetSubMenu (GetMenu (hwndDlg), i);

		info.dwTypeData = str;
		info.cch = wcslen (str);

		SetMenuItemInfoW (GetMenu (hwndDlg), i, TRUE,  &info); 
	}

	try
	{
		LoadFavoriteVolumes();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
	}

	// Resize the logo bitmap if the user has a non-default DPI
	if (ScreenDPI != USER_DEFAULT_SCREEN_DPI
		&& hbmLogoBitmapRescaled == NULL)	// If not re-called (e.g. after language pack change)
	{
		hbmLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_LOGO_288DPI),
			GetDlgItem (hwndDlg, IDC_LOGO),
			0, 0, 0, 0, FALSE, TRUE);
	}

	BuildTree (GetDlgItem (hwndDlg, IDC_DRIVELIST));

	if (*szDriveLetter != 0)
	{
		SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST), *szDriveLetter);

		if(nSelectedDriveIndex > SendMessage (GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_GETITEMCOUNT, 0, 0)/2) 
			SendMessage(GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_SCROLL, 0, 10000);
	}

	SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);
	EnableDisableButtons (hwndDlg);
}

void EnableDisableButtons (HWND hwndDlg)
{
	HWND hOKButton = GetDlgItem (hwndDlg, IDOK);
	WORD x;

	x = LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST)));

	EnableMenuItem (GetMenu (hwndDlg), IDM_MOUNT_VOLUME, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_MOUNT_VOLUME_OPTIONS, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_BACKUP_VOL_HEADER, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_RESTORE_VOL_HEADER, MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_CHANGE_PASSWORD, MF_ENABLED);
	EnableWindow (hOKButton, TRUE);

	switch (x)
	{
	case TC_MLIST_ITEM_NONSYS_VOL:
		{
			SetWindowTextW (hOKButton, GetString ("UNMOUNT_BUTTON"));
			EnableWindow (hOKButton, TRUE);
			EnableMenuItem (GetMenu (hwndDlg), IDM_UNMOUNT_VOLUME, MF_ENABLED);

			EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), TRUE);
			EnableMenuItem (GetMenu (hwndDlg), IDM_VOLUME_PROPERTIES, MF_ENABLED);
		}
		break;

	case TC_MLIST_ITEM_SYS_PARTITION:
	case TC_MLIST_ITEM_SYS_DRIVE:
		EnableWindow (hOKButton, FALSE);
		SetWindowTextW (hOKButton, GetString ("MOUNT_BUTTON"));
		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), TRUE);
		EnableMenuItem (GetMenu (hwndDlg), IDM_UNMOUNT_VOLUME, MF_GRAYED);
		break;

	case TC_MLIST_ITEM_FREE:
	default:
		SetWindowTextW (hOKButton, GetString ("MOUNT_BUTTON"));
		EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES), FALSE);
		EnableMenuItem (GetMenu (hwndDlg), IDM_VOLUME_PROPERTIES, MF_GRAYED);
		EnableMenuItem (GetMenu (hwndDlg), IDM_UNMOUNT_VOLUME, MF_GRAYED);
	}

	EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());
	EnableMenuItem (GetMenu (hwndDlg), IDM_WIPE_CACHE, IsPasswordCacheEmpty() ? MF_GRAYED:MF_ENABLED);
	EnableMenuItem (GetMenu (hwndDlg), IDM_CLEAR_HISTORY, IsComboEmpty (GetDlgItem (hwndDlg, IDC_VOLUME)) ? MF_GRAYED:MF_ENABLED);
}

BOOL VolumeSelected (HWND hwndDlg)
{
	return (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_VOLUME)) > 0);
}

/* Returns TRUE if the last partition/drive selected via the Select Device dialog box was the system 
partition/drive and if it is encrypted. 
         WARNING: This function is very fast but not always reliable (for example, if the user manually types
         a device path before Select Device is invoked during the session; after the Select Device dialog 
		 has been invoked at least once, the correct system device paths are cached). Therefore, it must NOT
		 be used before performing any dangerous operations (such as header backup restore or formatting a 
		 supposedly non-system device) -- instead use IsSystemDevicePath(path, hwndDlg, TRUE) for such 
		 purposes. This function can be used only for preliminary GUI checks requiring very fast responses. */
BOOL ActiveSysEncDeviceSelected (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.DriveEncrypted)
		{
			int retCode = 0;

			GetWindowText (GetDlgItem (MainDlg, IDC_VOLUME), szFileName, sizeof (szFileName));

			retCode = IsSystemDevicePath (szFileName, MainDlg, FALSE);

			return (WholeSysDriveEncryption(FALSE) ? (retCode == 2 || retCode == 1) : (retCode == 1));
		}
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return FALSE;
}

void LoadSettings (HWND hwndDlg)
{
	EnableHwEncryption ((ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? FALSE : TRUE);

	WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

	LoadSysEncSettings (hwndDlg);

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
	bUseDifferentTrayIconIfVolMounted =	ConfigReadInt ("UseDifferentTrayIconIfVolumesMounted", TRUE);

	bHistory =						ConfigReadInt ("SaveVolumeHistory", FALSE);

	bCacheInDriverDefault = bCacheInDriver = ConfigReadInt ("CachePasswords", FALSE);
	bWipeCacheOnExit =				ConfigReadInt ("WipePasswordCacheOnExit", FALSE);
	bWipeCacheOnAutoDismount =		ConfigReadInt ("WipeCacheOnAutoDismount", TRUE);

	bStartOnLogon =					ConfigReadInt ("StartOnLogon", FALSE);
	bMountDevicesOnLogon =			ConfigReadInt ("MountDevicesOnLogon", FALSE);
	bMountFavoritesOnLogon =		ConfigReadInt ("MountFavoritesOnLogon", FALSE);

	bEnableBkgTask =				ConfigReadInt ("EnableBackgroundTask", TRUE);
	bCloseBkgTaskWhenNoVolumes =	ConfigReadInt ("CloseBackgroundTaskOnNoVolumes", FALSE);

	bDismountOnLogOff =				ConfigReadInt ("DismountOnLogOff", !(IsServerOS() && IsAdmin()));
	bDismountOnPowerSaving =		ConfigReadInt ("DismountOnPowerSaving", FALSE);
	bDismountOnScreenSaver =		ConfigReadInt ("DismountOnScreenSaver", FALSE);
	bForceAutoDismount =			ConfigReadInt ("ForceAutoDismount", TRUE);
	MaxVolumeIdleTime =				ConfigReadInt ("MaxVolumeIdleTime", -60);

	HiddenSectorDetectionStatus =	ConfigReadInt ("HiddenSectorDetectionStatus", 0);

	defaultKeyFilesParam.EnableKeyFiles = ConfigReadInt ("UseKeyfiles", FALSE);

	bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = ConfigReadInt ("PreserveTimestamps", TRUE);
	defaultMountOptions.Removable =	ConfigReadInt ("MountVolumesRemovable", FALSE);
	defaultMountOptions.ReadOnly =	ConfigReadInt ("MountVolumesReadOnly", FALSE);
	defaultMountOptions.ProtectHiddenVolume = FALSE;
	defaultMountOptions.PartitionInInactiveSysEncScope = FALSE;
	defaultMountOptions.RecoveryMode = FALSE;
	defaultMountOptions.UseBackupHeader =  FALSE;

	mountOptions = defaultMountOptions;

	CloseSecurityTokenSessionsAfterMount = ConfigReadInt ("CloseSecurityTokenSessionsAfterMount", 0);
	DisableSystemCrashDetection = ConfigReadInt ("DisableSystemCrashDetection", FALSE);

	if (IsHiddenOSRunning())
		HiddenSysLeakProtectionNotificationStatus =	ConfigReadInt ("HiddenSystemLeakProtNotifStatus", TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE);

	// Drive letter - command line arg overrides registry
	if (szDriveLetter[0] == 0)
		ConfigReadString ("LastSelectedDrive", "", szDriveLetter, sizeof (szDriveLetter));

	ConfigReadString ("SecurityTokenLibrary", "", SecurityTokenLibraryPath, sizeof (SecurityTokenLibraryPath) - 1);
	if (SecurityTokenLibraryPath[0])
		InitSecurityTokenLibrary();

	// Hotkeys
	bPlaySoundOnSuccessfulHkDismount							= ConfigReadInt ("PlaySoundOnHotkeyMountDismount", TRUE);
	bDisplayBalloonOnSuccessfulHkDismount					= ConfigReadInt ("DisplayMsgBoxOnHotkeyDismount", TRUE);
	Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyModifiers					= ConfigReadInt ("HotkeyModAutoMountDevices", 0);
	Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyCode							= ConfigReadInt ("HotkeyCodeAutoMountDevices", 0);
	Hotkeys [HK_DISMOUNT_ALL].vKeyModifiers							= ConfigReadInt ("HotkeyModDismountAll", 0);
	Hotkeys [HK_DISMOUNT_ALL].vKeyCode								= ConfigReadInt ("HotkeyCodeDismountAll", 0);
	Hotkeys [HK_WIPE_CACHE].vKeyModifiers							= ConfigReadInt ("HotkeyModWipeCache", 0);
	Hotkeys [HK_WIPE_CACHE].vKeyCode								= ConfigReadInt ("HotkeyCodeWipeCache", 0);
	Hotkeys [HK_DISMOUNT_ALL_AND_WIPE].vKeyModifiers				= ConfigReadInt ("HotkeyModDismountAllWipe", 0);
	Hotkeys [HK_DISMOUNT_ALL_AND_WIPE].vKeyCode						= ConfigReadInt ("HotkeyCodeDismountAllWipe", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyModifiers			= ConfigReadInt ("HotkeyModForceDismountAllWipe", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyCode				= ConfigReadInt ("HotkeyCodeForceDismountAllWipe", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyModifiers	= ConfigReadInt ("HotkeyModForceDismountAllWipeExit", 0);
	Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyCode		= ConfigReadInt ("HotkeyCodeForceDismountAllWipeExit", 0);
	Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyModifiers				= ConfigReadInt ("HotkeyModMountFavoriteVolumes", 0);
	Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyCode					= ConfigReadInt ("HotkeyCodeMountFavoriteVolumes", 0);
	Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyModifiers				= ConfigReadInt ("HotkeyModShowHideMainWindow", 0);
	Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyCode						= ConfigReadInt ("HotkeyCodeShowHideMainWindow", 0);
	Hotkeys [HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyModifiers		= ConfigReadInt ("HotkeyModCloseSecurityTokenSessions", 0);
	Hotkeys [HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyCode				= ConfigReadInt ("HotkeyCodeCloseSecurityTokenSessions", 0);

	// History
	if (bHistoryCmdLine != TRUE)
	{
		LoadCombo (GetDlgItem (hwndDlg, IDC_VOLUME));
		if (CmdLineVolumeSpecified)
			SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName);
	}
}

void SaveSettings (HWND hwndDlg)
{
	WaitCursor ();

	char szTmp[32] = {0};
	LPARAM lLetter;

	// Options
	ConfigWriteBegin ();

	ConfigWriteInt ("OpenExplorerWindowAfterMount",		bExplore);
	ConfigWriteInt ("UseDifferentTrayIconIfVolumesMounted",	bUseDifferentTrayIconIfVolMounted);
	ConfigWriteInt ("SaveVolumeHistory",				!IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));

	ConfigWriteInt ("CachePasswords",					bCacheInDriverDefault);
	ConfigWriteInt ("WipePasswordCacheOnExit",			bWipeCacheOnExit);
	ConfigWriteInt ("WipeCacheOnAutoDismount",			bWipeCacheOnAutoDismount);

	ConfigWriteInt ("StartOnLogon",						bStartOnLogon);
	ConfigWriteInt ("MountDevicesOnLogon",				bMountDevicesOnLogon);
	ConfigWriteInt ("MountFavoritesOnLogon",			bMountFavoritesOnLogon);

	ConfigWriteInt ("MountVolumesReadOnly",				defaultMountOptions.ReadOnly);
	ConfigWriteInt ("MountVolumesRemovable",			defaultMountOptions.Removable);
	ConfigWriteInt ("PreserveTimestamps",				defaultMountOptions.PreserveTimestamp);

	ConfigWriteInt ("EnableBackgroundTask",				bEnableBkgTask);
	ConfigWriteInt ("CloseBackgroundTaskOnNoVolumes",	bCloseBkgTaskWhenNoVolumes);

	ConfigWriteInt ("DismountOnLogOff",					bDismountOnLogOff);
	ConfigWriteInt ("DismountOnPowerSaving",			bDismountOnPowerSaving);
	ConfigWriteInt ("DismountOnScreenSaver",			bDismountOnScreenSaver);
	ConfigWriteInt ("ForceAutoDismount",				bForceAutoDismount);
	ConfigWriteInt ("MaxVolumeIdleTime",				MaxVolumeIdleTime);

	ConfigWriteInt ("HiddenSectorDetectionStatus",				HiddenSectorDetectionStatus);

	ConfigWriteInt ("UseKeyfiles",						defaultKeyFilesParam.EnableKeyFiles);

	if (IsHiddenOSRunning())
		ConfigWriteInt ("HiddenSystemLeakProtNotifStatus", HiddenSysLeakProtectionNotificationStatus);

	// Drive Letter
	lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));
	if (LOWORD (lLetter) != 0xffff)
		StringCbPrintfA (szTmp, sizeof(szTmp), "%c:", (char) HIWORD (lLetter));
	ConfigWriteString ("LastSelectedDrive", szTmp);

	ConfigWriteInt ("CloseSecurityTokenSessionsAfterMount",	CloseSecurityTokenSessionsAfterMount);
	ConfigWriteInt ("DisableSystemCrashDetection", DisableSystemCrashDetection);

	// Hotkeys
	ConfigWriteInt ("HotkeyModAutoMountDevices",				Hotkeys[HK_AUTOMOUNT_DEVICES].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeAutoMountDevices",				Hotkeys[HK_AUTOMOUNT_DEVICES].vKeyCode);
	ConfigWriteInt ("HotkeyModDismountAll",						Hotkeys[HK_DISMOUNT_ALL].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeDismountAll",					Hotkeys[HK_DISMOUNT_ALL].vKeyCode);
	ConfigWriteInt ("HotkeyModWipeCache",						Hotkeys[HK_WIPE_CACHE].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeWipeCache",						Hotkeys[HK_WIPE_CACHE].vKeyCode);
	ConfigWriteInt ("HotkeyModDismountAllWipe",					Hotkeys[HK_DISMOUNT_ALL_AND_WIPE].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeDismountAllWipe",				Hotkeys[HK_DISMOUNT_ALL_AND_WIPE].vKeyCode);
	ConfigWriteInt ("HotkeyModForceDismountAllWipe",			Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeForceDismountAllWipe",			Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyCode);
	ConfigWriteInt ("HotkeyModForceDismountAllWipeExit",		Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeForceDismountAllWipeExit",		Hotkeys[HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyCode);
	ConfigWriteInt ("HotkeyModMountFavoriteVolumes",			Hotkeys[HK_MOUNT_FAVORITE_VOLUMES].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeMountFavoriteVolumes",			Hotkeys[HK_MOUNT_FAVORITE_VOLUMES].vKeyCode);
	ConfigWriteInt ("HotkeyModShowHideMainWindow",				Hotkeys[HK_SHOW_HIDE_MAIN_WINDOW].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeShowHideMainWindow",				Hotkeys[HK_SHOW_HIDE_MAIN_WINDOW].vKeyCode);
	ConfigWriteInt ("HotkeyModCloseSecurityTokenSessions",		Hotkeys[HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyModifiers);
	ConfigWriteInt ("HotkeyCodeCloseSecurityTokenSessions",		Hotkeys[HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyCode);
	ConfigWriteInt ("PlaySoundOnHotkeyMountDismount",			bPlaySoundOnSuccessfulHkDismount);
	ConfigWriteInt ("DisplayMsgBoxOnHotkeyDismount",			bDisplayBalloonOnSuccessfulHkDismount);

	// Language
	if (GetPreferredLangId () != NULL)
		ConfigWriteString ("Language", GetPreferredLangId ());

	// PKCS#11 Library Path
	ConfigWriteString ("SecurityTokenLibrary", SecurityTokenLibraryPath[0] ? SecurityTokenLibraryPath : "");

	ConfigWriteEnd ();

	// History
	DumpCombo (GetDlgItem (hwndDlg, IDC_VOLUME), IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY)));

	NormalCursor ();
}

// Returns TRUE if system encryption or decryption had been or is in progress and has not been completed
static BOOL SysEncryptionOrDecryptionRequired (void)
{
	/* If you update this function, revise SysEncryptionOrDecryptionRequired() in Tcformat.c as well. */

	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return (SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		|| SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING
		|| 
		(
			BootEncStatus.DriveMounted 
			&& 
			(
				BootEncStatus.ConfiguredEncryptedAreaStart != BootEncStatus.EncryptedAreaStart
				|| BootEncStatus.ConfiguredEncryptedAreaEnd != BootEncStatus.EncryptedAreaEnd
			)
		)
	);
}

// Returns TRUE if the system partition/drive is completely encrypted
static BOOL SysDriveOrPartitionFullyEncrypted (BOOL bSilent)
{
	/* If you update this function, revise SysDriveOrPartitionFullyEncrypted() in Tcformat.c as well. */

	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);
	}

	return (!BootEncStatus.SetupInProgress
		&& BootEncStatus.ConfiguredEncryptedAreaEnd != 0
		&& BootEncStatus.ConfiguredEncryptedAreaEnd != -1
		&& BootEncStatus.ConfiguredEncryptedAreaStart == BootEncStatus.EncryptedAreaStart
		&& BootEncStatus.ConfiguredEncryptedAreaEnd == BootEncStatus.EncryptedAreaEnd);
}

// Returns TRUE if the system partition/drive is being filtered by the TrueCrypt driver and the key data
// was successfully decrypted (the device is fully ready to be encrypted or decrypted). Note that this
// function does not examine whether the system device is encrypted or not (or to what extent).
static BOOL SysEncDeviceActive (BOOL bSilent)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);

		return FALSE;
	}

	return (BootEncStatus.DriveMounted);
}

// Returns TRUE if the entire system drive (as opposed to the system partition only) is (or is to be) encrypted
BOOL WholeSysDriveEncryption (BOOL bSilent)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		return (BootEncStatus.ConfiguredEncryptedAreaStart == TC_BOOT_LOADER_AREA_SIZE
			&& BootEncStatus.ConfiguredEncryptedAreaEnd >= BootEncStatus.BootDriveLength.QuadPart - 1);
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);

		return FALSE;
	}
}

// Returns the size of the system drive/partition (if encrypted) in bytes
unsigned __int64 GetSysEncDeviceSize (BOOL bSilent)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);
	}

	return (BootEncStatus.ConfiguredEncryptedAreaEnd - BootEncStatus.ConfiguredEncryptedAreaStart + 1);
}

// Returns the current size of the encrypted area of the system drive/partition in bytes
unsigned __int64 GetSysEncDeviceEncryptedPartSize (BOOL bSilent)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);
	}

	return (BootEncStatus.EncryptedAreaEnd - BootEncStatus.EncryptedAreaStart + 1);
}


static void PopulateSysEncContextMenu (HMENU popup, BOOL bToolsOnly)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (!bToolsOnly && !IsHiddenOSRunning())
	{
		if (SysEncryptionOrDecryptionRequired ())
		{
			if (!BootEncStatus.SetupInProgress)
				AppendMenuW (popup, MF_STRING, IDM_SYSENC_RESUME, GetString ("IDM_SYSENC_RESUME"));

			if (SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
				AppendMenuW (popup, MF_STRING, IDM_PERMANENTLY_DECRYPT_SYS, GetString ("PERMANENTLY_DECRYPT"));
			
			AppendMenuW (popup, MF_STRING, IDM_ENCRYPT_SYSTEM_DEVICE, GetString ("ENCRYPT"));
			AppendMenu (popup, MF_SEPARATOR, 0, "");
		}
	}

	AppendMenuW (popup, MF_STRING, IDM_CHANGE_SYS_PASSWORD, GetString ("IDM_CHANGE_SYS_PASSWORD"));
	AppendMenuW (popup, MF_STRING, IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO, GetString ("IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO"));

	AppendMenu (popup, MF_SEPARATOR, 0, "");
	AppendMenuW (popup, MF_STRING, IDM_SYS_ENC_SETTINGS, GetString ("IDM_SYS_ENC_SETTINGS"));

	if (!IsHiddenOSRunning())
	{
		AppendMenu (popup, MF_SEPARATOR, 0, "");
		AppendMenuW (popup, MF_STRING, IDM_CREATE_RESCUE_DISK, GetString ("IDM_CREATE_RESCUE_DISK"));
		AppendMenuW (popup, MF_STRING, IDM_VERIFY_RESCUE_DISK, GetString ("IDM_VERIFY_RESCUE_DISK"));
	}

	if (!bToolsOnly)
	{
		if (SysDriveOrPartitionFullyEncrypted (FALSE) && !IsHiddenOSRunning())
		{
			AppendMenu (popup, MF_SEPARATOR, 0, "");
			AppendMenuW (popup, MF_STRING, IDM_PERMANENTLY_DECRYPT_SYS, GetString ("PERMANENTLY_DECRYPT"));
		}
		AppendMenu (popup, MF_SEPARATOR, 0, "");
		AppendMenuW (popup, MF_STRING, IDM_VOLUME_PROPERTIES, GetString ("IDPM_PROPERTIES"));
	}
}


// WARNING: This function may take a long time to complete. To prevent data corruption, it MUST be called before
// mounting a partition (as a regular volume) that is within key scope of system encryption.
// Returns TRUE if the partition can be mounted as a partition within key scope of inactive system encryption.
// If devicePath is empty, the currently selected partition in the GUI is checked.
BOOL CheckSysEncMountWithoutPBA (const char *devicePath, BOOL quiet)
{
	BOOL tmpbDevice;
	char szDevicePath [TC_MAX_PATH+1];
	char szDiskFile [TC_MAX_PATH+1];

	if (strlen (devicePath) < 2)
	{
		GetWindowText (GetDlgItem (MainDlg, IDC_VOLUME), szDevicePath, sizeof (szDevicePath));
		CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szDevicePath, &tmpbDevice);

		if (!tmpbDevice)
		{
			if (!quiet)
				Warning ("NO_SYSENC_PARTITION_SELECTED");

			return FALSE;
		}

		if (LOWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST))) != TC_MLIST_ITEM_FREE)
		{
			if (!quiet)
				Warning ("SELECT_FREE_DRIVE");

			return FALSE;
		}
	}
	else
		StringCbCopyA (szDevicePath, sizeof(szDevicePath), devicePath);

	char *partionPortion = strrchr (szDevicePath, '\\');

	if (!partionPortion
		|| !_stricmp (partionPortion, "\\Partition0"))
	{
		// Only partitions are supported (not whole drives)
		if (!quiet)
			Warning ("NO_SYSENC_PARTITION_SELECTED");

		return FALSE;
	}

	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.DriveMounted)
		{
			int retCode = 0;
			int driveNo;
			char parentDrivePath [TC_MAX_PATH+1];

			if (sscanf (szDevicePath, "\\Device\\Harddisk%d\\Partition", &driveNo) != 1)
			{
				if (!quiet)
					Error ("INVALID_PATH");

				return FALSE;
			}

			StringCbPrintfA (parentDrivePath,
				sizeof (parentDrivePath),
				"\\Device\\Harddisk%d\\Partition0",
				driveNo);

			WaitCursor ();

			// This is critical (re-mounting a mounted system volume as a normal volume could cause data corruption)
			// so we force the slower but reliable method
			retCode = IsSystemDevicePath (parentDrivePath, MainDlg, TRUE);

			NormalCursor();

			if (retCode != 2)
				return TRUE;
			else
			{
				// The partition is located on active system drive

				if (!quiet)
					Warning ("MOUNT_WITHOUT_PBA_VOL_ON_ACTIVE_SYSENC_DRIVE");

				return FALSE;
			}
		}
		else
			return TRUE;
	}
	catch (Exception &e)
	{
		NormalCursor();
		e.Show (MainDlg);
	}

	return FALSE;
}


// Returns TRUE if the host drive of the specified partition contains a portion of the TrueCrypt Boot Loader
// and if the drive is not within key scope of active system encryption (e.g. the system drive of the running OS).
// If bPrebootPasswordDlgMode is TRUE, this function returns FALSE (because the check would be redundant).
BOOL TCBootLoaderOnInactiveSysEncDrive (void) 
{
	try
	{
		int driveNo;
		char szDevicePath [TC_MAX_PATH+1];
		char parentDrivePath [TC_MAX_PATH+1];

		if (bPrebootPasswordDlgMode)
			return FALSE;

		GetWindowText (GetDlgItem (MainDlg, IDC_VOLUME), szDevicePath, sizeof (szDevicePath));

		if (sscanf (szDevicePath, "\\Device\\Harddisk%d\\Partition", &driveNo) != 1)
			return FALSE;

		StringCbPrintfA (parentDrivePath,
			sizeof (parentDrivePath),
			"\\Device\\Harddisk%d\\Partition0",
			driveNo);

		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.DriveMounted
			&& IsSystemDevicePath (parentDrivePath, MainDlg, FALSE) == 2)
		{
			// The partition is within key scope of active system encryption
			return FALSE;
		}

		return ((BOOL) BootEncObj->IsBootLoaderOnDrive (parentDrivePath));
	}
	catch (...)
	{
		return FALSE;
	}

}


BOOL SelectItem (HWND hTree, char nLetter)
{
	if (nLetter == 0)
	{
		// The caller specified an invalid drive letter (typically because it is unknown). 
		// Find out which drive letter is currently selected in the list and use it.
		nLetter = (char) (HIWORD (GetSelectedLong (hTree)));
	}

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


static void LaunchVolCreationWizard (HWND hwndDlg, const char *arg)
{
	char t[TC_MAX_PATH] = {'"',0};
	char *tmp;

	GetModuleFileName (NULL, t+1, sizeof(t)-1);

	tmp = strrchr (t, '\\');
	if (tmp)
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		ZeroMemory (&si, sizeof (si));

		*tmp = 0;
		StringCbCopyA (t, sizeof(t), "\\VeraCrypt Format.exe\"");

		if (!FileExists(t))
			Error ("VOL_CREATION_WIZARD_NOT_FOUND");	// Display a user-friendly error message and advise what to do

		if (strlen (arg) > 0)
		{
			StringCbCatA (t, sizeof(t), " ");
			StringCbCatA (t, sizeof(t), arg);
		}

		if (!CreateProcess (NULL, (LPSTR) t, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
		{
			handleWin32Error (hwndDlg);
		}
		else
		{
			CloseHandle (pi.hProcess);
			CloseHandle (pi.hThread);
		}
	}
}


// Fills drive list
// drive>0 = update only the corresponding drive subitems
void LoadDriveLetters (HWND hTree, int drive)
{
	// Remember the top-most visible item 
	int lastTopMostVisibleItem = ListView_GetTopIndex (hTree);

	char *szDriveLetters[]=
	{"A:", "B:", "C:", "D:",
	 "E:", "F:", "G:", "H:", "I:", "J:", "K:",
	 "L:", "M:", "N:", "O:", "P:", "Q:", "R:",
	 "S:", "T:", "U:", "V:", "W:", "X:", "Y:",
	 "Z:"};

	DWORD dwResult;
	BOOL bResult;	
	DWORD dwUsedDrives;
	MOUNT_LIST_STRUCT driver;
	VOLUME_PROPERTIES_STRUCT propSysEnc;
	char sysDriveLetter = 0;

	BOOL bSysEnc = FALSE;
	BOOL bWholeSysDriveEncryption = FALSE;

	LVITEM listItem;
	int item = 0;
	char i;

	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		if (bSysEnc = BootEncStatus.DriveMounted)
		{
			BootEncObj->GetVolumeProperties (&propSysEnc);
		}
	}
	catch (...)
	{
		bSysEnc = FALSE;
	}

	ZeroMemory (&driver, sizeof (driver));
	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &driver,
		sizeof (driver), &driver, sizeof (driver), &dwResult,
		NULL);
	memcpy (&LastKnownMountList, &driver, sizeof (driver));

	if (bResult == FALSE)
	{
		KillTimer (MainDlg, TIMER_ID_MAIN);
		handleWin32Error (hTree);
		AbortProcessSilent();
	}

	LastKnownLogicalDrives = dwUsedDrives = GetLogicalDrives ();
	if (dwUsedDrives == 0)
			Warning ("DRIVELETTERS");

	if(drive == 0)
		ListView_DeleteAllItems(hTree);

	if (bSysEnc)
	{
		bWholeSysDriveEncryption = WholeSysDriveEncryption (TRUE);

		sysDriveLetter = GetSystemDriveLetter ();
	}

	/* System drive */

	if (bWholeSysDriveEncryption)
	{
		int curDrive = 0;

		if (drive > 0)
		{
			LVITEM tmp;
			memset(&tmp, 0, sizeof(LVITEM));
			tmp.mask = LVIF_PARAM;
			tmp.iItem = item;
			if (ListView_GetItem (hTree, &tmp))
				curDrive = HIWORD(tmp.lParam);
		}

		{
			char szTmp[1024];
			wchar_t szTmpW[1024];

			memset(&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			listItem.iImage = 2;
			listItem.iItem = item++;  

			listItem.pszText = szTmp;
			szTmp[0] = ' ';
			szTmp[1] = 0;

			listItem.lParam = MAKELONG (TC_MLIST_ITEM_SYS_DRIVE, ENC_SYSDRIVE_PSEUDO_DRIVE_LETTER);	

			if(drive == 0) 
				ListView_InsertItem (hTree, &listItem);
			else
				ListView_SetItem (hTree, &listItem);

			listItem.mask=LVIF_TEXT;   

			// Fully encrypted
			if (SysDriveOrPartitionFullyEncrypted (TRUE))
			{
				StringCbCopyW (szTmpW, sizeof(szTmpW), GetString ("SYSTEM_DRIVE"));
			}
			else
			{
				// Partially encrypted

				if (BootEncStatus.SetupInProgress)
				{
					// Currently encrypting/decrypting

					if (BootEncStatus.SetupMode != SetupDecryption)
					{
						StringCbPrintfW (szTmpW, 
							sizeof szTmpW,
							GetString ("SYSTEM_DRIVE_ENCRYPTING"),
							(double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0);
					}
					else
					{
						StringCbPrintfW (szTmpW, 
							sizeof szTmpW,
							GetString ("SYSTEM_DRIVE_DECRYPTING"),
							100.0 - ((double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0));
					}
				}
				else
				{
					StringCbPrintfW (szTmpW, 
						sizeof szTmpW,
						GetString ("SYSTEM_DRIVE_PARTIALLY_ENCRYPTED"),
						(double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0);
				}
			}
			 
			ListSubItemSetW (hTree, listItem.iItem, 1, szTmpW);

			GetSizeString (GetSysEncDeviceSize(TRUE), szTmpW, sizeof(szTmpW));
			ListSubItemSetW (hTree, listItem.iItem, 2, szTmpW);

			EAGetName (szTmp, propSysEnc.ea);
			listItem.iSubItem = 3;
			ListView_SetItem (hTree, &listItem);

			ListSubItemSetW (hTree, listItem.iItem, 4, GetString (IsHiddenOSRunning() ? "HIDDEN" : "SYSTEM_VOLUME_TYPE_ADJECTIVE"));
		}
	}

	/* Drive letters */

	for (i = 2; i < 26; i++)
	{
		int curDrive = 0;

		BOOL bSysEncPartition = (bSysEnc && !bWholeSysDriveEncryption && sysDriveLetter == *((char *) szDriveLetters[i]));

		if (drive > 0)
		{
			LVITEM tmp;
			memset(&tmp, 0, sizeof(LVITEM));
			tmp.mask = LVIF_PARAM;
			tmp.iItem = item;
			if (ListView_GetItem (hTree, &tmp))
				curDrive = HIWORD(tmp.lParam);
		}

		if (driver.ulMountedDrives & (1 << i)
			|| bSysEncPartition)
		{
			char szTmp[1024];
			wchar_t szTmpW[1024];
			wchar_t *ws;

			memset(&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			listItem.iImage = bSysEncPartition ? 2 : 1;
			listItem.iItem = item++;  

			if (drive > 0 && drive != curDrive)
				continue;

			listItem.lParam = MAKELONG (
				bSysEncPartition ? TC_MLIST_ITEM_SYS_PARTITION : TC_MLIST_ITEM_NONSYS_VOL, 
				i + 'A');

			listItem.pszText = szDriveLetters[i];
			
			if (drive == 0) 
				ListView_InsertItem (hTree, &listItem);
			else
				ListView_SetItem (hTree, &listItem);

			listItem.mask=LVIF_TEXT;   
			listItem.pszText = szTmp;

			if (bSysEncPartition)
			{
				// Fully encrypted
				if (SysDriveOrPartitionFullyEncrypted (TRUE))
				{
					StringCbCopyW (szTmpW, sizeof(szTmpW), GetString (IsHiddenOSRunning() ? "HIDDEN_SYSTEM_PARTITION" : "SYSTEM_PARTITION"));
				}
				else
				{
					// Partially encrypted

					if (BootEncStatus.SetupInProgress)
					{
						// Currently encrypting/decrypting

						if (BootEncStatus.SetupMode != SetupDecryption)
						{
							StringCbPrintfW (szTmpW, 
								sizeof szTmpW,
								GetString ("SYSTEM_PARTITION_ENCRYPTING"),
								(double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0);
						}
						else
						{
							StringCbPrintfW (szTmpW, 
								sizeof szTmpW,
								GetString ("SYSTEM_PARTITION_DECRYPTING"),
								100.0 - ((double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0));
						}
					}
					else
					{
						StringCbPrintfW (szTmpW, 
							sizeof szTmpW,
							GetString ("SYSTEM_PARTITION_PARTIALLY_ENCRYPTED"),
							(double) GetSysEncDeviceEncryptedPartSize (TRUE) / (double) GetSysEncDeviceSize (TRUE) * 100.0);
					}
				}

				ListSubItemSetW (hTree, listItem.iItem, 1, szTmpW);
			}
			else
			{
				ToSBCS (driver.wszVolume[i], sizeof(driver.wszVolume[i]));
				char *path = (char *) driver.wszVolume[i];

				if (memcmp (path, "\\??\\", 4) == 0)
					path += 4;

				listItem.iSubItem = 1;

				wstring label = GetFavoriteVolumeLabel (path);
				if (!label.empty())
					ListSubItemSetW (hTree, listItem.iItem, 1, (wchar_t *) label.c_str());
				else
					ListSubItemSet (hTree, listItem.iItem, 1, (char *) FitPathInGfxWidth (hTree, hUserFont, ListView_GetColumnWidth (hTree, 1) - GetTextGfxWidth (hTree, L"___", hUserFont), path).c_str());
			}

			GetSizeString (bSysEncPartition ? GetSysEncDeviceSize(TRUE) : driver.diskLength[i], szTmpW, sizeof(szTmpW));
			ListSubItemSetW (hTree, listItem.iItem, 2, szTmpW);

			EAGetName (szTmp, bSysEncPartition ? propSysEnc.ea : driver.ea[i]);
			listItem.iSubItem = 3;
			ListView_SetItem (hTree, &listItem);

			if (bSysEncPartition)
			{
				ws = GetString (IsHiddenOSRunning() ? "HIDDEN" : "SYSTEM_VOLUME_TYPE_ADJECTIVE");
				VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;
				ListSubItemSetW (hTree, listItem.iItem, 4, ws);
			}
			else
			{
				switch (driver.volumeType[i])
				{
				case PROP_VOL_TYPE_NORMAL:
					ws = GetString ("NORMAL");
					break;
				case PROP_VOL_TYPE_HIDDEN:
					ws = GetString ("HIDDEN");
					break;
				case PROP_VOL_TYPE_OUTER:
					ws = GetString ("OUTER");		// Normal/outer volume (hidden volume protected)
					break;
				case PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED:
					ws = GetString ("OUTER_VOL_WRITE_PREVENTED");	// Normal/outer volume (hidden volume protected AND write denied)
					break;
				default:
					ws = L"?";
				}
				ListSubItemSetW (hTree, listItem.iItem, 4, ws);

				if (driver.volumeType[i] == PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED)	// Normal/outer volume (hidden volume protected AND write denied)
				{				
					if (!VolumeNotificationsList.bHidVolDamagePrevReported[i])
					{
						wchar_t szTmp[4096];

						VolumeNotificationsList.bHidVolDamagePrevReported[i] = TRUE;
						StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), i+'A');
						SetForegroundWindow (GetParent(hTree));
						MessageBoxW (GetParent(hTree), szTmp, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
					}
				}
				else
				{
					VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;
				}
			}
		}
		else
		{
			VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;

			if (!(dwUsedDrives & 1 << i))
			{
				if(drive > 0 && drive != HIWORD (GetSelectedLong (hTree)))
				{
					item++;
					continue;
				}

				memset(&listItem,0,sizeof(listItem));

				listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
				listItem.iImage = 0;
				listItem.iItem = item++;  
				listItem.pszText = szDriveLetters[i];
				listItem.lParam = MAKELONG (TC_MLIST_ITEM_FREE, i + 'A');

				if(drive == 0) 
					ListView_InsertItem (hTree, &listItem);
				else
					ListView_SetItem (hTree, &listItem);

				listItem.mask=LVIF_TEXT;   
				listItem.pszText = "";
				listItem.iSubItem = 1;
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 2;
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 3;
				ListView_SetItem (hTree, &listItem);
				listItem.iSubItem = 4;
				ListView_SetItem (hTree, &listItem);

			}
		}
	}

	// Restore the original scroll position (the topmost item that was visible when we were called) and the
	// last selected item.
	SetListScrollHPos (hTree, lastTopMostVisibleItem);
	SelectItem (hTree, 0);
}

static void PasswordChangeEnable (HWND hwndDlg, int button, int passwordId, BOOL keyFilesEnabled,
								  int newPasswordId, int newVerifyId, BOOL newKeyFilesEnabled)
{
	char password[MAX_PASSWORD + 1];
	char newPassword[MAX_PASSWORD + 1];
	char newVerify[MAX_PASSWORD + 1];
	BOOL bEnable = TRUE;

	GetWindowText (GetDlgItem (hwndDlg, passwordId), password, sizeof (password));

	if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
		newKeyFilesEnabled = keyFilesEnabled;

	switch (pwdChangeDlgMode)
	{
	case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
	case PCDM_ADD_REMOVE_VOL_KEYFILES:
	case PCDM_CHANGE_PKCS5_PRF:
		memcpy (newPassword, password, sizeof (newPassword));
		memcpy (newVerify, password, sizeof (newVerify));
		break;

	default:
		GetWindowText (GetDlgItem (hwndDlg, newPasswordId), newPassword, sizeof (newPassword));
		GetWindowText (GetDlgItem (hwndDlg, newVerifyId), newVerify, sizeof (newVerify));
	}

	if (!keyFilesEnabled && strlen (password) < MIN_PASSWORD)
		bEnable = FALSE;
	else if (strcmp (newPassword, newVerify) != 0)
		bEnable = FALSE;
	else if (!newKeyFilesEnabled && strlen (newPassword) < MIN_PASSWORD)
		bEnable = FALSE;

	burn (password, sizeof (password));
	burn (newPassword, sizeof (newPassword));
	burn (newVerify, sizeof (newVerify));

	EnableWindow (GetDlgItem (hwndDlg, button), bEnable);
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PasswordChangeDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static KeyFilesDlgParam newKeyFilesParam;

	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LPARAM nIndex;
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			int i;
			WipeAlgorithmId headerWipeMode = TC_WIPE_3_DOD_5220;

			ZeroMemory (&newKeyFilesParam, sizeof (newKeyFilesParam));

			SetWindowTextW (hwndDlg, GetString ("IDD_PASSWORDCHANGE_DLG"));
			LocalizeDialog (hwndDlg, "IDD_PASSWORDCHANGE_DLG");

			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);

			SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, KeyFilesEnable);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), TRUE);

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
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
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
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEW_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_CONFIRM_PASSWORD), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), FALSE);
				break;

			case PCDM_CHANGE_PASSWORD:
			default:
				// NOP
				break;
			};

			if (bSysEncPwdChangeDlgMode)
			{
				ToBootPwdField (hwndDlg, IDC_PASSWORD);
				ToBootPwdField (hwndDlg, IDC_VERIFY);
				ToBootPwdField (hwndDlg, IDC_OLD_PASSWORD);

				if ((DWORD) GetKeyboardLayout (NULL) != 0x00000409 && (DWORD) GetKeyboardLayout (NULL) != 0x04090409)
				{
					DWORD keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
						EndDialog (hwndDlg, IDCANCEL);
						return 0;
					}

					bKeyboardLayoutChanged = TRUE;
				}

				ShowWindow(GetDlgItem(hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW), SW_HIDE);
				ShowWindow(GetDlgItem(hwndDlg, IDC_SHOW_PASSWORD_CHPWD_ORI), SW_HIDE);

				if (SetTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
				{
					Error ("CANNOT_SET_TIMER");
					EndDialog (hwndDlg, IDCANCEL);
					return 0;
				}

				newKeyFilesParam.EnableKeyFiles = FALSE;
				KeyFilesEnable = FALSE;
				SetCheckBox (hwndDlg, IDC_ENABLE_KEYFILES, FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_KEYFILES), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_ENABLE_NEW_KEYFILES), FALSE);
			}

			CheckCapsLock (hwndDlg, FALSE);

			return 0;
		}

	case WM_TIMER:
		switch (wParam)
		{
		case TIMER_ID_KEYB_LAYOUT_GUARD:
			if (bSysEncPwdChangeDlgMode)
			{
				DWORD keybLayout = (DWORD) GetKeyboardLayout (NULL);

				/* Watch the keyboard layout */

				if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
				{
					// Keyboard layout is not standard US

					// Attempt to wipe passwords stored in the input field buffers
					char tmp[MAX_PASSWORD+1];
					memset (tmp, 'X', MAX_PASSWORD);
					tmp [MAX_PASSWORD] = 0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);

					SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), "");
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), "");
					SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), "");

					keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}

					bKeyboardLayoutChanged = TRUE;

					wchar_t szTmp [4096];
					StringCbCopyW (szTmp, sizeof(szTmp), GetString ("KEYB_LAYOUT_CHANGE_PREVENTED"));
					StringCbCatW (szTmp, sizeof(szTmp), L"\n\n");
					StringCbCatW (szTmp, sizeof(szTmp), GetString ("KEYB_LAYOUT_SYS_ENC_EXPLANATION"));
					MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
				}


				/* Watch the right Alt key (which is used to enter various characters on non-US keyboards) */

				if (bKeyboardLayoutChanged && !bKeybLayoutAltKeyWarningShown)
				{
					if (GetAsyncKeyState (VK_RMENU) < 0)
					{
						bKeybLayoutAltKeyWarningShown = TRUE;

						wchar_t szTmp [4096];
						StringCbCopyW (szTmp, sizeof(szTmp), GetString ("ALT_KEY_CHARS_NOT_FOR_SYS_ENCRYPTION"));
						StringCbCatW (szTmp, sizeof(szTmp), L"\n\n");
						StringCbCatW (szTmp, sizeof(szTmp), GetString ("KEYB_LAYOUT_SYS_ENC_EXPLANATION"));
						MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONINFORMATION  | MB_SETFOREGROUND | MB_TOPMOST);
					}
				}
			}
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDCANCEL)
		{
			// Attempt to wipe passwords stored in the input field buffers
			char tmp[MAX_PASSWORD+1];
			memset (tmp, 'X', MAX_PASSWORD);
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

			return 1;
		}

		if (lw == IDC_KEYFILES)
		{
			if (bSysEncPwdChangeDlgMode)
			{
				Warning ("KEYFILES_NOT_SUPPORTED_FOR_SYS_ENCRYPTION");
				return 1;
			}

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
			if (bSysEncPwdChangeDlgMode)
			{
				Warning ("KEYFILES_NOT_SUPPORTED_FOR_SYS_ENCRYPTION");
				return 1;
			}

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
				if (bSysEncPwdChangeDlgMode)
				{
					int new_hash_algo_id = SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, 
						SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

					if (new_hash_algo_id != 0 && new_hash_algo_id != DEFAULT_HASH_ALGORITHM_BOOT)
					{
						int new_hash_algo_id = DEFAULT_HASH_ALGORITHM_BOOT;
						Info ("ALGO_NOT_SUPPORTED_FOR_SYS_ENCRYPTION");
						SelectAlgo (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), &new_hash_algo_id);
					}
				}
				break;
			}
			return 1;

		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_ORI)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_ORI) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), NULL, TRUE);
			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD_CHPWD_NEW)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW) ? 0 : '*',
						0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_CHPWD_NEW) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_VERIFY), NULL, TRUE);
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
			int pkcs5 = SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, 
					SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

			if (!CheckPasswordCharEncoding (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL))
			{
				Error ("UNSUPPORTED_CHARS_IN_PWD");
				return 1;
			}

			if (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF)
			{
				newKeyFilesParam.EnableKeyFiles = KeyFilesEnable;
			}
			else if (!(newKeyFilesParam.EnableKeyFiles && newKeyFilesParam.FirstKeyFile != NULL)
				&& pwdChangeDlgMode == PCDM_CHANGE_PASSWORD)
			{
				if (!CheckPasswordLength (hwndDlg, GetDlgItem (hwndDlg, IDC_PASSWORD)))
					return 1;
			}

			GetWindowText (GetDlgItem (hParent, IDC_VOLUME), szFileName, sizeof (szFileName));

			GetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), (LPSTR) oldPassword.Text, sizeof (oldPassword.Text));
			oldPassword.Length = strlen ((char *) oldPassword.Text);

			switch (pwdChangeDlgMode)
			{
			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			case PCDM_ADD_REMOVE_VOL_KEYFILES:
			case PCDM_CHANGE_PKCS5_PRF:
				memcpy (newPassword.Text, oldPassword.Text, sizeof (newPassword.Text));
				newPassword.Length = strlen ((char *) oldPassword.Text);
				break;

			default:
				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), (LPSTR) newPassword.Text, sizeof (newPassword.Text));
				newPassword.Length = strlen ((char *) newPassword.Text);
			}

			WaitCursor ();

			if (KeyFilesEnable)
				KeyFilesApply (&oldPassword, FirstKeyFile);

			if (newKeyFilesParam.EnableKeyFiles)
			{
				if (!KeyFilesApply (&newPassword, pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF ? FirstKeyFile : newKeyFilesParam.FirstKeyFile))
				{
					nStatus = ERR_DONT_REPORT;
					goto err;
				}
			}

			if (bSysEncPwdChangeDlgMode)
			{
				// System

				pkcs5 = 0;	// PKCS-5 PRF unchanged (currently system encryption supports only RIPEMD-160)

				try
				{
					nStatus = BootEncObj->ChangePassword (&oldPassword, &newPassword, pkcs5, GetWipePassCount(headerWiperMode));
				}
				catch (Exception &e)
				{
					e.Show (MainDlg);
					nStatus = ERR_OS_ERROR;
				}
			}
			else
			{
				// Non-system

				nStatus = ChangePwd (szFileName, &oldPassword, &newPassword, pkcs5, GetWipePassCount(headerWiperMode), hwndDlg);

				if (nStatus == ERR_OS_ERROR
					&& GetLastError () == ERROR_ACCESS_DENIED
					&& IsUacSupported ()
					&& IsVolumeDeviceHosted (szFileName))
				{
					nStatus = UacChangePwd (szFileName, &oldPassword, &newPassword, pkcs5, GetWipePassCount(headerWiperMode), hwndDlg);
				}
			}

err:
			burn (&oldPassword, sizeof (oldPassword));
			burn (&newPassword, sizeof (newPassword));

			NormalCursor ();

			if (nStatus == 0)
			{
				// Attempt to wipe passwords stored in the input field buffers
				char tmp[MAX_PASSWORD+1];
				memset (tmp, 'X', MAX_PASSWORD);
				tmp[MAX_PASSWORD] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);	
				SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);	

				KeyFileRemoveAll (&newKeyFilesParam.FirstKeyFile);
				RestoreDefaultKeyFilesParam ();

				if (bSysEncPwdChangeDlgMode)
				{
					KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
				}

				EndDialog (hwndDlg, IDOK);
			}
			return 1;
		}
		return 0;
	}

	return 0;
}

static char PasswordDlgVolume[MAX_PATH + 1];
static BOOL PasswordDialogDisableMountOptions;
static char *PasswordDialogTitleStringId;

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static Password *szXPwd;	

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			szXPwd = (Password *) lParam;
			LocalizeDialog (hwndDlg, "IDD_PASSWORD_DLG");
			DragAcceptFiles (hwndDlg, TRUE);

			if (PasswordDialogTitleStringId)
			{
				SetWindowTextW (hwndDlg, GetString (PasswordDialogTitleStringId));
			}
			else if (strlen (PasswordDlgVolume) > 0)
			{
				wchar_t s[1024];
				RECT rect;
				GetWindowRect (hwndDlg, &rect);

				wstring label = GetFavoriteVolumeLabel (PasswordDlgVolume);
				if (!label.empty())
				{
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR_LABEL"), label.c_str());
				}
				else
				{
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), "___");
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), FitPathInGfxWidth (hwndDlg, WindowTitleBarFont, rect.right - rect.left - GetTextGfxWidth (hwndDlg, s, WindowTitleBarFont), PasswordDlgVolume).c_str());
				}

				SetWindowTextW (hwndDlg, s);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);

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

			if (!SetForegroundWindow (hwndDlg) && (FavoriteMountOnArrivalInProgress || LogOn))
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
			ToBootPwdField (hwndDlg, IDC_PASSWORD);

			// Attempt to wipe the password stored in the input field buffer
			char tmp[MAX_PASSWORD+1];
			memset (tmp, 'X', MAX_PASSWORD);
			tmp [MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), "");

			StringCbPrintfA (OrigKeyboardLayout, sizeof(OrigKeyboardLayout),"%08X", (DWORD) GetKeyboardLayout (NULL) & 0xFFFF);

			DWORD keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

			if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
			{
				Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			if (SetTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
			{
				Error ("CANNOT_SET_TIMER");
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			SetCheckBox (hwndDlg, IDC_SHOW_PASSWORD, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD), FALSE);

			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_SETPASSWORDCHAR, '*', 0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);

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
					char tmp[MAX_PASSWORD+1];
					memset (tmp, 'X', MAX_PASSWORD);
					tmp [MAX_PASSWORD] = 0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), "");

					keybLayout = (DWORD) LoadKeyboardLayout ("00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION");
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

		if (lw == IDC_SHOW_PASSWORD)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL, TRUE);
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
			char tmp[MAX_PASSWORD+1];
			
			if (lw == IDOK)
			{
				if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
					KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile);

				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), (LPSTR) szXPwd->Text, MAX_PASSWORD + 1);
				szXPwd->Length = strlen ((char *) szXPwd->Text);

				bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));	 
			}

			// Attempt to wipe password stored in the input field buffer
			memset (tmp, 'X', MAX_PASSWORD);
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
					Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT");
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
					DragQueryFile (hdrop, i++, kf->FileName, sizeof (kf->FileName));
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

static void PreferencesDlgEnableButtons (HWND hwndDlg)
{
	BOOL back = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
	BOOL idle = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
	BOOL installed = !IsNonInstallMode();

	EnableWindow (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL), back && installed);
	EnableWindow (GetDlgItem (hwndDlg, IDT_LOGON), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START), back && installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT), back);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT_ON), back);
	EnableWindow (GetDlgItem (hwndDlg, IDT_MINUTES), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME), back && idle);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT), back);
}

BOOL CALLBACK PreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static BOOL PreferencesDialogActive = FALSE;
	static HWND ActivePreferencesDialogWindow;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			if (PreferencesDialogActive)
			{
				ShowWindow (ActivePreferencesDialogWindow, SW_SHOW);
				SetForegroundWindow (ActivePreferencesDialogWindow);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			ActivePreferencesDialogWindow = hwndDlg;
			PreferencesDialogActive = TRUE;

			LocalizeDialog (hwndDlg, "IDD_PREFERENCES_DLG");
		
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER), BM_SETCHECK, 
						bExplore ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_USE_DIFF_TRAY_ICON_IF_VOL_MOUNTED), BM_SETCHECK, 
						bUseDifferentTrayIconIfVolMounted ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PRESERVE_TIMESTAMPS), BM_SETCHECK, 
						defaultMountOptions.PreserveTimestamp ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT), BM_SETCHECK, 
						bWipeCacheOnExit ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT), BM_SETCHECK, 
						bWipeCacheOnAutoDismount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS), BM_SETCHECK, 
						bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_READONLY), BM_SETCHECK, 
						defaultMountOptions.ReadOnly ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_REMOVABLE), BM_SETCHECK, 
						defaultMountOptions.Removable ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START), BM_SETCHECK, 
						bStartOnLogon ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES), BM_SETCHECK, 
						bMountDevicesOnLogon ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE), BM_SETCHECK, 
						bEnableBkgTask ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL), BM_SETCHECK, 
						bCloseBkgTaskWhenNoVolumes || IsNonInstallMode() ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF), BM_SETCHECK, 
						bDismountOnLogOff ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING), BM_SETCHECK, 
						bDismountOnPowerSaving ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER), BM_SETCHECK, 
						bDismountOnScreenSaver ? BST_CHECKED:BST_UNCHECKED, 0);
			
			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT), BM_SETCHECK, 
						bForceAutoDismount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE), BM_SETCHECK, 
						MaxVolumeIdleTime > 0 ? BST_CHECKED:BST_UNCHECKED, 0);

			SetDlgItemInt (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME, abs (MaxVolumeIdleTime), FALSE);

			PreferencesDlgEnableButtons (hwndDlg);
		}
		return 0;

	case WM_COMMAND:

		if (lw == IDC_PREF_BKG_TASK_ENABLE && !IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE)))
		{
			if (AskWarnNoYes ("CONFIRM_BACKGROUND_TASK_DISABLED") == IDNO)
				SetCheckBox (hwndDlg, IDC_PREF_BKG_TASK_ENABLE, TRUE);
		}

		// Forced dismount disabled warning
		if (lw == IDC_PREF_DISMOUNT_INACTIVE
			|| lw == IDC_PREF_DISMOUNT_LOGOFF
			|| lw == IDC_PREF_DISMOUNT_POWERSAVING
			|| lw == IDC_PREF_DISMOUNT_SCREENSAVER
			|| lw == IDC_PREF_FORCE_AUTO_DISMOUNT)
		{
			BOOL i = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
			BOOL l = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF));
			BOOL p = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING));
			BOOL s = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER));
			BOOL q = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT));

			if (!q)
			{
				if (lw == IDC_PREF_FORCE_AUTO_DISMOUNT && (i || l || p || s))
				{
					if (AskWarnNoYes ("CONFIRM_NO_FORCED_AUTODISMOUNT") == IDNO)
						SetCheckBox (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT, TRUE);
				}
				else if ((lw == IDC_PREF_DISMOUNT_INACTIVE && i
					|| lw == IDC_PREF_DISMOUNT_LOGOFF && l
					|| lw == IDC_PREF_DISMOUNT_POWERSAVING && p
					|| lw == IDC_PREF_DISMOUNT_SCREENSAVER && s))
					Warning ("WARN_PREF_AUTO_DISMOUNT");
			}

			if (p && lw == IDC_PREF_DISMOUNT_POWERSAVING)
				Warning ("WARN_PREF_AUTO_DISMOUNT_ON_POWER");
		}

		if (lw == IDCANCEL)
		{
			PreferencesDialogActive = FALSE;
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			WaitCursor ();

			bExplore						= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_OPEN_EXPLORER));	 
			bUseDifferentTrayIconIfVolMounted = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_USE_DIFF_TRAY_ICON_IF_VOL_MOUNTED));	 
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PRESERVE_TIMESTAMPS));	 
			bWipeCacheOnExit				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT));
			bWipeCacheOnAutoDismount		= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT));
			bCacheInDriverDefault = bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS));	 
			defaultMountOptions.ReadOnly	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_READONLY));
			defaultMountOptions.Removable	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_REMOVABLE));
			bEnableBkgTask				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
			bCloseBkgTaskWhenNoVolumes	= IsNonInstallMode() ? bCloseBkgTaskWhenNoVolumes : IsButtonChecked (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL));
			bDismountOnLogOff				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF));
			bDismountOnPowerSaving			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING));
			bDismountOnScreenSaver			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER));
			bForceAutoDismount				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT));
			MaxVolumeIdleTime				= GetDlgItemInt (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE_TIME, NULL, FALSE)
												* (IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE)) ? 1 : -1);
			bStartOnLogon					= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START));	 
			bMountDevicesOnLogon			= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES));	 

			ManageStartupSeq ();

			SaveSettings (hwndDlg);

			NormalCursor ();

			PreferencesDialogActive = FALSE;
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_MORE_SETTINGS)
		{
			HMENU popup = CreatePopupMenu ();
			if (popup)
			{
				AppendMenuW (popup, MF_STRING, IDM_LANGUAGE, GetString ("IDM_LANGUAGE"));
				AppendMenuW (popup, MF_STRING, IDM_HOTKEY_SETTINGS, GetString ("IDM_HOTKEY_SETTINGS"));
				AppendMenuW (popup, MF_STRING, IDM_PERFORMANCE_SETTINGS, GetString ("IDM_PERFORMANCE_SETTINGS"));
				AppendMenuW (popup, MF_STRING, IDM_SYSENC_SETTINGS, GetString ("IDM_SYSENC_SETTINGS"));
				AppendMenuW (popup, MF_STRING, IDM_SYS_FAVORITES_SETTINGS, GetString ("IDM_SYS_FAVORITES_SETTINGS"));
				AppendMenuW (popup, MF_STRING, IDM_DEFAULT_KEYFILES, GetString ("IDM_DEFAULT_KEYFILES"));
				AppendMenuW (popup, MF_STRING, IDM_TOKEN_PREFERENCES, GetString ("IDM_TOKEN_PREFERENCES"));

				RECT rect;
				GetWindowRect (GetDlgItem (hwndDlg, IDC_MORE_SETTINGS), &rect);

				int menuItem = TrackPopupMenu (popup, TPM_RETURNCMD | TPM_LEFTBUTTON, rect.left + 2, rect.top + 2, 0, hwndDlg, NULL);
				DestroyMenu (popup);

				SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
				return 1;
			}
			else
				return 0;
		}

		if (HIWORD (wParam) == BN_CLICKED)
		{
			PreferencesDlgEnableButtons (hwndDlg);
			return 1;
		}

		return 0;
	}

	return 0;
}


BOOL CALLBACK MountOptionsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static MountOptions *mountOptions;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			BOOL protect;
			
			mountOptions = (MountOptions *) lParam;

			LocalizeDialog (hwndDlg, "IDD_MOUNT_OPTIONS");
		
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_READONLY, BM_SETCHECK,
				mountOptions->ReadOnly ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage (hwndDlg, IDC_MOUNT_REMOVABLE, BM_SETCHECK,
				mountOptions->Removable ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage (hwndDlg, IDC_PROTECT_HIDDEN_VOL, BM_SETCHECK,
				mountOptions->ProtectHiddenVolume ? BST_CHECKED : BST_UNCHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_PROTECT_HIDDEN_VOL, BM_SETCHECK,
				mountOptions->ProtectHiddenVolume ? BST_CHECKED : BST_UNCHECKED, 0);

			mountOptions->PartitionInInactiveSysEncScope = bPrebootPasswordDlgMode;

			SendDlgItemMessage (hwndDlg, IDC_MOUNT_SYSENC_PART_WITHOUT_PBA, BM_SETCHECK,
				bPrebootPasswordDlgMode ? BST_CHECKED : BST_UNCHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_USE_EMBEDDED_HEADER_BAK, BM_SETCHECK,
				mountOptions->UseBackupHeader ? BST_CHECKED : BST_UNCHECKED, 0);
			
			EnableWindow (GetDlgItem (hwndDlg, IDC_MOUNT_SYSENC_PART_WITHOUT_PBA), !bPrebootPasswordDlgMode);

			protect = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			EnableWindow (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_VOL_PROTECTION), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_MO), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_PROT_PASSWD), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT), protect);

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);

			SendDlgItemMessage (hwndDlg, IDC_PASSWORD_PROT_HIDVOL, EM_LIMITTEXT, MAX_PASSWORD, 0);

			if (mountOptions->ProtectedHidVolPassword.Length > 0)
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), (LPSTR) mountOptions->ProtectedHidVolPassword.Text);	
			
			ToHyperlink (hwndDlg, IDC_LINK_HIDVOL_PROTECTION_INFO);

		}
		return 0;

	case WM_CONTEXTMENU:
		{
			RECT buttonRect;
			GetWindowRect (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), &buttonRect);

			if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL))
				&& LOWORD (lParam) >= buttonRect.left && LOWORD (lParam) <= buttonRect.right
				&& HIWORD (lParam) >= buttonRect.top && HIWORD (lParam) <= buttonRect.bottom)
			{
				// The "Keyfiles" button has been right-clicked

				POINT popupPos;
				popupPos.x = buttonRect.left + 2;
				popupPos.y = buttonRect.top + 2;

				if (KeyfilesPopupMenu (hwndDlg, popupPos, &hidVolProtKeyFilesParam))
					SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);
			}
		}
		break;

	case WM_COMMAND:

		if (lw == IDC_KEYFILES_HIDVOL_PROT)
		{
			if (IDOK == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
				(DLGPROC) KeyFilesDlgProc, (LPARAM) &hidVolProtKeyFilesParam))
			{
				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);
			}
		}

		if (lw == IDC_KEYFILES_ENABLE_HIDVOL_PROT)
		{
			hidVolProtKeyFilesParam.EnableKeyFiles = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT);

			return 0;
		}

		if (lw == IDC_SHOW_PASSWORD_MO)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL),
						EM_SETPASSWORDCHAR,
						GetCheckBox (hwndDlg, IDC_SHOW_PASSWORD_MO) ? 0 : '*',
						0);
			InvalidateRect (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), NULL, TRUE);
			return 1;
		}

		if (lw == IDC_LINK_HIDVOL_PROTECTION_INFO)
		{
			Applink ("hiddenvolprotection", TRUE, "");
		}

		if (lw == IDCANCEL)
		{
			char tmp[MAX_PASSWORD+1];

			// Cleanup
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);	

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			char tmp[MAX_PASSWORD+1];
			
			mountOptions->ReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			mountOptions->Removable = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_REMOVABLE));
			mountOptions->ProtectHiddenVolume = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));
			mountOptions->PartitionInInactiveSysEncScope = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_SYSENC_PART_WITHOUT_PBA));
			mountOptions->UseBackupHeader = IsButtonChecked (GetDlgItem (hwndDlg, IDC_USE_EMBEDDED_HEADER_BAK));
			
			if (mountOptions->ProtectHiddenVolume)
			{
				GetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL),
					(LPSTR) mountOptions->ProtectedHidVolPassword.Text,
					sizeof (mountOptions->ProtectedHidVolPassword.Text));

				mountOptions->ProtectedHidVolPassword.Length = strlen ((char *) mountOptions->ProtectedHidVolPassword.Text);
			}

			// Cleanup
			memset (tmp, 'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);	

			if ((mountOptions->ProtectHiddenVolume && !bEnableBkgTask)
				&& (AskWarnYesNo ("HIDVOL_PROT_BKG_TASK_WARNING") == IDYES))
			{
				bEnableBkgTask = TRUE;
				TaskBarIconAdd (MainDlg);
			}

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_MOUNT_READONLY || lw == IDC_PROTECT_HIDDEN_VOL)
		{
			BOOL protect;

			if (lw == IDC_MOUNT_READONLY)
			{
				SendDlgItemMessage (hwndDlg, IDC_PROTECT_HIDDEN_VOL, BM_SETCHECK, BST_UNCHECKED, 0);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
				EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_VOL_PROTECTION), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			}

			protect = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_PROT_PASSWD), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_MO), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT), protect);

			return 1;
		}

		return 0;
	}

	return 0;
}


// Returns the block size (in bits) of the cipher with which the volume mounted as the
// specified drive letter is encrypted. In case of a cascade of ciphers with different
// block sizes the function returns the smallest block size.
int GetCipherBlockSizeByDriveNo (int nDosDriveNo)
{
	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;

	int blockSize = 0, cipherID;

	memset (&prop, 0, sizeof(prop));
	prop.driveNo = nDosDriveNo;

	if (DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL))
	{
		for (cipherID = EAGetLastCipher (prop.ea);
			cipherID != 0;
			cipherID = EAGetPreviousCipher (prop.ea, cipherID))
		{
			if (blockSize > 0)
				blockSize = min (blockSize, CipherGetBlockSize (cipherID) * 8);
			else
				blockSize = CipherGetBlockSize (cipherID) * 8;
		}
	}

	return blockSize;
}


// Returns the mode of operation in which the volume mounted as the specified drive letter is encrypted. 
int GetModeOfOperationByDriveNo (int nDosDriveNo)
{
	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;

	memset (&prop, 0, sizeof(prop));
	prop.driveNo = nDosDriveNo;

	if (DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL))
	{
		return prop.mode;
	}

	return 0;
}


BOOL CALLBACK VolumePropertiesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	BOOL bSysEnc = (BOOL) lParam;
	BOOL bSysEncWholeDrive = FALSE;
	WORD lw = LOWORD (wParam);
	int i = 0;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			VOLUME_PROPERTIES_STRUCT prop;
			DWORD dwResult;

			LVCOLUMNW lvCol;
			HWND list = GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES_LIST);
			char szTmp[1024];
			wchar_t sw[1024];
			wchar_t *s;

			if (bSysEnc)
			{
				try
				{
					BootEncStatus = BootEncObj->GetStatus();
					bSysEncWholeDrive = WholeSysDriveEncryption(FALSE);
				}
				catch (Exception &e)
				{
					e.Show (MainDlg);
					return 0;
				}

				if (!BootEncStatus.DriveEncrypted && !BootEncStatus.DriveMounted)
					return 0;
			}
			else
			{
				switch (LOWORD (GetSelectedLong (GetDlgItem (GetParent(hwndDlg), IDC_DRIVELIST))))
				{
				case TC_MLIST_ITEM_FREE:

					// No mounted volume
					EndDialog (hwndDlg, IDOK);
					return 0;

				case TC_MLIST_ITEM_NONSYS_VOL:
					// NOP
					break;

				case TC_MLIST_ITEM_SYS_DRIVE:
					// Encrypted system drive
					bSysEnc = TRUE;
					bSysEncWholeDrive = TRUE;
					break;

				case TC_MLIST_ITEM_SYS_PARTITION:
					// Encrypted system partition
					bSysEnc = TRUE;
					bSysEncWholeDrive = FALSE;
					break;
				}
			}

			LocalizeDialog (hwndDlg, "IDD_VOLUME_PROPERTIES");

			SendMessage (list,LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
				LVS_EX_FULLROWSELECT
				|LVS_EX_HEADERDRAGDROP
				|LVS_EX_LABELTIP
				);

			memset (&lvCol,0,sizeof(lvCol));
			lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;
			lvCol.pszText = GetString ("VALUE");
			lvCol.cx = CompensateXDPI (208);
			lvCol.fmt = LVCFMT_LEFT;
			SendMessage (list,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);

			lvCol.pszText = GetString ("PROPERTY");
			lvCol.cx = CompensateXDPI (192);
			lvCol.fmt = LVCFMT_LEFT;
			SendMessage (list,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);

			memset (&prop, 0, sizeof(prop));
			prop.driveNo = HIWORD (GetSelectedLong (GetDlgItem (GetParent(hwndDlg), IDC_DRIVELIST))) - 'A';

			if (bSysEnc)
			{
				try
				{
					BootEncStatus = BootEncObj->GetStatus();
					if (!BootEncStatus.DriveEncrypted && !BootEncStatus.DriveMounted)
						return 0;

					BootEncObj->GetVolumeProperties (&prop);
				}
				catch (Exception &e)
				{
					e.Show (MainDlg);
					return 0;
				}
			}
			else
			{
				if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL) || dwResult == 0)
					return 0;
			}

			// Location
			ListItemAddW (list, i, GetString ("LOCATION"));
			if (bSysEnc)
				ListSubItemSetW (list, i++, 1, GetString (bSysEncWholeDrive ? "SYSTEM_DRIVE" : IsHiddenOSRunning() ? "HIDDEN_SYSTEM_PARTITION" : "SYSTEM_PARTITION"));
			else
				ListSubItemSetW (list, i++, 1, (wchar_t *) (prop.wszVolume[1] != L'?' ? prop.wszVolume : prop.wszVolume + 4));

			// Size
			ListItemAddW (list, i, GetString ("SIZE"));
			StringCbPrintfW (sw, sizeof(sw), L"%I64u %s", prop.diskLength, GetString ("BYTES"));
			ListSubItemSetW (list, i++, 1, sw);

			// Type
			ListItemAddW (list, i, GetString ("TYPE"));
			if (bSysEnc)
				ListSubItemSetW (list, i++, 1, GetString (IsHiddenOSRunning() ? "TYPE_HIDDEN_SYSTEM_ADJECTIVE" : "SYSTEM_VOLUME_TYPE_ADJECTIVE"));
			else
			{
				ListSubItemSetW (list, i++, 1, 
					prop.hiddenVolume ? GetString ("HIDDEN") : 
					(prop.hiddenVolProtection != HIDVOL_PROT_STATUS_NONE ? GetString ("OUTER") : GetString ("NORMAL")));
			}
			
			if (!bSysEnc)
			{
				// Write protection
				ListItemAddW (list, i, GetString ("READ_ONLY"));

				if (prop.readOnly || prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
					s = GetString ("UISTR_YES");
				else
					s = GetString ("UISTR_NO");

				ListSubItemSetW (list, i++, 1, s);

				// Hidden Volume Protection
				ListItemAddW (list, i, GetString ("HIDDEN_VOL_PROTECTION"));
				if (prop.hiddenVolume)
					s = GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_NONE)
					s = GetString ("UISTR_NO");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTIVE)
					s = GetString ("UISTR_YES");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
					s = GetString ("HID_VOL_DAMAGE_PREVENTED");

				ListSubItemSetW (list, i++, 1, s);
			}

			// Encryption algorithm
			ListItemAddW (list, i, GetString ("ENCRYPTION_ALGORITHM"));

			if (prop.ea == 0 || prop.ea > EAGetCount ())
			{
				ListSubItemSet (list, i, 1, "?");
				return 1;
			}

			EAGetName (szTmp, prop.ea);
			ListSubItemSet (list, i++, 1, szTmp);

			// Key size(s)
			{
				char name[128];
				int size = EAGetKeySize (prop.ea);	
				EAGetName (name, prop.ea);

				// Primary key
				ListItemAddW (list, i, GetString ("KEY_SIZE"));
				StringCbPrintfW (sw, sizeof(sw), L"%d %s", size * 8, GetString ("BITS"));
				ListSubItemSetW (list, i++, 1, sw);

				if (strcmp (EAGetModeName (prop.ea, prop.mode, TRUE), "XTS") == 0)
				{
					// Secondary key (XTS)

					ListItemAddW (list, i, GetString ("SECONDARY_KEY_SIZE_XTS"));
					ListSubItemSetW (list, i++, 1, sw);
				}
			}

			// Block size
			ListItemAddW (list, i, GetString ("BLOCK_SIZE"));
			
			StringCbPrintfW (sw, sizeof(sw), L"%d ", CipherGetBlockSize (EAGetFirstCipher(prop.ea))*8);
			StringCbCatW (sw, sizeof(sw), GetString ("BITS"));
			ListSubItemSetW (list, i++, 1, sw);

			// Mode
			ListItemAddW (list, i, GetString ("MODE_OF_OPERATION"));
			ListSubItemSet (list, i++, 1, EAGetModeName (prop.ea, prop.mode, TRUE));

			// PKCS 5 PRF
			ListItemAddW (list, i, GetString ("PKCS5_PRF"));
			ListSubItemSet (list, i++, 1, get_pkcs5_prf_name (prop.pkcs5));

#if 0
			// PCKS 5 iterations
			ListItemAddW (list, i, GetString ("PKCS5_ITERATIONS"));
			sprintf (szTmp, "%d", prop.pkcs5Iterations);
			ListSubItemSet (list, i++, 1, szTmp);
#endif

#if 0
			{
				// Legacy

				FILETIME ft, curFt;
				LARGE_INTEGER ft64, curFt64;
				SYSTEMTIME st;
				wchar_t date[128];
				memset (date, 0, sizeof (date));

				// Volume date
				ListItemAddW (list, i, GetString ("VOLUME_CREATE_DATE"));
				*(unsigned __int64 *)(&ft) = prop.volumeCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				swprintf (date, L"%s ", sw);
				GetTimeFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				wcscat (date, sw);
				ListSubItemSetW (list, i++, 1, date);

				// Header date
				ListItemAddW (list, i, GetString ("VOLUME_HEADER_DATE"));
				*(unsigned __int64 *)(&ft) = prop.headerCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				swprintf (date, L"%s ", sw);
				GetTimeFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				wcscat (date, sw);

				GetLocalTime (&st);
				SystemTimeToFileTime (&st, &curFt);
				curFt64.HighPart = curFt.dwHighDateTime;
				curFt64.LowPart = curFt.dwLowDateTime;
				ft64.HighPart = ft.dwHighDateTime;
				ft64.LowPart = ft.dwLowDateTime;
				swprintf (date + wcslen (date),  GetString ("VOLUME_HEADER_DAYS")
					, (curFt64.QuadPart - ft64.QuadPart)/(24LL*3600*10000000));
				ListSubItemSetW (list, i++, 1, date);
			}
#endif // 0

			if (!bSysEnc || IsHiddenOSRunning())
			{
				// Volume format version
				ListItemAddW (list, i, GetString ("VOLUME_FORMAT_VERSION"));
				StringCbPrintfA (szTmp, sizeof(szTmp), "%d", prop.volFormatVersion);
				ListSubItemSet (list, i++, 1, szTmp);

				// Backup header
				ListItemAddW (list, i, GetString ("BACKUP_HEADER"));
				ListSubItemSetW (list, i++, 1, GetString (prop.volFormatVersion > 1 ? "UISTR_YES" : "UISTR_NO"));
			}

			// Total data read
			ListItemAddW (list, i, GetString ("TOTAL_DATA_READ"));
			GetSizeString (prop.totalBytesRead, sw, sizeof(sw));
			ListSubItemSetW (list, i++, 1, sw);

			// Total data written
			ListItemAddW (list, i, GetString ("TOTAL_DATA_WRITTEN"));
			GetSizeString (prop.totalBytesWritten, sw, sizeof(sw));
			ListSubItemSetW (list, i++, 1, sw);

			if (bSysEnc)
			{
				// TrueCrypt Boot Loader version
				ListItemAddW (list, i, GetString ("VC_BOOT_LOADER_VERSION"));
				ListSubItemSet (list, i++, 1, (char *) GetUserFriendlyVersionString (BootEncStatus.BootLoaderVersion).c_str());

				// Encrypted portion
				ListItemAddW (list, i, GetString ("ENCRYPTED_PORTION"));
				if (GetSysEncDeviceEncryptedPartSize (FALSE) == GetSysEncDeviceSize (FALSE))
					ListSubItemSetW (list, i++, 1, GetString ("ENCRYPTED_PORTION_FULLY_ENCRYPTED"));
				else if (GetSysEncDeviceEncryptedPartSize (FALSE) <= 1)
					ListSubItemSetW (list, i++, 1, GetString ("ENCRYPTED_PORTION_NOT_ENCRYPTED"));
				else
				{

					StringCbPrintfW (sw, 
						sizeof sw,
						GetString ("PROCESSED_PORTION_X_PERCENT"),
						(double) GetSysEncDeviceEncryptedPartSize (FALSE) / (double) GetSysEncDeviceSize (FALSE) * 100.0);

					ListSubItemSetW (list, i++, 1, sw);
				}
			}

			return 0;
		}

	case WM_COMMAND:
		if (lw == IDOK)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}
		return 0;

	case WM_CLOSE:
		EndDialog (hwndDlg, lw);
		return 1;
	}

	return 0;
}


BOOL CALLBACK TravelerDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static BOOL bAutoRunWarningDisplayed = FALSE;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			char i;
			int index;
			char drive[] = { 0, ':', 0 };

			LocalizeDialog (hwndDlg, "IDD_TRAVELER_DLG");

			SendDlgItemMessage (hwndDlg, IDC_COPY_WIZARD, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_AUTORUN_DISABLE, BM_SETCHECK, 
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_RESETCONTENT, 0, 0);

			index = SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) GetString ("FIRST_AVAILABLE"));
			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) 0);

			for (i = 'D'; i <= 'Z'; i++)
			{
				drive[0] = i;
				index = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) drive);
				SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) i);
			}
		
			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETCURSEL, 0, 0);

			return 0;
		}


	case WM_COMMAND:

		if (HIWORD (wParam) == BN_CLICKED
			&& (lw == IDC_AUTORUN_DISABLE || lw == IDC_AUTORUN_MOUNT || lw == IDC_AUTORUN_START ))
		{
			BOOL enabled = IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_MOUNT));
			
			EnableWindow (GetDlgItem (hwndDlg, IDC_BROWSE_FILES), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_NAME), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_DRIVELIST), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TRAVELER_MOUNT), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_LETTER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_SETTINGS), enabled);

			if (!bAutoRunWarningDisplayed
				&& (lw == IDC_AUTORUN_MOUNT || lw == IDC_AUTORUN_START))
			{
				bAutoRunWarningDisplayed = TRUE;
				Warning ("AUTORUN_MAY_NOT_ALWAYS_WORK");
			}

			return 1;
		}

		if (lw == IDC_BROWSE_FILES)
		{
			char dstDir[MAX_PATH];
			char volName[MAX_PATH] = { 0 };

			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstDir, sizeof dstDir);

			if (BrowseFilesInDir (hwndDlg, "OPEN_TITLE", dstDir, volName, bHistory, FALSE, NULL))
				SetDlgItemText (hwndDlg, IDC_VOLUME_NAME, strchr (volName, '\\') + 1);

			return 1;
		}

		if (lw == IDC_BROWSE_DIRS)
		{
			char dstPath[MAX_PATH * 2];
			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstPath, sizeof dstPath);

			if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", dstPath))
				SetDlgItemText (hwndDlg, IDC_DIRECTORY, dstPath);

			return 1;
		}

		if (lw == IDCANCEL || lw == IDCLOSE)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_CREATE)
		{

			BOOL copyWizard, bExplore, bCacheInDriver, bAutoRun, bAutoMount, bMountReadOnly;
			char dstDir[MAX_PATH];
			char srcPath[MAX_PATH * 2];
			char dstPath[MAX_PATH * 2];
			char appDir[MAX_PATH];
			char sysDir[MAX_PATH];
			char volName[MAX_PATH];
			int drive;
			char* ptr;

			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstDir, sizeof dstDir);
			volName[0] = 0;
			GetDlgItemText (hwndDlg, IDC_VOLUME_NAME, volName + 1, sizeof volName);
			
			drive = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETCURSEL, 0, 0);
			drive = SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETITEMDATA, drive, 0);

			copyWizard = IsButtonChecked (GetDlgItem (hwndDlg, IDC_COPY_WIZARD));
			bExplore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER));
			bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS));
			bMountReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			bAutoRun = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_DISABLE));
			bAutoMount = IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_MOUNT));

			if (dstDir[0] == 0)
			{
				SetFocus (GetDlgItem (hwndDlg, IDC_DIRECTORY));
				MessageBoxW (hwndDlg, GetString ("NO_PATH_SELECTED"), lpszTitle, MB_ICONEXCLAMATION);
				return 1;
			}

			
			if (bAutoMount && volName[1] == 0)
			{
				SetFocus (GetDlgItem (hwndDlg, IDC_VOLUME_NAME));
				MessageBoxW (hwndDlg, GetString ("NO_FILE_SELECTED"), lpszTitle, MB_ICONEXCLAMATION);
				return 1;
			}

			if (volName[1] != 0)
			{
				volName[0] = '"';
				StringCbCatA (volName, sizeof(volName), "\"");
			}

			GetModuleFileName (NULL, appDir, sizeof (appDir));
			if (ptr = strrchr (appDir, '\\'))
				ptr[0] = 0;

			WaitCursor ();
			GetSystemDirectory (sysDir, sizeof (sysDir));

			StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt", dstDir);
			CreateDirectory (dstPath, NULL);

			// Main app
			StringCbPrintfA (srcPath, sizeof(srcPath), "%s\\VeraCrypt.exe", appDir);
			StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt\\VeraCrypt.exe", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			// Wizard
			if (copyWizard)
			{
				StringCbPrintfA (srcPath, sizeof(srcPath), "%s\\VeraCrypt Format.exe", appDir);
				StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt\\VeraCrypt Format.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg);
					goto stop;
				}
			}

			// Driver
			StringCbPrintfA (srcPath, sizeof(srcPath), "%s\\veracrypt.sys", appDir);
			StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt\\veracrypt.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			// Driver x64
			StringCbPrintfA (srcPath, sizeof(srcPath), "%s\\veracrypt-x64.sys", appDir);
			StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt\\veracrypt-x64.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg);
				goto stop;
			}

			if (GetPreferredLangId () && strcmp (GetPreferredLangId (), "en") != 0)
			{
				// Language pack
				StringCbPrintfA (srcPath, sizeof(srcPath), "%s\\Language.%s.xml", appDir, GetPreferredLangId ());
				StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\VeraCrypt\\Language.%s.xml", dstDir, GetPreferredLangId ());
				TCCopyFile (srcPath, dstPath);
			}

			// AutoRun
			StringCbPrintfA (dstPath, sizeof(dstPath), "%s\\autorun.inf", dstDir);
			DeleteFile (dstPath);
			if (bAutoRun)
			{
				FILE *af;
				char autoMount[100];
				char driveLetter[] = { ' ', '/', 'l', (char) drive, 0 };

				af = fopen (dstPath, "w,ccs=UNICODE");

				if (af == NULL)
				{
					MessageBoxW (hwndDlg, GetString ("CANT_CREATE_AUTORUN"), lpszTitle, MB_ICONERROR);
					goto stop;
				}

				StringCbPrintfA (autoMount, sizeof(autoMount), "VeraCrypt\\VeraCrypt.exe /q background%s%s%s%s /m rm /v %s",
					drive > 0 ? driveLetter : "",
					bExplore ? " /e" : "",
					bCacheInDriver ? " /c y" : "",
					bMountReadOnly ? " /m ro" : "",
					volName);

				fwprintf (af, L"[autorun]\nlabel=%s\nicon=VeraCrypt\\VeraCrypt.exe\n", GetString ("TC_TRAVELER_DISK"));
				fwprintf (af, L"action=%s\n", bAutoMount ? GetString ("MOUNT_TC_VOLUME") : GetString ("IDC_PREF_LOGON_START"));
				fwprintf (af, L"open=%hs\n", bAutoMount ? autoMount : "VeraCrypt\\VeraCrypt.exe");
				fwprintf (af, L"shell\\start=%s\nshell\\start\\command=VeraCrypt\\VeraCrypt.exe\n", GetString ("IDC_PREF_LOGON_START"));
				fwprintf (af, L"shell\\dismount=%s\nshell\\dismount\\command=VeraCrypt\\VeraCrypt.exe /q /d\n", GetString ("DISMOUNT_ALL_TC_VOLUMES"));

				CheckFileStreamWriteErrors (af, dstPath);
				fclose (af);
			}
			MessageBoxW (hwndDlg, GetString ("TRAVELER_DISK_CREATED"), lpszTitle, MB_ICONINFORMATION);

stop:
			NormalCursor ();
			return 1;
		}
		return 0;
	}

	return 0;
}

void BuildTree (HWND hTree)
{
	HIMAGELIST hList;
	HBITMAP hBitmap, hBitmapMask;
	LVCOLUMNW lvCol;

	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);
	ListView_DeleteColumn (hTree,0);

	SendMessage(hTree,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
		LVS_EX_FULLROWSELECT
		|LVS_EX_HEADERDRAGDROP 
		); 

	memset(&lvCol,0,sizeof(lvCol)); 

	lvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
	lvCol.pszText = GetString ("DRIVE");                           
	lvCol.cx = CompensateXDPI (38);
	lvCol.fmt = LVCFMT_COL_HAS_IMAGES|LVCFMT_LEFT ;
	SendMessage (hTree,LVM_INSERTCOLUMNW,0,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("VOLUME");  
	lvCol.cx = CompensateXDPI (253);           
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,1,(LPARAM)&lvCol);
	LastDriveListVolumeColumnWidth = ListView_GetColumnWidth (hTree, 1);

	lvCol.pszText = GetString ("SIZE");  
	lvCol.cx = CompensateXDPI (55);
	lvCol.fmt = LVCFMT_RIGHT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,2,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("ENCRYPTION_ALGORITHM_LV");  
	lvCol.cx = CompensateXDPI (121);
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,3,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("TYPE");  
	lvCol.cx = CompensateXDPI (52);
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,4,(LPARAM)&lvCol);

	// Regular drive icon

	hBitmap = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON));
	if (hBitmap == NULL)
		return;
	hBitmapMask = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON_MASK));

	hList = ImageList_Create (16, 12, ILC_COLOR8|ILC_MASK, 2, 2);
	if (ImageList_Add (hList, hBitmap, hBitmapMask) == -1)
	{
		DeleteObject (hBitmap);
		DeleteObject (hBitmapMask);
		return;
	}
	else
	{
		DeleteObject (hBitmap);
		DeleteObject (hBitmapMask);
	}

	// System drive icon

	hBitmap = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_SYS_DRIVEICON));
	if (hBitmap == NULL)
		return;
	hBitmapMask = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_SYS_DRIVEICON_MASK));

	if (ImageList_Add (hList, hBitmap, hBitmapMask) == -1)
	{
		DeleteObject (hBitmap);
		DeleteObject (hBitmapMask);
		return;
	}
	else
	{
		DeleteObject (hBitmap);
		DeleteObject (hBitmapMask);
	}

	ListView_SetImageList (hTree, hList, LVSIL_NORMAL); 
	ListView_SetImageList (hTree, hList, LVSIL_SMALL);

	LoadDriveLetters (hTree, 0);
}

LPARAM GetSelectedLong (HWND hTree)
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

LPARAM GetItemLong (HWND hTree, int itemNo)
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

static int AskVolumePassword (HWND hwndDlg, Password *password, char *titleStringId, BOOL enableMountOptions)
{
	int result;

	PasswordDialogTitleStringId = titleStringId;
	PasswordDialogDisableMountOptions = !enableMountOptions;

	result = DialogBoxParamW (hInst, 
		MAKEINTRESOURCEW (IDD_PASSWORD_DLG), hwndDlg,
		(DLGPROC) PasswordDlgProc, (LPARAM) password);

	if (result != IDOK)
	{
		password->Length = 0;
		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	}

	return result == IDOK;
}

// GUI actions

static BOOL Mount (HWND hwndDlg, int nDosDriveNo, char *szFileName)
{
	BOOL status = FALSE;
	char fileName[MAX_PATH];
	int mounted = 0;

	bPrebootPasswordDlgMode = mountOptions.PartitionInInactiveSysEncScope;

	if (nDosDriveNo == 0)
		nDosDriveNo = HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A';

	if (!MultipleMountOperationInProgress)
		VolumePassword.Length = 0;

	if (szFileName == NULL)
	{
		GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), fileName, sizeof (fileName));
		szFileName = fileName;
	}

	if (strlen(szFileName) == 0)
	{
		status = FALSE;
		goto ret;
	}

	if (IsMountedVolume (szFileName))
	{
		Warning ("VOL_ALREADY_MOUNTED");
		status = FALSE;
		goto ret;
	}

	if (!VolumePathExists (szFileName))
	{
		if (!MultipleMountOperationInProgress)
			handleWin32Error (hwndDlg);

		status = FALSE;
		goto ret;
	}

	ResetWrongPwdRetryCount ();

	// First try cached passwords and if they fail ask user for a new one
	WaitCursor ();

	mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);
	
	// If keyfiles are enabled, test empty password first
	if (!mounted && KeyFilesEnable && FirstKeyFile)
	{
		Password emptyPassword;
		emptyPassword.Length = 0;

		KeyFilesApply (&emptyPassword, FirstKeyFile);
		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &emptyPassword, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);
		
		burn (&emptyPassword, sizeof (emptyPassword));
	}

	// Test password and/or keyfiles used for the previous volume
	if (!mounted && MultipleMountOperationInProgress && VolumePassword.Length != 0)
		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);

	NormalCursor ();

	if (mounted)
	{

		// Check for problematic file extensions (exe, dll, sys)
		if (CheckFileExtension(szFileName))
			Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING");
	}

	while (mounted == 0)
	{
		if (CmdVolumePassword.Length > 0)
		{
			VolumePassword = CmdVolumePassword;
		}
		else if (!Silent)
		{
			StringCbCopyA (PasswordDlgVolume, sizeof(PasswordDlgVolume), szFileName);

			if (!AskVolumePassword (hwndDlg, &VolumePassword, NULL, TRUE))
				goto ret;
		}
		
		WaitCursor ();

		if (KeyFilesEnable)
			KeyFilesApply (&VolumePassword, FirstKeyFile);

		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, Silent, !Silent);
		NormalCursor ();

		// Check for legacy non-ASCII passwords
		if (mounted > 0 && !KeyFilesEnable && !CheckPasswordCharEncoding (NULL, &VolumePassword))
			Warning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");

		// Check for problematic file extensions (exe, dll, sys)
		if (mounted > 0 && CheckFileExtension (szFileName))
			Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING");

		if (!MultipleMountOperationInProgress)
			burn (&VolumePassword, sizeof (VolumePassword));

		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

		if (CmdVolumePassword.Length > 0 || Silent)
			break;
	}

	if (mounted > 0)
	{
		status = TRUE;

		if (bBeep)
			MessageBeep (0xFFFFFFFF);

		RefreshMainDlg(hwndDlg);

		if (bExplore)
		{	
			WaitCursor();
			OpenVolumeExplorerWindow (nDosDriveNo);
			NormalCursor();
		}

		if (mountOptions.ProtectHiddenVolume)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT");
	}

ret:
	if (!MultipleMountOperationInProgress)
		burn (&VolumePassword, sizeof (VolumePassword));

	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

	RestoreDefaultKeyFilesParam ();

	if (UsePreferences)
		bCacheInDriver = bCacheInDriverDefault;

	if (status && CloseSecurityTokenSessionsAfterMount && !MultipleMountOperationInProgress)
		SecurityToken::CloseAllSessions();

	return status;
}


static BOOL Dismount (HWND hwndDlg, int nDosDriveNo)
{
	BOOL status = FALSE;
	WaitCursor ();

	if (nDosDriveNo == 0)
		nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A');

	if (bCloseDismountedWindows)
	{
		CloseVolumeExplorerWindows (hwndDlg, nDosDriveNo);
	}

	if (UnmountVolume (hwndDlg, nDosDriveNo, bForceUnmount))
	{
		status = TRUE;

		if (bBeep)
			MessageBeep (0xFFFFFFFF);
		RefreshMainDlg (hwndDlg);

		if (nCurrentOS == WIN_2000 && RemoteSession && !IsAdmin ())
			LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);
	}

	NormalCursor ();
	return status;
}

static BOOL DismountAll (HWND hwndDlg, BOOL forceUnmount, BOOL interact, int dismountMaxRetries, int dismountAutoRetryDelay)
{
	BOOL status = TRUE;
	MOUNT_LIST_STRUCT mountList;
	DWORD dwResult;
	UNMOUNT_STRUCT unmount;
	BOOL bResult;
	unsigned __int32 prevMountedDrives = 0;
	int i;

retry:
	WaitCursor();

	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL);

	if (mountList.ulMountedDrives == 0)
	{
		NormalCursor();
		return TRUE;
	}

	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, 0, mountList.ulMountedDrives);

	prevMountedDrives = mountList.ulMountedDrives;

	for (i = 0; i < 26; i++)
	{
		if (mountList.ulMountedDrives & (1 << i))
		{
			if (bCloseDismountedWindows)
				CloseVolumeExplorerWindows (hwndDlg, i);
		}
	}

	unmount.nDosDriveNo = 0;
	unmount.ignoreOpenFiles = forceUnmount;

	do
	{
		bResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_ALL_VOLUMES, &unmount,
			sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

		if (bResult == FALSE)
		{
			NormalCursor();
			handleWin32Error (hwndDlg);
			return FALSE;
		}

		if (unmount.nReturnCode == ERR_SUCCESS
			&& unmount.HiddenVolumeProtectionTriggered
			&& !VolumeNotificationsList.bHidVolDamagePrevReported [unmount.nDosDriveNo])
		{
			wchar_t msg[4096];

			VolumeNotificationsList.bHidVolDamagePrevReported [unmount.nDosDriveNo] = TRUE;
			StringCbPrintfW (msg, sizeof(msg), GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), unmount.nDosDriveNo + 'A');
			SetForegroundWindow (hwndDlg);
			MessageBoxW (hwndDlg, msg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);

			unmount.HiddenVolumeProtectionTriggered = FALSE;
			continue;
		}

		if (unmount.nReturnCode == ERR_FILES_OPEN)
			Sleep (dismountAutoRetryDelay);
		else
			break;

	} while (--dismountMaxRetries > 0);

	memset (&mountList, 0, sizeof (mountList));
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL);
	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, prevMountedDrives & ~mountList.ulMountedDrives);

	RefreshMainDlg (hwndDlg);

	if (nCurrentOS == WIN_2000 && RemoteSession && !IsAdmin ())
		LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

	NormalCursor();

	if (unmount.nReturnCode != 0)
	{
		if (forceUnmount)
			status = FALSE;

		if (unmount.nReturnCode == ERR_FILES_OPEN)
		{
			if (interact && IDYES == AskWarnYesNoTopmost ("UNMOUNTALL_LOCK_FAILED"))
			{
				forceUnmount = TRUE;
				goto retry;
			}

			if (IsOSAtLeast (WIN_7))
			{
				// Undo SHCNE_DRIVEREMOVED
				DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, NULL, 0, &mountList, sizeof (mountList), &dwResult, NULL);

				for (i = 0; i < 26; i++)
				{
					if (mountList.ulMountedDrives & (1 << i))
					{
						char root[] = { (char) i + 'A', ':', '\\', 0 };
						SHChangeNotify (SHCNE_DRIVEADD, SHCNF_PATH, root, NULL);
					}
				}
			}

			return FALSE;
		}
		
		if (interact)
			MessageBoxW (hwndDlg, GetString ("UNMOUNT_FAILED"), lpszTitle, MB_ICONERROR);
	}
	else
	{
		if (bBeep)
			MessageBeep (0xFFFFFFFF);
	}

	return status;
}

static BOOL MountAllDevices (HWND hwndDlg, BOOL bPasswordPrompt)
{
	HWND driveList = GetDlgItem (hwndDlg, IDC_DRIVELIST);
	int selDrive = ListView_GetSelectionMark (driveList);
	BOOL shared = FALSE, status = FALSE, bHeaderBakRetry = FALSE;
	int mountedVolCount = 0;
	vector <HostDevice> devices;

	VolumePassword.Length = 0;
	mountOptions = defaultMountOptions;
	bPrebootPasswordDlgMode = FALSE;

	if (selDrive == -1) 
		selDrive = 0;

	ResetWrongPwdRetryCount ();

	MultipleMountOperationInProgress = TRUE;

	do
	{
		if (!bHeaderBakRetry)
		{
			if (!CmdVolumePasswordValid && bPasswordPrompt)
			{
				PasswordDlgVolume[0] = '\0';
				if (!AskVolumePassword (hwndDlg, &VolumePassword, NULL, TRUE))
					goto ret;
			}
			else if (CmdVolumePasswordValid)
			{
				bPasswordPrompt = FALSE;
				VolumePassword = CmdVolumePassword;
			}

			WaitCursor();

			if (FirstCmdKeyFile)
				KeyFilesApply (&VolumePassword, FirstCmdKeyFile);
			else if (KeyFilesEnable)
				KeyFilesApply (&VolumePassword, FirstKeyFile);

		}

		if (devices.empty())
			devices = GetAvailableHostDevices (true, false, true, true);
		foreach (const HostDevice &drive, devices)
		{
			vector <HostDevice> partitions = drive.Partitions;
			partitions.insert (partitions.begin(), drive);

			foreach (const HostDevice &device, partitions)
			{
				char szFileName[TC_MAX_PATH];
				strcpy_s (szFileName, sizeof (szFileName), device.Path.c_str());
				BOOL mounted = IsMountedVolume (szFileName);

				// Skip other partitions of the disk if partition0 (whole disk) is mounted
				if (!device.IsPartition && mounted)
					break;

				if (device.Floppy)
					break;

				if (device.HasUnencryptedFilesystem && !mountOptions.UseBackupHeader && !bHeaderBakRetry)
					continue;

				if (!mounted)
				{	
					int nDosDriveNo;

					while (LOWORD (GetItemLong (driveList, selDrive)) != 0xffff)
					{
						if(LOWORD (GetItemLong (driveList, selDrive)) != TC_MLIST_ITEM_FREE)
						{
							selDrive++;
							continue;
						}
						nDosDriveNo = HIWORD(GetItemLong (driveList, selDrive)) - 'A';
						break;
					}

					if (LOWORD (GetItemLong (driveList, selDrive)) == 0xffff)
						goto ret;

					// First try user password then cached passwords
					if ((mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, TRUE, FALSE)) > 0
						|| (mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, TRUE, FALSE)) > 0)
					{
						// A volume has been successfully mounted

						ResetWrongPwdRetryCount ();

						if (mounted == 2)
							shared = TRUE;

						LoadDriveLetters (driveList, (HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), selDrive))));
						selDrive++;

						if (bExplore)
						{	
							WaitCursor();
							OpenVolumeExplorerWindow (nDosDriveNo);
							NormalCursor();
						}

						if (bBeep)
							MessageBeep (0xFFFFFFFF);

						status = TRUE;

						mountedVolCount++;

						// Skip other partitions of the disk if partition0 (whole disk) has been mounted
						if (!device.IsPartition)
							break;
					}
				}
			}
		}

		if (mountedVolCount < 1)
		{
			// Failed to mount any volume

			IncreaseWrongPwdRetryCount (1);

			if (WrongPwdRetryCountOverLimit ()
				&& !mountOptions.UseBackupHeader
				&& !bHeaderBakRetry)
			{
				// Retry using embedded header backup (if any)
				mountOptions.UseBackupHeader = TRUE;
				bHeaderBakRetry = TRUE;
			}
			else if (bHeaderBakRetry)
			{
				mountOptions.UseBackupHeader = defaultMountOptions.UseBackupHeader;
				bHeaderBakRetry = FALSE;
			}

			if (!Silent && !bHeaderBakRetry)
			{
				WCHAR szTmp[4096];

				StringCbPrintfW (szTmp, sizeof(szTmp), GetString (KeyFilesEnable || FirstCmdKeyFile ? "PASSWORD_OR_KEYFILE_WRONG_AUTOMOUNT" : "PASSWORD_WRONG_AUTOMOUNT"));
				if (CheckCapsLock (hwndDlg, TRUE))
					StringCbCatW (szTmp, sizeof(szTmp), GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONWARNING);
			}
		}
		else if (bHeaderBakRetry)
		{
			// We have successfully mounted a volume using the header backup embedded in the volume (the header is damaged)
			mountOptions.UseBackupHeader = defaultMountOptions.UseBackupHeader;
			bHeaderBakRetry = FALSE;

			if (!Silent)
				Warning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK");
		}

		if (!bHeaderBakRetry)
		{
			burn (&VolumePassword, sizeof (VolumePassword));
			burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
		}

	} while (bPasswordPrompt && mountedVolCount < 1);

	/* One or more volumes successfully mounted */

	ResetWrongPwdRetryCount ();

	if (shared)
		Warning ("DEVICE_IN_USE_INFO");

	if (mountOptions.ProtectHiddenVolume)
	{
		if (mountedVolCount > 1) 
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL");
		else if (mountedVolCount == 1)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT");
	}

	// Check for legacy non-ASCII passwords
	if (!KeyFilesEnable
		&& !FirstCmdKeyFile
		&& mountedVolCount > 0
		&& !CheckPasswordCharEncoding (NULL, &VolumePassword))
			Warning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");

	if (status && CloseSecurityTokenSessionsAfterMount)
		SecurityToken::CloseAllSessions();

ret:
	MultipleMountOperationInProgress = FALSE;

	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

	mountOptions.UseBackupHeader = defaultMountOptions.UseBackupHeader;

	RestoreDefaultKeyFilesParam ();

	if (UsePreferences)
		bCacheInDriver = bCacheInDriverDefault;

	EnableDisableButtons (hwndDlg);

	NormalCursor();

	return status;
}

static void ChangePassword (HWND hwndDlg)
{
	int result;
	
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, sizeof (szFileName));
	if (IsMountedVolume (szFileName))
	{
		Warning (pwdChangeDlgMode == PCDM_CHANGE_PKCS5_PRF ? "MOUNTED_NO_PKCS5_PRF_CHANGE" : "MOUNTED_NOPWCHANGE");
		return;
	}

	if (!VolumePathExists (szFileName))
	{
		handleWin32Error (hwndDlg);
		return;
	}

	bSysEncPwdChangeDlgMode = FALSE;

	result = DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_PASSWORDCHANGE_DLG), hwndDlg,
		(DLGPROC) PasswordChangeDlgProc);

	if (result == IDOK)
	{
		switch (pwdChangeDlgMode)
		{
		case PCDM_CHANGE_PKCS5_PRF:
			Info ("PKCS5_PRF_CHANGED");
			break;

		case PCDM_ADD_REMOVE_VOL_KEYFILES:
		case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
			Info ("KEYFILE_CHANGED");
			break;

		case PCDM_CHANGE_PASSWORD:
		default:
			Info ("PASSWORD_CHANGED");
		}
	}
}

// Change password of the system partition/drive
static void ChangeSysEncPassword (HWND hwndDlg, BOOL bOnlyChangeKDF)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (!BootEncStatus.DriveEncrypted 
		&& !BootEncStatus.DriveMounted
		&& !BootEncStatus.VolumeHeaderPresent
		&& !SysEncryptionOrDecryptionRequired ())
	{
		Warning ("SYS_DRIVE_NOT_ENCRYPTED");
		return;
	}

	if (SysEncryptionOrDecryptionRequired () 
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED");
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		StringCbPrintfA (OrigKeyboardLayout, sizeof(OrigKeyboardLayout), "%08X", (DWORD) GetKeyboardLayout (NULL) & 0xFFFF);

		bSysEncPwdChangeDlgMode = TRUE;

		if (bOnlyChangeKDF)
			pwdChangeDlgMode = PCDM_CHANGE_PKCS5_PRF;
		else
			pwdChangeDlgMode = PCDM_CHANGE_PASSWORD;


		INT_PTR result = DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_PASSWORDCHANGE_DLG), hwndDlg, (DLGPROC) PasswordChangeDlgProc);

		bSysEncPwdChangeDlgMode = FALSE;

		if (bKeyboardLayoutChanged)
		{
			// Restore the original keyboard layout
			if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL) 
				Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT");
			else
				bKeyboardLayoutChanged = FALSE;
		}

		bKeybLayoutAltKeyWarningShown = FALSE;

		if (result == IDOK)
		{
			switch (pwdChangeDlgMode)
			{
			case PCDM_CHANGE_PKCS5_PRF:
				Info ("PKCS5_PRF_CHANGED");

				if (!IsHiddenOSRunning())
				{
					if (AskWarnYesNo ("SYS_HKD_ALGO_CHANGED_ASK_RESCUE_DISK") == IDYES)
						CreateRescueDisk ();
				}

				break;

			case PCDM_ADD_REMOVE_VOL_KEYFILES:
			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
				// NOP - Keyfiles are not supported for system encryption
				break;

			case PCDM_CHANGE_PASSWORD:
			default:
				Info ("PASSWORD_CHANGED");

				if (!IsHiddenOSRunning())
				{
					if (AskWarnYesNo ("SYS_PASSWORD_CHANGED_ASK_RESCUE_DISK") == IDYES)
						CreateRescueDisk ();
				}
			}
		}

		CloseSysEncMutex ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}

// Initiates or resumes encryption of the system partition/drive
static void EncryptSystemDevice (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (!BootEncStatus.DriveEncrypted 
		&& !BootEncStatus.DriveMounted
		&& !SysEncryptionOrDecryptionRequired ())
	{
		// System partition/drive is not encrypted (nothing to resume). Initiate the process.

		if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
		{
			LaunchVolCreationWizard (MainDlg, "/sysenc");
		}
		else
			Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");

		return;
	}
	else if (SysEncryptionOrDecryptionRequired ())
	{
		// System partition/drive encryption already initiated but is incomplete -- attempt to resume the process.
		// Note that this also covers the pretest phase and paused decryption (reverses decrypting and starts encrypting)

		if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
		{
			LaunchVolCreationWizard (MainDlg, "/sysenc");
		}
		else
			Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
	}
	else if (SysDriveOrPartitionFullyEncrypted (FALSE))
	{
		// System partition/drive appears to be fully encrypted
		Info ("SYS_PARTITION_OR_DRIVE_APPEARS_FULLY_ENCRYPTED");
		return;
	}
}

// Initiates decryption of the system partition/drive
static void DecryptSystemDevice (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (!BootEncStatus.DriveEncrypted 
		&& !BootEncStatus.DriveMounted
		&& !BootEncStatus.DeviceFilterActive
		&& !BootEncStatus.VolumeHeaderPresent
		&& !SysEncryptionOrDecryptionRequired ())
	{
		Warning ("SYS_DRIVE_NOT_ENCRYPTED");
		return;
	}

	if (IsHiddenOSRunning())
	{
		Warning ("CANNOT_DECRYPT_HIDDEN_OS");
		return;
	}

	if (AskNoYes ("CONFIRM_DECRYPT_SYS_DEVICE") == IDNO)
		return;

	if (AskWarnNoYes ("CONFIRM_DECRYPT_SYS_DEVICE_CAUTION") == IDNO)
		return;

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		try
		{
			// User-mode app may have crashed and its mutex may have gotten lost, so we need to check the driver status too
			if (BootEncStatus.SetupInProgress)
			{
				int attempts = 20;

				BootEncObj->AbortSetup ();
				while (BootEncStatus.SetupInProgress && attempts > 0)
				{
					Sleep (100);
					BootEncStatus = BootEncObj->GetStatus();
					attempts--;
					WaitCursor();
				}
			}
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}
		NormalCursor ();

		if (BootEncStatus.SetupInProgress)
		{
			CloseSysEncMutex ();	
			Error ("SYS_ENCRYPTION_OR_DECRYPTION_IN_PROGRESS");
			return;
		}

		CloseSysEncMutex ();	
		LaunchVolCreationWizard (MainDlg, "/dsysenc");
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}

// Initiates the process of creation of a hidden operating system
static void CreateHiddenOS (void)
{

	// Display brief information as to what a hidden operating system is and what it's good for. This needs to be
	// done, because if the system partition/drive is currently encrypted, the wizard will not display any
	// such information, but will exit (displaying only an error meessage).
	Info("HIDDEN_OS_PREINFO");

	LaunchVolCreationWizard (MainDlg, "/isysenc");
}

// Blindly attempts (without any checks) to instruct the wizard to resume whatever system encryption process
// had been interrupted or not started but scheduled or exptected to start.
static void ResumeInterruptedSysEncProcess (void)
{
	if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
	{
		LaunchVolCreationWizard (MainDlg, "/csysenc");
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}

void CreateRescueDisk (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (IsHiddenOSRunning())
	{
		Warning ("CANNOT_CREATE_RESCUE_DISK_ON_HIDDEN_OS");
		return;
	}

	if (!BootEncStatus.DriveEncrypted 
		&& !BootEncStatus.DriveMounted
		&& !BootEncStatus.VolumeHeaderPresent
		&& !SysEncryptionOrDecryptionRequired ())
	{
		Warning ("SYS_DRIVE_NOT_ENCRYPTED");
		return;
	}

	if (SysEncryptionOrDecryptionRequired () 
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED");
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		try
		{
			wchar_t szTmp [8096];
			char szRescueDiskISO [TC_MAX_PATH+1];

			if (AskOkCancel ("RESCUE_DISK_NON_WIZARD_CREATION_SELECT_PATH") != IDOK)
			{		
				CloseSysEncMutex ();
				return;
			}

			char initialDir[MAX_PATH];
			SHGetFolderPath (NULL, CSIDL_MYDOCUMENTS, NULL, 0, initialDir);

			if (!BrowseFilesInDir (MainDlg, "OPEN_TITLE", initialDir, szRescueDiskISO, FALSE, TRUE, NULL, L"VeraCrypt Rescue Disk.iso", L"iso"))
			{		
				CloseSysEncMutex ();
				return;
			}

			WaitCursor();
			BootEncObj->CreateRescueIsoImage (false, szRescueDiskISO);

			StringCbPrintfW (szTmp, sizeof szTmp,
				GetString (IsWindowsIsoBurnerAvailable() ? "RESCUE_DISK_NON_WIZARD_CREATION_WIN_ISOBURN" : "RESCUE_DISK_NON_WIZARD_CREATION_BURN"),
				szRescueDiskISO);

			if (IsWindowsIsoBurnerAvailable())
			{
				if (AskYesNoString (szTmp) == IDYES)
					LaunchWindowsIsoBurner (MainDlg, szRescueDiskISO);
			}
			else
				InfoDirect (szTmp);
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("ERROR_CREATING_RESCUE_DISK");
		}
		CloseSysEncMutex ();

		NormalCursor ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}

static void VerifyRescueDisk (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (!BootEncStatus.DriveEncrypted 
		&& !BootEncStatus.DriveMounted
		&& !BootEncStatus.VolumeHeaderPresent
		&& !SysEncryptionOrDecryptionRequired ())
	{
		Warning ("SYS_DRIVE_NOT_ENCRYPTED");
		return;
	}

	if (SysEncryptionOrDecryptionRequired () 
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED");
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		try
		{
			if (AskOkCancel ("RESCUE_DISK_NON_WIZARD_CHECK_INSERT") != IDOK)
			{		
				CloseSysEncMutex ();
				return;
			}

			// Create a temporary up-to-date rescue disk image in RAM (with it the CD/DVD content will be compared)
			BootEncObj->CreateRescueIsoImage (false, "");

			WaitCursor();
			if (!BootEncObj->VerifyRescueDisk ())
				Error ("RESCUE_DISK_NON_WIZARD_CHECK_FAILED");
			else
				Info ("RESCUE_DISK_NON_WIZARD_CHECK_PASSED");
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("RESCUE_DISK_NON_WIZARD_CHECK_FAILED");
		}
		CloseSysEncMutex ();

		NormalCursor ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");
}

static void ShowSystemEncryptionStatus (void)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	if (GetAsyncKeyState (VK_SHIFT) < 0 && GetAsyncKeyState (VK_CONTROL) < 0)
	{
		// Ctrl+Shift held (for debugging purposes)

		DebugMsgBox ("Debugging information for system encryption:\n\nDeviceFilterActive: %d\nBootLoaderVersion: %x\nSetupInProgress: %d\nSetupMode: %d\nVolumeHeaderPresent: %d\nDriveMounted: %d\nDriveEncrypted: %d\n"
			"HiddenSystem: %d\nHiddenSystemPartitionStart: %I64d\n"
			"ConfiguredEncryptedAreaStart: %I64d\nConfiguredEncryptedAreaEnd: %I64d\nEncryptedAreaStart: %I64d\nEncryptedAreaEnd: %I64d\nEncrypted: %I64d%%",
			BootEncStatus.DeviceFilterActive,
			BootEncStatus.BootLoaderVersion,
			BootEncStatus.SetupInProgress,
			BootEncStatus.SetupMode,
			BootEncStatus.VolumeHeaderPresent,
			BootEncStatus.DriveMounted,
			BootEncStatus.DriveEncrypted,
			BootEncStatus.HiddenSystem ? 1 : 0,
			BootEncStatus.HiddenSystemPartitionStart,
			BootEncStatus.ConfiguredEncryptedAreaStart,
			BootEncStatus.ConfiguredEncryptedAreaEnd,
			BootEncStatus.EncryptedAreaStart,
			BootEncStatus.EncryptedAreaEnd,
			!BootEncStatus.DriveEncrypted ? 0 : (BootEncStatus.EncryptedAreaEnd + 1 - BootEncStatus.EncryptedAreaStart) * 100I64 / (BootEncStatus.ConfiguredEncryptedAreaEnd + 1 - BootEncStatus.ConfiguredEncryptedAreaStart));
	}

	if (!BootEncStatus.DriveEncrypted && !BootEncStatus.DriveMounted)
	{
		Info ("SYS_DRIVE_NOT_ENCRYPTED");
		return;
	}

	DialogBoxParamW (hInst, 
		MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), MainDlg,
		(DLGPROC) VolumePropertiesDlgProc, (LPARAM) TRUE);

}

static void ResumeInterruptedNonSysInplaceEncProcess (void)
{
	// IMPORTANT: This function must not check any config files! Otherwise, if a config file was lost or corrupt, 
	// the user would not be able resume encryption and the data on the volume would be inaccessible.

	LaunchVolCreationWizard (MainDlg, "/zinplace");
}

static BOOL SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, "OPEN_VOL_TITLE", szFileName, bHistory, FALSE, NULL) == FALSE)
		return FALSE;

	AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
	EnableDisableButtons (hwndDlg);
	SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
	return TRUE;
}

static BOOL SelectPartition (HWND hwndDlg)
{
	int nResult = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) & szFileName[0]);
	if (nResult == IDOK)
	{
		AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
		EnableDisableButtons (hwndDlg);
		SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		return TRUE;
	}

	return FALSE;
}

static void WipeCache (HWND hwndDlg, BOOL silent)
{
	DWORD dwResult;
	BOOL bResult;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
	if (hwndDlg == NULL)
		return;

	if (bResult == FALSE)
		handleWin32Error (hwndDlg);
	else
	{
		EnableDisableButtons (hwndDlg);

		if (!silent)
			InfoBalloon ("PASSWORD_CACHE_WIPED_SHORT", "PASSWORD_CACHE_WIPED");
	}
}

static void Benchmark (HWND hwndDlg)
{
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_BENCHMARK_DLG), hwndDlg,
		(DLGPROC) BenchmarkDlgProc, (LPARAM) NULL);
}


static BOOL CheckMountList ()
{
	MOUNT_LIST_STRUCT current;
	static BootEncryptionStatus newBootEncStatus;
	static BOOL lastbUseDifferentTrayIconIfVolMounted = bUseDifferentTrayIconIfVolMounted;
	static uint32 lastUlMountedDrives = 0;

	GetMountList (&current);

	if ((current.ulMountedDrives != lastUlMountedDrives || bUseDifferentTrayIconIfVolMounted != lastbUseDifferentTrayIconIfVolMounted)
		&& TaskBarIconMutex != NULL)
	{
		lastUlMountedDrives = current.ulMountedDrives;
		lastbUseDifferentTrayIconIfVolMounted = bUseDifferentTrayIconIfVolMounted;

		TaskBarIconChange (MainDlg, current.ulMountedDrives != 0 && bUseDifferentTrayIconIfVolMounted ? IDI_TRUECRYPT_MOUNTED_ICON : IDI_TRUECRYPT_ICON);
	}

	if (LastKnownLogicalDrives != GetLogicalDrives()
		|| memcmp (&LastKnownMountList, &current, sizeof (current)) != 0)
	{
		char selDrive;

		WaitCursor ();
		LastKnownMountList = current;

		selDrive = (char) HIWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST)));
		LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), 0);
		NormalCursor ();

		if (selDrive != -1 && (current.ulMountedDrives & (1 << (selDrive - 'A'))) == 0 && !IsDriveAvailable (selDrive - 'A'))
		{
			nSelectedDriveIndex = -1;
			return FALSE;
		}

		if (selDrive != -1)
			SelectItem (GetDlgItem (MainDlg, IDC_DRIVELIST),selDrive);
	}

	try
	{
		newBootEncStatus = BootEncObj->GetStatus();

		if (newBootEncStatus.SetupInProgress != RecentBootEncStatus.SetupInProgress
			|| newBootEncStatus.EncryptedAreaEnd != RecentBootEncStatus.EncryptedAreaEnd
			|| newBootEncStatus.DriveEncrypted != RecentBootEncStatus.DriveEncrypted
			|| newBootEncStatus.DriveMounted != RecentBootEncStatus.DriveMounted
			|| newBootEncStatus.SetupMode != RecentBootEncStatus.SetupMode
			|| newBootEncStatus.EncryptedAreaStart != RecentBootEncStatus.EncryptedAreaStart)
		{
			/* System encryption status change */

			char selDrive;
			int driveLetterToRefresh;

			if (RecentBootEncStatus.DriveMounted == newBootEncStatus.DriveMounted)	// If an icon (and whole new line) for a system device isn't to be added/removed
			{
				// Partial refresh
				if (WholeSysDriveEncryption (TRUE))
				{
					// System drive (not just partition)
					driveLetterToRefresh = ENC_SYSDRIVE_PSEUDO_DRIVE_LETTER;
				}
				else
				{
					// System partition 
					driveLetterToRefresh = GetSystemDriveLetter ();
				}
			}
			else
			{
				// Full rebuild of the mount list
				driveLetterToRefresh = 0;	
			}

			selDrive = (char) HIWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST)));
			LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), driveLetterToRefresh);

			RecentBootEncStatus = newBootEncStatus;

			if (selDrive != -1 && (current.ulMountedDrives & (1 << (selDrive - 'A'))) == 0 && !IsDriveAvailable (selDrive - 'A'))
			{
				nSelectedDriveIndex = -1;
			}

			if (selDrive != -1)
			{
				SelectItem (GetDlgItem (MainDlg, IDC_DRIVELIST),selDrive);
			}
		}

		/* Miscellaneous notifications */

		// Hibernation prevention notifications
		if (newBootEncStatus.HibernationPreventionCount != RecentBootEncStatus.HibernationPreventionCount
			&& !bHibernationPreventionNotified)
		{
			bHibernationPreventionNotified = TRUE;
			RecentBootEncStatus.HibernationPreventionCount = newBootEncStatus.HibernationPreventionCount;

			if (IsHiddenOSRunning() && BootEncObj->GetSystemDriveConfiguration().ExtraBootPartitionPresent)
				WarningTopMost ("HIDDEN_OS_HIBERNATION_PREVENTED");
			else
				WarningTopMost ("SYS_ENC_HIBERNATION_PREVENTED");
		}

		// Write mode prevention (hidden OS leak protection)
		if (IsHiddenOSRunning())
		{
			if (newBootEncStatus.HiddenSysLeakProtectionCount != RecentBootEncStatus.HiddenSysLeakProtectionCount
				&& !bHiddenSysLeakProtNotifiedDuringSession)
			{
				bHiddenSysLeakProtNotifiedDuringSession = TRUE;

				switch (HiddenSysLeakProtectionNotificationStatus)
				{
				case TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_COMPACT:
					{
						char *tmp[] = {0, "HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO", "SHOW_MORE_INFORMATION", "DO_NOT_SHOW_THIS_AGAIN", "CONTINUE", 0};
						switch (AskMultiChoice ((void **) tmp, FALSE))
						{
						case 1:
							InfoDirect ((wstring (GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO"))
								+ L"\n\n"
								+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")
								+ L"\n\n\n"
								+ GetString ("DECOY_TO_HIDDEN_OS_DATA_TRANSFER_HOWTO")).c_str());
							break;

						case 2:
							// No more warnings will be shown
							if (ConfigBuffer == NULL)
							{
								// We need to load the config file because it is not done automatically when
								// launched from the sys startup sequence (and SaveSettings would start by _loading_ 
								// the settings to cache).
								LoadSettings (MainDlg);	
							}
							HiddenSysLeakProtectionNotificationStatus = TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_DISABLED;
							SaveSettings (MainDlg);
							break;

						default:
							// NOP
							break;
						}
					}
					break;

				case TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_DISABLED:
					// NOP
					break;

				case TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE:
				default:
					{
						// First time warning -- include technical explanation
						InfoDirect ((wstring (GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO"))
							+ L"\n\n"
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")
							+ L"\n\n\n"
							+ GetString ("DECOY_TO_HIDDEN_OS_DATA_TRANSFER_HOWTO")).c_str());

						// Further warnings will not include the explanation (and will allow disabling)

						if (ConfigBuffer == NULL)
						{
							// We need to load the config file because it is not done automatically when
							// launched from the sys startup sequence (and SaveSettings would start by _loading_ 
							// the settings to cache).
							LoadSettings (MainDlg);	
						}
						HiddenSysLeakProtectionNotificationStatus = TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_COMPACT;
						SaveSettings (MainDlg);
					}
					break;
				}
			}
		}
	}
	catch (...)
	{
		// NOP
	}

	return TRUE;
}


/* Except in response to the WM_INITDIALOG and WM_ENDSESSION messages, the dialog box procedure
   should return nonzero if it processes a message, and zero if it does not. */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static UINT taskBarCreatedMsg;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	DWORD mPos;

	switch (uMsg)
	{
	case WM_HOTKEY:

		HandleHotKey (hwndDlg, wParam);
		return 1;

	case WM_INITDIALOG:
		{
			int exitCode = 0;

			MainDlg = hwndDlg;

			if (IsTrueCryptInstallerRunning())
				AbortProcess ("TC_INSTALLER_IS_RUNNING");

			// Set critical default options in case UsePreferences is false
			bPreserveTimestamp = defaultMountOptions.PreserveTimestamp = TRUE;

			ResetWrongPwdRetryCount ();

			ExtractCommandLine (hwndDlg, (char *) lParam);

			try
			{
				BootEncStatus = BootEncObj->GetStatus();
				RecentBootEncStatus = BootEncStatus;
			}
			catch (...)
			{
				// NOP
			}

			if (UsePreferences)
			{
				// General preferences
				LoadSettings (hwndDlg);

				// Keyfiles
				LoadDefaultKeyFilesParam ();
				RestoreDefaultKeyFilesParam ();
			}

			if (ComServerMode)
			{
				InitDialog (hwndDlg);

				if (!ComServerMain ())
				{
					handleWin32Error (hwndDlg);
					exit (1);
				}
				exit (0);
			}

			if (CmdMountOptionsValid)
				mountOptions = CmdMountOptions;

			InitMainDialog (hwndDlg);

			try
			{
				if (IsHiddenOSRunning())
				{
					if (BootEncObj->GetInstalledBootLoaderVersion() > VERSION_NUM)
						Warning ("UPDATE_TC_IN_HIDDEN_OS_TOO");
				}
				else if (SysDriveOrPartitionFullyEncrypted (TRUE)
					&& BootEncObj->GetInstalledBootLoaderVersion() != VERSION_NUM)
				{
					Warning ("BOOT_LOADER_VERSION_DIFFERENT_FROM_DRIVER_VERSION");
				}
			} 
			catch (...) { }

			// Automount
			if (bAuto || (Quit && szFileName[0] != 0))
			{
				// No drive letter specified on command line
				if (commandLineDrive == 0)
					szDriveLetter[0] = (char) GetFirstAvailableDrive () + 'A';

				if (bAutoMountDevices)
				{
					defaultMountOptions = mountOptions;
					if (FirstCmdKeyFile)
					{
						KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles = TRUE;
						FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
						defaultKeyFilesParam.FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
					}

					if (!MountAllDevices (hwndDlg, !Silent && !CmdVolumePasswordValid && IsPasswordCacheEmpty()))
						exitCode = 1;
				}

				if (bAutoMountFavorites)
				{
					defaultMountOptions = mountOptions;
					if (FirstCmdKeyFile)
					{
						KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles = TRUE;
						FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
						defaultKeyFilesParam.FirstKeyFile = KeyFileCloneAll (FirstCmdKeyFile);
					}

					if (!MountFavoriteVolumes (FALSE, LogOn))
						exitCode = 1;
				}

				if (szFileName[0] != 0 && !IsMountedVolume (szFileName))
				{
					BOOL mounted;

					// Cached password
					mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);

					// Command line password or keyfiles
					if (!mounted && (CmdVolumePassword.Length != 0 || FirstCmdKeyFile))
					{
						BOOL reportBadPasswd = CmdVolumePassword.Length > 0;

						if (FirstCmdKeyFile)
							KeyFilesApply (&CmdVolumePassword, FirstCmdKeyFile);

						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A',
							szFileName, &CmdVolumePassword, bCacheInDriver, bForceMount,
							&mountOptions, Silent, reportBadPasswd);

						burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
					}

					if (FirstCmdKeyFile)
					{
						FirstKeyFile = FirstCmdKeyFile;
						KeyFilesEnable = TRUE;
					}

					// Ask user for password
					while (!mounted && !Silent)
					{
						VolumePassword.Length = 0;

						StringCbCopyA (PasswordDlgVolume, sizeof(PasswordDlgVolume),szFileName);
						if (!AskVolumePassword (hwndDlg, &VolumePassword, NULL, TRUE))
							break;

						WaitCursor ();

						if (KeyFilesEnable && FirstKeyFile)
							KeyFilesApply (&VolumePassword, FirstKeyFile);

						mounted = MountVolume (hwndDlg, szDriveLetter[0] - 'A', szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, FALSE, TRUE);

						burn (&VolumePassword, sizeof (VolumePassword));
						burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

						NormalCursor ();
					}

					if (UsePreferences)
					{
						RestoreDefaultKeyFilesParam ();
						bCacheInDriver = bCacheInDriverDefault;
					}

					if (mounted > 0)
					{
						if (bBeep) 
							MessageBeep (0xFFFFFFFF);

						if (bExplore) 
							OpenVolumeExplorerWindow (szDriveLetter[0] - 'A');

						RefreshMainDlg(hwndDlg);

						if(!Silent)
						{
							// Check for problematic file extensions (exe, dll, sys)
							if (CheckFileExtension (szFileName))
								Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING");
						}
					}
					else
						exitCode = 1;
				}
				else if (bExplore && GetMountedVolumeDriveNo (szFileName) != -1)
					OpenVolumeExplorerWindow (GetMountedVolumeDriveNo (szFileName));
				else if (szFileName[0] != 0 && IsMountedVolume (szFileName))
					Warning ("VOL_ALREADY_MOUNTED");
					
				if (!Quit)
					RefreshMainDlg(hwndDlg);
			}
			
			// Wipe cache
			if (bWipe)
				WipeCache (hwndDlg, Silent);

			// Wipe command line password
			if (CmdVolumePassword.Length != 0)
			{
				burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
				CmdVolumePassword.Length = 0;
			}

			// Wipe command line keyfiles
			if (FirstCmdKeyFile)
			{
				if (defaultKeyFilesParam.FirstKeyFile)
					KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);

				defaultKeyFilesParam.EnableKeyFiles = FALSE;

				if (!Quit)
				{
					LoadSettings (hwndDlg);
					LoadDefaultKeyFilesParam ();
					RestoreDefaultKeyFilesParam ();
				}
			}

			// Dismount
			if (cmdUnmountDrive > 0)
			{
				MOUNT_LIST_STRUCT mountList;
				DWORD bytesReturned;

				if (DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, NULL, 0, &mountList, sizeof (mountList), &bytesReturned, NULL)
					&& (mountList.ulMountedDrives & (1 << cmdUnmountDrive)) == 0)
				{
					Error ("NO_VOLUME_MOUNTED_TO_DRIVE");
					exitCode = 1;
				}
				else if (!Dismount (hwndDlg, cmdUnmountDrive))
					exitCode = 1;
			}
			else if (cmdUnmountDrive == -1)
			{
				if (!DismountAll (hwndDlg, bForceUnmount, !Silent, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY))
					exitCode = 1;
			}

			// TaskBar icon
			if (bEnableBkgTask)
				TaskBarIconAdd (hwndDlg);

			// Quit
			if (Quit)
			{
				if (TaskBarIconMutex == NULL)
					exit (exitCode);

				MainWindowHidden = TRUE;

				LoadSettings (hwndDlg);
				LoadDefaultKeyFilesParam ();
				RestoreDefaultKeyFilesParam ();

				if (!bEnableBkgTask)
				{
					if (TaskBarIconMutex)
						TaskBarIconRemove (hwndDlg);
					exit (exitCode);
				}
			}

			// No command line arguments or only /volume => bring active instance
			// to foreground if available
			if (NoCmdLineArgs == 0 || (CmdLineVolumeSpecified && NoCmdLineArgs <= 2))
			{
				HWND h = hwndDlg;
				EnumWindows (FindTCWindowEnum, (LPARAM) &h);

				if (h != hwndDlg
					&& (!IsAdmin() || (GetWindowLongPtr (h, DWLP_USER) & TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES) != 0))
				{
					if (CmdLineVolumeSpecified)
					{
						COPYDATASTRUCT cd;
						memcpy (&cd.dwData, WM_COPY_SET_VOLUME_NAME, 4);
						cd.lpData = szFileName;
						cd.cbData = strlen (szFileName) + 1;

						SendMessage (h, WM_COPYDATA, (WPARAM)hwndDlg, (LPARAM)&cd);
					}

					SendMessage (h, TC_APPMSG_MOUNT_SHOW_WINDOW, 0, 0);

					ShowWindow (h, SW_SHOW);
					SetForegroundWindow (h);

					if (TaskBarIconMutex == NULL)
						exit (0);
				}
			}

			HookMouseWheel (hwndDlg, IDC_VOLUME);

			// Register hot keys
			if (!RegisterAllHotkeys (hwndDlg, Hotkeys)
				&& TaskBarIconMutex != NULL)	// Warn only if we are the first instance of TrueCrypt
				Warning("HOTKEY_REGISTRATION_ERROR");

			Silent = FALSE;

			GetMountList (&LastKnownMountList);
			SetTimer (hwndDlg, TIMER_ID_MAIN, TIMER_INTERVAL_MAIN, NULL);

			taskBarCreatedMsg = RegisterWindowMessage ("TaskbarCreated");

			SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));

			/* Check system encryption status */

			if (!Quit)	// Do not care about system encryption or in-place encryption if we were launched from the system startup sequence (the wizard was added to it too).
			{
				if (SysEncryptionOrDecryptionRequired ())
				{
					if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
					{
						// We shouldn't block the mutex at this point

						if (SystemEncryptionStatus == SYSENC_STATUS_PRETEST
							|| AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT") == IDYES)
						{
							// The wizard was not launched during the system startup seq, or the user may have forgotten
							// to resume the encryption/decryption process.


							LaunchVolCreationWizard (hwndDlg, "/csysenc");
						}
					}
				}

				if (bInPlaceEncNonSysPending && !NonSysInplaceEncInProgressElsewhere())
				{
					if (AskNonSysInPlaceEncryptionResume() == IDYES)
						ResumeInterruptedNonSysInplaceEncProcess ();
				}
			}

			if (!DisableSystemCrashDetection
				&& IsOSAtLeast (WIN_7))
			{
				// Auto-detect a system crash
				
				const int detectionPeriodInMonthsSinceReleaseDate = 2;
				int maxYear = TC_RELEASE_DATE_YEAR;
				int maxMonth = TC_RELEASE_DATE_MONTH + detectionPeriodInMonthsSinceReleaseDate;
				if (maxMonth > 12)
				{
					++maxYear;
					maxMonth -= 12;
				}

				SYSTEMTIME systemTime;
				GetSystemTime (&systemTime);

				if (systemTime.wYear >= TC_RELEASE_DATE_YEAR
					&& !(systemTime.wYear == TC_RELEASE_DATE_YEAR && systemTime.wMonth < TC_RELEASE_DATE_MONTH)
					&& systemTime.wYear <= maxYear
					&& !(systemTime.wYear == maxYear && systemTime.wMonth > maxMonth))
				{
					char winDir[MAX_PATH] = { 0 };
					GetWindowsDirectory (winDir, sizeof (winDir));

					WIN32_FIND_DATA findData;
					HANDLE find = FindFirstFile ((string (winDir) + "\\MEMORY.DMP").c_str(), &findData);

					if (find != INVALID_HANDLE_VALUE)
					{
						SYSTEMTIME systemTime;
						FILETIME ft;
						GetSystemTime (&systemTime);
						SystemTimeToFileTime (&systemTime, &ft);

						ULARGE_INTEGER sysTime, fileTime;
						sysTime.HighPart = ft.dwHighDateTime;
						sysTime.LowPart = ft.dwLowDateTime;
						fileTime.HighPart = findData.ftLastWriteTime.dwHighDateTime;
						fileTime.LowPart = findData.ftLastWriteTime.dwLowDateTime;

						// Memory dump must not be older than 10 minutes
						if (sysTime.QuadPart - fileTime.QuadPart < 10I64 * 1000 * 1000 * 60 * 10)
							SystemCrashDetected = TRUE;

						FindClose (find);
					}
				}
			}

			DoPostInstallTasks ();
			ResetCurrentDirectory ();
		}
		return 0;
		
	case WM_MOUSEWHEEL:
		return HandleDriveListMouseWheelEvent (uMsg, wParam, lParam, FALSE);

	case WM_WINDOWPOSCHANGING:
		if (MainWindowHidden)
		{
			// Prevent window from being shown
			PWINDOWPOS wp = (PWINDOWPOS)lParam;
			wp->flags &= ~SWP_SHOWWINDOW;
			return 0;
		}
		return 1;

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
		if (TaskBarIconMutex != NULL)
		{
			if (bDismountOnLogOff)
			{
				// Auto-dismount when user logs off
				DWORD dwResult;

				if (bWipeCacheOnAutoDismount)
					DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
				
				DismountAll (hwndDlg, bForceAutoDismount, FALSE, 1, 0);
			}

			TaskBarIconRemove (hwndDlg);
		}
		EndMainDlg (hwndDlg);
		localcleanup ();
		return 0;

	case WM_POWERBROADCAST:
		if (wParam == PBT_APMSUSPEND
			&& TaskBarIconMutex != NULL && bDismountOnPowerSaving)
		{
			// Auto-dismount when entering power-saving mode
			DWORD dwResult;

			if (bWipeCacheOnAutoDismount)
			{
				DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
				SecurityToken::CloseAllSessions();
			}

			DismountAll (hwndDlg, bForceAutoDismount, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
		}
		return 0;

	case WM_TIMER:
		{
			// Check mount list and update GUI if needed
			CheckMountList ();

			// Cache status
			if (IsPasswordCacheEmpty() == IsWindowEnabled (GetDlgItem (hwndDlg, IDC_WIPE_CACHE)))
				EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());

			// Check driver warning flags
			DWORD bytesOut;
			GetWarningFlagsRequest warnings;
			if (DeviceIoControl (hDriver, TC_IOCTL_GET_WARNING_FLAGS, NULL, 0, &warnings, sizeof (warnings), &bytesOut, NULL))
			{
				if (warnings.SystemFavoriteVolumeDirty)
					WarningTopMost ("SYS_FAVORITE_VOLUME_DIRTY");

				if (warnings.PagingFileCreationPrevented)
					WarningTopMost ("PAGING_FILE_CREATION_PREVENTED");
			}

			if (TaskBarIconMutex != NULL)
			{
				// Handle system crash
				static BOOL systemCrashHandlerLocked = FALSE;
				if (SystemCrashDetected && !systemCrashHandlerLocked)
				{
					systemCrashHandlerLocked = TRUE;

					SetForegroundWindow (hwndDlg);
					MainWindowHidden = FALSE;
					ShowWindow (hwndDlg, SW_SHOW);
					ShowWindow (hwndDlg, SW_RESTORE);

					if (AskYesNoTopmost ("SYSTEM_CRASHED_ASK_REPORT") == IDYES)
					{
						if (!IsAdmin() && IsUacSupported())
							UacAnalyzeKernelMiniDump (hwndDlg);
						else
							AnalyzeKernelMiniDump (hwndDlg);
					}
					else if (AskYesNoTopmost ("ASK_KEEP_DETECTING_SYSTEM_CRASH") == IDNO)
					{
						DisableSystemCrashDetection = TRUE;
						SaveSettings (hwndDlg);
					}
				}

				// Idle auto-dismount
				if (MaxVolumeIdleTime > 0)
					DismountIdleVolumes ();

				// Screen saver auto-dismount
				if (bDismountOnScreenSaver)
				{
					static BOOL previousState = FALSE;
					BOOL running = FALSE;
					SystemParametersInfo (SPI_GETSCREENSAVERRUNNING, 0, &running, 0);

					if (running && !previousState)
					{
						DWORD dwResult;
						previousState = TRUE;

						if (bWipeCacheOnAutoDismount)
						{
							DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
							SecurityToken::CloseAllSessions();
						}

						DismountAll (hwndDlg, bForceAutoDismount, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
					}
					else
					{
						previousState = running;
					}
				}

				// Auto-mount favorite volumes on arrival
#if TIMER_INTERVAL_MAIN != 500
#error TIMER_INTERVAL_MAIN != 500
#endif
				static int favoritesAutoMountTimerDivisor = 0;
				if ((++favoritesAutoMountTimerDivisor & 1) && !FavoritesOnArrivalMountRequired.empty())
				{
					static bool reentry = false;
					if (reentry)
						break;

					reentry = true;

					foreach (FavoriteVolume favorite, FavoritesOnArrivalMountRequired)
					{
						if (!favorite.VolumePathId.empty())
						{
							if (IsMountedVolume (favorite.Path.c_str()))
								continue;

							char volDevPath[TC_MAX_PATH];
							if (QueryDosDevice (favorite.VolumePathId.substr (4, favorite.VolumePathId.size() - 5).c_str(), volDevPath, TC_MAX_PATH) == 0)
								continue;

							favorite.DisconnectedDevice = false;
						}
						else if (favorite.Path.find ("\\\\?\\Volume{") == 0)
						{
							string resolvedPath = VolumeGuidPathToDevicePath (favorite.Path);
							if (resolvedPath.empty())
								continue;

							favorite.DisconnectedDevice = false;
							favorite.VolumePathId = favorite.Path;
							favorite.Path = resolvedPath;
						}

						if (IsMountedVolume (favorite.Path.c_str()))
							continue;

						if (!IsVolumeDeviceHosted (favorite.Path.c_str()))
						{
							if (!FileExists (favorite.Path.c_str()))
								continue;
						}
						else if (favorite.VolumePathId.empty())
							continue;

						bool mountedAndNotDisconnected = false;
						foreach (FavoriteVolume mountedFavorite, FavoritesMountedOnArrivalStillConnected)
						{
							if (favorite.Path == mountedFavorite.Path)
							{
								mountedAndNotDisconnected = true;
								break;
							}
						}

						if (!mountedAndNotDisconnected)
						{
							FavoriteMountOnArrivalInProgress = TRUE;
							MountFavoriteVolumes (FALSE, FALSE, FALSE, favorite);
							FavoriteMountOnArrivalInProgress = FALSE;

							FavoritesMountedOnArrivalStillConnected.push_back (favorite);
						}
					}

					bool deleted;
					for (list <FavoriteVolume>::iterator favorite = FavoritesMountedOnArrivalStillConnected.begin();
						favorite != FavoritesMountedOnArrivalStillConnected.end();
						deleted ? favorite : ++favorite)
					{
						deleted = false;

						if (IsMountedVolume (favorite->Path.c_str()))
							continue;

						if (!IsVolumeDeviceHosted (favorite->Path.c_str()))
						{
							if (FileExists (favorite->Path.c_str()))
								continue;
						}

						char volDevPath[TC_MAX_PATH];
						if (favorite->VolumePathId.size() > 5
							&& QueryDosDevice (favorite->VolumePathId.substr (4, favorite->VolumePathId.size() - 5).c_str(), volDevPath, TC_MAX_PATH) != 0)
						{
							continue;
						}

						favorite = FavoritesMountedOnArrivalStillConnected.erase (favorite);
						deleted = true;
					}

					reentry = false;
				}
			}

			// Exit background process in non-install mode or if no volume mounted
			// and no other instance active
			if (LastKnownMountList.ulMountedDrives == 0
				&& MainWindowHidden
#ifndef _DEBUG
				&& (bCloseBkgTaskWhenNoVolumes || IsNonInstallMode ()) 
				&& !SysEncDeviceActive (TRUE)
#endif
				&& GetDriverRefCount () < 2)
			{
				TaskBarIconRemove (hwndDlg);
				EndMainDlg (hwndDlg);
			}
		}
		return 1;

	case TC_APPMSG_TASKBAR_ICON:
		{
			switch (lParam)
			{
			case WM_LBUTTONDOWN:
				SetForegroundWindow (hwndDlg);
				MainWindowHidden = FALSE;
				ShowWindow (hwndDlg, SW_SHOW);
				ShowWindow (hwndDlg, SW_RESTORE);
				return 1;

			case WM_RBUTTONUP:
				{
					POINT pos;
					HMENU popup = CreatePopupMenu ();
					int sel, i, n;
					
					if (MainWindowHidden)
					{
						AppendMenuW (popup, MF_STRING, IDM_SHOW_HIDE, GetString ("SHOW_TC"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
					}
					else if (bEnableBkgTask
						&& (!(LastKnownMountList.ulMountedDrives == 0
						&& (bCloseBkgTaskWhenNoVolumes || IsNonInstallMode ()) 
						&& !SysEncDeviceActive (TRUE)
						&& GetDriverRefCount () < 2)))
					{
						AppendMenuW (popup, MF_STRING, IDM_SHOW_HIDE, GetString ("HIDE_TC"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
					}
					AppendMenuW (popup, MF_STRING, IDM_MOUNTALL, GetString ("IDC_MOUNTALL"));
					AppendMenuW (popup, MF_STRING, IDM_MOUNT_FAVORITE_VOLUMES, GetString ("IDM_MOUNT_FAVORITE_VOLUMES"));
					AppendMenuW (popup, MF_STRING, IDM_UNMOUNTALL, GetString ("IDC_UNMOUNTALL"));
					AppendMenu (popup, MF_SEPARATOR, 0, "");

					for (n = 0; n < 2; n++)
					{
						for (i = 0; i < 26; i++)
						{
							if (LastKnownMountList.ulMountedDrives & (1 << i))
							{
								wchar_t s[1024];
								wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[i];

								if (wcsstr (vol, L"\\??\\")) vol += 4;

								wstring label = GetFavoriteVolumeLabel (WideToSingleString (vol));

								StringCbPrintfW (s, sizeof(s), L"%s %c: (%s)",
									GetString (n==0 ? "OPEN" : "DISMOUNT"),
									i + L'A', 
									label.empty() ? vol : label.c_str());
								AppendMenuW (popup, MF_STRING, n*26 + TRAYICON_MENU_DRIVE_OFFSET + i, s);
							}
						}
						if (LastKnownMountList.ulMountedDrives != 0)
							AppendMenu (popup, MF_SEPARATOR, 0, "");
					}

					AppendMenuW (popup, MF_STRING, IDM_HELP, GetString ("MENU_HELP"));
					AppendMenuW (popup, MF_STRING, IDM_HOMEPAGE_SYSTRAY, GetString ("HOMEPAGE"));
					AppendMenuW (popup, MF_STRING, IDM_PREFERENCES, GetString ("IDM_PREFERENCES"));
					AppendMenuW (popup, MF_STRING, IDM_ABOUT, GetString ("IDM_ABOUT"));
					AppendMenu (popup, MF_SEPARATOR, 0, "");
					AppendMenuW (popup, MF_STRING, IDCANCEL, GetString ("EXIT"));

					GetCursorPos (&pos);

					SetForegroundWindow(hwndDlg);

					sel = TrackPopupMenu (popup,
						TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
						pos.x,
						pos.y,
						0,
						hwndDlg,
						NULL);

					if (sel >= TRAYICON_MENU_DRIVE_OFFSET && sel < TRAYICON_MENU_DRIVE_OFFSET + 26)
					{
						OpenVolumeExplorerWindow (sel - TRAYICON_MENU_DRIVE_OFFSET);
					}
					else if (sel >= TRAYICON_MENU_DRIVE_OFFSET + 26 && sel < TRAYICON_MENU_DRIVE_OFFSET + 26*2)
					{
						if (CheckMountList ())
						{
							if (Dismount (hwndDlg, sel - TRAYICON_MENU_DRIVE_OFFSET - 26))
							{
								wchar_t txt [2048];
								StringCbPrintfW (txt, sizeof(txt), GetString ("VOLUME_MOUNTED_AS_DRIVE_LETTER_X_DISMOUNTED"), sel - TRAYICON_MENU_DRIVE_OFFSET - 26 + L'A'); 

								InfoBalloonDirect (GetString ("SUCCESSFULLY_DISMOUNTED"), txt);
							}
						}
					}
					else if (sel == IDM_SHOW_HIDE)
					{
						ChangeMainWindowVisibility ();
					}
					else if (sel == IDM_HOMEPAGE_SYSTRAY)
					{
						Applink ("home", TRUE, "");
					}
					else if (sel == IDCANCEL)
					{
						if ((LastKnownMountList.ulMountedDrives == 0
							&& !SysEncDeviceActive (TRUE))
							|| AskWarnNoYes ("CONFIRM_EXIT") == IDYES)
						{
							// Close all other TC windows
							EnumWindows (CloseTCWindowsEnum, 0);

							TaskBarIconRemove (hwndDlg);
							SendMessage (hwndDlg, WM_COMMAND, sel, 0);
						}
					}
					else
					{
						SendMessage (hwndDlg, WM_COMMAND, sel, 0);
					}

					PostMessage(hwndDlg, WM_NULL, 0, 0);
					DestroyMenu (popup);
				}
				return 1;
			}
		}

		return 0;

	case TC_APPMSG_CLOSE_BKG_TASK:
		if (TaskBarIconMutex != NULL)
			TaskBarIconRemove (hwndDlg);

		return 1;

	case TC_APPMSG_SYSENC_CONFIG_UPDATE:
		LoadSysEncSettings (hwndDlg);

		// The wizard added VeraCrypt.exe to the system startup sequence or performed other operations that 
		// require us to update our cached settings.
		LoadSettings (hwndDlg);

		return 1;

	case WM_DEVICECHANGE:
		if (!IgnoreWmDeviceChange && wParam != DBT_DEVICEARRIVAL)
		{
			// Check if any host device has been removed and force dismount of volumes accordingly
			PDEV_BROADCAST_HDR hdr = (PDEV_BROADCAST_HDR) lParam;
			int m;

			GetMountList (&LastKnownMountList);

			if (wParam == DBT_DEVICEREMOVECOMPLETE && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
			{
				// File-hosted volumes
				PDEV_BROADCAST_VOLUME vol = (PDEV_BROADCAST_VOLUME) lParam;
				int i;

				for (i = 0; i < 26; i++)
				{
					if ((vol->dbcv_unitmask & (1 << i)) && !(GetLogicalDrives() & (1 << i)))
					{
						for (m = 0; m < 26; m++)
						{
							if (LastKnownMountList.ulMountedDrives & (1 << m))
							{
								wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[m];

								if (wcsstr (vol, L"\\??\\") == vol)
									vol += 4;

								if (vol[1] == L':' && i == (vol[0] - (vol[0] <= L'Z' ? L'A' : L'a')))
								{
									UnmountVolume (hwndDlg, m, TRUE);
									WarningBalloon ("HOST_DEVICE_REMOVAL_DISMOUNT_WARN_TITLE", "HOST_DEVICE_REMOVAL_DISMOUNT_WARN");
								}
							}
						}
					}
				}
			}

			// Device-hosted volumes
			for (m = 0; m < 26; m++)
			{
				if (LastKnownMountList.ulMountedDrives & (1 << m))
				{
					wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[m];
					char volp[MAX_PATH];

					if (wcsstr (vol, L"\\??\\") == vol)
						vol += 4;

					StringCbPrintfA (volp, sizeof(volp), "%ls", vol);

					if (IsVolumeDeviceHosted (volp))
					{
						OPEN_TEST_STRUCT ots;

						if (!OpenDevice (volp, &ots, FALSE))
						{
							UnmountVolume (hwndDlg, m, TRUE);
							WarningBalloon ("HOST_DEVICE_REMOVAL_DISMOUNT_WARN_TITLE", "HOST_DEVICE_REMOVAL_DISMOUNT_WARN");
						}
					}
				}
			}

			// Favorite volumes
			UpdateDeviceHostedFavoriteVolumes();

			return 1;
		}
		return 0;

	case WM_NOTIFY:

		if(wParam == IDC_DRIVELIST)
		{
			if (((LPNMHDR) lParam)->code == NM_CUSTOMDRAW)
			{
				int width = ListView_GetColumnWidth (GetDlgItem (hwndDlg, IDC_DRIVELIST), 1);
				if (width != LastDriveListVolumeColumnWidth)
				{
					LastDriveListVolumeColumnWidth = width;
					LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);
				}
				return 0;
			}

			/* Single click within drive list */
			if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
			{
				nSelectedDriveIndex = ((LPNMLISTVIEW) lParam)->iItem;
				EnableDisableButtons (hwndDlg);
				return 1;
			}

			/* Double click within drive list */
			if (((LPNMHDR) lParam)->code == LVN_ITEMACTIVATE)
			{
				int state = GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), ((LPNMITEMACTIVATE)lParam)->iItem );
				nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;
				if (LOWORD(state) == TC_MLIST_ITEM_NONSYS_VOL || LOWORD(state) == TC_MLIST_ITEM_SYS_PARTITION)
				{
					// Open explorer window for mounted volume
					WaitCursor ();
					OpenVolumeExplorerWindow (HIWORD(state) - 'A');
					NormalCursor ();
				}
				else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == TC_MLIST_ITEM_FREE)
				{
					mountOptions = defaultMountOptions;
					bPrebootPasswordDlgMode = FALSE;

					if (GetAsyncKeyState (VK_CONTROL) < 0)
					{
						if (IDCANCEL == DialogBoxParamW (hInst, 
							MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
							(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
							return 1;

						if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
							KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile);
					}

					if (CheckMountList ())
						Mount (hwndDlg, 0, 0);
				}
				return 1;
			}

			/* Right click and drag&drop operations */

			switch (((NM_LISTVIEW *) lParam)->hdr.code)
			{
			case NM_RCLICK:
			case LVN_BEGINRDRAG:
				/* If the mouse was moving while the right mouse button is pressed, popup menu would
				not open, because drag&drop operation would be initiated. Therefore, we're handling
				RMB drag-and-drop operations as well. */
				{

					/* Drive list context menu */

					int menuItem;
					HMENU popup = CreatePopupMenu ();

					SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));

					switch (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))))
					{
					case TC_MLIST_ITEM_FREE:
					
						// No mounted volume at this drive letter

						AppendMenuW (popup, MF_STRING, IDM_MOUNT_VOLUME, GetString ("IDM_MOUNT_VOLUME"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
						AppendMenuW (popup, MF_STRING, IDPM_SELECT_FILE_AND_MOUNT, GetString ("SELECT_FILE_AND_MOUNT"));
						AppendMenuW (popup, MF_STRING, IDPM_SELECT_DEVICE_AND_MOUNT, GetString ("SELECT_DEVICE_AND_MOUNT"));
						break;

					case TC_MLIST_ITEM_NONSYS_VOL:

						// There's a mounted non-system volume at this drive letter

						AppendMenuW (popup, MF_STRING, IDM_UNMOUNT_VOLUME, GetString ("DISMOUNT"));
						AppendMenuW (popup, MF_STRING, IDPM_OPEN_VOLUME, GetString ("OPEN"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
						AppendMenuW (popup, MF_STRING, IDPM_CHECK_FILESYS, GetString ("IDPM_CHECK_FILESYS"));
						AppendMenuW (popup, MF_STRING, IDPM_REPAIR_FILESYS, GetString ("IDPM_REPAIR_FILESYS"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
						AppendMenuW (popup, MF_STRING, IDPM_ADD_TO_FAVORITES, GetString ("IDPM_ADD_TO_FAVORITES"));
						AppendMenuW (popup, MF_STRING, IDPM_ADD_TO_SYSTEM_FAVORITES, GetString ("IDPM_ADD_TO_SYSTEM_FAVORITES"));
						AppendMenu (popup, MF_SEPARATOR, 0, "");
						AppendMenuW (popup, MF_STRING, IDM_VOLUME_PROPERTIES, GetString ("IDPM_PROPERTIES"));
						break;

					case TC_MLIST_ITEM_SYS_PARTITION:
					case TC_MLIST_ITEM_SYS_DRIVE:

						// System partition/drive

						PopulateSysEncContextMenu (popup, FALSE);
						break;
					}

					mPos=GetMessagePos();

					menuItem = TrackPopupMenu (popup,
						TPM_RETURNCMD | TPM_LEFTBUTTON,
						GET_X_LPARAM(mPos),
						GET_Y_LPARAM(mPos),
						0,
						hwndDlg,
						NULL);

					DestroyMenu (popup);

					switch (menuItem)
					{
					case IDPM_SELECT_FILE_AND_MOUNT:
						if (SelectContainer (hwndDlg))
							MountSelectedVolume (hwndDlg, FALSE);
						break;

					case IDPM_SELECT_DEVICE_AND_MOUNT:
						if (SelectPartition (hwndDlg))
							MountSelectedVolume (hwndDlg, FALSE);
						break;

					case IDPM_CHECK_FILESYS:
					case IDPM_REPAIR_FILESYS:
						{
							LPARAM lLetter = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

							if (LOWORD (lLetter) != 0xffff)
								CheckFilesystem ((char) HIWORD (lLetter) - 'A', menuItem == IDPM_REPAIR_FILESYS);
						}
						break;

					case IDM_UNMOUNT_VOLUME:
						if (CheckMountList ())
							Dismount (hwndDlg, 0);
						break;

					case IDPM_OPEN_VOLUME:
						{
							int state = GetItemLong(GetDlgItem (hwndDlg, IDC_DRIVELIST), ((LPNMITEMACTIVATE)lParam)->iItem );
							nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;

							WaitCursor ();
							OpenVolumeExplorerWindow (HIWORD(state) - 'A');
							NormalCursor ();
						}
						break;

					case IDM_VOLUME_PROPERTIES:
						DialogBoxParamW (hInst, 
							MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), hwndDlg,
							(DLGPROC) VolumePropertiesDlgProc, (LPARAM) FALSE);
						break;

					case IDM_MOUNT_VOLUME:
						if (!VolumeSelected(hwndDlg))
						{
							Warning ("NO_VOLUME_SELECTED");
						}
						else
						{
							mountOptions = defaultMountOptions;
							bPrebootPasswordDlgMode = FALSE;

							if (CheckMountList ())
								Mount (hwndDlg, 0, 0);
						}
						break;

					case IDPM_ADD_TO_FAVORITES:
					case IDPM_ADD_TO_SYSTEM_FAVORITES:
						{
							LPARAM selectedDrive = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

							if (LOWORD (selectedDrive) == TC_MLIST_ITEM_NONSYS_VOL)
								AddMountedVolumeToFavorites (hwndDlg, HIWORD (selectedDrive) - 'A', menuItem == IDPM_ADD_TO_SYSTEM_FAVORITES);
						}
						break;

					default:
						SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
						break;
					}
					return 1;
				}
			}
		}
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

		if (lw == IDOK && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == TC_MLIST_ITEM_NONSYS_VOL
			|| lw == IDM_UNMOUNT_VOLUME)
		{
			if (lw == IDM_UNMOUNT_VOLUME && LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) != TC_MLIST_ITEM_NONSYS_VOL)
			{
				Warning ("SELECT_A_MOUNTED_VOLUME");
				return 1;
			}

			if (CheckMountList ())
				Dismount (hwndDlg, 0);
			return 1;
		}

		if ((lw == IDOK || lw == IDM_MOUNT_VOLUME || lw == IDM_MOUNT_VOLUME_OPTIONS || lw == IDC_MOUNTALL || lw == IDM_MOUNTALL) 
			&& LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == 0xffff)
		{
			MessageBoxW (hwndDlg, GetString ("SELECT_FREE_DRIVE"), L"VeraCrypt", MB_ICONEXCLAMATION);
			return 1;
		}

		if ((lw == IDOK || lw == IDM_MOUNT_VOLUME || lw == IDM_MOUNT_VOLUME_OPTIONS))
		{
			MountSelectedVolume (hwndDlg, lw == IDM_MOUNT_VOLUME_OPTIONS);
			return 1;
		}

		if (lw == IDC_UNMOUNTALL || lw == IDM_UNMOUNTALL)
		{
			if (DismountAll (hwndDlg, bForceUnmount, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY)
				&& lw == IDM_UNMOUNTALL)	// If initiated via the systray menu
			{
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "MOUNTED_VOLUMES_DISMOUNTED");
			}

			return 1;
		}

		if (lw == IDC_MOUNTALL || lw == IDM_MOUNTALL)
		{
			// If Shift key is down and the password cache isn't empty, bypass password prompt
			MountAllDevices (hwndDlg, !(GetAsyncKeyState (VK_SHIFT) < 0 && !IsPasswordCacheEmpty()));
			return 1;
		}
		
		if (lw == IDC_SELECT_FILE || lw == IDM_SELECT_FILE)
		{
			SelectContainer (hwndDlg);
			return 1;
		}

		if (lw == IDC_SELECT_DEVICE || lw == IDM_SELECT_DEVICE)
		{
			SelectPartition (hwndDlg);
			return 1;
		}

		// System Encryption menu
		switch (lw)
		{
		case IDM_ENCRYPT_SYSTEM_DEVICE:
			EncryptSystemDevice ();
			break;
		case IDM_PERMANENTLY_DECRYPT_SYS:
			DecryptSystemDevice ();
			break;
		case IDM_CREATE_HIDDEN_OS:
			CreateHiddenOS ();
			break;
		case IDM_SYSENC_RESUME:
			ResumeInterruptedSysEncProcess ();
			break;
		case IDM_SYSTEM_ENCRYPTION_STATUS:
			ShowSystemEncryptionStatus ();
			break;
		case IDM_CHANGE_SYS_PASSWORD:
			ChangeSysEncPassword (hwndDlg, FALSE);
			break;
		case IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO:
			ChangeSysEncPassword (hwndDlg, TRUE);
			break;
		case IDM_CREATE_RESCUE_DISK:
			CreateRescueDisk ();
			break;
		case IDM_VERIFY_RESCUE_DISK:
			VerifyRescueDisk ();
			break;
		case IDM_MOUNT_SYSENC_PART_WITHOUT_PBA:

			if (CheckSysEncMountWithoutPBA ("", FALSE))
			{
				mountOptions = defaultMountOptions;
				mountOptions.PartitionInInactiveSysEncScope = TRUE;
				bPrebootPasswordDlgMode = TRUE;

				if (CheckMountList ())
					Mount (hwndDlg, 0, 0);

				bPrebootPasswordDlgMode = FALSE;
			}
			break;
		}

		if (lw == IDC_VOLUME_TOOLS)
		{
			/* Volume Tools popup menu */

			int menuItem;
			char volPath[TC_MAX_PATH];		/* Volume to mount */
			HMENU popup = CreatePopupMenu ();
			RECT rect;

			if (ActiveSysEncDeviceSelected ())
			{
				PopulateSysEncContextMenu (popup, TRUE);
			}
			else
			{
				AppendMenuW (popup, MF_STRING, IDM_CHANGE_PASSWORD, GetString ("IDM_CHANGE_PASSWORD"));
				AppendMenuW (popup, MF_STRING, IDM_CHANGE_HEADER_KEY_DERIV_ALGO, GetString ("IDM_CHANGE_HEADER_KEY_DERIV_ALGO"));
				AppendMenu (popup, MF_SEPARATOR, 0, "");
				AppendMenuW (popup, MF_STRING, IDM_ADD_REMOVE_VOL_KEYFILES, GetString ("IDM_ADD_REMOVE_VOL_KEYFILES"));
				AppendMenuW (popup, MF_STRING, IDM_REMOVE_ALL_KEYFILES_FROM_VOL, GetString ("IDM_REMOVE_ALL_KEYFILES_FROM_VOL"));
				AppendMenu (popup, MF_SEPARATOR, 0, "");
				AppendMenuW (popup, MF_STRING, IDM_BACKUP_VOL_HEADER, GetString ("IDM_BACKUP_VOL_HEADER"));
				AppendMenuW (popup, MF_STRING, IDM_RESTORE_VOL_HEADER, GetString ("IDM_RESTORE_VOL_HEADER"));
			}

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
					Warning ("NO_VOLUME_SELECTED");
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
					Warning ("NO_VOLUME_SELECTED");
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
					Warning ("NO_VOLUME_SELECTED");
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
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					pwdChangeDlgMode = PCDM_REMOVE_ALL_KEYFILES_FROM_VOL;
					ChangePassword (hwndDlg);
				}
				break;

			case IDM_BACKUP_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

					WaitCursor ();

					if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (volPath))
						UacBackupVolumeHeader (hwndDlg, TRUE, volPath);
					else
						BackupVolumeHeader (hwndDlg, TRUE, volPath);

					NormalCursor ();
				}
				break;

			case IDM_RESTORE_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED");
				}
				else
				{
					GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

					WaitCursor ();

					if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (volPath))
						UacRestoreVolumeHeader (hwndDlg, volPath);
					else
						RestoreVolumeHeader (hwndDlg, volPath);

					NormalCursor ();
				}
				break;

			default:
				SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
				break;
			}
			return 1;
		}

		if (lw == IDM_CHANGE_PASSWORD)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				if (ActiveSysEncDeviceSelected ())
				{
					ChangeSysEncPassword (hwndDlg, FALSE);
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PASSWORD;
					ChangePassword (hwndDlg);
				}
			}
			return 1;
		}

		if (lw == IDM_CHANGE_HEADER_KEY_DERIV_ALGO)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				if (ActiveSysEncDeviceSelected ())
				{
					ChangeSysEncPassword (hwndDlg, TRUE);
				}
				else
				{
					pwdChangeDlgMode = PCDM_CHANGE_PKCS5_PRF;
					ChangePassword (hwndDlg);
				}
			}
			return 1;
		}

		if (lw == IDC_WIPE_CACHE || lw == IDM_WIPE_CACHE)
		{
			WipeCache (hwndDlg, FALSE);
			return 1;
		}

		if (lw == IDM_CLEAR_HISTORY)
		{
			ClearHistory (GetDlgItem (hwndDlg, IDC_VOLUME));
			EnableDisableButtons (hwndDlg);
			return 1;
		}

		if (lw == IDC_CREATE_VOLUME || lw == IDM_CREATE_VOLUME || lw == IDM_VOLUME_WIZARD)
		{
			LaunchVolCreationWizard (hwndDlg, "");
			return 1;
		}

		if (lw == IDM_ADD_REMOVE_VOL_KEYFILES)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				pwdChangeDlgMode = PCDM_ADD_REMOVE_VOL_KEYFILES;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_REMOVE_ALL_KEYFILES_FROM_VOL)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{		
				pwdChangeDlgMode = PCDM_REMOVE_ALL_KEYFILES_FROM_VOL;
				ChangePassword (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_MANAGE_TOKEN_KEYFILES)
		{
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_KEYFILES), hwndDlg, (DLGPROC) SecurityTokenKeyfileDlgProc, NULL);
			return 1;
		}

		if (lw == IDM_CLOSE_ALL_TOKEN_SESSIONS)
		{
			{
				WaitCursor();
				finally_do ({ NormalCursor(); });

				SecurityToken::CloseAllSessions();
			}

			InfoBalloon (NULL, "ALL_TOKEN_SESSIONS_CLOSED");

			return 1;
		}

		if (lw == IDM_KEYFILE_GENERATOR)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_KEYFILE_GENERATOR), hwndDlg,
				(DLGPROC) KeyfileGeneratorDlgProc, (LPARAM) 0);

				return 1;
		}

		if (lw == IDM_LICENSE)
		{
			TextInfoDialogBox (TC_TBXID_LEGAL_NOTICES);
			return 1;
		}
	
		if (lw == IDM_WEBSITE)
		{
			Applink ("website", TRUE, "");
			return 1;
		}
		else if (lw == IDM_HOMEPAGE)
		{
			Applink ("homepage", TRUE, "");
			return 1;
		}
		else if (lw == IDM_ONLINE_TUTORIAL)
		{
			Applink ("tutorial", TRUE, "");
			return 1;
		}
		else if (lw == IDM_ONLINE_HELP)
		{
			OpenOnlineHelp ();
			return 1;
		}
		else if (lw == IDM_FAQ)
		{
			Applink ("faq", TRUE, "");
			return 1;
		}
		else if (lw == IDM_TC_DOWNLOADS)
		{
			Applink ("downloads", TRUE, "");
			return 1;
		}
		else if (lw == IDM_NEWS)
		{
			Applink ("news", TRUE, "");
			return 1;
		}
		else if (lw == IDM_VERSION_HISTORY)
		{
			Applink ("history", TRUE, "");
			return 1;
		}
		else if (lw == IDM_ANALYZE_SYSTEM_CRASH)
		{
			if (!IsAdmin() && IsUacSupported())
				UacAnalyzeKernelMiniDump (hwndDlg);
			else
				AnalyzeKernelMiniDump (hwndDlg);

			return 1;
		}
		else if (lw == IDM_CONTACT)
		{
			Applink ("contact", FALSE, "");
			return 1;
		}

		if (lw == IDM_PREFERENCES)
		{
			if (IDOK == DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_PREFERENCES_DLG), hwndDlg,
				(DLGPROC) PreferencesDlgProc, (LPARAM) 0))
			{
				if (bEnableBkgTask)
				{
					TaskBarIconAdd (hwndDlg);
				}
				else
				{
					TaskBarIconRemove (hwndDlg);
					if (MainWindowHidden)
						EndMainDlg (hwndDlg);
				}
			}
			return 1;
		}

		if (lw == IDM_HOTKEY_SETTINGS)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_HOTKEYS_DLG), hwndDlg,
				(DLGPROC) HotkeysDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDM_PERFORMANCE_SETTINGS)
		{
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_PERFORMANCE_SETTINGS), hwndDlg, (DLGPROC) PerformanceSettingsDlgProc, 0);
			return 1;
		}

		if (lw == IDM_DEFAULT_KEYFILES)
		{
			KeyfileDefaultsDlg (hwndDlg);
			return 1;
		}

		if (lw == IDM_ADD_VOLUME_TO_FAVORITES || lw == IDM_ADD_VOLUME_TO_SYSTEM_FAVORITES)
		{
			LPARAM selectedDrive = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

			char volPathLower[TC_MAX_PATH];
			wchar_t volPathLowerW[TC_MAX_PATH];

			// volPathLower will contain the volume path (if any) from the input field below the drive list 
			GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPathLower, sizeof (volPathLower));

			if (LOWORD (selectedDrive) != TC_MLIST_ITEM_NONSYS_VOL
				&& !(VolumeSelected (hwndDlg) && IsMountedVolume (volPathLower)))
			{
				Warning ("SELECT_A_MOUNTED_VOLUME");

				return 1;
			}

			int driveNo;

			if (VolumeSelected (hwndDlg)
				&& IsMountedVolume (volPathLower))
			{
				if (LOWORD (selectedDrive) != TC_MLIST_ITEM_NONSYS_VOL)
				{
					driveNo = GetMountedVolumeDriveNo (volPathLower);
				}
				else
				{
					/* We need to resolve selection ambiguity. Two different mounted volumes are currently
					selected (one in the drive letter list and the other in the input field below the list). */

					VOLUME_PROPERTIES_STRUCT prop;
					DWORD dwResult;

					memset (&prop, 0, sizeof(prop));
					prop.driveNo = HIWORD (selectedDrive) - 'A';

					if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL) || dwResult == 0)
					{
						Warning ("SELECT_A_MOUNTED_VOLUME");
						return 1;
					}

					// volPathHigher will contain the volume path selected in the main drive list
					wstring volPathHigher (prop.wszVolume);

					ToSBCS (prop.wszVolume, sizeof(prop.wszVolume));
					StringCbCopyA ((char *) volPathLowerW, sizeof(volPathLowerW), volPathLower);
					ToUNICODE ((char *) volPathLowerW, sizeof(volPathLowerW));

					if (strcmp (((memcmp ((char *) prop.wszVolume, "\\??\\", 4) == 0) ? (char *) prop.wszVolume + 4 : (char *) prop.wszVolume), volPathLower) != 0)
					{
						// The path selected in the input field is different from the path to the volume selected
						// in the drive lettter list. We have to resolve possible ambiguity.

						wchar_t *tmp[] = {L"", L"", L"", L"", L"", 0};
						const int maxVolPathLen = 80;

						if (volPathHigher.length () > maxVolPathLen)
						{
							volPathHigher = wstring (L"...") + volPathHigher.substr (volPathHigher.length () - maxVolPathLen, maxVolPathLen);
						}

						wstring volPathLowerWStr (volPathLowerW);

						if (volPathLowerWStr.length () > maxVolPathLen)
						{
							volPathLowerWStr = wstring (L"...") + volPathLowerWStr.substr (volPathLowerWStr.length () - maxVolPathLen, maxVolPathLen);
						}

						tmp[1] = GetString ("AMBIGUOUS_VOL_SELECTION");
						tmp[2] = (wchar_t *) volPathHigher.c_str();
						tmp[3] = (wchar_t *) volPathLowerWStr.c_str();
						tmp[4] = GetString ("IDCANCEL");

						switch (AskMultiChoice ((void **) tmp, FALSE))
						{
						case 1:
							driveNo = HIWORD (selectedDrive) - 'A';
							break;

						case 2:
							driveNo = GetMountedVolumeDriveNo (volPathLower);
							break;

						default:
							return 1;
						}
					}
					else
					{
						driveNo = HIWORD (selectedDrive) - 'A';
					}
				}
			}
			else
			{
				driveNo = HIWORD (selectedDrive) - 'A';
			}

			AddMountedVolumeToFavorites (hwndDlg, driveNo, lw == IDM_ADD_VOLUME_TO_SYSTEM_FAVORITES);

			return 1;
		}

		if (lw == IDM_ORGANIZE_FAVORITES || lw == IDM_ORGANIZE_SYSTEM_FAVORITES)
		{
			OrganizeFavoriteVolumes (hwndDlg, lw == IDM_ORGANIZE_SYSTEM_FAVORITES);
			return 1;
		}

		if (lw == IDM_TOKEN_PREFERENCES)
		{
			SecurityTokenPreferencesDialog (hwndDlg);
			return 1;
		}

		if (lw == IDM_SYSENC_SETTINGS || lw == IDM_SYS_ENC_SETTINGS)
		{
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_SETTINGS), hwndDlg, (DLGPROC) BootLoaderPreferencesDlgProc, 0);
			return 1;
		}

		if (lw == IDM_SYS_FAVORITES_SETTINGS)
		{
			OrganizeFavoriteVolumes (hwndDlg, true);
			return 1;
		}

		if (lw == IDM_BENCHMARK)
		{
			Benchmark (hwndDlg);
			return 1;
		}

		if (lw == IDM_TRAVELER)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_TRAVELER_DLG), hwndDlg,
				(DLGPROC) TravelerDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDM_BACKUP_VOL_HEADER)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				char volPath[TC_MAX_PATH];		/* Volume to mount */

				GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

				WaitCursor ();

				if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (volPath))
					UacBackupVolumeHeader (hwndDlg, TRUE, volPath);
				else
					BackupVolumeHeader (hwndDlg, TRUE, volPath);

				NormalCursor ();
			}
			return 1;
		}

		if (lw == IDM_RESTORE_VOL_HEADER)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED");
			}
			else
			{
				char volPath[TC_MAX_PATH];		/* Volume to mount */

				GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), volPath, sizeof (volPath));

				WaitCursor ();

				if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (volPath))
					UacRestoreVolumeHeader (hwndDlg, volPath);
				else
					RestoreVolumeHeader (hwndDlg, volPath);

				NormalCursor ();
			}
			return 1;
		}

		if (lw == IDM_LANGUAGE)
		{
			BOOL p;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), hwndDlg,
				(DLGPROC) LanguageDlgProc, (LPARAM) 0) == IDOK)
			{
				LoadLanguageFile ();
				SaveSettings (hwndDlg);

				p = LocalizationActive;
				LocalizationActive = TRUE;
				InitMainDialog (hwndDlg);
				InvalidateRect (hwndDlg, NULL, FALSE);
				LocalizationActive = p;
				DrawMenuBar (hwndDlg);
			}
			return 1;
		}

		if (lw == IDM_TEST_VECTORS)
		{
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_TEST_DLG), hwndDlg, (DLGPROC) CipherTestDialogProc, (LPARAM) 1);
			return 1;
		}

		if (lw == IDM_REFRESH_DRIVE_LETTERS)
		{
			DWORD driveMap = GetLogicalDrives ();
			
			WaitCursor ();

			if (!(nCurrentOS == WIN_2000 && RemoteSession))
			{
				BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, ~driveMap);
				Sleep (100);
				BroadcastDeviceChange (DBT_DEVICEARRIVAL, 0, driveMap);
			}

			LoadDriveLetters (GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

			if (nSelectedDriveIndex >= 0)
			{
				SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST),
					(char) HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), nSelectedDriveIndex)));
			}

			NormalCursor ();
			return 1;
		}

		if (lw == IDM_MOUNT_FAVORITE_VOLUMES)
		{
			MountFavoriteVolumes();
			return 1;
		}

		if (lw == IDM_RESUME_INTERRUPTED_PROC)
		{
			ResumeInterruptedNonSysInplaceEncProcess ();
			return 1;
		}

		if (lw == IDC_VOLUME_PROPERTIES || lw == IDM_VOLUME_PROPERTIES)
		{
			DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), hwndDlg,
				(DLGPROC) VolumePropertiesDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_EDITCHANGE)
		{
			EnableDisableButtons (hwndDlg);
			return 1;
		}

		if (lw == IDC_VOLUME && hw == CBN_SELCHANGE)
		{
			UpdateComboOrder (GetDlgItem (hwndDlg, IDC_VOLUME));
			MoveEditToCombo ((HWND) lParam, bHistory);
			PostMessage (hwndDlg, TC_APPMSG_MOUNT_ENABLE_DISABLE_CONTROLS, 0, 0);
			return 1;
		}

		if (lw == IDC_NO_HISTORY)
		{
			if (!(bHistory = !IsButtonChecked (GetDlgItem (hwndDlg, IDC_NO_HISTORY))))
				ClearHistory (GetDlgItem (hwndDlg, IDC_VOLUME));

			return 1;
		}

		if (lw >= TC_FAVORITE_MENU_CMD_ID_OFFSET && lw < TC_FAVORITE_MENU_CMD_ID_OFFSET_END)
		{
			size_t favoriteIndex = lw - TC_FAVORITE_MENU_CMD_ID_OFFSET;

			if (favoriteIndex < FavoriteVolumes.size())
			{
				if (IsMountedVolume (FavoriteVolumes[favoriteIndex].Path.c_str()))
				{
					WaitCursor();
					OpenVolumeExplorerWindow (GetMountedVolumeDriveNo ((char *) FavoriteVolumes[favoriteIndex].Path.c_str()));
					NormalCursor();
				}
				else
					MountFavoriteVolumes (FALSE, FALSE, FALSE, FavoriteVolumes[favoriteIndex]);
			}

			return 1;
		}

		return 0;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			DragQueryFile (hdrop, 0, szFileName, sizeof szFileName);
			DragFinish (hdrop);

			AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
			EnableDisableButtons (hwndDlg);
			SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
		}
		return 1;

	case TC_APPMSG_MOUNT_ENABLE_DISABLE_CONTROLS:
		EnableDisableButtons (hwndDlg);
		return 1;

	case TC_APPMSG_MOUNT_SHOW_WINDOW:
		MainWindowHidden = FALSE;
		ShowWindow (hwndDlg, SW_SHOW);
		ShowWindow (hwndDlg, SW_RESTORE);
		return 1;

	case WM_COPYDATA:
		{
			PCOPYDATASTRUCT cd = (PCOPYDATASTRUCT)lParam;
			if (memcmp (&cd->dwData, WM_COPY_SET_VOLUME_NAME, 4) == 0)
			{
				if (cd->cbData > 0)
				{
					((char *) cd->lpData)[cd->cbData - 1] = 0;
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), (char *)cd->lpData, bHistory);
				}

				EnableDisableButtons (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
			}
		}
		return 1;

	case WM_CLOSE:
		EndMainDlg (hwndDlg);
		return 1;

	default:
		// Recreate tray icon if Explorer restarted
		if (taskBarCreatedMsg != 0 && uMsg == taskBarCreatedMsg && TaskBarIconMutex != NULL)
		{
			TaskBarIconRemove (hwndDlg);
			TaskBarIconAdd (hwndDlg);
			return 1;
		}
	}

	return 0;
}

void ExtractCommandLine (HWND hwndDlg, char *lpszCommandLine)
{
	char **lpszCommandLineArgs = NULL;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */
	char tmpPath[MAX_PATH * 2];

	/* Defaults */
	mountOptions.PreserveTimestamp = TRUE;
	
	if (_stricmp (lpszCommandLine, "-Embedding") == 0)
	{
		ComServerMode = TRUE;
		return;
	}

	/* Extract command line arguments */
	NoCmdLineArgs = nNoCommandLineArgs = Win32CommandLine (lpszCommandLine, &lpszCommandLineArgs);

	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			enum
			{
				OptionAuto,
				OptionBeep,
				OptionCache,
				CommandDismount,
				OptionExplore,
				OptionForce,
				CommandHelp,
				OptionHistory,
				OptionKeyfile,
				OptionLetter,
				OptionMountOption,
				OptionPassword,
				OptionQuit,
				OptionSilent,
				OptionTokenLib,
				OptionVolume,
				CommandWipeCache
			};

			argument args[]=
			{
				{ OptionAuto,					"/auto",			"/a", FALSE },
				{ OptionBeep,					"/beep",			"/b", FALSE },
				{ OptionCache,					"/cache",			"/c", FALSE },
				{ CommandDismount,				"/dismount",		"/d", FALSE },
				{ OptionExplore,				"/explore",			"/e", FALSE },
				{ OptionForce,					"/force",			"/f", FALSE },
				{ CommandHelp,					"/help",			"/?", FALSE },
				{ OptionHistory,				"/history",			"/h", FALSE },
				{ OptionKeyfile,				"/keyfile",			"/k", FALSE },
				{ OptionLetter,					"/letter",			"/l", FALSE },
				{ OptionMountOption,			"/mountoption",		"/m", FALSE },
				{ OptionPassword,				"/password",		"/p", FALSE },
				{ OptionQuit,					"/quit",			"/q", FALSE },
				{ OptionSilent,					"/silent",			"/s", FALSE },
				{ OptionTokenLib,				"/tokenlib",		NULL, FALSE },
				{ OptionVolume,					"/volume",			"/v", FALSE },
				{ CommandWipeCache,				"/wipecache",		"/w", FALSE }
			};

			argumentspec as;

			int nArgPos;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);
			
			switch (GetArgumentID (&as, lpszCommandLineArgs[i], &nArgPos))
			{
			case OptionAuto:
				{
					char szTmp[32];
					bAuto = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "devices"))
							bAutoMountDevices = TRUE;
						else if (!_stricmp (szTmp, "favorites"))
							bAutoMountFavorites = TRUE;
						else if (!_stricmp (szTmp, "logon"))
							LogOn = TRUE;
					}
				}
				break;

			case OptionBeep:
				bBeep = TRUE;
				break;

			case OptionCache:
				{
					char szTmp[8];
					bCacheInDriver = TRUE;

					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));

					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
						bCacheInDriver = FALSE;
				}
				break;

			case CommandDismount:

				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
				     szDriveLetter, sizeof (szDriveLetter)))
					cmdUnmountDrive = toupper(szDriveLetter[0]) - 'A';
				else 
					cmdUnmountDrive = -1;

				break;

			case OptionExplore:
				bExplore = TRUE;
				break;

			case OptionForce:
				bForceMount = TRUE;
				bForceUnmount = TRUE;
				break;

			case OptionKeyfile:
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
					nNoCommandLineArgs, tmpPath, sizeof (tmpPath)))
				{
					KeyFile *kf;
					RelativePath2Absolute (tmpPath);
					kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						StringCbCopyA (kf->FileName, sizeof(kf->FileName), tmpPath);
						FirstCmdKeyFile = KeyFileAdd (FirstCmdKeyFile, kf);
					}
				}
				break;

			case OptionLetter:
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
					szDriveLetter, sizeof (szDriveLetter));
				commandLineDrive = *szDriveLetter = (char) toupper (*szDriveLetter);

				if (commandLineDrive < 'C' || commandLineDrive > 'Z')
					AbortProcess ("BAD_DRIVE_LETTER");

				break;

			case OptionHistory:
				{
					char szTmp[8];
					bHistory = bHistoryCmdLine = TRUE;

					GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     szTmp, sizeof (szTmp));

					if (!_stricmp(szTmp,"n") || !_stricmp(szTmp,"no"))
						bHistory = FALSE;
				}
				break;

			case OptionMountOption:
				{
					char szTmp[16];
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "ro") || !_stricmp (szTmp, "readonly"))
							mountOptions.ReadOnly = TRUE;

						if (!_stricmp (szTmp, "rm") || !_stricmp (szTmp, "removable"))
							mountOptions.Removable = TRUE;

						if (!_stricmp (szTmp, "ts") || !_stricmp (szTmp, "timestamp"))
							mountOptions.PreserveTimestamp = FALSE;

						if (!_stricmp (szTmp, "sm") || !_stricmp (szTmp, "system"))
							mountOptions.PartitionInInactiveSysEncScope = bPrebootPasswordDlgMode = TRUE;
					
						if (!_stricmp (szTmp, "bk") || !_stricmp (szTmp, "headerbak"))
							mountOptions.UseBackupHeader = TRUE;

						if (!_stricmp (szTmp, "recovery"))
							mountOptions.RecoveryMode = TRUE;

						CmdMountOptions = mountOptions;
						CmdMountOptionsValid = TRUE;
					}
				}
				break;

			case OptionPassword:
				GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs,
						     (char *) CmdVolumePassword.Text, sizeof (CmdVolumePassword.Text));
				CmdVolumePassword.Length = strlen ((char *) CmdVolumePassword.Text);
				CmdVolumePasswordValid = TRUE;
				break;

			case OptionVolume:
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, nArgPos, &i,
								      nNoCommandLineArgs, szFileName, sizeof (szFileName)))
				{
					RelativePath2Absolute (szFileName);
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
					CmdLineVolumeSpecified = TRUE;
				}
				break;

			case OptionQuit:
				{
					char szTmp[32];

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						nArgPos, &i, nNoCommandLineArgs, szTmp, sizeof (szTmp)))
					{
						if (!_stricmp (szTmp, "UAC")) // Used to indicate non-install elevation
							break;

						if (!_stricmp (szTmp, "preferences"))
						{
							Quit = TRUE;
							UsePreferences = TRUE;
							break;
						}

						if (!_stricmp (szTmp, "background"))
							bEnableBkgTask = TRUE;
					}

					Quit = TRUE;
					UsePreferences = FALSE;
				}
				break;

			case OptionSilent:
				Silent = TRUE;
				break;

			case OptionTokenLib:
				if (GetArgumentValue (lpszCommandLineArgs, nArgPos, &i, nNoCommandLineArgs, SecurityTokenLibraryPath, sizeof (SecurityTokenLibraryPath)) == HAS_ARGUMENT)
					InitSecurityTokenLibrary();
				else
					Error ("COMMAND_LINE_ERROR");

				break;

			case CommandWipeCache:
				bWipe = TRUE;
				break;

			case CommandHelp:
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);
				exit(0);
				break;

				// no option = file name
			default:
				{
					strcpy_s (szFileName, array_capacity (szFileName), lpszCommandLineArgs[i]);
					RelativePath2Absolute (szFileName);

					if (nNoCommandLineArgs == 1)
						CmdLineVolumeSpecified = TRUE;
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
				}
			}
		}
	}

	/* Free up the command line arguments */
	while (--nNoCommandLineArgs >= 0)
	{
		free (lpszCommandLineArgs[nNoCommandLineArgs]);
	}

	if (lpszCommandLineArgs)
		free (lpszCommandLineArgs);
}


static SERVICE_STATUS SystemFavoritesServiceStatus;
static SERVICE_STATUS_HANDLE SystemFavoritesServiceStatusHandle;


static void SystemFavoritesServiceLogError (const string &errorMessage)
{ 
	HANDLE eventSource = RegisterEventSource (NULL, TC_SYSTEM_FAVORITES_SERVICE_NAME);

	if (eventSource)
	{
		LPCTSTR strings[] = { TC_SYSTEM_FAVORITES_SERVICE_NAME, errorMessage.c_str() };
		ReportEvent (eventSource, EVENTLOG_ERROR_TYPE, 0, 0xC0000001, NULL, array_capacity (strings), 0, strings, NULL);

		DeregisterEventSource (eventSource);
	}
}


static void SystemFavoritesServiceSetStatus (DWORD status, DWORD waitHint = 0)
{
	SystemFavoritesServiceStatus.dwCurrentState = status;
	SystemFavoritesServiceStatus.dwWaitHint = waitHint;
	SystemFavoritesServiceStatus.dwWin32ExitCode = NO_ERROR;

	SetServiceStatus (SystemFavoritesServiceStatusHandle, &SystemFavoritesServiceStatus);
}


static VOID WINAPI SystemFavoritesServiceCtrlHandler (DWORD control)
{
	if (control == SERVICE_CONTROL_STOP) 
		SystemFavoritesServiceSetStatus (SERVICE_STOP_PENDING);
	else
		SystemFavoritesServiceSetStatus (SystemFavoritesServiceStatus.dwCurrentState);
}


static VOID WINAPI SystemFavoritesServiceMain (DWORD argc, LPTSTR *argv)
{
	memset (&SystemFavoritesServiceStatus, 0, sizeof (SystemFavoritesServiceStatus));
	SystemFavoritesServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

	SystemFavoritesServiceStatusHandle = RegisterServiceCtrlHandler (TC_SYSTEM_FAVORITES_SERVICE_NAME, SystemFavoritesServiceCtrlHandler);
	if (!SystemFavoritesServiceStatusHandle)
		return;

	SystemFavoritesServiceSetStatus (SERVICE_START_PENDING, 60000);

	try
	{
		MountFavoriteVolumes (TRUE);
	}
	catch (...) { }

	SystemFavoritesServiceSetStatus (SERVICE_RUNNING);
	SystemFavoritesServiceSetStatus (SERVICE_STOPPED);
}


static BOOL StartSystemFavoritesService ()
{
	ServiceMode = TRUE;
	Silent = TRUE;
	DeviceChangeBroadcastDisabled = TRUE;

	InitOSVersionInfo();

	if (DriverAttach() != ERR_SUCCESS)
		return FALSE;

	SERVICE_TABLE_ENTRY serviceTable[2];
	serviceTable[0].lpServiceName = TC_SYSTEM_FAVORITES_SERVICE_NAME;
	serviceTable[0].lpServiceProc = SystemFavoritesServiceMain;

	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;

	BOOL result = StartServiceCtrlDispatcher (serviceTable);

	if (!(ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD))
		WipeCache (NULL, TRUE);

	return result;
}


int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine, int nCmdShow)
{
	int argc;
	LPWSTR *argv = CommandLineToArgvW (GetCommandLineW(), &argc);

	if (argv && argc == 2 && SingleStringToWide (TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION) == argv[1])
		return StartSystemFavoritesService() ? 0 : 1;

	int status;
	atexit (localcleanup);
	SetProcessShutdownParameters (0x100, 0);

	VirtualLock (&VolumePassword, sizeof (VolumePassword));
	VirtualLock (&CmdVolumePassword, sizeof (CmdVolumePassword));
	VirtualLock (&mountOptions, sizeof (mountOptions));
	VirtualLock (&defaultMountOptions, sizeof (defaultMountOptions));
	VirtualLock (&szFileName, sizeof(szFileName));

	try
	{
		BootEncObj = new BootEncryption (NULL);
	}
	catch (Exception &e)
	{
		e.Show (NULL);
	}

	if (BootEncObj == NULL)
		AbortProcess ("INIT_SYS_ENC");

	InitCommonControls ();
	InitApp (hInstance, lpszCommandLine);

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = L"VeraCrypt";

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL);
		else
			handleError (NULL, status);

		AbortProcess ("NODRIVER");
	}

	/* Create the main dialog box */
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_MOUNT_DLG), NULL, (DLGPROC) MainDialogProc,
			(LPARAM) lpszCommandLine);

	/* Terminate */
	return 0;
}


BOOL TaskBarIconAdd (HWND hwnd) 
{ 
	NOTIFYICONDATAW tnid; 

	ZeroMemory (&tnid, sizeof (tnid));

	// Only one icon may be created
	if (TaskBarIconMutex != NULL) return TRUE;

	TaskBarIconMutex = CreateMutex (NULL, TRUE, "VeraCryptTaskBarIcon");
	if (TaskBarIconMutex == NULL || GetLastError () == ERROR_ALREADY_EXISTS)
	{
		if (TaskBarIconMutex)
		{
			CloseHandle(TaskBarIconMutex);
			TaskBarIconMutex = NULL;
		}
		return FALSE;
	}

	tnid.cbSize = sizeof (NOTIFYICONDATAW); 
	tnid.hWnd = hwnd; 
	tnid.uID = IDI_TRUECRYPT_ICON; 
	tnid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP; 
	tnid.uCallbackMessage = TC_APPMSG_TASKBAR_ICON; 
	tnid.hIcon = (HICON) LoadImage (hInst, MAKEINTRESOURCE (IDI_TRUECRYPT_ICON), 
		IMAGE_ICON, 
		ScreenDPI >= 120 ? 0 : 16, 
		ScreenDPI >= 120 ? 0 : 16,
		(ScreenDPI >= 120 ? LR_DEFAULTSIZE : 0) 
		| LR_SHARED
		| (nCurrentOS != WIN_2000 ? LR_DEFAULTCOLOR : LR_VGACOLOR)); // Windows 2000 cannot display more than 16 fixed colors in notification tray

	StringCbCopyW (tnid.szTip, sizeof(tnid.szTip), L"VeraCrypt");

	return Shell_NotifyIconW (NIM_ADD, &tnid); 
}


BOOL TaskBarIconRemove (HWND hwnd) 
{ 
	if (TaskBarIconMutex != NULL)
	{
		NOTIFYICONDATA tnid; 
		BOOL res;

		ZeroMemory (&tnid, sizeof (tnid));
		tnid.cbSize = sizeof(NOTIFYICONDATA); 
		tnid.hWnd = hwnd; 
		tnid.uID = IDI_TRUECRYPT_ICON; 

		res = Shell_NotifyIcon (NIM_DELETE, &tnid);
		if (TaskBarIconMutex)
		{
			CloseHandle (TaskBarIconMutex);
			TaskBarIconMutex = NULL;
		}
		return res;
	}
	else
		return FALSE;
}


BOOL TaskBarIconChange (HWND hwnd, int iconId) 
{ 
	if (TaskBarIconMutex == NULL)
		return FALSE;

	NOTIFYICONDATA tnid; 

	ZeroMemory (&tnid, sizeof (tnid));

	tnid.cbSize = sizeof (tnid); 
	tnid.hWnd = hwnd; 
	tnid.uID = IDI_TRUECRYPT_ICON; 
	tnid.uFlags = NIF_ICON; 
	tnid.hIcon = (HICON) LoadImage (hInst, MAKEINTRESOURCE (iconId), 
		IMAGE_ICON, 
		ScreenDPI >= 120 ? 0 : 16, 
		ScreenDPI >= 120 ? 0 : 16,
		(ScreenDPI >= 120 ? LR_DEFAULTSIZE : 0) 
		| LR_SHARED
		| (nCurrentOS != WIN_2000 ? LR_DEFAULTCOLOR : LR_VGACOLOR)); // Windows 2000 cannot display more than 16 fixed colors in notification tray

	return Shell_NotifyIcon (NIM_MODIFY, &tnid); 
}


void DismountIdleVolumes ()
{
	static DWORD lastMinTickCount;
	static int InactivityTime[26];
	static unsigned __int64 LastRead[26], LastWritten[26];
	static int LastId[26];

	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;
	BOOL bResult;
	int i;

	if (GetTickCount() > lastMinTickCount && GetTickCount() - lastMinTickCount < 60 * 1000)
		return;
	
	lastMinTickCount = GetTickCount();

	for (i = 0; i < 26; i++)
	{
		if (LastKnownMountList.ulMountedDrives & (1 << i))
		{
			memset (&prop, 0, sizeof(prop));
			prop.driveNo = i;

			bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop,
				sizeof (prop), &prop, sizeof (prop), &dwResult, NULL);

			if (bResult)
			{
				if (LastRead[i] == prop.totalBytesRead 
					&& LastWritten[i] == prop.totalBytesWritten
					&& LastId[i] == prop.uniqueId)
				{
					if (++InactivityTime[i] >= MaxVolumeIdleTime)
					{
						BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, i, 0);

						if (bCloseDismountedWindows && CloseVolumeExplorerWindows (MainDlg, i))
							Sleep (250);

						if (DriverUnmountVolume (MainDlg, i, bForceAutoDismount) == 0)
						{
							InactivityTime[i] = 0;
							BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, i, 0);

							if (bWipeCacheOnAutoDismount)
							{
								DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
								SecurityToken::CloseAllSessions();
							}
						}
					}
				}
				else
				{
					InactivityTime[i] = 0;
					LastRead[i] = prop.totalBytesRead;
					LastWritten[i] = prop.totalBytesWritten;
					LastId[i] = prop.uniqueId;
				}
			}
		}
	}
}


BOOL MountFavoriteVolumes (BOOL systemFavorites, BOOL logOnMount, BOOL hotKeyMount, const FavoriteVolume &favoriteVolumeToMount)
{
	BOOL status = TRUE;
	BOOL lastbExplore;
	BOOL userForcedReadOnly = FALSE;

	mountOptions = defaultMountOptions;

	VolumePassword.Length = 0;
	MultipleMountOperationInProgress = (favoriteVolumeToMount.Path.empty() || FavoriteMountOnArrivalInProgress);

	vector <FavoriteVolume> favorites;

	if (systemFavorites)
	{
		try
		{
			LoadFavoriteVolumes (favorites, true);
		}
		catch (...)
		{
			return false;
		}
	}
	else if (!favoriteVolumeToMount.Path.empty())
		favorites.push_back (favoriteVolumeToMount);
	else
		favorites = FavoriteVolumes;

	foreach (const FavoriteVolume &favorite, favorites)
	{
		if (favorite.DisconnectedDevice
			|| (logOnMount && !favorite.MountOnLogOn)
			|| (hotKeyMount && favorite.DisableHotkeyMount))
		{
			continue;
		}

		int drive;
		drive = toupper (favorite.MountPoint[0]) - 'A';

		mountOptions.ReadOnly = favorite.ReadOnly || userForcedReadOnly;
		mountOptions.Removable = favorite.Removable;

		if (favorite.SystemEncryption)
		{
			mountOptions.PartitionInInactiveSysEncScope = TRUE;
			bPrebootPasswordDlgMode = TRUE;
		}
		else
		{
			mountOptions.PartitionInInactiveSysEncScope = FALSE;
			bPrebootPasswordDlgMode = FALSE;
		}

		if ((LastKnownMountList.ulMountedDrives & (1 << drive)) == 0)
		{
			MountVolumesAsSystemFavorite = systemFavorites;

			string mountPoint = (char) (drive + 'A') + string (":\\");
			char prevVolumeAtMountPoint[MAX_PATH] = { 0 };

			if (systemFavorites)
			{
				// Partitions of new drives are assigned free drive letters by Windows on boot. Make sure this does not prevent system favorite volumes
				// from being mounted. Each partition (using the same drive letter as a system favorite volume) is assigned another free drive letter.

				if (GetVolumeNameForVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint, sizeof (prevVolumeAtMountPoint)))
					DeleteVolumeMountPoint (mountPoint.c_str());
				else
					prevVolumeAtMountPoint[0] = 0;
			}

			lastbExplore = bExplore;

			bExplore = (BOOL) favorite.OpenExplorerWindow;

			if (!systemFavorites
				&& !logOnMount
				&& !hotKeyMount
				&& !favoriteVolumeToMount.Path.empty()
				&& GetAsyncKeyState (VK_CONTROL) < 0)
			{
				if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), MainDlg, MountOptionsDlgProc, (LPARAM) &mountOptions) == IDCANCEL)
				{
					status = FALSE;
					goto skipMount;
				}
			}

			BOOL prevReadOnly = mountOptions.ReadOnly;

			if (!Mount (MainDlg, drive, (char *) favorite.Path.c_str()))
				status = FALSE;

			if (status && mountOptions.ReadOnly != prevReadOnly)
				userForcedReadOnly = mountOptions.ReadOnly;

skipMount:
			bExplore = lastbExplore;

			if (systemFavorites && prevVolumeAtMountPoint[0])
			{
				if (status)
				{
					int freeDrive = GetFirstAvailableDrive();
					if (freeDrive != -1)
					{
						mountPoint[0] = (char) (freeDrive + 'A');
						SetVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint);
					}
				}
				else
					SetVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint);
			}

			LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), 0);

			MountVolumesAsSystemFavorite = FALSE;

			if (ServiceMode && LastMountedVolumeDirty)
			{
				DWORD bytesOut;
				DeviceIoControl (hDriver, TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY, NULL, 0, NULL, 0, &bytesOut, NULL);

				SystemFavoritesServiceLogError (string ("The filesystem of the volume mounted as ") + (char) (drive + 'A') + ": was not cleanly dismounted and needs to be checked for errors.");
			}
		}
		else if (!systemFavorites && !favoriteVolumeToMount.Path.empty())
			Error ("DRIVE_LETTER_UNAVAILABLE");
	}

	MultipleMountOperationInProgress = FALSE;
	burn (&VolumePassword, sizeof (VolumePassword));

	if (status && CloseSecurityTokenSessionsAfterMount)
		SecurityToken::CloseAllSessions();

	return status;
}


static void SaveDefaultKeyFilesParam (void)
{
	if (defaultKeyFilesParam.FirstKeyFile == NULL)
	{
		/* No keyfiles selected */ 
		remove (GetConfigPath (TC_APPD_FILENAME_DEFAULT_KEYFILES));
	}
	else
	{
		FILE *f;
		KeyFile *kf = FirstKeyFile;

		f = fopen (GetConfigPath (TC_APPD_FILENAME_DEFAULT_KEYFILES), "w");
		if (f == NULL)
		{
			handleWin32Error (MainDlg);
			return;
		}

		XmlWriteHeader (f);

		fputs ("\n\t<defaultkeyfiles>", f);

		while (kf != NULL)
		{
			char q[TC_MAX_PATH * 2];

			XmlQuoteText (kf->FileName, q, sizeof (q));
			fprintf (f, "\n\t\t<keyfile>%s</keyfile>", q); 

			kf = kf->Next;
		}

		fputs ("\n\t</defaultkeyfiles>", f); 

		XmlWriteFooter (f);

		CheckFileStreamWriteErrors (f, TC_APPD_FILENAME_DEFAULT_KEYFILES);
		fclose (f);
		return;
	}
}


static void KeyfileDefaultsDlg (HWND hwndDlg)
{
	KeyFilesDlgParam param;

	param.EnableKeyFiles = defaultKeyFilesParam.EnableKeyFiles;
	param.FirstKeyFile = defaultKeyFilesParam.FirstKeyFile;

	if (DialogBoxParamW (hInst,
		MAKEINTRESOURCEW (IDD_KEYFILES), hwndDlg,
		(DLGPROC) KeyFilesDlgProc, (LPARAM) &param) == IDOK)
	{
		if (!param.EnableKeyFiles || AskWarnYesNo ("CONFIRM_SAVE_DEFAULT_KEYFILES") == IDYES)
		{
			KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
			defaultKeyFilesParam.EnableKeyFiles = param.EnableKeyFiles;
			defaultKeyFilesParam.FirstKeyFile = param.FirstKeyFile;

			RestoreDefaultKeyFilesParam ();
			SaveDefaultKeyFilesParam ();
		}
	}
}


static void HandleHotKey (HWND hwndDlg, WPARAM wParam)
{
	DWORD dwResult;
	BOOL success = TRUE;

	switch (wParam)
	{
	case HK_AUTOMOUNT_DEVICES:
		MountAllDevices (hwndDlg, TRUE);
		break;

	case HK_DISMOUNT_ALL:
	case HK_DISMOUNT_ALL_AND_WIPE:

		if (wParam == HK_DISMOUNT_ALL_AND_WIPE)
			WipeCache (hwndDlg, TRUE);

		if (DismountAll (hwndDlg, FALSE, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY))
		{
			if (bDisplayBalloonOnSuccessfulHkDismount)
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", (wParam == HK_DISMOUNT_ALL_AND_WIPE ? "VOLUMES_DISMOUNTED_CACHE_WIPED" : "MOUNTED_VOLUMES_DISMOUNTED"));

			if (bPlaySoundOnSuccessfulHkDismount)
				MessageBeep (0xFFFFFFFF);
		}

		break;

	case HK_WIPE_CACHE:
		WipeCache (hwndDlg, FALSE);

		break;

	case HK_FORCE_DISMOUNT_ALL_AND_WIPE:
		success = DismountAll (hwndDlg, TRUE, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
		success &= DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
		if (success)
		{
			if (bDisplayBalloonOnSuccessfulHkDismount)
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "VOLUMES_DISMOUNTED_CACHE_WIPED");

			if (bPlaySoundOnSuccessfulHkDismount)
				MessageBeep (0xFFFFFFFF);
		}
		break;

	case HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT:
		success = DismountAll (hwndDlg, TRUE, FALSE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
		success &= DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
		if (success)
		{
			if (bDisplayBalloonOnSuccessfulHkDismount)
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "VOLUMES_DISMOUNTED_CACHE_WIPED");

			if (bPlaySoundOnSuccessfulHkDismount)
				MessageBeep (0xFFFFFFFF);
		}
		TaskBarIconRemove (hwndDlg);
		EndMainDlg (hwndDlg);
		break;

	case HK_MOUNT_FAVORITE_VOLUMES:
		MountFavoriteVolumes (FALSE, FALSE, TRUE);
		break;

	case HK_SHOW_HIDE_MAIN_WINDOW:
		ChangeMainWindowVisibility ();
		break;

	case HK_CLOSE_SECURITY_TOKEN_SESSIONS:
		SecurityToken::CloseAllSessions();

		InfoBalloon (NULL, "ALL_TOKEN_SESSIONS_CLOSED");

		break;
	}
}


void ChangeMainWindowVisibility ()
{
	MainWindowHidden = !MainWindowHidden;

	if (!MainWindowHidden)
		SetForegroundWindow (MainDlg);

	ShowWindow (MainDlg, !MainWindowHidden ? SW_SHOW : SW_HIDE);

	if (!MainWindowHidden)
		ShowWindow (MainDlg, SW_RESTORE);
}


int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, const char *lpszVolume)
{
	int nStatus = ERR_OS_ERROR;
	wchar_t szTmp[4096];
	int fBackup = -1;
	OpenVolumeContext volume;
	OpenVolumeContext hiddenVolume;
	Password hiddenVolPassword;
	byte temporaryKey[MASTER_KEYDATA_SIZE];
	byte originalK2[MASTER_KEYDATA_SIZE];

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus);
      return nStatus;
   }

	volume.VolumeIsOpen = FALSE;
	hiddenVolume.VolumeIsOpen = FALSE;

	switch (IsSystemDevicePath (lpszVolume, hwndDlg, TRUE))
	{
	case 1:
	case 2:
		if (AskErrNoYes ("BACKUP_HEADER_NOT_FOR_SYS_DEVICE") == IDYES)
			CreateRescueDisk ();

		return 0;
	}

	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST");
		goto ret;
	}

	if (!VolumePathExists (lpszVolume))
	{
		handleWin32Error (hwndDlg);
		goto ret;
	}

	Info ("EXTERNAL_VOL_HEADER_BAK_FIRST_INFO");


	WaitCursor();

	// Open both types of volumes
	for (int type = TC_VOLUME_TYPE_NORMAL; type <= TC_VOLUME_TYPE_HIDDEN; ++type)
	{
		OpenVolumeContext *askVol = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolume : &volume);
		Password *askPassword = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolPassword : &VolumePassword);

		while (TRUE)
		{
			if (!AskVolumePassword (hwndDlg, askPassword, type == TC_VOLUME_TYPE_HIDDEN ? "ENTER_HIDDEN_VOL_PASSWORD" : "ENTER_NORMAL_VOL_PASSWORD", FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}

			WaitCursor();

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (askPassword, FirstKeyFile);

			nStatus = OpenVolume (askVol, lpszVolume, askPassword, FALSE, bPreserveTimestamp, FALSE);

			NormalCursor();

			if (nStatus == ERR_SUCCESS)
			{
				if ((type == TC_VOLUME_TYPE_NORMAL && askVol->CryptoInfo->hiddenVolume)
					|| (type == TC_VOLUME_TYPE_HIDDEN && !askVol->CryptoInfo->hiddenVolume))
				{
					CloseVolume (askVol);
					handleError (hwndDlg, ERR_PASSWORD_WRONG);
					continue;
				}

				RandSetHashFunction (askVol->CryptoInfo->pkcs5);

				if (type == TC_VOLUME_TYPE_NORMAL)
				{
					// Ask the user if there is a hidden volume
					char *volTypeChoices[] = {0, "DOES_VOLUME_CONTAIN_HIDDEN", "VOLUME_CONTAINS_HIDDEN", "VOLUME_DOES_NOT_CONTAIN_HIDDEN", "IDCANCEL", 0};
					switch (AskMultiChoice ((void **) volTypeChoices, FALSE))
					{
					case 1:
						break;
					case 2:
						goto noHidden;

					default:
						nStatus = ERR_SUCCESS;
						goto ret;
					}
				}

				break;
			}

			if (nStatus != ERR_PASSWORD_WRONG)
				goto error;

			handleError (hwndDlg, nStatus);
		}
	}
noHidden:

	if (hiddenVolume.VolumeIsOpen && volume.CryptoInfo->LegacyVolume != hiddenVolume.CryptoInfo->LegacyVolume)
	{
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CONFIRM_VOL_HEADER_BAK"), lpszVolume);

	if (bRequireConfirmation 
		&& (MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONQUESTION|MB_DEFBUTTON1) == IDNO))
		goto ret;

	/* Select backup file */
	if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, TRUE, NULL))
		goto ret;

	/* Conceive the backup file */
	if ((fBackup = _open(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	// Backup headers

	byte backup[TC_VOLUME_HEADER_GROUP_SIZE];

	bool legacyVolume = volume.CryptoInfo->LegacyVolume ? true : false;
	int backupFileSize = legacyVolume ? TC_VOLUME_HEADER_SIZE_LEGACY * 2 : TC_VOLUME_HEADER_GROUP_SIZE;

	// Fill backup buffer with random data
	memcpy (originalK2, volume.CryptoInfo->k2, sizeof (volume.CryptoInfo->k2));

	if (Randinit() != ERR_SUCCESS)
	{
		nStatus = ERR_PARAMETER_INCORRECT; 
		goto error;
	}

	NormalCursor();
	UserEnrichRandomPool (hwndDlg);
	WaitCursor();

	// Temporary keys
	if (!RandgetBytes (temporaryKey, EAGetKeySize (volume.CryptoInfo->ea), TRUE)
		|| !RandgetBytes (volume.CryptoInfo->k2, sizeof (volume.CryptoInfo->k2), FALSE))
	{
		nStatus = ERR_PARAMETER_INCORRECT; 
		goto error;
	}

	if (EAInit (volume.CryptoInfo->ea, temporaryKey, volume.CryptoInfo->ks) != ERR_SUCCESS || !EAInitMode (volume.CryptoInfo))
	{
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	EncryptBuffer (backup, backupFileSize, volume.CryptoInfo);

	memcpy (volume.CryptoInfo->k2, originalK2, sizeof (volume.CryptoInfo->k2));
	if (EAInit (volume.CryptoInfo->ea, volume.CryptoInfo->master_keydata, volume.CryptoInfo->ks) != ERR_SUCCESS || !EAInitMode (volume.CryptoInfo))
	{
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	// Store header encrypted with a new key
	nStatus = ReEncryptVolumeHeader ((char *) backup, FALSE, volume.CryptoInfo, &VolumePassword, FALSE);
	if (nStatus != ERR_SUCCESS)
		goto error;

	if (hiddenVolume.VolumeIsOpen)
	{
		nStatus = ReEncryptVolumeHeader ((char *) backup + (legacyVolume ? TC_VOLUME_HEADER_SIZE_LEGACY : TC_VOLUME_HEADER_SIZE),
			 FALSE, hiddenVolume.CryptoInfo, &hiddenVolPassword, FALSE);

		if (nStatus != ERR_SUCCESS)
			goto error;
	}

	if (_write (fBackup, backup, backupFileSize) == -1)
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	/* Backup has been successfully created */
	Warning("VOL_HEADER_BACKED_UP");

ret:
	nStatus = ERR_SUCCESS;

error:
	DWORD dwError = GetLastError ();

	CloseVolume (&volume);
	CloseVolume (&hiddenVolume);

	if (fBackup != -1)
		_close (fBackup);

	SetLastError (dwError);
	if (nStatus != 0)
		handleError (hwndDlg, nStatus);

	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&hiddenVolPassword, sizeof (hiddenVolPassword));
	burn (temporaryKey, sizeof (temporaryKey));
	burn (originalK2, sizeof (originalK2));
	
	RestoreDefaultKeyFilesParam();
	RandStop (FALSE);
	NormalCursor();

	return nStatus;
}


int RestoreVolumeHeader (HWND hwndDlg, const char *lpszVolume)
{
	int nDosLinkCreated = -1, nStatus = ERR_OS_ERROR;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szFileName[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	BOOL bDevice;
	unsigned __int64 hostSize = 0;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	wchar_t szTmp[4096];
	BOOL bTimeStampValid = FALSE;
	HANDLE fBackup = INVALID_HANDLE_VALUE;
	LARGE_INTEGER headerOffset;
	CRYPTO_INFO *restoredCryptoInfo = NULL;

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus);
      return nStatus;
   }

	switch (IsSystemDevicePath (lpszVolume, hwndDlg, TRUE))
	{
	case 1:
	case 2:
		if (AskErrNoYes ("RESTORE_HEADER_NOT_FOR_SYS_DEVICE") == IDYES)
			CreateRescueDisk ();

		return 0;

	case -1:
		// In some environments (such as PE), the system volume is not located on a hard drive.
		// Therefore, we must interpret this return code as "Not a system device path" (otherwise,
		// it would not be possible to restore headers on non-system devices in such environments).
		// Note that this is rather safe, because bReliableRequired is set to TRUE.

		// NOP
		break;
	}

	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST");
		return 0;
	}

	if (!VolumePathExists (lpszVolume))
	{
		handleWin32Error (hwndDlg);
		return 0;
	}

	BOOL restoreInternalBackup;

	// Ask the user to select the type of backup (internal/external)
	char *volTypeChoices[] = {0, "HEADER_RESTORE_EXTERNAL_INTERNAL", "HEADER_RESTORE_INTERNAL", "HEADER_RESTORE_EXTERNAL", "IDCANCEL", 0};
	switch (AskMultiChoice ((void **) volTypeChoices, FALSE))
	{
	case 1:
		restoreInternalBackup = TRUE;
		break;
	case 2:
		restoreInternalBackup = FALSE;
		break;
	default:
		return 0;
	}

	OpenVolumeContext volume;
	volume.VolumeIsOpen = FALSE;

	WaitCursor();

	if (restoreInternalBackup)
	{
		// Restore header from the internal backup

		// Open the volume using backup header
		while (TRUE)
		{
			StringCbCopyA (PasswordDlgVolume, sizeof(PasswordDlgVolume), lpszVolume);
			if (!AskVolumePassword (hwndDlg, &VolumePassword, NULL, FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}

			WaitCursor();

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (&VolumePassword, FirstKeyFile);

			nStatus = OpenVolume (&volume, lpszVolume, &VolumePassword, TRUE, bPreserveTimestamp, TRUE);

			NormalCursor();

			if (nStatus == ERR_SUCCESS)
				break;

			if (nStatus != ERR_PASSWORD_WRONG)
				goto error;

			handleError (hwndDlg, nStatus);
		}

		if (volume.CryptoInfo->LegacyVolume)
		{
			Error ("VOLUME_HAS_NO_BACKUP_HEADER");
			nStatus = ERROR_SUCCESS;
			goto error;
		}

		// Create a new header with a new salt
		char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];

		nStatus = ReEncryptVolumeHeader (buffer, FALSE, volume.CryptoInfo, &VolumePassword, FALSE);
		if (nStatus != 0)
			goto error;

		headerOffset.QuadPart = volume.CryptoInfo->hiddenVolume ? TC_HIDDEN_VOLUME_HEADER_OFFSET : TC_VOLUME_HEADER_OFFSET;
		if (!SetFilePointerEx (volume.HostFileHandle, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (!WriteEffectiveVolumeHeader (volume.IsDevice, volume.HostFileHandle, (byte *) buffer))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}
	}
	else
	{
		// Restore header from an external backup
		
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CONFIRM_VOL_HEADER_RESTORE"), lpszVolume);

		if (MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2) == IDNO)
		{
			nStatus = ERR_SUCCESS;
			goto ret;
		}

		/* Select backup file */
		if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, FALSE, NULL))
		{
			nStatus = ERR_SUCCESS;
			goto ret;
		}

		/* Open the backup file */
		fBackup = CreateFile (szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (fBackup == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		// Determine size of the backup file
		LARGE_INTEGER backupSize;
		if (!GetFileSizeEx (fBackup, &backupSize))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), lpszVolume, &bDevice);

		if (bDevice == FALSE)
			StringCbCopyA (szCFDevice, sizeof(szCFDevice), szDiskFile);
		else
		{
			nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, sizeof(szDosDevice),szCFDevice, sizeof(szCFDevice),FALSE);
			if (nDosLinkCreated != 0)
				goto error;
		}

		// Open the volume
		dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		// Determine volume host size
		if (bDevice)
		{
			PARTITION_INFORMATION diskInfo;
			DWORD dwResult;
			BOOL bResult;

			bResult = GetPartitionInfo (lpszVolume, &diskInfo);

			if (bResult)
			{
				hostSize = diskInfo.PartitionLength.QuadPart;
			}
			else
			{
				DISK_GEOMETRY driveInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
					goto error;

				hostSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
					driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
			}

			if (hostSize == 0)
			{
				nStatus =  ERR_VOL_SIZE_WRONG;
				goto error;
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

		if (!bDevice && bPreserveTimestamp)
		{
			/* Remember the container modification/creation date and time. */

			if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
				bTimeStampValid = FALSE;
			else
				bTimeStampValid = TRUE;
		}

		/* Read the volume header from the backup file */
		char buffer[TC_VOLUME_HEADER_GROUP_SIZE];

		DWORD bytesRead;
		if (!ReadFile (fBackup, buffer, sizeof (buffer), &bytesRead, NULL))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (bytesRead != backupSize.QuadPart)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		LARGE_INTEGER headerOffset;
		LARGE_INTEGER headerBackupOffset;
		bool legacyBackup;
		int headerOffsetBackupFile;

		// Determine the format of the backup file
		switch (backupSize.QuadPart)
		{
		case TC_VOLUME_HEADER_GROUP_SIZE:
			legacyBackup = false;
			break;

		case TC_VOLUME_HEADER_SIZE_LEGACY * 2:
			legacyBackup = true;
			break;

		default:
			Error ("HEADER_BACKUP_SIZE_INCORRECT");
			nStatus = ERR_SUCCESS;
			goto error;
		}

		// Open the header
		while (TRUE)
		{
			if (!AskVolumePassword (hwndDlg, &VolumePassword, "ENTER_HEADER_BACKUP_PASSWORD", FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (&VolumePassword, FirstKeyFile);

			// Decrypt volume header
			headerOffsetBackupFile = 0;
			for (int type = TC_VOLUME_TYPE_NORMAL; type <= TC_VOLUME_TYPE_HIDDEN; ++type)
			{
				if (type == TC_VOLUME_TYPE_HIDDEN)
					headerOffsetBackupFile += (legacyBackup ? TC_VOLUME_HEADER_SIZE_LEGACY : TC_VOLUME_HEADER_SIZE);

				nStatus = ReadVolumeHeader (FALSE, buffer + headerOffsetBackupFile, &VolumePassword, &restoredCryptoInfo, NULL);
				if (nStatus == ERR_SUCCESS)
					break;
			}

			if (nStatus == ERR_SUCCESS)
				break;

			if (nStatus != ERR_PASSWORD_WRONG)
				goto error;

			handleError (hwndDlg, nStatus);
		}

		BOOL hiddenVol = restoredCryptoInfo->hiddenVolume;

		if (legacyBackup)
		{
			headerOffset.QuadPart = hiddenVol ? hostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY : TC_VOLUME_HEADER_OFFSET;
		}
		else
		{
			headerOffset.QuadPart = hiddenVol ? TC_HIDDEN_VOLUME_HEADER_OFFSET : TC_VOLUME_HEADER_OFFSET;
			headerBackupOffset.QuadPart = hiddenVol ? hostSize - TC_VOLUME_HEADER_SIZE : hostSize - TC_VOLUME_HEADER_GROUP_SIZE;
		}

		WaitCursor();

		// Restore header encrypted with a new key
		nStatus = ReEncryptVolumeHeader (buffer, FALSE, restoredCryptoInfo, &VolumePassword, FALSE);
		if (nStatus != ERR_SUCCESS)
			goto error;

		if (!SetFilePointerEx (dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (!WriteEffectiveVolumeHeader (bDevice, dev, (byte *) buffer))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (!restoredCryptoInfo->LegacyVolume)
		{
			// Restore backup header encrypted with a new key
			nStatus = ReEncryptVolumeHeader (buffer, FALSE, restoredCryptoInfo, &VolumePassword, FALSE);
			if (nStatus != ERR_SUCCESS)
				goto error;

			if (!SetFilePointerEx (dev, headerBackupOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (bDevice, dev, (byte *) buffer))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}


	/* Volume header has been successfully restored */

	Info("VOL_HEADER_RESTORED");
ret:
	nStatus = ERR_SUCCESS;

error:
	dwError = GetLastError ();
	NormalCursor();

	if (restoreInternalBackup)
	{
		CloseVolume (&volume);
	}
	else
	{
		if (restoredCryptoInfo)
			crypto_close (restoredCryptoInfo);

		if (bTimeStampValid)
			SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

		if (dev != INVALID_HANDLE_VALUE)
			CloseHandle (dev);

		if (fBackup != INVALID_HANDLE_VALUE)
			CloseHandle (fBackup);

		if (nDosLinkCreated == 0)
			RemoveFakeDosName (szDiskFile, szDosDevice);
	}

	SetLastError (dwError);
	if (nStatus != 0)
		handleError (hwndDlg, nStatus);

	burn (&VolumePassword, sizeof (VolumePassword));
	RestoreDefaultKeyFilesParam();
	RandStop (FALSE);
	NormalCursor();

	return nStatus;
}


void SetDriverConfigurationFlag (uint32 flag, BOOL state)
{
	BootEncObj->SetDriverConfigurationFlag (flag, state ? true : false);
}


static BOOL CALLBACK PerformanceSettingsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, "IDD_PERFORMANCE_SETTINGS");

			uint32 driverConfig = ReadDriverConfigurationFlags();
			CheckDlgButton (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION, (driverConfig & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? BST_UNCHECKED : BST_CHECKED);

			SYSTEM_INFO sysInfo;
			GetSystemInfo (&sysInfo);

			HWND freeCpuCombo = GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT);
			uint32 encryptionFreeCpuCount = ReadEncryptionThreadPoolFreeCpuCountLimit();

			if (encryptionFreeCpuCount > sysInfo.dwNumberOfProcessors - 1)
				encryptionFreeCpuCount = sysInfo.dwNumberOfProcessors - 1;

			for (uint32 i = 1; i < sysInfo.dwNumberOfProcessors; ++i)
			{
				stringstream s;
				s << i;
				AddComboPair (freeCpuCombo, s.str().c_str(), i);
			}

			if (sysInfo.dwNumberOfProcessors < 2 || encryptionFreeCpuCount == 0)
				EnableWindow (freeCpuCombo, FALSE);

			if (sysInfo.dwNumberOfProcessors < 2)
				EnableWindow (GetDlgItem (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL), FALSE);

			if (encryptionFreeCpuCount != 0)
			{
				CheckDlgButton (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL, BST_CHECKED);
				SendMessage (freeCpuCombo, CB_SETCURSEL, encryptionFreeCpuCount - 1, 0);
			}

			SetWindowTextW (GetDlgItem (hwndDlg, IDT_LIMIT_ENC_THREAD_POOL_NOTE), GetString("LIMIT_ENC_THREAD_POOL_NOTE"));

			SetDlgItemTextW (hwndDlg, IDC_HW_AES_SUPPORTED_BY_CPU, (wstring (L" ") + (GetString (is_aes_hw_cpu_supported() ? "UISTR_YES" : "UISTR_NO"))).c_str());

			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_HW_ACCELERATION);
			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_THREAD_BASED_PARALLELIZATION);
		}
		return 0;

	case WM_COMMAND:

		switch (lw)
		{
		case IDCANCEL:
			EndDialog (hwndDlg, lw);
			return 1;

		case IDOK:
			{
				if (IsNonInstallMode())
				{
					Error ("FEATURE_REQUIRES_INSTALLATION");
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				BOOL disableHW = !IsDlgButtonChecked (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION);

				try
				{
					try
					{
						BootEncStatus = BootEncObj->GetStatus();
					}
					catch (...)
					{
						BootEncStatus.DriveMounted = false;	
					}

					if (BootEncStatus.DriveMounted)
					{
						byte userConfig;
						string customUserMessage;
						uint16 bootLoaderVersion;

						BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig, &customUserMessage, &bootLoaderVersion);

						if (bootLoaderVersion != VERSION_NUM)
							Warning ("BOOT_LOADER_VERSION_INCORRECT_PREFERENCES");

						if (disableHW)
							userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_HW_ENCRYPTION;
						else
							userConfig &= ~TC_BOOT_USER_CFG_FLAG_DISABLE_HW_ENCRYPTION;

						BootEncObj->WriteBootSectorUserConfig (userConfig, customUserMessage);
					}

					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION, disableHW);

					DWORD bytesReturned;
					if (!DeviceIoControl (hDriver, TC_IOCTL_REREAD_DRIVER_CONFIG, NULL, 0, NULL, 0, &bytesReturned, NULL))
						handleWin32Error (hwndDlg);

					EnableHwEncryption (!disableHW);

					uint32 cpuFreeCount = 0;
					if (IsDlgButtonChecked (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL))
					{
						LRESULT cpuFreeItem = SendMessage (GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT), CB_GETCURSEL, 0, 0);
						if (cpuFreeItem != CB_ERR)
							cpuFreeCount = (uint32) (cpuFreeItem + 1);
					}

					if (ReadEncryptionThreadPoolFreeCpuCountLimit() != cpuFreeCount)
					{
						BootEncObj->WriteLocalMachineRegistryDwordValue ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, cpuFreeCount);
						Warning ("SETTING_REQUIRES_REBOOT");
					}

					EndDialog (hwndDlg, lw);
					return 1;
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}
			}
			return 1;

		case IDC_ENABLE_HARDWARE_ENCRYPTION:
			if (!IsDlgButtonChecked (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION)
				&& AskWarnYesNo ("CONFIRM_SETTING_DEGRADES_PERFORMANCE") == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION, BST_CHECKED);
			}
			return 1;

		case IDC_LIMIT_ENC_THREAD_POOL:
			if (IsDlgButtonChecked (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL)
				&& AskWarnYesNo ("CONFIRM_SETTING_DEGRADES_PERFORMANCE") == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL, BST_UNCHECKED);
			}
			else
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT), CB_SETCURSEL, 0, 0);
				Warning ("SETTING_REQUIRES_REBOOT");	// Warn the user before he thinks about benchmarking
			}

			EnableWindow (GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT), IsDlgButtonChecked (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL));
			return 1;

		case IDC_BENCHMARK:
			Benchmark (hwndDlg);
			return 1;

		case IDC_MORE_INFO_ON_HW_ACCELERATION:
			Applink ("hwacceleration", TRUE, "");
			return 1;

		case IDC_MORE_INFO_ON_THREAD_BASED_PARALLELIZATION:
			Applink ("parallelization", TRUE, "");
			return 1;
		}

		return 0;
	}

	return 0;
}


static BOOL CALLBACK SecurityTokenPreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		LocalizeDialog (hwndDlg, "IDD_TOKEN_PREFERENCES");
		SetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, SecurityTokenLibraryPath);
		CheckDlgButton (hwndDlg, IDC_CLOSE_TOKEN_SESSION_AFTER_MOUNT, CloseSecurityTokenSessionsAfterMount ? BST_CHECKED : BST_UNCHECKED);

		SetWindowTextW (GetDlgItem (hwndDlg, IDT_PKCS11_LIB_HELP), GetString("PKCS11_LIB_LOCATION_HELP"));

		return 0;

	case WM_COMMAND:

		switch (lw)
		{
		case IDCANCEL:
			EndDialog (hwndDlg, lw);
			return 1;

		case IDOK:
			{
				char securityTokenLibraryPath[MAX_PATH];
				GetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, securityTokenLibraryPath, sizeof (securityTokenLibraryPath));

				if (securityTokenLibraryPath[0] == 0)
				{
					try
					{
						SecurityToken::CloseLibrary();
					}
					catch (...) { }

					SecurityTokenLibraryPath[0] = 0;
				}
				else
				{
					char prevSecurityTokenLibraryPath[MAX_PATH];
					StringCbCopyA (prevSecurityTokenLibraryPath, sizeof(prevSecurityTokenLibraryPath), SecurityTokenLibraryPath);
					StringCbCopyA (SecurityTokenLibraryPath, sizeof(SecurityTokenLibraryPath), securityTokenLibraryPath);

					if (!InitSecurityTokenLibrary())
					{
						StringCbCopyA (SecurityTokenLibraryPath, sizeof(SecurityTokenLibraryPath), prevSecurityTokenLibraryPath);
						return 1;
					}
				}

				CloseSecurityTokenSessionsAfterMount = (IsDlgButtonChecked (hwndDlg, IDC_CLOSE_TOKEN_SESSION_AFTER_MOUNT) == BST_CHECKED);

				WaitCursor ();
				SaveSettings (hwndDlg);
				NormalCursor ();

				EndDialog (hwndDlg, lw);
				return 1;
			}

		case IDC_AUTO_DETECT_PKCS11_MODULE:
			{
				char systemDir[MAX_PATH];
				GetSystemDirectory (systemDir, sizeof (systemDir));
				WIN32_FIND_DATA findData;
				bool found = false;

				WaitCursor();

				HANDLE find = FindFirstFile ((string (systemDir) + "\\*.dll").c_str(), &findData);
				while (!found && find != INVALID_HANDLE_VALUE)
				{
					string dllPathname = string (systemDir) + "\\" + findData.cFileName;
					DWORD fileSize;

					char *file = LoadFile (dllPathname.c_str(), &fileSize);
					if (file)
					{
						const char *functionName = "C_GetFunctionList";
						size_t strLen = strlen (functionName);

						if (fileSize > strLen)
						{
							for (size_t i = 0; i < fileSize - strLen; ++i)
							{
								if (memcmp (file + i, functionName, strLen) == 0)
								{
									HMODULE module = LoadLibrary (dllPathname.c_str());
									if (module)
									{
										if (GetProcAddress (module, functionName))
										{
											SetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, dllPathname.c_str());
											found = true;

											FreeLibrary (module);
											break;
										}

										FreeLibrary (module);
									}
								}
							}
						}

						free (file);
					}

					if (!FindNextFile (find, &findData))
						break;
				}

				if (find != INVALID_HANDLE_VALUE)
					FindClose (find);

				NormalCursor();

				if (!found)
					Warning ("PKCS11_MODULE_AUTO_DETECTION_FAILED");

				return 1;
			}

		case IDC_SELECT_PKCS11_MODULE:
			{
				char securityTokenLibraryPath[MAX_PATH];
				char systemDir[MAX_PATH];
				wchar_t browseFilter[1024];

				Info ("SELECT_PKCS11_MODULE_HELP");

				StringCbPrintfW (browseFilter, sizeof(browseFilter), L"%ls (*.dll)%c*.dll%c%c", GetString ("DLL_FILES"), 0, 0, 0);
				GetSystemDirectory (systemDir, sizeof (systemDir));

				if (BrowseFilesInDir (hwndDlg, "SELECT_PKCS11_MODULE", systemDir, securityTokenLibraryPath, TRUE, FALSE, browseFilter))
					SetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, securityTokenLibraryPath);
				return 1;
			}
		}
		return 0;
	}

	return 0;
}


void SecurityTokenPreferencesDialog (HWND hwndDlg)
{
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_PREFERENCES), hwndDlg, (DLGPROC) SecurityTokenPreferencesDlgProc, 0);
}


static BOOL CALLBACK BootLoaderPreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			if (!BootEncObj->GetStatus().DriveMounted)
			{
				Warning ("SYS_DRIVE_NOT_ENCRYPTED");
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			try
			{
				LocalizeDialog (hwndDlg, "IDD_SYSENC_SETTINGS");

				uint32 driverConfig = ReadDriverConfigurationFlags();
				byte userConfig;
				string customUserMessage;
				uint16 bootLoaderVersion;

				BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig, &customUserMessage, &bootLoaderVersion);

				if (bootLoaderVersion != VERSION_NUM)
					Warning ("BOOT_LOADER_VERSION_INCORRECT_PREFERENCES");

				SendMessage (GetDlgItem (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE), EM_LIMITTEXT, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, 0);
				SetDlgItemText (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE, customUserMessage.c_str());

				CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT, (userConfig & TC_BOOT_USER_CFG_FLAG_SILENT_MODE) ? BST_CHECKED : BST_UNCHECKED);
				CheckDlgButton (hwndDlg, IDC_ALLOW_ESC_PBA_BYPASS, (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_ESC) ? BST_UNCHECKED : BST_CHECKED);
				CheckDlgButton (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD, (driverConfig & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD) ? BST_CHECKED : BST_UNCHECKED);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE_HELP), GetString("CUSTOM_BOOT_LOADER_MESSAGE_HELP"));
			}
			catch (Exception &e)
			{
				e.Show (hwndDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}
		}
		return 0;

	case WM_COMMAND:

		switch (lw)
		{
		case IDCANCEL:
			EndDialog (hwndDlg, lw);
			return 1;

		case IDOK:
			{
				if (!BootEncObj->GetStatus().DriveMounted)
				{
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				char customUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
				GetDlgItemText (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE, customUserMessage, sizeof (customUserMessage));

				byte userConfig;
				try
				{
					BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					return 1;
				}

				if (IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT))
					userConfig |= TC_BOOT_USER_CFG_FLAG_SILENT_MODE;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_SILENT_MODE;

				if (!IsDlgButtonChecked (hwndDlg, IDC_ALLOW_ESC_PBA_BYPASS))
					userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_ESC;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_DISABLE_ESC;

				try
				{
					BootEncObj->WriteBootSectorUserConfig (userConfig, customUserMessage);
					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD, IsDlgButtonChecked (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD));
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					return 1;
				}

				EndDialog (hwndDlg, lw);
				return 1;
			}

		case IDC_DISABLE_BOOT_LOADER_OUTPUT:
			if ((IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT))
				&& AskWarnYesNo ("CUSTOM_BOOT_LOADER_MESSAGE_PROMPT") == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT, BST_UNCHECKED);
			}

			break;

		case IDC_BOOT_LOADER_CACHE_PASSWORD:
			if (IsDlgButtonChecked (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD))
				Warning ("BOOT_PASSWORD_CACHE_KEYBOARD_WARNING");

			break;
		}
		return 0;
	}

	return 0;
}


void MountSelectedVolume (HWND hwndDlg, BOOL mountWithOptions)
{
	if (!VolumeSelected(hwndDlg))
	{
		Warning ("NO_VOLUME_SELECTED");
	}
	else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == TC_MLIST_ITEM_FREE)
	{
		mountOptions = defaultMountOptions;
		bPrebootPasswordDlgMode = FALSE;

		if (mountWithOptions || GetAsyncKeyState (VK_CONTROL) < 0)
		{
			if (IDCANCEL == DialogBoxParamW (hInst, 
				MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
				(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
				return;

			if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
				KeyFilesApply (&mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile);
		}

		if (CheckMountList ())
			Mount (hwndDlg, 0, 0);
	}
	else
		Warning ("SELECT_FREE_DRIVE");
}


BOOL GetExecutableImageInformation (const string &path, string &version, string &description, string &companyName, string &productName)
{
	DWORD handle;
	DWORD size = GetFileVersionInfoSize (path.c_str(), &handle);
	if (size == 0)
		return FALSE;

	void *buf = err_malloc (size);
	finally_do_arg (void*, buf, { free (finally_arg); });

	if (!GetFileVersionInfo (path.c_str(), handle, size, buf))
		return FALSE;

	version = description = companyName = productName = "";

	UINT varSize;
	VS_FIXEDFILEINFO *fileInfo;
	if (VerQueryValue (buf, "\\", (LPVOID *) &fileInfo, &varSize) && varSize > 0)
	{
		stringstream s;
		s << HIWORD (fileInfo->dwFileVersionMS) << '.' << LOWORD (fileInfo->dwFileVersionMS) << '.' << HIWORD (fileInfo->dwFileVersionLS) << '.' << LOWORD (fileInfo->dwFileVersionLS);
		version = s.str();
	}

	DWORD *langCodes;
	if (VerQueryValue (buf, "\\VarFileInfo\\Translation", (LPVOID *) &langCodes, &varSize) && varSize >= sizeof (DWORD))
	{
		char prefix[128];
		sprintf_s (prefix, sizeof (prefix), "\\StringFileInfo\\%04x%04x\\", LOWORD (langCodes[0]), HIWORD (langCodes[0]));

		char *str;
		if (VerQueryValue (buf, (string (prefix) + "FileDescription").c_str(), (LPVOID *) &str, &varSize) && varSize > 0)
			description = str;

		if (VerQueryValue (buf, (string (prefix) + "CompanyName").c_str(), (LPVOID *) &str, &varSize) && varSize > 0)
			companyName = str;

		if (VerQueryValue (buf, (string (prefix) + "ProductName").c_str(), (LPVOID *) &str, &varSize) && varSize > 0)
			productName = str;
	}

	return TRUE;
}


void AnalyzeKernelMiniDump (HWND hwndDlg)
{
	char winDir[MAX_PATH] = { 0 };
	GetWindowsDirectory (winDir, sizeof (winDir));
	string memDumpPath = string (winDir) + "\\MEMORY.DMP";
	string tmpDumpPath;

	string dumpPath = FindLatestFileOrDirectory (string (winDir) + "\\Minidump", "*.dmp", false, true);
	if (dumpPath.empty())
	{
		Error ("NO_MINIDUMP_FOUND");
		return;
	}

	WIN32_FIND_DATA findData;
	HANDLE find = FindFirstFile (memDumpPath.c_str(), &findData);

	if (find != INVALID_HANDLE_VALUE)
	{
		ULARGE_INTEGER memDumpTime, miniDumpTime;
		memDumpTime.HighPart = findData.ftLastWriteTime.dwHighDateTime;
		memDumpTime.LowPart = findData.ftLastWriteTime.dwLowDateTime;

		FindClose (find);

		find = FindFirstFile (dumpPath.c_str(), &findData);
		if (find != INVALID_HANDLE_VALUE)
		{
			miniDumpTime.HighPart = findData.ftLastWriteTime.dwHighDateTime;
			miniDumpTime.LowPart = findData.ftLastWriteTime.dwLowDateTime;

			if (_abs64 (miniDumpTime.QuadPart - memDumpTime.QuadPart) < 10I64 * 1000 * 1000 * 60 * 5)
			{
				// Rename MEMORY.DMP file first as it can be deleted by Windows when system crash dialog is closed
				tmpDumpPath = memDumpPath + ".hd_crypt.dmp"; // Application name must be mangled to avoid interfering with crash analysis

				if (MoveFile (memDumpPath.c_str(), tmpDumpPath.c_str()))
					dumpPath = tmpDumpPath;
				else
					tmpDumpPath.clear();
			}

			FindClose (find);
		}
	}

	finally_do_arg2 (string, tmpDumpPath, string, memDumpPath,
	{
		if (!finally_arg.empty())
		{
			if (AskYesNo ("ASK_DELETE_KERNEL_CRASH_DUMP") == IDYES)
				DeleteFile (finally_arg.c_str());
			else
				MoveFile (finally_arg.c_str(), finally_arg2.c_str());
		}
	});

	STARTUPINFO startupInfo;
	PROCESS_INFORMATION procInfo; 

	ZeroMemory (&startupInfo, sizeof (startupInfo));
	ZeroMemory (&procInfo, sizeof (procInfo));

	if (!IsApplicationInstalled (Is64BitOs() ? "Debugging Tools for Windows (x64)" : "Debugging Tools for Windows (x86)"))
	{
		string sDbgCmd;
		if (AskOkCancel ("ASK_DEBUGGER_INSTALL") != IDOK)
			return;

		if (Is64BitOs())
			sDbgCmd = "msiexec.exe /qb /i http://www.idrix.fr/Root/MSDebug/dbg_amd64_6.11.1.404.msi";
		else
			sDbgCmd = "msiexec.exe /qb /i http://www.idrix.fr/Root/MSDebug/dbg_x86_6.11.1.404.msi";
		
		if (!CreateProcess (NULL, (LPSTR) sDbgCmd.c_str(),
			NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfo))
		{
			handleWin32Error (hwndDlg);
			return;
		}

		WaitCursor();
		WaitForSingleObject (procInfo.hProcess, INFINITE);
		NormalCursor();

		DWORD exitCode;
		bool bExitCheck = (!GetExitCodeProcess (procInfo.hProcess, &exitCode) || exitCode != 0);

		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);

		if (bExitCheck)
			return;
	}

	if (AskOkCancel ("SYSTEM_CRASH_ANALYSIS_INFO") == IDCANCEL)
		return;

	ZeroMemory (&startupInfo, sizeof (startupInfo));
	ZeroMemory (&procInfo, sizeof (procInfo));

	SECURITY_ATTRIBUTES securityAttrib; 
	securityAttrib.bInheritHandle = TRUE; 
	securityAttrib.nLength = sizeof (securityAttrib); 
	securityAttrib.lpSecurityDescriptor = NULL; 

	HANDLE hChildStdoutWrite = INVALID_HANDLE_VALUE;
	HANDLE hChildStdoutRead = INVALID_HANDLE_VALUE;
	if (!CreatePipe (&hChildStdoutRead, &hChildStdoutWrite, &securityAttrib, 0))
	{
		handleWin32Error (hwndDlg);
		return;
	}
	SetHandleInformation (hChildStdoutRead, HANDLE_FLAG_INHERIT, 0);

	startupInfo.hStdInput = INVALID_HANDLE_VALUE;
	startupInfo.hStdOutput = hChildStdoutWrite;
	startupInfo.cb = sizeof (startupInfo); 
	startupInfo.hStdError = hChildStdoutWrite;
	startupInfo.dwFlags |= STARTF_USESTDHANDLES;

	list <string> kdPaths;
	string kdPath;
	char progPath[MAX_PATH];
	if (SHGetSpecialFolderPath (hwndDlg, progPath, CSIDL_PROGRAM_FILES, FALSE))
	{
		if (Is64BitOs())
		{
			string s = progPath;
			size_t p = s.find (" (x86)");
			if (p != string::npos)
			{
				s = s.substr (0, p);
				if (_access (s.c_str(), 0) != -1)
					strcpy_s (progPath, sizeof (progPath), s.c_str());
			}
		}

		kdPath = string (progPath) + "\\Debugging Tools for Windows (" + (Is64BitOs() ? "x64" : "x86") + ")\\kd.exe";
		kdPaths.push_back (kdPath);
	}

	kdPath = FindLatestFileOrDirectory (string (winDir).substr (0, 1) + ":\\WinDDK", "*", true, false);
	kdPath += "\\Debuggers\\kd.exe";
	kdPaths.push_back (kdPath);

	kdPaths.push_back ("kd.exe");

	bool kdRunning = false;
	foreach (const string &kdPath, kdPaths)
	{
		if (CreateProcess (NULL, (LPSTR) ("\"" + kdPath + "\" -z \"" + dumpPath + "\" -y http://msdl.microsoft.com/download/symbols -c \".bugcheck; !analyze -v; q\"").c_str(),
			NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &procInfo))
		{
			kdRunning = true;
			break;
		}
	}

	if (!kdRunning)
	{
		handleWin32Error (hwndDlg);
		Error ("DEBUGGER_NOT_FOUND");
		CloseHandle (procInfo.hProcess);
		CloseHandle (procInfo.hThread);
		CloseHandle (hChildStdoutRead);
		CloseHandle (hChildStdoutWrite);
		return;
	}

	EnableElevatedCursorChange (hwndDlg);
	WaitCursor();

	CloseHandle (procInfo.hProcess);
	CloseHandle (procInfo.hThread);
	CloseHandle (hChildStdoutWrite);

	string output;

	while (TRUE) 
	{ 
		DWORD bytesReceived;
		char pipeBuffer [4096];

		if (!ReadFile (hChildStdoutRead, pipeBuffer, sizeof (pipeBuffer), &bytesReceived, NULL)) 
			break; 

		output.insert (output.size(), pipeBuffer, bytesReceived);
	}

	CloseHandle (hChildStdoutRead);

	NormalCursor();

	bool otherDriver = (StringToUpperCase (output).find (StringToUpperCase (TC_APP_NAME)) == string::npos);

	size_t p, p2;
	while ((p = output.find ('`')) != string::npos)
		output.erase (output.begin() + p);

	p = output.find ("Bugcheck code ");
	if (p == string::npos)
	{
		Error ("ERR_PARAMETER_INCORRECT");
		return;
	}

	uint64 bugcheckCode;
	int n = sscanf (output.substr (p + 14, 8).c_str(), "%I64uX", &bugcheckCode);
	if (n != 1)
	{
		Error ("ERR_PARAMETER_INCORRECT");
		return;
	}

	p = output.find ("Arguments ", p);
	
	uint64 bugcheckArgs[4];
	n = sscanf (output.substr (p + 10, (Is64BitOs() ? 17 : 9) * 4).c_str(), "%I64uX %I64uX %I64uX %I64uX", &bugcheckArgs[0], &bugcheckArgs[1], &bugcheckArgs[2], &bugcheckArgs[3]);
	if (n != 4)
	{
		Error ("ERR_PARAMETER_INCORRECT");
		return;
	}

	// Image name
	string imageName, imageVersion;
	p = output.find ("IMAGE_NAME:");
	if (p != string::npos)
	{
		p += 13;
		p2 = output.find ('\n', p);
		if (p2 != string::npos)
			imageName = output.substr (p, p2 - p);
	}

	// Stack trace
	p = output.find ("STACK_TEXT:");
	if (p == string::npos)
	{
		Error ("ERR_PARAMETER_INCORRECT");
		return;
	}

	p2 = output.find ("FOLLOWUP_IP:", p);
	if (p2 == string::npos)
		p2 = output.find ("STACK_COMMAND:", p);
	if (p2 == string::npos)
		p2 = output.size();

	output = output.substr (p, p2 - p);

	list <string> retAddrs;
	p = 0;
	while ((p = output.find ("+", p)) != string::npos)
	{
		size_t p1 = output.rfind (" ", p);
		if (p1 == string::npos)
			break;

		p = output.find ('\n', p);
		if (p == string::npos)
			p = output.size() - 1;

		string s = output.substr (p1 + 1, p - p1 - 1);

		if (s.find ('(') == 0)
			s = s.substr (1);
		if (s.rfind (')') == s.size() - 1)
			s = s.substr (0, s.size() - 1);

		retAddrs.push_back (s);
	}
/*
	char url[MAX_URL_LENGTH];
	sprintf (url, TC_APPLINK_SECURE "&dest=syserr-report&os=%s&osver=%d.%d.%d&arch=%s&err=%I64x&arg1=%I64x&arg2=%I64x&arg3=%I64x&arg4=%I64x&flag=%s&drv=%s",
		GetWindowsEdition().c_str(),
		CurrentOSMajor,
		CurrentOSMinor,
		CurrentOSServicePack,
		Is64BitOs() ? "x64" : "x86",
		bugcheckCode,
		bugcheckArgs[0],
		bugcheckArgs[1],
		bugcheckArgs[2],
		bugcheckArgs[3],
		otherDriver ? "0" : "1",
		imageName.empty() ? "-" : imageName.c_str()
		);
*/
	stringstream stackTraceArgs;
	int i = 0;
	foreach (const string &retAddr, retAddrs)
	{
		stackTraceArgs << "&st" << i++ << "=" << retAddr;
	}

	wstring msg;

	if (!imageName.empty() && StringToUpperCase (imageName) != StringToUpperCase (TC_APP_NAME) + ".SYS")
	{
		msg += wstring (GetString ("SYSTEM_CRASH_UPDATE_DRIVER")) + L"\n\n" + SingleStringToWide (imageName);

		string description, company, product;
		if (GetExecutableImageInformation (string (winDir) + "\\System32\\drivers\\" + imageName, imageVersion, description, company, product))
		{
			string s;
			if (!description.empty())
				s += description;
			if (!company.empty())
				s += ";  " + company;
			if (!product.empty())
				s += ";  " + product;

			if (s.find (";  ") == 0)
				s = s.substr (3);

			if (!s.empty())
				msg += SingleStringToWide ("  (" + s + ")");
		}

		msg += L"\n\n";
	}

	if (otherDriver)
	{
		msg += GetString ("SYSTEM_CRASH_NO_TRUECRYPT");
		msg += L"\n\n";
	}

	InfoDirect(msg.c_str());
/*
	string urlStr = string (url) + "&drvver=" + (imageVersion.empty() ? "-" : imageVersion) + stackTraceArgs.str();

	for (size_t i = 0; i < urlStr.size(); ++i)
	{
		if (urlStr[i] == '+')
			urlStr[i] = '.';
	}

	msg += GetString ("SYSTEM_CRASH_REPORT");
	msg += L"\n\n";

	msg += SingleStringToWide (urlStr);

	msg += L"\n\n";
	msg += GetString ("ASK_SEND_ERROR_REPORT");

	if (AskYesNoString (msg.c_str()) == IDYES)
		ShellExecute (NULL, "open", urlStr.c_str(), NULL, NULL, SW_SHOWNORMAL);
*/
}


static BOOL HandleDriveListMouseWheelEvent (UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL bListMustBePointed)
{
	static BOOL eventHandlerActive = FALSE;
	if (eventHandlerActive)
		return 0;

	RECT listRect;
	int mouseX = GET_X_LPARAM (lParam);
	int mouseY = GET_Y_LPARAM (lParam);

	GetWindowRect (GetDlgItem (MainDlg, IDC_DRIVELIST), &listRect);

	// Determine if the mouse pointer is within the main drive list
	bool bListPointed = (mouseX >= listRect.left && mouseX <= listRect.right
		&& mouseY >= listRect.top && mouseY <= listRect.bottom);

	if (bListMustBePointed && bListPointed
		|| !bListMustBePointed)
	{
		eventHandlerActive = TRUE;

		if (!bListMustBePointed && bListPointed)
			SetFocus (GetDlgItem (MainDlg, IDC_DRIVELIST));

		SendMessage (GetDlgItem (MainDlg, IDC_DRIVELIST), uMsg, wParam, lParam);

		eventHandlerActive = FALSE;
		return 0;	// Do not process this event any further e.g. to prevent two lists from being scrolled at once
	}

	return 1;
}


static LRESULT CALLBACK MouseWheelProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtr (hwnd, GWLP_USERDATA);

	switch (message)
	{
	case WM_MOUSEWHEEL:

		if (HandleDriveListMouseWheelEvent (message, wParam, lParam, TRUE) == 0)
			return 0;	// Do not process this event any further e.g. to prevent two lists from being scrolled at once
	}

	return CallWindowProc (wp, hwnd, message, wParam, lParam);
}


void HookMouseWheel (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SetWindowLongPtr (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtr (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtr (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) MouseWheelProc);
}
