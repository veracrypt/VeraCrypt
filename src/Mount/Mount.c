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

#import <msxml6.dll>

#include <wtsapi32.h>

typedef BOOL (WINAPI *WTSREGISTERSESSIONNOTIFICATION)(HWND, DWORD);
typedef BOOL (WINAPI *WTSUNREGISTERSESSIONNOTIFICATION)(HWND);

using namespace VeraCrypt;

enum timer_ids
{
	TIMER_ID_MAIN = 0xff,
	TIMER_ID_KEYB_LAYOUT_GUARD,
	TIMER_ID_UPDATE_DEVICE_LIST
};

enum hidden_os_read_only_notif_mode
{
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE = 0,
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_COMPACT,
	TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_DISABLED
};

#define TIMER_INTERVAL_MAIN					500
#define TIMER_INTERVAL_KEYB_LAYOUT_GUARD	10
#define TIMER_INTERVAL_UPDATE_DEVICE_LIST	1000

BootEncryption			*BootEncObj = NULL;
BootEncryptionStatus	BootEncStatus;
BootEncryptionStatus	RecentBootEncStatus;

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

int HiddenSysLeakProtectionNotificationStatus = TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE;
int MaxVolumeIdleTime = -120;
int nCurrentShowType = 0;			/* current display mode, mount, unmount etc */
int nSelectedDriveIndex = -1;		/* Item number of selected drive */

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
KeyFile *FirstCmdKeyFile;

HBITMAP hbmLogoBitmapRescaled = NULL;
wchar_t OrigKeyboardLayout [8+1] = L"00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */

static KeyFilesDlgParam				hidVolProtKeyFilesParam;

static MOUNT_LIST_STRUCT	LastKnownMountList = {0};
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
// WTS handling
static HMODULE hWtsLib = NULL;
static WTSREGISTERSESSIONNOTIFICATION   fnWtsRegisterSessionNotification = NULL;
static WTSUNREGISTERSESSIONNOTIFICATION fnWtsUnRegisterSessionNotification = NULL;

static void RegisterWtsNotification(HWND hWnd)
{
	if (!hWtsLib)
	{
		wchar_t dllPath[MAX_PATH];
		if (GetSystemDirectory(dllPath, MAX_PATH))
			StringCbCatW(dllPath, sizeof(dllPath), L"\\wtsapi32.dll");
		else
			StringCbCopyW(dllPath, sizeof(dllPath), L"c:\\Windows\\System32\\wtsapi32.dll");

		hWtsLib = LoadLibrary(dllPath);
		if (hWtsLib)
		{
			fnWtsRegisterSessionNotification = (WTSREGISTERSESSIONNOTIFICATION) GetProcAddress(hWtsLib, "WTSRegisterSessionNotification" );
			fnWtsUnRegisterSessionNotification = (WTSUNREGISTERSESSIONNOTIFICATION) GetProcAddress(hWtsLib, "WTSUnRegisterSessionNotification" );
			if (	!fnWtsRegisterSessionNotification
				|| 	!fnWtsUnRegisterSessionNotification
				||	!fnWtsRegisterSessionNotification( hWnd, NOTIFY_FOR_THIS_SESSION )
				)
			{
				fnWtsRegisterSessionNotification = NULL;
				fnWtsUnRegisterSessionNotification = NULL;
				FreeLibrary(hWtsLib);
				hWtsLib = NULL;
			}
		}
	}
}

static void UnregisterWtsNotification(HWND hWnd)
{
	if (hWtsLib && fnWtsUnRegisterSessionNotification)
	{
		fnWtsUnRegisterSessionNotification(hWnd);
		FreeLibrary(hWtsLib);
		hWtsLib = NULL;
		fnWtsRegisterSessionNotification = NULL;
		fnWtsUnRegisterSessionNotification = NULL;
	}
}

static std::vector<MSXML2::IXMLDOMNodePtr> GetReadChildNodes (MSXML2::IXMLDOMNodeListPtr childs)
{
	std::vector<MSXML2::IXMLDOMNodePtr> list;	
	if (childs && childs->Getlength())
	{
		for (long i = 0; i < childs->Getlength(); i++)
		{
			MSXML2::IXMLDOMNodePtr node = childs->Getitem(i);
			if (node)
			{
				//skip comments
				if (node->GetnodeType() == NODE_COMMENT)
					continue;
				// skip root xml node
				if (node->GetbaseName().GetBSTR() && (0 == strcmp ("xml", (const char*) node->GetbaseName())))
					continue;

				list.push_back (node);
			}
		}
	}

	return list;
}

static bool validateDcsPropXml(const char* xmlData)
{
	bool bValid = false;	
	HRESULT hr = CoInitialize(NULL);
	if(FAILED(hr))
		return false;
	else
	{
		MSXML2::IXMLDOMDocumentPtr pXMLDom;
		hr= pXMLDom.CreateInstance(__uuidof(MSXML2::DOMDocument60), NULL, CLSCTX_INPROC_SERVER);
		if (SUCCEEDED(hr)) 
		{
			try
			{
				pXMLDom->async = VARIANT_FALSE;
				pXMLDom->validateOnParse = VARIANT_FALSE;
				pXMLDom->resolveExternals = VARIANT_FALSE;

				if(pXMLDom->loadXML(xmlData) == VARIANT_TRUE && pXMLDom->hasChildNodes())
				{
					MSXML2::IXMLDOMNodePtr veracryptNode, configurationNode, configNode;
					std::vector<MSXML2::IXMLDOMNodePtr> nodes = GetReadChildNodes (pXMLDom->GetchildNodes());
					size_t nodesCount = nodes.size();
					if (nodesCount == 1 
						&& ((veracryptNode = nodes[0])->GetnodeType() == NODE_ELEMENT)
						&& veracryptNode->GetnodeName().GetBSTR()
						&& (0 == strcmp ((const char*) veracryptNode->GetnodeName(), "VeraCrypt")) 
						&& veracryptNode->hasChildNodes()
						
						)
					{
						nodes = GetReadChildNodes (veracryptNode->GetchildNodes());
						nodesCount = nodes.size();
						if ((nodesCount == 1)
							&& ((configurationNode = nodes[0])->GetnodeType() == NODE_ELEMENT)
							&& configurationNode->GetnodeName().GetBSTR()
							&&  (0 == strcmp ((const char*) configurationNode->GetnodeName(), "configuration"))
							&&  (configurationNode->hasChildNodes())
							)
						{
							nodes = GetReadChildNodes (configurationNode->GetchildNodes());
							nodesCount = nodes.size();

							if (nodesCount > 1)
							{
								bValid = true;
								for (size_t i = 0; bValid && (i < nodesCount); i++)
								{
									configNode = nodes[i];
									if (configNode->GetnodeType() == NODE_COMMENT)
										continue;									
									else if (	(configNode->GetnodeType() == NODE_ELEMENT)
										&&	(configNode->GetnodeName().GetBSTR())
										&& (0 == strcmp ((const char*) configNode->GetnodeName(), "config"))	
										)
									{
										nodes = GetReadChildNodes (configNode->GetchildNodes());
										nodesCount = nodes.size();
										if ((nodesCount == 0 || (nodesCount == 1 && nodes[0]->GetnodeType() == NODE_TEXT)) 
											&& configNode->Getattributes() 
											&& (configNode->Getattributes()->Getlength() == 1)
											&& (configNode->Getattributes()->Getitem(0))
											)
										{
											std::string val;
											bstr_t bstr = configNode->Getattributes()->Getitem(0)->GetnodeName ();
											if (bstr.GetBSTR())
												val = (const char*) bstr;
											if (val != "key")
												bValid = false;
										}
										else
											bValid = false;
									}
									else
										bValid = false;
								}
							}
						}
					}
				}
			}
			catch(_com_error errorObject)
			{
				bValid = false;
			}
		}
	}

	CoUninitialize();
	return bValid;
}


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
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&CmdVolumePkcs5, sizeof (CmdVolumePkcs5));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&CmdVolumePim, sizeof (CmdVolumePim));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
	burn (&CmdVolumeTrueCryptMode, sizeof (CmdVolumeTrueCryptMode));
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
	int drive = (wchar_t) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))));

	MoveEditToCombo (GetDlgItem (hwndDlg, IDC_VOLUME), bHistory);
	LoadDriveLetters (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST), drive);
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
		SetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), L"");
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
		KillTimer (hwndDlg, TIMER_ID_UPDATE_DEVICE_LIST);
		TaskBarIconRemove (hwndDlg);
		UnregisterWtsNotification(hwndDlg);
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

	SetWindowLongPtrW (hwndDlg, DWLP_USER, (LONG_PTR) (IsAdmin() ? TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES : 0));

	DragAcceptFiles (hwndDlg, TRUE);

	SendMessageW (GetDlgItem (hwndDlg, IDC_VOLUME), CB_LIMITTEXT, TC_MAX_PATH, 0);
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
		info.cch = (UINT) wcslen (str);

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
		info.cch = (UINT) wcslen (str);

		SetMenuItemInfoW (GetMenu (hwndDlg), i, TRUE,  &info);
	}

	{
		// disable hidden OS creation for GPT system encryption
		if (bSystemIsGPT)
		{
			EnableMenuItem (GetMenu (hwndDlg), IDM_CREATE_HIDDEN_OS, MF_GRAYED);
		}
	}

	// Disable menu item for changing system header key derivation algorithm until it's implemented
	EnableMenuItem (GetMenu (hwndDlg), IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO, MF_GRAYED);

	try
	{
		LoadFavoriteVolumes();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
	}

	// initialize the list of devices available for mounting as early as possible
	UpdateMountableHostDeviceList (false);

	// Resize the logo bitmap if the user has a non-default DPI
	if (ScreenDPI != USER_DEFAULT_SCREEN_DPI
		&& hbmLogoBitmapRescaled == NULL)	// If not re-called (e.g. after language pack change)
	{
		hbmLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_LOGO_288DPI),
			GetDlgItem (hwndDlg, IDC_LOGO),
			0, 0, 0, 0, FALSE, TRUE);
	}

	BuildTree (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST));

	if (*szDriveLetter != 0)
	{
		SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST), *szDriveLetter);

		if(nSelectedDriveIndex > SendMessage (GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_GETITEMCOUNT, 0, 0)/2)
			SendMessage(GetDlgItem (hwndDlg, IDC_DRIVELIST), LVM_SCROLL, 0, 10000);
	}
	else
	{
		SendMessage(hwndDlg, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hwndDlg, IDC_DRIVELIST), 1L);
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

void GetVolumePath (HWND hwndDlg, LPWSTR szPath, int nMaxCount)
{
	GetWindowText (GetDlgItem (hwndDlg, IDC_VOLUME), szPath, nMaxCount);
	CorrectFileName (szPath);
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

			GetVolumePath (MainDlg, szFileName, ARRAYSIZE (szFileName));

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

// When a function does not require the affected volume to be dismounted, there may be cases where we have two valid
// paths selected in the main window and we cannot be sure which of them the user really intends to apply the function to.
// This function asks the user to explicitly select either the volume path specified in the input field below the main
// drive list (whether mounted or not), or the path to the volume selected in the main drive list. If, however, both
// of the GUI elements contain the same volume (or one of them does not contain any path), this function does not
// ask the user and returns the volume path directly (no selection ambiguity).
// If driveNoPtr is not NULL, and the volume is mounted, its drive letter is returned in *driveNoPtr (if no valid drive
// letter is resolved, -1 is stored instead).
static wstring ResolveAmbiguousSelection (HWND hwndDlg, int *driveNoPtr)
{
	LPARAM selectedDrive = GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST));

	wchar_t volPathInputField [TC_MAX_PATH];

	wchar_t volPathDriveListW [TC_MAX_PATH];
	wstring volPathDriveListStr;

	wstring retPath;

	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;

	BOOL useInputField = TRUE;

	memset (&prop, 0, sizeof(prop));

	BOOL ambig = (LOWORD (selectedDrive) != TC_MLIST_ITEM_FREE && LOWORD (selectedDrive) != 0xffff && HIWORD (selectedDrive) != 0xffff
		&& VolumeSelected (MainDlg));

	if (VolumeSelected (MainDlg))
	{
		// volPathInputField will contain the volume path (if any) from the input field below the drive list
		GetVolumePath (MainDlg, volPathInputField, ARRAYSIZE (volPathInputField));

		if (!ambig)
			retPath = (wstring) volPathInputField;
	}

	if (LOWORD (selectedDrive) != TC_MLIST_ITEM_FREE && LOWORD (selectedDrive) != 0xffff && HIWORD (selectedDrive) != 0xffff)
	{
		// A volume is selected in the main drive list.

		switch (LOWORD (selectedDrive))
		{
		case TC_MLIST_ITEM_NONSYS_VOL:
			prop.driveNo = HIWORD (selectedDrive) - L'A';

			if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL) || dwResult == 0)
			{
				// The driver did not return any path for this drive letter (the volume may have been dismounted).

				// Return whatever is in the input field below the drive list (even if empty)
				return ((wstring) volPathInputField);
			}

			// volPathDriveListWStr will contain the volume path selected in the main drive list
			volPathDriveListStr = (wstring) prop.wszVolume;
			break;

		case TC_MLIST_ITEM_SYS_PARTITION:

			GetSysDevicePaths (MainDlg);

			if (bCachedSysDevicePathsValid)
			{
				volPathDriveListStr = (wstring) SysPartitionDevicePath;
			}

			break;

		case TC_MLIST_ITEM_SYS_DRIVE:

			GetSysDevicePaths (MainDlg);

			if (bCachedSysDevicePathsValid)
			{
				volPathDriveListStr = (wstring) SysDriveDevicePath;
			}

			break;
		}

		if (!ambig)
		{
			useInputField = FALSE;
			retPath = volPathDriveListStr;
		}
	}

	if (ambig)
	{
		/* We have two paths. Compare them and if they don't match, ask the user to select one of them. Otherwise, return the path without asking. */

		if (wmemcmp (volPathDriveListStr.c_str (), L"\\??\\", 4) == 0)
		{
			// The volume path starts with "\\??\\" which is used for file-hosted containers. We're going to strip this prefix.

			volPathDriveListStr = (wstring) (volPathDriveListStr.c_str () + 4);
		}

		StringCbCopyW (volPathDriveListW, sizeof(volPathDriveListW), volPathDriveListStr.c_str ());

		if (wcscmp (((wmemcmp (volPathDriveListW, L"\\??\\", 4) == 0) ? volPathDriveListW + 4 : volPathDriveListW), volPathInputField) != 0)
		{
			// The path selected in the input field is different from the path to the volume selected
			// in the drive lettter list. We have to resolve possible ambiguity.

			wchar_t *tmp[] = {L"", L"", L"", L"", L"", 0};
			const int maxVolPathLen = 80;

			if (volPathDriveListStr.length () > maxVolPathLen)
			{
				// Ellipsis (path too long)
				volPathDriveListStr = wstring (L"...") + volPathDriveListStr.substr (volPathDriveListStr.length () - maxVolPathLen, maxVolPathLen);
			}

			wstring volPathInputFieldWStr (volPathInputField);

			if (volPathInputFieldWStr.length () > maxVolPathLen)
			{
				// Ellipsis (path too long)
				volPathInputFieldWStr = wstring (L"...") + volPathInputFieldWStr.substr (volPathInputFieldWStr.length () - maxVolPathLen, maxVolPathLen);
			}

			tmp[1] = GetString ("AMBIGUOUS_VOL_SELECTION");
			tmp[2] = (wchar_t *) volPathDriveListStr.c_str();
			tmp[3] = (wchar_t *) volPathInputFieldWStr.c_str();
			tmp[4] = GetString ("IDCANCEL");

			switch (AskMultiChoice ((void **) tmp, FALSE, hwndDlg))
			{
			case 1:
				retPath = volPathDriveListStr;
				break;

			case 2:
				retPath = (wstring) volPathInputField;
				break;

			default:
				if (driveNoPtr != NULL)
					*driveNoPtr = -1;

				return wstring (L"");
			}
		}
		else
		{
			// Both selected paths are the same
			retPath = (wstring) volPathInputField;
		}
	}

	if (driveNoPtr != NULL)
		*driveNoPtr = GetMountedVolumeDriveNo ((wchar_t *) retPath.c_str ());


	if (wmemcmp (retPath.c_str (), L"\\??\\", 4) == 0)
	{
		// The selected volume path starts with "\\??\\" which is used for file-hosted containers. We're going to strip this prefix.

		retPath = (wstring) (retPath.c_str () + 4);
	}

	return retPath;
}

void LoadSettingsAndCheckModified (HWND hwndDlg, BOOL bOnlyCheckModified, BOOL* pbSettingsModified, BOOL* pbHistoryModified)
{
	char langid[6] = {0};
	if (!bOnlyCheckModified)
	   EnableHwEncryption ((ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? FALSE : TRUE);

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

	// Options
	ConfigReadCompareInt ("OpenExplorerWindowAfterMount", FALSE, &bExplore, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("UseDifferentTrayIconIfVolumesMounted", TRUE, &bUseDifferentTrayIconIfVolMounted, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("SaveVolumeHistory", FALSE, &bHistory, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("CachePasswords", FALSE, &bCacheInDriverDefault, bOnlyCheckModified, pbSettingsModified);
	if (!bOnlyCheckModified)
		bCacheInDriver = bCacheInDriverDefault;

	ConfigReadCompareInt ("CachePasswordDuringMultipleMount", FALSE, &bCacheDuringMultipleMount, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("WipePasswordCacheOnExit", FALSE, &bWipeCacheOnExit, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("WipeCacheOnAutoDismount", TRUE, &bWipeCacheOnAutoDismount, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("IncludePimInCache", FALSE, &bIncludePimInCache, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("TryEmptyPasswordWhenKeyfileUsed",FALSE, &bTryEmptyPasswordWhenKeyfileUsed, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("StartOnLogon", FALSE, &bStartOnLogon, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("MountDevicesOnLogon", FALSE, &bMountDevicesOnLogon, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("MountFavoritesOnLogon", FALSE, &bMountFavoritesOnLogon, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("EnableBackgroundTask", TRUE, &bEnableBkgTask, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("CloseBackgroundTaskOnNoVolumes", FALSE, &bCloseBkgTaskWhenNoVolumes, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("DismountOnLogOff", !(IsServerOS() && IsAdmin()), &bDismountOnLogOff, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("DismountOnSessionLocked", FALSE, &bDismountOnSessionLocked, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("DismountOnPowerSaving", FALSE, &bDismountOnPowerSaving, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("DismountOnScreenSaver", FALSE, &bDismountOnScreenSaver, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("ForceAutoDismount", TRUE, &bForceAutoDismount, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("MaxVolumeIdleTime", -60, &MaxVolumeIdleTime, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("HiddenSectorDetectionStatus", 0, &HiddenSectorDetectionStatus, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("UseKeyfiles", FALSE, &defaultKeyFilesParam.EnableKeyFiles, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("PreserveTimestamps", TRUE, &defaultMountOptions.PreserveTimestamp, bOnlyCheckModified, pbSettingsModified);
	if (!bOnlyCheckModified)
		bPreserveTimestamp = defaultMountOptions.PreserveTimestamp;

	ConfigReadCompareInt ("ShowDisconnectedNetworkDrives", FALSE, &bShowDisconnectedNetworkDrives, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("HideWaitingDialog", FALSE, &bHideWaitingDialog, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("UseSecureDesktop", FALSE, &bUseSecureDesktop, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("MountVolumesRemovable", FALSE, &defaultMountOptions.Removable, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("MountVolumesReadOnly", FALSE, &defaultMountOptions.ReadOnly, bOnlyCheckModified, pbSettingsModified);

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

	if (IsHiddenOSRunning())
		ConfigReadCompareInt ("HiddenSystemLeakProtNotifStatus", TC_HIDDEN_OS_READ_ONLY_NOTIF_MODE_NONE, &HiddenSysLeakProtectionNotificationStatus, bOnlyCheckModified, pbSettingsModified);

	// Drive letter - command line arg overrides registry
	if (!bOnlyCheckModified && bHistory && szDriveLetter[0] == 0)
	{
		char szTmp[3] = {0};
		ConfigReadString ("LastSelectedDrive", "", szTmp, sizeof (szTmp));
		MultiByteToWideChar (CP_UTF8, 0, szTmp, -1, szDriveLetter, ARRAYSIZE (szDriveLetter));
	}
	if (bHistory && pbSettingsModified)
	{
		// only check for last drive modification if history enabled
		char szTmp[32] = {0};
		LPARAM lLetter;
		lLetter = GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST));
		if (LOWORD (lLetter) != 0xffff)
			StringCbPrintfA (szTmp, sizeof(szTmp), "%lc:", (wchar_t) HIWORD (lLetter));

		ConfigReadCompareString ("LastSelectedDrive", "", szTmp, sizeof (szTmp), bOnlyCheckModified, pbSettingsModified);
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

	// Hotkeys
	ConfigReadCompareInt ("PlaySoundOnHotkeyMountDismount", TRUE, &bPlaySoundOnSuccessfulHkDismount, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("DisplayMsgBoxOnHotkeyDismount", TRUE, &bDisplayBalloonOnSuccessfulHkDismount, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModAutoMountDevices", 0, (int*) &Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeAutoMountDevices", 0, (int*) &Hotkeys [HK_AUTOMOUNT_DEVICES].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModDismountAll", 0, (int*) &Hotkeys [HK_DISMOUNT_ALL].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeDismountAll", 0, (int*) &Hotkeys [HK_DISMOUNT_ALL].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModWipeCache", 0, (int*) &Hotkeys [HK_WIPE_CACHE].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeWipeCache", 0, (int*) &Hotkeys [HK_WIPE_CACHE].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModDismountAllWipe", 0, (int*) &Hotkeys [HK_DISMOUNT_ALL_AND_WIPE].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeDismountAllWipe", 0, (int*) &Hotkeys [HK_DISMOUNT_ALL_AND_WIPE].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModForceDismountAllWipe", 0, (int*) &Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeForceDismountAllWipe", 0, (int*) &Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModForceDismountAllWipeExit", 0, (int*) &Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeForceDismountAllWipeExit", 0, (int*) &Hotkeys [HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModMountFavoriteVolumes", 0, (int*) &Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeMountFavoriteVolumes", 0, (int*) &Hotkeys [HK_MOUNT_FAVORITE_VOLUMES].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModShowHideMainWindow", 0, (int*) &Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeShowHideMainWindow", 0, (int*) &Hotkeys [HK_SHOW_HIDE_MAIN_WINDOW].vKeyCode, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyModCloseSecurityTokenSessions", 0, (int*) &Hotkeys [HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyModifiers, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("HotkeyCodeCloseSecurityTokenSessions", 0, (int*) &Hotkeys [HK_CLOSE_SECURITY_TOKEN_SESSIONS].vKeyCode, bOnlyCheckModified, pbSettingsModified);

	// History
	if (bHistoryCmdLine != TRUE)
	{
		LoadCombo (GetDlgItem (MainDlg, IDC_VOLUME), bHistory, bOnlyCheckModified, pbHistoryModified);
		if (!bOnlyCheckModified && CmdLineVolumeSpecified)
			SetWindowText (GetDlgItem (MainDlg, IDC_VOLUME), szFileName);
	}

	// Mount Options
	ConfigReadCompareInt ("DefaultPRF", 0, &DefaultVolumePkcs5, bOnlyCheckModified, pbSettingsModified);
	ConfigReadCompareInt ("DefaultTrueCryptMode", FALSE, &DefaultVolumeTrueCryptMode, bOnlyCheckModified, pbSettingsModified);

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

	if (DefaultVolumePkcs5 < 0 || DefaultVolumePkcs5 > LAST_PRF_ID)
		DefaultVolumePkcs5 = 0;
	if (DefaultVolumeTrueCryptMode != TRUE && DefaultVolumeTrueCryptMode != FALSE)
		DefaultVolumeTrueCryptMode = FALSE;

}

void LoadSettings ( HWND hwndDlg )
{
	LoadSettingsAndCheckModified (hwndDlg, FALSE, NULL, NULL);
}

void SaveSettings (HWND hwndDlg)
{
	WaitCursor ();

	// Check first if modifications ocurred before writing to the settings and history files
	// This avoids leaking information about VeraCrypt usage when user only mount volumes without changing setttings or history
	BOOL bSettingsChanged = FALSE;
	BOOL bHistoryChanged = FALSE;

	LoadSettingsAndCheckModified (hwndDlg, TRUE, &bSettingsChanged, &bHistoryChanged);

	if (bSettingsChanged)
	{
		char szTmp[32] = {0};
		LPARAM lLetter;

		// Options
		ConfigWriteBegin ();

		ConfigWriteInt ("OpenExplorerWindowAfterMount",		bExplore);
		ConfigWriteInt ("UseDifferentTrayIconIfVolumesMounted",	bUseDifferentTrayIconIfVolMounted);
		ConfigWriteInt ("SaveVolumeHistory",				bHistory);

		ConfigWriteInt ("CachePasswords",					bCacheInDriverDefault);
		ConfigWriteInt ("CachePasswordDuringMultipleMount",	bCacheDuringMultipleMount);
		ConfigWriteInt ("WipePasswordCacheOnExit",			bWipeCacheOnExit);
		ConfigWriteInt ("WipeCacheOnAutoDismount",			bWipeCacheOnAutoDismount);

		ConfigWriteInt ("IncludePimInCache",				bIncludePimInCache);

		ConfigWriteInt ("TryEmptyPasswordWhenKeyfileUsed",	bTryEmptyPasswordWhenKeyfileUsed);

		ConfigWriteInt ("StartOnLogon",						bStartOnLogon);
		ConfigWriteInt ("MountDevicesOnLogon",				bMountDevicesOnLogon);
		ConfigWriteInt ("MountFavoritesOnLogon",			bMountFavoritesOnLogon);

		ConfigWriteInt ("MountVolumesReadOnly",				defaultMountOptions.ReadOnly);
		ConfigWriteInt ("MountVolumesRemovable",			defaultMountOptions.Removable);
		ConfigWriteInt ("PreserveTimestamps",				defaultMountOptions.PreserveTimestamp);
		ConfigWriteInt ("ShowDisconnectedNetworkDrives",bShowDisconnectedNetworkDrives);
		ConfigWriteInt ("HideWaitingDialog",				bHideWaitingDialog);
		ConfigWriteInt ("UseSecureDesktop",					bUseSecureDesktop);

		ConfigWriteInt ("EnableBackgroundTask",				bEnableBkgTask);
		ConfigWriteInt ("CloseBackgroundTaskOnNoVolumes",	bCloseBkgTaskWhenNoVolumes);

		ConfigWriteInt ("DismountOnLogOff",					bDismountOnLogOff);
		ConfigWriteInt ("DismountOnSessionLocked",			bDismountOnSessionLocked);
		ConfigWriteInt ("DismountOnPowerSaving",			bDismountOnPowerSaving);
		ConfigWriteInt ("DismountOnScreenSaver",			bDismountOnScreenSaver);
		ConfigWriteInt ("ForceAutoDismount",				bForceAutoDismount);
		ConfigWriteInt ("MaxVolumeIdleTime",				MaxVolumeIdleTime);

		ConfigWriteInt ("HiddenSectorDetectionStatus",				HiddenSectorDetectionStatus);

		ConfigWriteInt ("UseKeyfiles",						defaultKeyFilesParam.EnableKeyFiles);

		if (IsHiddenOSRunning())
			ConfigWriteInt ("HiddenSystemLeakProtNotifStatus", HiddenSysLeakProtectionNotificationStatus);

		// save last selected drive only when history enabled
		if (bHistory)
		{
			// Drive Letter
			lLetter = GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST));
			if (LOWORD (lLetter) != 0xffff)
				StringCbPrintfA (szTmp, sizeof(szTmp), "%lc:", (wchar_t) HIWORD (lLetter));
			ConfigWriteString ("LastSelectedDrive", szTmp);
		}

		ConfigWriteInt ("CloseSecurityTokenSessionsAfterMount",	CloseSecurityTokenSessionsAfterMount);

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
		ConfigWriteString ("Language", GetPreferredLangId ());

		// PKCS#11 Library Path
		ConfigWriteStringW ("SecurityTokenLibrary", SecurityTokenLibraryPath[0] ? SecurityTokenLibraryPath : L"");

		// Mount Options
		ConfigWriteInt ("DefaultPRF", DefaultVolumePkcs5);
		ConfigWriteInt ("DefaultTrueCryptMode", DefaultVolumeTrueCryptMode);

		ConfigWriteEnd (hwndDlg);
	}

	if (bHistoryChanged)
	{
		// History
		DumpCombo (GetDlgItem (MainDlg, IDC_VOLUME), IsButtonChecked (GetDlgItem (MainDlg, IDC_NO_HISTORY)));
	}

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

// Returns TRUE if the entire system drive (as opposed to the system partition only) of the currently running OS is (or is to be) encrypted
BOOL WholeSysDriveEncryption (BOOL bSilent)
{
	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.BootDriveLength.QuadPart < 1) // paranoid check
			return FALSE;
		else
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
		return 1;
	}

	if (	BootEncStatus.ConfiguredEncryptedAreaEnd < 0
		||	BootEncStatus.ConfiguredEncryptedAreaStart < 0
		||	BootEncStatus.ConfiguredEncryptedAreaEnd < BootEncStatus.ConfiguredEncryptedAreaStart
		)
		return 1; // we return 1 to avoid devision by zero
	else
		return ((unsigned __int64)(BootEncStatus.ConfiguredEncryptedAreaEnd - BootEncStatus.ConfiguredEncryptedAreaStart)) + 1;
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
		return 0;
	}

	if (	BootEncStatus.EncryptedAreaEnd < 0
		|| BootEncStatus.EncryptedAreaStart < 0
		|| BootEncStatus.EncryptedAreaEnd < BootEncStatus.EncryptedAreaStart
		)
		return 0;
	else
		return ((unsigned __int64)(BootEncStatus.EncryptedAreaEnd - BootEncStatus.EncryptedAreaStart)) + 1;
}


static void PopulateSysEncContextMenu (HMENU popup, BOOL bToolsOnly)
{
	SystemDriveConfiguration config;
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		config = BootEncObj->GetSystemDriveConfiguration();
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
			AppendMenu (popup, MF_SEPARATOR, 0, L"");
		}
	}

	AppendMenuW (popup, MF_STRING, IDM_CHANGE_SYS_PASSWORD, GetString ("IDM_CHANGE_SYS_PASSWORD"));
	// AppendMenuW (popup, MF_STRING, IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO, GetString ("IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO"));

	AppendMenu (popup, MF_SEPARATOR, 0, L"");
	AppendMenuW (popup, MF_STRING, IDM_SYS_ENC_SETTINGS, GetString ("IDM_SYS_ENC_SETTINGS"));

	if (!IsHiddenOSRunning())
	{
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDM_CREATE_RESCUE_DISK, GetString ("IDM_CREATE_RESCUE_DISK"));
		AppendMenuW (popup, MF_STRING, IDM_VERIFY_RESCUE_DISK, GetString ("IDM_VERIFY_RESCUE_DISK"));
		AppendMenuW (popup, MF_STRING, IDM_VERIFY_RESCUE_DISK_ISO, GetString ("IDM_VERIFY_RESCUE_DISK_ISO"));
	}

	if (!bToolsOnly)
	{
		if (SysDriveOrPartitionFullyEncrypted (FALSE) && !IsHiddenOSRunning())
		{
			AppendMenu (popup, MF_SEPARATOR, 0, L"");
			AppendMenuW (popup, MF_STRING, IDM_PERMANENTLY_DECRYPT_SYS, GetString ("PERMANENTLY_DECRYPT"));
		}
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDM_VOLUME_PROPERTIES, GetString ("IDPM_PROPERTIES"));
	}
}


// WARNING: This function may take a long time to complete. To prevent data corruption, it MUST be called before
// mounting a partition (as a regular volume) that is within key scope of system encryption.
// Returns TRUE if the partition can be mounted as a partition within key scope of inactive system encryption.
// If devicePath is empty, the currently selected partition in the GUI is checked.
BOOL CheckSysEncMountWithoutPBA (HWND hwndDlg, const wchar_t *devicePath, BOOL quiet)
{
	BOOL tmpbDevice;
	wchar_t szDevicePath [TC_MAX_PATH+1];
	wchar_t szDiskFile [TC_MAX_PATH+1];

	if (wcslen (devicePath) < 2)
	{
		GetVolumePath (MainDlg, szDevicePath, ARRAYSIZE (szDevicePath));
		CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szDevicePath, &tmpbDevice);

		if (!tmpbDevice)
		{
			if (!quiet)
				Warning ("NO_SYSENC_PARTITION_SELECTED", hwndDlg);

			return FALSE;
		}

		if (LOWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST))) != TC_MLIST_ITEM_FREE)
		{
			if (!quiet)
				Warning ("SELECT_FREE_DRIVE", hwndDlg);

			return FALSE;
		}
	}
	else
		StringCbCopyW (szDevicePath, sizeof(szDevicePath), devicePath);

	wchar_t *partionPortion = wcsrchr (szDevicePath, L'\\');

	if (!partionPortion
		|| !_wcsicmp (partionPortion, L"\\Partition0"))
	{
		// Only partitions are supported (not whole drives)
		if (!quiet)
			Warning ("NO_SYSENC_PARTITION_SELECTED", hwndDlg);

		return FALSE;
	}

	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.DriveMounted)
		{
			int retCode = 0;
			int driveNo;
			wchar_t parentDrivePath [TC_MAX_PATH+1];

			if (swscanf (szDevicePath, L"\\Device\\Harddisk%d\\Partition", &driveNo) != 1)
			{
				if (!quiet)
					Error ("INVALID_PATH", hwndDlg);

				return FALSE;
			}

			StringCbPrintfW (parentDrivePath,
				sizeof (parentDrivePath),
				L"\\Device\\Harddisk%d\\Partition0",
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
					Warning ("MOUNT_WITHOUT_PBA_VOL_ON_ACTIVE_SYSENC_DRIVE", hwndDlg);

				return FALSE;
			}
		}
		else
			return TRUE;
	}
	catch (Exception &e)
	{
		NormalCursor();
		e.Show (hwndDlg);
	}

	return FALSE;
}


// Returns TRUE if the host drive of the specified partition contains a portion of the TrueCrypt Boot Loader
// and if the drive is not within key scope of active system encryption (e.g. the system drive of the running OS).
// If bPrebootPasswordDlgMode is TRUE, this function returns FALSE (because the check would be redundant).
BOOL TCBootLoaderOnInactiveSysEncDrive (wchar_t *szDevicePath)
{
	try
	{
		int driveNo;
		wchar_t parentDrivePath [TC_MAX_PATH+1];

		if (bPrebootPasswordDlgMode)
			return FALSE;


		if (swscanf (szDevicePath, L"\\Device\\Harddisk%d\\Partition", &driveNo) != 1)
			return FALSE;

		StringCbPrintfW (parentDrivePath,
			sizeof (parentDrivePath),
			L"\\Device\\Harddisk%d\\Partition0",
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


BOOL SelectItem (HWND hTree, wchar_t nLetter)
{
	if (nLetter == 0)
	{
		// The caller specified an invalid drive letter (typically because it is unknown).
		// Find out which drive letter is currently selected in the list and use it.
		nLetter = (wchar_t) (HIWORD (GetSelectedLong (hTree)));
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


static void LaunchVolCreationWizard (HWND hwndDlg, const wchar_t *arg, BOOL bElevation)
{
	wchar_t t[TC_MAX_PATH + 1024] = {L'"',0};
	wchar_t *tmp;

	GetModuleFileName (NULL, t+1, ARRAYSIZE(t)-1);

	tmp = wcsrchr (t, L'\\');
	if (tmp)
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		wchar_t formatExeName[64];
		wchar_t* suffix = NULL;
		ZeroMemory (&si, sizeof (si));

		StringCbCopyW (formatExeName, sizeof (formatExeName), L"\\VeraCrypt Format");

		// check if there is a suffix in VeraCrypt file name
		// in order to use the same for "VeraCrypt Format"
		suffix = wcsrchr (tmp + 1, L'-');
		if (suffix)
		{
			StringCbCatW (formatExeName, sizeof (formatExeName), suffix);
			StringCbCatW (formatExeName, sizeof (formatExeName), L"\"");
		}
		else
			StringCbCatW (formatExeName, sizeof (formatExeName), L".exe\"");

		*tmp = 0;
		StringCbCatW (t, sizeof(t), formatExeName);

		if (!FileExists(t))
			Error ("VOL_CREATION_WIZARD_NOT_FOUND", hwndDlg);	// Display a user-friendly error message and advise what to do
		else
		{

			if (bElevation && !IsAdmin() && IsUacSupported())
			{
				LaunchElevatedProcess (hwndDlg, t, arg);
			}
			else
			{
				if (wcslen (arg) > 0)
				{
					StringCbCatW (t, sizeof(t), L" ");
					StringCbCatW (t, sizeof(t), arg);
				}
				if (!CreateProcess (NULL, (LPWSTR) t, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
				{
					handleWin32Error (hwndDlg, SRC_POS);
				}
				else
				{
					CloseHandle (pi.hProcess);
					CloseHandle (pi.hThread);
				}
			}
		}
	}
}

static void LaunchVolExpander (HWND hwndDlg)
{
	wchar_t t[TC_MAX_PATH + TC_MAX_PATH] = {L'"',0};
	wchar_t *tmp;

	GetModuleFileName (NULL, t+1, ARRAYSIZE(t)-1);

	tmp = wcsrchr (t, L'\\');
	if (tmp)
	{
		wchar_t expanderExeName[64];
		wchar_t* suffix = NULL;

		StringCbCopyW (expanderExeName, sizeof (expanderExeName), L"\\VeraCryptExpander");

		// check if there is a suffix in VeraCrypt file name
		// in order to use the same for "VeraCrypt Format"
		suffix = wcsrchr (tmp + 1, L'-');
		if (suffix)
		{
			StringCbCatW (expanderExeName, sizeof (expanderExeName), suffix);
			StringCbCatW (expanderExeName, sizeof (expanderExeName), L"\"");
		}
		else
			StringCbCatW (expanderExeName, sizeof (expanderExeName), L".exe\"");

		*tmp = 0;
		StringCbCatW (t, sizeof(t), expanderExeName);

		if (!FileExists(t))
			Error ("VOL_EXPANDER_NOT_FOUND", hwndDlg);	// Display a user-friendly error message and advise what to do
		else if (((int)ShellExecuteW (NULL, (!IsAdmin() && IsUacSupported()) ? L"runas" : L"open", t, NULL, NULL, SW_SHOW)) <= 32)
		{
			handleWin32Error (hwndDlg, SRC_POS);
		}
	}
}


// Fills drive list
// drive>0 = update only the corresponding drive subitems
void LoadDriveLetters (HWND hwndDlg, HWND hTree, int drive)
{
	// Remember the top-most visible item
	int lastTopMostVisibleItem = ListView_GetTopIndex (hTree);

	wchar_t *szDriveLetters[]=
	{L"A:", L"B:", L"C:", L"D:",
	 L"E:", L"F:", L"G:", L"H:", L"I:", L"J:", L"K:",
	 L"L:", L"M:", L"N:", L"O:", L"P:", L"Q:", L"R:",
	 L"S:", L"T:", L"U:", L"V:", L"W:", L"X:", L"Y:",
	 L"Z:"};

	DWORD dwResult;
	BOOL bResult;
	DWORD dwUsedDrives;
	MOUNT_LIST_STRUCT driver;
	VOLUME_PROPERTIES_STRUCT propSysEnc;
	wchar_t sysDriveLetter = 0;

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

	if ((bResult == FALSE) || (driver.ulMountedDrives >= (1 << 26)))
	{
		KillTimer (MainDlg, TIMER_ID_MAIN);
		KillTimer (hwndDlg, TIMER_ID_UPDATE_DEVICE_LIST);
		handleWin32Error (hTree, SRC_POS);
		AbortProcessSilent();
	}

	LastKnownLogicalDrives = dwUsedDrives = GetUsedLogicalDrives ();
	if (dwUsedDrives == 0)
			Warning ("DRIVELETTERS", hwndDlg);

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
			wchar_t szTmp[1024];
			wchar_t szTmpW[1024];

			memset(&listItem, 0, sizeof(listItem));

			listItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			listItem.iImage = 2;
			listItem.iItem = item++;

			listItem.pszText = szTmp;
			szTmp[0] = L' ';
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

			ListSubItemSet (hTree, listItem.iItem, 1, szTmpW);

			GetSizeString (GetSysEncDeviceSize(TRUE), szTmpW, sizeof(szTmpW));
			ListSubItemSet (hTree, listItem.iItem, 2, szTmpW);

			if (propSysEnc.ea >= EAGetFirst() && propSysEnc.ea <= EAGetCount())
			{
				EAGetName (szTmp, propSysEnc.ea, 1);
			}
			else
			{
				szTmp[0] = L'?';
				szTmp[1] = 0;
			}
			listItem.iSubItem = 3;
			ListView_SetItem (hTree, &listItem);

			ListSubItemSet (hTree, listItem.iItem, 4, GetString (IsHiddenOSRunning() ? "HIDDEN" : "SYSTEM_VOLUME_TYPE_ADJECTIVE"));
		}
	}

	/* Drive letters */

	for (i = 0; i < 26; i++)
	{
		int curDrive = 0;

		BOOL bSysEncPartition = (bSysEnc && !bWholeSysDriveEncryption && sysDriveLetter == *((wchar_t *) szDriveLetters[i]));

		if (drive > 0)
		{
			LVITEM tmp;
			memset(&tmp, 0, sizeof(LVITEM));
			tmp.mask = LVIF_PARAM;
			tmp.iItem = item;
			if (ListView_GetItem (hTree, &tmp))
				curDrive = HIWORD(tmp.lParam);
		}

		if (((driver.ulMountedDrives & (1 << i)) && (IsNullTerminateString (driver.wszVolume[i], TC_MAX_PATH)))
			|| bSysEncPartition)
		{
			wchar_t szTmp[1024];
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
				i + L'A');

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

				ListSubItemSet (hTree, listItem.iItem, 1, szTmpW);
			}
			else
			{
				wchar_t *path = driver.wszVolume[i];

				if (wmemcmp (path, L"\\??\\", 4) == 0)
					path += 4;

				listItem.iSubItem = 1;

				// first check label used for mounting. If empty, look for it in favorites.
				bool useInExplorer = false;
				wstring label = (wchar_t *) driver.wszLabel[i];
				if (label.empty())
					label = GetFavoriteVolumeLabel (path, useInExplorer);
				if (!label.empty())
					ListSubItemSet (hTree, listItem.iItem, 1, (wchar_t *) label.c_str());
				else
					ListSubItemSet (hTree, listItem.iItem, 1, (wchar_t *) FitPathInGfxWidth (hTree, hUserFont, ListView_GetColumnWidth (hTree, 1) - GetTextGfxWidth (hTree, L"___", hUserFont), path).c_str());
			}

			GetSizeString (bSysEncPartition ? GetSysEncDeviceSize(TRUE) : driver.diskLength[i], szTmpW, sizeof(szTmpW));
			ListSubItemSet (hTree, listItem.iItem, 2, szTmpW);

			EAGetName (szTmp, bSysEncPartition ? propSysEnc.ea : driver.ea[i], 1);
			listItem.iSubItem = 3;
			ListView_SetItem (hTree, &listItem);

			if (bSysEncPartition)
			{
				ws = GetString (IsHiddenOSRunning() ? "HIDDEN" : "SYSTEM_VOLUME_TYPE_ADJECTIVE");
				VolumeNotificationsList.bHidVolDamagePrevReported[i] = FALSE;
				ListSubItemSet (hTree, listItem.iItem, 4, ws);
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

				if (driver.truecryptMode[i])
				{
					StringCbPrintfW (szTmpW, sizeof(szTmpW), L"TrueCrypt-%s", ws);
					ListSubItemSet (hTree, listItem.iItem, 4, szTmpW);
				}
				else
					ListSubItemSet (hTree, listItem.iItem, 4, ws);

				if (driver.volumeType[i] == PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED)	// Normal/outer volume (hidden volume protected AND write denied)
				{
					if (!VolumeNotificationsList.bHidVolDamagePrevReported[i])
					{
						wchar_t szTmp[4096];

						VolumeNotificationsList.bHidVolDamagePrevReported[i] = TRUE;
						StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), i+L'A');
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
				listItem.pszText = L"";
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

	if (bSysEncPwdChangeDlgMode)
	{
		// System

		try
		{
			VOLUME_PROPERTIES_STRUCT properties;
			BootEncObj->GetVolumeProperties(&properties);
			pThreadParam->old_pkcs5 = properties.pkcs5;
		}
		catch(...)
		{}

		pThreadParam->pkcs5 = 0;	// PKCS-5 PRF unchanged (currently we can't change PRF of system encryption)

		try
		{
			*pThreadParam->pnStatus = BootEncObj->ChangePassword (pThreadParam->oldPassword, pThreadParam->old_pkcs5, pThreadParam->old_pim, pThreadParam->newPassword, pThreadParam->pkcs5, pThreadParam->pim, pThreadParam->wipePassCount, hwndDlg);
		}
		catch (Exception &e)
		{
			e.Show (hwndDlg);
			*(pThreadParam->pnStatus) = ERR_OS_ERROR;
		}
	}
	else
	{
		// Non-system

		*pThreadParam->pnStatus = ChangePwd (szFileName, pThreadParam->oldPassword, pThreadParam->old_pkcs5, pThreadParam->old_pim, pThreadParam->truecryptMode, pThreadParam->newPassword, pThreadParam->pkcs5, pThreadParam->pim, pThreadParam->wipePassCount, hwndDlg);

		if (*pThreadParam->pnStatus == ERR_OS_ERROR
			&& GetLastError () == ERROR_ACCESS_DENIED
			&& IsUacSupported ()
			&& IsVolumeDeviceHosted (szFileName))
		{
			*pThreadParam->pnStatus = UacChangePwd (szFileName, pThreadParam->oldPassword, pThreadParam->old_pkcs5, pThreadParam->old_pim, pThreadParam->truecryptMode, pThreadParam->newPassword, pThreadParam->pkcs5, pThreadParam->pim, pThreadParam->wipePassCount, hwndDlg);
		}
	}
}

// implementation for support of backup header operation in wait dialog mechanism

typedef struct
{
	BOOL bRequireConfirmation;
	wchar_t *lpszVolume;
	size_t cchVolume;
	int* iResult;
} BackupHeaderThreadParam;

void CALLBACK BackupHeaderWaitThreadProc(void* pArg, HWND hwndDlg)
{
	BackupHeaderThreadParam* pThreadParam = (BackupHeaderThreadParam*) pArg;

	if (TranslateVolumeID (hwndDlg, pThreadParam->lpszVolume, pThreadParam->cchVolume))
	{
		if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (pThreadParam->lpszVolume))
			*(pThreadParam->iResult) = UacBackupVolumeHeader (hwndDlg, pThreadParam->bRequireConfirmation, pThreadParam->lpszVolume);
		else
			*(pThreadParam->iResult) = BackupVolumeHeader (hwndDlg, pThreadParam->bRequireConfirmation, pThreadParam->lpszVolume);
	}
	else
		*(pThreadParam->iResult) = ERR_OS_ERROR;
}

// implementation for support of restoring header operation in wait dialog mechanism

typedef struct
{
	wchar_t *lpszVolume;
	size_t cchVolume;
	int* iResult;
} RestoreHeaderThreadParam;

void CALLBACK RestoreHeaderWaitThreadProc(void* pArg, HWND hwndDlg)
{
	RestoreHeaderThreadParam* pThreadParam = (RestoreHeaderThreadParam*) pArg;

	if (TranslateVolumeID (hwndDlg, pThreadParam->lpszVolume, pThreadParam->cchVolume))
	{
		if (!IsAdmin () && IsUacSupported () && IsVolumeDeviceHosted (pThreadParam->lpszVolume))
			*(pThreadParam->iResult) = UacRestoreVolumeHeader (hwndDlg, pThreadParam->lpszVolume);
		else
			*(pThreadParam->iResult) = RestoreVolumeHeader (hwndDlg, pThreadParam->lpszVolume);
	}
	else
		*(pThreadParam->iResult) = ERR_OS_ERROR;
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

			SendMessage (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_VERIFY), EM_LIMITTEXT, MAX_PASSWORD, 0);
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

			if (bSysEncPwdChangeDlgMode)
			{
				/* No support for changing the password of TrueCrypt system partition */
				SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_TRUECRYPT_MODE), FALSE);

				ToBootPwdField (hwndDlg, IDC_PASSWORD);
				ToBootPwdField (hwndDlg, IDC_VERIFY);
				ToBootPwdField (hwndDlg, IDC_OLD_PASSWORD);

				if ((DWORD) GetKeyboardLayout (NULL) != 0x00000409 && (DWORD) GetKeyboardLayout (NULL) != 0x04090409)
				{
					DWORD keybLayout = (DWORD) LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", hwndDlg);
						EndDialog (hwndDlg, IDCANCEL);
						return 0;
					}

					bKeyboardLayoutChanged = TRUE;
				}


				/* for system encryption, we can't change the PRF */
				EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDT_NEW_PKCS5_PRF), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_OLD_PRF_ID), FALSE);

				if (SetTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
				{
					Error ("CANNOT_SET_TIMER", hwndDlg);
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
					wchar_t tmp[MAX_PASSWORD+1];
					wmemset (tmp, L'X', MAX_PASSWORD);
					tmp [MAX_PASSWORD] = 0;
					SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), tmp);
					SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), tmp);

					SetWindowText (GetDlgItem (hwndDlg, IDC_OLD_PASSWORD), L"");
					SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD), L"");
					SetWindowText (GetDlgItem (hwndDlg, IDC_VERIFY), L"");

					keybLayout = (DWORD) LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", hwndDlg);
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
			if (bSysEncPwdChangeDlgMode)
			{
				Warning ("KEYFILES_NOT_SUPPORTED_FOR_SYS_ENCRYPTION", hwndDlg);
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
				Warning ("KEYFILES_NOT_SUPPORTED_FOR_SYS_ENCRYPTION", hwndDlg);
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
					int new_hash_algo_id = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, 
						SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

					if (new_hash_algo_id != 0 && !bSystemIsGPT && !HashForSystemEncryption(new_hash_algo_id))
					{
						int new_hash_algo_id = DEFAULT_HASH_ALGORITHM_BOOT;
						Info ("ALGO_NOT_SUPPORTED_FOR_SYS_ENCRYPTION", hwndDlg);
						SelectAlgo (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), &new_hash_algo_id);
					}
				}
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

			if (bSysEncPwdChangeDlgMode && !CheckPasswordCharEncoding (GetDlgItem (hwndDlg, IDC_PASSWORD), NULL))
			{
				Error ("UNSUPPORTED_CHARS_IN_PWD", hwndDlg);
				return 1;
			}

			if (bSysEncPwdChangeDlgMode && (pim > MAX_BOOT_PIM_VALUE))
			{
				SetFocus (GetDlgItem(hwndDlg, IDC_PIM));
				Error ("PIM_SYSENC_TOO_BIG", hwndDlg);
				return 1;
			}

			if (!bSysEncPwdChangeDlgMode && (pim > MAX_PIM_VALUE))
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
				if (bSysEncPwdChangeDlgMode)
				{
					try
					{
						VOLUME_PROPERTIES_STRUCT properties;
						BootEncObj->GetVolumeProperties(&properties);
						bootPRF = properties.pkcs5;
					}
					catch(...)
					{}
				}
				if (!CheckPasswordLength (hwndDlg, GetWindowTextLength(GetDlgItem (hwndDlg, IDC_PASSWORD)), pim, bSysEncPwdChangeDlgMode, bootPRF, FALSE, FALSE))
					return 1;
			}

			GetVolumePath (hParent, szFileName, ARRAYSIZE (szFileName));

			if (GetPassword (hwndDlg, IDC_OLD_PASSWORD, (LPSTR) oldPassword.Text, sizeof (oldPassword.Text), TRUE))
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
				if (GetPassword (hwndDlg, IDC_PASSWORD, (LPSTR) newPassword.Text, sizeof (newPassword.Text), TRUE))
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

static wchar_t PasswordDlgVolume[MAX_PATH + 1];
static BOOL PasswordDialogDisableMountOptions;
static char *PasswordDialogTitleStringId;

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
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
			int i, nIndex, defaultPrfIndex = 0;
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
				RECT rect;
				GetWindowRect (hwndDlg, &rect);

				bool useInExplorer = false;
				wstring label = GetFavoriteVolumeLabel (PasswordDlgVolume, useInExplorer);
				if (!label.empty())
				{
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR_LABEL"), label.c_str());
					if (useInExplorer)
						StringCbCopyW (mountOptions.Label, sizeof (mountOptions.Label), label.c_str());
				}
				else
				{
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), L"___");
					StringCbPrintfW (s, sizeof(s), GetString ("ENTER_PASSWORD_FOR"), FitPathInGfxWidth (hwndDlg, WindowTitleBarFont, rect.right - rect.left - GetTextGfxWidth (hwndDlg, s, WindowTitleBarFont), PasswordDlgVolume).c_str());
				}

				SetWindowTextW (hwndDlg, s);
			}

			/* Populate the PRF algorithms list */
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				if (*pkcs5 && (*pkcs5 == i))
					defaultPrfIndex = nIndex;
			}

			/* make autodetection the default unless a specific PRF was specified in the command line */
			SendMessage (hComboBox, CB_SETCURSEL, defaultPrfIndex, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PASSWORD), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_CACHE), BM_SETCHECK, bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_PIM), EM_LIMITTEXT, MAX_PIM, 0);

			SetPim (hwndDlg, IDC_PIM, *pim);

			/* make PIM field visible if a PIM value has been explicitely specified */
			if (*pim > 0)
			{
				SetCheckBox (hwndDlg, IDC_PIM_ENABLE, TRUE);
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
				/* Disable TrueCrypt mode option in case of backup/restore header operation */
				SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_TRUECRYPT_MODE), FALSE);
			}
			else if (*truecryptMode)
			{
				/* Check TrueCryptMode if it is enabled on the command line */
				SetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE, TRUE);
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
			/* Repopulate the PRF algorithms list with algorithms that support system encryption */
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			int i, defaultPrfIndex = 0, nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				if (bSystemIsGPT || HashForSystemEncryption(i))
				{
					nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
					SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
					if (*pkcs5 && (*pkcs5 == i))
						defaultPrfIndex = nIndex;
				}
			}

			/* make autodetection the default unless a specific PRF was specified in the command line */
			SendMessage (hComboBox, CB_SETCURSEL, defaultPrfIndex, 0);

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
			/* Use default PRF specified by the user if any */
			if (mountOptions.ProtectedHidVolPkcs5Prf == 0)
				mountOptions.ProtectedHidVolPkcs5Prf = *pkcs5;
			if (mountOptions.ProtectedHidVolPim == 0)
				mountOptions.ProtectedHidVolPim = *pim;
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

		if (lw == IDC_TRUECRYPT_MODE)
		{
			BOOL bEnablePim = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE) ? FALSE: TRUE;
			EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), bEnablePim);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), bEnablePim);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), bEnablePim);
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
				if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
					KeyFilesApply (hwndDlg, &mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, wcslen (PasswordDlgVolume) > 0 ? PasswordDlgVolume : NULL);

				if (GetPassword (hwndDlg, IDC_PASSWORD, (LPSTR) szXPwd->Text, MAX_PASSWORD + 1, TRUE))
					szXPwd->Length = (unsigned __int32) strlen ((char *) szXPwd->Text);
				else
					return 1;

				bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_CACHE));
				*pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);
				*truecryptMode = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE);

				*pim = GetPim (hwndDlg, IDC_PIM, 0);

				/* check that PRF is supported in TrueCrypt Mode */
				if (	(*truecryptMode)
					&& ((!is_pkcs5_prf_supported (*pkcs5, TRUE, PRF_BOOT_NO)) || (mountOptions.ProtectHiddenVolume && !is_pkcs5_prf_supported (mountOptions.ProtectedHidVolPkcs5Prf, TRUE, PRF_BOOT_NO)))
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

static void PreferencesDlgEnableButtons (HWND hwndDlg)
{
	BOOL back = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
	BOOL idle = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
	BOOL installed = !IsNonInstallMode();
	BOOL wtsEnabled = (hWtsLib != NULL) ? TRUE : FALSE;

	EnableWindow (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL), back && installed);
	EnableWindow (GetDlgItem (hwndDlg, IDT_LOGON), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_START), back && installed);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_LOGON_MOUNT_DEVICES), installed);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT), back);
	EnableWindow (GetDlgItem (hwndDlg, IDT_AUTO_DISMOUNT_ON), back);
	EnableWindow (GetDlgItem (hwndDlg, IDT_MINUTES), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF), back);
	EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SESSION_LOCKED), back && wtsEnabled);
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

			SendMessage (GetDlgItem (hwndDlg, IDC_SHOW_DISCONNECTED_NETWORK_DRIVES), BM_SETCHECK,
				bShowDisconnectedNetworkDrives ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_HIDE_WAITING_DIALOG), BM_SETCHECK,
				bHideWaitingDialog ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_SECURE_DESKTOP_PASSWORD_ENTRY), BM_SETCHECK,
				bUseSecureDesktop ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_TEMP_CACHE_ON_MULTIPLE_MOUNT), BM_SETCHECK,
						bCacheDuringMultipleMount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT), BM_SETCHECK,
						bWipeCacheOnExit ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT), BM_SETCHECK,
						bWipeCacheOnAutoDismount ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS), BM_SETCHECK,
						bCacheInDriver ? BST_CHECKED:BST_UNCHECKED, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PIM), BM_SETCHECK,
						bIncludePimInCache? BST_CHECKED:BST_UNCHECKED, 0);

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

			SendMessage (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SESSION_LOCKED), BM_SETCHECK,
						bDismountOnSessionLocked ? BST_CHECKED:BST_UNCHECKED, 0);

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
			if (AskWarnNoYes ("CONFIRM_BACKGROUND_TASK_DISABLED", hwndDlg) == IDNO)
				SetCheckBox (hwndDlg, IDC_PREF_BKG_TASK_ENABLE, TRUE);
		}

		// Forced dismount disabled warning
		if (lw == IDC_PREF_DISMOUNT_INACTIVE
			|| lw == IDC_PREF_DISMOUNT_LOGOFF
			|| lw == IDC_PREF_DISMOUNT_SESSION_LOCKED
			|| lw == IDC_PREF_DISMOUNT_POWERSAVING
			|| lw == IDC_PREF_DISMOUNT_SCREENSAVER
			|| lw == IDC_PREF_FORCE_AUTO_DISMOUNT)
		{
			BOOL i = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_INACTIVE));
			BOOL l = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF));
			BOOL sl = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SESSION_LOCKED));
			BOOL p = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_POWERSAVING));
			BOOL s = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SCREENSAVER));
			BOOL q = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT));

			if (!q)
			{
				if (lw == IDC_PREF_FORCE_AUTO_DISMOUNT && (i || l || sl || p || s))
				{
					if (AskWarnNoYes ("CONFIRM_NO_FORCED_AUTODISMOUNT", hwndDlg) == IDNO)
						SetCheckBox (hwndDlg, IDC_PREF_FORCE_AUTO_DISMOUNT, TRUE);
				}
				else if ((lw == IDC_PREF_DISMOUNT_INACTIVE && i
					|| lw == IDC_PREF_DISMOUNT_LOGOFF && l
					|| lw == IDC_PREF_DISMOUNT_SESSION_LOCKED && sl
					|| lw == IDC_PREF_DISMOUNT_POWERSAVING && p
					|| lw == IDC_PREF_DISMOUNT_SCREENSAVER && s))
					Warning ("WARN_PREF_AUTO_DISMOUNT", hwndDlg);
			}

			if (p && lw == IDC_PREF_DISMOUNT_POWERSAVING)
				Warning ("WARN_PREF_AUTO_DISMOUNT_ON_POWER", hwndDlg);
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
			bShowDisconnectedNetworkDrives = IsButtonChecked (GetDlgItem (hwndDlg, IDC_SHOW_DISCONNECTED_NETWORK_DRIVES));
			bHideWaitingDialog = IsButtonChecked (GetDlgItem (hwndDlg, IDC_HIDE_WAITING_DIALOG));
			bUseSecureDesktop = IsButtonChecked (GetDlgItem (hwndDlg, IDC_SECURE_DESKTOP_PASSWORD_ENTRY));
			bCacheDuringMultipleMount	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_TEMP_CACHE_ON_MULTIPLE_MOUNT));
			bWipeCacheOnExit				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_EXIT));
			bWipeCacheOnAutoDismount		= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_WIPE_CACHE_ON_AUTODISMOUNT));
			bCacheInDriverDefault = bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PASSWORDS));
			bIncludePimInCache = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PIM));
			defaultMountOptions.ReadOnly	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_READONLY));
			defaultMountOptions.Removable	= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_MOUNT_REMOVABLE));
			bEnableBkgTask				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_BKG_TASK_ENABLE));
			bCloseBkgTaskWhenNoVolumes	= IsNonInstallMode() ? bCloseBkgTaskWhenNoVolumes : IsButtonChecked (GetDlgItem (hwndDlg, IDC_CLOSE_BKG_TASK_WHEN_NOVOL));
			bDismountOnLogOff				= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_LOGOFF));
			bDismountOnSessionLocked		= IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_DISMOUNT_SESSION_LOCKED));
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
				AppendMenuW (popup, MF_STRING, IDM_DEFAULT_MOUNT_PARAMETERS, GetString ("IDM_DEFAULT_MOUNT_PARAMETERS"));
				AppendMenuW (popup, MF_STRING, IDM_TOKEN_PREFERENCES, GetString ("IDM_TOKEN_PREFERENCES"));

				RECT rect;
				GetWindowRect (GetDlgItem (hwndDlg, IDC_MORE_SETTINGS), &rect);

				int menuItem = TrackPopupMenu (popup, TPM_RETURNCMD | TPM_LEFTBUTTON, rect.left + 2, rect.top + 2, 0, hwndDlg, NULL);
				DestroyMenu (popup);

				SendMessage (MainDlg, WM_COMMAND, menuItem, (LPARAM) hwndDlg);
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

			SetDlgItemTextW (hwndDlg, IDC_VOLUME_LABEL, mountOptions->Label);
			SendDlgItemMessage (hwndDlg, IDC_VOLUME_LABEL, EM_LIMITTEXT, 32, 0); // 32 is the maximum possible length for a drive label in Windows

			/* Add PRF algorithm list for hidden volume password */
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			int i, nSelectedIndex = 0, nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				/* if a PRF was selected previously, select it */
				if (i == mountOptions->ProtectedHidVolPkcs5Prf)
					nSelectedIndex = nIndex;
			}

			SendMessage (hComboBox, CB_SETCURSEL, nSelectedIndex, 0);

			protect = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));

			EnableWindow (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_VOL_PROTECTION), !IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY)));
			EnableWindow (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PASSWORD_MO), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_HIDDEN_PROT_PASSWD), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_HIDVOL_PROT), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), protect);

			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE_HIDVOL_PROT, hidVolProtKeyFilesParam.EnableKeyFiles);

			SendDlgItemMessage (hwndDlg, IDC_PASSWORD_PROT_HIDVOL, EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendDlgItemMessage (hwndDlg, IDC_PIM, EM_LIMITTEXT, MAX_PIM, 0);

			if (mountOptions->ProtectedHidVolPassword.Length > 0)
			{
				wchar_t szTmp[MAX_PASSWORD + 1];
				if (0 == MultiByteToWideChar (CP_UTF8, 0, (LPSTR) mountOptions->ProtectedHidVolPassword.Text, -1, szTmp, MAX_PASSWORD + 1))
					szTmp [0] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), szTmp);
				burn (szTmp, sizeof (szTmp));
			}

			SetPim (hwndDlg, IDC_PIM, mountOptions->ProtectedHidVolPim);

			/* make PIM field visible if a PIM value has been explicitely specified */
			if (mountOptions->ProtectedHidVolPim > 0)
			{
				SetCheckBox (hwndDlg, IDC_PIM_ENABLE, TRUE);
				ShowWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), SW_SHOW);
			}

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
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD_MO, IDC_PASSWORD_PROT_HIDVOL, IDC_PIM);
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

		if (lw == IDC_LINK_HIDVOL_PROTECTION_INFO)
		{
			Applink ("hiddenvolprotection");
		}

		if (lw == IDCANCEL)
		{
			wchar_t tmp[MAX_PASSWORD+1];

			// Cleanup
			wmemset (tmp, L'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);

			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDOK)
		{
			wchar_t tmp[MAX_PASSWORD+1];

			mountOptions->ReadOnly = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY));
			mountOptions->Removable = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_REMOVABLE));
			mountOptions->ProtectHiddenVolume = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PROTECT_HIDDEN_VOL));
			mountOptions->PartitionInInactiveSysEncScope = IsButtonChecked (GetDlgItem (hwndDlg, IDC_MOUNT_SYSENC_PART_WITHOUT_PBA));
			mountOptions->UseBackupHeader = IsButtonChecked (GetDlgItem (hwndDlg, IDC_USE_EMBEDDED_HEADER_BAK));

			GetDlgItemTextW (hwndDlg, IDC_VOLUME_LABEL, mountOptions->Label, sizeof (mountOptions->Label) /sizeof (wchar_t));

			if (mountOptions->ProtectHiddenVolume)
			{
				GetPassword (hwndDlg, IDC_PASSWORD_PROT_HIDVOL,
					(LPSTR) mountOptions->ProtectedHidVolPassword.Text, MAX_PASSWORD + 1,
					FALSE);

				mountOptions->ProtectedHidVolPassword.Length = (unsigned __int32) strlen ((char *) mountOptions->ProtectedHidVolPassword.Text);

				mountOptions->ProtectedHidVolPkcs5Prf = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

				mountOptions->ProtectedHidVolPim = GetPim (hwndDlg, IDC_PIM, 0);
			}

			// Cleanup
			wmemset (tmp, L'X', MAX_PASSWORD);
			tmp[MAX_PASSWORD] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_PASSWORD_PROT_HIDVOL), tmp);

			if ((mountOptions->ProtectHiddenVolume && !bEnableBkgTask)
				&& (AskWarnYesNo ("HIDVOL_PROT_BKG_TASK_WARNING", hwndDlg) == IDYES))
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
			EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), protect);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_ENABLE), protect);

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
		if (	(prop.driveNo == nDosDriveNo)
			&&	(prop.ea >= EAGetFirst() && prop.ea <= EAGetCount())
			)
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
		if (	(prop.driveNo == nDosDriveNo)
			&&	(prop.ea >= EAGetFirst() && prop.ea <= EAGetCount())
			&&	(prop.mode >= FIRST_MODE_OF_OPERATION_ID && prop.mode < MODE_ENUM_END_ID)
			)
		{
			return prop.mode;
		}
	}

	return 0;
}

void DisplayVolumePropertiesListContextMenu (HWND hwndDlg, LPARAM lParam)
{
	/* Volume Properties list context menu */
	DWORD mPos;
	int menuItem;
	HWND hList = GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES_LIST);
	int hItem = ListView_GetSelectionMark (hList);

	SetFocus (hList);

	if (hItem >= 0)
	{
		HMENU popup = CreatePopupMenu ();
		AppendMenuW (popup, MF_STRING, IDPM_COPY_VALUE_TO_CLIPBOARD, GetString ("IDPM_COPY_VALUE_TO_CLIPBOARD"));

		if (lParam)
		{
			mPos=GetMessagePos();
		}
		else
		{
			POINT pt = {0};
			if (ListView_GetItemPosition (hList, hItem, &pt))
			{
				pt.x += 2 + ::GetSystemMetrics(SM_CXICON);
				pt.y += 2;
			}
			ClientToScreen (hList, &pt);
			mPos  = MAKELONG (pt.x, pt.y);
		}

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
		case IDPM_COPY_VALUE_TO_CLIPBOARD:
			{
				wchar_t valueText[256] = {0};
				ListView_GetItemText (hList, hItem, 1, valueText, ARRAYSIZE (valueText));
				CopyTextToClipboard (valueText);
			}
			break;
		}
	}
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
			wchar_t szTmp[1024];
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
			prop.driveNo = HIWORD (GetSelectedLong (GetDlgItem (GetParent(hwndDlg), IDC_DRIVELIST))) - L'A';

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
			ListItemAdd (list, i, GetString ("LOCATION"));
			if (bSysEnc)
				ListSubItemSet (list, i++, 1, GetString (bSysEncWholeDrive ? "SYSTEM_DRIVE" : IsHiddenOSRunning() ? "HIDDEN_SYSTEM_PARTITION" : "SYSTEM_PARTITION"));
			else
				ListSubItemSet (list, i++, 1, (wchar_t *) (prop.wszVolume[1] != L'?' ? prop.wszVolume : prop.wszVolume + 4));

			if (!bSysEnc && IsVolumeDeviceHosted ((wchar_t *) (prop.wszVolume[1] != L'?' ? prop.wszVolume : prop.wszVolume + 4)))
			{
				// Volume ID
				std::wstring hexID = ArrayToHexWideString (prop.volumeID, sizeof (prop.volumeID));
				ListItemAdd (list, i, GetString ("VOLUME_ID"));

				ListSubItemSet (list, i++, 1, hexID.c_str());
			}


			// Size
			ListItemAdd (list, i, GetString ("SIZE"));
			StringCbPrintfW (sw, sizeof(sw), L"%I64u %s", prop.diskLength, GetString ("BYTES"));
			ListSubItemSet (list, i++, 1, sw);

			// Type
			ListItemAdd (list, i, GetString ("TYPE"));
			if (bSysEnc)
				ListSubItemSet (list, i++, 1, GetString (IsHiddenOSRunning() ? "TYPE_HIDDEN_SYSTEM_ADJECTIVE" : "SYSTEM_VOLUME_TYPE_ADJECTIVE"));
			else
			{
				bool truecryptMode = prop.pkcs5Iterations == get_pkcs5_iteration_count(prop.pkcs5, 0, TRUE, prop.partitionInInactiveSysEncScope);
				s = prop.hiddenVolume ? GetString ("HIDDEN") :
					(prop.hiddenVolProtection != HIDVOL_PROT_STATUS_NONE ? GetString ("OUTER") : GetString ("NORMAL"));

				if (truecryptMode)
				{
					StringCbPrintfW (sw, sizeof(sw), L"TrueCrypt - %s", s);
					ListSubItemSet (list, i++, 1, sw);
				}
				else
					ListSubItemSet (list, i++, 1, s);
			}

			if (!bSysEnc)
			{
				// Write protection
				ListItemAdd (list, i, GetString ("READ_ONLY"));

				if (prop.readOnly || prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
					s = GetString ("UISTR_YES");
				else
					s = GetString ("UISTR_NO");

				ListSubItemSet (list, i++, 1, s);

				// Hidden Volume Protection
				ListItemAdd (list, i, GetString ("HIDDEN_VOL_PROTECTION"));
				if (prop.hiddenVolume)
					s = GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_NONE)
					s = GetString ("UISTR_NO");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTIVE)
					s = GetString ("UISTR_YES");
				else if (prop.hiddenVolProtection == HIDVOL_PROT_STATUS_ACTION_TAKEN)
					s = GetString ("HID_VOL_DAMAGE_PREVENTED");

				ListSubItemSet (list, i++, 1, s);
			}

			// Encryption algorithm
			ListItemAdd (list, i, GetString ("ENCRYPTION_ALGORITHM"));

			if (prop.ea < EAGetFirst() || prop.ea > EAGetCount ())
			{
				ListSubItemSet (list, i, 1, L"?");
				return 1;
			}

			EAGetName (szTmp, prop.ea, 1);
			ListSubItemSet (list, i++, 1, szTmp);

			// Key size(s)
			{
				wchar_t name[128];
				int size = EAGetKeySize (prop.ea);
				EAGetName (name, prop.ea, 1);

				// Primary key
				ListItemAdd (list, i, GetString ("KEY_SIZE"));
				StringCbPrintfW (sw, sizeof(sw), L"%d %s", size * 8, GetString ("BITS"));
				ListSubItemSet (list, i++, 1, sw);

				if (wcscmp (EAGetModeName (prop.ea, prop.mode, TRUE), L"XTS") == 0)
				{
					// Secondary key (XTS)

					ListItemAdd (list, i, GetString ("SECONDARY_KEY_SIZE_XTS"));
					ListSubItemSet (list, i++, 1, sw);
				}
			}

			// Block size
			ListItemAdd (list, i, GetString ("BLOCK_SIZE"));

			StringCbPrintfW (sw, sizeof(sw), L"%d ", CipherGetBlockSize (EAGetFirstCipher(prop.ea))*8);
			StringCbCatW (sw, sizeof(sw), GetString ("BITS"));
			ListSubItemSet (list, i++, 1, sw);

			// Mode
			ListItemAdd (list, i, GetString ("MODE_OF_OPERATION"));
			ListSubItemSet (list, i++, 1, EAGetModeName (prop.ea, prop.mode, TRUE));

			// PKCS 5 PRF
			ListItemAdd (list, i, GetString ("PKCS5_PRF"));
			if (prop.volumePim == 0)
				ListSubItemSet (list, i++, 1, get_pkcs5_prf_name (prop.pkcs5));
			else
			{
				StringCbPrintfW (szTmp, sizeof(szTmp), L"%s (Dynamic)", get_pkcs5_prf_name (prop.pkcs5));
				ListSubItemSet (list, i++, 1, szTmp);
			}

#if 0
			// PCKS 5 iterations
			ListItemAdd (list, i, GetString ("PKCS5_ITERATIONS"));
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
				ListItemAdd (list, i, GetString ("VOLUME_CREATE_DATE"));
				*(unsigned __int64 *)(&ft) = prop.volumeCreationTime;
				FileTimeToSystemTime (&ft, &st);
				GetDateFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				swprintf (date, L"%s ", sw);
				GetTimeFormatW (LOCALE_USER_DEFAULT, 0, &st, 0, sw, sizeof (sw)/2);
				wcscat (date, sw);
				ListSubItemSet (list, i++, 1, date);

				// Header date
				ListItemAdd (list, i, GetString ("VOLUME_HEADER_DATE"));
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
				ListSubItemSet (list, i++, 1, date);
			}
#endif // 0

			if (!bSysEnc || IsHiddenOSRunning())
			{
				// Volume format version
				ListItemAdd (list, i, GetString ("VOLUME_FORMAT_VERSION"));
				StringCbPrintfW (szTmp, sizeof(szTmp), L"%d", prop.volFormatVersion);
				ListSubItemSet (list, i++, 1, szTmp);

				// Backup header
				ListItemAdd (list, i, GetString ("BACKUP_HEADER"));
				ListSubItemSet (list, i++, 1, GetString (prop.volFormatVersion > 1 ? "UISTR_YES" : "UISTR_NO"));
			}

			// Total data read
			ListItemAdd (list, i, GetString ("TOTAL_DATA_READ"));
			GetSizeString (prop.totalBytesRead, sw, sizeof(sw));
			ListSubItemSet (list, i++, 1, sw);

			// Total data written
			ListItemAdd (list, i, GetString ("TOTAL_DATA_WRITTEN"));
			GetSizeString (prop.totalBytesWritten, sw, sizeof(sw));
			ListSubItemSet (list, i++, 1, sw);

			if (bSysEnc)
			{
				// TrueCrypt Boot Loader version
				ListItemAdd (list, i, GetString ("VC_BOOT_LOADER_VERSION"));
				ListSubItemSet (list, i++, 1, GetUserFriendlyVersionString (BootEncStatus.BootLoaderVersion).c_str());

				// Encrypted portion
				ListItemAdd (list, i, GetString ("ENCRYPTED_PORTION"));
				if (GetSysEncDeviceEncryptedPartSize (FALSE) == GetSysEncDeviceSize (FALSE))
					ListSubItemSet (list, i++, 1, GetString ("ENCRYPTED_PORTION_FULLY_ENCRYPTED"));
				else if (GetSysEncDeviceEncryptedPartSize (FALSE) <= 1)
					ListSubItemSet (list, i++, 1, GetString ("ENCRYPTED_PORTION_NOT_ENCRYPTED"));
				else
				{

					StringCbPrintfW (sw,
						sizeof sw,
						GetString ("PROCESSED_PORTION_X_PERCENT"),
						(double) GetSysEncDeviceEncryptedPartSize (FALSE) / (double) GetSysEncDeviceSize (FALSE) * 100.0);

					ListSubItemSet (list, i++, 1, sw);
				}
			}

			return 0;
		}

	case WM_NOTIFY:

		if(wParam == IDC_VOLUME_PROPERTIES_LIST)
		{
			/* Right click */

			switch (((NM_LISTVIEW *) lParam)->hdr.code)
			{
			case NM_RCLICK:
			case LVN_BEGINRDRAG:
				/* If the mouse was moving while the right mouse button is pressed, popup menu would
				not open, because drag&drop operation would be initiated. Therefore, we're handling
				RMB drag-and-drop operations as well. */
				{

					DisplayVolumePropertiesListContextMenu (hwndDlg, lParam);

					return 1;
				}
			}
		}
		return 0;

	case WM_CONTEXTMENU:
		{
			HWND hList = GetDlgItem (hwndDlg, IDC_VOLUME_PROPERTIES_LIST);
			// only handle if it is coming from keyboard and if the drive
			// list has focus. The other cases are handled elsewhere
			if (   (-1 == GET_X_LPARAM(lParam))
				&& (-1 == GET_Y_LPARAM(lParam))
				&& (GetFocus () == hList)
				)
			{
				DisplayVolumePropertiesListContextMenu (hwndDlg, NULL);
			}
		}
		return 0;

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
			WCHAR i;
			int index;
			WCHAR drive[] = { 0, L':', 0 };

			LocalizeDialog (hwndDlg, "IDD_TRAVELER_DLG");

			SendDlgItemMessage (hwndDlg, IDC_COPY_WIZARD, BM_SETCHECK,
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_COPY_EXPANDER, BM_SETCHECK,
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER, BM_SETCHECK,
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_AUTORUN_DISABLE, BM_SETCHECK,
						BST_CHECKED, 0);

			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_RESETCONTENT, 0, 0);

			index = (int) SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) GetString ("FIRST_AVAILABLE"));
			SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) 0);

			for (i = L'A'; i <= L'Z'; i++)
			{
				if (i == L'C')
					continue;
				drive[0] = i;
				index = (int) SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_ADDSTRING, 0, (LPARAM) drive);
				SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_SETITEMDATA, index, (LPARAM) i);
			}

			SendDlgItemMessageW (hwndDlg, IDC_DRIVELIST, CB_SETCURSEL, 0, 0);

			return 0;
		}

	case WM_CTLCOLORSTATIC:
		{
			HDC hdc = (HDC)	wParam;
			HWND hw = (HWND) lParam;
			if (hw == GetDlgItem(hwndDlg, IDC_DIRECTORY))
			{
				// This the directory field. Make its background like normal edit
				HBRUSH hbr = GetSysColorBrush (COLOR_WINDOW);
				::SelectObject(hdc, hbr);
				return (BOOL) hbr;
			}
		}
		return 0;

	case WM_COMMAND:

		if (HIWORD (wParam) == BN_CLICKED
			&& (lw == IDC_AUTORUN_DISABLE || lw == IDC_AUTORUN_MOUNT || lw == IDC_AUTORUN_START ))
		{
			BOOL enabled = IsButtonChecked (GetDlgItem (hwndDlg, IDC_AUTORUN_MOUNT));

			EnableWindow (GetDlgItem (hwndDlg, IDC_BROWSE_FILES), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_VOLUME_NAME), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PIM), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_MOUNT_READONLY), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_DRIVELIST), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TRAVELER_MOUNT), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_LETTER), enabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_MOUNT_SETTINGS), enabled);

			if (!bAutoRunWarningDisplayed
				&& (lw == IDC_AUTORUN_MOUNT || lw == IDC_AUTORUN_START))
			{
				bAutoRunWarningDisplayed = TRUE;
				Warning ("AUTORUN_MAY_NOT_ALWAYS_WORK", hwndDlg);
			}

			return 1;
		}

		if (lw == IDC_BROWSE_FILES)
		{
			wchar_t dstDir[MAX_PATH];
			wchar_t volName[MAX_PATH] = { 0 };

			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstDir, ARRAYSIZE (dstDir));

			if (BrowseFilesInDir (hwndDlg, "OPEN_TITLE", dstDir, volName, bHistory, FALSE, NULL))
				SetDlgItemText (hwndDlg, IDC_VOLUME_NAME, wcschr (volName, L'\\') + 1);

			return 1;
		}

		if (lw == IDC_BROWSE_DIRS)
		{
			wchar_t dstPath[MAX_PATH * 2];
			GetDlgItemText (hwndDlg, IDC_DIRECTORY, dstPath, ARRAYSIZE (dstPath));

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

			BOOL copyWizard, copyExpander, bExplore, bCacheInDriver, bIncludePimInCache, bAutoRun, bAutoMount, bMountReadOnly;
			WCHAR dstDir[MAX_PATH + 1];
			WCHAR srcPath[1024 + MAX_PATH + 1];
			WCHAR dstPath[2*MAX_PATH + 1];
			WCHAR appDir[1024];
			WCHAR volName[MAX_PATH + 2];
			int drive;
			WCHAR* ptr;

			GetDlgItemTextW (hwndDlg, IDC_DIRECTORY, dstDir, array_capacity (dstDir));
			volName[0] = 0;
			GetDlgItemTextW (hwndDlg, IDC_VOLUME_NAME, volName + 1, (array_capacity (volName)) - 1);

			drive = (int) SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETCURSEL, 0, 0);
			drive = (int) SendDlgItemMessage (hwndDlg, IDC_DRIVELIST, CB_GETITEMDATA, drive, 0);

			copyWizard = IsButtonChecked (GetDlgItem (hwndDlg, IDC_COPY_WIZARD));
			copyExpander = IsButtonChecked (GetDlgItem (hwndDlg, IDC_COPY_EXPANDER));
			bExplore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAVEL_OPEN_EXPLORER));
			bCacheInDriver = IsButtonChecked (GetDlgItem (hwndDlg, IDC_TRAV_CACHE_PASSWORDS));
			bIncludePimInCache = IsButtonChecked (GetDlgItem (hwndDlg, IDC_PREF_CACHE_PIM));
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
				volName[0] = L'"';
				StringCbCatW (volName, sizeof(volName), L"\"");
			}

			GetModuleFileNameW (NULL, appDir, array_capacity (appDir));
			if (ptr = wcsrchr (appDir, L'\\'))
				ptr[0] = 0;

			WaitCursor ();

			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt", dstDir);
			if (!CreateDirectoryW (dstPath, NULL))
			{
				handleWin32Error (hwndDlg, SRC_POS);
				goto stop;
			}

			// Main app 32-bit
			if (Is64BitOs () && !IsNonInstallMode ())
				StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt-x86.exe", appDir);
			else
				StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt.exe", appDir);
			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCrypt.exe", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg, SRC_POS);
				goto stop;
			}

			// Main app 64-bit
			if (Is64BitOs () && !IsNonInstallMode ())
				StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt.exe", appDir);
			else
				StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt-x64.exe", appDir);
			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCrypt-x64.exe", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg, SRC_POS);
				goto stop;
			}

			// Wizard
			if (copyWizard)
			{
				// Wizard 32-bit
				if (Is64BitOs () && !IsNonInstallMode ())
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt Format-x86.exe", appDir);
				else
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt Format.exe", appDir);
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCrypt Format.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					goto stop;
				}

				// Wizard 64-bit
				if (Is64BitOs () && !IsNonInstallMode ())
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt Format.exe", appDir);
				else
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCrypt Format-x64.exe", appDir);
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCrypt Format-x64.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					goto stop;
				}
			}

			// Expander
			if (copyExpander)
			{
				// Expander 32-bit
				if (Is64BitOs () && !IsNonInstallMode ())
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCryptExpander-x86.exe", appDir);
				else
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCryptExpander.exe", appDir);
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCryptExpander.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					goto stop;
				}

				// Expander 64-bit
				if (Is64BitOs () && !IsNonInstallMode ())
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCryptExpander.exe", appDir);
				else
					StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\VeraCryptExpander-x64.exe", appDir);
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\VeraCryptExpander-x64.exe", dstDir);
				if (!TCCopyFile (srcPath, dstPath))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					goto stop;
				}
			}

			// Driver
			StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\veracrypt.sys", appDir);
			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\veracrypt.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg, SRC_POS);
				goto stop;
			}

			// Driver x64
			StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\veracrypt-x64.sys", appDir);
			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\veracrypt-x64.sys", dstDir);
			if (!TCCopyFile (srcPath, dstPath))
			{
				handleWin32Error (hwndDlg, SRC_POS);
				goto stop;
			}

			if (strcmp (GetPreferredLangId (), "en") != 0)
			{
				// Language pack
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\Languages", dstDir);
				if (!CreateDirectoryW (dstPath, NULL))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					goto stop;
				}
				StringCbPrintfW (srcPath, sizeof(srcPath), L"%s\\Languages\\Language.%hs.xml", appDir, GetPreferredLangId ());
				StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\VeraCrypt\\Languages\\Language.%hs.xml", dstDir, GetPreferredLangId ());
				TCCopyFile (srcPath, dstPath);
			}

			// AutoRun
			StringCbPrintfW (dstPath, sizeof(dstPath), L"%s\\autorun.inf", dstDir);
			DeleteFileW (dstPath);
			if (bAutoRun)
			{
				FILE *af;
				wchar_t autoMount[2*MAX_PATH + 2];
				wchar_t driveLetter[] = { L' ', L'/', L'l', L' ', (wchar_t) drive, 0 };

				af = _wfopen (dstPath, L"w,ccs=UNICODE");

				if (af == NULL)
				{
					MessageBoxW (hwndDlg, GetString ("CANT_CREATE_AUTORUN"), lpszTitle, MB_ICONERROR);
					goto stop;
				}

				StringCbPrintfW (autoMount, sizeof(autoMount), L"VeraCrypt\\VeraCrypt.exe /q background%s%s%s%s /m rm /v %s",
					drive > 0 ? driveLetter : L"",
					bExplore ? L" /e" : L"",
					bCacheInDriver ? (bIncludePimInCache? L" /c p" : L" /c y") : L"",
					bMountReadOnly ? L" /m ro" : L"",
					volName);

				fwprintf (af, L"[autorun]\nlabel=%s\nicon=VeraCrypt\\VeraCrypt.exe\n", GetString ("TC_TRAVELER_DISK"));
				fwprintf (af, L"action=%s\n", bAutoMount ? GetString ("MOUNT_TC_VOLUME") : GetString ("IDC_PREF_LOGON_START"));
				fwprintf (af, L"open=%s\n", bAutoMount ? autoMount : L"VeraCrypt\\VeraCrypt.exe");
				fwprintf (af, L"shell\\start=%s\nshell\\start\\command=VeraCrypt\\VeraCrypt.exe\n", GetString ("IDC_PREF_LOGON_START"));
				fwprintf (af, L"shell\\dismount=%s\nshell\\dismount\\command=VeraCrypt\\VeraCrypt.exe /q /d\n", GetString ("DISMOUNT_ALL_TC_VOLUMES"));

				CheckFileStreamWriteErrors (hwndDlg, af, dstPath);
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

void BuildTree (HWND hwndDlg, HWND hTree)
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
	lvCol.cx = CompensateXDPI (200);
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,1,(LPARAM)&lvCol);
	LastDriveListVolumeColumnWidth = ListView_GetColumnWidth (hTree, 1);

	lvCol.pszText = GetString ("SIZE");
	lvCol.cx = CompensateXDPI (55);
	lvCol.fmt = LVCFMT_RIGHT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,2,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("ENCRYPTION_ALGORITHM_LV");
	lvCol.cx = CompensateXDPI (123);
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,3,(LPARAM)&lvCol);

	lvCol.pszText = GetString ("TYPE");
	lvCol.cx = CompensateXDPI (100);
	lvCol.fmt = LVCFMT_LEFT;
	SendMessage (hTree,LVM_INSERTCOLUMNW,4,(LPARAM)&lvCol);

	// Regular drive icon

	hBitmap = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON));
	if (hBitmap == NULL)
		return;
	hBitmapMask = LoadBitmap (hInst, MAKEINTRESOURCE (IDB_DRIVEICON_MASK));

	hList = CreateImageList (16, 12, ILC_COLOR8|ILC_MASK, 2, 2);
	if (AddBitmapToImageList (hList, hBitmap, hBitmapMask) == -1)
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

	if (AddBitmapToImageList (hList, hBitmap, hBitmapMask) == -1)
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

	LoadDriveLetters (hwndDlg, hTree, 0);
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

	if (	(ListView_GetItemCount (hTree) < 1)
		||	(ListView_GetItem (hTree, &item) == FALSE)
		)
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

static int AskVolumePassword (HWND hwndDlg, Password *password, int *pkcs5, int *pim, BOOL* truecryptMode, char *titleStringId, BOOL enableMountOptions)
{
	INT_PTR result;
	PasswordDlgParam dlgParam;

	PasswordDialogTitleStringId = titleStringId;
	PasswordDialogDisableMountOptions = !enableMountOptions;

	dlgParam.password = password;
	dlgParam.pkcs5 = pkcs5;
	dlgParam.pim = pim;
	dlgParam.truecryptMode = truecryptMode;

	result = SecureDesktopDialogBoxParam (hInst,
		MAKEINTRESOURCEW (IDD_PASSWORD_DLG), hwndDlg,
		(DLGPROC) PasswordDlgProc, (LPARAM) &dlgParam);

	if (result != IDOK)
	{
		password->Length = 0;
		*pkcs5 = 0;
		*pim = -1;
		*truecryptMode = FALSE;
		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
		burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));
	}

	return result == IDOK;
}

// GUI actions

static BOOL Mount (HWND hwndDlg, int nDosDriveNo, wchar_t *szFileName, int pim, int pkcs5, int trueCryptMode)
{
	BOOL status = FALSE;
	wchar_t fileName[MAX_PATH];
	int mounted = 0, EffectiveVolumePkcs5 = 0;
	BOOL EffectiveVolumeTrueCryptMode = FALSE;
	int EffectiveVolumePim = (pim < 0)? CmdVolumePim : pim;
	BOOL bEffectiveCacheDuringMultipleMount = bCmdCacheDuringMultipleMount? TRUE: bCacheDuringMultipleMount;
	BOOL bEffectiveTryEmptyPasswordWhenKeyfileUsed = bCmdTryEmptyPasswordWhenKeyfileUsedValid? bCmdTryEmptyPasswordWhenKeyfileUsed : bTryEmptyPasswordWhenKeyfileUsed;
	BOOL bUseCmdVolumePassword = CmdVolumePasswordValid && ((CmdVolumePassword.Length > 0) || (KeyFilesEnable && FirstKeyFile));

	/* Priority is given to arguments and command line parameters
	 * Default values used only when nothing specified
	 */
	if (pkcs5 > 0)
		EffectiveVolumePkcs5 = pkcs5;
	else if (CmdVolumePkcs5 > 0)
		EffectiveVolumePkcs5 = CmdVolumePkcs5;
	else
		EffectiveVolumePkcs5 = DefaultVolumePkcs5;

	if (trueCryptMode >= 0)
		EffectiveVolumeTrueCryptMode = (trueCryptMode == 0)? FALSE : TRUE;
	else if (CmdVolumeTrueCryptMode)
		EffectiveVolumeTrueCryptMode = TRUE;
	else
		EffectiveVolumeTrueCryptMode = DefaultVolumeTrueCryptMode;

	if (EffectiveVolumeTrueCryptMode)
	{
		/* No PIM Mode if TrueCrypt Mode specified */
		EffectiveVolumePim = 0;

		/* valdate the effective PRF is compatible with TrueCrypt Mode */
		if (!is_pkcs5_prf_supported (EffectiveVolumePkcs5, TRUE, mountOptions.PartitionInInactiveSysEncScope? PRF_BOOT_MBR : PRF_BOOT_NO))
			EffectiveVolumePkcs5 = 0;
	}

	bPrebootPasswordDlgMode = mountOptions.PartitionInInactiveSysEncScope;

	if (nDosDriveNo == -1)
		nDosDriveNo = HIWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST))) - L'A';

	if (!MultipleMountOperationInProgress)
	{
		VolumePassword.Length = 0;
		VolumePkcs5 = 0;
		VolumeTrueCryptMode = FALSE;
		VolumePim = -1;
	}

	if (szFileName == NULL)
	{
		GetVolumePath (hwndDlg, fileName, ARRAYSIZE (fileName));
	}
	else
		StringCchCopyW (fileName, ARRAYSIZE (fileName), szFileName);

	if (wcslen(fileName) == 0)
	{
		status = FALSE;
		goto ret;
	}

	if (!TranslateVolumeID (hwndDlg, fileName, ARRAYSIZE (fileName)))
	{
		status = FALSE;
		goto ret;
	}

	szFileName = fileName;

	if (IsMountedVolume (szFileName))
	{
		Warning ("VOL_ALREADY_MOUNTED", hwndDlg);
		status = FALSE;
		goto ret;
	}

	if (!VolumePathExists (szFileName))
	{
		if (!MultipleMountOperationInProgress)
			handleWin32Error (hwndDlg, SRC_POS);

		status = FALSE;
		goto ret;
	}

	ResetWrongPwdRetryCount ();

	WaitCursor ();

	if (!bUseCmdVolumePassword)
	{
		// First try cached passwords and if they fail ask user for a new one
		if (EffectiveVolumeTrueCryptMode)
			mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, EffectiveVolumePkcs5, 0, TRUE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);
		else
			mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, EffectiveVolumePkcs5, EffectiveVolumePim, FALSE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);

		// If keyfiles are enabled, test empty password first
		if (!mounted && KeyFilesEnable && FirstKeyFile && bEffectiveTryEmptyPasswordWhenKeyfileUsed)
		{
			Password emptyPassword = {0};

			KeyFilesApply (hwndDlg, &emptyPassword, FirstKeyFile, szFileName);

			if (EffectiveVolumeTrueCryptMode)
				mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &emptyPassword, EffectiveVolumePkcs5, 0, TRUE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);
			else
				mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &emptyPassword, EffectiveVolumePkcs5, EffectiveVolumePim, FALSE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);

			burn (&emptyPassword, sizeof (emptyPassword));
		}
	}

	// Test password and/or keyfiles used for the previous volume
	if (!mounted && bEffectiveCacheDuringMultipleMount && MultipleMountOperationInProgress && VolumePassword.Length != 0)
	{
		// try TrueCrypt mode first as it is quick, only if no custom pim specified
		if (EffectiveVolumeTrueCryptMode)
			mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, EffectiveVolumePkcs5, 0, TRUE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);
		else // if no PIM specified for favorite, we use also the PIM of the previous volume alongside its password.
			mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, EffectiveVolumePkcs5, (EffectiveVolumePim < 0)? VolumePim : EffectiveVolumePim, FALSE, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);
	}

	NormalCursor ();

	if (mounted)
	{

		// Check for problematic file extensions (exe, dll, sys)
		if (CheckFileExtension(szFileName))
			Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING", hwndDlg);
	}

	while (mounted == 0)
	{
		if (bUseCmdVolumePassword)
		{
			VolumePassword = CmdVolumePassword;
			VolumePkcs5 = EffectiveVolumePkcs5;
			VolumeTrueCryptMode = EffectiveVolumeTrueCryptMode;
			VolumePim = EffectiveVolumePim;
		}
		else if (!Silent)
		{
			int GuiPkcs5 = EffectiveVolumePkcs5;
			BOOL GuiTrueCryptMode = EffectiveVolumeTrueCryptMode;
			int GuiPim = EffectiveVolumePim;
			StringCbCopyW (PasswordDlgVolume, sizeof(PasswordDlgVolume), szFileName);

			if (!AskVolumePassword (hwndDlg, &VolumePassword, &GuiPkcs5, &GuiPim, &GuiTrueCryptMode, NULL, TRUE))
				goto ret;
			else
			{
				VolumePkcs5 = GuiPkcs5;
				VolumeTrueCryptMode = GuiTrueCryptMode;
				VolumePim = GuiPim;
				burn (&GuiPkcs5, sizeof(GuiPkcs5));
				burn (&GuiTrueCryptMode, sizeof(GuiTrueCryptMode));
				burn (&GuiPim, sizeof(GuiPim));
			}
		}

		WaitCursor ();

		if (KeyFilesEnable)
			KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, szFileName);

		mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, VolumePkcs5, VolumePim, VolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, !Silent);
		NormalCursor ();

		// Check for problematic file extensions (exe, dll, sys)
		if (mounted > 0 && CheckFileExtension (szFileName))
			Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING", hwndDlg);

		if (!MultipleMountOperationInProgress)
		{
			burn (&VolumePassword, sizeof (VolumePassword));
			burn (&VolumePkcs5, sizeof (VolumePkcs5));
			burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
			burn (&VolumePim, sizeof (VolumePim));
		}

		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
		burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));

		if (CmdVolumePassword.Length > 0 || Silent)
			break;
	}

	if (mounted > 0)
	{
		status = TRUE;

		if (bBeep)
			MessageBeep (0xFFFFFFFF);

		RefreshMainDlg(MainDlg);

		if (bExplore)
		{
			WaitCursor();
			OpenVolumeExplorerWindow (nDosDriveNo);
			NormalCursor();
		}

		if (mountOptions.ProtectHiddenVolume)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT", hwndDlg);
	}

ret:
	if (!MultipleMountOperationInProgress)
	{
		burn (&VolumePassword, sizeof (VolumePassword));
		burn (&VolumePkcs5, sizeof (VolumePkcs5));
		burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
		burn (&VolumePim, sizeof (VolumePim));
	}

	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));

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

	if (nDosDriveNo == -2)
		nDosDriveNo = (char) (HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - L'A');

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
			LoadDriveLetters (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);
	}

	NormalCursor ();
	return status;
}

void __cdecl mountThreadFunction (void *hwndDlgArg)
{
	HWND hwndDlg =(HWND) hwndDlgArg;
	BOOL bIsForeground = (GetForegroundWindow () == hwndDlg)? TRUE : FALSE;
	// Disable parent dialog during processing to avoid user interaction
	EnableWindow(hwndDlg, FALSE);
	finally_do_arg2 (HWND, hwndDlg, BOOL, bIsForeground, { EnableWindow(finally_arg, TRUE);  if (finally_arg2) BringToForeground (finally_arg); bPrebootPasswordDlgMode = FALSE;});

	Mount (hwndDlg, -1, 0, -1, -1, -1);
}

typedef struct
{
	UNMOUNT_STRUCT* punmount;
	BOOL interact;
	int dismountMaxRetries;
	int dismountAutoRetryDelay;
	BOOL* pbResult;
	DWORD* pdwResult;
	DWORD dwLastError;
	BOOL bReturn;
} DismountAllThreadParam;

void CALLBACK DismountAllThreadProc(void* pArg, HWND hwndDlg)
{
	DismountAllThreadParam* pThreadParam = (DismountAllThreadParam*) pArg;
	UNMOUNT_STRUCT* punmount = pThreadParam->punmount;
	BOOL* pbResult = pThreadParam->pbResult;
	DWORD* pdwResult = pThreadParam->pdwResult;
	int dismountMaxRetries = pThreadParam->dismountMaxRetries;
	int dismountAutoRetryDelay = pThreadParam->dismountAutoRetryDelay;

	do
	{
		*pbResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_ALL_VOLUMES, punmount,
			sizeof (UNMOUNT_STRUCT), punmount, sizeof (UNMOUNT_STRUCT), pdwResult, NULL);

		if (	punmount->nDosDriveNo < 0 || punmount->nDosDriveNo > 25
				|| (punmount->ignoreOpenFiles != TRUE && punmount->ignoreOpenFiles != FALSE)
				||	(punmount->HiddenVolumeProtectionTriggered != TRUE && punmount->HiddenVolumeProtectionTriggered != FALSE)
				||	(punmount->nReturnCode < 0)
			)
		{
			if (*pbResult)
				SetLastError (ERROR_INTERNAL_ERROR);
			*pbResult = FALSE;
		}

		if (*pbResult == FALSE)
		{
			NormalCursor();
			handleWin32Error (hwndDlg, SRC_POS);
			pThreadParam->dwLastError = GetLastError ();
			pThreadParam->bReturn = FALSE;
			return;
		}

		if (punmount->nReturnCode == ERR_SUCCESS
			&& punmount->HiddenVolumeProtectionTriggered
			&& !VolumeNotificationsList.bHidVolDamagePrevReported [punmount->nDosDriveNo]
			&& pThreadParam->interact
			&& !Silent)
		{
			wchar_t msg[4096];

			VolumeNotificationsList.bHidVolDamagePrevReported [punmount->nDosDriveNo] = TRUE;

			StringCbPrintfW (msg, sizeof(msg), GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), punmount->nDosDriveNo + L'A');
			SetForegroundWindow (hwndDlg);
			MessageBoxW (hwndDlg, msg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);

			punmount->HiddenVolumeProtectionTriggered = FALSE;
			continue;
		}

		if (punmount->nReturnCode == ERR_FILES_OPEN)
			Sleep (dismountAutoRetryDelay);
		else
			break;

	} while (--dismountMaxRetries > 0);

	pThreadParam->dwLastError = GetLastError ();
	pThreadParam->bReturn = TRUE;
}

static BOOL DismountAll (HWND hwndDlg, BOOL forceUnmount, BOOL interact, int dismountMaxRetries, int dismountAutoRetryDelay)
{
	BOOL status = TRUE;
	MOUNT_LIST_STRUCT mountList = {0};
	DWORD dwResult;
	UNMOUNT_STRUCT unmount = {0};
	BOOL bResult;
	MOUNT_LIST_STRUCT prevMountList = {0};
	int i;
	DismountAllThreadParam dismountAllThreadParam;

retry:
	WaitCursor();

	status = DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL);

	if (!status || (mountList.ulMountedDrives == 0) || (mountList.ulMountedDrives >= (1 << 26)))
	{
		NormalCursor();
		return status && (mountList.ulMountedDrives == 0)? TRUE : FALSE;
	}

	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, 0, mountList.ulMountedDrives);

	memcpy (&prevMountList, &mountList, sizeof (mountList));

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

	dismountAllThreadParam.punmount = &unmount;
	dismountAllThreadParam.interact = interact;
	dismountAllThreadParam.dismountMaxRetries = dismountMaxRetries;
	dismountAllThreadParam.dismountAutoRetryDelay = dismountAutoRetryDelay;
	dismountAllThreadParam.pbResult = &bResult;
	dismountAllThreadParam.pdwResult = &dwResult;
	dismountAllThreadParam.dwLastError = ERROR_SUCCESS;
	dismountAllThreadParam.bReturn = TRUE;

	if (interact && !Silent)
	{

		ShowWaitDialog (hwndDlg, FALSE, DismountAllThreadProc, &dismountAllThreadParam);
	}
	else
		DismountAllThreadProc (&dismountAllThreadParam, hwndDlg);

	SetLastError (dismountAllThreadParam.dwLastError);

	if (!dismountAllThreadParam.bReturn)
		return FALSE;

	memset (&mountList, 0, sizeof (mountList));
	if (	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mountList, sizeof (mountList), &mountList, sizeof (mountList), &dwResult, NULL)
		&& (mountList.ulMountedDrives < (1 << 26))
		)
	{
		// remove any custom label from registry
		if (prevMountList.ulMountedDrives)
		{
			for (i = 0; i < 26; i++)
			{
				if ((prevMountList.ulMountedDrives & (1 << i)) && (!(mountList.ulMountedDrives & (1 << i))) && IsNullTerminateString (prevMountList.wszLabel[i], 33) && wcslen (prevMountList.wszLabel[i]))
				{
					UpdateDriveCustomLabel (i, prevMountList.wszLabel[i], FALSE);
				}
			}
		}
	}

	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, prevMountList.ulMountedDrives & ~mountList.ulMountedDrives);

	RefreshMainDlg (hwndDlg);

	if (nCurrentOS == WIN_2000 && RemoteSession && !IsAdmin ())
		LoadDriveLetters (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

	NormalCursor();

	if (unmount.nReturnCode != 0)
	{
		if (forceUnmount)
			status = FALSE;

		if (unmount.nReturnCode == ERR_FILES_OPEN)
		{
			if (interact && IDYES == AskWarnYesNoTopmost ("UNMOUNTALL_LOCK_FAILED", hwndDlg))
			{
				forceUnmount = TRUE;
				goto retry;
			}

			if (IsOSAtLeast (WIN_7))
			{
				// Undo SHCNE_DRIVEREMOVED
				if (	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, NULL, 0, &mountList, sizeof (mountList), &dwResult, NULL)
					&& mountList.ulMountedDrives
					&& (mountList.ulMountedDrives < (1 << 26))
					)
				{
					for (i = 0; i < 26; i++)
					{
						if (mountList.ulMountedDrives & (1 << i))
						{
							wchar_t root[] = { (wchar_t) i + L'A', L':', L'\\', 0 };
							SHChangeNotify (SHCNE_DRIVEADD, SHCNF_PATH, root, NULL);
						}
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

static BOOL MountAllDevicesThreadCode (HWND hwndDlg, BOOL bPasswordPrompt)
{
	HWND driveList = GetDlgItem (MainDlg, IDC_DRIVELIST);
	int selDrive = ListView_GetSelectionMark (driveList);
	BOOL shared = FALSE, status = FALSE, bHeaderBakRetry = FALSE;
	int mountedVolCount = 0;
	vector <HostDevice> devices;
	int EffectiveVolumePkcs5 = CmdVolumePkcs5;
	BOOL EffectiveVolumeTrueCryptMode = CmdVolumeTrueCryptMode;

	/* Priority is given to command line parameters
	 * Default values used only when nothing specified in command line
	 */
	if (EffectiveVolumePkcs5 == 0)
		EffectiveVolumePkcs5 = DefaultVolumePkcs5;
	if (!EffectiveVolumeTrueCryptMode)
		EffectiveVolumeTrueCryptMode = DefaultVolumeTrueCryptMode;

	VolumePassword.Length = 0;
	mountOptions = defaultMountOptions;
	bPrebootPasswordDlgMode = FALSE;
	VolumePim = -1;

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
				int GuiPkcs5 = EffectiveVolumePkcs5;
				BOOL GuiTrueCryptMode = EffectiveVolumeTrueCryptMode;
				int GuiPim = CmdVolumePim;
				PasswordDlgVolume[0] = '\0';
				if (!AskVolumePassword (hwndDlg, &VolumePassword, &GuiPkcs5, &GuiPim, &GuiTrueCryptMode, NULL, TRUE))
					goto ret;
				else
				{
					VolumePkcs5 = GuiPkcs5;
					VolumeTrueCryptMode = GuiTrueCryptMode;
					VolumePim = GuiPim;
					burn (&GuiPkcs5, sizeof(GuiPkcs5));
					burn (&GuiTrueCryptMode, sizeof(GuiTrueCryptMode));
					burn (&GuiPim, sizeof(GuiPim));
				}
			}
			else if (CmdVolumePasswordValid)
			{
				bPasswordPrompt = FALSE;
				VolumePassword = CmdVolumePassword;
				VolumePkcs5 = EffectiveVolumePkcs5;
				VolumeTrueCryptMode = EffectiveVolumeTrueCryptMode;
				VolumePim = CmdVolumePim;
			}

			WaitCursor();

			if (FirstCmdKeyFile)
				KeyFilesApply (hwndDlg, &VolumePassword, FirstCmdKeyFile, NULL);
			else if (KeyFilesEnable)
				KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, NULL);

		}

		if (devices.empty())
			devices = GetAvailableHostDevices (true, false, true, true);
		foreach (const HostDevice &drive, devices)
		{
			vector <HostDevice> partitions = drive.Partitions;
			partitions.insert (partitions.begin(), drive);

			foreach (const HostDevice &device, partitions)
			{
				wchar_t szFileName[TC_MAX_PATH];
				StringCbCopyW (szFileName, sizeof (szFileName), device.Path.c_str());
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
					int driveAItem = -1, driveBItem = -1;

					while (LOWORD (GetItemLong (driveList, selDrive)) != 0xffff)
					{
						if(LOWORD (GetItemLong (driveList, selDrive)) != TC_MLIST_ITEM_FREE)
						{
							selDrive++;
							continue;
						}
						nDosDriveNo = HIWORD(GetItemLong (driveList, selDrive)) - L'A';

						/* don't use drives A: and B: for now until no other free drive found */
						if (nDosDriveNo == 0)
						{
							driveAItem = selDrive;
							selDrive++;
							continue;
						}
						if (nDosDriveNo == 1)
						{
							driveBItem = selDrive;
							selDrive++;
							continue;
						}
						break;
					}

					if (LOWORD (GetItemLong (driveList, selDrive)) == 0xffff)
					{
						/* use A: or B: if available as a last resort */
						if (driveAItem >= 0)
						{
							nDosDriveNo = 0;
							selDrive = driveAItem;
						}
						else if (driveBItem >= 0)
						{
							nDosDriveNo = 1;
							selDrive = driveBItem;
						}
						else
							goto ret;
					}

					// First try user password then cached passwords
					if ((mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &VolumePassword, VolumePkcs5, VolumePim, VolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, TRUE, FALSE)) > 0
						|| ((VolumePassword.Length > 0) && ((mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, NULL, VolumePkcs5, VolumePim, VolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, TRUE, FALSE)) > 0)))
					{
						// A volume has been successfully mounted

						ResetWrongPwdRetryCount ();

						if (mounted == 2)
							shared = TRUE;

						LoadDriveLetters (hwndDlg, driveList, (HIWORD (GetItemLong (GetDlgItem (MainDlg, IDC_DRIVELIST), selDrive))));
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
				Warning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK", hwndDlg);
		}

		if (!bHeaderBakRetry)
		{
			burn (&VolumePassword, sizeof (VolumePassword));
			burn (&VolumePkcs5, sizeof (VolumePkcs5));
			burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
			burn (&VolumePim, sizeof (VolumePim));
			burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
			burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));
		}

	} while (bPasswordPrompt && mountedVolCount < 1);

	/* One or more volumes successfully mounted */

	ResetWrongPwdRetryCount ();

	if (shared)
		Warning ("DEVICE_IN_USE_INFO", hwndDlg);

	if (mountOptions.ProtectHiddenVolume)
	{
		if (mountedVolCount > 1)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL", hwndDlg);
		else if (mountedVolCount == 1)
			Info ("HIDVOL_PROT_WARN_AFTER_MOUNT", hwndDlg);
	}

	if (status && CloseSecurityTokenSessionsAfterMount)
		SecurityToken::CloseAllSessions();

ret:
	MultipleMountOperationInProgress = FALSE;

	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
	burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));

	mountOptions.UseBackupHeader = defaultMountOptions.UseBackupHeader;

	RestoreDefaultKeyFilesParam ();

	if (UsePreferences)
		bCacheInDriver = bCacheInDriverDefault;

	EnableDisableButtons (MainDlg);

	NormalCursor();

	return status;
}

typedef struct
{
	BOOL bPasswordPrompt;
	BOOL bRet;
} MountAllDevicesThreadParam;

void CALLBACK mountAllDevicesThreadProc(void* pArg, HWND hwndDlg)
{
	MountAllDevicesThreadParam* threadParam =(MountAllDevicesThreadParam*) pArg;
	BOOL bPasswordPrompt = threadParam->bPasswordPrompt;

	threadParam->bRet = MountAllDevicesThreadCode (hwndDlg, bPasswordPrompt);
}

static BOOL MountAllDevices (HWND hwndDlg, BOOL bPasswordPrompt)
{
	MountAllDevicesThreadParam param;
	param.bPasswordPrompt = bPasswordPrompt;
	param.bRet = FALSE;

	ShowWaitDialog (hwndDlg, FALSE, mountAllDevicesThreadProc, &param);

	return param.bRet;
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
				if (newPimValue != -1)
				{
					// update the encoded volue in favorite XML if found
					bool bFavoriteFound = false;
					for (vector <FavoriteVolume>::iterator favorite = FavoriteVolumes.begin();
						favorite != FavoriteVolumes.end(); favorite++)
					{
						if (favorite->Path == szFileName)
						{
							bFavoriteFound = true;
							favorite->Pim = newPimValue;
							SaveFavoriteVolumes (hwndDlg, FavoriteVolumes, false);
							break;
						}
					}

					if (!bFavoriteFound)
					{
						for (vector <FavoriteVolume>::iterator favorite = SystemFavoriteVolumes.begin();
							favorite != SystemFavoriteVolumes.end(); favorite++)
						{
							if (favorite->Path == szFileName)
							{
								bFavoriteFound = true;
								favorite->Pim = newPimValue;

								if (AskYesNo("FAVORITE_PIM_CHANGED", hwndDlg) == IDYES)
								{
									SaveFavoriteVolumes (hwndDlg, SystemFavoriteVolumes, true);
								}
								break;
							}
						}
					}
				}
			}
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
		Warning ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
		return;
	}

	if (SysEncryptionOrDecryptionRequired ()
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED", hwndDlg);
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		StringCbPrintfW (OrigKeyboardLayout, sizeof(OrigKeyboardLayout), L"%08X", (DWORD) GetKeyboardLayout (NULL) & 0xFFFF);

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
				Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT", hwndDlg);
			else
				bKeyboardLayoutChanged = FALSE;
		}

		bKeybLayoutAltKeyWarningShown = FALSE;

		if (result == IDOK)
		{
			switch (pwdChangeDlgMode)
			{
			case PCDM_CHANGE_PKCS5_PRF:
				Info ("PKCS5_PRF_CHANGED", hwndDlg);

				if (!IsHiddenOSRunning())
				{
					if (AskWarnYesNo ("SYS_HKD_ALGO_CHANGED_ASK_RESCUE_DISK", hwndDlg) == IDYES)
						CreateRescueDisk (hwndDlg);
				}

				break;

			case PCDM_ADD_REMOVE_VOL_KEYFILES:
			case PCDM_REMOVE_ALL_KEYFILES_FROM_VOL:
				// NOP - Keyfiles are not supported for system encryption
				break;

			case PCDM_CHANGE_PASSWORD:
			default:
				Info ("PASSWORD_CHANGED", hwndDlg);

				if (!IsHiddenOSRunning())
				{
					if (AskWarnYesNo ("SYS_PASSWORD_CHANGED_ASK_RESCUE_DISK", hwndDlg) == IDYES)
						CreateRescueDisk (hwndDlg);
				}
			}
		}

		CloseSysEncMutex ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
}

// Initiates or resumes encryption of the system partition/drive
static void EncryptSystemDevice (HWND hwndDlg)
{
	SystemDriveConfiguration config;
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		config = BootEncObj->GetSystemDriveConfiguration ();
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
			LaunchVolCreationWizard (hwndDlg, L"/sysenc", FALSE);
		}
		else
			Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);

		return;
	}
	else if (SysEncryptionOrDecryptionRequired ())
	{
		// System partition/drive encryption already initiated but is incomplete -- attempt to resume the process.
		// Note that this also covers the pretest phase and paused decryption (reverses decrypting and starts encrypting)

		if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
		{
			LaunchVolCreationWizard (hwndDlg, L"/sysenc",FALSE);
		}
		else
			Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
	}
	else if (SysDriveOrPartitionFullyEncrypted (FALSE))
	{
		// System partition/drive appears to be fully encrypted
		Info ("SYS_PARTITION_OR_DRIVE_APPEARS_FULLY_ENCRYPTED", hwndDlg);
		return;
	}
}

// Initiates decryption of the system partition/drive
static void DecryptSystemDevice (HWND hwndDlg)
{
	SystemDriveConfiguration config;
	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		config = BootEncObj->GetSystemDriveConfiguration ();
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
		Warning ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
		return;
	}

	if (IsHiddenOSRunning())
	{
		Warning ("CANNOT_DECRYPT_HIDDEN_OS", hwndDlg);
		return;
	}

	if (AskNoYes ("CONFIRM_DECRYPT_SYS_DEVICE", hwndDlg) == IDNO)
		return;

	if (AskWarnNoYes ("CONFIRM_DECRYPT_SYS_DEVICE_CAUTION", hwndDlg) == IDNO)
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
			Error ("SYS_ENCRYPTION_OR_DECRYPTION_IN_PROGRESS", hwndDlg);
			return;
		}

		CloseSysEncMutex ();	
		LaunchVolCreationWizard (hwndDlg, L"/dsysenc", FALSE);
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
}

// Initiates the process of creation of a hidden operating system
static void CreateHiddenOS (HWND hwndDlg)
{

	// Display brief information as to what a hidden operating system is and what it's good for. This needs to be
	// done, because if the system partition/drive is currently encrypted, the wizard will not display any
	// such information, but will exit (displaying only an error meessage).
	Info("HIDDEN_OS_PREINFO", hwndDlg);

	LaunchVolCreationWizard (hwndDlg, L"/isysenc", FALSE);
}

static void DecryptNonSysDevice (HWND hwndDlg, BOOL bResolveAmbiguousSelection, BOOL bUseDriveListSel)
{
	wstring scPath;

	if (bResolveAmbiguousSelection)
	{
		scPath = ResolveAmbiguousSelection (hwndDlg, NULL);

		if (scPath.empty ())
		{
			// The user selected Cancel
			return;
		}
	}
	else if (bUseDriveListSel)
	{
		// Decrypt mounted volume selected in the main drive list

		LPARAM lLetter = GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST));

		if (LOWORD (lLetter) != 0xffff)
		{
			VOLUME_PROPERTIES_STRUCT prop;
			DWORD bytesReturned;

			memset (&prop, 0, sizeof (prop));
			prop.driveNo = (wchar_t) HIWORD (lLetter) - L'A';

			if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &bytesReturned, NULL))
			{
				handleWin32Error (MainDlg, SRC_POS);
				return;
			}

			scPath = prop.wszVolume;
		}
		else
			return;
	}
	else
	{
		// Decrypt volume specified in the input field below the main drive list

		wchar_t volPath [TC_MAX_PATH];

		GetVolumePath (MainDlg, volPath, ARRAYSIZE (volPath));

		scPath = volPath;
	}

	if (scPath.empty ())
	{
		Warning ("NO_VOLUME_SELECTED", hwndDlg);
		return;
	}

	WaitCursor();

	switch (IsSystemDevicePath (scPath.c_str (), MainDlg, TRUE))
	{
	case 1:
	case 2:
		// The user wants to decrypt the system partition/drive. Divert to the appropriate function.

		NormalCursor ();

		DecryptSystemDevice (hwndDlg);
		return;
	}

	WaitCursor();

	// Make sure the user is not attempting to decrypt a partition on an entirely encrypted system drive.
	if (IsNonSysPartitionOnSysDrive (scPath.c_str ()) == 1)
	{
		if (WholeSysDriveEncryption (TRUE))
		{
			// The system drive is entirely encrypted and the encrypted OS is running

			NormalCursor ();

			Warning ("CANT_DECRYPT_PARTITION_ON_ENTIRELY_ENCRYPTED_SYS_DRIVE", hwndDlg);
			return;
		}
	}
	else if (TCBootLoaderOnInactiveSysEncDrive ((wchar_t *) scPath.c_str ()))
	{
		// The system drive MAY be entirely encrypted (external access without PBA) and the potentially encrypted OS is not running

		NormalCursor ();

		Warning ("CANT_DECRYPT_PARTITION_ON_ENTIRELY_ENCRYPTED_SYS_DRIVE_UNSURE", hwndDlg);

		// We allow the user to continue as we don't know if the drive is really an encrypted system drive.
		// If it is, the user has been warned and he will not be able to start decrypting, because the
		// format wizard will not enable (nor will it allow the user to enable) the mount option for
		// external without-PBA access (the user will receive the 'Incorrect password' error message).
	}

	NormalCursor ();


	if (AskNoYesString ((wstring (GetString ("CONFIRM_DECRYPT_NON_SYS_DEVICE")) + L"\n\n" + scPath).c_str(), hwndDlg) == IDNO)
		return;

	if (AskWarnNoYes ("CONFIRM_DECRYPT_NON_SYS_DEVICE_CAUTION", hwndDlg) == IDNO)
		return;

	LaunchVolCreationWizard (hwndDlg, (wstring (L"/inplacedec \"") + scPath + L"\"").c_str (), FALSE);
}

// Blindly attempts (without any checks) to instruct the wizard to resume whatever system encryption process
// had been interrupted or not started but scheduled or exptected to start.
static void ResumeInterruptedSysEncProcess (HWND hwndDlg)
{
	if (!MutexExistsOnSystem (TC_MUTEX_NAME_SYSENC))	// If no instance of the wizard is currently taking care of system encryption
	{
		SystemDriveConfiguration config;
		try
		{
			config = BootEncObj->GetSystemDriveConfiguration ();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		LaunchVolCreationWizard (MainDlg, L"/csysenc", FALSE);
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
}

void CreateRescueDisk (HWND hwndDlg)
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
		Warning ("CANNOT_CREATE_RESCUE_DISK_ON_HIDDEN_OS", hwndDlg);
		return;
	}

	if (!BootEncStatus.DriveEncrypted
		&& !BootEncStatus.DriveMounted
		&& !BootEncStatus.VolumeHeaderPresent
		&& !SysEncryptionOrDecryptionRequired ())
	{
		Warning ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
		return;
	}

	if (SysEncryptionOrDecryptionRequired ()
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED", hwndDlg);
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		try
		{
			wchar_t szTmp [8096];
			wchar_t szRescueDiskISO [TC_MAX_PATH+1];

			if (AskOkCancel ("RESCUE_DISK_NON_WIZARD_CREATION_SELECT_PATH", hwndDlg) != IDOK)
			{
				CloseSysEncMutex ();
				return;
			}

			wchar_t initialDir[MAX_PATH];
			SHGetFolderPath (NULL, CSIDL_MYDOCUMENTS, NULL, 0, initialDir);

			if (!BrowseFilesInDir (hwndDlg, "OPEN_TITLE", initialDir, szRescueDiskISO, FALSE, TRUE, NULL, szDefaultRescueDiskName, szRescueDiskExtension))
			{
				CloseSysEncMutex ();
				return;
			}

			WaitCursor();
			BootEncObj->CreateRescueIsoImage (false, szRescueDiskISO);

			if (bSystemIsGPT)
			{
				StringCbPrintfW (szTmp, sizeof szTmp, GetString ("RESCUE_DISK_EFI_NON_WIZARD_CREATION"), szRescueDiskISO);
				InfoDirect (szTmp, hwndDlg);
			}
			else
			{
				StringCbPrintfW (szTmp, sizeof szTmp,
					GetString (IsWindowsIsoBurnerAvailable() ? "RESCUE_DISK_NON_WIZARD_CREATION_WIN_ISOBURN" : "RESCUE_DISK_NON_WIZARD_CREATION_BURN"),
					szRescueDiskISO);

				if (IsWindowsIsoBurnerAvailable())
				{
					if (AskYesNoString (szTmp, hwndDlg) == IDYES)
						LaunchWindowsIsoBurner (MainDlg, szRescueDiskISO);
				}
				else
					InfoDirect (szTmp, hwndDlg);
			}
		}
		catch (Exception &e)
		{
			e.Show (hwndDlg);
			Error ("ERROR_CREATING_RESCUE_DISK", hwndDlg);
		}
		CloseSysEncMutex ();

		NormalCursor ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
}

static void VerifyRescueDisk (HWND hwndDlg, bool checkImageFile)
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
		Warning ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
		return;
	}

	if (SysEncryptionOrDecryptionRequired ()
		|| BootEncStatus.SetupInProgress)
	{
		Warning ("SYSTEM_ENCRYPTION_NOT_COMPLETED", hwndDlg);
		return;
	}

	if (CreateSysEncMutex ())	// If no instance of the wizard is currently taking care of system encryption
	{
		try
		{
			if (!checkImageFile && (AskOkCancel ("RESCUE_DISK_NON_WIZARD_CHECK_INSERT", hwndDlg) != IDOK))
			{
				CloseSysEncMutex ();
				return;
			}

			// Create a temporary up-to-date rescue disk image in RAM (with it the CD/DVD content will be compared)
			BootEncObj->CreateRescueIsoImage (false, L"");


			if (checkImageFile)
			{
				wchar_t szRescueDiskImage [TC_MAX_PATH+1];
				wchar_t initialDir[MAX_PATH];
				SHGetFolderPath (NULL, CSIDL_MYDOCUMENTS, NULL, 0, initialDir);

				if (!BrowseFilesInDir (hwndDlg, "OPEN_TITLE", initialDir, szRescueDiskImage, FALSE, FALSE, NULL,szDefaultRescueDiskName, szRescueDiskExtension))
				{
					CloseSysEncMutex ();
					return;
				}

				WaitCursor();
				if (!BootEncObj->VerifyRescueDiskImage (szRescueDiskImage))
					Error ("RESCUE_DISK_ISO_IMAGE_CHECK_FAILED", hwndDlg);
				else
					Info ("RESCUE_DISK_ISO_IMAGE_CHECK_PASSED", hwndDlg);
			}
			else
			{
				WaitCursor();
				if (!BootEncObj->VerifyRescueDisk ())
					Error (bSystemIsGPT? "RESCUE_DISK_EFI_NON_WIZARD_CHECK_FAILED" : "RESCUE_DISK_NON_WIZARD_CHECK_FAILED", hwndDlg);
				else
					Info ("RESCUE_DISK_NON_WIZARD_CHECK_PASSED", hwndDlg);
			}
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error (bSystemIsGPT? "RESCUE_DISK_EFI_NON_WIZARD_CHECK_FAILED" : "RESCUE_DISK_NON_WIZARD_CHECK_FAILED", hwndDlg);
		}
		CloseSysEncMutex ();

		NormalCursor ();
	}
	else
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
}

static void ShowSystemEncryptionStatus (HWND hwndDlg)
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
		Info ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
		return;
	}

	DialogBoxParamW (hInst,
		MAKEINTRESOURCEW (IDD_VOLUME_PROPERTIES), hwndDlg,
		(DLGPROC) VolumePropertiesDlgProc, (LPARAM) TRUE);

}

static void ResumeInterruptedNonSysInplaceEncProcess (BOOL bDecrypt)
{
	// IMPORTANT: This function must not check any config files! Otherwise, if a config file was lost or corrupt,
	// the user would not be able resume encryption and the data on the volume would be inaccessible.

	LaunchVolCreationWizard (MainDlg, bDecrypt? L"/resumeinplacedec" : L"/zinplace", FALSE);
}

BOOL SelectContainer (HWND hwndDlg)
{
	if (BrowseFiles (hwndDlg, "OPEN_VOL_TITLE", szFileName, bHistory, FALSE, NULL) == FALSE)
		return FALSE;

	AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
	EnableDisableButtons (hwndDlg);
	SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
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
		handleWin32Error (hwndDlg, SRC_POS);
	else
	{
		EnableDisableButtons (hwndDlg);

		if (!silent)
			InfoBalloon ("PASSWORD_CACHE_WIPED_SHORT", "PASSWORD_CACHE_WIPED", hwndDlg);
	}
}

static void Benchmark (HWND hwndDlg)
{

	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_BENCHMARK_DLG), hwndDlg,
		(DLGPROC) BenchmarkDlgProc, (LPARAM) bSystemIsGPT);
}


static BOOL CheckMountList (HWND hwndDlg, BOOL bForceTaskBarUpdate)
{
	MOUNT_LIST_STRUCT current = {0};
	static BootEncryptionStatus newBootEncStatus;
	static BOOL lastbUseDifferentTrayIconIfVolMounted = bUseDifferentTrayIconIfVolMounted;
	static uint32 lastUlMountedDrives = 0;

	if (!GetMountList (&current))
	{
		return bForceTaskBarUpdate;
	}

	if ((bForceTaskBarUpdate || current.ulMountedDrives != lastUlMountedDrives || bUseDifferentTrayIconIfVolMounted != lastbUseDifferentTrayIconIfVolMounted)
		&& TaskBarIconMutex != NULL)
	{
		lastUlMountedDrives = current.ulMountedDrives;
		lastbUseDifferentTrayIconIfVolMounted = bUseDifferentTrayIconIfVolMounted;

		TaskBarIconChange (MainDlg, current.ulMountedDrives != 0 && bUseDifferentTrayIconIfVolMounted ? IDI_TRUECRYPT_MOUNTED_ICON : IDI_TRUECRYPT_ICON);
	}

	if (bForceTaskBarUpdate)
	{
		return TRUE;
	}

	if (LastKnownLogicalDrives != GetUsedLogicalDrives()
		|| memcmp (&LastKnownMountList, &current, sizeof (current)) != 0)
	{
		wchar_t selDrive;

		WaitCursor ();
		LastKnownMountList = current;

		selDrive = (wchar_t) HIWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST)));
		LoadDriveLetters (hwndDlg, GetDlgItem (MainDlg, IDC_DRIVELIST), 0);
		NormalCursor ();

		if (selDrive != ((wchar_t) 0xFFFF) && (current.ulMountedDrives & (1 << (selDrive - L'A'))) == 0 && !IsDriveAvailable (selDrive - L'A'))
		{
			nSelectedDriveIndex = -1;
			return FALSE;
		}

		if (selDrive != ((wchar_t) 0xFFFF))
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

			wchar_t selDrive;
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

			selDrive = (wchar_t) HIWORD (GetSelectedLong (GetDlgItem (MainDlg, IDC_DRIVELIST)));
			LoadDriveLetters (hwndDlg, GetDlgItem (MainDlg, IDC_DRIVELIST), driveLetterToRefresh);

			RecentBootEncStatus = newBootEncStatus;

			if (selDrive != ((wchar_t) 0xFFFF) && (current.ulMountedDrives & (1 << (selDrive - L'A'))) == 0 && !IsDriveAvailable (selDrive - L'A'))
			{
				nSelectedDriveIndex = -1;
			}

			if (selDrive != ((wchar_t) 0xFFFF))
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
				WarningTopMost ("HIDDEN_OS_HIBERNATION_PREVENTED", hwndDlg);
			else
				WarningTopMost ("SYS_ENC_HIBERNATION_PREVENTED", hwndDlg);
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
						switch (AskMultiChoice ((void **) tmp, FALSE, hwndDlg))
						{
						case 1:
							InfoDirect ((wstring (GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO"))
								+ L"\n\n"
								+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")
								+ L"\n\n\n"
								+ GetString ("DECOY_TO_HIDDEN_OS_DATA_TRANSFER_HOWTO")).c_str(), hwndDlg);
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
							+ GetString ("DECOY_TO_HIDDEN_OS_DATA_TRANSFER_HOWTO")).c_str(), hwndDlg);

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


void DisplayDriveListContextMenu (HWND hwndDlg, LPARAM lParam)
{
	/* Drive list context menu */
	DWORD mPos;
	int menuItem;
	HMENU popup = CreatePopupMenu ();
	HWND hList = GetDlgItem (hwndDlg, IDC_DRIVELIST);

	SetFocus (hList);

	switch (LOWORD (GetSelectedLong (hList)))
	{
	case TC_MLIST_ITEM_FREE:

		// No mounted volume at this drive letter

		AppendMenuW (popup, MF_STRING, IDM_MOUNT_VOLUME, GetString ("IDM_MOUNT_VOLUME"));
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDPM_SELECT_FILE_AND_MOUNT, GetString ("SELECT_FILE_AND_MOUNT"));
		AppendMenuW (popup, MF_STRING, IDPM_SELECT_DEVICE_AND_MOUNT, GetString ("SELECT_DEVICE_AND_MOUNT"));
		break;

	case TC_MLIST_ITEM_NONSYS_VOL:

		// There's a mounted non-system volume at this drive letter

		AppendMenuW (popup, MF_STRING, IDM_UNMOUNT_VOLUME, GetString ("DISMOUNT"));
		AppendMenuW (popup, MF_STRING, IDPM_OPEN_VOLUME, GetString ("OPEN"));
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDPM_CHECK_FILESYS, GetString ("IDPM_CHECK_FILESYS"));
		AppendMenuW (popup, MF_STRING, IDPM_REPAIR_FILESYS, GetString ("IDPM_REPAIR_FILESYS"));
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDPM_ADD_TO_FAVORITES, GetString ("IDPM_ADD_TO_FAVORITES"));
		AppendMenuW (popup, MF_STRING, IDPM_ADD_TO_SYSTEM_FAVORITES, GetString ("IDPM_ADD_TO_SYSTEM_FAVORITES"));
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDM_DECRYPT_NONSYS_VOL, GetString ("IDM_DECRYPT_NONSYS_VOL"));
		AppendMenu (popup, MF_SEPARATOR, 0, L"");
		AppendMenuW (popup, MF_STRING, IDM_VOLUME_PROPERTIES, GetString ("IDPM_PROPERTIES"));
		break;

	case TC_MLIST_ITEM_SYS_PARTITION:
	case TC_MLIST_ITEM_SYS_DRIVE:

		// System partition/drive

		PopulateSysEncContextMenu (popup, FALSE);
		break;
	}

	if (lParam)
	{
		mPos=GetMessagePos();
	}
	else
	{
		POINT pt = {0};
		if (ListView_GetItemPosition (hList, nSelectedDriveIndex, &pt))
		{
			pt.x += 2 + ::GetSystemMetrics(SM_CXICON);
			pt.y += 2;
		}
		ClientToScreen (hList, &pt);
		mPos  = MAKELONG (pt.x, pt.y);
	}

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
			LPARAM lLetter = GetSelectedLong (hList);

			if (LOWORD (lLetter) != 0xffff)
				CheckFilesystem (hwndDlg, (wchar_t) HIWORD (lLetter) - L'A', menuItem == IDPM_REPAIR_FILESYS);
		}
		break;

	case IDM_UNMOUNT_VOLUME:
		if (CheckMountList (hwndDlg, FALSE))
			Dismount (hwndDlg, -2);
		break;

	case IDM_DECRYPT_NONSYS_VOL:
		if (CheckMountList (hwndDlg, FALSE))
			DecryptNonSysDevice (hwndDlg, FALSE, TRUE);
		break;

	case IDPM_OPEN_VOLUME:
		{
			LPARAM state;
			if (lParam)
				nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;
			else
				nSelectedDriveIndex = ListView_GetSelectionMark (hList);
			state = GetItemLong (hList, nSelectedDriveIndex );

			WaitCursor ();
			OpenVolumeExplorerWindow (HIWORD(state) - L'A');
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
			Warning ("NO_VOLUME_SELECTED", hwndDlg);
		}
		else
		{
			mountOptions = defaultMountOptions;
			bPrebootPasswordDlgMode = FALSE;

			if (CheckMountList (hwndDlg, FALSE))
				_beginthread(mountThreadFunction, 0, hwndDlg);
		}
		break;

	case IDPM_ADD_TO_FAVORITES:
	case IDPM_ADD_TO_SYSTEM_FAVORITES:
		{
			LPARAM selectedDrive = GetSelectedLong (hList);

			if (LOWORD (selectedDrive) == TC_MLIST_ITEM_NONSYS_VOL)
				AddMountedVolumeToFavorites (hwndDlg, HIWORD (selectedDrive) - L'A', menuItem == IDPM_ADD_TO_SYSTEM_FAVORITES);
		}
		break;

	default:
		SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
		break;
	}
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
			bShowDisconnectedNetworkDrives = FALSE;
			bHideWaitingDialog = FALSE;
			bUseSecureDesktop = FALSE;

			ResetWrongPwdRetryCount ();

			ExtractCommandLine (hwndDlg, (wchar_t *) lParam);

			try
			{
				BootEncObj->SetParentWindow (hwndDlg);
				BootEncStatus = BootEncObj->GetStatus();
				RecentBootEncStatus = BootEncStatus;
				bSystemIsGPT = BootEncObj->GetSystemDriveConfiguration().SystemPartition.IsGPT;
			}
			catch (...)
			{
				// NOP
			}

			if (bSystemIsGPT)
				StringCbCopyW (szRescueDiskExtension, sizeof (szRescueDiskExtension), L"zip");
			else
				StringCbCopyW (szRescueDiskExtension, sizeof (szRescueDiskExtension), L"iso");
			
			StringCbCopyW (szDefaultRescueDiskName, sizeof (szDefaultRescueDiskName), L"VeraCrypt Rescue Disk.");		
			StringCbCatW  (szDefaultRescueDiskName, sizeof (szDefaultRescueDiskName), szRescueDiskExtension);

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
					handleWin32Error (hwndDlg, SRC_POS);
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
					uint32 driverConfig = ReadDriverConfigurationFlags();
					if (BootEncObj->GetInstalledBootLoaderVersion() != VERSION_NUM)
						Warning ("UPDATE_TC_IN_HIDDEN_OS_TOO", hwndDlg);
					if (	!(driverConfig & TC_DRIVER_CONFIG_DISABLE_EVIL_MAID_ATTACK_DETECTION)
						&&	!BootEncObj->CheckBootloaderFingerprint ())
						Warning ("BOOT_LOADER_FINGERPRINT_CHECK_FAILED", hwndDlg);
				}
				else if (SysDriveOrPartitionFullyEncrypted (TRUE))
				{
					uint32 driverConfig = ReadDriverConfigurationFlags();
					if (BootEncObj->GetInstalledBootLoaderVersion() != VERSION_NUM)
					{
						Warning ("BOOT_LOADER_VERSION_DIFFERENT_FROM_DRIVER_VERSION", hwndDlg);
					}
					if (	!(driverConfig & TC_DRIVER_CONFIG_DISABLE_EVIL_MAID_ATTACK_DETECTION)
						&&	!BootEncObj->CheckBootloaderFingerprint ())
						Warning ("BOOT_LOADER_FINGERPRINT_CHECK_FAILED", hwndDlg);
				}
			}
			catch (...) { }

			// Automount
			if (bAuto || (Quit && szFileName[0] != 0))
			{
				// No drive letter specified on command line
				if (commandLineDrive == 0)
					szDriveLetter[0] = (wchar_t) GetFirstAvailableDrive () + L'A';

				if (bAutoMountDevices)
				{
					defaultMountOptions = mountOptions;
					if (FirstCmdKeyFile)
					{
						KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles = TRUE;
						KeyFileCloneAll (FirstCmdKeyFile, &FirstKeyFile);
						KeyFileCloneAll (FirstCmdKeyFile, &defaultKeyFilesParam.FirstKeyFile);
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
						KeyFileCloneAll (FirstCmdKeyFile, &FirstKeyFile);
						KeyFileCloneAll (FirstCmdKeyFile, &defaultKeyFilesParam.FirstKeyFile);
					}

					if (!MountFavoriteVolumes (hwndDlg, FALSE, LogOn))
						exitCode = 1;
				}

				if (szFileName[0] != 0 && !TranslateVolumeID (hwndDlg, szFileName, ARRAYSIZE (szFileName)))
				{
					exitCode = 1;
				}
				else if (szFileName[0] != 0 && !IsMountedVolume (szFileName))
				{
					BOOL mounted = FALSE;
					int EffectiveVolumePkcs5 = CmdVolumePkcs5;
					BOOL EffectiveVolumeTrueCryptMode = CmdVolumeTrueCryptMode;
					BOOL bEffectiveTryEmptyPasswordWhenKeyfileUsed = bCmdTryEmptyPasswordWhenKeyfileUsedValid? bCmdTryEmptyPasswordWhenKeyfileUsed : bTryEmptyPasswordWhenKeyfileUsed;

					if (!VolumePathExists (szFileName))
					{
						handleWin32Error (hwndDlg, SRC_POS);
					}
					else
					{
						/* Priority is given to command line parameters
						 * Default values used only when nothing specified in command line
						 */
						if (EffectiveVolumePkcs5 == 0)
							EffectiveVolumePkcs5 = DefaultVolumePkcs5;
						if (!EffectiveVolumeTrueCryptMode)
							EffectiveVolumeTrueCryptMode = DefaultVolumeTrueCryptMode;

						// Command line password or keyfiles
						if (CmdVolumePassword.Length != 0 || (FirstCmdKeyFile && (CmdVolumePasswordValid || bEffectiveTryEmptyPasswordWhenKeyfileUsed)))
						{
							BOOL reportBadPasswd = CmdVolumePassword.Length > 0;

							if (FirstCmdKeyFile)
								KeyFilesApply (hwndDlg, &CmdVolumePassword, FirstCmdKeyFile, szFileName);

							mounted = MountVolume (hwndDlg, szDriveLetter[0] - L'A',
								szFileName, &CmdVolumePassword, EffectiveVolumePkcs5, CmdVolumePim, EffectiveVolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount,
								&mountOptions, Silent, reportBadPasswd);

							burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
						}
						else
						{
							// Cached password
							mounted = MountVolume (hwndDlg, szDriveLetter[0] - L'A', szFileName, NULL, EffectiveVolumePkcs5, CmdVolumePim, EffectiveVolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, Silent, FALSE);
						}

						if (FirstCmdKeyFile)
						{
							KeyFileRemoveAll (&FirstKeyFile);
							FirstKeyFile = FirstCmdKeyFile;
							KeyFilesEnable = TRUE;
						}

						// Ask user for password
						while (!mounted && !Silent)
						{
							int GuiPkcs5 = EffectiveVolumePkcs5;
							int GuiPim = CmdVolumePim;
							BOOL GuiTrueCryptMode = EffectiveVolumeTrueCryptMode;
							VolumePassword.Length = 0;

							StringCbCopyW (PasswordDlgVolume, sizeof(PasswordDlgVolume),szFileName);
							if (!AskVolumePassword (hwndDlg, &VolumePassword, &GuiPkcs5, &GuiPim, &GuiTrueCryptMode, NULL, TRUE))
								break;
							else
							{
								VolumePkcs5 = GuiPkcs5;
								VolumePim = GuiPim;
								VolumeTrueCryptMode = GuiTrueCryptMode;
								burn (&GuiPkcs5, sizeof(GuiPkcs5));
								burn (&GuiPim, sizeof(GuiPim));
								burn (&GuiTrueCryptMode, sizeof(GuiTrueCryptMode));
							}

							WaitCursor ();

							if (KeyFilesEnable && FirstKeyFile)
								KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, szFileName);

							mounted = MountVolume (hwndDlg, szDriveLetter[0] - L'A', szFileName, &VolumePassword, VolumePkcs5, VolumePim, VolumeTrueCryptMode, bCacheInDriver, bIncludePimInCache, bForceMount, &mountOptions, FALSE, TRUE);

							burn (&VolumePassword, sizeof (VolumePassword));
							burn (&VolumePkcs5, sizeof (VolumePkcs5));
							burn (&VolumePim, sizeof (VolumePim));
							burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
							burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));
							burn (&mountOptions.ProtectedHidVolPkcs5Prf, sizeof (mountOptions.ProtectedHidVolPkcs5Prf));

							NormalCursor ();
						}
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
							OpenVolumeExplorerWindow (szDriveLetter[0] - L'A');

						RefreshMainDlg(hwndDlg);

						if(!Silent)
						{
							// Check for problematic file extensions (exe, dll, sys)
							if (CheckFileExtension (szFileName))
								Warning ("EXE_FILE_EXTENSION_MOUNT_WARNING", hwndDlg);
						}
					}
					else
						exitCode = 1;
				}
				else if (bExplore && GetMountedVolumeDriveNo (szFileName) != -1)
					OpenVolumeExplorerWindow (GetMountedVolumeDriveNo (szFileName));
				else if (szFileName[0] != 0 && IsMountedVolume (szFileName))
					Warning ("VOL_ALREADY_MOUNTED", hwndDlg);

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
			if (cmdUnmountDrive >= 0)
			{
				MOUNT_LIST_STRUCT mountList;
				DWORD bytesReturned;

				if (DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, NULL, 0, &mountList, sizeof (mountList), &bytesReturned, NULL)
					&& ((mountList.ulMountedDrives < (1 << 26))
					&& (mountList.ulMountedDrives & (1 << cmdUnmountDrive)) == 0)
					)
				{
					Error ("NO_VOLUME_MOUNTED_TO_DRIVE", hwndDlg);
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
					&& (!IsAdmin() || (GetWindowLongPtrW (h, DWLP_USER) & TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES) != 0))
				{
					if (CmdLineVolumeSpecified)
					{
						COPYDATASTRUCT cd;
						memcpy (&cd.dwData, WM_COPY_SET_VOLUME_NAME, 4);
						cd.lpData = szFileName;
						cd.cbData = (DWORD) ((wcslen (szFileName) + 1) * sizeof (wchar_t));

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
				Warning("HOTKEY_REGISTRATION_ERROR", hwndDlg);

			Silent = FALSE;

			GetMountList (&LastKnownMountList);
			SetTimer (hwndDlg, TIMER_ID_MAIN, TIMER_INTERVAL_MAIN, NULL);
			SetTimer (hwndDlg, TIMER_ID_UPDATE_DEVICE_LIST, TIMER_INTERVAL_UPDATE_DEVICE_LIST, NULL);

			taskBarCreatedMsg = RegisterWindowMessage (L"TaskbarCreated");

			AllowMessageInUIPI (taskBarCreatedMsg);

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
							|| AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT", hwndDlg) == IDYES)
						{
							// The wizard was not launched during the system startup seq, or the user may have forgotten
							// to resume the encryption/decryption process.
							SystemDriveConfiguration config;
							try
							{
								config = BootEncObj->GetSystemDriveConfiguration ();
							}
							catch (Exception &e)
							{
								e.Show (MainDlg);
							}

							LaunchVolCreationWizard (hwndDlg, L"/csysenc", FALSE);
						}
					}
				}

				if (bInPlaceEncNonSysPending && !NonSysInplaceEncInProgressElsewhere())
				{
					BOOL bDecrypt = FALSE;
					if (AskNonSysInPlaceEncryptionResume(hwndDlg, &bDecrypt) == IDYES)
						ResumeInterruptedNonSysInplaceEncProcess (bDecrypt);
				}
			}

			if (TaskBarIconMutex != NULL)
				RegisterWtsNotification(hwndDlg);
			DoPostInstallTasks (hwndDlg);
			ResetCurrentDirectory ();
		}
		return 0;

	case WM_MOUSEWHEEL:
		return HandleDriveListMouseWheelEvent (uMsg, wParam, lParam, FALSE);

	case WM_CONTEXTMENU:
		{
			HWND hList = GetDlgItem (hwndDlg, IDC_DRIVELIST);
			// only handle if it is coming from keyboard and if the drive
			// list has focus. The other cases are handled elsewhere
			if (   (-1 == GET_X_LPARAM(lParam))
				&& (-1 == GET_Y_LPARAM(lParam))
				&& (GetFocus () == hList)
				)
			{
				INT item = ListView_GetSelectionMark (hList);
				if (item >= 0)
				{
					nSelectedDriveIndex = item;
					DisplayDriveListContextMenu (hwndDlg, NULL);
				}
			}
		}
		break;

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

	case WM_WTSSESSION_CHANGE:
		if (TaskBarIconMutex != NULL)
		{
			if (bDismountOnSessionLocked && ((WTS_SESSION_LOCK == wParam) || (WTS_CONSOLE_DISCONNECT == wParam) || (WTS_REMOTE_DISCONNECT == wParam)))
			{
				// Auto-dismount when session is locked
				DWORD dwResult;

				if (bWipeCacheOnAutoDismount)
				{
					DeviceIoControl (hDriver, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0, &dwResult, NULL);
					SecurityToken::CloseAllSessions();
				}

				DismountAll (hwndDlg, bForceAutoDismount, TRUE, UNMOUNT_MAX_AUTO_RETRIES, UNMOUNT_AUTO_RETRY_DELAY);
			}
		}
		return 0;

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
			UnregisterWtsNotification(hwndDlg);
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
			if (wParam == TIMER_ID_UPDATE_DEVICE_LIST)
			{
				UpdateMountableHostDeviceList (false);
			}
			else
			{
				// Check mount list and update GUI if needed
				CheckMountList (hwndDlg, FALSE);

				// Cache status
				if (IsPasswordCacheEmpty() == IsWindowEnabled (GetDlgItem (hwndDlg, IDC_WIPE_CACHE)))
					EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_CACHE), !IsPasswordCacheEmpty());

				// Check driver warning flags
				DWORD bytesOut;
				GetWarningFlagsRequest warnings;
				if (DeviceIoControl (hDriver, TC_IOCTL_GET_WARNING_FLAGS, NULL, 0, &warnings, sizeof (warnings), &bytesOut, NULL))
				{
					if (warnings.SystemFavoriteVolumeDirty)
						WarningTopMost ("SYS_FAVORITE_VOLUME_DIRTY", hwndDlg);

					if (warnings.PagingFileCreationPrevented)
						WarningTopMost ("PAGING_FILE_CREATION_PREVENTED", hwndDlg);
				}

				if (TaskBarIconMutex != NULL)
				{

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
							if (favorite.UseVolumeID)
							{
								if (IsMountedVolumeID (favorite.VolumeID))
									continue;

								std::wstring volDevPath = FindDeviceByVolumeID (favorite.VolumeID);
								if (volDevPath.length() > 0)
								{
									favorite.Path = volDevPath;
									favorite.DisconnectedDevice = false;
								}
								else
									continue;
							}
							else if (!favorite.VolumePathId.empty())
							{
								if (IsMountedVolume (favorite.Path.c_str()))
									continue;

								wchar_t volDevPath[TC_MAX_PATH];
								if (QueryDosDevice (favorite.VolumePathId.substr (4, favorite.VolumePathId.size() - 5).c_str(), volDevPath, TC_MAX_PATH) == 0)
									continue;

								favorite.DisconnectedDevice = false;
							}
							else if (favorite.Path.find (L"\\\\?\\Volume{") == 0)
							{
								wstring resolvedPath = VolumeGuidPathToDevicePath (favorite.Path);
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
								MountFavoriteVolumes (hwndDlg, FALSE, FALSE, FALSE, favorite);
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

							wchar_t volDevPath[TC_MAX_PATH];
							if (favorite->VolumePathId.size() > 5
								&& QueryDosDevice (favorite->VolumePathId.substr (4, favorite->VolumePathId.size() - 5).c_str(), volDevPath, TC_MAX_PATH) != 0)
							{
								continue;
							}

							// set DisconnectedDevice field on FavoritesOnArrivalMountRequired element
							foreach (FavoriteVolume onArrivalFavorite, FavoritesOnArrivalMountRequired)
							{
								if (onArrivalFavorite.Path == favorite->Path)
								{
									onArrivalFavorite.DisconnectedDevice = true;
									break;
								}
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
					UnregisterWtsNotification(hwndDlg);
					EndMainDlg (hwndDlg);
				}
			}
			return 1;
		}		

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
						AppendMenu (popup, MF_SEPARATOR, 0, L"");
					}
					else if (bEnableBkgTask
						&& (!(LastKnownMountList.ulMountedDrives == 0
						&& (bCloseBkgTaskWhenNoVolumes || IsNonInstallMode ())
						&& !SysEncDeviceActive (TRUE)
						&& GetDriverRefCount () < 2)))
					{
						AppendMenuW (popup, MF_STRING, IDM_SHOW_HIDE, GetString ("HIDE_TC"));
						AppendMenu (popup, MF_SEPARATOR, 0, L"");
					}
					AppendMenuW (popup, MF_STRING, IDM_MOUNTALL, GetString ("IDC_MOUNTALL"));
					AppendMenuW (popup, MF_STRING, IDM_MOUNT_FAVORITE_VOLUMES, GetString ("IDM_MOUNT_FAVORITE_VOLUMES"));
					AppendMenuW (popup, MF_STRING, IDM_UNMOUNTALL, GetString ("IDC_UNMOUNTALL"));
					AppendMenu (popup, MF_SEPARATOR, 0, L"");

					for (n = 0; n < 2; n++)
					{
						for (i = 0; i < 26; i++)
						{
							if ((LastKnownMountList.ulMountedDrives & (1 << i)) && IsNullTerminateString (LastKnownMountList.wszVolume[i], TC_MAX_PATH))
							{
								wchar_t s[1024];
								wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[i];

								if (wcsstr (vol, L"\\??\\")) vol += 4;

								// first check label used for mounting. If empty, look for it in favorites.
								bool useInExplorer = false;
								wstring label;
								if (IsNullTerminateString (LastKnownMountList.wszLabel[i], 33))
									label = (wchar_t *) LastKnownMountList.wszLabel[i];
								if (label.empty())
									label = GetFavoriteVolumeLabel (vol, useInExplorer);

								StringCbPrintfW (s, sizeof(s), L"%s %c: (%s)",
									GetString (n==0 ? "OPEN" : "DISMOUNT"),
									i + L'A',
									label.empty() ? vol : label.c_str());
								AppendMenuW (popup, MF_STRING, n*26 + TRAYICON_MENU_DRIVE_OFFSET + i, s);
							}
						}
						if (LastKnownMountList.ulMountedDrives != 0)
							AppendMenu (popup, MF_SEPARATOR, 0, L"");
					}

					AppendMenuW (popup, MF_STRING, IDM_HELP, GetString ("MENU_HELP"));
					AppendMenuW (popup, MF_STRING, IDM_HOMEPAGE_SYSTRAY, GetString ("HOMEPAGE"));
					AppendMenuW (popup, MF_STRING, IDM_PREFERENCES, GetString ("IDM_PREFERENCES"));
					AppendMenuW (popup, MF_STRING, IDM_ABOUT, GetString ("IDM_ABOUT"));
					AppendMenu (popup, MF_SEPARATOR, 0, L"");
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
						if (CheckMountList (hwndDlg, FALSE))
						{
							if (Dismount (hwndDlg, sel - TRAYICON_MENU_DRIVE_OFFSET - 26))
							{
								wchar_t txt [2048];
								StringCbPrintfW (txt, sizeof(txt), GetString ("VOLUME_MOUNTED_AS_DRIVE_LETTER_X_DISMOUNTED"), sel - TRAYICON_MENU_DRIVE_OFFSET - 26 + L'A');

								InfoBalloonDirect (GetString ("SUCCESSFULLY_DISMOUNTED"), txt, hwndDlg);
							}
						}
					}
					else if (sel == IDM_SHOW_HIDE)
					{
						ChangeMainWindowVisibility ();
					}
					else if (sel == IDM_HOMEPAGE_SYSTRAY)
					{
						Applink ("home");
					}
					else if (sel == IDCANCEL)
					{
						if ((LastKnownMountList.ulMountedDrives == 0
							&& !SysEncDeviceActive (TRUE))
							|| AskWarnNoYes ("CONFIRM_EXIT", hwndDlg) == IDYES)
						{
							// Close all other TC windows
							EnumWindows (CloseTCWindowsEnum, 0);

							TaskBarIconRemove (hwndDlg);
							UnregisterWtsNotification(hwndDlg);
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
		UnregisterWtsNotification(hwndDlg);

		return 1;

	case TC_APPMSG_SYSENC_CONFIG_UPDATE:
		LoadSysEncSettings ();

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

			if (GetMountList (&LastKnownMountList))
			{
				if (wParam == DBT_DEVICEREMOVECOMPLETE && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
				{
					// File-hosted volumes
					PDEV_BROADCAST_VOLUME vol = (PDEV_BROADCAST_VOLUME) lParam;
					int i;

					for (i = 0; i < 26; i++)
					{
						if (LastKnownMountList.ulMountedDrives && (vol->dbcv_unitmask & (1 << i)) && !(GetUsedLogicalDrives() & (1 << i)))
						{
							for (m = 0; m < 26; m++)
							{
								if ((LastKnownMountList.ulMountedDrives & (1 << m)) && IsNullTerminateString (LastKnownMountList.wszVolume[m], TC_MAX_PATH))
								{
									wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[m];

									if (wcsstr (vol, L"\\??\\") == vol)
										vol += 4;

									if (vol[1] == L':' && i == (vol[0] - (vol[0] <= L'Z' ? L'A' : L'a')))
									{
										UnmountVolume (hwndDlg, m, TRUE);
										WarningBalloon ("HOST_DEVICE_REMOVAL_DISMOUNT_WARN_TITLE", "HOST_DEVICE_REMOVAL_DISMOUNT_WARN", hwndDlg);
									}
								}
							}
						}
					}
				}

				// Device-hosted volumes
				for (m = 0; m < 26; m++)
				{
					if ((LastKnownMountList.ulMountedDrives & (1 << m)) && IsNullTerminateString (LastKnownMountList.wszVolume[m], TC_MAX_PATH))
					{
						wchar_t *vol = (wchar_t *) LastKnownMountList.wszVolume[m];

						if (wcsstr (vol, L"\\??\\") == vol)
							vol += 4;

						if (IsVolumeDeviceHosted (vol))
						{
							OPEN_TEST_STRUCT ots = {0};

							if (!OpenDevice (vol, &ots, FALSE, FALSE))
							{
								UnmountVolume (hwndDlg, m, TRUE);
								WarningBalloon ("HOST_DEVICE_REMOVAL_DISMOUNT_WARN_TITLE", "HOST_DEVICE_REMOVAL_DISMOUNT_WARN", hwndDlg);
							}
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
					LoadDriveLetters (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);
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
				LPARAM state = GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), ((LPNMITEMACTIVATE)lParam)->iItem );
				nSelectedDriveIndex = ((LPNMITEMACTIVATE)lParam)->iItem;
				if (LOWORD(state) == TC_MLIST_ITEM_NONSYS_VOL || LOWORD(state) == TC_MLIST_ITEM_SYS_PARTITION)
				{
					// Open explorer window for mounted volume
					WaitCursor ();
					OpenVolumeExplorerWindow (HIWORD(state) - L'A');
					NormalCursor ();
				}
				else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == TC_MLIST_ITEM_FREE)
				{
					mountOptions = defaultMountOptions;
					bPrebootPasswordDlgMode = FALSE;

					if (GetAsyncKeyState (VK_CONTROL) < 0)
					{
						/* Priority is given to command line parameters
						 * Default values used only when nothing specified in command line
						 */
						if (CmdVolumePkcs5 == 0)
							mountOptions.ProtectedHidVolPkcs5Prf = DefaultVolumePkcs5;
						else
							mountOptions.ProtectedHidVolPkcs5Prf = CmdVolumePkcs5;
						mountOptions.ProtectedHidVolPim = CmdVolumePim;

						if (IDCANCEL == DialogBoxParamW (hInst,
							MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
							(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
							return 1;

						if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
						{
							wchar_t selectedVolume [TC_MAX_PATH + 1];
							GetVolumePath (hwndDlg, selectedVolume, ARRAYSIZE (selectedVolume));
							KeyFilesApply (hwndDlg, &mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, selectedVolume);
						}
					}

					if (CheckMountList (hwndDlg, FALSE))
						_beginthread(mountThreadFunction, 0, hwndDlg);
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

					DisplayDriveListContextMenu (hwndDlg, lParam);

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
				Warning ("SELECT_A_MOUNTED_VOLUME", hwndDlg);
				return 1;
			}

			if (CheckMountList (hwndDlg, FALSE))
				Dismount (hwndDlg, -2);
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
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "MOUNTED_VOLUMES_DISMOUNTED", hwndDlg);
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
			EncryptSystemDevice (hwndDlg);
			break;
		case IDM_PERMANENTLY_DECRYPT_SYS:
			DecryptSystemDevice (hwndDlg);
			break;
		case IDM_CREATE_HIDDEN_OS:
			CreateHiddenOS (hwndDlg);
			break;
		case IDM_SYSENC_RESUME:
			ResumeInterruptedSysEncProcess (hwndDlg);
			break;
		case IDM_SYSTEM_ENCRYPTION_STATUS:
			ShowSystemEncryptionStatus (hwndDlg);
			break;
		case IDM_CHANGE_SYS_PASSWORD:
			ChangeSysEncPassword (hwndDlg, FALSE);
			break;
		case IDM_CHANGE_SYS_HEADER_KEY_DERIV_ALGO:
			ChangeSysEncPassword (hwndDlg, TRUE);
			break;
		case IDM_CREATE_RESCUE_DISK:
			CreateRescueDisk (hwndDlg);
			break;
		case IDM_VERIFY_RESCUE_DISK:
			VerifyRescueDisk (hwndDlg, false);
			break;
		case IDM_VERIFY_RESCUE_DISK_ISO:
			VerifyRescueDisk (hwndDlg, true);
			break;
		case IDM_MOUNT_SYSENC_PART_WITHOUT_PBA:

			if (CheckSysEncMountWithoutPBA (hwndDlg, L"", FALSE))
			{
				mountOptions = defaultMountOptions;
				mountOptions.PartitionInInactiveSysEncScope = TRUE;
				bPrebootPasswordDlgMode = TRUE;

				if (CheckMountList (hwndDlg, FALSE))
					_beginthread(mountThreadFunction, 0, hwndDlg);
			}
			break;
		}

		if (lw == IDC_VOLUME_TOOLS)
		{
			/* Volume Tools popup menu */

			int menuItem;
			wchar_t volPath[TC_MAX_PATH];		/* Volume to mount */
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
				AppendMenu (popup, MF_SEPARATOR, 0, L"");
				AppendMenuW (popup, MF_STRING, IDM_ADD_REMOVE_VOL_KEYFILES, GetString ("IDM_ADD_REMOVE_VOL_KEYFILES"));
				AppendMenuW (popup, MF_STRING, IDM_REMOVE_ALL_KEYFILES_FROM_VOL, GetString ("IDM_REMOVE_ALL_KEYFILES_FROM_VOL"));
				AppendMenu (popup, MF_SEPARATOR, 0, L"");
				AppendMenuW (popup, MF_STRING, IDM_DECRYPT_NONSYS_VOL, GetString ("IDM_DECRYPT_NONSYS_VOL"));
				AppendMenu (popup, MF_SEPARATOR, 0, NULL);
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
			case IDM_DECRYPT_NONSYS_VOL:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					DecryptNonSysDevice (hwndDlg, TRUE, FALSE);
				}
				break;

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

			case IDM_BACKUP_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					GetVolumePath (hwndDlg, volPath, ARRAYSIZE (volPath));

					WaitCursor ();

					int iStatus = 0;
					BackupHeaderThreadParam threadParam;
					threadParam.bRequireConfirmation = TRUE;
					threadParam.lpszVolume = volPath;
					threadParam.cchVolume = ARRAYSIZE (volPath);
					threadParam.iResult = &iStatus;

					ShowWaitDialog (hwndDlg, TRUE, BackupHeaderWaitThreadProc, &threadParam);

					NormalCursor ();
				}
				break;

			case IDM_RESTORE_VOL_HEADER:
				if (!VolumeSelected(hwndDlg))
				{
					Warning ("NO_VOLUME_SELECTED", hwndDlg);
				}
				else
				{
					GetVolumePath (hwndDlg, volPath, ARRAYSIZE (volPath));

					WaitCursor ();

					int iStatus = 0;
					RestoreHeaderThreadParam threadParam;
					threadParam.lpszVolume = volPath;
					threadParam.cchVolume = ARRAYSIZE (volPath);
					threadParam.iResult = &iStatus;

					ShowWaitDialog(hwndDlg, TRUE, RestoreHeaderWaitThreadProc, &threadParam);

					NormalCursor ();
				}
				break;

			default:
				SendMessage (MainDlg, WM_COMMAND, menuItem, NULL);
				break;
			}
			return 1;
		}

		if (lw == IDM_DECRYPT_NONSYS_VOL)
		{
			LPARAM selectedDrive = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

			if (LOWORD (selectedDrive) == TC_MLIST_ITEM_FREE && !VolumeSelected (MainDlg))
			{
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
			}
			else
			{
				DecryptNonSysDevice (hwndDlg, TRUE, FALSE);
			}

			return 1;
		}

		if (lw == IDM_CHANGE_PASSWORD)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
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
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
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
			LaunchVolCreationWizard (hwndDlg, L"", FALSE);
			return 1;
		}

		if (lw == IDM_VOLUME_EXPANDER)
		{
			LaunchVolExpander (hwndDlg);
			return 1;
		}

		if (lw == IDM_ADD_REMOVE_VOL_KEYFILES)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
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
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
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

			InfoBalloon (NULL, "ALL_TOKEN_SESSIONS_CLOSED", hwndDlg);

			return 1;
		}

		if (lw == IDM_KEYFILE_GENERATOR)
		{
			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILE_GENERATOR), hwndDlg,
				(DLGPROC) KeyfileGeneratorDlgProc, (LPARAM) 0);

				return 1;
		}

		if (lw == IDM_DONATE)
		{
			Applink ("donate");
			return 1;
		}

		if (lw == IDM_LICENSE)
		{
			TextInfoDialogBox (TC_TBXID_LEGAL_NOTICES);
			return 1;
		}

		if (lw == IDM_WEBSITE)
		{
			Applink ("website");
			return 1;
		}
		else if (lw == IDM_HOMEPAGE)
		{
			Applink ("homepage");
			return 1;
		}
		else if (lw == IDM_ONLINE_TUTORIAL)
		{
			Applink ("tutorial");
			return 1;
		}
		else if (lw == IDM_ONLINE_HELP)
		{
			OpenOnlineHelp ();
			return 1;
		}
		else if (lw == IDM_FAQ)
		{
			Applink ("faq");
			return 1;
		}
		else if (lw == IDM_TC_DOWNLOADS)
		{
			Applink ("downloads");
			return 1;
		}
		else if (lw == IDM_NEWS)
		{
			Applink ("news");
			return 1;
		}
		else if (lw == IDM_VERSION_HISTORY)
		{
			Applink ("history");
			return 1;
		}
		else if (lw == IDM_CONTACT)
		{
			Applink ("contact");
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
					RegisterWtsNotification(hwndDlg);
				}
				else
				{
					TaskBarIconRemove (hwndDlg);
					UnregisterWtsNotification(hwndDlg);
					if (MainWindowHidden)
						EndMainDlg (hwndDlg);
				}
			}
			return 1;
		}

		if (lw == IDM_HOTKEY_SETTINGS)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_HOTKEYS_DLG), hwndParent,
				(DLGPROC) HotkeysDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDM_PERFORMANCE_SETTINGS)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_PERFORMANCE_SETTINGS), hwndParent, (DLGPROC) PerformanceSettingsDlgProc, 0);
			return 1;
		}

		if (lw == IDM_DEFAULT_KEYFILES)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			KeyfileDefaultsDlg (hwndParent);
			return 1;
		}

		if (lw == IDM_DEFAULT_MOUNT_PARAMETERS)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_DEFAULT_MOUNT_PARAMETERS), hwndParent, (DLGPROC) DefaultMountParametersDlgProc, 0);
			return 1;
		}

		if (lw == IDM_ADD_VOLUME_TO_FAVORITES || lw == IDM_ADD_VOLUME_TO_SYSTEM_FAVORITES)
		{
			LPARAM selectedDrive = GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST));

			wchar_t volPathLower[TC_MAX_PATH];

			// volPathLower will contain the volume path (if any) from the input field below the drive list
			GetVolumePath (hwndDlg, volPathLower, ARRAYSIZE (volPathLower));

			if (LOWORD (selectedDrive) != TC_MLIST_ITEM_NONSYS_VOL
				&& !(VolumeSelected (hwndDlg) && IsMountedVolume (volPathLower)))
			{
				Warning ("SELECT_A_MOUNTED_VOLUME", hwndDlg);

				return 1;
			}

			int driveNo;

			if (VolumeSelected (hwndDlg)
				&& IsMountedVolume (volPathLower))
			{
				if (!TranslateVolumeID (hwndDlg, volPathLower, ARRAYSIZE (volPathLower)))
					return 1;

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
					prop.driveNo = HIWORD (selectedDrive) - L'A';

					if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL) || dwResult == 0)
					{
						Warning ("SELECT_A_MOUNTED_VOLUME", hwndDlg);
						return 1;
					}

					// volPathHigher will contain the volume path selected in the main drive list
					wstring volPathHigher (prop.wszVolume);

					if (wcscmp (((wmemcmp (prop.wszVolume, L"\\??\\", 4) == 0) ? (wchar_t *) prop.wszVolume + 4 : prop.wszVolume), volPathLower) != 0)
					{
						// The path selected in the input field is different from the path to the volume selected
						// in the drive lettter list. We have to resolve possible ambiguity.

						wchar_t *tmp[] = {L"", L"", L"", L"", L"", 0};
						const int maxVolPathLen = 80;

						if (volPathHigher.length () > maxVolPathLen)
						{
							volPathHigher = wstring (L"...") + volPathHigher.substr (volPathHigher.length () - maxVolPathLen, maxVolPathLen);
						}

						wstring volPathLowerWStr (volPathLower);

						if (volPathLowerWStr.length () > maxVolPathLen)
						{
							volPathLowerWStr = wstring (L"...") + volPathLowerWStr.substr (volPathLowerWStr.length () - maxVolPathLen, maxVolPathLen);
						}

						tmp[1] = GetString ("AMBIGUOUS_VOL_SELECTION");
						tmp[2] = (wchar_t *) volPathHigher.c_str();
						tmp[3] = (wchar_t *) volPathLowerWStr.c_str();
						tmp[4] = GetString ("IDCANCEL");

						switch (AskMultiChoice ((void **) tmp, FALSE, hwndDlg))
						{
						case 1:
							driveNo = HIWORD (selectedDrive) - L'A';
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
						driveNo = HIWORD (selectedDrive) - L'A';
					}
				}
			}
			else
			{
				driveNo = HIWORD (selectedDrive) - L'A';
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
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			SecurityTokenPreferencesDialog (hwndParent);
			return 1;
		}

		if (lw == IDM_SYSENC_SETTINGS || lw == IDM_SYS_ENC_SETTINGS)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (bSystemIsGPT? IDD_EFI_SYSENC_SETTINGS : IDD_SYSENC_SETTINGS), hwndParent, (DLGPROC) BootLoaderPreferencesDlgProc, 0);
			return 1;
		}

		if (lw == IDM_SYS_FAVORITES_SETTINGS)
		{
			HWND hwndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			OrganizeFavoriteVolumes (hwndParent, true);
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
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
			}
			else
			{
				wchar_t volPath[TC_MAX_PATH];		/* Volume to mount */

				GetVolumePath (hwndDlg, volPath, ARRAYSIZE (volPath));

				WaitCursor ();

				int iStatus = 0;
				BackupHeaderThreadParam threadParam;
				threadParam.bRequireConfirmation = TRUE;
				threadParam.lpszVolume = volPath;
				threadParam.cchVolume = ARRAYSIZE (volPath);
				threadParam.iResult = &iStatus;

				ShowWaitDialog (hwndDlg, TRUE, BackupHeaderWaitThreadProc, &threadParam);

				NormalCursor ();
			}
			return 1;
		}

		if (lw == IDM_RESTORE_VOL_HEADER)
		{
			if (!VolumeSelected(hwndDlg))
			{
				Warning ("NO_VOLUME_SELECTED", hwndDlg);
			}
			else
			{
				wchar_t volPath[TC_MAX_PATH];		/* Volume to mount */

				GetVolumePath (hwndDlg, volPath, ARRAYSIZE (volPath));

				WaitCursor ();

				int iStatus = 0;
				RestoreHeaderThreadParam threadParam;
				threadParam.lpszVolume = volPath;
				threadParam.cchVolume = ARRAYSIZE (volPath);
				threadParam.iResult = &iStatus;

				ShowWaitDialog(hwndDlg, TRUE, RestoreHeaderWaitThreadProc, &threadParam);

				NormalCursor ();
			}
			return 1;
		}

		if (lw == IDM_LANGUAGE)
		{
			BOOL p;
			HWND wndParent = (lParam != 0)? (HWND) lParam : hwndDlg;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), wndParent,
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
			DWORD driveMap = GetUsedLogicalDrives ();

			WaitCursor ();

			if (!(nCurrentOS == WIN_2000 && RemoteSession))
			{
				BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, 0, ~driveMap);
				Sleep (100);
				BroadcastDeviceChange (DBT_DEVICEARRIVAL, 0, driveMap);
			}

			LoadDriveLetters (hwndDlg, GetDlgItem (hwndDlg, IDC_DRIVELIST), 0);

			if (nSelectedDriveIndex >= 0)
			{
				SelectItem (GetDlgItem (hwndDlg, IDC_DRIVELIST),
					(wchar_t) HIWORD (GetItemLong (GetDlgItem (hwndDlg, IDC_DRIVELIST), nSelectedDriveIndex)));
			}

			NormalCursor ();
			return 1;
		}

		if (lw == IDM_MOUNT_FAVORITE_VOLUMES)
		{
			_beginthread(mountFavoriteVolumeThreadFunction, 0, NULL);
			return 1;
		}

		if (lw == IDM_RESUME_INTERRUPTED_PROC)
		{
			// Ask the user to select encryption, decryption, or cancel
			BOOL bDecrypt = FALSE;
			char *tmpStr[] = {0,
				"CHOOSE_ENCRYPT_OR_DECRYPT",
				"ENCRYPT",
				"DECRYPT",
				"IDCANCEL",
				0};

			switch (AskMultiChoice ((void **) tmpStr, FALSE, hwndDlg))
			{
			case 1:
				bDecrypt = FALSE;
				break;
			case 2:
				bDecrypt = TRUE;
				break;
			default:
				return 1;
			}
			ResumeInterruptedNonSysInplaceEncProcess (bDecrypt);
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
				if ((FavoriteVolumes[favoriteIndex].UseVolumeID && IsMountedVolumeID (FavoriteVolumes[favoriteIndex].VolumeID))
					|| (!FavoriteVolumes[favoriteIndex].UseVolumeID  && IsMountedVolume (FavoriteVolumes[favoriteIndex].Path.c_str()))
					)
				{
					std::wstring volName;
					WaitCursor();
					if (FavoriteVolumes[favoriteIndex].UseVolumeID)
						volName = FindDeviceByVolumeID (FavoriteVolumes[favoriteIndex].VolumeID);
					else
						volName = FavoriteVolumes[favoriteIndex].Path;
					OpenVolumeExplorerWindow (GetMountedVolumeDriveNo ((wchar_t*) FavoriteVolumes[favoriteIndex].Path.c_str()));
					NormalCursor();
				}
				else
				{
					mountFavoriteVolumeThreadParam* pParam = (mountFavoriteVolumeThreadParam*) calloc(1, sizeof(mountFavoriteVolumeThreadParam));
					pParam->systemFavorites = FALSE;
					pParam->logOnMount = FALSE;
					pParam->hotKeyMount = FALSE;
					pParam->favoriteVolumeToMount = &FavoriteVolumes[favoriteIndex];

					_beginthread(mountFavoriteVolumeThreadFunction, 0, pParam);
				}
			}

			return 1;
		}

		return 0;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;
			DragQueryFile (hdrop, 0, szFileName, ARRAYSIZE (szFileName));
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

	case VC_APPMSG_CREATE_RESCUE_DISK:
		CreateRescueDisk (hwndDlg);
		return 1;

	case WM_COPYDATA:
		{
			PCOPYDATASTRUCT cd = (PCOPYDATASTRUCT)lParam;
			if (memcmp (&cd->dwData, WM_COPY_SET_VOLUME_NAME, 4) == 0)
			{
				if (cd->cbData > 0)
				{
					((wchar_t *) cd->lpData)[(cd->cbData / sizeof (wchar_t)) - 1] = 0;
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), (wchar_t *)cd->lpData, bHistory);
				}

				EnableDisableButtons (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_DRIVELIST));
			}
		}
		return 1;

	case WM_CLOSE:
		EndMainDlg (hwndDlg);
		return 1;

	case WM_INITMENUPOPUP:
		{
			// disable "Set Header Key Derivation Algorithm" entry in "Volumes" menu
			// "Volumes" menu is the first (index 0) submenu of the main menu
			if ((HMENU) wParam == GetSubMenu (GetMenu (hwndDlg), 0))
			{
				if (ActiveSysEncDeviceSelected ())
					EnableMenuItem (GetMenu (hwndDlg), IDM_CHANGE_HEADER_KEY_DERIV_ALGO, MF_GRAYED);
				else
					EnableMenuItem (GetMenu (hwndDlg), IDM_CHANGE_HEADER_KEY_DERIV_ALGO, MF_ENABLED);
			}
		}
		return 1;

	default:
		// Recreate tray icon if Explorer restarted
		if (taskBarCreatedMsg != 0 && uMsg == taskBarCreatedMsg && TaskBarIconMutex != NULL)
		{
			TaskBarIconRemove (hwndDlg);
			TaskBarIconAdd (hwndDlg);
			CheckMountList(hwndDlg, TRUE);
			return 1;
		}
	}

	return 0;
}

void ExtractCommandLine (HWND hwndDlg, wchar_t *lpszCommandLine)
{
	wchar_t **lpszCommandLineArgs = NULL;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */
	wchar_t tmpPath[MAX_PATH * 2];

	/* Defaults */
	mountOptions.PreserveTimestamp = TRUE;

	if (_wcsicmp (lpszCommandLine, L"-Embedding") == 0)
	{
		ComServerMode = TRUE;
		return;
	}

	/* Extract command line arguments */
	NoCmdLineArgs = nNoCommandLineArgs = Win32CommandLine (&lpszCommandLineArgs);

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
				OptionTokenPin,
				OptionVolume,
				CommandWipeCache,
				OptionPkcs5,
				OptionTrueCryptMode,
				OptionPim,
				OptionTryEmptyPassword,
				OptionNoWaitDlg,
				OptionSecureDesktop,
			};

			argument args[]=
			{
				{ OptionAuto,					L"/auto",			L"/a", FALSE },
				{ OptionBeep,					L"/beep",			L"/b", FALSE },
				{ OptionCache,					L"/cache",			L"/c", FALSE },
				{ CommandDismount,				L"/dismount",		L"/d", FALSE },
				{ OptionExplore,				L"/explore",			L"/e", FALSE },
				{ OptionForce,					L"/force",			L"/f", FALSE },
				{ OptionPkcs5,					L"/hash",			NULL , FALSE },
				{ CommandHelp,					L"/help",			L"/?", FALSE },
				{ OptionHistory,				L"/history",			L"/h", FALSE },
				{ OptionKeyfile,				L"/keyfile",			L"/k", FALSE },
				{ OptionLetter,					L"/letter",			L"/l", FALSE },
				{ OptionMountOption,			L"/mountoption",		L"/m", FALSE },
				{ OptionPassword,				L"/password",		L"/p", FALSE },
				{ OptionPim,					L"/pim",				NULL, FALSE },
				{ OptionQuit,					L"/quit",			L"/q", FALSE },
				{ OptionSilent,					L"/silent",			L"/s", FALSE },
				{ OptionTokenLib,				L"/tokenlib",		NULL, FALSE },
				{ OptionTokenPin,				L"/tokenpin",		NULL, FALSE },
				{ OptionTrueCryptMode,			L"/truecrypt",			L"/tc", FALSE },
				{ OptionVolume,					L"/volume",			L"/v", FALSE },
				{ CommandWipeCache,				L"/wipecache",		L"/w", FALSE },
				{ OptionTryEmptyPassword,		L"/tryemptypass",	NULL, FALSE },
				{ OptionNoWaitDlg,			L"/nowaitdlg",	NULL, FALSE },
				{ OptionSecureDesktop,			L"/secureDesktop",	NULL, FALSE },
			};

			argumentspec as;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);

			switch (GetArgumentID (&as, lpszCommandLineArgs[i]))
			{
			case OptionAuto:
				{
					wchar_t szTmp[32] = {0};
					bAuto = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp (szTmp, L"devices"))
							bAutoMountDevices = TRUE;
						else if (!_wcsicmp (szTmp, L"favorites"))
							bAutoMountFavorites = TRUE;
						else if (!_wcsicmp (szTmp, L"logon"))
							LogOn = TRUE;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionBeep:
				bBeep = TRUE;
				break;

			case OptionTryEmptyPassword:
				{
					wchar_t szTmp[16] = {0};
					bCmdTryEmptyPasswordWhenKeyfileUsed = TRUE;
					bCmdTryEmptyPasswordWhenKeyfileUsedValid = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
							bCmdTryEmptyPasswordWhenKeyfileUsed = FALSE;
						else if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
							bCmdTryEmptyPasswordWhenKeyfileUsed = TRUE;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionNoWaitDlg:
				{
					wchar_t szTmp[16] = {0};
					bCmdHideWaitingDialog = TRUE;
					bCmdHideWaitingDialogValid = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
							bCmdHideWaitingDialog = FALSE;
						else if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
							bCmdHideWaitingDialog = TRUE;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionSecureDesktop:
				{
					wchar_t szTmp[16] = {0};
					bCmdUseSecureDesktop = TRUE;
					bCmdUseSecureDesktopValid = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
							bCmdUseSecureDesktop = FALSE;
						else if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
							bCmdUseSecureDesktop = TRUE;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionCache:
				{
					wchar_t szTmp[16] = {0};
					bCacheInDriver = TRUE;
					bIncludePimInCache = FALSE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
							bCacheInDriver = FALSE;
						else if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
							bCacheInDriver = TRUE;
						else if (!_wcsicmp(szTmp,L"p") || !_wcsicmp(szTmp,L"pim"))
						{
							bCacheInDriver = TRUE;
							bIncludePimInCache = TRUE;
						}
						else if (!_wcsicmp(szTmp,L"f") || !_wcsicmp(szTmp,L"favorites"))
						{
							bCacheInDriver = FALSE;
							bCmdCacheDuringMultipleMount = TRUE;
						}
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case CommandDismount:

				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
				     szDriveLetter, ARRAYSIZE (szDriveLetter)))
				{
					if (	(wcslen(szDriveLetter) == 1)
						|| (wcslen(szDriveLetter) == 2 && szDriveLetter[1] == L':')
						)
					{
						cmdUnmountDrive = towupper(szDriveLetter[0]) - L'A';
						if ((cmdUnmountDrive < 0) || (cmdUnmountDrive > (L'Z' - L'A')))
							AbortProcess ("BAD_DRIVE_LETTER");
					}
					else
						AbortProcess ("BAD_DRIVE_LETTER");

				}
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
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i,
					nNoCommandLineArgs, tmpPath, ARRAYSIZE (tmpPath)))
				{
					KeyFile *kf;
					RelativePath2Absolute (tmpPath);
					kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						StringCchCopyW (kf->FileName, ARRAYSIZE(kf->FileName), tmpPath);
						FirstCmdKeyFile = KeyFileAdd (FirstCmdKeyFile, kf);
					}
				}
				else
					AbortProcess ("COMMAND_LINE_ERROR");

				break;

			case OptionLetter:
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
					szDriveLetter, ARRAYSIZE (szDriveLetter)))
				{
					if (	(wcslen(szDriveLetter) == 1)
						|| (wcslen(szDriveLetter) == 2 && szDriveLetter[1] == L':')
						)
					{
						commandLineDrive = *szDriveLetter = (wchar_t) towupper (*szDriveLetter);

						if (commandLineDrive < L'A' || commandLineDrive > L'Z')
							AbortProcess ("BAD_DRIVE_LETTER");
					}
					else
						AbortProcess ("BAD_DRIVE_LETTER");
				}
				else
					AbortProcess ("BAD_DRIVE_LETTER");

				break;

			case OptionHistory:
				{
					wchar_t szTmp[8] = {0};
					bHistory = bHistoryCmdLine = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
							bHistory = FALSE;
						else if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
							bHistory = TRUE;
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionMountOption:
				{
					wchar_t szTmp[64] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp (szTmp, L"ro") || !_wcsicmp (szTmp, L"readonly"))
							mountOptions.ReadOnly = TRUE;

						else if (!_wcsicmp (szTmp, L"rm") || !_wcsicmp (szTmp, L"removable"))
							mountOptions.Removable = TRUE;

						else if (!_wcsicmp (szTmp, L"ts") || !_wcsicmp (szTmp, L"timestamp"))
							mountOptions.PreserveTimestamp = FALSE;

						else if (!_wcsicmp (szTmp, L"sm") || !_wcsicmp (szTmp, L"system"))
							mountOptions.PartitionInInactiveSysEncScope = bPrebootPasswordDlgMode = TRUE;

						else if (!_wcsicmp (szTmp, L"bk") || !_wcsicmp (szTmp, L"headerbak"))
							mountOptions.UseBackupHeader = TRUE;

						else if (!_wcsicmp (szTmp, L"recovery"))
							mountOptions.RecoveryMode = TRUE;
						else if ((wcslen(szTmp) > 6) && (wcslen(szTmp) <= 38) && !_wcsnicmp (szTmp, L"label=", 6))
						{
							// get the label
							StringCbCopyW (mountOptions.Label, sizeof (mountOptions.Label), &szTmp[6]);
						}
						else
							AbortProcess ("COMMAND_LINE_ERROR");

						CmdMountOptions = mountOptions;
						CmdMountOptionsValid = TRUE;
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionPassword:
				{
					wchar_t szTmp[MAX_PASSWORD + 1];
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
								  szTmp, ARRAYSIZE (szTmp)))
					{
						int iLen = WideCharToMultiByte (CP_UTF8, 0, szTmp, -1, (char*) CmdVolumePassword.Text, MAX_PASSWORD + 1, NULL, NULL);
						burn (szTmp, sizeof (szTmp));
						if (iLen > 0)
						{
							CmdVolumePassword.Length = (unsigned __int32) (iLen - 1);
							CmdVolumePasswordValid = TRUE;
						}
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionVolume:
				if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i,
								      nNoCommandLineArgs, szFileName, ARRAYSIZE (szFileName)))
				{
					RelativePath2Absolute (szFileName);
					AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
					CmdLineVolumeSpecified = TRUE;
				}
				else
					AbortProcess ("COMMAND_LINE_ERROR");
				break;

			case OptionQuit:
				{
					wchar_t szTmp[32] = {0};

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp (szTmp, L"UAC")) // Used to indicate non-install elevation
							break;

						else if (!_wcsicmp (szTmp, L"preferences"))
						{
							Quit = TRUE;
							UsePreferences = TRUE;
							break;
						}

						else if (!_wcsicmp (szTmp, L"background"))
							bEnableBkgTask = TRUE;

						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}

					Quit = TRUE;
					UsePreferences = FALSE;
				}
				break;

			case OptionSilent:
				Silent = TRUE;
				break;

			case OptionTokenLib:
				if (GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, SecurityTokenLibraryPath, ARRAYSIZE (SecurityTokenLibraryPath)) == HAS_ARGUMENT)
					InitSecurityTokenLibrary(hwndDlg);
				else
					AbortProcess ("COMMAND_LINE_ERROR");

				break;

			case OptionTokenPin:
				{
					wchar_t szTmp[SecurityToken::MaxPasswordLength + 1] = {0};
					if (GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)) == HAS_ARGUMENT)
					{
						if (0 == WideCharToMultiByte (CP_UTF8, 0, szTmp, -1, CmdTokenPin, TC_MAX_PATH, nullptr, nullptr))
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}

				break;

			case CommandWipeCache:
				bWipe = TRUE;
				break;

			case CommandHelp:
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);
				exit(0);
				break;

			case OptionPkcs5:
				{
					wchar_t szTmp[32] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						/* match against special names first */
						if (_wcsicmp(szTmp, L"sha512") == 0)
							CmdVolumePkcs5 = SHA512;
						else if (_wcsicmp(szTmp, L"sha256") == 0)
							CmdVolumePkcs5 = SHA256;
						else if (_wcsicmp(szTmp, L"ripemd160") == 0)
							CmdVolumePkcs5 = RIPEMD160;
						else
						{
							/* match using internal hash names */
							CmdVolumePkcs5 = HashGetIdByName (szTmp);
							if (0 == CmdVolumePkcs5)
							{
								AbortProcess ("COMMAND_LINE_ERROR");
							}
						}
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionPim:
				{
					wchar_t szTmp[32] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						wchar_t* endPtr = NULL;
						CmdVolumePim = (int) wcstol(szTmp, &endPtr, 0);
						if (CmdVolumePim < 0 || CmdVolumePim > MAX_PIM_VALUE || endPtr == szTmp || *endPtr != L'\0')
						{
							CmdVolumePim = 0;
							AbortProcess ("COMMAND_LINE_ERROR");
						}

					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionTrueCryptMode:
				CmdVolumeTrueCryptMode = TRUE;
				break;

				// no option = file name if there is only one argument
			default:
				{
					if (nNoCommandLineArgs == 1)
					{
						StringCbCopyW (szFileName, array_capacity (szFileName), lpszCommandLineArgs[i]);
						RelativePath2Absolute (szFileName);

						CmdLineVolumeSpecified = TRUE;
						AddComboItem (GetDlgItem (hwndDlg, IDC_VOLUME), szFileName, bHistory);
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
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

static void SystemFavoritesServiceLogMessage (const wstring &errorMessage, WORD wType)
{
	HANDLE eventSource = RegisterEventSource (NULL, TC_SYSTEM_FAVORITES_SERVICE_NAME);

	if (eventSource)
	{
		LPCTSTR strings[] = { TC_SYSTEM_FAVORITES_SERVICE_NAME, errorMessage.c_str() };
		ReportEvent (eventSource, wType, 0, 0xC0000000 + wType, NULL, array_capacity (strings), 0, strings, NULL);

		DeregisterEventSource (eventSource);
	}
}

static void SystemFavoritesServiceLogError (const wstring &errorMessage)
{
	SystemFavoritesServiceLogMessage (errorMessage, EVENTLOG_ERROR_TYPE);
}

static void SystemFavoritesServiceLogWarning (const wstring &warningMessage)
{
	SystemFavoritesServiceLogMessage (warningMessage, EVENTLOG_WARNING_TYPE);
}

static void SystemFavoritesServiceLogInfo (const wstring &infoMessage)
{
	SystemFavoritesServiceLogMessage (infoMessage, EVENTLOG_INFORMATION_TYPE);
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

static LONG WINAPI SystemFavoritesServiceExceptionHandler (EXCEPTION_POINTERS *ep)
{
	SetUnhandledExceptionFilter (NULL);

	if (!(ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD))
		WipeCache (NULL, TRUE);

	UnhandledExceptionFilter (ep);
	return EXCEPTION_EXECUTE_HANDLER;
}

static void SystemFavoritesServiceInvalidParameterHandler (const wchar_t *expression, const wchar_t *function, const wchar_t *file, unsigned int line, uintptr_t reserved)
{
	TC_THROW_FATAL_EXCEPTION;
}

static VOID WINAPI SystemFavoritesServiceMain (DWORD argc, LPTSTR *argv)
{
	BOOL status = FALSE;
	memset (&SystemFavoritesServiceStatus, 0, sizeof (SystemFavoritesServiceStatus));
	SystemFavoritesServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

	SystemFavoritesServiceStatusHandle = RegisterServiceCtrlHandler (TC_SYSTEM_FAVORITES_SERVICE_NAME, SystemFavoritesServiceCtrlHandler);
	if (!SystemFavoritesServiceStatusHandle)
		return;

	InitGlobalLocks ();

	SetUnhandledExceptionFilter (SystemFavoritesServiceExceptionHandler);
	_set_invalid_parameter_handler (SystemFavoritesServiceInvalidParameterHandler);

	SystemFavoritesServiceSetStatus (SERVICE_START_PENDING, 120000);

	SystemFavoritesServiceLogInfo (wstring (L"Initializing list of host devices"));
	// initialize the list of devices available for mounting as early as possible
	UpdateMountableHostDeviceList (true);

	SystemFavoritesServiceLogInfo (wstring (L"Starting System Favorites mounting process"));

	try
	{
		status = MountFavoriteVolumes (NULL, TRUE);
	}
	catch (...) { }

	if (status)
	{
		SystemFavoritesServiceLogInfo (wstring (L"System Favorites mounting process finished"));
	}
	else
	{
		SystemFavoritesServiceLogError (wstring (L"System Favorites mounting process failed."));
	}

	FinalizeGlobalLocks ();

	SystemFavoritesServiceSetStatus (SERVICE_RUNNING);
	SystemFavoritesServiceSetStatus (SERVICE_STOPPED);
}


static BOOL StartSystemFavoritesService ()
{
	ServiceMode = TRUE;
	Silent = TRUE;
	DeviceChangeBroadcastDisabled = TRUE;
	bShowDisconnectedNetworkDrives = TRUE;
	bHideWaitingDialog = TRUE;
	bUseSecureDesktop = FALSE;

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

#ifndef VCEXPANDER
int WINAPI wWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, wchar_t *lpszCommandLine, int nCmdShow)
{
	int argc;
	LPWSTR *argv = CommandLineToArgvW (GetCommandLineW(), &argc);

	if (argv && argc == 2 && wstring (TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION) == argv[1])
		return StartSystemFavoritesService() ? 0 : 1;

	int status;
	atexit (localcleanup);
	SetProcessShutdownParameters (0x100, 0);

	VirtualLock (&VolumePassword, sizeof (VolumePassword));
	VirtualLock (&CmdVolumePassword, sizeof (CmdVolumePassword));
	VirtualLock (&mountOptions, sizeof (mountOptions));
	VirtualLock (&defaultMountOptions, sizeof (defaultMountOptions));
	VirtualLock (&szFileName, sizeof(szFileName));	

	DetectX86Features ();

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

	InitApp (hInstance, lpszCommandLine);

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = L"VeraCrypt";

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
#endif


BOOL TaskBarIconAdd (HWND hwnd)
{
	NOTIFYICONDATAW tnid;

	ZeroMemory (&tnid, sizeof (tnid));

	// Only one icon may be created
	if (TaskBarIconMutex != NULL) return TRUE;

	TaskBarIconMutex = CreateMutex (NULL, TRUE, L"VeraCryptTaskBarIcon");
	if (TaskBarIconMutex == NULL || GetLastError () == ERROR_ALREADY_EXISTS)
	{
		if (TaskBarIconMutex != NULL)
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

			if (	bResult
				&&	(	(prop.driveNo == i) && prop.uniqueId >= 0
					&& prop.ea >= EAGetFirst() && prop.ea <= EAGetCount()
					&& prop.mode >= FIRST_MODE_OF_OPERATION_ID && prop.mode <= LAST_MODE_OF_OPERATION
					&& prop.pkcs5 >= FIRST_PRF_ID && prop.pkcs5 <= LAST_PRF_ID
					&& prop.pkcs5Iterations > 0
					&& prop.hiddenVolProtection >= 0 && prop.volFormatVersion >= 0
					&& prop.volumePim >= 0
					)
				)
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

static BOOL MountFavoriteVolumeBase (HWND hwnd, const FavoriteVolume &favorite, BOOL& lastbExplore, BOOL& userForcedReadOnly, BOOL systemFavorites, BOOL logOnMount, BOOL hotKeyMount, const FavoriteVolume &favoriteVolumeToMount)
{
	BOOL status = TRUE;
	int drive;
	std::wstring effectiveVolumePath;
	drive = towupper (favorite.MountPoint[0]) - L'A';

	if ((drive < MIN_MOUNTED_VOLUME_DRIVE_NUMBER) || (drive > MAX_MOUNTED_VOLUME_DRIVE_NUMBER))
	{
		if (!systemFavorites)
			Error ("DRIVE_LETTER_UNAVAILABLE", MainDlg);
		else if (ServiceMode && systemFavorites)
		{
			SystemFavoritesServiceLogError (wstring (L"The drive letter ") + (wchar_t) (drive + L'A') + wstring (L" used by favorite \"") + favorite.Path + L"\" is invalid.\nThis system favorite will not be mounted");
		}
		return FALSE;
	}

	mountOptions.ReadOnly = favorite.ReadOnly || userForcedReadOnly;
	mountOptions.Removable = favorite.Removable;
	if (favorite.UseLabelInExplorer && !favorite.Label.empty())
		StringCbCopyW (mountOptions.Label, sizeof (mountOptions.Label), favorite.Label.c_str());
	else
		ZeroMemory (mountOptions.Label, sizeof (mountOptions.Label));

	if (favorite.UseVolumeID && !IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID)))
	{
		effectiveVolumePath = FindDeviceByVolumeID (favorite.VolumeID);
	}
	else
		effectiveVolumePath = favorite.Path;

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

		wstring mountPoint = (wchar_t) (drive + L'A') + wstring (L":\\");
		wchar_t prevVolumeAtMountPoint[MAX_PATH] = { 0 };

		if (systemFavorites)
		{
			// Partitions of new drives are assigned free drive letters by Windows on boot. Make sure this does not prevent system favorite volumes
			// from being mounted. Each partition (using the same drive letter as a system favorite volume) is assigned another free drive letter.

			if (GetVolumeNameForVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint, ARRAYSIZE (prevVolumeAtMountPoint)))
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
			/* Priority is given to command line parameters
			 * Default values used only when nothing specified in command line
			 */
			if (CmdVolumePkcs5 == 0)
				mountOptions.ProtectedHidVolPkcs5Prf = DefaultVolumePkcs5;
			else
				mountOptions.ProtectedHidVolPkcs5Prf = CmdVolumePkcs5;
			mountOptions.ProtectedHidVolPim = CmdVolumePim;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwnd, (DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions) == IDCANCEL)
			{
				status = FALSE;
				goto skipMount;
			}
		}

		BOOL prevReadOnly = mountOptions.ReadOnly;

		if (ServiceMode)
			SystemFavoritesServiceLogInfo (wstring (L"Mounting system favorite \"") + effectiveVolumePath + L"\"");

		status = Mount (hwnd, drive, (wchar_t *) effectiveVolumePath.c_str(), favorite.Pim, favorite.Pkcs5, favorite.TrueCryptMode);

		if (ServiceMode)
		{
			// Update the service status to avoid being killed
			SystemFavoritesServiceStatus.dwCheckPoint++;
			SystemFavoritesServiceSetStatus (SERVICE_START_PENDING, 120000);

			if (status)
			{
				SystemFavoritesServiceLogInfo (wstring (L"Favorite \"") + effectiveVolumePath + wstring (L"\" mounted successfully as ") + (wchar_t) (drive + L'A') + L":");
			}
			else
			{
				SystemFavoritesServiceLogError (wstring (L"Favorite \"") + effectiveVolumePath + L"\" failed to mount");
			}
		}

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
					mountPoint[0] = (wchar_t) (freeDrive + L'A');
					SetVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint);
				}
			}
			else
				SetVolumeMountPoint (mountPoint.c_str(), prevVolumeAtMountPoint);
		}

		LoadDriveLetters (MainDlg, GetDlgItem (MainDlg, IDC_DRIVELIST), 0);

		MountVolumesAsSystemFavorite = FALSE;

		if (ServiceMode && LastMountedVolumeDirty)
		{
			DWORD bytesOut;
			DeviceIoControl (hDriver, TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY, NULL, 0, NULL, 0, &bytesOut, NULL);

			SystemFavoritesServiceLogError (wstring (L"The filesystem of the volume mounted as ") + (wchar_t) (drive + L'A') + L": was not cleanly dismounted and needs to be checked for errors.");
		}
	}
	else if (!systemFavorites && !favoriteVolumeToMount.Path.empty())
		Error ("DRIVE_LETTER_UNAVAILABLE", MainDlg);
	else if (ServiceMode && systemFavorites)
	{
		SystemFavoritesServiceLogError (wstring (L"The drive letter ") + (wchar_t) (drive + L'A') + wstring (L" used by favorite \"") + effectiveVolumePath + L"\" is already taken.\nThis system favorite will not be mounted");
	}

	return status;
}


BOOL MountFavoriteVolumes (HWND hwnd, BOOL systemFavorites, BOOL logOnMount, BOOL hotKeyMount, const FavoriteVolume &favoriteVolumeToMount)
{
	BOOL bRet = TRUE, status = TRUE;
	BOOL lastbExplore;
	BOOL userForcedReadOnly = FALSE;

	if (ServiceMode)
	{
		// in service case, intialize some global variable here.
		LastKnownMountList.ulMountedDrives = 0;
		LoadDriveLetters (MainDlg, GetDlgItem (MainDlg, IDC_DRIVELIST), 0);
	}

	mountOptions = defaultMountOptions;

	VolumePassword.Length = 0;
	MultipleMountOperationInProgress = (favoriteVolumeToMount.Path.empty() || FavoriteMountOnArrivalInProgress);

	vector <FavoriteVolume> favorites, skippedSystemFavorites;

	if (systemFavorites)
	{
		try
		{
			if (ServiceMode)
				SystemFavoritesServiceLogInfo (wstring (L"Reading System Favorites XML file"));
			LoadFavoriteVolumes (favorites, true);

			if (ServiceMode)
			{
				wchar_t szTmp[32];
				StringCbPrintf (szTmp, sizeof(szTmp), L"%d", (int) favorites.size());
				SystemFavoritesServiceLogInfo (wstring (L"Loaded ") + szTmp + wstring (L" favorites from the file"));

				/* correct set the connected state of the system favorites */
				for (vector <FavoriteVolume>::iterator favorite = favorites.begin();
					favorite != favorites.end(); favorite++)
				{
					if (favorite->UseVolumeID)
					{
						std::wstring path = FindDeviceByVolumeID (favorite->VolumeID);
						if (path.empty ())
						{
							favorite->DisconnectedDevice = true;
						}
						else
						{
							favorite->DisconnectedDevice = false;
							favorite->Path = path;
							favorite->UseVolumeID = false; /* force the use of real path to avoid calling FindDeviceByVolumeID again */
						}
					}
				}
			}
		}
		catch (...)
		{
			if (ServiceMode)
				SystemFavoritesServiceLogError (wstring (L"An error occured while reading System Favorites XML file"));
			return false;
		}
	}
	else if (!favoriteVolumeToMount.Path.empty())
		favorites.push_back (favoriteVolumeToMount);
	else
		favorites = FavoriteVolumes;

	foreach (const FavoriteVolume &favorite, favorites)
	{
		if (ServiceMode && systemFavorites && favorite.DisconnectedDevice)
		{
			skippedSystemFavorites.push_back (favorite);
			if (favorite.UseVolumeID)
				SystemFavoritesServiceLogWarning (wstring (L"Favorite \"ID:") + ArrayToHexWideString (favorite.VolumeID, sizeof (favorite.VolumeID)) + L"\" is disconnected. It will be ignored.");
			else
				SystemFavoritesServiceLogWarning (wstring (L"Favorite \"") + favorite.Path + L"\" is disconnected. It will be ignored.");
		}

		if (favorite.DisconnectedDevice
			|| (logOnMount && !favorite.MountOnLogOn)
			|| (hotKeyMount && favorite.DisableHotkeyMount))
		{
			continue;
		}

		status = MountFavoriteVolumeBase (hwnd, favorite, lastbExplore, userForcedReadOnly, systemFavorites, logOnMount, hotKeyMount, favoriteVolumeToMount);
		if (!status)
			bRet = FALSE;
	}

	if (systemFavorites && ServiceMode && !skippedSystemFavorites.empty())
	{
		// Some drives need more time to initialize correctly.
		// We retry 4 times after sleeping 5 seconds
		int retryCounter = 0;
		size_t remainingFavorites = skippedSystemFavorites.size();
		while ((remainingFavorites > 0) && (retryCounter++ < 4))
		{
			Sleep (5000);

			SystemFavoritesServiceLogInfo (wstring (L"Updating list of host devices"));
			UpdateMountableHostDeviceList (true);

			SystemFavoritesServiceLogInfo (wstring (L"Trying to mount skipped system favorites"));

			// Update the service status to avoid being killed
			SystemFavoritesServiceStatus.dwCheckPoint++;
			SystemFavoritesServiceSetStatus (SERVICE_START_PENDING, 120000);

			for (vector <FavoriteVolume>::iterator favorite = skippedSystemFavorites.begin();
					favorite != skippedSystemFavorites.end(); favorite++)
			{
				if (favorite->DisconnectedDevice)
				{
					// check if the favorite is here and get its path
					wstring resolvedPath;
					if (favorite->UseVolumeID)
					{
						resolvedPath = FindDeviceByVolumeID (favorite->VolumeID);
					}
					else
						resolvedPath = VolumeGuidPathToDevicePath (favorite->Path);
					if (!resolvedPath.empty())
					{
						favorite->DisconnectedDevice = false;
						favorite->VolumePathId = favorite->Path;
						favorite->Path = resolvedPath;

						remainingFavorites--;

						// favorite OK.
						if (favorite->UseVolumeID)
							SystemFavoritesServiceLogInfo (wstring (L"Favorite \"ID:") + ArrayToHexWideString (favorite->VolumeID, sizeof (favorite->VolumeID)) + L"\" is connected. Performing mount.");
						else
							SystemFavoritesServiceLogInfo (wstring (L"Favorite \"") + favorite->VolumePathId + L"\" is connected. Performing mount.");

						status = MountFavoriteVolumeBase (hwnd, *favorite, lastbExplore, userForcedReadOnly, systemFavorites, logOnMount, hotKeyMount, favoriteVolumeToMount);
						if (!status)
							bRet = FALSE;
					}
				}
			}

			if (remainingFavorites == 0)
				SystemFavoritesServiceLogInfo (wstring (L"All skipped system favorites have been processed"));
			else
			{
				wchar_t szTmp[32];
				StringCbPrintfW (szTmp, sizeof(szTmp), L"%d", (int) remainingFavorites);
				SystemFavoritesServiceLogWarning (wstring (L"Number of unprocessed system favorites is ") + szTmp);
			}
		}
	}

	MultipleMountOperationInProgress = FALSE;
	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));

	if (bRet && CloseSecurityTokenSessionsAfterMount)
		SecurityToken::CloseAllSessions();

	return bRet;
}

void CALLBACK mountFavoriteVolumeCallbackFunction (void *pArg, HWND hwnd)
{
	mountFavoriteVolumeThreadParam* pParam = (mountFavoriteVolumeThreadParam*) pArg;

	if (pParam)
	{
		if (pParam->favoriteVolumeToMount)
			MountFavoriteVolumes (hwnd, pParam->systemFavorites, pParam->logOnMount, pParam->hotKeyMount, *(pParam->favoriteVolumeToMount));
		else
			MountFavoriteVolumes (hwnd, pParam->systemFavorites, pParam->logOnMount, pParam->hotKeyMount);

		free (pParam);
	}
	else
		MountFavoriteVolumes (hwnd);
}

void __cdecl mountFavoriteVolumeThreadFunction (void *pArg)
{
	ShowWaitDialog (MainDlg, FALSE, mountFavoriteVolumeCallbackFunction, pArg);
}

static void SaveDefaultKeyFilesParam (HWND hwnd)
{
	if (defaultKeyFilesParam.FirstKeyFile == NULL)
	{
		/* No keyfiles selected */
		_wremove (GetConfigPath (TC_APPD_FILENAME_DEFAULT_KEYFILES));
	}
	else
	{
		FILE *f;
		KeyFile *kf = FirstKeyFile;

		f = _wfopen (GetConfigPath (TC_APPD_FILENAME_DEFAULT_KEYFILES), L"w,ccs=UTF-8");
		if (f == NULL)
		{
			handleWin32Error (MainDlg, SRC_POS);
			return;
		}

		XmlWriteHeader (f);

		fputws (L"\n\t<defaultkeyfiles>", f);

		while (kf != NULL)
		{
			wchar_t q[TC_MAX_PATH * 2];

			XmlQuoteTextW (kf->FileName, q, ARRAYSIZE (q));
			fwprintf (f, L"\n\t\t<keyfile>%s</keyfile>", q);

			kf = kf->Next;
		}

		fputws (L"\n\t</defaultkeyfiles>", f);

		XmlWriteFooter (f);

		CheckFileStreamWriteErrors (hwnd, f, TC_APPD_FILENAME_DEFAULT_KEYFILES);
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
		if (!param.EnableKeyFiles || AskWarnYesNo ("CONFIRM_SAVE_DEFAULT_KEYFILES", hwndDlg) == IDYES)
		{
			KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
			defaultKeyFilesParam.EnableKeyFiles = param.EnableKeyFiles;
			defaultKeyFilesParam.FirstKeyFile = param.FirstKeyFile;

			RestoreDefaultKeyFilesParam ();
			SaveDefaultKeyFilesParam (hwndDlg);
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
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", (wParam == HK_DISMOUNT_ALL_AND_WIPE ? "VOLUMES_DISMOUNTED_CACHE_WIPED" : "MOUNTED_VOLUMES_DISMOUNTED"), hwndDlg);

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
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "VOLUMES_DISMOUNTED_CACHE_WIPED", hwndDlg);

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
				InfoBalloon ("SUCCESSFULLY_DISMOUNTED", "VOLUMES_DISMOUNTED_CACHE_WIPED", hwndDlg);

			if (bPlaySoundOnSuccessfulHkDismount)
				MessageBeep (0xFFFFFFFF);
		}
		TaskBarIconRemove (hwndDlg);
		UnregisterWtsNotification(hwndDlg);
		EndMainDlg (hwndDlg);
		break;

	case HK_MOUNT_FAVORITE_VOLUMES:
		{
			mountFavoriteVolumeThreadParam* pParam = (mountFavoriteVolumeThreadParam*) calloc(1, sizeof(mountFavoriteVolumeThreadParam));
			pParam->systemFavorites = FALSE;
			pParam->logOnMount = FALSE;
			pParam->hotKeyMount = TRUE;
			pParam->favoriteVolumeToMount = NULL;

			_beginthread(mountFavoriteVolumeThreadFunction, 0, pParam);
		}
		break;

	case HK_SHOW_HIDE_MAIN_WINDOW:
		ChangeMainWindowVisibility ();
		break;

	case HK_CLOSE_SECURITY_TOKEN_SESSIONS:
		SecurityToken::CloseAllSessions();

		InfoBalloon (NULL, "ALL_TOKEN_SESSIONS_CLOSED", hwndDlg);

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


int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, const wchar_t *lpszVolume)
{
	int nStatus = ERR_OS_ERROR;
	wchar_t szTmp[4096];
	int fBackup = -1;
	OpenVolumeContext volume;
	OpenVolumeContext hiddenVolume;
	Password hiddenVolPassword;
	int hiddenVolPkcs5 = 0, hiddenVolPim = 0;
	CRYPTOPP_ALIGN_DATA(16) byte temporaryKey[MASTER_KEYDATA_SIZE];
	CRYPTOPP_ALIGN_DATA(16) byte originalK2[MASTER_KEYDATA_SIZE];
	int EffectiveVolumePkcs5 = CmdVolumePkcs5;
	int EffectiveVolumePim = CmdVolumePim;

	/* Priority is given to command line parameters
	 * Default values used only when nothing specified in command line
	 */
	if (EffectiveVolumePkcs5 == 0)
		EffectiveVolumePkcs5 = DefaultVolumePkcs5;

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus, SRC_POS);
      return nStatus;
   }

	volume.VolumeIsOpen = FALSE;
	hiddenVolume.VolumeIsOpen = FALSE;

	switch (IsSystemDevicePath (lpszVolume, hwndDlg, TRUE))
	{
	case 1:
	case 2:
		if (AskErrNoYes ("BACKUP_HEADER_NOT_FOR_SYS_DEVICE", hwndDlg) == IDYES)
			CreateRescueDisk (hwndDlg);

		return 0;
	}

	if (IsMountedVolume (lpszVolume))
	{
		Warning ("DISMOUNT_FIRST", hwndDlg);
		goto ret;
	}

	if (!VolumePathExists (lpszVolume))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		goto ret;
	}

	Info ("EXTERNAL_VOL_HEADER_BAK_FIRST_INFO", hwndDlg);


	WaitCursor();

	// Open both types of volumes
	for (int type = TC_VOLUME_TYPE_NORMAL; type <= TC_VOLUME_TYPE_HIDDEN; ++type)
	{
		OpenVolumeContext *askVol = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolume : &volume);
		Password *askPassword = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolPassword : &VolumePassword);
		int* askPkcs5 = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolPkcs5 : &VolumePkcs5);
		int* askPim = (type == TC_VOLUME_TYPE_HIDDEN ? &hiddenVolPim : &VolumePim);

		while (TRUE)
		{
			int GuiPkcs5 = ((EffectiveVolumePkcs5 > 0) && (*askPkcs5 == 0))? EffectiveVolumePkcs5 : *askPkcs5;
			int GuiPim = ((EffectiveVolumePim > 0) && (*askPim <= 0))? EffectiveVolumePim : *askPim;
			if (!AskVolumePassword (hwndDlg, askPassword, &GuiPkcs5, &GuiPim, &VolumeTrueCryptMode, type == TC_VOLUME_TYPE_HIDDEN ? "ENTER_HIDDEN_VOL_PASSWORD" : "ENTER_NORMAL_VOL_PASSWORD", FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}
			else
			{
				*askPkcs5 = GuiPkcs5;
				*askPim = GuiPim;
				burn (&GuiPkcs5, sizeof (GuiPkcs5));
				burn (&GuiPim, sizeof (GuiPim));
			}

			WaitCursor();

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (hwndDlg, askPassword, FirstKeyFile, lpszVolume);

			nStatus = OpenVolume (askVol, lpszVolume, askPassword, *askPkcs5, *askPim, VolumeTrueCryptMode, FALSE, bPreserveTimestamp, FALSE);

			NormalCursor();

			if (nStatus == ERR_SUCCESS)
			{
				if ((type == TC_VOLUME_TYPE_NORMAL && askVol->CryptoInfo->hiddenVolume)
					|| (type == TC_VOLUME_TYPE_HIDDEN && !askVol->CryptoInfo->hiddenVolume))
				{
					CloseVolume (askVol);
					handleError (hwndDlg, ERR_PASSWORD_WRONG, SRC_POS);
					continue;
				}

				RandSetHashFunction (askVol->CryptoInfo->pkcs5);

				if (type == TC_VOLUME_TYPE_NORMAL)
				{
					// Ask the user if there is a hidden volume
					char *volTypeChoices[] = {0, "DOES_VOLUME_CONTAIN_HIDDEN", "VOLUME_CONTAINS_HIDDEN", "VOLUME_DOES_NOT_CONTAIN_HIDDEN", "IDCANCEL", 0};
					switch (AskMultiChoice ((void **) volTypeChoices, FALSE, hwndDlg))
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

			handleError (hwndDlg, nStatus, SRC_POS);
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
	if ((fBackup = _wopen(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
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
		if (CryptoAPILastError == ERROR_SUCCESS)
			nStatus = ERR_RAND_INIT_FAILED;
		else
			nStatus = ERR_CAPI_INIT_FAILED;
		goto error;
	}

	/* force the display of the random enriching dialog */
	SetRandomPoolEnrichedByUserStatus (FALSE);

	NormalCursor();
	UserEnrichRandomPool (hwndDlg);
	WaitCursor();

	// Temporary keys
	if (!RandgetBytes (hwndDlg, temporaryKey, EAGetKeySize (volume.CryptoInfo->ea), TRUE)
		|| !RandgetBytes (hwndDlg, volume.CryptoInfo->k2, sizeof (volume.CryptoInfo->k2), FALSE))
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
	nStatus = ReEncryptVolumeHeader (hwndDlg, (char *) backup, FALSE, volume.CryptoInfo, &VolumePassword, VolumePim, FALSE);
	if (nStatus != ERR_SUCCESS)
		goto error;

	if (hiddenVolume.VolumeIsOpen)
	{
		nStatus = ReEncryptVolumeHeader (hwndDlg, (char *) backup + (legacyVolume ? TC_VOLUME_HEADER_SIZE_LEGACY : TC_VOLUME_HEADER_SIZE),
			 FALSE, hiddenVolume.CryptoInfo, &hiddenVolPassword, hiddenVolPim, FALSE);

		if (nStatus != ERR_SUCCESS)
			goto error;
	}

	if (_write (fBackup, backup, backupFileSize) == -1)
	{
		nStatus = ERR_OS_ERROR;
		goto error;
	}

	/* Backup has been successfully created */
	Warning("VOL_HEADER_BACKED_UP", hwndDlg);

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
		handleError (hwndDlg, nStatus, SRC_POS);

	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
	burn (&hiddenVolPassword, sizeof (hiddenVolPassword));
	burn (temporaryKey, sizeof (temporaryKey));
	burn (originalK2, sizeof (originalK2));

	RestoreDefaultKeyFilesParam();
	RandStop (FALSE);
	NormalCursor();

	return nStatus;
}


int RestoreVolumeHeader (HWND hwndDlg, const wchar_t *lpszVolume)
{
	int nDosLinkCreated = -1, nStatus = ERR_OS_ERROR;
	wchar_t szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	wchar_t szFileName[TC_MAX_PATH];
	wchar_t szDosDevice[TC_MAX_PATH];
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
	int EffectiveVolumePkcs5 = CmdVolumePkcs5;
	int EffectiveVolumePim = CmdVolumePim;

	/* Priority is given to command line parameters
	 * Default values used only when nothing specified in command line
	 */
	if (EffectiveVolumePkcs5 == 0)
		EffectiveVolumePkcs5 = DefaultVolumePkcs5;

   if (!lpszVolume)
   {
      nStatus = ERR_OUTOFMEMORY;
      handleError (hwndDlg, nStatus, SRC_POS);
      return nStatus;
   }

	switch (IsSystemDevicePath (lpszVolume, hwndDlg, TRUE))
	{
	case 1:
	case 2:
		if (AskErrNoYes ("RESTORE_HEADER_NOT_FOR_SYS_DEVICE", hwndDlg) == IDYES)
			CreateRescueDisk (hwndDlg);

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
		Warning ("DISMOUNT_FIRST", hwndDlg);
		return 0;
	}

	if (!VolumePathExists (lpszVolume))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		return 0;
	}

	BOOL restoreInternalBackup;

	// Ask the user to select the type of backup (internal/external)
	char *volTypeChoices[] = {0, "HEADER_RESTORE_EXTERNAL_INTERNAL", "HEADER_RESTORE_INTERNAL", "HEADER_RESTORE_EXTERNAL", "IDCANCEL", 0};
	switch (AskMultiChoice ((void **) volTypeChoices, FALSE, hwndDlg))
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

	/* force the display of the random enriching dialog */
	SetRandomPoolEnrichedByUserStatus (FALSE);

	WaitCursor();

	if (restoreInternalBackup)
	{
		// Restore header from the internal backup

		// Open the volume using backup header
		while (TRUE)
		{
			int GuiPkcs5 = ((EffectiveVolumePkcs5 > 0) && (VolumePkcs5 == 0))? EffectiveVolumePkcs5 : VolumePkcs5;
			int GuiPim = ((EffectiveVolumePim > 0) && (VolumePim <= 0))? EffectiveVolumePim : VolumePim;
			StringCbCopyW (PasswordDlgVolume, sizeof(PasswordDlgVolume), lpszVolume);
			if (!AskVolumePassword (hwndDlg, &VolumePassword, &GuiPkcs5, &GuiPim, &VolumeTrueCryptMode, NULL, FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}
			else
			{
				VolumePkcs5 = GuiPkcs5;
				VolumePim = GuiPim;
				burn (&GuiPkcs5, sizeof (GuiPkcs5));
				burn (&GuiPim, sizeof (GuiPim));
			}

			WaitCursor();

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, lpszVolume);

			nStatus = OpenVolume (&volume, lpszVolume, &VolumePassword, VolumePkcs5, VolumePim, VolumeTrueCryptMode,TRUE, bPreserveTimestamp, TRUE);

			NormalCursor();

			if (nStatus == ERR_SUCCESS)
				break;

			if (nStatus != ERR_PASSWORD_WRONG)
				goto error;

			handleError (hwndDlg, nStatus, SRC_POS);
		}

		if (volume.CryptoInfo->LegacyVolume)
		{
			Error ("VOLUME_HAS_NO_BACKUP_HEADER", hwndDlg);
			nStatus = ERROR_SUCCESS;
			goto error;
		}

		// Create a new header with a new salt
		char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];

		nStatus = ReEncryptVolumeHeader (hwndDlg, buffer, FALSE, volume.CryptoInfo, &VolumePassword, VolumePim, FALSE);
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
			StringCbCopyW (szCFDevice, sizeof(szCFDevice), szDiskFile);
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
				DISK_GEOMETRY_EX driveInfo;

				bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
					&driveInfo, sizeof (driveInfo), &dwResult, NULL);

				if (!bResult)
					goto error;

				hostSize = driveInfo.DiskSize.QuadPart;
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
			Error ("HEADER_BACKUP_SIZE_INCORRECT", hwndDlg);
			nStatus = ERR_SUCCESS;
			goto error;
		}

		// Open the header
		while (TRUE)
		{
			int GuiPkcs5 = ((EffectiveVolumePkcs5 > 0) && (VolumePkcs5 == 0))? EffectiveVolumePkcs5 : VolumePkcs5;
			int GuiPim = ((EffectiveVolumePim > 0) && (VolumePim <= 0))? EffectiveVolumePim : VolumePim;
			if (!AskVolumePassword (hwndDlg, &VolumePassword, &GuiPkcs5, &GuiPim, &VolumeTrueCryptMode, "ENTER_HEADER_BACKUP_PASSWORD", FALSE))
			{
				nStatus = ERR_SUCCESS;
				goto ret;
			}
			else
			{
				VolumePkcs5 = GuiPkcs5;
				VolumePim = GuiPim;
				burn (&GuiPkcs5, sizeof (GuiPkcs5));
				burn (&GuiPim, sizeof (GuiPim));
			}

			if (KeyFilesEnable && FirstKeyFile)
				KeyFilesApply (hwndDlg, &VolumePassword, FirstKeyFile, bDevice? NULL : lpszVolume);

			// Decrypt volume header
			headerOffsetBackupFile = 0;
			for (int type = TC_VOLUME_TYPE_NORMAL; type <= TC_VOLUME_TYPE_HIDDEN; ++type)
			{
				if (type == TC_VOLUME_TYPE_HIDDEN)
					headerOffsetBackupFile += (legacyBackup ? TC_VOLUME_HEADER_SIZE_LEGACY : TC_VOLUME_HEADER_SIZE);

				nStatus = ReadVolumeHeader (FALSE, buffer + headerOffsetBackupFile, &VolumePassword, VolumePkcs5, VolumePim, VolumeTrueCryptMode, &restoredCryptoInfo, NULL);
				if (nStatus == ERR_SUCCESS)
					break;
			}

			if (nStatus == ERR_SUCCESS)
				break;

			if (nStatus != ERR_PASSWORD_WRONG)
				goto error;

			handleError (hwndDlg, nStatus, SRC_POS);
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
		nStatus = ReEncryptVolumeHeader (hwndDlg, buffer, FALSE, restoredCryptoInfo, &VolumePassword, VolumePim, FALSE);
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
			nStatus = ReEncryptVolumeHeader (hwndDlg, buffer, FALSE, restoredCryptoInfo, &VolumePassword, VolumePim, FALSE);
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

	Info("VOL_HEADER_RESTORED", hwndDlg);
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
		handleError (hwndDlg, nStatus, SRC_POS);

	burn (&VolumePassword, sizeof (VolumePassword));
	burn (&VolumePkcs5, sizeof (VolumePkcs5));
	burn (&VolumePim, sizeof (VolumePim));
	burn (&VolumeTrueCryptMode, sizeof (VolumeTrueCryptMode));
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
			CheckDlgButton (hwndDlg, IDC_ENABLE_EXTENDED_IOCTL_SUPPORT, (driverConfig & TC_DRIVER_CONFIG_ENABLE_EXTENDED_IOCTL) ? BST_CHECKED : BST_UNCHECKED);

			SYSTEM_INFO sysInfo;
			GetSystemInfo (&sysInfo);

			HWND freeCpuCombo = GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT);
			uint32 encryptionFreeCpuCount = ReadEncryptionThreadPoolFreeCpuCountLimit();

			if (encryptionFreeCpuCount > sysInfo.dwNumberOfProcessors - 1)
				encryptionFreeCpuCount = sysInfo.dwNumberOfProcessors - 1;

			for (uint32 i = 1; i < sysInfo.dwNumberOfProcessors; ++i)
			{
				wstringstream s;
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
					Error ("FEATURE_REQUIRES_INSTALLATION", hwndDlg);
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				BOOL disableHW = !IsDlgButtonChecked (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION);
				BOOL enableExtendedIOCTL = IsDlgButtonChecked (hwndDlg, IDC_ENABLE_EXTENDED_IOCTL_SUPPORT);

				try
				{
					VOLUME_PROPERTIES_STRUCT prop;
					try
					{
						BootEncStatus = BootEncObj->GetStatus();
						BootEncObj->GetVolumeProperties (&prop);
					}
					catch (...)
					{
						BootEncStatus.DriveMounted = false;	
					}

					if (BootEncStatus.DriveMounted && !bSystemIsGPT)
					{
						byte userConfig;
						string customUserMessage;
						uint16 bootLoaderVersion;

						if (!BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig, &customUserMessage, &bootLoaderVersion))
							return 1;

						if (bootLoaderVersion != VERSION_NUM)
							Warning ("BOOT_LOADER_VERSION_INCORRECT_PREFERENCES", hwndDlg);

						if (disableHW)
							userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_HW_ENCRYPTION;
						else
							userConfig &= ~TC_BOOT_USER_CFG_FLAG_DISABLE_HW_ENCRYPTION;

						BootEncObj->WriteBootSectorUserConfig (userConfig, customUserMessage, prop.volumePim, prop.pkcs5);
					}

					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION, disableHW);
					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_ENABLE_EXTENDED_IOCTL, enableExtendedIOCTL);

					DWORD bytesReturned;
					if (!DeviceIoControl (hDriver, TC_IOCTL_REREAD_DRIVER_CONFIG, NULL, 0, NULL, 0, &bytesReturned, NULL))
						handleWin32Error (hwndDlg, SRC_POS);

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
						BootEncObj->WriteLocalMachineRegistryDwordValue (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, cpuFreeCount);
						Warning ("SETTING_REQUIRES_REBOOT", hwndDlg);
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
				&& AskWarnYesNo ("CONFIRM_SETTING_DEGRADES_PERFORMANCE", hwndDlg) == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_ENABLE_HARDWARE_ENCRYPTION, BST_CHECKED);
			}
			return 1;

		case IDC_LIMIT_ENC_THREAD_POOL:
			if (IsDlgButtonChecked (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL)
				&& AskWarnYesNo ("CONFIRM_SETTING_DEGRADES_PERFORMANCE", hwndDlg) == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL, BST_UNCHECKED);
			}
			else
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT), CB_SETCURSEL, 0, 0);
				Warning ("SETTING_REQUIRES_REBOOT", hwndDlg);	// Warn the user before he thinks about benchmarking
			}

			EnableWindow (GetDlgItem (hwndDlg, IDC_ENCRYPTION_FREE_CPU_COUNT), IsDlgButtonChecked (hwndDlg, IDC_LIMIT_ENC_THREAD_POOL));
			return 1;

		case IDC_BENCHMARK:
			Benchmark (hwndDlg);
			return 1;

		case IDC_MORE_INFO_ON_HW_ACCELERATION:
			Applink ("hwacceleration");
			return 1;

		case IDC_MORE_INFO_ON_THREAD_BASED_PARALLELIZATION:
			Applink ("parallelization");
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
				wchar_t securityTokenLibraryPath[MAX_PATH];
				GetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, securityTokenLibraryPath, ARRAYSIZE (securityTokenLibraryPath));

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
					wchar_t prevSecurityTokenLibraryPath[MAX_PATH];
					StringCbCopyW (prevSecurityTokenLibraryPath, sizeof(prevSecurityTokenLibraryPath), SecurityTokenLibraryPath);
					StringCbCopyW (SecurityTokenLibraryPath, sizeof(SecurityTokenLibraryPath), securityTokenLibraryPath);

					if (!InitSecurityTokenLibrary(hwndDlg))
					{
						StringCbCopyW (SecurityTokenLibraryPath, sizeof(SecurityTokenLibraryPath), prevSecurityTokenLibraryPath);
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
				wchar_t systemDir[MAX_PATH];
				GetSystemDirectory (systemDir, ARRAYSIZE (systemDir));
				WIN32_FIND_DATA findData;
				bool found = false;

				WaitCursor();

				HANDLE find = FindFirstFile ((wstring (systemDir) + L"\\*.dll").c_str(), &findData);
				while (!found && find != INVALID_HANDLE_VALUE)
				{
					wstring dllPathname = wstring (systemDir) + L"\\" + findData.cFileName;
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
					Warning ("PKCS11_MODULE_AUTO_DETECTION_FAILED", hwndDlg);

				return 1;
			}

		case IDC_SELECT_PKCS11_MODULE:
			{
				wchar_t securityTokenLibraryPath[MAX_PATH];
				wchar_t systemDir[MAX_PATH];
				wchar_t browseFilter[1024];

				Info ("SELECT_PKCS11_MODULE_HELP", hwndDlg);

				StringCbPrintfW (browseFilter, sizeof(browseFilter), L"%ls (*.dll)%c*.dll%c%c", GetString ("DLL_FILES"), 0, 0, 0);
				GetSystemDirectory (systemDir, ARRAYSIZE (systemDir));

				if (BrowseFilesInDir (hwndDlg, "SELECT_PKCS11_MODULE", systemDir, securityTokenLibraryPath, TRUE, FALSE, browseFilter))
					SetDlgItemText (hwndDlg, IDC_PKCS11_MODULE, securityTokenLibraryPath);
				return 1;
			}
		}
		return 0;
	}

	return 0;
}

static BOOL CALLBACK DefaultMountParametersDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, "IDD_DEFAULT_MOUNT_PARAMETERS");

			SendMessage (GetDlgItem (hwndDlg, IDC_TRUECRYPT_MODE), BM_SETCHECK,
				DefaultVolumeTrueCryptMode ? BST_CHECKED:BST_UNCHECKED, 0);

			/* Populate the PRF algorithms list */
			int i, nIndex, defaultPrfIndex = 0;
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

			nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
			{
				nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				if (DefaultVolumePkcs5 && (DefaultVolumePkcs5 == i))
					defaultPrfIndex = nIndex;
			}

			/* make autodetection the default unless a specific PRF was specified in the command line */
			SendMessage (hComboBox, CB_SETCURSEL, defaultPrfIndex, 0);

			return 0;
		}

	case WM_COMMAND:

		switch (lw)
		{
		case IDCANCEL:
			EndDialog (hwndDlg, lw);
			return 1;

		case IDOK:
			{
				int pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);
				BOOL truecryptMode = GetCheckBox (hwndDlg, IDC_TRUECRYPT_MODE);
				/* check that PRF is supported in TrueCrypt Mode */
				if (	(truecryptMode)
					&& (!is_pkcs5_prf_supported(pkcs5, TRUE, PRF_BOOT_NO))
					)
				{
					Error ("ALGO_NOT_SUPPORTED_FOR_TRUECRYPT_MODE", hwndDlg);
				}
				else
				{
					WaitCursor ();
					DefaultVolumeTrueCryptMode = truecryptMode;
					DefaultVolumePkcs5 = pkcs5;

					SaveSettings (hwndDlg);

					NormalCursor ();
					EndDialog (hwndDlg, lw);
				}
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
	static std::string platforminfo;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			BootEncryptionStatus BootEncStatus = BootEncObj->GetStatus();
			if (!BootEncStatus.DriveMounted)
			{
				Warning ("SYS_DRIVE_NOT_ENCRYPTED", hwndDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			try
			{
				LocalizeDialog (hwndDlg, "IDD_SYSENC_SETTINGS");
				uint32 driverConfig = ReadDriverConfigurationFlags();
				byte userConfig;
				string customUserMessage;
				uint16 bootLoaderVersion = 0;
				BOOL bPasswordCacheEnabled = (driverConfig & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD)? TRUE : FALSE;
				BOOL bPimCacheEnabled = (driverConfig & TC_DRIVER_CONFIG_CACHE_BOOT_PIM)? TRUE : FALSE;

				if (!BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig, &customUserMessage, &bootLoaderVersion))
				{
					// operations canceled
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				if (bootLoaderVersion != VERSION_NUM)
					Warning ("BOOT_LOADER_VERSION_INCORRECT_PREFERENCES", hwndDlg);

				if (bSystemIsGPT)
				{
					CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_HASH_PROMPT, (userConfig & TC_BOOT_USER_CFG_FLAG_STORE_HASH) ? BST_CHECKED : BST_UNCHECKED);
					// read PlatformInfo file if it exists
					try
					{
						platforminfo = ReadESPFile (L"\\EFI\\VeraCrypt\\PlatformInfo", true);						
					}
					catch (Exception &)	{}

					if (platforminfo.length() == 0)
					{
						// could not read PlatformInfo file. Disable corresponding button in UI
						EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PLATFORMINFO), FALSE);
					}
				}
				else
				{
					SendMessage (GetDlgItem (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE), EM_LIMITTEXT, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH, 0);
					SetDlgItemTextA (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE, customUserMessage.c_str());
					CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT, (userConfig & TC_BOOT_USER_CFG_FLAG_SILENT_MODE) ? BST_CHECKED : BST_UNCHECKED);
					CheckDlgButton (hwndDlg, IDC_ALLOW_ESC_PBA_BYPASS, (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_ESC) ? BST_UNCHECKED : BST_CHECKED);
					CheckDlgButton (hwndDlg, IDC_DISABLE_EVIL_MAID_ATTACK_DETECTION, (driverConfig & TC_DRIVER_CONFIG_DISABLE_EVIL_MAID_ATTACK_DETECTION) ? BST_CHECKED : BST_UNCHECKED);
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE_HELP), GetString("CUSTOM_BOOT_LOADER_MESSAGE_HELP"));
				}

				CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_PIM_PROMPT, (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM) ? BST_CHECKED : BST_UNCHECKED);
				CheckDlgButton (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD, bPasswordCacheEnabled ? BST_CHECKED : BST_UNCHECKED);
				EnableWindow (GetDlgItem (hwndDlg, IDC_BOOT_LOADER_CACHE_PIM), bPasswordCacheEnabled);
				CheckDlgButton (hwndDlg, IDC_BOOT_LOADER_CACHE_PIM, (bPasswordCacheEnabled && bPimCacheEnabled)? BST_CHECKED : BST_UNCHECKED);
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
		case IDC_SHOW_PLATFORMINFO:
			TextEditDialogBox(TRUE, hwndDlg, GetString ("EFI_PLATFORM_INFORMATION"), platforminfo);
			return 0;

		case IDC_EDIT_DCSPROP:
			if (AskWarnNoYes ("EDIT_DCSPROP_FOR_ADVANCED_ONLY", hwndDlg) == IDYES)
			{
				try
				{
					std::string dcsprop = ReadESPFile (L"\\EFI\\VeraCrypt\\DcsProp", true);

					while (TextEditDialogBox(FALSE, hwndDlg, GetString ("BOOT_LOADER_CONFIGURATION_FILE"), dcsprop) == IDOK)
					{
						if (validateDcsPropXml (dcsprop.c_str()))
						{
							WriteESPFile (L"\\EFI\\VeraCrypt\\DcsProp", (LPBYTE) dcsprop.c_str(), (DWORD) dcsprop.size(), true);
							break;
						}
						else
						{
							MessageBoxW (hwndDlg, GetString ("DCSPROP_XML_VALIDATION_FAILED"), lpszTitle, ICON_HAND);
						}
					}
				}
				catch (Exception &e)	{	e.Show(hwndDlg); }
			}
			return 0;

		case IDOK:
			{
				VOLUME_PROPERTIES_STRUCT prop;

				if (!BootEncObj->GetStatus().DriveMounted)
				{
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				try
				{
					BootEncObj->GetVolumeProperties (&prop);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				char customUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1] = {0};
				if (!bSystemIsGPT)
					GetDlgItemTextA (hwndDlg, IDC_CUSTOM_BOOT_LOADER_MESSAGE, customUserMessage, sizeof (customUserMessage));

				byte userConfig;
				try
				{
					if (!BootEncObj->ReadBootSectorConfig (nullptr, 0, &userConfig))
						return 1;
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					return 1;
				}

				if (IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_PIM_PROMPT))
					userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_PIM;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_DISABLE_PIM;

				if (bSystemIsGPT)
				{
				if (IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_HASH_PROMPT))
					userConfig |= TC_BOOT_USER_CFG_FLAG_STORE_HASH;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_STORE_HASH;
				}
				else
				{
					if (IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT))
					userConfig |= TC_BOOT_USER_CFG_FLAG_SILENT_MODE;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_SILENT_MODE;

				if (!IsDlgButtonChecked (hwndDlg, IDC_ALLOW_ESC_PBA_BYPASS))
					userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_ESC;
				else
					userConfig &= ~TC_BOOT_USER_CFG_FLAG_DISABLE_ESC;
				}

				try
				{
					BOOL bPasswordCacheEnabled = IsDlgButtonChecked (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD);
					BOOL bPimCacheEnabled = IsDlgButtonChecked (hwndDlg, IDC_BOOT_LOADER_CACHE_PIM);
					BootEncObj->WriteBootSectorUserConfig (userConfig, customUserMessage, prop.volumePim, prop.pkcs5);
					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD, bPasswordCacheEnabled);
					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PIM, (bPasswordCacheEnabled && bPimCacheEnabled)? TRUE : FALSE);
					SetDriverConfigurationFlag (TC_DRIVER_CONFIG_DISABLE_EVIL_MAID_ATTACK_DETECTION, IsDlgButtonChecked (hwndDlg, IDC_DISABLE_EVIL_MAID_ATTACK_DETECTION));
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					return 1;
				}

				EndDialog (hwndDlg, lw);
				return 1;
			}

		case IDC_DISABLE_BOOT_LOADER_PIM_PROMPT:
			if ((IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_PIM_PROMPT))
				&& AskWarnYesNo ("DISABLE_BOOT_LOADER_PIM_PROMPT", hwndDlg) == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_PIM_PROMPT, BST_UNCHECKED);
			}

			break;

		case IDC_DISABLE_BOOT_LOADER_OUTPUT:
			if ((IsDlgButtonChecked (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT))
				&& AskWarnYesNo ("CUSTOM_BOOT_LOADER_MESSAGE_PROMPT", hwndDlg) == IDNO)
			{
				CheckDlgButton (hwndDlg, IDC_DISABLE_BOOT_LOADER_OUTPUT, BST_UNCHECKED);
			}

			break;

		case IDC_BOOT_LOADER_CACHE_PASSWORD:
			if (IsDlgButtonChecked (hwndDlg, IDC_BOOT_LOADER_CACHE_PASSWORD))
			{
				Warning ("BOOT_PASSWORD_CACHE_KEYBOARD_WARNING", hwndDlg);
				EnableWindow (GetDlgItem (hwndDlg, IDC_BOOT_LOADER_CACHE_PIM), TRUE);
			}
			else
			{
				EnableWindow (GetDlgItem (hwndDlg, IDC_BOOT_LOADER_CACHE_PIM), FALSE);
			}

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
		Warning ("NO_VOLUME_SELECTED", hwndDlg);
	}
	else if (LOWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) == TC_MLIST_ITEM_FREE)
	{
		mountOptions = defaultMountOptions;
		bPrebootPasswordDlgMode = FALSE;

		if (mountWithOptions || GetAsyncKeyState (VK_CONTROL) < 0)
		{
			/* Priority is given to command line parameters
			 * Default values used only when nothing specified in command line
			 */
			if (CmdVolumePkcs5 == 0)
				mountOptions.ProtectedHidVolPkcs5Prf = DefaultVolumePkcs5;
			else
				mountOptions.ProtectedHidVolPkcs5Prf = CmdVolumePkcs5;
			mountOptions.ProtectedHidVolPim = CmdVolumePim;
			if (IDCANCEL == DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_MOUNT_OPTIONS), hwndDlg,
				(DLGPROC) MountOptionsDlgProc, (LPARAM) &mountOptions))
				return;

			if (mountOptions.ProtectHiddenVolume && hidVolProtKeyFilesParam.EnableKeyFiles)
			{
				wchar_t selectedVolume [TC_MAX_PATH + 1];
				GetVolumePath (hwndDlg, selectedVolume, ARRAYSIZE (selectedVolume));
				KeyFilesApply (hwndDlg, &mountOptions.ProtectedHidVolPassword, hidVolProtKeyFilesParam.FirstKeyFile, selectedVolume);
			}
		}

		if (CheckMountList (hwndDlg, FALSE))
			_beginthread (mountThreadFunction, 0, hwndDlg);
	}
	else
		Warning ("SELECT_FREE_DRIVE", hwndDlg);
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
	WNDPROC wp = (WNDPROC) GetWindowLongPtrW (hwnd, GWLP_USERDATA);

	switch (message)
	{
	case WM_MOUSEWHEEL:

		if (HandleDriveListMouseWheelEvent (message, wParam, lParam, TRUE) == 0)
			return 0;	// Do not process this event any further e.g. to prevent two lists from being scrolled at once
	}

	return CallWindowProcW (wp, hwnd, message, wParam, lParam);
}


void HookMouseWheel (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SetWindowLongPtrW (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) MouseWheelProc);
}
