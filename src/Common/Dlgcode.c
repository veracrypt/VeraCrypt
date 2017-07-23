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

#include <windowsx.h>
#include <dbghelp.h>
#include <dbt.h>
#include <Setupapi.h>
#include <fcntl.h>
#include <io.h>
#include <math.h>
#include <shlobj.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>
#include <Richedit.h>
#if defined (TCMOUNT) || defined (VOLFORMAT)
#include <Shlwapi.h>
#include <process.h>
#include <Tlhelp32.h>
#endif

#include "Resource.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include "Apidrvr.h"
#include "BootEncryption.h"
#include "Combo.h"
#include "Crc.h"
#include "Crypto.h"
#include "Dictionary.h"
#include "Dlgcode.h"
#include "EncryptionThreadPool.h"
#include "Endian.h"
#include "Format/Inplace.h"
#include "Language.h"
#include "Keyfiles.h"
#include "Pkcs5.h"
#include "Random.h"
#include "Registry.h"
#include "SecurityToken.h"
#include "Tests.h"
#include "Volumes.h"
#include "Wipe.h"
#include "Xml.h"
#include "Xts.h"
#include "Boot/Windows/BootCommon.h"
#include "Progress.h"
#include "zip.h"

#ifdef TCMOUNT
#include "Mount/Mount.h"
#include "Mount/resource.h"
#endif

#ifdef VOLFORMAT
#include "Format/Tcformat.h"
#endif

#ifdef SETUP
#include "Setup/Setup.h"
#endif

#include <Setupapi.h>
#include <strsafe.h>

#pragma comment( lib, "setupapi.lib" )

/* GPT Partition Type GUIDs */
#define LOCAL_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) const GUID name = {l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8}
LOCAL_DEFINE_GUID(PARTITION_ENTRY_UNUSED_GUID,   0x00000000L, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);    // Entry unused
LOCAL_DEFINE_GUID(PARTITION_SYSTEM_GUID,         0xC12A7328L, 0xF81F, 0x11D2, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B);    // EFI system partition
LOCAL_DEFINE_GUID(PARTITION_MSFT_RESERVED_GUID,  0xE3C9E316L, 0x0B5C, 0x4DB8, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE);    // Microsoft reserved space                                        
LOCAL_DEFINE_GUID(PARTITION_BASIC_DATA_GUID,     0xEBD0A0A2L, 0xB9E5, 0x4433, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7);    // Basic data partition
LOCAL_DEFINE_GUID(PARTITION_LDM_METADATA_GUID,   0x5808C8AAL, 0x7E8F, 0x42E0, 0x85, 0xD2, 0xE1, 0xE9, 0x04, 0x34, 0xCF, 0xB3);    // Logical Disk Manager metadata partition
LOCAL_DEFINE_GUID(PARTITION_LDM_DATA_GUID,       0xAF9B60A0L, 0x1431, 0x4F62, 0xBC, 0x68, 0x33, 0x11, 0x71, 0x4A, 0x69, 0xAD);    // Logical Disk Manager data partition
LOCAL_DEFINE_GUID(PARTITION_MSFT_RECOVERY_GUID,  0xDE94BBA4L, 0x06D1, 0x4D40, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC);    // Microsoft recovery partition
LOCAL_DEFINE_GUID(PARTITION_CLUSTER_GUID, 	   0xdb97dba9L, 0x0840, 0x4bae, 0x97, 0xf0, 0xff, 0xb9, 0xa3, 0x27, 0xc7, 0xe1);    // Cluster metadata partition

using namespace VeraCrypt;

LONG DriverVersion;

char *LastDialogId;
wchar_t szHelpFile[TC_MAX_PATH];
wchar_t szHelpFile2[TC_MAX_PATH];
wchar_t SecurityTokenLibraryPath[TC_MAX_PATH];
char CmdTokenPin [TC_MAX_PATH] = {0};

HFONT hFixedDigitFont = NULL;
HFONT hBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;

HFONT hUserFont = NULL;
HFONT hUserUnderlineFont = NULL;
HFONT hUserBoldFont = NULL;
HFONT hUserUnderlineBoldFont = NULL;

HFONT WindowTitleBarFont;

WCHAR EditPasswordChar = 0;

int ScreenDPI = USER_DEFAULT_SCREEN_DPI;
double DPIScaleFactorX = 1;
double DPIScaleFactorY = 1;
double DlgAspectRatio = 1;

HWND MainDlg = NULL;
wchar_t *lpszTitle = NULL;

BOOL Silent = FALSE;
BOOL bPreserveTimestamp = TRUE;
BOOL bShowDisconnectedNetworkDrives = FALSE;
BOOL bHideWaitingDialog = FALSE;
BOOL bCmdHideWaitingDialog = FALSE;
BOOL bCmdHideWaitingDialogValid = FALSE;
BOOL bUseSecureDesktop = FALSE;
BOOL bCmdUseSecureDesktop = FALSE;
BOOL bCmdUseSecureDesktopValid = FALSE;
BOOL bStartOnLogon = FALSE;
BOOL bMountDevicesOnLogon = FALSE;
BOOL bMountFavoritesOnLogon = FALSE;

BOOL bHistory = FALSE;

// Status of detection of hidden sectors (whole-system-drive encryption). 
// 0 - Unknown/undetermined/completed, 1: Detection is or was in progress (but did not complete e.g. due to system crash).
int HiddenSectorDetectionStatus = 0;	

OSVersionEnum nCurrentOS = WIN_UNKNOWN;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;
int CurrentOSServicePack = 0;
BOOL RemoteSession = FALSE;
BOOL UacElevated = FALSE;

BOOL bPortableModeConfirmed = FALSE;		// TRUE if it is certain that the instance is running in portable mode

BOOL bInPlaceEncNonSysPending = FALSE;		// TRUE if the non-system in-place encryption config file indicates that one or more partitions are scheduled to be encrypted. This flag is set only when config files are loaded during app startup.

/* Globals used by Mount and Format (separately per instance) */ 
BOOL PimEnable = FALSE;
BOOL KeyFilesEnable = FALSE;
KeyFile	*FirstKeyFile = NULL;
KeyFilesDlgParam		defaultKeyFilesParam;

BOOL IgnoreWmDeviceChange = FALSE;
BOOL DeviceChangeBroadcastDisabled = FALSE;
BOOL LastMountedVolumeDirty;
BOOL MountVolumesAsSystemFavorite = FALSE;
BOOL FavoriteMountOnArrivalInProgress = FALSE;
BOOL MultipleMountOperationInProgress = FALSE;

BOOL WaitDialogDisplaying = FALSE;

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;

/* This mutex is used to prevent multiple instances of the wizard or main app from dealing with system encryption */
volatile HANDLE hSysEncMutex = NULL;		

/* This mutex is used for non-system in-place encryption but only for informative (non-blocking) purposes,
such as whether an app should prompt the user whether to resume scheduled process. */
volatile HANDLE hNonSysInplaceEncMutex = NULL;

/* This mutex is used to prevent multiple instances of the wizard or main app from trying to install or
register the driver or from trying to launch it in portable mode at the same time. */
volatile HANDLE hDriverSetupMutex = NULL;

/* This mutex is used to prevent users from running the main TrueCrypt app or the wizard while an instance
of the TrueCrypt installer is running (which is also useful for enforcing restart before the apps can be used). */
volatile HANDLE hAppSetupMutex = NULL;

/* Critical section used to protect access to global variables used in WNetGetConnection calls */
CRITICAL_SECTION csWNetCalls;

/* Critical section used to protect access to global list of physical drives */
CRITICAL_SECTION csMountableDevices;
CRITICAL_SECTION csVolumeIdCandidates;

static std::vector<HostDevice> mountableDevices;
static std::vector<HostDevice> rawHostDeviceList;

HINSTANCE hInst = NULL;
HCURSOR hCursor = NULL;

ATOM hDlgClass, hSplashClass;

/* This value may changed only by calling ChangeSystemEncryptionStatus(). Only the wizard can change it
(others may still read it though). */
int SystemEncryptionStatus = SYSENC_STATUS_NONE;	

/* Only the wizard can change this value (others may only read it). */
WipeAlgorithmId nWipeMode = TC_WIPE_NONE;

BOOL bSysPartitionSelected = FALSE;		/* TRUE if the user selected the system partition via the Select Device dialog */
BOOL bSysDriveSelected = FALSE;			/* TRUE if the user selected the system drive via the Select Device dialog */

/* To populate these arrays, call GetSysDevicePaths(). If they contain valid paths, bCachedSysDevicePathsValid is TRUE. */
wchar_t SysPartitionDevicePath [TC_MAX_PATH];
wchar_t SysDriveDevicePath [TC_MAX_PATH];
wstring ExtraBootPartitionDevicePath;
char bCachedSysDevicePathsValid = FALSE;

BOOL bHyperLinkBeingTracked = FALSE;

int WrongPwdRetryCounter = 0;

static FILE *ConfigFileHandle;
char *ConfigBuffer;

BOOL SystemFileSelectorCallPending = FALSE;
DWORD SystemFileSelectorCallerThreadId;

#define RANDPOOL_DISPLAY_REFRESH_INTERVAL	30
#define RANDPOOL_DISPLAY_ROWS 16
#define RANDPOOL_DISPLAY_COLUMNS 20

HMODULE hRichEditDll = NULL;
HMODULE hComctl32Dll = NULL;
HMODULE hSetupDll = NULL;
HMODULE hShlwapiDll = NULL;
HMODULE hProfApiDll = NULL;
HMODULE hUsp10Dll = NULL;
HMODULE hCryptSpDll = NULL;
HMODULE hUXThemeDll = NULL;
HMODULE hUserenvDll = NULL;
HMODULE hRsaenhDll = NULL;
HMODULE himm32dll = NULL;
HMODULE hMSCTFdll = NULL;
HMODULE hfltlibdll = NULL;
HMODULE hframedyndll = NULL;
HMODULE hpsapidll = NULL;
HMODULE hsecur32dll = NULL;
HMODULE hnetapi32dll = NULL;
HMODULE hauthzdll = NULL;
HMODULE hxmllitedll = NULL;
HMODULE hmprdll = NULL;
HMODULE hsppdll = NULL;
HMODULE vssapidll = NULL;
HMODULE hvsstracedll = NULL;
HMODULE hcfgmgr32dll = NULL;
HMODULE hdevobjdll = NULL;
HMODULE hpowrprofdll = NULL;
HMODULE hsspiclidll = NULL;
HMODULE hcryptbasedll = NULL;
HMODULE hdwmapidll = NULL;
HMODULE hmsasn1dll = NULL;
HMODULE hcrypt32dll = NULL;
HMODULE hbcryptdll = NULL;
HMODULE hbcryptprimitivesdll = NULL;
HMODULE hMsls31 = NULL;
HMODULE hntmartadll = NULL;
HMODULE hwinscarddll = NULL;

#define FREE_DLL(h)	if (h) { FreeLibrary (h); h = NULL;}

#ifndef BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE
#define BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE 0x00000001
#endif

#ifndef BASE_SEARCH_PATH_PERMANENT
#define BASE_SEARCH_PATH_PERMANENT 0x00008000
#endif

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

typedef BOOL (WINAPI *SetDllDirectoryPtr)(LPCWSTR lpPathName);
typedef BOOL (WINAPI *SetSearchPathModePtr)(DWORD Flags);
typedef BOOL (WINAPI *SetDefaultDllDirectoriesPtr)(DWORD DirectoryFlags);


typedef void (WINAPI *InitCommonControlsPtr)(void);
typedef HIMAGELIST  (WINAPI *ImageList_CreatePtr)(int cx, int cy, UINT flags, int cInitial, int cGrow);
typedef int         (WINAPI *ImageList_AddPtr)(HIMAGELIST himl, HBITMAP hbmImage, HBITMAP hbmMask);

typedef VOID (WINAPI *SetupCloseInfFilePtr)(HINF InfHandle);
typedef HKEY (WINAPI *SetupDiOpenClassRegKeyPtr)(CONST GUID *ClassGuid,REGSAM samDesired);
typedef BOOL (WINAPI *SetupInstallFromInfSectionWPtr)(HWND,HINF,PCWSTR,UINT,HKEY,PCWSTR,UINT,PSP_FILE_CALLBACK_W,PVOID,HDEVINFO,PSP_DEVINFO_DATA);
typedef HINF (WINAPI *SetupOpenInfFileWPtr)(PCWSTR FileName,PCWSTR InfClass,DWORD InfStyle,PUINT ErrorLine);

typedef LSTATUS (STDAPICALLTYPE *SHDeleteKeyWPtr)(HKEY hkey, LPCWSTR pszSubKey);

typedef HRESULT (STDAPICALLTYPE *SHStrDupWPtr)(LPCWSTR psz, LPWSTR *ppwsz);

// ChangeWindowMessageFilter
typedef BOOL (WINAPI *ChangeWindowMessageFilterPtr) (UINT, DWORD);

SetDllDirectoryPtr SetDllDirectoryFn = NULL;
SetSearchPathModePtr SetSearchPathModeFn = NULL;
SetDefaultDllDirectoriesPtr SetDefaultDllDirectoriesFn = NULL;

ImageList_CreatePtr ImageList_CreateFn = NULL;
ImageList_AddPtr ImageList_AddFn = NULL;

SetupCloseInfFilePtr SetupCloseInfFileFn = NULL;
SetupDiOpenClassRegKeyPtr SetupDiOpenClassRegKeyFn = NULL;
SetupInstallFromInfSectionWPtr SetupInstallFromInfSectionWFn = NULL;
SetupOpenInfFileWPtr SetupOpenInfFileWFn = NULL;
SHDeleteKeyWPtr SHDeleteKeyWFn = NULL;
SHStrDupWPtr SHStrDupWFn = NULL;
ChangeWindowMessageFilterPtr ChangeWindowMessageFilterFn = NULL;

/* Windows dialog class */
#define WINDOWS_DIALOG_CLASS L"#32770"

/* Custom class names */
#define TC_DLG_CLASS L"VeraCryptCustomDlg"
#define TC_SPLASH_CLASS L"VeraCryptSplashDlg"

/* constant used by ChangeWindowMessageFilter calls */
#ifndef MSGFLT_ADD
#define MSGFLT_ADD	1
#endif

/* undocumented message sent during drag-n-drop */
#ifndef WM_COPYGLOBALDATA
#define WM_COPYGLOBALDATA 0x0049
#endif

/* Benchmarks */

#ifndef SETUP

#define BENCHMARK_MAX_ITEMS 100
#define BENCHMARK_DEFAULT_BUF_SIZE	BYTES_PER_MB
#define HASH_FNC_BENCHMARKS	FALSE 	// For development purposes only. Must be FALSE when building a public release.
#define PKCS5_BENCHMARKS	FALSE	// For development purposes only. Must be FALSE when building a public release.
#if PKCS5_BENCHMARKS && HASH_FNC_BENCHMARKS
#error PKCS5_BENCHMARKS and HASH_FNC_BENCHMARKS are both TRUE (at least one of them should be FALSE).
#endif

enum 
{
	BENCHMARK_TYPE_ENCRYPTION = 0,
	BENCHMARK_TYPE_PRF,
	BENCHMARK_TYPE_HASH
};

enum 
{
	BENCHMARK_SORT_BY_NAME = 0,
	BENCHMARK_SORT_BY_SPEED
};

typedef struct 
{
	int id;
	wchar_t name[100];
	unsigned __int64 encSpeed;
	unsigned __int64 decSpeed;
	unsigned __int64 meanBytesPerSec;
} BENCHMARK_REC;

BENCHMARK_REC benchmarkTable [BENCHMARK_MAX_ITEMS];
int benchmarkTotalItems = 0;
int benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
int benchmarkLastBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
int benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;
LARGE_INTEGER benchmarkPerformanceFrequency;
int benchmarkType = BENCHMARK_TYPE_ENCRYPTION;
int benchmarkPim = -1;
BOOL benchmarkPreBoot = FALSE;
BOOL benchmarkGPT = FALSE;

#endif	// #ifndef SETUP


typedef struct 
{
	void *strings;
	BOOL bold;

} MULTI_CHOICE_DLGPROC_PARAMS;

void InitGlobalLocks ()
{
	InitializeCriticalSection (&csWNetCalls);
	InitializeCriticalSection (&csMountableDevices);
	InitializeCriticalSection (&csVolumeIdCandidates);
}

void FinalizeGlobalLocks ()
{
	DeleteCriticalSection (&csWNetCalls);
	DeleteCriticalSection (&csMountableDevices);
	DeleteCriticalSection (&csVolumeIdCandidates);
}

void cleanup ()
{
	burn (&CmdTokenPin, sizeof (CmdTokenPin));

	/* Cleanup the GDI fonts */
	if (hFixedFont != NULL)
		DeleteObject (hFixedFont);
	if (hFixedDigitFont != NULL)
		DeleteObject (hFixedDigitFont);
	if (hBoldFont != NULL)
		DeleteObject (hBoldFont);
	if (hTitleFont != NULL)
		DeleteObject (hTitleFont);
	if (hUserFont != NULL)
		DeleteObject (hUserFont);
	if (hUserUnderlineFont != NULL)
		DeleteObject (hUserUnderlineFont);
	if (hUserBoldFont != NULL)
		DeleteObject (hUserBoldFont);
	if (hUserUnderlineBoldFont != NULL)
		DeleteObject (hUserUnderlineBoldFont);

	/* Cleanup our dialog class */
	if (hDlgClass)
		UnregisterClassW (TC_DLG_CLASS, hInst);
	if (hSplashClass)
		UnregisterClassW (TC_SPLASH_CLASS, hInst);

	/* Close the device driver handle */
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		// Unload driver mode if possible (non-install mode) 
		if (IsNonInstallMode ())
		{
			// If a dismount was forced in the lifetime of the driver, Windows may later prevent it to be loaded again from
			// the same path. Therefore, the driver will not be unloaded even though it was loaded in non-install mode.
			int driverUnloadDisabled;
			DWORD dwResult;

			if (!DeviceIoControl (hDriver, TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED, NULL, 0, &driverUnloadDisabled, sizeof (driverUnloadDisabled), &dwResult, NULL))
				driverUnloadDisabled = 0;

			if (!driverUnloadDisabled)
				DriverUnload ();
			else
			{
				CloseHandle (hDriver);
				hDriver = INVALID_HANDLE_VALUE;
			}
		}
		else
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
	}

	if (ConfigBuffer != NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
	}

	CoUninitialize ();

	CloseSysEncMutex ();

#ifndef SETUP
	try
	{
		if (SecurityToken::IsInitialized())
			SecurityToken::CloseLibrary();
	}
	catch (...) { }

	EncryptionThreadPoolStop();
#endif

	FinalizeGlobalLocks ();
}


void LowerCaseCopy (wchar_t *lpszDest, const wchar_t *lpszSource)
{
	size_t i = wcslen (lpszSource) + 1;

	lpszDest[i - 1] = 0;
	while (--i > 0)
	{
		lpszDest[i - 1] = (wchar_t) towlower (lpszSource[i - 1]);
	}

}

void UpperCaseCopy (wchar_t *lpszDest, size_t cbDest, const wchar_t *lpszSource)
{
	if (lpszDest && cbDest)
	{
		size_t i = wcslen (lpszSource);
		if (i >= cbDest)
			i = cbDest - 1;

		lpszDest[i] = 0;
		i++;
		while (--i > 0)
		{
			lpszDest[i - 1] = (wchar_t) towupper (lpszSource[i - 1]);
		}
	}
}


std::wstring ToUpperCase (const std::wstring &str)
{
	wstring u;
	foreach (wchar_t c, str)
	{
		u += (wchar_t) towupper (c);
	}

	return u;
}

size_t TrimWhiteSpace(wchar_t *str)
{
  wchar_t *end, *ptr = str;
  size_t out_size;

  if(!str || *str == 0)
    return 0;

  // Trim leading space
  while(iswspace(*ptr)) ptr++;

  if(*ptr == 0)  // All spaces?
  {
    *str = 0;
    return 0;
  }

  // Trim trailing space
  end = str + wcslen(str) - 1;
  while(end > ptr && iswspace(*end)) end--;
  end++;

  // Set output size to trimmed string length
  out_size = (end - ptr);

  // Copy trimmed string and add null terminator
  wmemmove(str, ptr, out_size);
  str[out_size] = 0;

  return out_size;
}

BOOL IsNullTerminateString (const wchar_t* str, size_t cbSize)
{
	if (str && cbSize)
	{
		for (size_t i = 0; i < cbSize; i++)
		{
			if (str[i] == 0)
				return TRUE;
		}
	}

	return FALSE;
}

// check the validity of a file name
BOOL IsValidFileName(const wchar_t* str)
{
	static wchar_t invalidChars[9] = {L'<', L'>', L':', L'"', L'/', L'\\', L'|', L'?', L'*'};
	wchar_t c;
	int i;
	BOOL bNotDotOnly = FALSE;
	while ((c = *str))
	{
		if (c != L'.')
			bNotDotOnly = TRUE;
		for (i= 0; i < ARRAYSIZE(invalidChars); i++)
			if (c == invalidChars[i])
				return FALSE;
		str++;
	}

	return bNotDotOnly;
}

BOOL IsVolumeDeviceHosted (const wchar_t *lpszDiskFile)
{
	return wcsstr (lpszDiskFile, L"\\Device\\") == lpszDiskFile
		|| wcsstr (lpszDiskFile, L"\\DEVICE\\") == lpszDiskFile;
}


void CreateFullVolumePath (wchar_t *lpszDiskFile, size_t cbDiskFile, const wchar_t *lpszFileName, BOOL * bDevice)
{
	UpperCaseCopy (lpszDiskFile, cbDiskFile, lpszFileName);

	*bDevice = FALSE;

	if (wmemcmp (lpszDiskFile, L"\\DEVICE", 7) == 0)
	{
		*bDevice = TRUE;
	}

	StringCbCopyW (lpszDiskFile, cbDiskFile, lpszFileName);

#if _DEBUG
	OutputDebugString (L"CreateFullVolumePath: ");
	OutputDebugString (lpszDiskFile);
	OutputDebugString (L"\n");
#endif

}

int FakeDosNameForDevice (const wchar_t *lpszDiskFile , wchar_t *lpszDosDevice , size_t cbDosDevice, wchar_t *lpszCFDevice , size_t cbCFDevice, BOOL bNameOnly)
{
	BOOL bDosLinkCreated = TRUE;
	StringCbPrintfW (lpszDosDevice, cbDosDevice,L"veracrypt%lu", GetCurrentProcessId ());

	if (bNameOnly == FALSE)
		bDosLinkCreated = DefineDosDevice (DDD_RAW_TARGET_PATH, lpszDosDevice, lpszDiskFile);

	if (bDosLinkCreated == FALSE)
		return ERR_OS_ERROR;
	else
		StringCbPrintfW (lpszCFDevice, cbCFDevice,L"\\\\.\\%s", lpszDosDevice);

	return 0;
}

int RemoveFakeDosName (wchar_t *lpszDiskFile, wchar_t *lpszDosDevice)
{
	BOOL bDosLinkRemoved = DefineDosDevice (DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE |
			DDD_REMOVE_DEFINITION, lpszDosDevice, lpszDiskFile);
	if (bDosLinkRemoved == FALSE)
	{
		return ERR_OS_ERROR;
	}

	return 0;
}


void AbortProcessDirect (wchar_t *abortMsg)
{
	// Note that this function also causes localcleanup() to be called (see atexit())
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBoxW (NULL, abortMsg, lpszTitle, ICON_HAND);
	FREE_DLL (hRichEditDll);
	FREE_DLL (hComctl32Dll);
	FREE_DLL (hSetupDll);
	FREE_DLL (hShlwapiDll);
	FREE_DLL (hProfApiDll);
	FREE_DLL (hUsp10Dll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hUXThemeDll);
	FREE_DLL (hUserenvDll);
	FREE_DLL (hRsaenhDll);
	FREE_DLL (himm32dll);
	FREE_DLL (hMSCTFdll);
	FREE_DLL (hfltlibdll);
	FREE_DLL (hframedyndll);
	FREE_DLL (hpsapidll);
	FREE_DLL (hsecur32dll);
	FREE_DLL (hnetapi32dll);
	FREE_DLL (hauthzdll);
	FREE_DLL (hxmllitedll);
	FREE_DLL (hmprdll);
	FREE_DLL (hsppdll);
	FREE_DLL (vssapidll);
	FREE_DLL (hvsstracedll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hcfgmgr32dll);
	FREE_DLL (hdevobjdll);
	FREE_DLL (hpowrprofdll);
	FREE_DLL (hsspiclidll);
	FREE_DLL (hcryptbasedll);
	FREE_DLL (hdwmapidll);
	FREE_DLL (hmsasn1dll);
	FREE_DLL (hcrypt32dll);
	FREE_DLL (hbcryptdll);
	FREE_DLL (hbcryptprimitivesdll);
	FREE_DLL (hMsls31);
	FREE_DLL (hntmartadll);
	FREE_DLL (hwinscarddll);

	exit (1);
}

void AbortProcess (char *stringId)
{
	// Note that this function also causes localcleanup() to be called (see atexit())
	AbortProcessDirect (GetString (stringId));
}

void AbortProcessSilent (void)
{
	FREE_DLL (hRichEditDll);
	FREE_DLL (hComctl32Dll);
	FREE_DLL (hSetupDll);
	FREE_DLL (hShlwapiDll);
	FREE_DLL (hProfApiDll);
	FREE_DLL (hUsp10Dll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hUXThemeDll);
	FREE_DLL (hUserenvDll);
	FREE_DLL (hRsaenhDll);
	FREE_DLL (himm32dll);
	FREE_DLL (hMSCTFdll);
	FREE_DLL (hfltlibdll);
	FREE_DLL (hframedyndll);
	FREE_DLL (hpsapidll);
	FREE_DLL (hsecur32dll);
	FREE_DLL (hnetapi32dll);
	FREE_DLL (hauthzdll);
	FREE_DLL (hxmllitedll);
	FREE_DLL (hmprdll);
	FREE_DLL (hsppdll);
	FREE_DLL (vssapidll);
	FREE_DLL (hvsstracedll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hcfgmgr32dll);
	FREE_DLL (hdevobjdll);
	FREE_DLL (hpowrprofdll);
	FREE_DLL (hsspiclidll);
	FREE_DLL (hcryptbasedll);
	FREE_DLL (hdwmapidll);
	FREE_DLL (hmsasn1dll);
	FREE_DLL (hcrypt32dll);
	FREE_DLL (hbcryptdll);
	FREE_DLL (hbcryptprimitivesdll);
	FREE_DLL (hMsls31);
	FREE_DLL (hntmartadll);
	FREE_DLL (hwinscarddll);

	// Note that this function also causes localcleanup() to be called (see atexit())
	exit (1);
}


#pragma warning(push)
#pragma warning(disable:4702)

void *err_malloc (size_t size)
{
	void *z = (void *) TCalloc (size);
	if (z)
		return z;
	AbortProcess ("OUTOFMEMORY");
	return 0;
}

#pragma warning(pop)


char *err_strdup (char *lpszText)
{
	size_t j = (strlen (lpszText) + 1) * sizeof (char);
	char *z = (char *) err_malloc (j);
	memmove (z, lpszText, j);
	return z;
}


BOOL IsDiskReadError (DWORD error)
{
	return (error == ERROR_CRC
		|| error == ERROR_IO_DEVICE
		|| error == ERROR_BAD_CLUSTERS
		|| error == ERROR_SECTOR_NOT_FOUND
		|| error == ERROR_READ_FAULT
		|| error == ERROR_INVALID_FUNCTION // I/O error may be reported as ERROR_INVALID_FUNCTION by buggy chipset drivers
		|| error == ERROR_SEM_TIMEOUT);	// I/O operation timeout may be reported as ERROR_SEM_TIMEOUT
}


BOOL IsDiskWriteError (DWORD error)
{
	return (error == ERROR_IO_DEVICE
		|| error == ERROR_BAD_CLUSTERS
		|| error == ERROR_SECTOR_NOT_FOUND
		|| error == ERROR_WRITE_FAULT
		|| error == ERROR_INVALID_FUNCTION // I/O error may be reported as ERROR_INVALID_FUNCTION by buggy chipset drivers
		|| error == ERROR_SEM_TIMEOUT);	// I/O operation timeout may be reported as ERROR_SEM_TIMEOUT
}


BOOL IsDiskError (DWORD error)
{
	return IsDiskReadError (error) || IsDiskWriteError (error);
}


DWORD handleWin32Error (HWND hwndDlg, const char* srcPos)
{
	PWSTR lpMsgBuf;
	DWORD dwError = GetLastError ();	
	wchar_t szErrorValue[32];
	wchar_t* pszDesc;

	if (Silent || dwError == 0 || dwError == ERROR_INVALID_WINDOW_HANDLE)
		return dwError;

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		ErrorDirect ( AppendSrcPos (GetString ("ERR_ACCESS_DENIED"), srcPos).c_str (), hwndDlg);
		SetLastError (dwError);		// Preserve the original error code
		return dwError;
	}

	FormatMessageW (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			      NULL,
			      dwError,
			      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			      (PWSTR) &lpMsgBuf,
			      0,
			      NULL
	    );

	if (lpMsgBuf)
		pszDesc = (wchar_t*) lpMsgBuf;
	else
	{
		StringCchPrintfW (szErrorValue, ARRAYSIZE (szErrorValue), L"Error 0x%.8X", dwError);
		pszDesc = szErrorValue;
	}

	MessageBoxW (hwndDlg, AppendSrcPos (pszDesc, srcPos).c_str (), lpszTitle, ICON_HAND);
	if (lpMsgBuf) LocalFree (lpMsgBuf);

	// User-friendly hardware error explanation
	if (IsDiskError (dwError))
		Error ("ERR_HARDWARE_ERROR", hwndDlg);

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		HandleDriveNotReadyError(hwndDlg);

	SetLastError (dwError);		// Preserve the original error code

	return dwError;
}

BOOL translateWin32Error (wchar_t *lpszMsgBuf, int nWSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError,
			   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			   lpszMsgBuf, nWSizeOfBuf, NULL))
	{
		SetLastError (dwError);		// Preserve the original error code
		return TRUE;
	}

	SetLastError (dwError);			// Preserve the original error code
	return FALSE;
}

// If the user has a non-default screen DPI, all absolute font sizes must be
// converted using this function.
int CompensateDPIFont (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorY * DlgAspectRatio * 0.999;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


// If the user has a non-default screen DPI, some screen coordinates and sizes must
// be converted using this function
int CompensateXDPI (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorX;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


// If the user has a non-default screen DPI, some screen coordinates and sizes must
// be converted using this function
int CompensateYDPI (int val)
{
	if (ScreenDPI == USER_DEFAULT_SCREEN_DPI)
		return val;
	else
	{
		double tmpVal = (double) val * DPIScaleFactorY;

		if (tmpVal > 0)
			return (int) floor(tmpVal);
		else
			return (int) ceil(tmpVal);
	}
}


int GetTextGfxWidth (HWND hwndDlgItem, const wchar_t *text, HFONT hFont)
{
	SIZE sizes;
	TEXTMETRIC textMetrics;
	HDC hdc = GetDC (hwndDlgItem); 

	SelectObject(hdc, (HGDIOBJ) hFont);

	GetTextExtentPoint32W (hdc, text, (int) wcslen (text), &sizes);

	GetTextMetrics(hdc, &textMetrics);	// Necessary for non-TrueType raster fonts (tmOverhang)

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cx - (int) textMetrics.tmOverhang);
}


int GetTextGfxHeight (HWND hwndDlgItem, const wchar_t *text, HFONT hFont)
{
	SIZE sizes;
	HDC hdc = GetDC (hwndDlgItem); 

	SelectObject(hdc, (HGDIOBJ) hFont);

	GetTextExtentPoint32W (hdc, text, (int) wcslen (text), &sizes);

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cy);
}


std::wstring FitPathInGfxWidth (HWND hwnd, HFONT hFont, LONG width, const std::wstring &path)
{
	wstring newPath;

	RECT rect;
	rect.left = 0;
	rect.top = 0;
	rect.right = width;
	rect.bottom = LONG_MAX;

	HDC hdc = GetDC (hwnd); 
	SelectObject (hdc, (HGDIOBJ) hFont);

	wchar_t pathBuf[TC_MAX_PATH];
	StringCchCopyW (pathBuf, ARRAYSIZE (pathBuf), path.c_str());

	if (DrawText (hdc, pathBuf, (int) path.size(), &rect, DT_CALCRECT | DT_MODIFYSTRING | DT_PATH_ELLIPSIS | DT_SINGLELINE) != 0)
		newPath = pathBuf;

	ReleaseDC (hwnd, hdc); 
	return newPath;
}


static LRESULT CALLBACK HyperlinkProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtrW (hwnd, GWLP_USERDATA);

	switch (message)
	{
	case WM_SETCURSOR:
		if (!bHyperLinkBeingTracked)
		{
			TRACKMOUSEEVENT	trackMouseEvent;

			trackMouseEvent.cbSize = sizeof(trackMouseEvent);
			trackMouseEvent.dwFlags = TME_LEAVE;
			trackMouseEvent.hwndTrack = hwnd;

			bHyperLinkBeingTracked = TrackMouseEvent(&trackMouseEvent);

			HandCursor();
		}
		return 0;

	case WM_MOUSELEAVE:
		bHyperLinkBeingTracked = FALSE;
		NormalCursor();
		return 0;
	}

	return CallWindowProcW (wp, hwnd, message, wParam, lParam);
}


BOOL ToHyperlink (HWND hwndDlg, UINT ctrlId)
{
	return ToCustHyperlink (hwndDlg, ctrlId, hUserUnderlineFont);
}


BOOL ToCustHyperlink (HWND hwndDlg, UINT ctrlId, HFONT hFont)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SendMessageW (hwndCtrl, WM_SETFONT, (WPARAM) hFont, 0);

	SetWindowLongPtrW (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) HyperlinkProc);

	// Resize the field according to its actual size in pixels and move it if centered or right-aligned.
	// This should be done again if the link text changes.
	AccommodateTextField (hwndDlg, ctrlId, TRUE, hFont);

	return TRUE;
}


// Resizes a text field according to its actual width and height in pixels (font size is taken into account) and moves
// it accordingly if the field is centered or right-aligned. Should be used on all hyperlinks upon dialog init
// after localization (bFirstUpdate should be TRUE) and later whenever a hyperlink text changes (bFirstUpdate
// must be FALSE).
void AccommodateTextField (HWND hwndDlg, UINT ctrlId, BOOL bFirstUpdate, HFONT hFont)
{
	RECT rec, wrec, trec;
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);
	int width, origWidth, height, origHeight;
	int horizSubOffset, vertSubOffset, vertOffset, alignPosDiff = 0;
	wchar_t text [MAX_URL_LENGTH];
	WINDOWINFO windowInfo;
	BOOL bBorderlessWindow = !(GetWindowLongPtrW (hwndDlg, GWL_STYLE) & (WS_BORDER | WS_DLGFRAME));

	// Resize the field according to its length and font size and move if centered or right-aligned

	GetWindowTextW (hwndCtrl, text, sizeof (text) / sizeof (wchar_t));

	width = GetTextGfxWidth (hwndCtrl, text, hFont);
	height = GetTextGfxHeight (hwndCtrl, text, hFont);

	GetClientRect (hwndCtrl, &rec);		
	origWidth = rec.right;
	origHeight = rec.bottom;

	if (width >= 0
		&& (!bFirstUpdate || origWidth > width))	// The original width of the field is the maximum allowed size 
	{
		horizSubOffset = origWidth - width;
		vertSubOffset = origHeight - height;

		// Window coords
		GetWindowRect(hwndDlg, &wrec);
		GetClientRect(hwndDlg, &trec);

		// Vertical "title bar" offset
		vertOffset = wrec.bottom - wrec.top - trec.bottom - (bBorderlessWindow ? 0 : GetSystemMetrics(SM_CYFIXEDFRAME));

		// Text field coords
		GetWindowRect(hwndCtrl, &rec);

		// Alignment offset
		windowInfo.cbSize = sizeof(windowInfo);
		GetWindowInfo (hwndCtrl, &windowInfo);

		if (windowInfo.dwStyle & SS_CENTER)
			alignPosDiff = horizSubOffset / 2;
		else if (windowInfo.dwStyle & SS_RIGHT)
			alignPosDiff = horizSubOffset;
		
		// Resize/move
		if (alignPosDiff > 0)
		{
			// Resize and move the text field
			MoveWindow (hwndCtrl,
				rec.left - wrec.left - (bBorderlessWindow ? 0 : GetSystemMetrics(SM_CXFIXEDFRAME)) + alignPosDiff,
				rec.top - wrec.top - vertOffset,
				origWidth - horizSubOffset,
				origHeight - vertSubOffset,
				TRUE);
		}
		else
		{
			// Resize the text field
			SetWindowPos (hwndCtrl, 0, 0, 0,
				origWidth - horizSubOffset,
				origHeight - vertSubOffset,
				SWP_NOMOVE | SWP_NOZORDER);
		}

		SetWindowPos (hwndCtrl, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

		InvalidateRect (hwndCtrl, NULL, TRUE);
	}
}

// Note that the user can still close the window by right-clicking its taskbar icon and selecting 'Close window', or by pressing Alt-F4, or using the Task Manager.
void DisableCloseButton (HWND hwndDlg)
{
	EnableMenuItem (GetSystemMenu (hwndDlg, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
}


void EnableCloseButton (HWND hwndDlg)
{
	EnableMenuItem (GetSystemMenu (hwndDlg, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_ENABLED);
}

// Protects an input field from having its content updated by a Paste action (call ToBootPwdField() to use this).
static LRESULT CALLBACK BootPwdFieldProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtrW (hwnd, GWLP_USERDATA);

	switch (message)
	{
	case WM_PASTE:
		return 1;
	}

	return CallWindowProcW (wp, hwnd, message, wParam, lParam);
}


// Protects an input field from having its content updated by a Paste action. Used for pre-boot password
// input fields (only the US keyboard layout is supported in pre-boot environment so we must prevent the 
// user from pasting a password typed using a non-US keyboard layout).
void ToBootPwdField (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SetWindowLongPtrW (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtrW (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) BootPwdFieldProc);
}



// This function currently serves the following purposes:
// - Determines scaling factors for current screen DPI and GUI aspect ratio.
// - Determines how Windows skews the GUI aspect ratio (which happens when the user has a non-default DPI).
// The determined values must be used when performing some GUI operations and calculations.
BOOL CALLBACK AuxiliaryDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HDC hDC = GetDC (hwndDlg);

			if (hDC)
			{
				ScreenDPI = GetDeviceCaps (hDC, LOGPIXELSY);
				ReleaseDC (hwndDlg, hDC); 
			}

			DPIScaleFactorX = 1;
			DPIScaleFactorY = 1;
			DlgAspectRatio = 1;

			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				// Windows skews the GUI aspect ratio if the user has a non-default DPI. Hence, working with 
				// actual screen DPI is redundant and leads to incorrect results. What really matters here is
				// how Windows actually renders our GUI. This is determined by comparing the expected and current
				// sizes of a hidden calibration text field.

				RECT trec;

				trec.right = 0;
				trec.bottom = 0;

				GetClientRect (GetDlgItem (hwndDlg, IDC_ASPECT_RATIO_CALIBRATION_BOX), &trec);

				if (trec.right != 0 && trec.bottom != 0)
				{
					// The size of the 282x282 IDC_ASPECT_RATIO_CALIBRATION_BOX rendered at the default DPI (96) is 423x458
					DPIScaleFactorX = (double) trec.right / 423;
					DPIScaleFactorY = (double) trec.bottom / 458;
					DlgAspectRatio = DPIScaleFactorX / DPIScaleFactorY;
				}
			}

			EndDialog (hwndDlg, 0);
			return 1;
		}

	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK AboutDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static HBITMAP hbmTextualLogoBitmapRescaled = NULL;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			wchar_t szTmp[100];
			RECT rec;

			LocalizeDialog (hwndDlg, "IDD_ABOUT_DLG");

			// Hyperlink
			SetWindowText (GetDlgItem (hwndDlg, IDC_HOMEPAGE), L"www.idrix.fr");
			ToHyperlink (hwndDlg, IDC_HOMEPAGE);

			// Logo area background (must not keep aspect ratio; must retain Windows-imposed distortion)
			GetClientRect (GetDlgItem (hwndDlg, IDC_ABOUT_LOGO_AREA), &rec);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_ABOUT_BKG), HWND_TOP, 0, 0, rec.right, rec.bottom, SWP_NOMOVE);

			// Resize the logo bitmap if the user has a non-default DPI 
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				// Logo (must recreate and keep the original aspect ratio as Windows distorts it)
				hbmTextualLogoBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_TEXTUAL_LOGO_288DPI),
					GetDlgItem (hwndDlg, IDC_TEXTUAL_LOGO_IMG),
					0, 0, 0, 0, FALSE, TRUE);

				SetWindowPos (GetDlgItem (hwndDlg, IDC_ABOUT_BKG), HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			}

			// Version
			SendMessage (GetDlgItem (hwndDlg, IDT_ABOUT_VERSION), WM_SETFONT, (WPARAM) hUserBoldFont, 0);
			StringCbPrintfW (szTmp, sizeof(szTmp), L"VeraCrypt %s", _T(VERSION_STRING));
#ifdef _WIN64
			StringCbCatW (szTmp, sizeof(szTmp), L"  (64-bit)");
#else
			StringCbCatW (szTmp, sizeof(szTmp), L"  (32-bit)");
#endif
#if (defined(_DEBUG) || defined(DEBUG))
			StringCbCatW (szTmp, sizeof(szTmp), L"  (debug)");
#endif
			SetDlgItemText (hwndDlg, IDT_ABOUT_VERSION, szTmp);
			SetDlgItemText (hwndDlg, IDT_ABOUT_RELEASE, TC_STR_RELEASED_BY);

			// Credits
			SendMessage (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS), WM_SETFONT, (WPARAM) hUserFont, (LPARAM) 0);
			SendMessage (hwndDlg, WM_APP, 0, 0);
			return 1;
		}

	case WM_APP:
		SetWindowText (GetDlgItem (hwndDlg, IDC_ABOUT_CREDITS),
			L"Based on TrueCrypt 7.1a, freely available at http://www.truecrypt.org/ .\r\n\r\n"

			L"Portions of this software:\r\n"
			L"Copyright \xA9 2013-2017 IDRIX. All rights reserved.\r\n"
			L"Copyright \xA9 2003-2012 TrueCrypt Developers Association. All Rights Reserved.\r\n"
			L"Copyright \xA9 1998-2000 Paul Le Roux. All Rights Reserved.\r\n"
			L"Copyright \xA9 1998-2008 Brian Gladman. All Rights Reserved.\r\n"
			L"Copyright \xA9 1995-2017 Jean-loup Gailly and Mark Adler.\r\n"
			L"Copyright \xA9 2016 Disk Cryptography Services for EFI (DCS), Alex Kolotnikov.\r\n"
			L"Copyright \xA9 Dieter Baron and Thomas Klausner.\r\n"
			L"Copyright \xA9 2013, Alexey Degtyarev. All rights reserved.\r\n"
			L"Copyright \xA9 1999-2013,2014,2015,2016 Jack Lloyd. All rights reserved.\r\n\r\n"

			L"This software as a whole:\r\n"
			L"Copyright \xA9 2013-2017 IDRIX. All rights reserved.\r\n\r\n"

			L"An IDRIX Release");

		return 1;

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}

		if (lw == IDC_HOMEPAGE)
		{
			Applink ("main");
			return 1;
		}

		// Disallow modification of credits
		if (HIWORD (wParam) == EN_UPDATE)
		{
			SendMessage (hwndDlg, WM_APP, 0, 0);
			return 1;
		}

		return 0;

	case WM_CLOSE:
		/* Delete buffered bitmaps (if any) */
		if (hbmTextualLogoBitmapRescaled != NULL)
		{
			DeleteObject ((HGDIOBJ) hbmTextualLogoBitmapRescaled);
			hbmTextualLogoBitmapRescaled = NULL;
		}

		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


static HWND StaticModelessWaitDlgHandle = NULL;

// Call DisplayStaticModelessWaitDlg() to open this dialog and CloseStaticModelessWaitDlg() to close it.
static BOOL CALLBACK StaticModelessWaitDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, NULL);

			return 0;
		}

	case WM_COMMAND:

		if (lw == IDOK || lw == IDCANCEL)
			return 1;

		return 0;


	case WM_CLOSE:
		StaticModelessWaitDlgHandle = NULL;
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


// Opens a dialog window saying "Please wait..." which is not modal and does not need any GUI refresh after initialization.
void DisplayStaticModelessWaitDlg (HWND parent)
{
	if (StaticModelessWaitDlgHandle != NULL)
		return;	// Already shown

	StaticModelessWaitDlgHandle = CreateDialogParamW (hInst, MAKEINTRESOURCEW (IDD_STATIC_MODELESS_WAIT_DLG), parent, (DLGPROC) StaticModelessWaitDlgProc, (LPARAM) 0);

	ShowWindow (StaticModelessWaitDlgHandle, SW_SHOWNORMAL);

	// Allow synchronous use with the GUI being instantly and fully rendered
	ProcessPaintMessages (StaticModelessWaitDlgHandle, 500);
}


void CloseStaticModelessWaitDlg (void)
{
	if (StaticModelessWaitDlgHandle == NULL)
		return;	// Not shown

	DestroyWindow (StaticModelessWaitDlgHandle);
}


BOOL IsButtonChecked (HWND hButton)
{
	if (SendMessage (hButton, BM_GETCHECK, 0, 0) == BST_CHECKED)
		return TRUE;
	else
		return FALSE;
}


void CheckButton (HWND hButton)
{
	SendMessage (hButton, BM_SETCHECK, BST_CHECKED, 0);
}


void LeftPadString (wchar_t *szTmp, int len, int targetLen, wchar_t filler)
{
	int i;

	if (targetLen <= len)
		return;

	for (i = targetLen-1; i >= (targetLen-len); i--)
		szTmp [i] = szTmp [i-(targetLen-len)];

	wmemset (szTmp, filler, targetLen-len);
	szTmp [targetLen] = 0;
}

/* InitDialog - initialize the applications main dialog, this function should
   be called only once in the dialogs WM_INITDIALOG message handler */
void InitDialog (HWND hwndDlg)
{
	NONCLIENTMETRICSW metric;
	static BOOL aboutMenuAppended = FALSE;

	int nHeight;
	LOGFONTW lf;
	HMENU hMenu;
	Font *font;

	/* Fonts */

	memset (&lf, 0, sizeof(lf));

	// Normal
	font = GetFont ("font_normal");

	metric.cbSize = sizeof (metric);
	SystemParametersInfoW (SPI_GETNONCLIENTMETRICS, sizeof(metric), &metric, 0);

	WindowTitleBarFont = CreateFontIndirectW (&metric.lfCaptionFont);

	metric.lfMessageFont.lfHeight = CompensateDPIFont (!font ? -11 : -font->Size);
	metric.lfMessageFont.lfWidth = 0;

	if (font && wcscmp (font->FaceName, L"default") != 0)
	{
		StringCbCopyW ((WCHAR *)metric.lfMessageFont.lfFaceName, sizeof (metric.lfMessageFont.lfFaceName), font->FaceName);
	}
	else if (IsOSAtLeast (WIN_VISTA))
	{
		// Vista's new default font (size and spacing) breaks compatibility with Windows 2k/XP applications.
		// Force use of Tahoma (as Microsoft does in many dialogs) until a native Vista look is implemented.
		StringCbCopyW ((WCHAR *)metric.lfMessageFont.lfFaceName, sizeof (metric.lfMessageFont.lfFaceName), L"Tahoma");
	}

	hUserFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	hUserUnderlineFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = FALSE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	metric.lfMessageFont.lfUnderline = TRUE;
	metric.lfMessageFont.lfWeight = FW_BOLD;
	hUserUnderlineBoldFont = CreateFontIndirectW (&metric.lfMessageFont);

	// Fixed-size (hexadecimal digits)
	nHeight = CompensateDPIFont (-12);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_NORMAL;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	StringCbCopyW (lf.lfFaceName, sizeof(lf.lfFaceName), L"Courier New");
	hFixedDigitFont = CreateFontIndirectW (&lf);
	if (hFixedDigitFont == NULL)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		AbortProcess ("NOFONT");
	}

	// Bold
	font = GetFont ("font_bold");

	nHeight = CompensateDPIFont (!font ? -13 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BLACK;
	StringCbCopyW (lf.lfFaceName, sizeof(lf.lfFaceName), !font ? L"Arial" : font->FaceName);
	hBoldFont = CreateFontIndirectW (&lf);
	if (hBoldFont == NULL)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		AbortProcess ("NOFONT");
	}

	// Title
	font = GetFont ("font_title");

	nHeight = CompensateDPIFont (!font ? -21 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	StringCbCopyW (lf.lfFaceName, sizeof(lf.lfFaceName),!font ? L"Times New Roman" : font->FaceName);
	hTitleFont = CreateFontIndirectW (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		AbortProcess ("NOFONT");
	}

	// Fixed-size
	font = GetFont ("font_fixed");

	nHeight = CompensateDPIFont (!font ? -12 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_NORMAL;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = PROOF_QUALITY;
	lf.lfPitchAndFamily = FF_DONTCARE;
	StringCbCopyW (lf.lfFaceName, sizeof(lf.lfFaceName),!font ? L"Lucida Console" : font->FaceName);
	hFixedFont = CreateFontIndirectW (&lf);
	if (hFixedFont == NULL)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		AbortProcess ("NOFONT");
	}

	if (!aboutMenuAppended)
	{
		hMenu = GetSystemMenu (hwndDlg, FALSE);
		AppendMenu (hMenu, MF_SEPARATOR, 0, L"");
		AppendMenuW (hMenu, MF_ENABLED | MF_STRING, IDC_ABOUT, GetString ("ABOUTBOX"));

		aboutMenuAppended = TRUE;
	}
}


// The parameter maxMessagesToProcess prevents endless processing of paint messages
void ProcessPaintMessages (HWND hwnd, int maxMessagesToProcess)
{
	MSG paintMsg;
	int msgCounter = maxMessagesToProcess;	

	while (PeekMessageW (&paintMsg, hwnd, 0, 0, PM_REMOVE | PM_QS_PAINT) != 0 && msgCounter-- > 0)
	{
		DispatchMessageW (&paintMsg);
	}
}


HDC CreateMemBitmap (HINSTANCE hInstance, HWND hwnd, wchar_t *resource)
{
	HBITMAP picture = LoadBitmap (hInstance, resource);
	HDC viewDC = GetDC (hwnd), dcMem;

	dcMem = CreateCompatibleDC (viewDC);

	SetMapMode (dcMem, MM_TEXT);

	SelectObject (dcMem, picture);

	DeleteObject (picture);

	ReleaseDC (hwnd, viewDC);

	return dcMem;
}


/* Renders the specified bitmap at the specified location and stretches it to fit (anti-aliasing is applied). 
If bDirectRender is FALSE and both nWidth and nHeight are zero, the width and height of hwndDest are
retrieved and adjusted according to screen DPI (the width and height of the resultant image are adjusted the
same way); furthermore, if bKeepAspectRatio is TRUE, the smaller DPI factor of the two (i.e. horiz. or vert.)
is used both for horiz. and vert. scaling (note that the overall GUI aspect ratio changes irregularly in
both directions depending on the DPI). If bDirectRender is TRUE, bKeepAspectRatio is ignored. 
This function returns a handle to the scaled bitmap. When the bitmap is no longer needed, it should be
deleted by calling DeleteObject() with the handle passed as the parameter. 
Known Windows issues: 
- For some reason, anti-aliasing is not applied if the source bitmap contains less than 16K pixels. 
- Windows 2000 may produce slightly inaccurate colors even when source, buffer, and target are 24-bit true color. */
HBITMAP RenderBitmap (wchar_t *resource, HWND hwndDest, int x, int y, int nWidth, int nHeight, BOOL bDirectRender, BOOL bKeepAspectRatio)
{
	LRESULT lResult = 0;

	HDC hdcSrc = CreateMemBitmap (hInst, hwndDest, resource);
	if (!hdcSrc)
		return NULL;

	HGDIOBJ picture = GetCurrentObject (hdcSrc, OBJ_BITMAP);

	HBITMAP hbmpRescaled = NULL;
	BITMAP bitmap;

	HDC hdcRescaled;

	if (!bDirectRender && nWidth == 0 && nHeight == 0)
	{
		RECT rec;

		GetClientRect (hwndDest, &rec);

		if (bKeepAspectRatio)
		{
			if (DlgAspectRatio > 1)
			{
				// Do not fix this, it's correct. We use the Y scale factor intentionally for both
				// directions to maintain aspect ratio (see above for more info).
				nWidth = CompensateYDPI (rec.right);
				nHeight = CompensateYDPI (rec.bottom);
			}
			else
			{
				// Do not fix this, it's correct. We use the X scale factor intentionally for both
				// directions to maintain aspect ratio (see above for more info).
				nWidth = CompensateXDPI (rec.right);
				nHeight = CompensateXDPI (rec.bottom);
			}
		}
		else
		{
			nWidth = CompensateXDPI (rec.right);
			nHeight = CompensateYDPI (rec.bottom);
		}
	}

	GetObject (picture, sizeof (BITMAP), &bitmap);

	hdcRescaled = CreateCompatibleDC (hdcSrc); 

	if (hdcRescaled)
	{
		hbmpRescaled = CreateCompatibleBitmap (hdcSrc, nWidth, nHeight); 

		SelectObject (hdcRescaled, hbmpRescaled);

		/* Anti-aliasing mode (HALFTONE is the only anti-aliasing algorithm natively supported by Windows 2000.
		TODO: GDI+ offers higher quality -- InterpolationModeHighQualityBicubic) */
		SetStretchBltMode (hdcRescaled, HALFTONE);

		StretchBlt (hdcRescaled,
			0,
			0,
			nWidth,
			nHeight,
			hdcSrc,
			0,
			0,
			bitmap.bmWidth, 
			bitmap.bmHeight,
			SRCCOPY);

		DeleteDC (hdcSrc);

		if (bDirectRender)
		{
			HDC hdcDest = GetDC (hwndDest);
			if (hdcDest)
			{
				BitBlt (hdcDest, x, y, nWidth, nHeight, hdcRescaled, 0, 0, SRCCOPY);
				ReleaseDC (hwndDest, hdcDest);
			}
		}
		else
		{
			lResult = SendMessage (hwndDest, (UINT) STM_SETIMAGE, (WPARAM) IMAGE_BITMAP, (LPARAM) (HANDLE) hbmpRescaled);
		}

		if ((HGDIOBJ) lResult != NULL && (HGDIOBJ) lResult != (HGDIOBJ) hbmpRescaled)
			DeleteObject ((HGDIOBJ) lResult);

		DeleteDC (hdcRescaled);
	}

	return hbmpRescaled;
}


LRESULT CALLBACK
RedTick (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_CREATE)
	{
	}
	else if (uMsg == WM_DESTROY)
	{
	}
	else if (uMsg == WM_TIMER)
	{
	}
	else if (uMsg == WM_PAINT)
	{
		PAINTSTRUCT tmp;
		HPEN hPen;
		HDC hDC;
		BOOL bEndPaint;
		RECT Rect;

		if (GetUpdateRect (hwnd, NULL, FALSE))
		{
			hDC = BeginPaint (hwnd, &tmp);
			bEndPaint = TRUE;
			if (hDC == NULL)
				return DefWindowProcW (hwnd, uMsg, wParam, lParam);
		}
		else
		{
			hDC = GetDC (hwnd);
			bEndPaint = FALSE;
		}

		GetClientRect (hwnd, &Rect);

		hPen = CreatePen (PS_SOLID, 2, RGB (0, 255, 0));
		if (hPen != NULL)
		{
			HGDIOBJ hObj = SelectObject (hDC, hPen);
			WORD bx = LOWORD (GetDialogBaseUnits ());
			WORD by = HIWORD (GetDialogBaseUnits ());

			MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);
			LineTo (hDC, Rect.right, Rect.top);
			MoveToEx (hDC, (Rect.right - Rect.left) / 2, Rect.bottom, NULL);

			LineTo (hDC, (3 * bx) / 4, (2 * by) / 8);

			SelectObject (hDC, hObj);
			DeleteObject (hPen);
		}

		if (bEndPaint)
			EndPaint (hwnd, &tmp);
		else
			ReleaseDC (hwnd, hDC);

		return TRUE;
	}

	return DefWindowProcW (hwnd, uMsg, wParam, lParam);
}

BOOL
RegisterRedTick (HINSTANCE hInstance)
{
  WNDCLASSW wc;
  ULONG rc;

  memset(&wc, 0 , sizeof wc);

  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.cbClsExtra = 0;
  wc.cbWndExtra = 4;
  wc.hInstance = hInstance;
  wc.hIcon = LoadIcon (NULL, IDI_APPLICATION);
  wc.hCursor = NULL;
  wc.hbrBackground = (HBRUSH) GetStockObject (LTGRAY_BRUSH);
  wc.lpszClassName = L"VCREDTICK";
  wc.lpfnWndProc = &RedTick; 
  
  rc = (ULONG) RegisterClassW (&wc);

  return rc == 0 ? FALSE : TRUE;
}

BOOL
UnregisterRedTick (HINSTANCE hInstance)
{
  return UnregisterClassW (L"VCREDTICK", hInstance);
}

LRESULT CALLBACK
SplashDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefDlgProcW (hwnd, uMsg, wParam, lParam);
}

static int g_waitCursorCounter = 0;

void
WaitCursor ()
{
	static HCURSOR hcWait;
	if (hcWait == NULL)
		hcWait = LoadCursor (NULL, IDC_WAIT);

	if ((g_waitCursorCounter == 0) || (hCursor != hcWait))
	{
		SetCursor (hcWait);
		hCursor = hcWait;
	}
	g_waitCursorCounter++;
}

void
NormalCursor ()
{
	static HCURSOR hcArrow;
	if (hcArrow == NULL)
		hcArrow = LoadCursor (NULL, IDC_ARROW);
	if (g_waitCursorCounter > 0)
		g_waitCursorCounter--;
	if (g_waitCursorCounter == 0)
	{
		SetCursor (hcArrow);
		hCursor = NULL;
	}
}

void
ArrowWaitCursor ()
{
	static HCURSOR hcArrowWait;
	if (hcArrowWait == NULL)
		hcArrowWait = LoadCursor (NULL, IDC_APPSTARTING);
	if ((g_waitCursorCounter == 0) || (hCursor != hcArrowWait))
	{
		SetCursor (hcArrowWait);
		hCursor = hcArrowWait;
	}
	g_waitCursorCounter++;
}

void HandCursor ()
{
	static HCURSOR hcHand;
	if (hcHand == NULL)
		hcHand = LoadCursor (NULL, IDC_HAND);
	SetCursor (hcHand);
	hCursor = hcHand;
}

void
AddComboPair (HWND hComboBox, const wchar_t *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
	nIndex = SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) value);
}

void
SelectAlgo (HWND hComboBox, int *algo_id)
{
	LPARAM nCount = SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	LPARAM x, i;

	for (i = 0; i < nCount; i++)
	{
		x = SendMessage (hComboBox, CB_GETITEMDATA, i, 0);
		if (x == (LPARAM) *algo_id)
		{
			SendMessage (hComboBox, CB_SETCURSEL, i, 0);
			return;
		}
	}

	/* Something went wrong ; couldn't find the requested algo id so we drop
	   back to a default */

	*algo_id = (int) SendMessage (hComboBox, CB_GETITEMDATA, 0, 0);

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

}

void PopulateWipeModeCombo (HWND hComboBox, BOOL bNA, BOOL bInPlaceEncryption, BOOL bHeaderWipe)
{
	if (bNA)
	{
		AddComboPair (hComboBox, GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE"), TC_WIPE_NONE);
	}
	else
	{
		if (!bHeaderWipe)
		{
			AddComboPair (hComboBox, GetString ("WIPE_MODE_NONE"), TC_WIPE_NONE);				
		}

		AddComboPair (hComboBox, GetString ("WIPE_MODE_1_RAND"), TC_WIPE_1_RAND);
		AddComboPair (hComboBox, GetString ("WIPE_MODE_3_DOD_5220"), TC_WIPE_3_DOD_5220);
		AddComboPair (hComboBox, GetString ("WIPE_MODE_7_DOD_5220"), TC_WIPE_7_DOD_5220);
		AddComboPair (hComboBox, GetString ("WIPE_MODE_35_GUTMANN"), TC_WIPE_35_GUTMANN);

		if (bHeaderWipe)
			AddComboPair (hComboBox, GetString ("WIPE_MODE_256"), TC_WIPE_256); // paranoid wipe for volume header
	}
}

wchar_t *GetWipeModeName (WipeAlgorithmId modeId)
{
	switch (modeId)
	{
	case TC_WIPE_NONE:
		return GetString ("WIPE_MODE_NONE");

	case TC_WIPE_1_RAND:
		return GetString ("WIPE_MODE_1_RAND");

	case TC_WIPE_3_DOD_5220:
		return GetString ("WIPE_MODE_3_DOD_5220");

	case TC_WIPE_7_DOD_5220:
		return GetString ("WIPE_MODE_7_DOD_5220");

	case TC_WIPE_35_GUTMANN:
		return GetString ("WIPE_MODE_35_GUTMANN");

	case TC_WIPE_256:
		return GetString ("WIPE_MODE_256");

	default:
		return GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE");
	}
}

wchar_t *GetPathType (const wchar_t *path, BOOL bUpperCase, BOOL *bIsPartition)
{
	if (wcsstr (path, L"Partition")
		&& wcsstr (path, L"Partition0") == NULL)
	{
		*bIsPartition = TRUE;
		return GetString (bUpperCase ? "PARTITION_UPPER_CASE" : "PARTITION_LOWER_CASE");
	}
	else if (wcsstr (path, L"HarddiskVolume"))
	{
		*bIsPartition = TRUE;
		return GetString (bUpperCase ? "VOLUME_UPPER_CASE" : "VOLUME_LOWER_CASE");
	}

	*bIsPartition = FALSE;
	return GetString (bUpperCase ? "DEVICE_UPPER_CASE" : "DEVICE_LOWER_CASE");
}

LRESULT CALLBACK CustomDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_SETCURSOR && hCursor != NULL)
	{
		SetCursor (hCursor);
		return TRUE;
	}

	return DefDlgProcW (hwnd, uMsg, wParam, lParam);
}

/*
static BOOL IsReturnAddress (DWORD64 address)
{
	static size_t codeEnd = 0;
	byte *sp = (byte *) address;

	if (codeEnd == 0)
	{
		MEMORY_BASIC_INFORMATION mi;
		if (VirtualQuery ((LPCVOID) 0x401000, &mi, sizeof (mi)) >= sizeof (mi))
			codeEnd = (size_t) mi.BaseAddress + mi.RegionSize;
	}

	if (address < 0x401000 + 8 || address > codeEnd)
		return FALSE;

	return sp[-5] == 0xe8									// call ADDR
		|| (sp[-6] == 0xff && sp[-5] == 0x15)				// call [ADDR]
		|| (sp[-2] == 0xff && (sp[-1] & 0xf0) == 0xd0);		// call REG
}
*/

typedef struct
{
	EXCEPTION_POINTERS *ExceptionPointers;
	HANDLE ExceptionThread;

} ExceptionHandlerThreadArgs;


void ExceptionHandlerThread (void *threadArg)
{
	ExceptionHandlerThreadArgs *args = (ExceptionHandlerThreadArgs *) threadArg;

	EXCEPTION_POINTERS *ep = args->ExceptionPointers;
	//DWORD addr;
	DWORD exCode = ep->ExceptionRecord->ExceptionCode;
	// SYSTEM_INFO si;
	// wchar_t msg[8192];
	// char modPath[MAX_PATH];
	// int crc = 0;
	// char url[MAX_URL_LENGTH];
	// char lpack[128];
	// stringstream callStack;
	// addr = (DWORD) ep->ExceptionRecord->ExceptionAddress;
	// PDWORD sp = (PDWORD) ep->ContextRecord->Esp;
	// int frameNumber = 0;

	switch (exCode)
	{
	case STATUS_IN_PAGE_ERROR:
	case 0xeedfade:
		// Exception not caused by VeraCrypt
		MessageBoxW (0, GetString ("EXCEPTION_REPORT_EXT"),
			GetString ("EXCEPTION_REPORT_TITLE"),
			MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);
		return;
	}

	// Call stack
/*	HMODULE dbgDll = LoadLibrary ("dbghelp.dll");
	if (dbgDll)
	{
		typedef DWORD (__stdcall *SymGetOptions_t) ();
		typedef DWORD (__stdcall *SymSetOptions_t) (DWORD SymOptions);
		typedef BOOL (__stdcall *SymInitialize_t) (HANDLE hProcess, PCSTR UserSearchPath, BOOL fInvadeProcess);
		typedef BOOL (__stdcall *StackWalk64_t) (DWORD MachineType, HANDLE hProcess, HANDLE hThread, LPSTACKFRAME64 StackFrame, PVOID ContextRecord, PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine, PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine, PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine, PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
		typedef BOOL (__stdcall * SymFromAddr_t) (HANDLE hProcess, DWORD64 Address, PDWORD64 Displacement, PSYMBOL_INFO Symbol);

		SymGetOptions_t DbgHelpSymGetOptions = (SymGetOptions_t) GetProcAddress (dbgDll, "SymGetOptions");
		SymSetOptions_t DbgHelpSymSetOptions = (SymSetOptions_t) GetProcAddress (dbgDll, "SymSetOptions");
		SymInitialize_t DbgHelpSymInitialize = (SymInitialize_t) GetProcAddress (dbgDll, "SymInitialize");
		PFUNCTION_TABLE_ACCESS_ROUTINE64 DbgHelpSymFunctionTableAccess64 = (PFUNCTION_TABLE_ACCESS_ROUTINE64) GetProcAddress (dbgDll, "SymFunctionTableAccess64");
		PGET_MODULE_BASE_ROUTINE64 DbgHelpSymGetModuleBase64 = (PGET_MODULE_BASE_ROUTINE64) GetProcAddress (dbgDll, "SymGetModuleBase64");
		StackWalk64_t DbgHelpStackWalk64 = (StackWalk64_t) GetProcAddress (dbgDll, "StackWalk64");
		SymFromAddr_t DbgHelpSymFromAddr = (SymFromAddr_t) GetProcAddress (dbgDll, "SymFromAddr");

		if (DbgHelpSymGetOptions && DbgHelpSymSetOptions && DbgHelpSymInitialize && DbgHelpSymFunctionTableAccess64 && DbgHelpSymGetModuleBase64 && DbgHelpStackWalk64 && DbgHelpSymFromAddr)
		{
			DbgHelpSymSetOptions (DbgHelpSymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_NO_CPP);

			if (DbgHelpSymInitialize (GetCurrentProcess(), NULL, TRUE))
			{
				STACKFRAME64 frame;
				memset (&frame, 0, sizeof (frame));

				frame.AddrPC.Offset = ep->ContextRecord->Eip;
				frame.AddrPC.Mode = AddrModeFlat;
				frame.AddrStack.Offset = ep->ContextRecord->Esp;
				frame.AddrStack.Mode = AddrModeFlat;
				frame.AddrFrame.Offset = ep->ContextRecord->Ebp;
				frame.AddrFrame.Mode = AddrModeFlat;

				string lastSymbol;

				while (frameNumber < 32 && DbgHelpStackWalk64 (IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), args->ExceptionThread, &frame, ep->ContextRecord, NULL, DbgHelpSymFunctionTableAccess64, DbgHelpSymGetModuleBase64, NULL))
				{
					if (!frame.AddrPC.Offset)
						continue;

					ULONG64 symbolBuffer[(sizeof (SYMBOL_INFO) + MAX_SYM_NAME * sizeof (TCHAR) + sizeof (ULONG64) - 1) / sizeof (ULONG64)];
					memset (symbolBuffer, 0, sizeof (symbolBuffer));

					PSYMBOL_INFO symbol = (PSYMBOL_INFO) symbolBuffer;
					symbol->SizeOfStruct = sizeof (SYMBOL_INFO);
					symbol->MaxNameLen = MAX_SYM_NAME;

					if (DbgHelpSymFromAddr (GetCurrentProcess(), frame.AddrPC.Offset, NULL, symbol) && symbol->NameLen > 0)
					{
						for (size_t i = 0; i < symbol->NameLen; ++i)
						{
							if (!isalnum (symbol->Name[i]))
								symbol->Name[i] = '_';
						}

						if (symbol->Name != lastSymbol)
							callStack << "&st" << frameNumber++ << "=" << symbol->Name;

						lastSymbol = symbol->Name;
					}
					else if (frameNumber == 0 || IsReturnAddress (frame.AddrPC.Offset))
					{
						callStack << "&st" << frameNumber++ << "=0x" << hex << frame.AddrPC.Offset << dec;
					}
				}
			}
		}
	}

	// StackWalk64() may fail due to missing frame pointers
	list <DWORD> retAddrs;
	if (frameNumber == 0)
		retAddrs.push_back (ep->ContextRecord->Eip);

	retAddrs.push_back (0);

	MEMORY_BASIC_INFORMATION mi;
	VirtualQuery (sp, &mi, sizeof (mi));
	PDWORD stackTop = (PDWORD)((byte *) mi.BaseAddress + mi.RegionSize);
	int i = 0;

	while (retAddrs.size() < 16 && &sp[i] < stackTop)
	{
		if (IsReturnAddress (sp[i]))
		{
			bool duplicate = false;
			foreach (DWORD prevAddr, retAddrs)
			{
				if (sp[i] == prevAddr)
				{
					duplicate = true;
					break;
				}
			}

			if (!duplicate)
				retAddrs.push_back (sp[i]);
		}
		i++;
	}

	if (retAddrs.size() > 1)
	{
		foreach (DWORD addr, retAddrs)
		{
			callStack << "&st" << frameNumber++ << "=0x" << hex << addr << dec;
		}
	}

	// Checksum of the module
	if (GetModuleFileName (NULL, modPath, sizeof (modPath)))
	{
		HANDLE h = CreateFile (modPath, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			BY_HANDLE_FILE_INFORMATION fi;
			if (GetFileInformationByHandle (h, &fi))
			{
				char *buf = (char *) malloc (fi.nFileSizeLow);
				if (buf)
				{
					DWORD bytesRead;
					if (ReadFile (h, buf, fi.nFileSizeLow, &bytesRead, NULL) && bytesRead == fi.nFileSizeLow)
						crc = GetCrc32 ((unsigned char *) buf, fi.nFileSizeLow);
					free (buf);
				}
			}
			CloseHandle (h);
		}
	}

	GetSystemInfo (&si);

	if (LocalizationActive)
		sprintf_s (lpack, sizeof (lpack), "&langpack=%s_%s", GetPreferredLangId (), GetActiveLangPackVersion ());
	else
		lpack[0] = 0;

	
	sprintf (url, TC_APPLINK_SECURE "&dest=err-report%s&os=%s&osver=%d.%d.%d&arch=%s&cpus=%d&app=%s&cksum=%x&dlg=%s&err=%x&addr=%x"
		, lpack
		, GetWindowsEdition().c_str()
		, CurrentOSMajor
		, CurrentOSMinor
		, CurrentOSServicePack
		, Is64BitOs () ? "x64" : "x86"
		, si.dwNumberOfProcessors
#ifdef TCMOUNT
		,"main"
#endif
#ifdef VOLFORMAT
		,"format"
#endif
#ifdef SETUP
		,"setup"
#endif
		, crc
		, LastDialogId ? LastDialogId : "-"
		, exCode
		, addr);

	string urlStr = url + callStack.str();

	_snwprintf (msg, array_capacity (msg), GetString ("EXCEPTION_REPORT"), urlStr.c_str());

	if (IDYES == MessageBoxW (0, msg, GetString ("EXCEPTION_REPORT_TITLE"), MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1))
		ShellExecute (NULL, "open", urlStr.c_str(), NULL, NULL, SW_SHOWNORMAL);
	else */
		UnhandledExceptionFilter (ep);
}


LONG __stdcall ExceptionHandler (EXCEPTION_POINTERS *ep)
{
	SetUnhandledExceptionFilter (NULL);

	if (SystemFileSelectorCallPending && SystemFileSelectorCallerThreadId == GetCurrentThreadId())
	{
		MessageBoxW (NULL, GetString ("EXCEPTION_REPORT_EXT_FILESEL"), GetString ("EXCEPTION_REPORT_TITLE"), MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);

		UnhandledExceptionFilter (ep);
		return EXCEPTION_EXECUTE_HANDLER;
	}

	ExceptionHandlerThreadArgs args;
	args.ExceptionPointers = ep;
	args.ExceptionThread = GetCurrentThread();

	WaitForSingleObject ((HANDLE) _beginthread (ExceptionHandlerThread, 0, &args), INFINITE);

	return EXCEPTION_EXECUTE_HANDLER;
}


void InvalidParameterHandler (const wchar_t *expression, const wchar_t *function, const wchar_t *file, unsigned int line, uintptr_t reserved)
{
	TC_THROW_FATAL_EXCEPTION;
}


static LRESULT CALLBACK NonInstallUacWndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProcW (hWnd, message, wParam, lParam);
}

BOOL LaunchElevatedProcess (HWND hwndDlg, const wchar_t* szModPath, const wchar_t* args)
{
	wchar_t newCmdLine[4096];
	WNDCLASSEXW wcex;
	HWND hWnd;

	memset (&wcex, 0, sizeof (wcex));
	wcex.cbSize = sizeof(WNDCLASSEX); 
	wcex.lpfnWndProc = (WNDPROC) NonInstallUacWndProc;
	wcex.hInstance = hInst;
	wcex.lpszClassName = L"VeraCrypt";
	RegisterClassExW (&wcex);

	// A small transparent window is necessary to bring the new instance to foreground
	hWnd = CreateWindowExW (WS_EX_TOOLWINDOW | WS_EX_LAYERED,
		L"VeraCrypt", L"VeraCrypt", 0,
		GetSystemMetrics (SM_CXSCREEN)/2,
		GetSystemMetrics (SM_CYSCREEN)/2,
		1, 1, NULL, NULL, hInst, NULL);

	SetLayeredWindowAttributes (hWnd, 0, 0, LWA_ALPHA);
	ShowWindow (hWnd, SW_SHOWNORMAL);

	StringCbCopyW (newCmdLine, sizeof(newCmdLine), L"/q UAC ");
	StringCbCatW (newCmdLine, sizeof (newCmdLine), args);

	if ((int)ShellExecuteW (hWnd, L"runas", szModPath, newCmdLine, NULL, SW_SHOWNORMAL) <= 32)
	{
		if (hwndDlg)
			handleWin32Error (hwndDlg, SRC_POS);
		return FALSE;
	}
	else
	{
		Sleep (2000);
		return TRUE;
	}
}


// Mutex handling to prevent multiple instances of the wizard or main app from dealing with system encryption.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateSysEncMutex (void)
{
	return TCCreateMutex (&hSysEncMutex, TC_MUTEX_NAME_SYSENC);
}


BOOL InstanceHasSysEncMutex (void)
{
	return (hSysEncMutex != NULL);
}


// Mutex handling to prevent multiple instances of the wizard from dealing with system encryption
void CloseSysEncMutex (void)
{
	TCCloseMutex (&hSysEncMutex);
}


// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateNonSysInplaceEncMutex (void)
{
	return TCCreateMutex (&hNonSysInplaceEncMutex, TC_MUTEX_NAME_NONSYS_INPLACE_ENC);
}


BOOL InstanceHasNonSysInplaceEncMutex (void)
{
	return (hNonSysInplaceEncMutex != NULL);
}


void CloseNonSysInplaceEncMutex (void)
{
	TCCloseMutex (&hNonSysInplaceEncMutex);
}


// Returns TRUE if another instance of the wizard is preparing, resuming or performing non-system in-place encryption
BOOL NonSysInplaceEncInProgressElsewhere (void)
{
	return (!InstanceHasNonSysInplaceEncMutex () 
		&& MutexExistsOnSystem (TC_MUTEX_NAME_NONSYS_INPLACE_ENC));
}


// Mutex handling to prevent multiple instances of the wizard or main app from trying to install
// or register the driver or from trying to launch it in portable mode at the same time.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateDriverSetupMutex (void)
{
	return TCCreateMutex (&hDriverSetupMutex, TC_MUTEX_NAME_DRIVER_SETUP);
}


void CloseDriverSetupMutex (void)
{
	TCCloseMutex (&hDriverSetupMutex);
}


BOOL CreateAppSetupMutex (void)
{
	return TCCreateMutex (&hAppSetupMutex, TC_MUTEX_NAME_APP_SETUP);
}


void CloseAppSetupMutex (void)
{
	TCCloseMutex (&hAppSetupMutex);
}


BOOL IsTrueCryptInstallerRunning (void)
{
	return (MutexExistsOnSystem (TC_MUTEX_NAME_APP_SETUP));
}


// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL TCCreateMutex (volatile HANDLE *hMutex, wchar_t *name)
{
	if (*hMutex != NULL)
		return TRUE;	// This instance already has the mutex

	*hMutex = CreateMutex (NULL, TRUE, name);
	if (*hMutex == NULL)
	{
		// In multi-user configurations, the OS returns "Access is denied" here when a user attempts
		// to acquire the mutex if another user already has. However, on Vista, "Access is denied" is
		// returned also if the mutex is owned by a process with admin rights while we have none.

		return FALSE;
	}

	if (GetLastError () == ERROR_ALREADY_EXISTS)
	{
		ReleaseMutex (*hMutex);
		CloseHandle (*hMutex);

		*hMutex = NULL;
		return FALSE;
	}

	return TRUE;
}


void TCCloseMutex (volatile HANDLE *hMutex)
{
	if (*hMutex != NULL)
	{
		if (ReleaseMutex (*hMutex)
			&& CloseHandle (*hMutex))
			*hMutex = NULL;
	}
}


// Returns TRUE if a process running on the system has the specified mutex (otherwise FALSE). 
BOOL MutexExistsOnSystem (wchar_t *name)
{
	if (name[0] == 0)
		return FALSE;

	HANDLE hMutex = OpenMutex (MUTEX_ALL_ACCESS, FALSE, name);

	if (hMutex == NULL)
	{
		if (GetLastError () == ERROR_FILE_NOT_FOUND)
			return FALSE;

		if (GetLastError () == ERROR_ACCESS_DENIED) // On Vista, this is returned if the owner of the mutex is elevated while we are not
			return TRUE;		

		// The call failed and it is not certain whether the mutex exists or not
		return FALSE;
	}

	CloseHandle (hMutex);
	return TRUE;
}


uint32 ReadDriverConfigurationFlags ()
{
	DWORD configMap;

	if (!ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, &configMap))
		configMap = 0;

	return configMap;
}


uint32 ReadEncryptionThreadPoolFreeCpuCountLimit ()
{
	DWORD count;

	if (!ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, &count))
		count = 0;

	return count;
}


BOOL LoadSysEncSettings ()
{
	BOOL status = TRUE;
	DWORD size = 0;
	char *sysEncCfgFileBuf = LoadFile (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION), &size);
	char *xml = sysEncCfgFileBuf;
	char paramName[100], paramVal[MAX_PATH];

	// Defaults
	int newSystemEncryptionStatus = SYSENC_STATUS_NONE;
	WipeAlgorithmId newnWipeMode = TC_WIPE_NONE;

	if (!FileExists (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION)))
	{
		SystemEncryptionStatus = newSystemEncryptionStatus;
		nWipeMode = newnWipeMode;
	}

	if (xml == NULL)
	{
		return FALSE;
	}

	while (xml = XmlFindElement (xml, "config"))
	{
		XmlGetAttributeText (xml, "key", paramName, sizeof (paramName));
		XmlGetNodeText (xml, paramVal, sizeof (paramVal));

		if (strcmp (paramName, "SystemEncryptionStatus") == 0)
		{
			newSystemEncryptionStatus = atoi (paramVal);
		}
		else if (strcmp (paramName, "WipeMode") == 0)
		{
			newnWipeMode = (WipeAlgorithmId) atoi (paramVal);
		}

		xml++;
	}

	SystemEncryptionStatus = newSystemEncryptionStatus;
	nWipeMode = newnWipeMode;

	free (sysEncCfgFileBuf);
	return status;
}


// Returns the number of partitions where non-system in-place encryption is progress or had been in progress
// but was interrupted. In addition, via the passed pointer, returns the last selected wipe algorithm ID.
int LoadNonSysInPlaceEncSettings (WipeAlgorithmId *wipeAlgorithm)
{
	char *fileBuf = NULL;
	char *fileBuf2 = NULL;
	DWORD size, size2;
	int count;

	*wipeAlgorithm = TC_WIPE_NONE;

	if (!FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC)))
		return 0;

	if ((fileBuf = LoadFile (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC), &size)) == NULL)
		return 0;

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE)))
	{
		if ((fileBuf2 = LoadFile (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE), &size2)) != NULL)
			*wipeAlgorithm = (WipeAlgorithmId) atoi (fileBuf2);
	}

	count = atoi (fileBuf);

	if (fileBuf != NULL)
		TCfree (fileBuf);

	if (fileBuf2 != NULL)
		TCfree (fileBuf2);

	return (count);
}


void RemoveNonSysInPlaceEncNotifications (void)
{
	if (FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC)))
		_wremove (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC));

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE)))
		_wremove (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE));

	if (!IsNonInstallMode () && SystemEncryptionStatus == SYSENC_STATUS_NONE)
		ManageStartupSeqWiz (TRUE, L"");
}


void SavePostInstallTasksSettings (int command)
{
	FILE *f = NULL;

	if (IsNonInstallMode() && command != TC_POST_INSTALL_CFG_REMOVE_ALL)
		return;

	switch (command)
	{
	case TC_POST_INSTALL_CFG_REMOVE_ALL:
		_wremove (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL));
		_wremove (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES));
		_wremove (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RESCUE_DISK));
		break;

	case TC_POST_INSTALL_CFG_TUTORIAL:
		f = _wfopen (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL), L"w");
		break;

	case TC_POST_INSTALL_CFG_RELEASE_NOTES:
		f = _wfopen (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES), L"w");
		break;

	case TC_POST_INSTALL_CFG_RESCUE_DISK:
		f = _wfopen (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RESCUE_DISK), L"w");
		break;

	default:
		return;
	}

	if (f == NULL)
		return;

	if (fputws (L"1", f) < 0)
	{
		// Error
		fclose (f);
		return;
	}

	TCFlushFile (f);

	fclose (f);
}


void DoPostInstallTasks (HWND hwndDlg)
{
	BOOL bDone = FALSE;

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL)))
	{
		if (AskYesNo ("AFTER_INSTALL_TUTORIAL", hwndDlg) == IDYES)
			Applink ("beginnerstutorial");

		bDone = TRUE;
	}

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES)))
	{
		if (AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES", hwndDlg) == IDYES)
			Applink ("releasenotes");

		bDone = TRUE;
	}

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RESCUE_DISK)))
	{
		if (AskYesNo ("AFTER_UPGRADE_RESCUE_DISK", hwndDlg) == IDYES)
			PostMessage (hwndDlg, VC_APPMSG_CREATE_RESCUE_DISK, 0, 0);

		bDone = TRUE;
	}

	if (bDone)
		SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_REMOVE_ALL);
}

/*
 * Use RtlGetVersion to get Windows version because GetVersionEx is affected by application manifestation.
 */
typedef NTSTATUS (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static BOOL GetWindowsVersion(LPOSVERSIONINFOW lpVersionInformation)
{
	BOOL bRet = FALSE;
	RtlGetVersionPtr RtlGetVersionFn = (RtlGetVersionPtr) GetProcAddress(GetModuleHandle (L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersionFn != NULL)
	{
		if (ERROR_SUCCESS == RtlGetVersionFn (lpVersionInformation))
			bRet = TRUE;
	}

	if (!bRet)
		bRet = GetVersionExW (lpVersionInformation);

	return bRet;
}


void InitOSVersionInfo ()
{
	OSVERSIONINFOEXW os;
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXW);

	if (GetWindowsVersion ((LPOSVERSIONINFOW) &os) == FALSE)
		AbortProcess ("NO_OS_VER");

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;
	CurrentOSServicePack = os.wServicePackMajor;

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 2)
	{
		if (os.wProductType == VER_NT_SERVER || os.wProductType == VER_NT_DOMAIN_CONTROLLER)
			nCurrentOS = WIN_SERVER_2003;
		else
			nCurrentOS = WIN_XP64;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 0)
	{
		if (os.wProductType !=  VER_NT_WORKSTATION)
			nCurrentOS = WIN_SERVER_2008;
		else
			nCurrentOS = WIN_VISTA;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 1)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2008_R2 : WIN_7);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 2)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2012 : WIN_8);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 3)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2012_R2 : WIN_8_1);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 10 && CurrentOSMinor == 0)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2016 : WIN_10);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 4)
		nCurrentOS = WIN_NT4;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 0)
		nCurrentOS = WIN_95;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10)
		nCurrentOS = WIN_98;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 90)
		nCurrentOS = WIN_ME;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32s)
		nCurrentOS = WIN_31;
	else
		nCurrentOS = WIN_UNKNOWN;
}

static void LoadSystemDll (LPCTSTR szModuleName, HMODULE *pHandle, BOOL bIgnoreError, const char* srcPos)
{
	wchar_t dllPath[MAX_PATH];

	/* Load dll explictely from System32 to avoid Dll hijacking attacks*/
	if (!GetSystemDirectory(dllPath, MAX_PATH))
		StringCbCopyW(dllPath, sizeof(dllPath), L"C:\\Windows\\System32");

	StringCbCatW(dllPath, sizeof(dllPath), L"\\");
	StringCbCatW(dllPath, sizeof(dllPath), szModuleName);

	if (((*pHandle = LoadLibrary(dllPath)) == NULL) && !bIgnoreError)
	{
		// This error is fatal
		handleWin32Error (NULL, srcPos);
		AbortProcess ("INIT_DLL");
	}
}

/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void InitApp (HINSTANCE hInstance, wchar_t *lpszCommandLine)
{
	WNDCLASSW wc;
	char langId[6];	
	InitCommonControlsPtr InitCommonControlsFn = NULL;	

   /* remove current directory from dll search path */
   SetDllDirectoryFn = (SetDllDirectoryPtr) GetProcAddress (GetModuleHandle(L"kernel32.dll"), "SetDllDirectoryW");
   SetSearchPathModeFn = (SetSearchPathModePtr) GetProcAddress (GetModuleHandle(L"kernel32.dll"), "SetSearchPathMode");
   SetDefaultDllDirectoriesFn = (SetDefaultDllDirectoriesPtr) GetProcAddress (GetModuleHandle(L"kernel32.dll"), "SetDefaultDllDirectories");

   if (SetDllDirectoryFn)
      SetDllDirectoryFn (L"");
   if (SetSearchPathModeFn)
      SetSearchPathModeFn (BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
   if (SetDefaultDllDirectoriesFn)
      SetDefaultDllDirectoriesFn (LOAD_LIBRARY_SEARCH_SYSTEM32);

   InitOSVersionInfo();

	VirtualLock (&CmdTokenPin, sizeof (CmdTokenPin));

	InitGlobalLocks ();

	LoadSystemDll (L"ntmarta.dll", &hntmartadll, TRUE, SRC_POS);
	LoadSystemDll (L"MPR.DLL", &hmprdll, TRUE, SRC_POS);
#ifdef SETUP
	if (IsOSAtLeast (WIN_7))
	{
		LoadSystemDll (L"ProfApi.DLL", &hProfApiDll, TRUE, SRC_POS);
		LoadSystemDll (L"cryptbase.dll", &hcryptbasedll, TRUE, SRC_POS);
		LoadSystemDll (L"sspicli.dll", &hsspiclidll, TRUE, SRC_POS);
	}
#endif
	LoadSystemDll (L"psapi.dll", &hpsapidll, TRUE, SRC_POS);
	LoadSystemDll (L"secur32.dll", &hsecur32dll, TRUE, SRC_POS);
	LoadSystemDll (L"msasn1.dll", &hmsasn1dll, TRUE, SRC_POS);
	LoadSystemDll (L"Usp10.DLL", &hUsp10Dll, TRUE, SRC_POS);
	if (IsOSAtLeast (WIN_7))
		LoadSystemDll (L"dwmapi.dll", &hdwmapidll, TRUE, SRC_POS);
	LoadSystemDll (L"UXTheme.dll", &hUXThemeDll, TRUE, SRC_POS);   

	LoadSystemDll (L"msls31.dll", &hMsls31, TRUE, SRC_POS);	
	LoadSystemDll (L"SETUPAPI.DLL", &hSetupDll, FALSE, SRC_POS);
	LoadSystemDll (L"SHLWAPI.DLL", &hShlwapiDll, FALSE, SRC_POS);	

	LoadSystemDll (L"userenv.dll", &hUserenvDll, TRUE, SRC_POS);
	LoadSystemDll (L"rsaenh.dll", &hRsaenhDll, TRUE, SRC_POS);

#ifdef SETUP
	if (nCurrentOS < WIN_7)
	{
		if (nCurrentOS == WIN_XP)
		{
			LoadSystemDll (L"imm32.dll", &himm32dll, TRUE, SRC_POS);
			LoadSystemDll (L"MSCTF.dll", &hMSCTFdll, TRUE, SRC_POS);
			LoadSystemDll (L"fltlib.dll", &hfltlibdll, TRUE, SRC_POS);
			LoadSystemDll (L"wbem\\framedyn.dll", &hframedyndll, TRUE, SRC_POS);
		}

		if (IsOSAtLeast (WIN_VISTA))
		{					
			LoadSystemDll (L"netapi32.dll", &hnetapi32dll, TRUE, SRC_POS);
			LoadSystemDll (L"authz.dll", &hauthzdll, TRUE, SRC_POS);
			LoadSystemDll (L"xmllite.dll", &hxmllitedll, TRUE, SRC_POS);
		}
	}

	if (IsOSAtLeast (WIN_VISTA))
	{					
		LoadSystemDll (L"atl.dll", &hsppdll, TRUE, SRC_POS);
		LoadSystemDll (L"vsstrace.dll", &hvsstracedll, TRUE, SRC_POS);
		LoadSystemDll (L"vssapi.dll", &vssapidll, TRUE, SRC_POS);
		LoadSystemDll (L"spp.dll", &hsppdll, TRUE, SRC_POS);

		if (IsOSAtLeast (WIN_7))
		{
			LoadSystemDll (L"CryptSP.dll", &hCryptSpDll, TRUE, SRC_POS);

			LoadSystemDll (L"cfgmgr32.dll", &hcfgmgr32dll, TRUE, SRC_POS);
			LoadSystemDll (L"devobj.dll", &hdevobjdll, TRUE, SRC_POS);
			LoadSystemDll (L"powrprof.dll", &hpowrprofdll, TRUE, SRC_POS);

			LoadSystemDll (L"crypt32.dll", &hcrypt32dll, TRUE, SRC_POS);

			LoadSystemDll (L"bcrypt.dll", &hbcryptdll, TRUE, SRC_POS);
			LoadSystemDll (L"bcryptprimitives.dll", &hbcryptprimitivesdll, TRUE, SRC_POS);								
		}
	}	
#else
	LoadSystemDll (L"WINSCARD.DLL", &hwinscarddll, TRUE, SRC_POS);
#endif

	LoadSystemDll (L"COMCTL32.DLL", &hComctl32Dll, FALSE, SRC_POS);
	
	// call InitCommonControls function
	InitCommonControlsFn = (InitCommonControlsPtr) GetProcAddress (hComctl32Dll, "InitCommonControls");
	ImageList_AddFn = (ImageList_AddPtr) GetProcAddress (hComctl32Dll, "ImageList_Add");
	ImageList_CreateFn = (ImageList_CreatePtr) GetProcAddress (hComctl32Dll, "ImageList_Create");

	if (InitCommonControlsFn && ImageList_AddFn && ImageList_CreateFn)
	{
		InitCommonControlsFn();
	}
	else
		AbortProcess ("INIT_DLL");

	LoadSystemDll (L"Riched20.dll", &hRichEditDll, FALSE, SRC_POS);

	// Get SetupAPI functions pointers
	SetupCloseInfFileFn = (SetupCloseInfFilePtr) GetProcAddress (hSetupDll, "SetupCloseInfFile");
	SetupDiOpenClassRegKeyFn = (SetupDiOpenClassRegKeyPtr) GetProcAddress (hSetupDll, "SetupDiOpenClassRegKey");
	SetupInstallFromInfSectionWFn = (SetupInstallFromInfSectionWPtr) GetProcAddress (hSetupDll, "SetupInstallFromInfSectionW");
	SetupOpenInfFileWFn = (SetupOpenInfFileWPtr) GetProcAddress (hSetupDll, "SetupOpenInfFileW");

	if (!SetupCloseInfFileFn || !SetupDiOpenClassRegKeyFn || !SetupInstallFromInfSectionWFn || !SetupOpenInfFileWFn)
		AbortProcess ("INIT_DLL");

	// Get SHDeleteKeyW function pointer
	SHDeleteKeyWFn = (SHDeleteKeyWPtr) GetProcAddress (hShlwapiDll, "SHDeleteKeyW");
	SHStrDupWFn = (SHStrDupWPtr) GetProcAddress (hShlwapiDll, "SHStrDupW");
	if (!SHDeleteKeyWFn || !SHStrDupWFn)
		AbortProcess ("INIT_DLL");

	if (IsOSAtLeast (WIN_VISTA))
	{
		/* Get ChangeWindowMessageFilter used to enable some messages bypasss UIPI (User Interface Privilege Isolation) */
		ChangeWindowMessageFilterFn = (ChangeWindowMessageFilterPtr) GetProcAddress (GetModuleHandle (L"user32.dll"), "ChangeWindowMessageFilter");

#ifndef SETUP
		/* enable drag-n-drop when we are running elevated */
		AllowMessageInUIPI (WM_DROPFILES);
		AllowMessageInUIPI (WM_COPYDATA);
		AllowMessageInUIPI (WM_COPYGLOBALDATA);
#endif
	}

	/* Save the instance handle for later */
	hInst = hInstance;

	SetErrorMode (SetErrorMode (0) | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
	CoInitialize (NULL);

#ifndef SETUP
	// Application ID
	typedef HRESULT (WINAPI *SetAppId_t) (PCWSTR appID);
	SetAppId_t setAppId = (SetAppId_t) GetProcAddress (GetModuleHandle (L"shell32.dll"), "SetCurrentProcessExplicitAppUserModelID");

	if (setAppId)
		setAppId (TC_APPLICATION_ID);
#endif

	// Language
	langId[0] = 0;
	SetPreferredLangId (ConfigReadString ("Language", "", langId, sizeof (langId)));
	
	if (langId[0] == 0)
	{
		if (IsNonInstallMode ())
		{
			// only support automatic use of a language file in portable mode
			// this is achieved by placing a unique language XML file in the same
			// place as portable VeraCrypt binaries.
			DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), NULL,
				(DLGPROC) LanguageDlgProc, (LPARAM) 1);
		}
		else
		{
			// when installed, force using English as default language
			SetPreferredLangId ("en");
		}
	}

	LoadLanguageFile ();

#ifndef SETUP
	// UAC elevation moniker cannot be used in portable mode.
	// A new instance of the application must be created with elevated privileges.
	if (IsNonInstallMode () && !IsAdmin () && IsUacSupported ())
	{
		wchar_t modPath[MAX_PATH];

		if (wcsstr (lpszCommandLine, L"/q UAC ") == lpszCommandLine)
		{
			Error ("UAC_INIT_ERROR", NULL);
			exit (1);
		}

		GetModuleFileNameW (NULL, modPath, ARRAYSIZE (modPath));

		if (LaunchElevatedProcess (NULL, modPath, lpszCommandLine))
			exit (0);
		else
			exit (1);
	}
#endif

	SetUnhandledExceptionFilter (ExceptionHandler);
	_set_invalid_parameter_handler (InvalidParameterHandler);

	RemoteSession = GetSystemMetrics (SM_REMOTESESSION) != 0;

	// OS version check
	if (CurrentOSMajor < 5)
	{
		MessageBoxW (NULL, GetString ("UNSUPPORTED_OS"), lpszTitle, MB_ICONSTOP);
		exit (1);
	}
	else
	{
		// Service pack check & warnings about critical MS issues
		switch (nCurrentOS)
		{
		case WIN_2000:
			if (CurrentOSServicePack < 3)
				Warning ("LARGE_IDE_WARNING_2K", NULL);
			else
			{
				DWORD val = 0, size = sizeof(val);
				HKEY hkey;

				if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Atapi\\Parameters", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
				{
					if (RegQueryValueExW (hkey, L"EnableBigLba", 0, 0, (LPBYTE) &val, &size) != ERROR_SUCCESS
							|| val != 1)
					{
						Warning ("LARGE_IDE_WARNING_2K_REGISTRY", NULL);
					}
					RegCloseKey (hkey);
				}
			}
			break;

		case WIN_XP:
			if (CurrentOSServicePack < 1)
			{
				HKEY k;
				// PE environment does not report version of SP
				if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\minint", 0, KEY_READ, &k) != ERROR_SUCCESS)
					Warning ("LARGE_IDE_WARNING_XP", NULL);
				else
					RegCloseKey (k);
			}
			break;
		}
	}
	
	/* Get the attributes for the standard dialog class */
	if ((GetClassInfoW (hInst, WINDOWS_DIALOG_CLASS, &wc)) == 0)
	{
		handleWin32Error (NULL, SRC_POS);
		AbortProcess ("INIT_REGISTER");
	}

#ifndef SETUP
	wc.hIcon = LoadIcon (hInstance, MAKEINTRESOURCE (IDI_TRUECRYPT_ICON));
#else
#include "../setup/resource.h"
	wc.hIcon = LoadIcon (hInstance, MAKEINTRESOURCE (IDI_SETUP));
#endif
	wc.lpszClassName = TC_DLG_CLASS;
	wc.lpfnWndProc = &CustomDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hDlgClass = RegisterClassW (&wc);
	if (hDlgClass == 0)
	{
		handleWin32Error (NULL, SRC_POS);
		AbortProcess ("INIT_REGISTER");
	}

	wc.lpszClassName = TC_SPLASH_CLASS;
	wc.lpfnWndProc = &SplashDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hSplashClass = RegisterClassW (&wc);
	if (hSplashClass == 0)
	{
		handleWin32Error (NULL, SRC_POS);
		AbortProcess ("INIT_REGISTER");
	}

	// DPI and GUI aspect ratio
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_AUXILIARY_DLG), NULL,
		(DLGPROC) AuxiliaryDlgProc, (LPARAM) 1);

	InitHelpFileName ();

#ifndef SETUP
	if (!EncryptionThreadPoolStart (ReadEncryptionThreadPoolFreeCpuCountLimit()))
	{
		handleWin32Error (NULL, SRC_POS);
		FREE_DLL (hRichEditDll);
		FREE_DLL (hComctl32Dll);
		FREE_DLL (hSetupDll);
		FREE_DLL (hShlwapiDll);
		FREE_DLL (hProfApiDll);
		FREE_DLL (hUsp10Dll);
		FREE_DLL (hCryptSpDll);
		FREE_DLL (hUXThemeDll);
		FREE_DLL (hUserenvDll);
		FREE_DLL (hRsaenhDll);
		FREE_DLL (himm32dll);
		FREE_DLL (hMSCTFdll);
		FREE_DLL (hfltlibdll);
		FREE_DLL (hframedyndll);
		FREE_DLL (hpsapidll);
		FREE_DLL (hsecur32dll);
		FREE_DLL (hnetapi32dll);
		FREE_DLL (hauthzdll);
		FREE_DLL (hxmllitedll);
		FREE_DLL (hmprdll);
		FREE_DLL (hsppdll);
		FREE_DLL (vssapidll);
		FREE_DLL (hvsstracedll);
		FREE_DLL (hCryptSpDll);
		FREE_DLL (hcfgmgr32dll);
		FREE_DLL (hdevobjdll);
		FREE_DLL (hpowrprofdll);
		FREE_DLL (hsspiclidll);
		FREE_DLL (hcryptbasedll);
		FREE_DLL (hdwmapidll);
		FREE_DLL (hmsasn1dll);
		FREE_DLL (hcrypt32dll);
		FREE_DLL (hbcryptdll);
		FREE_DLL (hbcryptprimitivesdll);
		FREE_DLL (hMsls31);
		FREE_DLL (hntmartadll);
		FREE_DLL (hwinscarddll);
		exit (1);
	}
#endif
}

void FinalizeApp (void)
{
	FREE_DLL (hRichEditDll);
	FREE_DLL (hComctl32Dll);
	FREE_DLL (hSetupDll);
	FREE_DLL (hShlwapiDll);
	FREE_DLL (hProfApiDll);
	FREE_DLL (hUsp10Dll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hUXThemeDll);
	FREE_DLL (hUserenvDll);
	FREE_DLL (hRsaenhDll);
	FREE_DLL (himm32dll);
	FREE_DLL (hMSCTFdll);
	FREE_DLL (hfltlibdll);
	FREE_DLL (hframedyndll);
	FREE_DLL (hpsapidll);
	FREE_DLL (hsecur32dll);
	FREE_DLL (hnetapi32dll);
	FREE_DLL (hauthzdll);
	FREE_DLL (hxmllitedll);
	FREE_DLL (hmprdll);
	FREE_DLL (hsppdll);
	FREE_DLL (vssapidll);
	FREE_DLL (hvsstracedll);
	FREE_DLL (hCryptSpDll);
	FREE_DLL (hcfgmgr32dll);
	FREE_DLL (hdevobjdll);
	FREE_DLL (hpowrprofdll);
	FREE_DLL (hsspiclidll);
	FREE_DLL (hcryptbasedll);
	FREE_DLL (hdwmapidll);
	FREE_DLL (hmsasn1dll);
	FREE_DLL (hcrypt32dll);
	FREE_DLL (hbcryptdll);
	FREE_DLL (hbcryptprimitivesdll);
	FREE_DLL (hMsls31);
	FREE_DLL (hntmartadll);
	FREE_DLL (hwinscarddll);
}

void InitHelpFileName (void)
{
	wchar_t *lpszTmp;

	GetModuleFileNameW (NULL, szHelpFile, ARRAYSIZE (szHelpFile));
	lpszTmp = wcsrchr (szHelpFile, L'\\');
	if (lpszTmp)
	{
		wchar_t szTemp[TC_MAX_PATH];

		++lpszTmp;
		*lpszTmp = 0; // add null terminating character to prepare for append operations

		// Primary file name
		if (strcmp (GetPreferredLangId(), "en") == 0
			|| strlen(GetPreferredLangId()) == 0)
		{
			StringCbCatW (szHelpFile, sizeof(szHelpFile), L"docs\\VeraCrypt User Guide.chm");
		}
		else
		{
			StringCbPrintfW (szTemp, sizeof(szTemp), L"docs\\VeraCrypt User Guide.%S.chm", GetPreferredLangId());
			StringCbCatW (szHelpFile, sizeof(szHelpFile), szTemp);
		}

		// Secondary file name (used when localized documentation is not found).
		GetModuleFileNameW (NULL, szHelpFile2, ARRAYSIZE (szHelpFile2));
		lpszTmp = wcsrchr (szHelpFile2, L'\\');
		if (lpszTmp)
		{
			++lpszTmp;
			*lpszTmp = 0;
			StringCbCatW (szHelpFile2, sizeof(szHelpFile2), L"docs\\VeraCrypt User Guide.chm");
		}
	}
}

#ifndef SETUP
BOOL OpenDevice (const wchar_t *lpszPath, OPEN_TEST_STRUCT *driver, BOOL detectFilesystem, BOOL computeVolumeIDs)
{
	DWORD dwResult;
	BOOL bResult;
	wchar_t wszFileName[TC_MAX_PATH];

	StringCbCopyW (wszFileName, sizeof(wszFileName), lpszPath);

	memset (driver, 0, sizeof (OPEN_TEST_STRUCT));
	memcpy (driver->wszFileName, wszFileName, sizeof (wszFileName));

	driver->bDetectTCBootLoader = FALSE;
	driver->DetectFilesystem = detectFilesystem;
	driver->bComputeVolumeIDs = computeVolumeIDs;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
				   driver, sizeof (OPEN_TEST_STRUCT),
				   driver, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL);

	// check variable driver
	if (	bResult 
		&& ( (driver->bDetectTCBootLoader != TRUE && driver->bDetectTCBootLoader != FALSE) ||
			  (driver->TCBootLoaderDetected != TRUE && driver->TCBootLoaderDetected != FALSE) ||
			  (driver->DetectFilesystem != TRUE && driver->DetectFilesystem != FALSE) ||
			  (driver->FilesystemDetected != TRUE && driver->FilesystemDetected != FALSE) ||
			  (wcscmp (wszFileName, driver->wszFileName))
			)
		)
	{
		return FALSE;
	}

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();

		if (dwResult == ERROR_SHARING_VIOLATION || dwResult == ERROR_NOT_READY)
		{
			driver->TCBootLoaderDetected = FALSE;
			driver->FilesystemDetected = FALSE;
			memset (driver->VolumeIDComputed, 0, sizeof (driver->VolumeIDComputed));
			return TRUE;
		}
		else
			return FALSE;
	}
		
	return TRUE;
}

#endif

// Tells the driver that it's running in portable mode
void NotifyDriverOfPortableMode (void)
{
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;

		DeviceIoControl (hDriver, TC_IOCTL_SET_PORTABLE_MODE_STATUS, NULL, 0, NULL, 0, &dwResult, NULL);
	}
}


BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize)
{
	DWORD fileSystemFlags;
	wchar_t root[] = { L'A' + (wchar_t) driveNo, L':', L'\\', 0 };

	return GetVolumeInformationW (root, label, labelSize / 2, NULL, NULL, &fileSystemFlags, NULL, 0);
}

#ifndef SETUP

/* Stores the device path of the system partition in SysPartitionDevicePath and the device path of the system drive
in SysDriveDevicePath.
IMPORTANT: As this may take a very long time if called for the first time, it should be called only before performing 
           a dangerous operation (such as header backup restore or formatting a supposedly non-system device) never 
		   at WM_INITDIALOG or any other GUI events -- instead call IsSystemDevicePath (path, hwndDlg, FALSE) for 
		   very fast preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the user
		   selected the system partition/device.
After this function completes successfully, the results are cached for the rest of the session and repeated
executions complete very fast. Returns TRUE if successful (otherwise FALSE). */
BOOL GetSysDevicePaths (HWND hwndDlg)
{
	if (!bCachedSysDevicePathsValid
		|| wcslen (SysPartitionDevicePath) <= 1 
		|| wcslen (SysDriveDevicePath) <= 1)
	{
		foreach (const HostDevice &device, GetAvailableHostDevices (false, true))
		{
			if (device.ContainsSystem)
				StringCchCopyW (device.IsPartition ? SysPartitionDevicePath : SysDriveDevicePath, TC_MAX_PATH, device.Path.c_str()); 
		}

		if (IsOSAtLeast (WIN_7))
		{
			// Find extra boot partition
			foreach (const HostDevice &drive, GetAvailableHostDevices (false, false))
			{
				if (drive.ContainsSystem)
				{
					foreach (const HostDevice &sysDrivePartition, drive.Partitions)
					{
						if (sysDrivePartition.Bootable)
						{
							if (sysDrivePartition.Size <= TC_MAX_EXTRA_BOOT_PARTITION_SIZE)
								ExtraBootPartitionDevicePath = sysDrivePartition.Path;
							break;
						}
					}
					break;
				}
			}
		}

		bCachedSysDevicePathsValid = 1;
	}

	return (bCachedSysDevicePathsValid 
		&& wcslen (SysPartitionDevicePath) > 1 
		&& wcslen (SysDriveDevicePath) > 1);
}

/* Determines whether the device path is the path of the system partition or of the system drive (or neither). 
If bReliableRequired is TRUE, very fast execution is guaranteed, but the results cannot be relied upon. 
If it's FALSE and the function is called for the first time, execution may take up to one minute but the
results are reliable.
IMPORTANT: As the execution may take a very long time if called for the first time with bReliableRequired set
           to TRUE, it should be called with bReliableRequired set to TRUE only before performing a dangerous
		   operation (such as header backup restore or formatting a supposedly non-system device) never at 
		   WM_INITDIALOG or any other GUI events (use IsSystemDevicePath(path, hwndDlg, FALSE) for fast 
		   preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the
		   user selected the system partition/device).
After this function completes successfully, the results are cached for the rest of the session, bReliableRequired
is ignored (TRUE implied), repeated executions complete very fast, and the results are always reliable. 
Return codes:
1  - it is the system partition path (e.g. \Device\Harddisk0\Partition1)
2  - it is the system drive path (e.g. \Device\Harddisk0\Partition0)
3  - it is the extra boot partition path
0  - it's not the system partition/drive path
-1 - the result can't be determined, isn't reliable, or there was an error. */
int IsSystemDevicePath (const wchar_t *path, HWND hwndDlg, BOOL bReliableRequired)
{
	if (!bCachedSysDevicePathsValid
		&& bReliableRequired)
	{
		if (!GetSysDevicePaths (hwndDlg))
			return -1;
	}

	if (wcslen (SysPartitionDevicePath) <= 1 || wcslen (SysDriveDevicePath) <= 1)
		return -1;

	if (!path)
		return -1;

	if (wcsncmp (path, SysPartitionDevicePath, max (wcslen(path), wcslen(SysPartitionDevicePath))) == 0)
		return 1;
	else if (wcsncmp (path, SysDriveDevicePath, max (wcslen(path), wcslen(SysDriveDevicePath))) == 0)
		return 2;
	else if (ExtraBootPartitionDevicePath == path)
		return 3;

	return 0;
}


/* Determines whether the path points to a non-system partition on the system drive.
IMPORTANT: As this may take a very long time if called for the first time, it should be called
           only before performing a dangerous operation, never at WM_INITDIALOG or any other GUI events. 
Return codes:
0  - it isn't a non-system partition on the system drive 
1  - it's a non-system partition on the system drive 
-1 - the result can't be determined, isn't reliable, or there was an error. */
int IsNonSysPartitionOnSysDrive (const wchar_t *path)
{
	wchar_t tmpPath [TC_MAX_PATH + 1];
	int pos;

	if (!GetSysDevicePaths (MainDlg))
		return -1;

	if (wcslen (SysPartitionDevicePath) <= 1 || wcslen (SysDriveDevicePath) <= 1)
		return -1;

	if (wcsncmp (path, SysPartitionDevicePath, max (wcslen(path), wcslen(SysPartitionDevicePath))) == 0
		|| wcsncmp (path, SysDriveDevicePath, max (wcslen(path), wcslen(SysDriveDevicePath))) == 0)
	{
		// It is the system partition/drive path (it isn't a non-system partition)
		return 0;
	}

	memset (tmpPath, 0, sizeof (tmpPath));
	wcsncpy (tmpPath, path, ARRAYSIZE (tmpPath) - 1);


	pos = (int) FindString ((const char*) tmpPath, (const char*) L"Partition", (int) wcslen (tmpPath) * 2, (int) wcslen (L"Partition") * 2, 0);

	if (pos < 0)
		return -1;

	pos /= 2;
	pos += (int) strlen ("Partition");

	if (pos + 1 > ARRAYSIZE (tmpPath) - 1)
		return -1;

	tmpPath [pos] = L'0';
	tmpPath [pos + 1] = 0;

	if (wcsncmp (tmpPath, SysDriveDevicePath, max (wcslen(tmpPath), wcslen(SysDriveDevicePath))) == 0)
	{
		// It is a non-system partition on the system drive 
		return 1;
	}
	else 
	{
		// The partition is not on the system drive 
		return 0;
	}
}

#endif //!SETUP

wstring GetSysEncryptionPretestInfo2String (void)
{
	// This huge string is divided into smaller portions to make it easier for translators to
	// re-translate it when a minor modification is made to it (the whole huge string will not be
	// reverted to English, so they will have to translate only a small portion of it).
	return (wstring (L"\n")
		+ GetString ("SYS_ENCRYPTION_PRETEST_INFO2_PORTION_1")
		+ GetString ("SYS_ENCRYPTION_PRETEST_INFO2_PORTION_2")
		+ GetString ("SYS_ENCRYPTION_PRETEST_INFO2_PORTION_3")
		+ GetString ("SYS_ENCRYPTION_PRETEST_INFO2_PORTION_4"));
}


wstring GetRescueDiskHelpString (void)
{
	// This huge string is divided into smaller portions to make it easier for translators to
	// re-translate it when a minor modification is made to it (the whole huge string will not be
	// reverted to English, so they will have to translate only a small portion of it).
	return (wstring (
		GetString ("RESCUE_DISK_HELP_PORTION_1"))
		+ GetString ("RESCUE_DISK_HELP_PORTION_2")
		+ GetString ("RESCUE_DISK_HELP_PORTION_3")
		+ GetString ("RESCUE_DISK_HELP_PORTION_4")
		+ GetString ("RESCUE_DISK_HELP_PORTION_5")
		+ GetString ("RESCUE_DISK_HELP_PORTION_6")
		+ GetString ("RESCUE_DISK_HELP_PORTION_7")
		+ GetString ("RESCUE_DISK_HELP_PORTION_8")
		+ GetString ("RESCUE_DISK_HELP_PORTION_9"));
}


wstring GetDecoyOsInstructionsString (void)
{
	// This huge string is divided into smaller portions to make it easier for translators to
	// re-translate it when a minor modification is made to it (the whole huge string will not be
	// reverted to English, so they will have to translate only a small portion of it).
	return (wstring (
		GetString ("DECOY_OS_INSTRUCTIONS_PORTION_1"))
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_2")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_3")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_4")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_5")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_6")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_7")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_8")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_9")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_10")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_11")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_12")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_13")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_14")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_15")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_16")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_17")
		+ GetString ("DECOY_OS_INSTRUCTIONS_PORTION_18"));
}

struct _TEXT_EDIT_DIALOG_PARAM {
	BOOL ReadOnly;
	std::string&  Text;
	const WCHAR*  Title;

	_TEXT_EDIT_DIALOG_PARAM(BOOL _readOnly, const WCHAR* title, std::string&  _text) : Title(title), Text(_text), ReadOnly(_readOnly) {}
	_TEXT_EDIT_DIALOG_PARAM& operator=( const _TEXT_EDIT_DIALOG_PARAM& other) { 
		ReadOnly = other.ReadOnly;
		Text = other.Text;
		Title = other.Title;
		return *this; 
}
};
typedef struct _TEXT_EDIT_DIALOG_PARAM TEXT_INFO_DIALOG_PARAM,*TEXT_INFO_DIALOG_PARAM_PTR;

INT_PTR TextEditDialogBox (BOOL readOnly, HWND parent, const WCHAR* Title, std::string& text)
{
	TEXT_INFO_DIALOG_PARAM pm(readOnly, Title, text);
	return DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TEXT_EDIT_DLG), parent, (DLGPROC) TextEditDlgProc, (LPARAM) &pm);
}

BOOL CALLBACK TextEditDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static int nID = 0;
	static TEXT_INFO_DIALOG_PARAM_PTR prm;
	switch (msg)
	{
	case WM_INITDIALOG:
		{
			prm = (TEXT_INFO_DIALOG_PARAM_PTR)lParam;
			// increase size limit of rich edit control
			SendMessage(GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), EM_EXLIMITTEXT, 0, -1);

			SetWindowTextW (hwndDlg, prm->Title);
			// Left margin for rich edit text field
			SendMessage (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), EM_SETMARGINS, (WPARAM) EC_LEFTMARGIN, (LPARAM) CompensateXDPI (4));

			if (prm->ReadOnly)
			{
				// switch rich edit control to ReadOnly
				SendMessage(GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), ES_READONLY, TRUE, 0);
				// hide cancel button
				ShowWindow(GetDlgItem(hwndDlg, IDCANCEL), SW_HIDE);
			}

			SendMessage (hwndDlg, TC_APPMSG_LOAD_TEXT_BOX_CONTENT, 0, 0);
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDOK )
		{
			if (!prm->ReadOnly)
			{
				prm->Text.resize(GetWindowTextLengthA (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT)) + 1);
				GetWindowTextA (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), &(prm->Text)[0], (int) prm->Text.size());
			}
			NormalCursor ();
			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL )
		{
			NormalCursor ();
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;

	case TC_APPMSG_LOAD_TEXT_BOX_CONTENT:
		{
			SetWindowTextA (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), prm->Text.c_str());
		}
		return 0;

	case WM_CLOSE:
		NormalCursor ();
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

INT_PTR TextInfoDialogBox (int nID)
{
	return DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TEXT_INFO_DIALOG_BOX_DLG), MainDlg, (DLGPROC) TextInfoDialogBoxDlgProc, (LPARAM) nID);
}

BOOL CALLBACK TextInfoDialogBoxDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static int nID = 0;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			nID = (int) lParam;

			// increase size limit of rich edit control
			SendMessage(GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), EM_EXLIMITTEXT, 0, -1);

			// Left margin for rich edit text field
			SendMessage (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), EM_SETMARGINS, (WPARAM) EC_LEFTMARGIN, (LPARAM) CompensateXDPI (4));

			ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_HIDE);

			switch (nID)
			{
			case TC_TBXID_LEGAL_NOTICES:
				LocalizeDialog (hwndDlg, "LEGAL_NOTICES_DLG_TITLE");
				break;

			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;

			case TC_TBXID_DECOY_OS_INSTRUCTIONS:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;

			case TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS:
				LocalizeDialog (hwndDlg, NULL);
				ShowWindow(GetDlgItem(hwndDlg, IDC_PRINT), SW_SHOW);
				break;
			}

			SendMessage (hwndDlg, TC_APPMSG_LOAD_TEXT_BOX_CONTENT, 0, 0);
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			NormalCursor ();
			EndDialog (hwndDlg, 0);
			return 1;
		}

		if (lw == IDC_PRINT)
		{
			switch (nID)
			{
			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				PrintHardCopyTextUTF16 ((wchar_t *) GetSysEncryptionPretestInfo2String ().c_str(), L"Pre-Boot Troubleshooting", GetSysEncryptionPretestInfo2String ().length () * 2);
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				PrintHardCopyTextUTF16 ((wchar_t *) GetRescueDiskHelpString ().c_str(), L"VeraCrypt Rescue Disk Help", GetRescueDiskHelpString ().length () * 2);
				break;

			case TC_TBXID_DECOY_OS_INSTRUCTIONS:
				PrintHardCopyTextUTF16 ((wchar_t *) GetDecoyOsInstructionsString ().c_str(), L"How to Create Decoy OS", GetDecoyOsInstructionsString ().length () * 2);
				break;

			case TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS:
				PrintHardCopyTextUTF16 (GetString ("EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS"), L"How to Remove Extra Boot Partition", wcslen (GetString ("EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS")) * 2);
				break;
			}
			return 1;
		}

		return 0;

	case TC_APPMSG_LOAD_TEXT_BOX_CONTENT:
		{
			char *r = NULL;

			switch (nID)
			{
			case TC_TBXID_LEGAL_NOTICES:
				LocalizeDialog (hwndDlg, "LEGAL_NOTICES_DLG_TITLE");
				r = GetLegalNotices ();
				if (r != NULL)
				{
					SETTEXTEX TextInfo = {0};

					TextInfo.flags = ST_SELECTION;
					TextInfo.codepage = CP_ACP;

					SendMessage(GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), EM_SETTEXTEX, (WPARAM)&TextInfo, (LPARAM)r);
					free (r);
				}
				break;

			case TC_TBXID_SYS_ENCRYPTION_PRETEST:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), (wchar_t *) GetSysEncryptionPretestInfo2String ().c_str());
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), (wchar_t *) GetRescueDiskHelpString ().c_str());
				break;

			case TC_TBXID_DECOY_OS_INSTRUCTIONS:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), (wchar_t *) GetDecoyOsInstructionsString ().c_str());
				break;

			case TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS:
				LocalizeDialog (hwndDlg, NULL);
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), GetString ("EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS"));
				break;
			}
		}
		return 1;

	case WM_CLOSE:
		NormalCursor ();
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}


char * GetLegalNotices ()
{
	static char *resource;
	static DWORD size;
	char *buf = NULL;

	if (resource == NULL)
		resource = (char *) MapResource (L"Text", IDR_LICENSE, &size);

	if (resource != NULL)
	{
		buf = (char *) malloc (size + 1);
		if (buf != NULL)
		{
			memcpy (buf, resource, size);
			buf[size] = 0;
		}
	}

	return buf;
}

#ifndef SETUP

BOOL CALLBACK RawDevicesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static wchar_t *lpszFileName;		// This is actually a pointer to a GLOBAL array
	static vector <HostDevice> devices;
	static map <int, HostDevice> itemToDeviceMap;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_DEVICELIST);
			RawDevicesDlgParam* pDlgParam = (RawDevicesDlgParam *) lParam;

			LocalizeDialog (hwndDlg, "IDD_RAWDEVICES_DLG");

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE|LVS_EX_LABELTIP 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("DEVICE");
			LvCol.cx = CompensateXDPI (186);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("DRIVE");  
			LvCol.cx = CompensateXDPI (38);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("SIZE");
			LvCol.cx = CompensateXDPI (64);
			LvCol.fmt = LVCFMT_RIGHT;
			SendMessage (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

			LvCol.pszText = GetString ("LABEL");
			LvCol.cx = CompensateXDPI (128);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,3,(LPARAM)&LvCol);

			devices.clear();
			itemToDeviceMap.clear();

			if (pDlgParam->devices.empty())
			{
				WaitCursor();
				devices = GetAvailableHostDevices (false, true, false);
				NormalCursor();
			}
			else
				devices = pDlgParam->devices;

			if (devices.empty())
			{
				MessageBoxW (hwndDlg, GetString ("RAWDEVICES"), lpszTitle, ICON_HAND);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			int line = 1;
			LVITEM item;
			memset (&item, 0, sizeof (item));
			item.mask = LVIF_TEXT;

			foreach (const HostDevice &device, devices)
			{
				item.iSubItem = 1;

				if (device.ContainsSystem)
				{
					if (device.IsPartition)
						StringCbCopyW (SysPartitionDevicePath, sizeof (SysPartitionDevicePath), device.Path.c_str());
					else
						StringCbCopyW (SysDriveDevicePath, sizeof (SysDriveDevicePath), device.Path.c_str());
				}

				// Path
				if (!device.IsPartition || device.DynamicVolume)
				{
					if (!device.Floppy && (device.Size == 0) 
						&& (device.IsPartition || device.Partitions.empty() || device.Partitions[0].Size == 0)
						)
						continue;

					if (line > 1)
					{
						ListItemAdd (hList, item.iItem, L"");
						item.iItem = line++;   
					}

					if (device.Floppy || device.DynamicVolume)
					{
						ListItemAdd (hList, item.iItem, (wchar_t *) device.Path.c_str());
					}
					else
					{
						wchar_t s[1024];
						if (device.Removable)
							StringCbPrintfW (s, sizeof(s), L"%s %d", GetString ("REMOVABLE_DISK"), device.SystemNumber);
						else
							StringCbPrintfW (s, sizeof(s), L"%s %d", GetString ("HARDDISK"), device.SystemNumber);

						if (!device.Partitions.empty())
							StringCbCatW (s, sizeof(s), L":");

						ListItemAdd (hList, item.iItem, s);
					}
				}
				else
				{
					ListItemAdd (hList, item.iItem, (wchar_t *) device.Path.c_str());
				}

				itemToDeviceMap[item.iItem] = device;

				// Size
				if (device.Size != 0)
				{
					wchar_t size[100] = { 0 };
					GetSizeString (device.Size, size, sizeof(size));
					ListSubItemSet (hList, item.iItem, 2, size);
				}

				// Mount point
				if (!device.MountPoint.empty())
					ListSubItemSet (hList, item.iItem, 1, (wchar_t *) device.MountPoint.c_str());

				// Label
				if (!device.Name.empty())
					ListSubItemSet (hList, item.iItem, 3, (wchar_t *) device.Name.c_str());
#ifdef TCMOUNT
				else
				{
					bool useInExplorer = false;
					wstring favoriteLabel = GetFavoriteVolumeLabel (device.Path, useInExplorer);
					if (!favoriteLabel.empty())
						ListSubItemSet (hList, item.iItem, 3, (wchar_t *) favoriteLabel.c_str());
				}
#endif

				item.iItem = line++;   
			}

			SendMessageW(hList, LVM_SETCOLUMNWIDTH, 0, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
			SendMessageW(hList, LVM_SETCOLUMNWIDTH, 1, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
			SendMessageW(hList, LVM_SETCOLUMNWIDTH, 2, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
			SendMessageW(hList, LVM_SETCOLUMNWIDTH, 3, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));

			lpszFileName = pDlgParam->pszFileName;

#ifdef VOLFORMAT
			EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
#endif
			return 1;
		}

	case WM_COMMAND:
	case WM_NOTIFY:
		// catch non-device line selected
		if (msg == WM_NOTIFY && ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED ))
		{
			BOOL bEnableOkButton = FALSE;
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));			
			LvItem.mask = LVIF_TEXT | LVIF_PARAM;   
			LvItem.iItem = ((LPNMLISTVIEW) lParam)->iItem;
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			lpszFileName[0] = 0;
			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEM, LvItem.iItem, (LPARAM) &LvItem);
			if (lpszFileName[0] != 0 && lpszFileName[0] != ' ')
			{
				bEnableOkButton = TRUE;
#ifdef VOLFORMAT
				if (	bInPlaceEncNonSysResumed && (WizardMode == WIZARD_MODE_NONSYS_DEVICE)
					&&	LvItem.iItem != -1 && itemToDeviceMap.find (LvItem.iItem) != itemToDeviceMap.end()
					)
				{
					const HostDevice selectedDevice = itemToDeviceMap[LvItem.iItem];
					if (selectedDevice.ContainsSystem)
					{
						bEnableOkButton = FALSE;
					}
				}
#endif
			}
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), bEnableOkButton);

			return 1;
		}

		if (msg == WM_COMMAND && lw == IDOK || msg == WM_NOTIFY && ((NMHDR *)lParam)->code == LVN_ITEMACTIVATE)
		{
			int selectedItem = ListView_GetSelectionMark (GetDlgItem (hwndDlg, IDC_DEVICELIST));

			if (selectedItem == -1 || itemToDeviceMap.find (selectedItem) == itemToDeviceMap.end())
				return 1; // non-device line selected	

			const HostDevice selectedDevice = itemToDeviceMap[selectedItem];
			StringCchCopyW (lpszFileName, TC_MAX_PATH, selectedDevice.Path.c_str());

#ifdef VOLFORMAT
			if (selectedDevice.ContainsSystem && selectedDevice.IsPartition)
			{
				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
				{
					if (bInPlaceEncNonSysResumed && (WizardMode == WIZARD_MODE_NONSYS_DEVICE))
					{
						// disable selection
						return 1;
					}

					if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE", hwndDlg) == IDNO)
					{
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}

					bSysPartitionSelected = TRUE;
					bSysDriveSelected = FALSE;
					lpszFileName[0] = 0;
					SwitchWizardToSysEncMode ();

					NormalCursor ();
					EndDialog (hwndDlg, IDOK);
					return 1;
				}
				else
				{
					// This should never be the case because the Select Device dialog is not available in this wizard mode
					bSysPartitionSelected = TRUE;
					bSysDriveSelected = FALSE;
					lpszFileName[0] = 0;
					SwitchWizardToSysEncMode ();
					NormalCursor ();
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}
			}

			if (!(selectedDevice.ContainsSystem && !selectedDevice.IsPartition))
			{
				if (bWarnDeviceFormatAdvanced
					&& !bHiddenVolDirect
					&& AskWarnNoYes("FORMAT_DEVICE_FOR_ADVANCED_ONLY", hwndDlg) == IDNO)
				{
					if (AskNoYes("CONFIRM_CHANGE_WIZARD_MODE_TO_FILE_CONTAINER", hwndDlg) == IDYES)
					{
						SwitchWizardToFileContainerMode ();
					}
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				if (!bHiddenVolDirect)
					bWarnDeviceFormatAdvanced = FALSE;
			}

#else	// #ifdef VOLFORMAT

			bSysPartitionSelected = (selectedDevice.ContainsSystem && selectedDevice.IsPartition);
			bSysDriveSelected = FALSE;

#endif	// #ifdef VOLFORMAT

			if (!selectedDevice.IsPartition && !selectedDevice.Floppy)
			{
				// Whole device selected

#ifdef VOLFORMAT
				if (selectedDevice.ContainsSystem && !selectedDevice.IsPartition)
				{
					if (WizardMode != WIZARD_MODE_SYS_DEVICE)
					{
						if (bInPlaceEncNonSysResumed && (WizardMode == WIZARD_MODE_NONSYS_DEVICE))
						{
							// disable selection
							return 1;
						}

						if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE", hwndDlg) == IDNO)
						{
							NormalCursor ();
							EndDialog (hwndDlg, IDCANCEL);
							return 1;
						}

						bSysDriveSelected = TRUE;
						bSysPartitionSelected = FALSE;
						lpszFileName[0] = 0;
						SwitchWizardToSysEncMode ();

						NormalCursor ();
						EndDialog (hwndDlg, IDOK);
						return 1;
					}
					else
					{
						// This should never be the case because the Select Device dialog is not available in this wizard mode
						bSysDriveSelected = TRUE;
						bSysPartitionSelected = FALSE;
						lpszFileName[0] = 0;
						SwitchWizardToSysEncMode ();
						NormalCursor ();
						EndDialog (hwndDlg, IDCANCEL);
						return 1;
					}
				}

				// Disallow format if the device contains partitions, but not if the partition is virtual or system 
				if (!selectedDevice.IsVirtualPartition
					&& !bHiddenVolDirect)
				{
					if (!selectedDevice.Partitions.empty())
					{
						EnableWindow (GetDlgItem (hwndDlg, IDOK), FALSE);
						Error ("DEVICE_PARTITIONS_ERR_W_INPLACE_ENC_NOTE", hwndDlg);
						return 1;
					}

					if (AskWarnNoYes ("WHOLE_NONSYS_DEVICE_ENC_CONFIRM", hwndDlg) == IDNO)
						return 1;
				}
#else	// #ifdef VOLFORMAT

				bSysDriveSelected = (selectedDevice.ContainsSystem && !selectedDevice.IsPartition);
				bSysPartitionSelected = FALSE;

#endif	// #ifdef VOLFORMAT
			}
			else 
				bSysDriveSelected = FALSE;

#ifdef VOLFORMAT
			bRemovableHostDevice = selectedDevice.Removable;
#endif
			NormalCursor ();
			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if ((msg == WM_COMMAND) && (lw == IDCANCEL))
		{
			NormalCursor ();
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;
	}
	return 0;
}

#endif //!SETUP

BOOL DoDriverInstall (HWND hwndDlg)
{
#ifdef SETUP
	if (SystemEncryptionUpdate)
		return TRUE;
#endif

	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

#ifdef SETUP
	StatusMessage (hwndDlg, "INSTALLING_DRIVER");
#endif

	hService = CreateService (hManager, L"veracrypt", L"veracrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
		L"System32\\drivers\\veracrypt.sys",
		NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
		goto error;
	else
		CloseServiceHandle (hService);

	hService = OpenService (hManager, L"veracrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

#ifdef SETUP
	StatusMessage (hwndDlg, "STARTING_DRIVER");
#endif

	bRet = StartService (hService, 0, NULL);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

error:
	if (bOK == FALSE && GetLastError () != ERROR_SERVICE_ALREADY_RUNNING)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		MessageBoxW (hwndDlg, GetString ("DRIVER_INSTALL_FAILED"), lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}


// Install and start driver service and mark it for removal (non-install mode)
static int DriverLoad ()
{
	HANDLE file;
	WIN32_FIND_DATA find;
	SC_HANDLE hManager, hService = NULL;
	wchar_t driverPath[TC_MAX_PATH*2];
	BOOL res;
	wchar_t *tmp;
	DWORD startType;

	if (ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", L"Start", &startType) && startType == SERVICE_BOOT_START)
		return ERR_PARAMETER_INCORRECT;

	GetModuleFileName (NULL, driverPath, ARRAYSIZE (driverPath));
	tmp = wcsrchr (driverPath, L'\\');
	if (!tmp)
	{
		driverPath[0] = L'.';
		driverPath[1] = 0;
	}
	else
		*tmp = 0;

	StringCbCatW (driverPath, sizeof(driverPath), !Is64BitOs () ? L"\\veracrypt.sys" : L"\\veracrypt-x64.sys");

	file = FindFirstFile (driverPath, &find);

	if (file == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (0, GetString ("DRIVER_NOT_FOUND"), lpszTitle, ICON_HAND);
		return ERR_DONT_REPORT;
	}

	FindClose (file);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
	{
		if (GetLastError () == ERROR_ACCESS_DENIED)
		{
			MessageBoxW (0, GetString ("ADMIN_PRIVILEGES_DRIVER"), lpszTitle, ICON_HAND);
			return ERR_DONT_REPORT;
		}

		return ERR_OS_ERROR;
	}

	hService = OpenService (hManager, L"veracrypt", SERVICE_ALL_ACCESS);
	if (hService != NULL)
	{
		// Remove stale service (driver is not loaded but service exists)
		DeleteService (hService);
		CloseServiceHandle (hService);
		Sleep (500);
	}

	hService = CreateService (hManager, L"veracrypt", L"veracrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		driverPath, NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
	{
		CloseServiceHandle (hManager);
		return ERR_OS_ERROR;
	}

	res = StartService (hService, 0, NULL);
	DeleteService (hService);

	CloseServiceHandle (hManager);
	CloseServiceHandle (hService);

	return !res ? ERR_OS_ERROR : ERROR_SUCCESS;
}


BOOL DriverUnload ()
{
	MOUNT_LIST_STRUCT driver;
	int refCount;
	int volumesMounted;
	DWORD dwResult;
	BOOL bResult;

	SC_HANDLE hManager, hService = NULL;
	BOOL bRet;
	SERVICE_STATUS status;
	int x;
	BOOL driverUnloaded = FALSE;

	if (hDriver == INVALID_HANDLE_VALUE)
		return TRUE;
	
	try
	{
		if (BootEncryption (NULL).GetStatus().DeviceFilterActive)
			return FALSE;
	}
	catch (...) { }

	// Test for mounted volumes
	bResult = DeviceIoControl (hDriver, TC_IOCTL_IS_ANY_VOLUME_MOUNTED, NULL, 0, &volumesMounted, sizeof (volumesMounted), &dwResult, NULL);

	if (!bResult)
	{
		bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_MOUNTED_VOLUMES, NULL, 0, &driver, sizeof (driver), &dwResult, NULL);
		if (bResult)
			volumesMounted = driver.ulMountedDrives;
	}

	if (bResult)
	{
		if (volumesMounted != 0)
			return FALSE;
	}
	else
		return TRUE;

	// Test for any applications attached to driver
	refCount = GetDriverRefCount ();

	if (refCount > 1)
		return FALSE;

	CloseHandle (hDriver);
	hDriver = INVALID_HANDLE_VALUE;

	// Stop driver service

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, L"veracrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = QueryServiceStatus (hService, &status);
	if (bRet != TRUE)
		goto error;

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		ControlService (hService, SERVICE_CONTROL_STOP, &status);

		for (x = 0; x < 10; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState == SERVICE_STOPPED)
			{
				driverUnloaded = TRUE;
				break;
			}

			Sleep (200);
		}
	}
	else
		driverUnloaded = TRUE;

error:
	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	if (driverUnloaded)
	{
		hDriver = INVALID_HANDLE_VALUE;
		return TRUE;
	}

	return FALSE;
}


int DriverAttach (void)
{
	/* Try to open a handle to the device driver. It will be closed later. */

#ifndef SETUP

	int nLoadRetryCount = 0;
start:

#endif

	hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
#ifndef SETUP

		LoadSysEncSettings ();

		if (!CreateDriverSetupMutex ())
		{
			// Another instance is already attempting to install, register or start the driver

			while (!CreateDriverSetupMutex ())
			{
				Sleep (100);	// Wait until the other instance finishes
			}

			// Try to open a handle to the driver again (keep the mutex in case the other instance failed)
			goto start;		
		}
		else
		{
			// No other instance is currently attempting to install, register or start the driver

			if (SystemEncryptionStatus != SYSENC_STATUS_NONE)
			{
				// This is an inconsistent state. The config file indicates system encryption should be
				// active, but the driver is not running. This may happen e.g. when the pretest fails and 
				// the user selects "Last Known Good Configuration" from the Windows boot menu.
				// To fix this, we're going to reinstall the driver, start it, and register it for boot.

				if (DoDriverInstall (NULL))
				{
					Sleep (1000);
					hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

					try
					{
						BootEncryption bootEnc (NULL);
						bootEnc.RegisterBootDriver (bootEnc.GetHiddenOSCreationPhase() != TC_HIDDEN_OS_CREATION_PHASE_NONE ? true : false);
					}
					catch (Exception &e)
					{
						e.Show (NULL);
					}
				}

				CloseDriverSetupMutex ();
			}
			else
			{
				// Attempt to load the driver (non-install/portable mode)
load:
				BOOL res = DriverLoad ();

				CloseDriverSetupMutex ();

				if (res != ERROR_SUCCESS)
					return res;

				bPortableModeConfirmed = TRUE;
			
				if (hDriver != INVALID_HANDLE_VALUE)
					CloseHandle (hDriver);
				hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			}

			if (bPortableModeConfirmed)
				NotifyDriverOfPortableMode ();
		}

#endif	// #ifndef SETUP

		if (hDriver == INVALID_HANDLE_VALUE)
			return ERR_OS_ERROR;
	}

	CloseDriverSetupMutex ();

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;

		BOOL bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

		if (!bResult)
			bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

#ifndef SETUP // Don't check version during setup to allow removal of another version
		if (bResult == FALSE)
		{
			return ERR_OS_ERROR;
		}
		else if (DriverVersion != VERSION_NUM)
		{
			// Unload an incompatbile version of the driver loaded in non-install mode and load the required version
			if (IsNonInstallMode () && CreateDriverSetupMutex () && DriverUnload () && nLoadRetryCount++ < 3)
				goto load;

			CloseDriverSetupMutex ();
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
			return ERR_DRIVER_VERSION;
		}
#else
		if (!bResult)
			DriverVersion = 0;
#endif
	}

	return 0;
}


void ResetCurrentDirectory ()
{
	wchar_t p[MAX_PATH];
	if (!IsNonInstallMode () && SHGetFolderPath (NULL, CSIDL_PROFILE, NULL, 0, p) == ERROR_SUCCESS)
	{
		SetCurrentDirectory (p);
	}
	else
	{
		GetModPath (p, ARRAYSIZE (p));
		SetCurrentDirectory (p);
	}
}


BOOL BrowseFiles (HWND hwndDlg, char *stringId, wchar_t *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter)
{
	return BrowseFilesInDir (hwndDlg, stringId, NULL, lpszFileName, keepHistory, saveMode, browseFilter);
}


BOOL BrowseFilesInDir (HWND hwndDlg, char *stringId, wchar_t *initialDir, wchar_t *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter, const wchar_t *initialFileName, const wchar_t *defaultExtension)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));
	*lpszFileName = 0;

	if (initialDir)
	{
		ofn.lpstrInitialDir			= initialDir;
	}

	if (initialFileName)
		StringCchCopyW (file, array_capacity (file), initialFileName);

	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;

	StringCbPrintfW (filter, sizeof(filter), L"%ls (*.*)%c*.*%c%ls (*.hc)%c*.hc%c%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0, 0);
	ofn.lpstrFilter				= browseFilter ? browseFilter : filter;
	ofn.nFilterIndex			= 1;
	ofn.lpstrFile				= file;
	ofn.nMaxFile				= sizeof (file) / sizeof (file[0]);
	ofn.lpstrTitle				= GetString (stringId);
	ofn.lpstrDefExt				= defaultExtension;
	ofn.Flags					= OFN_HIDEREADONLY
		| OFN_PATHMUSTEXIST
		| (keepHistory ? 0 : OFN_DONTADDTORECENT)
		| (saveMode ? OFN_OVERWRITEPROMPT : 0);

	if (!keepHistory)
		CleanLastVisitedMRU ();

	SystemFileSelectorCallerThreadId = GetCurrentThreadId();
	SystemFileSelectorCallPending = TRUE;

	if (!saveMode)
	{
		if (!GetOpenFileNameW (&ofn))
			goto ret;
	}
	else
	{
		if (!GetSaveFileNameW (&ofn))
			goto ret;
	}

	SystemFileSelectorCallPending = FALSE;

	StringCchCopyW (lpszFileName, MAX_PATH, file);

	if (!keepHistory)
		CleanLastVisitedMRU ();

	status = TRUE;

ret:
	SystemFileSelectorCallPending = FALSE;
	ResetCurrentDirectory();
	CoUninitialize();

	return status;
}


static wchar_t SelectMultipleFilesPath[131072];
static int SelectMultipleFilesOffset;

BOOL SelectMultipleFiles (HWND hwndDlg, const char *stringId, wchar_t *lpszFileName, size_t cbFileName,BOOL keepHistory)
{
	OPENFILENAMEW ofn;
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));

	SelectMultipleFilesPath[0] = 0;
	*lpszFileName = 0;
	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;
	StringCbPrintfW (filter, sizeof(filter), L"%ls (*.*)%c*.*%c%ls (*.hc)%c*.hc%c%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0, 0);
	ofn.lpstrFilter				= filter;
	ofn.nFilterIndex			= 1;
	ofn.lpstrFile				= SelectMultipleFilesPath;
	ofn.nMaxFile				= 0xffff * 2; // The size must not exceed 0xffff*2 due to a bug in Windows 2000 and XP SP1
	ofn.lpstrTitle				= GetString (stringId);
	ofn.Flags					= OFN_HIDEREADONLY
		| OFN_EXPLORER
		| OFN_PATHMUSTEXIST
		| OFN_ALLOWMULTISELECT
		| (keepHistory ? 0 : OFN_DONTADDTORECENT);
	
	if (!keepHistory)
		CleanLastVisitedMRU ();

	SystemFileSelectorCallerThreadId = GetCurrentThreadId();
	SystemFileSelectorCallPending = TRUE;

	if (!GetOpenFileNameW (&ofn))
		goto ret;

	SystemFileSelectorCallPending = FALSE;

	if (SelectMultipleFilesPath[ofn.nFileOffset - 1] != 0)
	{
		// Single file selected
		StringCbCopyW (lpszFileName, cbFileName, SelectMultipleFilesPath);
		SelectMultipleFilesOffset = 0;
		SecureZeroMemory (SelectMultipleFilesPath, sizeof (SelectMultipleFilesPath));
	}
	else
	{
		// Multiple files selected
		SelectMultipleFilesOffset = ofn.nFileOffset;
		SelectMultipleFilesNext (lpszFileName, cbFileName);
	}

	if (!keepHistory)
		CleanLastVisitedMRU ();

	status = TRUE;
	
ret:
	SystemFileSelectorCallPending = FALSE;
	ResetCurrentDirectory();
	CoUninitialize();

	return status;
}


BOOL SelectMultipleFilesNext (wchar_t *lpszFileName, size_t cbFileName)
{
	if (SelectMultipleFilesOffset == 0)
		return FALSE;

	StringCbCopyW (lpszFileName, cbFileName,SelectMultipleFilesPath);
	lpszFileName[TC_MAX_PATH - 1] = 0;

	if (lpszFileName[wcslen (lpszFileName) - 1] != L'\\')
		StringCbCatW (lpszFileName, cbFileName,L"\\");

	StringCbCatW (lpszFileName, cbFileName,SelectMultipleFilesPath + SelectMultipleFilesOffset);

	SelectMultipleFilesOffset += (int) wcslen (SelectMultipleFilesPath + SelectMultipleFilesOffset) + 1;
	if (SelectMultipleFilesPath[SelectMultipleFilesOffset] == 0)
	{
		SelectMultipleFilesOffset = 0;
		SecureZeroMemory (SelectMultipleFilesPath, sizeof (SelectMultipleFilesPath));
	}

	return TRUE;
}


static int CALLBACK BrowseCallbackProc(HWND hwnd,UINT uMsg,LPARAM lp, LPARAM pData) 
{
	switch(uMsg) {
	case BFFM_INITIALIZED: 
	{
	  /* WParam is TRUE since we are passing a path.
	   It would be FALSE if we were passing a pidl. */
	   SendMessageW (hwnd,BFFM_SETSELECTION,TRUE,(LPARAM)pData);
	   break;
	}

	case BFFM_SELCHANGED: 
	{
		wchar_t szDir[TC_MAX_PATH];

	   /* Set the status window to the currently selected path. */
	   if (SHGetPathFromIDList((LPITEMIDLIST) lp ,szDir)) 
	   {
		  SendMessage (hwnd,BFFM_SETSTATUSTEXT,0,(LPARAM)szDir);
	   }
	   break;
	}

	default:
	   break;
	}

	return 0;
}


BOOL BrowseDirectories (HWND hwndDlg, char *lpszTitle, wchar_t *dirName)
{
	BROWSEINFOW bi;
	LPITEMIDLIST pidl;
	LPMALLOC pMalloc;
	BOOL bOK  = FALSE;

	CoInitialize (NULL);

	if (SUCCEEDED (SHGetMalloc (&pMalloc))) 
	{
		ZeroMemory (&bi, sizeof(bi));
		bi.hwndOwner = hwndDlg;
		bi.pszDisplayName = 0;
		bi.lpszTitle = GetString (lpszTitle);
		bi.pidlRoot = 0;
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT;
		bi.lpfn = BrowseCallbackProc;
		bi.lParam = (LPARAM)dirName;

		pidl = SHBrowseForFolderW (&bi);
		if (pidl != NULL) 
		{
			if (SHGetPathFromIDList(pidl, dirName)) 
			{
				bOK = TRUE;
			}

			pMalloc->Free (pidl);
			pMalloc->Release();
		}
	}

	CoUninitialize();

	return bOK;
}


std::wstring GetWrongPasswordErrorMessage (HWND hwndDlg)
{
	WCHAR szTmp[8192];

	StringCbPrintfW (szTmp, sizeof(szTmp), GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG"));
	if (CheckCapsLock (hwndDlg, TRUE))
		StringCbCatW (szTmp, sizeof(szTmp), GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

#ifdef TCMOUNT
	wchar_t szDevicePath [TC_MAX_PATH+1] = {0};
	GetWindowText (GetDlgItem (MainDlg, IDC_VOLUME), szDevicePath, ARRAYSIZE (szDevicePath));

	if (TCBootLoaderOnInactiveSysEncDrive (szDevicePath))
	{
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_OR_MODE_WRONG" : "PASSWORD_OR_MODE_WRONG"));

		if (CheckCapsLock (hwndDlg, TRUE))
			StringCbCatW (szTmp, sizeof(szTmp), GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

		StringCbCatW (szTmp, sizeof(szTmp), GetString ("SYSENC_MOUNT_WITHOUT_PBA_NOTE"));
	}
#endif

	wstring msg = szTmp;

#ifdef TCMOUNT
	if (KeyFilesEnable && HiddenFilesPresentInKeyfilePath)
	{
		msg += GetString ("HIDDEN_FILES_PRESENT_IN_KEYFILE_PATH");
		HiddenFilesPresentInKeyfilePath = FALSE;
	}
#endif

	return msg;
}


void handleError (HWND hwndDlg, int code, const char* srcPos)
{
	WCHAR szTmp[4096];

	if (Silent) return;

	switch (code & 0x0000FFFF)
	{
	case ERR_OS_ERROR:
		handleWin32Error (hwndDlg, srcPos);
		break;
	case ERR_OUTOFMEMORY:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("OUTOFMEMORY"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;

	case ERR_PASSWORD_WRONG:
		MessageBoxW (hwndDlg, AppendSrcPos (GetWrongPasswordErrorMessage (hwndDlg).c_str(), srcPos).c_str(), lpszTitle, MB_ICONWARNING);
		break;

	case ERR_DRIVE_NOT_FOUND:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("NOT_FOUND"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("OPENFILES_DRIVER"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN_LOCK:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("OPENFILES_LOCK"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SIZE_WRONG:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("VOL_SIZE_WRONG"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("COMPRESSION_NOT_SUPPORTED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("WRONG_VOL_TYPE"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SEEKING:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("VOL_SEEKING"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_FAILURE:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("ERR_CIPHER_INIT_FAILURE"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_WEAK_KEY:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("ERR_CIPHER_INIT_WEAK_KEY"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("VOL_ALREADY_MOUNTED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_FILE_OPEN_FAILED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("FILE_OPEN_FAILED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_MOUNT_FAILED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString  ("VOL_MOUNT_FAILED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_DRIVES:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("NO_FREE_DRIVES"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;
	case ERR_ACCESS_DENIED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("ACCESS_DENIED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;

	case ERR_DRIVER_VERSION:
		Error ("DRIVER_VERSION", hwndDlg);
		break;

	case ERR_NEW_VERSION_REQUIRED:
		MessageBoxW (hwndDlg, AppendSrcPos (GetString ("NEW_VERSION_REQUIRED"), srcPos).c_str(), lpszTitle, ICON_HAND);
		break;

	case ERR_SELF_TESTS_FAILED:
		Error ("ERR_SELF_TESTS_FAILED", hwndDlg);
		break;

	case ERR_VOL_FORMAT_BAD:
		Error ("ERR_VOL_FORMAT_BAD", hwndDlg);
		break;

	case ERR_ENCRYPTION_NOT_COMPLETED:
		Error ("ERR_ENCRYPTION_NOT_COMPLETED", hwndDlg);
		break;

	case ERR_NONSYS_INPLACE_ENC_INCOMPLETE:
		Error ("ERR_NONSYS_INPLACE_ENC_INCOMPLETE", hwndDlg);
		break;

	case ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG:
		Error ("ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG", hwndDlg);
		break;

	case ERR_PARAMETER_INCORRECT:
		Error ("ERR_PARAMETER_INCORRECT", hwndDlg);
		break;

	case ERR_USER_ABORT:
	case ERR_DONT_REPORT:
		// A non-error
		break;

	case ERR_UNSUPPORTED_TRUECRYPT_FORMAT:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("UNSUPPORTED_TRUECRYPT_FORMAT"), (code >> 24), (code >> 16) & 0x000000FF);
		MessageBoxW (hwndDlg, AppendSrcPos (szTmp, srcPos).c_str(), lpszTitle, ICON_HAND);
		break;

#ifndef SETUP
	case ERR_RAND_INIT_FAILED:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("INIT_RAND"), SRC_POS, GetLastError ());
		MessageBoxW (hwndDlg, AppendSrcPos (szTmp, srcPos).c_str(), lpszTitle, MB_ICONERROR);
		break;

	case ERR_CAPI_INIT_FAILED:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CAPI_RAND"), SRC_POS, CryptoAPILastError);
		MessageBoxW (hwndDlg, AppendSrcPos (szTmp, srcPos).c_str(), lpszTitle, MB_ICONERROR);
		break;
#endif

	default:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("ERR_UNKNOWN"), code);
		MessageBoxW (hwndDlg, AppendSrcPos (szTmp, srcPos).c_str(), lpszTitle, ICON_HAND);
	}
}


BOOL CheckFileStreamWriteErrors (HWND hwndDlg, FILE *file, const wchar_t *fileName)
{
	if (ferror (file))
	{
		wchar_t s[TC_MAX_PATH];
		StringCbPrintfW (s, sizeof (s), GetString ("CANNOT_WRITE_FILE_X"), fileName);
		ErrorDirect (s, hwndDlg);

		return FALSE;
	}

	return TRUE;
}


static BOOL CALLBACK LocalizeDialogEnum( HWND hwnd, LPARAM font)
{
	// Localization of controls

	if (LocalizationActive)
	{
		int ctrlId = GetDlgCtrlID (hwnd);
		if (ctrlId != 0)
		{
			WCHAR name[10] = { 0 };
			GetClassNameW (hwnd, name, array_capacity (name));

			if (_wcsicmp (name, L"Button") == 0 || _wcsicmp (name, L"Static") == 0)
			{
				wchar_t *str = (wchar_t *) GetDictionaryValueByInt (ctrlId);
				if (str != NULL)
					SetWindowTextW (hwnd, str);
			}
		}
	}

	// Font
	SendMessageW (hwnd, WM_SETFONT, (WPARAM) font, 0);
	
	return TRUE;
}

void LocalizeDialog (HWND hwnd, char *stringId)
{
	LastDialogId = stringId;
	SetWindowLongPtrW (hwnd, GWLP_USERDATA, (LONG_PTR) 'VERA');
	SendMessageW (hwnd, WM_SETFONT, (WPARAM) hUserFont, 0);

	if (stringId == NULL)
		SetWindowTextW (hwnd, L"VeraCrypt");
	else
		SetWindowTextW (hwnd, GetString (stringId));
	
	if (hUserFont != 0)
		EnumChildWindows (hwnd, LocalizeDialogEnum, (LPARAM) hUserFont);
}

void OpenVolumeExplorerWindow (int driveNo)
{
	wchar_t dosName[5];
	SHFILEINFO fInfo;

	StringCbPrintfW (dosName, sizeof(dosName), L"%c:\\", (wchar_t) driveNo + L'A');

	// Force explorer to discover the drive
	SHGetFileInfo (dosName, 0, &fInfo, sizeof (fInfo), 0);

	ShellExecute (NULL, L"open", dosName, NULL, NULL, SW_SHOWNORMAL);
}

static BOOL explorerCloseSent;
static HWND explorerTopLevelWindow;

static BOOL CALLBACK CloseVolumeExplorerWindowsChildEnum (HWND hwnd, LPARAM driveStr)
{
	WCHAR s[MAX_PATH];
	SendMessageW (hwnd, WM_GETTEXT, array_capacity (s), (LPARAM) s);

	if (wcsstr (s, (WCHAR *) driveStr) != NULL)
	{
		PostMessageW (explorerTopLevelWindow, WM_CLOSE, 0, 0);
		explorerCloseSent = TRUE;
		return FALSE;
	}

	return TRUE;
}

static BOOL CALLBACK CloseVolumeExplorerWindowsEnum (HWND hwnd, LPARAM driveNo)
{
	WCHAR driveStr[10];
	WCHAR s[MAX_PATH];

	StringCbPrintfW (driveStr, sizeof(driveStr), L"%c:\\", driveNo + L'A');

	GetClassNameW (hwnd, s, array_capacity (s));
	if (wcscmp (s, L"CabinetWClass") == 0)
	{
		GetWindowTextW (hwnd, s, array_capacity (s));
		if (wcsstr (s, driveStr) != NULL)
		{
			PostMessageW (hwnd, WM_CLOSE, 0, 0);
			explorerCloseSent = TRUE;
			return TRUE;
		}

		explorerTopLevelWindow = hwnd;
		EnumChildWindows (hwnd, CloseVolumeExplorerWindowsChildEnum, (LPARAM) driveStr);
	}

	return TRUE;
}

BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo)
{
	if (driveNo >= 0)
	{
		explorerCloseSent = FALSE;
		EnumWindows (CloseVolumeExplorerWindowsEnum, (LPARAM) driveNo);
	}

	return explorerCloseSent;
}

BOOL UpdateDriveCustomLabel (int driveNo, wchar_t* effectiveLabel, BOOL bSetValue)
{
	wchar_t wszRegPath[MAX_PATH];
	wchar_t driveStr[] = {L'A' + (wchar_t) driveNo, 0};
	HKEY hKey;
	LSTATUS lStatus;
	DWORD cbLabelLen = (DWORD) ((wcslen (effectiveLabel) + 1) * sizeof (wchar_t));
	BOOL bToBeDeleted = FALSE;

	StringCbPrintfW (wszRegPath, sizeof (wszRegPath), L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%s\\DefaultLabel", driveStr);	
	
	if (bSetValue)
		lStatus = RegCreateKeyExW (HKEY_CURRENT_USER, wszRegPath, NULL, NULL, 0, 
			KEY_READ | KEY_WRITE | KEY_SET_VALUE, NULL, &hKey, NULL);
	else
		lStatus = RegOpenKeyExW (HKEY_CURRENT_USER, wszRegPath, 0, KEY_READ | KEY_WRITE | KEY_SET_VALUE, &hKey);
	if (ERROR_SUCCESS == lStatus)
	{
		if (bSetValue)
			lStatus = RegSetValueExW (hKey, NULL, NULL, REG_SZ, (LPCBYTE) effectiveLabel, cbLabelLen);
		else
		{
			wchar_t storedLabel[34] = {0};
			DWORD cbStoredLen = sizeof (storedLabel) - 1, dwType;
			lStatus = RegQueryValueExW (hKey, NULL, NULL, &dwType, (LPBYTE) storedLabel, &cbStoredLen);
			if ((ERROR_SUCCESS == lStatus) && (REG_SZ == dwType) && (0 == wcscmp(storedLabel, effectiveLabel)))
			{
				// same label stored. mark key for deletion
				bToBeDeleted = TRUE;
			}
		}
		RegCloseKey (hKey);
	}

	if (bToBeDeleted)
	{
		StringCbPrintfW (wszRegPath, sizeof (wszRegPath), L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%s", driveStr);	
		lStatus = RegOpenKeyExW (HKEY_CURRENT_USER, wszRegPath, 0, KEY_READ | KEY_WRITE | KEY_SET_VALUE, &hKey);
		if (ERROR_SUCCESS == lStatus)
		{
			lStatus = RegDeleteKeyW (hKey, L"DefaultLabel");
			RegCloseKey (hKey);
		}

		// delete drive letter of nothing else is present under it
		RegDeleteKeyW (HKEY_CURRENT_USER, wszRegPath);

	}

	return (ERROR_SUCCESS == lStatus)? TRUE : FALSE;
}

wstring GetUserFriendlyVersionString (int version)
{
	wchar_t szTmp [64];
	StringCbPrintfW (szTmp, sizeof(szTmp), L"%x", version);

	wstring versionString (szTmp);

	versionString.insert (version > 0xfff ? 2 : 1,L".");

	return (versionString);
}

wstring IntToWideString (int val)
{
	wchar_t szTmp [64];
	StringCbPrintfW (szTmp, sizeof(szTmp), L"%d", val);

	return szTmp;
}

wstring ArrayToHexWideString (const unsigned char* pbData, int cbData)
{
	static wchar_t* hexChar = L"0123456789ABCDEF";
	wstring result;
	if (pbData)
	{
		for (int i = 0; i < cbData; i++)
		{
			result += hexChar[pbData[i] >> 4];
			result += hexChar[pbData[i] & 0x0F];
		}
	}

	return result;
}

bool HexToByte (wchar_t c, byte& b)
{
	bool bRet = true;
	if (c >= L'0' && c <= L'9')
		b = (byte) (c - L'0');
	else if (c >= L'a' && c <= L'z')
		b = (byte) (c - L'a' + 10);
	else if (c >= L'A' && c <= L'Z')
		b = (byte) (c - L'A' + 10);
	else
		bRet = false;

	return bRet;
}

bool HexWideStringToArray (const wchar_t* hexStr, std::vector<byte>& arr)
{
	byte b1, b2;
	size_t i, len = wcslen (hexStr);

	arr.clear();
	if (len %2)
		return false;
	
	for (i = 0; i < len/2; i++)
	{
		if (!HexToByte (*hexStr++, b1) || !HexToByte (*hexStr++, b2))
			return false;
		arr.push_back (b1 << 4 | b2);
	}
	return true;
}

wstring GetTempPathString ()
{
	wchar_t tempPath[MAX_PATH];
	DWORD tempLen = ::GetTempPath (ARRAYSIZE (tempPath), tempPath);
	if (tempLen == 0 || tempLen > ARRAYSIZE (tempPath))
		throw ParameterIncorrect (SRC_POS);

	return wstring (tempPath);
}

void GetSizeString (unsigned __int64 size, wchar_t *str, size_t cbStr)
{
	static wchar_t *b, *kb, *mb, *gb, *tb, *pb;
	static int serNo;

	if (b == NULL || serNo != LocalizationSerialNo)
	{
		serNo = LocalizationSerialNo;
		kb = GetString ("KB");
		mb = GetString ("MB");
		gb = GetString ("GB");
		tb = GetString ("TB");
		pb = GetString ("PB");
		b = GetString ("BYTE");
	}

	if (size > 1024I64*1024*1024*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s", size/1024/1024/1024/1024/1024, pb);
	else if (size > 1024I64*1024*1024*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(size/1024.0/1024/1024/1024/1024), pb);
	else if (size > 1024I64*1024*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s",size/1024/1024/1024/1024, tb);
	else if (size > 1024I64*1024*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(size/1024.0/1024/1024/1024), tb);
	else if (size > 1024I64*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s",size/1024/1024/1024, gb);
	else if (size > 1024I64*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(size/1024.0/1024/1024), gb);
	else if (size > 1024I64*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s", size/1024/1024, mb);
	else if (size > 1024I64*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(size/1024.0/1024), mb);
	else if (size >= 1024I64)
		StringCbPrintfW (str, cbStr, L"%I64d %s", size/1024, kb);
	else
		StringCbPrintfW (str, cbStr, L"%I64d %s", size, b);
}

#ifndef SETUP
void GetSpeedString (unsigned __int64 speed, wchar_t *str, size_t cbStr)
{
	static wchar_t *b, *kb, *mb, *gb, *tb, *pb;
	static int serNo;
	
	if (b == NULL || serNo != LocalizationSerialNo)
	{
		serNo = LocalizationSerialNo;
		kb = GetString ("KB_PER_SEC");
		mb = GetString ("MB_PER_SEC");
		gb = GetString ("GB_PER_SEC");
		tb = GetString ("TB_PER_SEC");
		pb = GetString ("PB_PER_SEC");
		b = GetString ("B_PER_SEC");
	}

	if (speed > 1024I64*1024*1024*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s", speed/1024/1024/1024/1024/1024, pb);
	else if (speed > 1024I64*1024*1024*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024/1024), pb);
	else if (speed > 1024I64*1024*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s",speed/1024/1024/1024/1024, tb);
	else if (speed > 1024I64*1024*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024), tb);
	else if (speed > 1024I64*1024*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s",speed/1024/1024/1024, gb);
	else if (speed > 1024I64*1024*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(speed/1024.0/1024/1024), gb);
	else if (speed > 1024I64*1024*99)
		StringCbPrintfW (str, cbStr, L"%I64d %s", speed/1024/1024, mb);
	else if (speed > 1024I64*1024)
		StringCbPrintfW (str, cbStr, L"%.1f %s",(double)(speed/1024.0/1024), mb);
	else if (speed > 1024I64)
		StringCbPrintfW (str, cbStr, L"%I64d %s", speed/1024, kb);
	else
		StringCbPrintfW (str, cbStr, L"%I64d %s", speed, b);
}

static void ResetBenchmarkList (HWND hwndDlg)
{
	LVCOLUMNW LvCol;

	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);

	/* Render the results */
	// delete data
	SendMessage (hList, LVM_DELETEALLITEMS, 0, 0);
	// Delete headers
	SendMessageW (hList, LVM_DELETECOLUMN, 1, 0);
	SendMessageW (hList, LVM_DELETECOLUMN, 1, 0);
	SendMessageW (hList, LVM_DELETECOLUMN, 1, 0);

	memset (&LvCol,0,sizeof(LvCol));               
	LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
	switch(benchmarkType) {
	case BENCHMARK_TYPE_ENCRYPTION:
		// Create headers
		LvCol.pszText = GetString ("ENCRYPTION");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

		LvCol.pszText = GetString ("DECRYPTION");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);

		LvCol.pszText = GetString ("MEAN");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,3,(LPARAM)&LvCol);
		break;
	case BENCHMARK_TYPE_HASH:
		LvCol.pszText = GetString ("MEAN");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);
		break;
	case BENCHMARK_TYPE_PRF:
		LvCol.pszText = GetString ("TIME");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&LvCol);

		LvCol.pszText = GetString ("ITERATIONS");
		LvCol.cx = CompensateXDPI (80);
		LvCol.fmt = LVCFMT_RIGHT;
		SendMessageW (hList,LVM_INSERTCOLUMNW,2,(LPARAM)&LvCol);
		break;
	}
}

static void DisplayBenchmarkResults (HWND hwndDlg)
{
	wchar_t item1[100]={0};
	LVITEMW LvItem;
	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
	int ea, i;
	BOOL unsorted = TRUE;
	BENCHMARK_REC tmp_line;

	ResetBenchmarkList (hwndDlg);

	/* Sort the list */

	switch (benchmarkSortMethod)
	{
	case BENCHMARK_SORT_BY_SPEED:

		while (unsorted)
		{
			unsorted = FALSE;
			for (i = 0; i < benchmarkTotalItems - 1; i++)
			{

				if (((benchmarkType == BENCHMARK_TYPE_PRF) && (benchmarkTable[i].meanBytesPerSec > benchmarkTable[i+1].meanBytesPerSec)) ||
					 ((benchmarkType != BENCHMARK_TYPE_PRF) && (benchmarkTable[i].meanBytesPerSec < benchmarkTable[i+1].meanBytesPerSec))
					)
				{
					unsorted = TRUE;
					memcpy (&tmp_line, &benchmarkTable[i], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i], &benchmarkTable[i+1], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i+1], &tmp_line, sizeof(BENCHMARK_REC));
				}
			}
		}
		break;

	case BENCHMARK_SORT_BY_NAME:

		while (unsorted)
		{
			unsorted = FALSE;
			for (i = 0; i < benchmarkTotalItems - 1; i++)
			{
				if (benchmarkTable[i].id > benchmarkTable[i+1].id)
				{
					unsorted = TRUE;
					memcpy (&tmp_line, &benchmarkTable[i], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i], &benchmarkTable[i+1], sizeof(BENCHMARK_REC));
					memcpy (&benchmarkTable[i+1], &tmp_line, sizeof(BENCHMARK_REC));
				}
			}
		}
		break;
	}
  
	for (i = 0; i < benchmarkTotalItems; i++)
	{
		ea = benchmarkTable[i].id;

		memset (&LvItem,0,sizeof(LvItem));
		LvItem.mask = LVIF_TEXT;
		LvItem.iItem = i;
		LvItem.iSubItem = 0;
		LvItem.pszText = (LPWSTR) benchmarkTable[i].name;
		SendMessageW (hList, LVM_INSERTITEM, 0, (LPARAM)&LvItem); 
		switch(benchmarkType) {
		case BENCHMARK_TYPE_ENCRYPTION:
			GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].encSpeed / benchmarkPerformanceFrequency.QuadPart)), item1, sizeof(item1));
			LvItem.iSubItem = 1;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

			GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].decSpeed / benchmarkPerformanceFrequency.QuadPart)), item1, sizeof(item1));
			LvItem.iSubItem = 2;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

			GetSpeedString (benchmarkTable[i].meanBytesPerSec, item1, sizeof(item1));
			LvItem.iSubItem = 3;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
			break;
		case BENCHMARK_TYPE_HASH:
			GetSpeedString (benchmarkTable[i].meanBytesPerSec, item1, sizeof(item1));
			LvItem.iSubItem = 1;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
			break;
		case BENCHMARK_TYPE_PRF:
			swprintf_s (item1, sizeof(item1) / sizeof(item1[0]), L"%d ms", benchmarkTable[i].meanBytesPerSec);
			LvItem.iSubItem = 1;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
			swprintf_s (item1, sizeof(item1) / sizeof(item1[0]), L"%d", benchmarkTable[i].decSpeed);
			LvItem.iSubItem = 2;
			LvItem.pszText = item1;
			SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
			break;
		}
	}

	SendMessageW(hList, LVM_SETCOLUMNWIDTH, 0, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
	SendMessageW(hList, LVM_SETCOLUMNWIDTH, 1, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
	SendMessageW(hList, LVM_SETCOLUMNWIDTH, 2, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
	SendMessageW(hList, LVM_SETCOLUMNWIDTH, 3, MAKELPARAM(LVSCW_AUTOSIZE_USEHEADER, 0));
}

// specific implementation for support of benchmark operation in wait dialog mechanism

typedef struct
{
	HWND hBenchDlg;
	BOOL bStatus; 
} BenchmarkThreadParam;

static BOOL PerformBenchmark(HWND hBenchDlg, HWND hwndDlg);

void CALLBACK BenchmarkThreadProc(void* pArg, HWND hwndDlg)
{
	BenchmarkThreadParam* pThreadParam = (BenchmarkThreadParam*) pArg;

	pThreadParam->bStatus = PerformBenchmark (pThreadParam->hBenchDlg, hwndDlg);
}

static BOOL PerformBenchmark(HWND hBenchDlg, HWND hwndDlg)
{
    LARGE_INTEGER performanceCountStart, performanceCountEnd;
	BYTE *lpTestBuffer = NULL;
	PCRYPTO_INFO ci = NULL;
	UINT64_STRUCT startDataUnitNo;
	SYSTEM_INFO sysInfo = {0};

	GetSystemInfo (&sysInfo);
	startDataUnitNo.Value = 0;

	/* set priority to critical only when there are 2 or more CPUs on the system */
	if (sysInfo.dwNumberOfProcessors > 1 && (benchmarkType != BENCHMARK_TYPE_ENCRYPTION))
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	ci = crypto_open ();
	if (!ci)
		return FALSE;

	if (QueryPerformanceFrequency (&benchmarkPerformanceFrequency) == 0)
	{
		if (ci)
			crypto_close (ci);
		MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	if (benchmarkType != BENCHMARK_TYPE_PRF)
	{
		lpTestBuffer = (BYTE *) _aligned_malloc(benchmarkBufferSize - (benchmarkBufferSize % 16), 16);
		if (lpTestBuffer == NULL)
		{
			if (ci)
				crypto_close (ci);
			MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
			return FALSE;
		}
		VirtualLock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));
	}

	WaitCursor ();
	benchmarkTotalItems = 0;

	switch(benchmarkType) {

	case BENCHMARK_TYPE_HASH:
		/*	Measures the speed at which each of the hash algorithms processes the message to produce
			a single digest.
		*/
		{
			BYTE *digest [MAX_DIGESTSIZE];
			WHIRLPOOL_CTX	wctx;
			RMD160_CTX		rctx;
			sha512_ctx		s2ctx;
			sha256_ctx		s256ctx;
			STREEBOG_CTX		stctx;

			int hid, i;

			for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++) 
			{
				if (QueryPerformanceCounter (&performanceCountStart) == 0)
					goto counter_error;

				for (i = 1; i <= 2; i++) 
				{
					switch (hid)
					{

					case SHA512:
						sha512_begin (&s2ctx);
						sha512_hash (lpTestBuffer, benchmarkBufferSize, &s2ctx);
						sha512_end ((unsigned char *) digest, &s2ctx);
						break;

					case SHA256:
						sha256_begin (&s256ctx);
						sha256_hash (lpTestBuffer, benchmarkBufferSize, &s256ctx);
						sha256_end ((unsigned char *) digest, &s256ctx);
						break;

					case RIPEMD160:
						RMD160Init(&rctx);
						RMD160Update(&rctx, lpTestBuffer, benchmarkBufferSize);
						RMD160Final((unsigned char *) digest, &rctx);
						break;

					case WHIRLPOOL:
						WHIRLPOOL_init (&wctx);
						WHIRLPOOL_add (lpTestBuffer, benchmarkBufferSize, &wctx);
						WHIRLPOOL_finalize (&wctx, (unsigned char *) digest);
						break;

					case STREEBOG:
						STREEBOG_init(&stctx);
						STREEBOG_add(&stctx, lpTestBuffer, benchmarkBufferSize);
						STREEBOG_finalize(&stctx, (unsigned char *)digest);
						break;

					}
				}

				if (QueryPerformanceCounter (&performanceCountEnd) == 0)
					goto counter_error;

				benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

				benchmarkTable[benchmarkTotalItems].decSpeed = benchmarkTable[benchmarkTotalItems].encSpeed;
				benchmarkTable[benchmarkTotalItems].id = hid;
				benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart / 2));
				StringCbPrintfW (benchmarkTable[benchmarkTotalItems].name, sizeof(benchmarkTable[benchmarkTotalItems].name),L"%s", HashGetName(hid));

				benchmarkTotalItems++;
			}
		}
	break;

	case BENCHMARK_TYPE_PRF:
	/* Measures the time that it takes for the PKCS-5 routine to derive a header key using
	   each of the implemented PRF algorithms. 
	*/
	{
		int thid, i;
		char dk[MASTER_KEYDATA_SIZE];
		char *tmp_salt = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"};

		for (thid = FIRST_PRF_ID; thid <= LAST_PRF_ID; thid++) 
		{
			if (benchmarkPreBoot && !benchmarkGPT && !HashForSystemEncryption (thid))
				continue;

			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			for (i = 1; i <= 2; i++) 
			{
				switch (thid)
				{

				case SHA512:
					/* PKCS-5 test with HMAC-SHA-512 used as the PRF */
					derive_key_sha512 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot), dk, MASTER_KEYDATA_SIZE);
					break;

				case SHA256:
					/* PKCS-5 test with HMAC-SHA-256 used as the PRF */
					derive_key_sha256 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot), dk, MASTER_KEYDATA_SIZE);
					break;

				case RIPEMD160:
					/* PKCS-5 test with HMAC-RIPEMD-160 used as the PRF */
					derive_key_ripemd160 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot), dk, MASTER_KEYDATA_SIZE);
					break;

				case WHIRLPOOL:
					/* PKCS-5 test with HMAC-Whirlpool used as the PRF */
					derive_key_whirlpool ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot), dk, MASTER_KEYDATA_SIZE);
					break;

				case STREEBOG:
					/* PKCS-5 test with HMAC-STREEBOG used as the PRF */
					derive_key_streebog("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot), dk, MASTER_KEYDATA_SIZE);
					break;
				}
			}

			if (QueryPerformanceCounter (&performanceCountEnd) == 0)
				goto counter_error;

			benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
			benchmarkTable[benchmarkTotalItems].id = thid;
			benchmarkTable[benchmarkTotalItems].decSpeed = get_pkcs5_iteration_count(thid, benchmarkPim, FALSE, benchmarkPreBoot);
			benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (unsigned __int64) (1000 * ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart / 2));
			if (benchmarkPreBoot)
			{
				/* heuristics for boot times */
				if (benchmarkGPT)
				{
					benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (benchmarkTable[benchmarkTotalItems].meanBytesPerSec * 8) / 5;
				}
				else
				{
					if (thid == SHA256)
					{
#ifdef  _WIN64
						benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (benchmarkTable[benchmarkTotalItems].meanBytesPerSec * 26);
#else
						benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (benchmarkTable[benchmarkTotalItems].meanBytesPerSec * 24);
#endif
					}
					else
					{
#ifdef _WIN64
						benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (benchmarkTable[benchmarkTotalItems].meanBytesPerSec * 21) / 5;
#else
						benchmarkTable[benchmarkTotalItems].meanBytesPerSec = (benchmarkTable[benchmarkTotalItems].meanBytesPerSec * 18) / 5;
#endif
					}
				}
			}
			StringCbPrintfW (benchmarkTable[benchmarkTotalItems].name, sizeof(benchmarkTable[benchmarkTotalItems].name),L"%s", get_pkcs5_prf_name (thid));

			benchmarkTotalItems++;
		}
	}
	break;
	case BENCHMARK_TYPE_ENCRYPTION:
		{
			/* Encryption algorithm benchmarks */

			// CPU "warm up" (an attempt to prevent skewed results on systems where CPU frequency
			// gradually changes depending on CPU load).
			ci->ea = EAGetFirst();
			if (!EAInit (ci->ea, ci->master_keydata, ci->ks))
			{
				ci->mode = FIRST_MODE_OF_OPERATION_ID;
				if (EAInitMode (ci))
				{
					int i;

					for (i = 0; i < 10; i++)
					{
						EncryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);
						DecryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);
					}
				}
			}

			for (ci->ea = EAGetFirst(); ci->ea != 0; ci->ea = EAGetNext(ci->ea))
			{
				if (!EAIsFormatEnabled (ci->ea))
					continue;

				if (ERR_CIPHER_INIT_FAILURE == EAInit (ci->ea, ci->master_keydata, ci->ks))
					goto counter_error;

				ci->mode = FIRST_MODE_OF_OPERATION_ID;
				if (!EAInitMode (ci))
					goto counter_error;

				if (QueryPerformanceCounter (&performanceCountStart) == 0)
					goto counter_error;

				EncryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);

				if (QueryPerformanceCounter (&performanceCountEnd) == 0)
					goto counter_error;

				benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

				if (QueryPerformanceCounter (&performanceCountStart) == 0)
					goto counter_error;

				DecryptDataUnits (lpTestBuffer, &startDataUnitNo, (TC_LARGEST_COMPILER_UINT) benchmarkBufferSize / ENCRYPTION_DATA_UNIT_SIZE, ci);

				if (QueryPerformanceCounter (&performanceCountEnd) == 0)
					goto counter_error;

				benchmarkTable[benchmarkTotalItems].decSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
				benchmarkTable[benchmarkTotalItems].id = ci->ea;
				benchmarkTable[benchmarkTotalItems].meanBytesPerSec = ((unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart)) + (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].decSpeed / benchmarkPerformanceFrequency.QuadPart))) / 2;
				EAGetName (benchmarkTable[benchmarkTotalItems].name, ci->ea, 1);

				benchmarkTotalItems++;
			}
		}
	break;
	}

	if (ci)
		crypto_close (ci);

	if (lpTestBuffer)
	{
		VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

		_aligned_free(lpTestBuffer);
	}

	benchmarkLastBufferSize = benchmarkBufferSize;

	DisplayBenchmarkResults(hBenchDlg);

	EnableWindow (GetDlgItem (hBenchDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hBenchDlg, IDCLOSE), TRUE);

	NormalCursor ();
	return TRUE;

counter_error:
	
	if (ci)
		crypto_close (ci);

	if (lpTestBuffer)
	{
		VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

		_aligned_free(lpTestBuffer);
	}

	NormalCursor ();

	EnableWindow (GetDlgItem (hBenchDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hBenchDlg, IDCLOSE), TRUE);

	MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
	return FALSE;
}


BOOL CALLBACK BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	LPARAM nIndex;
	static HWND hCboxSortMethod = NULL, hCboxBufferSize = NULL, hCboxList = NULL;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			wchar_t s[128];
			HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
			hCboxSortMethod = GetDlgItem (hwndDlg, IDC_BENCHMARK_SORT_METHOD);
			hCboxBufferSize = GetDlgItem (hwndDlg, IDC_BENCHMARK_BUFFER_SIZE);
			hCboxList = GetDlgItem (hwndDlg, IDC_BENCHMARK_LIST);

			LocalizeDialog (hwndDlg, "IDD_BENCHMARK_DLG");

			benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
			benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;
			benchmarkType = BENCHMARK_TYPE_ENCRYPTION;

			if (lParam)
			{
				benchmarkGPT = TRUE;
			}
			else
				benchmarkGPT = FALSE;

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("ALGORITHM");
			LvCol.cx = CompensateXDPI (114);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

			ResetBenchmarkList (hwndDlg);

			/* Combo boxes */

			// Sort method

			SendMessage (hCboxSortMethod, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("ALPHABETICAL_CATEGORIZED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("MEAN_SPEED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			SendMessage (hCboxSortMethod, CB_SETCURSEL, 1, 0);		// Default sort method

			// benchmark list

			SendMessage (hCboxList, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hCboxList, CB_ADDSTRING, 0, (LPARAM) GetString ("ENCRYPTION_ALGORITHM"));
			SendMessage (hCboxList, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessageW (hCboxList, CB_ADDSTRING, 0, (LPARAM) GetString ("PKCS5_PRF"));
			SendMessage (hCboxList, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessageW (hCboxList, CB_ADDSTRING, 0, (LPARAM) GetString ("IDT_HASH_ALGO"));
			SendMessage (hCboxList, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			SendMessage (hCboxList, CB_SETCURSEL, 0, 0);		// Default: benchmark of encryption

			// Buffer size

			SendMessage (hCboxBufferSize, CB_RESETCONTENT, 0, 0);

			StringCbPrintfW (s, sizeof(s), L"100 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_KB);

			StringCbPrintfW (s, sizeof(s), L"500 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_KB);

			StringCbPrintfW (s, sizeof(s), L"1 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"5 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"10 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 10 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"50 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 50 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"100 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"200 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 200 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"500 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_MB);

			StringCbPrintfW (s, sizeof(s), L"1 %s", GetString ("GB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_GB);

			SendMessage (hCboxBufferSize, CB_SETCURSEL, 5, 0);		// Default buffer size


			uint32 driverConfig = ReadDriverConfigurationFlags();
			int isAesHwSupported = is_aes_hw_cpu_supported();

			SetDlgItemTextW (hwndDlg, IDC_HW_AES, (wstring (L" ") + (GetString (isAesHwSupported ? ((driverConfig & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? "UISTR_DISABLED" : "UISTR_YES") : "NOT_APPLICABLE_OR_NOT_AVAILABLE"))).c_str());

			ToHyperlink (hwndDlg, IDC_HW_AES_LABEL_LINK);

			if (isAesHwSupported && (driverConfig & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION))
			{
				Warning ("DISABLED_HW_AES_AFFECTS_PERFORMANCE", hwndDlg);
			}

			SYSTEM_INFO sysInfo;
			GetSystemInfo (&sysInfo);

			size_t nbrThreads = GetEncryptionThreadCount();

			wchar_t nbrThreadsStr [300];
			if (sysInfo.dwNumberOfProcessors < 2)
			{
				StringCbCopyW (nbrThreadsStr, sizeof(nbrThreadsStr), GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE"));
			}
			else if (nbrThreads < 2)
			{
				StringCbCopyW (nbrThreadsStr, sizeof(nbrThreadsStr), GetString ("UISTR_DISABLED"));
			}
			else
			{
				StringCbPrintfW (nbrThreadsStr, sizeof(nbrThreadsStr), GetString ("NUMBER_OF_THREADS"), nbrThreads);
			}

			SetDlgItemTextW (hwndDlg, IDC_PARALLELIZATION, (wstring (L" ") + nbrThreadsStr).c_str());

			ToHyperlink (hwndDlg, IDC_PARALLELIZATION_LABEL_LINK);

			if (nbrThreads < min (sysInfo.dwNumberOfProcessors, GetMaxEncryptionThreadCount())
				&& sysInfo.dwNumberOfProcessors > 1)
			{
				Warning ("LIMITED_THREAD_COUNT_AFFECTS_PERFORMANCE", hwndDlg);
			}

			return 1;
		}
		break;

	case WM_COMMAND:

		switch (lw)
		{
		case IDC_BENCHMARK_SORT_METHOD:

			nIndex = SendMessage (hCboxSortMethod, CB_GETCURSEL, 0, 0);
			if (nIndex != benchmarkSortMethod)
			{
				benchmarkSortMethod = (int) nIndex;
				DisplayBenchmarkResults (hwndDlg);
			}
			return 1;

		case IDC_BENCHMARK_LIST:

			nIndex = SendMessage (hCboxList, CB_GETCURSEL, 0, 0);
			if (nIndex != benchmarkType)
			{
				benchmarkType = (int) nIndex;
				benchmarkTotalItems = 0;
				ResetBenchmarkList (hwndDlg);
			}

			if (benchmarkType == BENCHMARK_TYPE_PRF)
			{
				ShowWindow (GetDlgItem (hwndDlg, IDC_BENCHMARK_BUFFER_SIZE), SW_HIDE);
				ShowWindow (GetDlgItem (hwndDlg, IDT_BUFFER_SIZE), SW_HIDE);
				ShowWindow (GetDlgItem (hwndDlg, IDC_PIM), SW_SHOW);
				ShowWindow (GetDlgItem (hwndDlg, IDT_PIM), SW_SHOW);
				ShowWindow (GetDlgItem (hwndDlg, IDC_BENCHMARK_PREBOOT), SW_SHOW);
			}
			else
			{
				ShowWindow (GetDlgItem (hwndDlg, IDC_BENCHMARK_BUFFER_SIZE), SW_SHOW);
				ShowWindow (GetDlgItem (hwndDlg, IDT_BUFFER_SIZE), SW_SHOW);
				ShowWindow (GetDlgItem (hwndDlg, IDC_PIM), SW_HIDE);
				ShowWindow (GetDlgItem (hwndDlg, IDT_PIM), SW_HIDE);
				ShowWindow (GetDlgItem (hwndDlg, IDC_BENCHMARK_PREBOOT), SW_HIDE);
			}
			return 1;

		case IDC_PERFORM_BENCHMARK:

			if (benchmarkType == BENCHMARK_TYPE_PRF)
			{
				benchmarkPim = GetPim (hwndDlg, IDC_PIM, 0);
				benchmarkPreBoot = GetCheckBox (hwndDlg, IDC_BENCHMARK_PREBOOT);
			}
			else
			{
				nIndex = SendMessage (hCboxBufferSize, CB_GETCURSEL, 0, 0);
				benchmarkBufferSize = (int) SendMessage (hCboxBufferSize, CB_GETITEMDATA, nIndex, 0);
			}

			BenchmarkThreadParam threadParam;
			threadParam.hBenchDlg = hwndDlg;
			threadParam.bStatus = FALSE;

			WaitCursor ();

			ShowWaitDialog (hwndDlg, TRUE, BenchmarkThreadProc, &threadParam);

			NormalCursor ();

			if (threadParam.bStatus == FALSE)
			{
				EndDialog (hwndDlg, IDCLOSE);
			}
			return 1;

		case IDC_HW_AES_LABEL_LINK:

			Applink ("hwacceleration");
			return 1;

		case IDC_PARALLELIZATION_LABEL_LINK:

			Applink ("parallelization");
			return 1;

		case IDCLOSE:
		case IDCANCEL:

			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		}
		return 0;

		break;

	case WM_CLOSE:
		EndDialog (hwndDlg, IDCLOSE);
		return 1;

		break;

	}
	return 0;
}


static BOOL CALLBACK RandomPoolEnrichementDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static unsigned char randPool [RNG_POOL_SIZE];
	static unsigned char lastRandPool [RNG_POOL_SIZE];
	static unsigned char maskRandPool [RNG_POOL_SIZE];
	static BOOL bUseMask = FALSE;
	static DWORD mouseEntropyGathered = 0xFFFFFFFF;
	static DWORD mouseEventsInitialCount = 0;
	/* max value of entropy needed to fill all random pool = 8 * RNG_POOL_SIZE = 2560 bits */
	static const DWORD maxEntropyLevel = RNG_POOL_SIZE * 8;
	static HWND hEntropyBar = NULL;
	static wchar_t outputDispBuffer [RNG_POOL_SIZE * 3 + RANDPOOL_DISPLAY_ROWS + 2];
	static BOOL bDisplayPoolContents = FALSE;
	static BOOL bRandPoolDispAscii = FALSE;
	int hash_algo = RandGetHashFunction();
	int hid;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PRF_ID);
			HCRYPTPROV hRngProv = NULL;

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (lastRandPool, sizeof(lastRandPool));
			VirtualLock (outputDispBuffer, sizeof(outputDispBuffer));
			VirtualLock (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
			VirtualLock (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
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

			LocalizeDialog (hwndDlg, "IDD_RANDOM_POOL_ENRICHMENT");

			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
			for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
			{
				if (!HashIsDeprecated (hid))
					AddComboPair (hComboBox, HashGetName(hid), hid);
			}
			SelectAlgo (hComboBox, &hash_algo);

			SetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS, bDisplayPoolContents);

			SetTimer (hwndDlg, 0xfd, RANDPOOL_DISPLAY_REFRESH_INTERVAL, NULL);
			SendMessage (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			
			hEntropyBar = GetDlgItem (hwndDlg, IDC_ENTROPY_BAR);
			SendMessage (hEntropyBar, PBM_SETRANGE32, 0, maxEntropyLevel);
			SendMessage (hEntropyBar, PBM_SETSTEP, 1, 0);
			SendMessage (hEntropyBar, PBM_SETSTATE, PBST_ERROR, 0);
			return 1;
		}

	case WM_TIMER:
		{
			wchar_t tmp[4];
			unsigned char tmpByte;
			int col, row;
			DWORD mouseEventsCounter;

			RandpeekBytes (hwndDlg, randPool, sizeof (randPool), &mouseEventsCounter);

			ProcessEntropyEstimate (hEntropyBar, &mouseEventsInitialCount, mouseEventsCounter, maxEntropyLevel, &mouseEntropyGathered);

			if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
			{
				outputDispBuffer[0] = 0;

				for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
				{
					for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
					{
						if (bDisplayPoolContents)
						{
							tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];
							StringCbPrintfW (tmp, sizeof(tmp), bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != L'&') ? L" %c " : L" . ") : L"%02X ", tmpByte);
						}
						else if (bUseMask)
						{
							/* use mask to compute a randomized ascii representation */
							tmpByte = (randPool[row * RANDPOOL_DISPLAY_COLUMNS + col] - 
										 lastRandPool[row * RANDPOOL_DISPLAY_COLUMNS + col]) ^ maskRandPool [row * RANDPOOL_DISPLAY_COLUMNS + col];
							tmp[0] = (wchar_t) (((tmpByte >> 4) % 6) + L'*');
							tmp[1] = (wchar_t) (((tmpByte & 0x0F) % 6) + L'*');
							tmp[2] = L' ';
							tmp[3] = 0;
						}
						else
						{
							StringCbCopyW (tmp, sizeof(tmp), L"** ");
						}

						StringCbCatW (outputDispBuffer, sizeof(outputDispBuffer), tmp);
					}
					StringCbCatW (outputDispBuffer, sizeof(outputDispBuffer), L"\n");
				}
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), outputDispBuffer);

				memcpy (lastRandPool, randPool, sizeof(lastRandPool));
			}
			return 1;
		}

	case WM_COMMAND:
		if (lw == IDC_CONTINUE)
			lw = IDOK;

		if (lw == IDOK || lw == IDCLOSE || lw == IDCANCEL)
		{
			goto exit;
		}

		if (lw == IDC_PRF_ID && hw == CBN_SELCHANGE)
		{
			hid = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETCURSEL, 0, 0);
			hash_algo = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETITEMDATA, hid, 0);
			RandSetHashFunction (hash_algo);
			return 1;
		}

		if (lw == IDC_DISPLAY_POOL_CONTENTS)
		{
			if (!(bDisplayPoolContents = GetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS)))
			{
				wchar_t tmp[RNG_POOL_SIZE+1];

				wmemset (tmp, L' ', ARRAYSIZE(tmp));
				tmp [RNG_POOL_SIZE] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);
			}

			return 1;
		}

		return 0;

	case WM_CLOSE:
		{
			wchar_t tmp[RNG_POOL_SIZE+1];
exit:
			KillTimer (hwndDlg, 0xfd);

			burn (randPool, sizeof(randPool));
			burn (lastRandPool, sizeof(lastRandPool));
			burn (outputDispBuffer, sizeof(outputDispBuffer));
			burn (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
			burn (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
			burn (maskRandPool, sizeof(maskRandPool));

			// Attempt to wipe the pool contents in the GUI text area
			wmemset (tmp, L' ', RNG_POOL_SIZE);
			tmp [RNG_POOL_SIZE] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);

			if (msg == WM_COMMAND && lw == IDOK)
				EndDialog (hwndDlg, IDOK);
			else
				EndDialog (hwndDlg, IDCLOSE);

			return 1;
		}
	}
	return 0;
}

/* Randinit is always called before UserEnrichRandomPool, so we don't need
 * the extra Randinit call here since it will always succeed but we keep it
 * for clarity purposes
 */
void UserEnrichRandomPool (HWND hwndDlg)
{
	if ((0 == Randinit()) && !IsRandomPoolEnrichedByUser())
	{
		INT_PTR result = DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_RANDOM_POOL_ENRICHMENT), hwndDlg ? hwndDlg : MainDlg, (DLGPROC) RandomPoolEnrichementDlgProc, (LPARAM) 0);
		SetRandomPoolEnrichedByUserStatus (result == IDOK);
	}
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static unsigned char randPool [RNG_POOL_SIZE];
	static unsigned char lastRandPool [RNG_POOL_SIZE];
	static unsigned char maskRandPool [RNG_POOL_SIZE];
	static BOOL bUseMask = FALSE;
	static DWORD mouseEntropyGathered = 0xFFFFFFFF;
	static DWORD mouseEventsInitialCount = 0;
	/* max value of entropy needed to fill all random pool = 8 * RNG_POOL_SIZE = 2560 bits */
	static const DWORD maxEntropyLevel = RNG_POOL_SIZE * 8;
	static HWND hEntropyBar = NULL;
	static wchar_t outputDispBuffer [RNG_POOL_SIZE * 3 + RANDPOOL_DISPLAY_ROWS + 2];
	static BOOL bDisplayPoolContents = FALSE;
	static BOOL bRandPoolDispAscii = FALSE;
	int hash_algo = RandGetHashFunction();
	int hid;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PRF_ID);
			HCRYPTPROV hRngProv = NULL;

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (lastRandPool, sizeof(lastRandPool));
			VirtualLock (outputDispBuffer, sizeof(outputDispBuffer));
			VirtualLock (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
			VirtualLock (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
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

			LocalizeDialog (hwndDlg, "IDD_KEYFILE_GENERATOR");

			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
			for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
			{
				if (!HashIsDeprecated (hid))
					AddComboPair (hComboBox, HashGetName(hid), hid);
			}
			SelectAlgo (hComboBox, &hash_algo);

			SetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS, bDisplayPoolContents);
			hEntropyBar = GetDlgItem (hwndDlg, IDC_ENTROPY_BAR);
			SendMessage (hEntropyBar, PBM_SETRANGE32, 0, maxEntropyLevel);
			SendMessage (hEntropyBar, PBM_SETSTEP, 1, 0);
			SendMessage (hEntropyBar, PBM_SETSTATE, PBST_ERROR, 0);

#ifndef VOLFORMAT			
			if (Randinit ()) 
			{
				handleError (hwndDlg, (CryptoAPILastError == ERROR_SUCCESS)? ERR_RAND_INIT_FAILED : ERR_CAPI_INIT_FAILED, SRC_POS);
				EndDialog (hwndDlg, IDCLOSE);
			}
#endif
			SetTimer (hwndDlg, 0xfd, RANDPOOL_DISPLAY_REFRESH_INTERVAL, NULL);
			SendMessage (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			// 9-digit limit for the number of keyfiles (more than enough!)
			SendMessage  (GetDlgItem (hwndDlg, IDC_NUMBER_KEYFILES), EM_SETLIMITTEXT, (WPARAM) 9, 0);
			SetWindowText(GetDlgItem (hwndDlg, IDC_NUMBER_KEYFILES), L"1");
			// maximum keyfile size is 1048576, so limit the edit control to 7 characters
			SendMessage  (GetDlgItem (hwndDlg, IDC_KEYFILES_SIZE), EM_SETLIMITTEXT, (WPARAM) 7, 0);
			SetWindowText(GetDlgItem (hwndDlg, IDC_KEYFILES_SIZE), L"64");
			// set the maximum length of the keyfile base name to (TC_MAX_PATH - 1)
			SendMessage (GetDlgItem (hwndDlg, IDC_KEYFILES_BASE_NAME), EM_SETLIMITTEXT, (WPARAM) (TC_MAX_PATH - 1), 0);
			return 1;
		}

	case WM_TIMER:
		{
			wchar_t tmp[4];
			unsigned char tmpByte;
			int col, row;
			DWORD mouseEventsCounter;

			RandpeekBytes (hwndDlg, randPool, sizeof (randPool), &mouseEventsCounter);

			ProcessEntropyEstimate (hEntropyBar, &mouseEventsInitialCount, mouseEventsCounter, maxEntropyLevel, &mouseEntropyGathered);

			if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
			{
				outputDispBuffer[0] = 0;

				for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
				{
					for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
					{
						if (bDisplayPoolContents)
						{
							tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];
							StringCbPrintfW (tmp, sizeof(tmp), bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != L'&') ? L" %c " : L" . ") : L"%02X ", tmpByte);
						}
						else if (bUseMask)
						{
							/* use mask to compute a randomized ASCII representation */
							tmpByte = (randPool[row * RANDPOOL_DISPLAY_COLUMNS + col] - 
										 lastRandPool[row * RANDPOOL_DISPLAY_COLUMNS + col]) ^ maskRandPool [row * RANDPOOL_DISPLAY_COLUMNS + col];
							tmp[0] = (wchar_t) (((tmpByte >> 4) % 6) + L'*');
							tmp[1] = (wchar_t) (((tmpByte & 0x0F) % 6) + L'*');
							tmp[2] = L' ';
							tmp[3] = 0;
						}
						else
						{
							StringCbCopyW (tmp, sizeof(tmp), L"** ");
						}

						StringCbCatW (outputDispBuffer, sizeof(outputDispBuffer), tmp);
					}
					StringCbCatW (outputDispBuffer, sizeof(outputDispBuffer), L"\n");
				}
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), outputDispBuffer);

				memcpy (lastRandPool, randPool, sizeof(lastRandPool));
			}
			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			goto exit;
		}

		if (lw == IDC_PRF_ID && hw == CBN_SELCHANGE)
		{
			hid = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETCURSEL, 0, 0);
			hash_algo = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PRF_ID), CB_GETITEMDATA, hid, 0);
			RandSetHashFunction (hash_algo);
			return 1;
		}

		if (lw == IDC_DISPLAY_POOL_CONTENTS)
		{
			if (!(bDisplayPoolContents = GetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS)))
			{
				wchar_t tmp[RNG_POOL_SIZE+1];

				wmemset (tmp, L' ', ARRAYSIZE(tmp));
				tmp [RNG_POOL_SIZE] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);
			}
			return 1;
		}

		if (lw == IDC_KEYFILES_RANDOM_SIZE)
		{
			EnableWindow(GetDlgItem (hwndDlg, IDC_KEYFILES_SIZE), !GetCheckBox (hwndDlg, IDC_KEYFILES_RANDOM_SIZE));
		}

		if (lw == IDC_GENERATE_AND_SAVE_KEYFILE)
		{
			wchar_t szNumber[16] = {0};
			wchar_t szFileBaseName[TC_MAX_PATH];
			wchar_t szDirName[TC_MAX_PATH];
			wchar_t szFileName [2*TC_MAX_PATH + 16];
			unsigned char *keyfile = NULL;
			int fhKeyfile = -1, status;
			long keyfilesCount = 0, keyfilesSize = 0, i;
			wchar_t* fileExtensionPtr = 0;
			wchar_t szSuffix[32];
			BOOL bRandomSize = GetCheckBox (hwndDlg, IDC_KEYFILES_RANDOM_SIZE);

			if (!GetWindowText(GetDlgItem (hwndDlg, IDC_NUMBER_KEYFILES), szNumber, ARRAYSIZE(szNumber)))
				szNumber[0] = 0;

			keyfilesCount = wcstoul(szNumber, NULL, 0);
			if (keyfilesCount <= 0 || keyfilesCount == LONG_MAX)
			{
				Warning("KEYFILE_INCORRECT_NUMBER", hwndDlg);
				SendMessage(hwndDlg, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hwndDlg, IDC_NUMBER_KEYFILES), TRUE);
				return 1;
			}

			if (!bRandomSize)
			{
				if (!GetWindowText(GetDlgItem (hwndDlg, IDC_KEYFILES_SIZE), szNumber, ARRAYSIZE(szNumber)))
					szNumber[0] = 0;

				keyfilesSize = wcstoul(szNumber, NULL, 0);
				if (keyfilesSize < 64 || keyfilesSize > 1024*1024)
				{
					Warning("KEYFILE_INCORRECT_SIZE", hwndDlg);
					SendMessage(hwndDlg, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hwndDlg, IDC_KEYFILES_SIZE), TRUE);
					return 1;
				}
			}

			if (!GetWindowText(GetDlgItem (hwndDlg, IDC_KEYFILES_BASE_NAME), szFileBaseName, TC_MAX_PATH))
				szFileBaseName[0] = 0;

			// Trim trailing space
			if (TrimWhiteSpace(szFileBaseName) == 0)
			{
				Warning("KEYFILE_EMPTY_BASE_NAME", hwndDlg);
				SendMessage(hwndDlg, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hwndDlg, IDC_KEYFILES_BASE_NAME), TRUE);
				return 1;
			}

			if (!IsValidFileName(szFileBaseName))
			{
				Warning("KEYFILE_INVALID_BASE_NAME", hwndDlg);
				SendMessage(hwndDlg, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hwndDlg, IDC_KEYFILES_BASE_NAME), TRUE);
				return 1;
			}

			fileExtensionPtr = wcsrchr(szFileBaseName, L'.');

			/* Select directory */
			if (!BrowseDirectories (hwndDlg, "SELECT_KEYFILE_GENERATION_DIRECTORY", szDirName))
				return 1;

			if (szDirName[wcslen(szDirName) - 1] != L'\\' && szDirName[wcslen(szDirName) - 1] != L'/')
				StringCbCat(szDirName, sizeof(szDirName), L"\\");

			WaitCursor();

			keyfile = (unsigned char*) TCalloc( bRandomSize? KEYFILE_MAX_READ_LEN : keyfilesSize );

			for (i= 0; i < keyfilesCount; i++)
			{
				StringCbCopyW(szFileName, sizeof(szFileName), szDirName);
				
				if (i > 0)
				{
					StringCbPrintfW(szSuffix, sizeof(szSuffix), L"_%d", i);
					// Append the counter to the name
					if (fileExtensionPtr)
					{
						StringCchCatN(szFileName, ARRAYSIZE(szFileName), szFileBaseName, (size_t) (fileExtensionPtr - szFileBaseName));
						StringCbCat(szFileName, sizeof(szFileName), szSuffix);
						StringCbCat(szFileName, sizeof(szFileName), fileExtensionPtr);
					}
					else
					{
						StringCbCat(szFileName, sizeof(szFileName), szFileBaseName);
						StringCbCat(szFileName, sizeof(szFileName), szSuffix);
					}
				}
				else
					StringCbCat(szFileName, sizeof(szFileName), szFileBaseName);

				// check if the file exists
				if ((fhKeyfile = _wopen(szFileName, _O_RDONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) != -1)
				{
					WCHAR s[4*TC_MAX_PATH] = {0};

					_close (fhKeyfile);

					StringCbPrintfW (s, sizeof(s), GetString ("KEYFILE_ALREADY_EXISTS"), szFileName);
					status = AskWarnNoYesString (s, hwndDlg);
					if (status == IDNO)
					{
						TCfree(keyfile);
						NormalCursor();
						return 1;
					}
				}

				/* Conceive the file */
				if ((fhKeyfile = _wopen(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
				{
					TCfree(keyfile);
					NormalCursor();
					handleWin32Error (hwndDlg, SRC_POS);
					return 1;
				}

				if (bRandomSize)
				{
					/* Generate a random size */
					if (!RandgetBytes (hwndDlg, (unsigned char*) &keyfilesSize, sizeof(keyfilesSize), FALSE))
					{
						_close (fhKeyfile);
						DeleteFile (szFileName);
						TCfree(keyfile);
						NormalCursor();
						return 1;
					}
					
					/* since keyfilesSize < 1024 * 1024, we mask with 0x000FFFFF */
					keyfilesSize = (long) (((unsigned long) keyfilesSize) & 0x000FFFFF);

					keyfilesSize %= ((KEYFILE_MAX_READ_LEN - 64) + 1);
					keyfilesSize += 64;
				}

				/* Generate the keyfile */ 				
				if (!RandgetBytesFull (hwndDlg, keyfile, keyfilesSize, TRUE, TRUE))
				{
					_close (fhKeyfile);
					DeleteFile (szFileName);
					TCfree(keyfile);
					NormalCursor();
					return 1;
				}				

				/* Write the keyfile */
				status = _write (fhKeyfile, keyfile, keyfilesSize);
				burn (keyfile, keyfilesSize);
				_close (fhKeyfile);

				if (status == -1)
				{
					TCfree(keyfile);
					NormalCursor();
					handleWin32Error (hwndDlg, SRC_POS);
					return 1;
				}				
			}

			TCfree(keyfile);
			NormalCursor();

			Info("KEYFILE_CREATED", hwndDlg);

			return 1;
		}
		return 0;

	case WM_CLOSE:
		{
			wchar_t tmp[RNG_POOL_SIZE+1];
exit:
			WaitCursor();
			KillTimer (hwndDlg, 0xfd);

#ifndef VOLFORMAT			
			RandStop (FALSE);
#endif
			/* Cleanup */

			burn (randPool, sizeof(randPool));
			burn (lastRandPool, sizeof(lastRandPool));
			burn (outputDispBuffer, sizeof(outputDispBuffer));
			burn (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
			burn (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
			burn (maskRandPool, sizeof(maskRandPool));

			// Attempt to wipe the pool contents in the GUI text area
			wmemset (tmp, L' ', RNG_POOL_SIZE);
			tmp [RNG_POOL_SIZE] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);

			EndDialog (hwndDlg, IDCLOSE);
			NormalCursor ();
			return 1;
		}
	}
	return 0;
}



/* Except in response to the WM_INITDIALOG message, the dialog box procedure
should return nonzero if it processes the message, and zero if it does
not. - see DialogProc */
BOOL CALLBACK
CipherTestDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static int idTestCipher = -1;		/* Currently selected cipher for the test vector facility (none = -1). */
	static BOOL bXTSTestEnabled = FALSE;

	PCRYPTO_INFO ci;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			int ea;
			wchar_t buf[100];

			LocalizeDialog (hwndDlg, "IDD_CIPHER_TEST_DLG");

			SendMessage(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), WM_SETFONT, (WPARAM)hBoldFont, MAKELPARAM(TRUE,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_KEY), EM_LIMITTEXT, 128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_KEY), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), EM_LIMITTEXT,64,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), EM_LIMITTEXT,64,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), EM_LIMITTEXT, 128,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SendMessage(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), EM_LIMITTEXT,32,0);
			SendMessage(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), WM_SETFONT, (WPARAM)hFixedDigitFont, MAKELPARAM(1,0));
			SetCheckBox (hwndDlg, IDC_XTS_MODE_ENABLED, bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);

			if (idTestCipher == -1)
				idTestCipher = (int) lParam;

			SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_RESETCONTENT, 0, 0);
			for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
			{
				if (EAGetCipherCount (ea) == 1 && EAIsFormatEnabled (ea))
					AddComboPair (GetDlgItem (hwndDlg, IDC_CIPHER), EAGetName (buf, ea, 1), EAGetFirstCipher (ea));
			}

			ResetCipherTest(hwndDlg, idTestCipher);

			SelectAlgo (GetDlgItem (hwndDlg, IDC_CIPHER), &idTestCipher);

			return 1;
		}

	case WM_COMMAND:

		if (hw == CBN_SELCHANGE && lw == IDC_CIPHER)
		{
			idTestCipher = (int) SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_CIPHER), CB_GETCURSEL, 0, 0), 0);
			ResetCipherTest(hwndDlg, idTestCipher);
			SendMessage (hwndDlg, WM_INITDIALOG, 0, 0);
			return 1;
		}

		if (hw == CBN_SELCHANGE && lw == IDC_KEY_SIZE)
		{
			// NOP
			return 1;
		}

		if (lw == IDC_RESET)
		{
			ResetCipherTest(hwndDlg, idTestCipher);

			return 1;
		}

		if (lw == IDC_AUTO)
		{
			WaitCursor ();
			if (!AutoTestAlgorithms())
			{
				ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_SHOWNORMAL);
				SetWindowTextW(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), GetString ("TESTS_FAILED"));
			} 
			else
			{
				ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_SHOWNORMAL);
				SetWindowTextW(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), GetString ("TESTS_PASSED"));
				ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_SHOWNORMAL);
			}
			NormalCursor ();

			return 1;

		}

		if (lw == IDC_XTS_MODE_ENABLED)
		{
			bXTSTestEnabled = GetCheckBox (hwndDlg, IDC_XTS_MODE_ENABLED);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_SECONDARY_KEY), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_BLOCK_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDT_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			EnableWindow (GetDlgItem (hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), bXTSTestEnabled);
			if (bXTSTestEnabled)
				SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		}

		if (lw == IDOK || lw == IDC_ENCRYPT || lw == IDC_DECRYPT)
		{
			CRYPTOPP_ALIGN_DATA(16) char key[128+1], inputtext[128+1], secondaryKey[64+1], dataUnitNo[16+1];
			wchar_t szTmp[128+1];
			int ks, pt, n, tlen, blockNo = 0;
			BOOL bEncrypt;

			ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_HIDE);

			ks = (int) SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_GETCURSEL, 0,0);
			ks = (int) SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_GETITEMDATA, ks,0);
			pt = (int) SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_GETITEMDATA, 0,0);

			bEncrypt = lw == IDC_ENCRYPT;

			memset(key,0,sizeof(key));
			memset(szTmp,0,sizeof(szTmp));
			n = GetWindowText(GetDlgItem(hwndDlg, IDC_KEY), szTmp, ARRAYSIZE(szTmp));
			if (n != ks * 2)
			{
				Warning ("TEST_KEY_SIZE", hwndDlg);
				return 1;
			}

			for (n = 0; n < ks; n ++)
			{
				wchar_t szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = wcstol(szTmp2, &ptr, 16);

				key[n] = (char) x;
			}

			memset(inputtext, 0, sizeof(inputtext));
			memset(secondaryKey, 0, sizeof(secondaryKey));
			memset(dataUnitNo, 0, sizeof(dataUnitNo));
			memset(szTmp, 0, sizeof(szTmp));

			if (bEncrypt)
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), szTmp, ARRAYSIZE(szTmp));
			}
			else
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), szTmp, ARRAYSIZE(szTmp));
			}

			if (n != pt * 2)
			{
				if (bEncrypt)
				{
					Warning ("TEST_PLAINTEXT_SIZE", hwndDlg);
					return 1;
				}
				else
				{
					Warning  ("TEST_CIPHERTEXT_SIZE", hwndDlg);
					return 1;
				}
			}

			for (n = 0; n < pt; n ++)
			{
				wchar_t szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = wcstol(szTmp2, &ptr, 16);

				inputtext[n] = (char) x;
			}
			
			// XTS
			if (bXTSTestEnabled)
			{
				// Secondary key

				if (GetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), szTmp, ARRAYSIZE(szTmp)) != 64)
				{
					Warning ("TEST_INCORRECT_SECONDARY_KEY_SIZE", hwndDlg);
					return 1;
				}

				for (n = 0; n < 64; n ++)
				{
					wchar_t szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = wcstol(szTmp2, &ptr, 16);

					secondaryKey[n] = (char) x;
				}

				// Data unit number

				tlen = GetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), szTmp, ARRAYSIZE(szTmp));

				if (tlen > 16 || tlen < 1)
				{
					Warning ("TEST_INCORRECT_TEST_DATA_UNIT_SIZE", hwndDlg);
					return 1;
				}

				LeftPadString (szTmp, tlen, 16, L'0');

				for (n = 0; n < 16; n ++)
				{
					wchar_t szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = wcstol(szTmp2, &ptr, 16);

					dataUnitNo[n] = (char) x;
				}

				// Block number

				blockNo = (int) SendMessage (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_GETITEMDATA, SendMessage (GetDlgItem (hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_GETCURSEL, 0, 0), 0);
			}	// if (bXTSTestEnabled)

			
			/* Perform the actual tests */

			if (ks != CB_ERR && pt != CB_ERR) 
			{
				char tmp[128];
				int tmpRetVal;

				/* Copy the plain/ciphertext */
				memcpy(tmp,inputtext, pt);

				if (bXTSTestEnabled)
				{
					UINT64_STRUCT structDataUnitNo;

					/* XTS mode */

					ci = crypto_open ();
					if (!ci)
						return 1;

					ci->mode = XTS;

					for (ci->ea = EAGetFirst (); ci->ea != 0 ; ci->ea = EAGetNext (ci->ea))
						if (EAGetCipherCount (ci->ea) == 1 && EAGetFirstCipher (ci->ea) == idTestCipher)
							break;

					if ((tmpRetVal = EAInit (ci->ea, (unsigned char *) key, ci->ks)) != ERR_SUCCESS)
					{
						handleError (hwndDlg, tmpRetVal, SRC_POS);
						crypto_close (ci);
						return 1;
					}

					memcpy (&ci->k2, secondaryKey, sizeof (secondaryKey));
					if (!EAInitMode (ci))
					{
						crypto_close (ci);
						return 1;
					}

					structDataUnitNo.Value = BE64(((unsigned __int64 *)dataUnitNo)[0]);

					if (bEncrypt)
						EncryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);
					else
						DecryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);

					crypto_close (ci);
				}
				else
				{

					CipherInit2(idTestCipher, key, ks_tmp, ks);

					if (bEncrypt)
					{
						EncipherBlock(idTestCipher, tmp, ks_tmp);
					}
					else
					{
						DecipherBlock(idTestCipher, tmp, ks_tmp);
					}

				}
				*szTmp = 0;

				for (n = 0; n < pt; n ++)
				{
					wchar_t szTmp2[3];
					StringCbPrintfW(szTmp2, sizeof(szTmp2), L"%02x", (int)((unsigned char)tmp[n]));
					StringCbCatW(szTmp, sizeof(szTmp), szTmp2);
				}

				if (bEncrypt)
					SetWindowText(GetDlgItem(hwndDlg,IDC_CIPHERTEXT), szTmp);
				else
					SetWindowText(GetDlgItem(hwndDlg,IDC_PLAINTEXT), szTmp);
			}

			return 1;
		}

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			idTestCipher = -1;
			EndDialog (hwndDlg, 0);
			return 1;
		}
		break;

	case WM_CLOSE:
		idTestCipher = -1;
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

void 
ResetCipherTest(HWND hwndDlg, int idTestCipher)
{
	int ndx;

	ShowWindow(GetDlgItem(hwndDlg, IDC_TESTS_MESSAGE), SW_HIDE);
	ShowWindow(GetDlgItem(hwndDlg, IDC_REDTICK), SW_HIDE);

	EnableWindow(GetDlgItem(hwndDlg,IDC_KEY_SIZE), FALSE);

	/* Setup the keysize and plaintext sizes for the selected cipher */

	SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
	SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_RESETCONTENT, 0,0);
	SendMessage (GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_RESETCONTENT, 0,0);

	ndx = (int) SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) L"64");
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

	for (ndx = 0; ndx < BLOCKS_PER_XTS_DATA_UNIT; ndx++)
	{
		wchar_t tmpStr [16];

		StringCbPrintfW (tmpStr, sizeof(tmpStr), L"%d", ndx);

		ndx = (int) SendMessage (GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_ADDSTRING, 0,(LPARAM) tmpStr);
		SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETITEMDATA, ndx,(LPARAM) ndx);
	}

	SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETCURSEL, 0, 0);

	SetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), L"0000000000000000000000000000000000000000000000000000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), L"0");
	
	SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), L"0000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), L"0000000000000000");

	if (idTestCipher == AES || idTestCipher == SERPENT || idTestCipher == TWOFISH || idTestCipher == CAMELLIA
#if defined(CIPHER_GOST89)
		|| idTestCipher == GOST89
#endif
		|| idTestCipher == KUZNYECHIK
		)
	{
		ndx = (int) SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) L"256");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 32);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);

		SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
		ndx = (int) SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) L"128");
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), L"0000000000000000000000000000000000000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), L"00000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), L"00000000000000000000000000000000");
	}
}

#endif	// #ifndef SETUP


BOOL CALLBACK MultiChoiceDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int nChoiceIDs [MAX_MULTI_CHOICES+1] = { IDC_MULTI_CHOICE_MSG, IDC_CHOICE1, IDC_CHOICE2, IDC_CHOICE3,
		IDC_CHOICE4, IDC_CHOICE5, IDC_CHOICE6, IDC_CHOICE7, IDC_CHOICE8, IDC_CHOICE9, IDC_CHOICE10 };
	int nBaseButtonWidth = 0;
	int nBaseButtonHeight = 0;
	int nActiveChoices = -1;
	int nStr = 0;
	int vertSubOffset, horizSubOffset, vertMsgHeightOffset;
	int vertOffset = 0;
	int nLongestButtonCaptionWidth = 6;
	int nLongestButtonCaptionCharLen = 1;
	int nTextGfxLineHeight = 0;
	int nMainTextLenInChars = 0;
	int newLineSeqCount = 0;
	RECT rec, wrec, wtrec, trec;
	BOOL bResolve;

	WORD lw = LOWORD (wParam);

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			char **pStr = (char **) ((MULTI_CHOICE_DLGPROC_PARAMS *) lParam)->strings;
			char **pStrOrig = pStr;
			wchar_t **pwStr = (wchar_t **) ((MULTI_CHOICE_DLGPROC_PARAMS *) lParam)->strings;
			wchar_t **pwStrOrig = pwStr;

			LocalizeDialog (hwndDlg, NULL);

			SetWindowPos (hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			SetWindowPos (hwndDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

			bResolve = (*pStr == NULL);

			// Style
			if (((MULTI_CHOICE_DLGPROC_PARAMS *) lParam)->bold)
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_MULTI_CHOICE_MSG), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			}

			// Process the strings
			pStr++;
			pwStr++;

			do 
			{
				if (*pStr != 0)
				{
					SetWindowTextW (GetDlgItem(hwndDlg, nChoiceIDs[nStr]), bResolve ? GetString(*pStr) : *pwStr);

					if (nStr > 0)
					{
						nLongestButtonCaptionWidth = max (
							GetTextGfxWidth (GetDlgItem(hwndDlg, IDC_CHOICE1),
											bResolve ? GetString(*pStr) : *pwStr,
											hUserFont),
							nLongestButtonCaptionWidth);

						nLongestButtonCaptionCharLen = max (nLongestButtonCaptionCharLen, 
							(int) wcslen ((const wchar_t *) (bResolve ? GetString(*pStr) : *pwStr)));
					}

					nActiveChoices++;
					pStr++;
					pwStr++;
				}
				else
				{
					ShowWindow(GetDlgItem(hwndDlg, nChoiceIDs[nStr]), SW_HIDE);
				}
				nStr++;

			} while (nStr < MAX_MULTI_CHOICES+1);

			// Length of main message in characters (not bytes)
			nMainTextLenInChars = (int) wcslen ((const wchar_t *) (bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1)));

			if (nMainTextLenInChars > 200 
				&& nMainTextLenInChars / nLongestButtonCaptionCharLen >= 10)
			{
				// As the main text is longer than 200 characters, we will "pad" the widest button caption with 
				// spaces (if it is not wide enough) so as to increase the width of the whole dialog window. 
				// Otherwise, it would look too tall (dialog boxes look better when they are more wide than tall).
				nLongestButtonCaptionWidth = CompensateXDPI (max (
					nLongestButtonCaptionWidth, 
					min (350, nMainTextLenInChars)));
			}

			// Get the window coords
			GetWindowRect(hwndDlg, &wrec);

			// Get the base button size
			GetClientRect(GetDlgItem(hwndDlg, IDC_CHOICE1), &rec);
			nBaseButtonWidth = rec.right + 2;
			nBaseButtonHeight = rec.bottom + 2;

			// Increase in width based on the gfx length of the widest button caption
			horizSubOffset = min (CompensateXDPI (500), max (0, nLongestButtonCaptionWidth + CompensateXDPI (50) - nBaseButtonWidth));

			// Vertical "title bar" offset
			GetClientRect(hwndDlg, &wtrec);
			vertOffset = wrec.bottom - wrec.top - wtrec.bottom - GetSystemMetrics(SM_CYFIXEDFRAME);

			// Height/width of the message text
			GetClientRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &trec);

			// Determine the number of newlines contained in the message text
			{
				int64 offset = -1;

				do
				{
					offset = FindString ((char *) (bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1)), 
						(char *) L"\n",
						nMainTextLenInChars * 2, 
						(int) wcslen (L"\n") * 2, 
						offset + 1);

					newLineSeqCount++;

				} while (offset != -1);
			}

			nTextGfxLineHeight = GetTextGfxHeight (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
								bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1),
								hUserFont);

			vertMsgHeightOffset = ((GetTextGfxWidth (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
								bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1),
								hUserFont) / (trec.right + horizSubOffset) + 1)	* nTextGfxLineHeight) - trec.bottom;

			vertMsgHeightOffset = min (CompensateYDPI (350), vertMsgHeightOffset + newLineSeqCount * nTextGfxLineHeight + (trec.bottom + vertMsgHeightOffset) / 10);	// As reserve, we are adding 10% and the number of lines equal to the number of newlines in the message

			// Reduction in height according to the number of shown buttons
			vertSubOffset = ((MAX_MULTI_CHOICES - nActiveChoices) * nBaseButtonHeight);

			if (horizSubOffset > 0 
				|| vertMsgHeightOffset > 0 
				|| vertOffset > 0)
			{
				// Resize/move each button if necessary
				for (nStr = 1; nStr < MAX_MULTI_CHOICES+1; nStr++)
				{
					GetWindowRect(GetDlgItem(hwndDlg, nChoiceIDs[nStr]), &rec);

					MoveWindow (GetDlgItem(hwndDlg, nChoiceIDs[nStr]),
						rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
						rec.top - wrec.top - vertOffset + vertMsgHeightOffset,
						nBaseButtonWidth + horizSubOffset,
						nBaseButtonHeight,
						TRUE);
				}

				// Resize/move the remaining GUI elements
				GetWindowRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MULTI_CHOICE_MSG),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2 + vertMsgHeightOffset,
					TRUE);

				GetWindowRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR1), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR1), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MC_DLG_HR1),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2,
					TRUE);
				
				GetWindowRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR2), &rec);
				GetClientRect(GetDlgItem(hwndDlg, IDC_MC_DLG_HR2), &trec);
				MoveWindow (GetDlgItem(hwndDlg, IDC_MC_DLG_HR2),
					rec.left - wrec.left - GetSystemMetrics(SM_CXFIXEDFRAME),
					rec.top - wrec.top - vertOffset + vertMsgHeightOffset,
					trec.right + 2 + horizSubOffset,
					trec.bottom + 2,
					TRUE);
			}

			// Resize the window according to number of shown buttons and the longest button caption
			MoveWindow (hwndDlg,
				wrec.left - horizSubOffset / 2,
				wrec.top + vertSubOffset / 2 - vertMsgHeightOffset / 2,
				wrec.right - wrec.left + horizSubOffset,
				wrec.bottom - wrec.top - vertSubOffset + 1 + vertMsgHeightOffset,
				TRUE);

			DisableCloseButton (hwndDlg);

			return 1;
		}

	case WM_COMMAND:

		if (lw == IDCLOSE || lw == IDCANCEL)
		{
			EndDialog (hwndDlg, 0);
			return 1;
		}

		for (nStr = 1; nStr < MAX_MULTI_CHOICES+1; nStr++)
		{
			if (lw == nChoiceIDs[nStr])
			{
				EndDialog (hwndDlg, nStr);
				return 1;
			}
		}
		break;

	case WM_CLOSE:
		// This prevents the window from being closed by pressing Alt-F4 (the Close button is hidden).
		// Note that the OS handles modal MessageBox() dialog windows the same way.
		return 1;
	}

	return 0;
}


BOOL CheckCapsLock (HWND hwnd, BOOL quiet)
{
	if ((GetKeyState(VK_CAPITAL) & 1) != 0)	
	{
		if (!quiet)
		{
			MessageBoxW (hwnd, GetString ("CAPSLOCK_ON"), lpszTitle, MB_ICONEXCLAMATION);
		}
		return TRUE;
	}
	return FALSE;
}


// Checks whether the file extension is not used for executable files or similarly problematic, which often
// causes Windows and antivirus software to interfere with the container.
BOOL CheckFileExtension (wchar_t *fileName)
{
	int i = 0;
	wchar_t *ext = wcsrchr (fileName, L'.');
	static wchar_t *problemFileExt[] = {
		// These are protected by the Windows Resource Protection
		L".asa", L".asp", L".aspx", L".ax", L".bas", L".bat", L".bin", L".cer", L".chm", L".clb", L".cmd", L".cnt", L".cnv",
		L".com", L".cpl", L".cpx", L".crt", L".csh", L".dll", L".drv", L".dtd", L".exe", L".fxp", L".grp", L".h1s", L".hlp",
		L".hta", L".ime", L".inf", L".ins", L".isp", L".its", L".js", L".jse", L".ksh", L".lnk", L".mad", L".maf", L".mag",
		L".mam", L".man", L".maq", L".mar", L".mas", L".mat", L".mau", L".mav", L".maw", L".mda", L".mdb", L".mde", L".mdt",
		L".mdw", L".mdz", L".msc", L".msi", L".msp", L".mst", L".mui", L".nls", L".ocx", L".ops", L".pal", L".pcd", L".pif",
		L".prf", L".prg", L".pst", L".reg", L".scf", L".scr", L".sct", L".shb", L".shs", L".sys", L".tlb", L".tsp", L".url",
		L".vb", L".vbe", L".vbs", L".vsmacros", L".vss", L".vst", L".vsw", L".ws", L".wsc", L".wsf", L".wsh", L".xsd", L".xsl",
		// These additional file extensions are usually watched by antivirus programs
		L".386", L".acm", L".ade", L".adp", L".ani", L".app", L".asd", L".asf", L".asx", L".awx", L".ax", L".boo", L".bz2", L".cdf",
		L".class", L".dhtm", L".dhtml",L".dlo", L".emf", L".eml", L".flt", L".fot", L".gz", L".hlp", L".htm", L".html", L".ini", 
		L".j2k", L".jar", L".jff", L".jif", L".jmh", L".jng", L".jp2", L".jpe", L".jpeg", L".jpg", L".lsp", L".mod", L".nws",
		L".obj", L".olb", L".osd", L".ov1", L".ov2", L".ov3", L".ovl", L".ovl", L".ovr", L".pdr", L".pgm", L".php", L".pkg",
		L".pl", L".png", L".pot", L".pps", L".ppt", L".ps1", L".ps1xml", L".psc1", L".rar", L".rpl", L".rtf", L".sbf", L".script", L".sh", L".sha", L".shtm",
		L".shtml", L".spl", L".swf", L".tar", L".tgz", L".tmp", L".ttf", L".vcs", L".vlm", L".vxd", L".vxo", L".wiz", L".wll", L".wmd",
		L".wmf",	L".wms", L".wmz", L".wpc", L".wsc", L".wsh", L".wwk", L".xhtm", L".xhtml", L".xl", L".xml", L".zip", L".7z", 0};

	if (!ext)
		return FALSE;

	while (problemFileExt[i])
	{
		if (!_wcsicmp (ext, problemFileExt[i++]))
			return TRUE;
	}

	return FALSE;
}

void CorrectFileName (wchar_t* fileName)
{
	/* replace '/' by '\' */
	size_t i, len = wcslen (fileName);
	for (i = 0; i < len; i++)
	{
		if (fileName [i] == L'/')
			fileName [i] = L'\\';
	}
}

void CorrectFileName (std::wstring& fileName)
{
	/* replace '/' by '\' */
	size_t i, len = fileName.length();
	for (i = 0; i < len; i++)
	{
		if (fileName [i] == L'/')
			fileName [i] = L'\\';
	}
}

void CorrectURL (wchar_t* fileName)
{
	/* replace '\' by '/' */
	size_t i, len = wcslen (fileName);
	for (i = 0; i < len; i++)
	{
		if (fileName [i] == L'\\')
			fileName [i] = L'/';
	}
}

void IncreaseWrongPwdRetryCount (int count)
{
	WrongPwdRetryCounter += count;
}


void ResetWrongPwdRetryCount (void)
{
	WrongPwdRetryCounter = 0;
}


BOOL WrongPwdRetryCountOverLimit (void)
{
	return (WrongPwdRetryCounter > TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES);
}

DWORD GetUsedLogicalDrives (void)
{
	DWORD dwUsedDrives = GetLogicalDrives();
	if (!bShowDisconnectedNetworkDrives)
	{
		static DWORD g_dwLastMappedDrives = 0;
		static time_t g_lastCallTime = 0;

		EnterCriticalSection (&csWNetCalls);

		finally_do ({ LeaveCriticalSection (&csWNetCalls); });

		/* update values every 1 minute to reduce CPU consumption */
		if ((time (NULL) - g_lastCallTime) > 60)
		{
			/* detect disconnected mapped network shares and removed
			 * their associated drives from the list
			 */
			WCHAR remotePath[512];
			WCHAR drive[3] = {L'A', L':', 0};
			DWORD dwLen, status;
			g_dwLastMappedDrives = 0;
			for (WCHAR i = 0; i <= MAX_MOUNTED_VOLUME_DRIVE_NUMBER; i++)
			{
				if ((dwUsedDrives & (1 << i)) == 0)
				{
					drive[0] = L'A' + i;
					dwLen = ARRAYSIZE (remotePath);
					status =  WNetGetConnection (drive, remotePath, &dwLen);
					if ((NO_ERROR == status) || (status == ERROR_CONNECTION_UNAVAIL))
					{
						/* this is a mapped network share, mark it as used */
						g_dwLastMappedDrives |= (1 << i);
					}
				}
			}

			g_lastCallTime = time (NULL);
		}

		dwUsedDrives |= g_dwLastMappedDrives;
	}

	return dwUsedDrives;
}


int GetFirstAvailableDrive ()
{
	DWORD dwUsedDrives = GetUsedLogicalDrives();
	int i, drive;

	/* let A: and B: be used as last resort since they can introduce side effects */
	for (i = 2; i < 28; i++)
	{
		drive = (i < 26) ? i : (i - 26);
		if (!(dwUsedDrives & 1 << drive))
			return i;
	}

	return -1;
}


int GetLastAvailableDrive ()
{
	DWORD dwUsedDrives = GetUsedLogicalDrives();
	int i;

	for (i = 25; i >= 0; i--)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}


BOOL IsDriveAvailable (int driveNo)
{
	return (GetUsedLogicalDrives() & (1 << driveNo)) == 0;
}


BOOL IsDeviceMounted (wchar_t *deviceName)
{
	BOOL bResult = FALSE;
	DWORD dwResult;
	HANDLE dev = INVALID_HANDLE_VALUE;

	if ((dev = CreateFile (deviceName,
		GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL)) != INVALID_HANDLE_VALUE)
	{
		bResult = DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL);
		CloseHandle (dev);
	}

	return bResult;
}


int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced)
{
	UNMOUNT_STRUCT unmount;
	DWORD dwResult;
	VOLUME_PROPERTIES_STRUCT prop;
	BOOL bResult;
	WCHAR wszLabel[33] = {0};
	BOOL bDriverSetLabel = FALSE;

	memset (&prop, 0, sizeof(prop));
	prop.driveNo = nDosDriveNo;

	if (	DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL)
		&&	prop.driveNo == nDosDriveNo
		)
	{
		memcpy (wszLabel, prop.wszLabel, sizeof (wszLabel));
		bDriverSetLabel = prop.bDriverSetLabel;
	}
	
	unmount.nDosDriveNo = nDosDriveNo;
	unmount.ignoreOpenFiles = forced;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_VOLUME, &unmount,
			sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		return 1;
	}
	else if ((unmount.nReturnCode == ERR_SUCCESS) && bDriverSetLabel && wszLabel[0])
		UpdateDriveCustomLabel (nDosDriveNo, wszLabel, FALSE);

#ifdef TCMOUNT

	if (unmount.nReturnCode == ERR_SUCCESS
		&& unmount.HiddenVolumeProtectionTriggered
		&& !VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo]
		&& !Silent)
	{
		wchar_t msg[4096];

		VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo] = TRUE;
		StringCbPrintfW (msg, sizeof(msg), GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), nDosDriveNo + L'A');
		SetForegroundWindow (hwndDlg);
		MessageBoxW (hwndDlg, msg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
	}

#endif	// #ifdef TCMOUNT

	return unmount.nReturnCode;
}


void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap)
{
	DEV_BROADCAST_VOLUME dbv;
	DWORD_PTR dwResult;
	LONG eventId = 0;
	int i;

	if (DeviceChangeBroadcastDisabled)
		return;

	if (message == DBT_DEVICEARRIVAL)
		eventId = SHCNE_DRIVEADD;
	else if (message == DBT_DEVICEREMOVECOMPLETE)
		eventId = SHCNE_DRIVEREMOVED;
	else if (IsOSAtLeast (WIN_7) && message == DBT_DEVICEREMOVEPENDING) // Explorer on Windows 7 holds open handles of all drives when 'Computer' is expanded in navigation pane. SHCNE_DRIVEREMOVED must be used as DBT_DEVICEREMOVEPENDING is ignored.
		eventId = SHCNE_DRIVEREMOVED;

	if (driveMap == 0)
		driveMap = (1 << nDosDriveNo);

	if (eventId != 0)
	{
		for (i = 0; i < 26; i++)
		{
			if (driveMap & (1 << i))
			{
				wchar_t root[] = { (wchar_t) i + L'A', L':', L'\\', 0 };
				SHChangeNotify (eventId, SHCNF_PATH, root, NULL);


			}
		}
	}

	dbv.dbcv_size = sizeof (dbv); 
	dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME; 
	dbv.dbcv_reserved = 0;
	dbv.dbcv_unitmask = driveMap;
	dbv.dbcv_flags = 0; 

	UINT timeOut = 1000;

	// SHChangeNotify() works on Vista, so the Explorer does not require WM_DEVICECHANGE
	if (CurrentOSMajor >= 6)
		timeOut = 100;

	IgnoreWmDeviceChange = TRUE;
	SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), SMTO_ABORTIFHUNG, timeOut, &dwResult);

	// Explorer prior Vista sometimes fails to register a new drive
	if (CurrentOSMajor < 6 && message == DBT_DEVICEARRIVAL)
		SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), SMTO_ABORTIFHUNG, 200, &dwResult);

	IgnoreWmDeviceChange = FALSE;
}

static BOOL GetDeviceStorageProperty (HANDLE hDevice, STORAGE_PROPERTY_ID propertyId, DWORD dwDescSize, void* pDesc)
{
	DWORD dwRet = NO_ERROR;

	if (!pDesc)
		return FALSE;

	ZeroMemory (pDesc, dwDescSize);

	// Set the input data structure
	STORAGE_PROPERTY_QUERY storagePropertyQuery;
	ZeroMemory(&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY));
	storagePropertyQuery.PropertyId = propertyId;
	storagePropertyQuery.QueryType = PropertyStandardQuery;

	// Get the necessary output buffer size
	STORAGE_DESCRIPTOR_HEADER descHeader = {0};
	DWORD dwBytesReturned = 0;
	BOOL bRet = ::DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
		&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
		&descHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
		&dwBytesReturned, NULL);
	if (bRet)
	{
		if (dwBytesReturned == sizeof(STORAGE_DESCRIPTOR_HEADER))
		{
			unsigned char* outputBuffer = (unsigned char*) TCalloc (descHeader.Size);
			bRet = ::DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
				&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
				outputBuffer, descHeader.Size,
				&dwBytesReturned, NULL);
			if (bRet)
			{
				if (dwBytesReturned >= dwDescSize)
				{
					memcpy (pDesc, outputBuffer, dwDescSize);
					((STORAGE_DESCRIPTOR_HEADER*)pDesc)->Version = dwDescSize;
					((STORAGE_DESCRIPTOR_HEADER*)pDesc)->Size = dwDescSize;
				}
				else
				{
					bRet = FALSE;
					dwRet = ERROR_UNHANDLED_ERROR;
				}
			}
			else
				dwRet = ::GetLastError();
			TCfree (outputBuffer);
		}
		else
		{
			bRet = FALSE;
			dwRet = ERROR_UNHANDLED_ERROR;
		}
	}
	else
		dwRet = ::GetLastError();

	if (!bRet)
	{
		SetLastError (dwRet);
		return FALSE;
	}
	else
		return TRUE;
}

BOOL GetPhysicalDriveStorageInformation(UINT nDriveNumber, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR* pAlignmentDesc, STORAGE_ADAPTER_DESCRIPTOR* pAdapterDesc)
{
	DWORD dwRet = NO_ERROR;

	if (!pAlignmentDesc || pAdapterDesc)
	{
		SetLastError (ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// Format physical drive path (may be '\\.\PhysicalDrive0', '\\.\PhysicalDrive1' and so on).
	TCHAR strDrivePath[512];
	StringCbPrintf(strDrivePath, sizeof(strDrivePath), _T("\\\\.\\PhysicalDrive%u"), nDriveNumber);

	// Get a handle to physical drive
	HANDLE hDevice = ::CreateFile(strDrivePath, 0, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);

	if(INVALID_HANDLE_VALUE == hDevice)
		return FALSE;

	BOOL bRet = (GetDeviceStorageProperty (hDevice, StorageAccessAlignmentProperty, sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR), pAlignmentDesc)
		|| GetDeviceStorageProperty (hDevice, StorageAdapterProperty, sizeof (STORAGE_ADAPTER_DESCRIPTOR), pAdapterDesc))? TRUE : FALSE;
	dwRet = ::GetLastError();
	::CloseHandle(hDevice);

	if (!bRet)
	{
		SetLastError (dwRet);
		return FALSE;
	}
	else
		return TRUE;
}

#ifndef SETUP

/************************************************************/

// implementation of the generic wait dialog mechanism

static UINT g_wmWaitDlg = ::RegisterWindowMessage(L"VeraCryptWaitDlgMessage");

typedef struct
{
	HWND hwnd;
	void* pArg;
	WaitThreadProc callback;
} WaitThreadParam;

static void _cdecl WaitThread (void* pParam)
{
	WaitThreadParam* pThreadParam = (WaitThreadParam*) pParam;

	pThreadParam->callback(pThreadParam->pArg, pThreadParam->hwnd);

	/* close the wait dialog */
	PostMessage (pThreadParam->hwnd, g_wmWaitDlg, 0, 0);
}

BOOL CALLBACK WaitDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			WaitThreadParam* thParam = (WaitThreadParam*) lParam;

			// set the progress bar type to MARQUEE (indefinite progress)
			HWND hProgress = GetDlgItem (hwndDlg, IDC_WAIT_PROGRESS_BAR);
			if (hProgress)
			{
				SetWindowLongPtrW (hProgress, GWL_STYLE, PBS_MARQUEE | GetWindowLongPtrW (hProgress, GWL_STYLE));
				::SendMessageW(hProgress, PBM_SETMARQUEE, (WPARAM) TRUE, (LPARAM) 0);
			}
			
			thParam->hwnd = hwndDlg; 

			// For now, we don't have system menu is the resources but we leave this code
			// if it is enabled in the future
			HMENU hSysMenu = GetSystemMenu(hwndDlg, FALSE);
			if (hSysMenu)
			{
				//disable the X
				EnableMenuItem(hSysMenu,SC_CLOSE, MF_BYCOMMAND|MF_GRAYED);

				// set icons
				HICON hIcon = (HICON)::LoadImage(hInst, MAKEINTRESOURCE(IDI_TRUECRYPT_ICON), IMAGE_ICON, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
				::SendMessage(hwndDlg, WM_SETICON, TRUE, (LPARAM)hIcon);
				HICON hIconSmall = (HICON)::LoadImage(hInst, MAKEINTRESOURCE(IDI_TRUECRYPT_ICON), IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
				::SendMessage(hwndDlg, WM_SETICON, FALSE, (LPARAM)hIconSmall);   
			} 

			LocalizeDialog (hwndDlg, NULL);
			_beginthread(WaitThread, 0, thParam);
			return 0;
		}

	case WM_COMMAND:

		if (lw == IDOK || lw == IDCANCEL)
			return 1;
		else
			return 0;

	default:
		if (msg == g_wmWaitDlg)
		{
			EndDialog (hwndDlg, IDOK);
			return 1;
		}
		return 0;
	}
}


void BringToForeground(HWND hWnd)
{
	if(!::IsWindow(hWnd)) return;
 
	DWORD lockTimeOut = 0;
	HWND  hCurrWnd = ::GetForegroundWindow();
	DWORD dwThisTID = ::GetCurrentThreadId(),
	      dwCurrTID = ::GetWindowThreadProcessId(hCurrWnd,0);
 
	if (hCurrWnd != hWnd)
	{
		if(dwThisTID != dwCurrTID)
		{
			::AttachThreadInput(dwThisTID, dwCurrTID, TRUE);
	 
			::SystemParametersInfo(SPI_GETFOREGROUNDLOCKTIMEOUT,0,&lockTimeOut,0);
			::SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT,0,0,SPIF_SENDWININICHANGE | SPIF_UPDATEINIFILE);
	 
			::AllowSetForegroundWindow(ASFW_ANY);
		}
	 
		::SetForegroundWindow(hWnd);
	 
		if(dwThisTID != dwCurrTID)
		{
			::SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT,0,(PVOID)lockTimeOut,SPIF_SENDWININICHANGE | SPIF_UPDATEINIFILE);
			::AttachThreadInput(dwThisTID, dwCurrTID, FALSE);
		}
	}

#ifdef TCMOUNT
	if (hWnd == MainDlg)
	{
		SetFocus (hWnd);
		::SendMessage(hWnd, WM_NEXTDLGCTL, (WPARAM) GetDlgItem (hWnd, IDC_DRIVELIST), 1L);
	}
#endif
}

void ShowWaitDialog(HWND hwnd, BOOL bUseHwndAsParent, WaitThreadProc callback, void* pArg)
{
	HWND hParent = (hwnd && bUseHwndAsParent)? hwnd : GetDesktopWindow();
	BOOL bEffectiveHideWaitingDialog = bCmdHideWaitingDialogValid? bCmdHideWaitingDialog : bHideWaitingDialog;
	WaitThreadParam threadParam;
	threadParam.callback = callback;
	threadParam.pArg = pArg;

	if (WaitDialogDisplaying || bEffectiveHideWaitingDialog)
	{
		if (!WaitDialogDisplaying) WaitCursor ();
		callback (pArg, hwnd);
		if (!WaitDialogDisplaying) NormalCursor ();
	}
	else
	{
		BOOL bIsForeground = FALSE;
		HWND creatorWnd = hwnd? hwnd : MainDlg;
		WaitDialogDisplaying = TRUE;
		if (creatorWnd)
		{
			if (GetForegroundWindow () == creatorWnd)
				bIsForeground = TRUE;
			EnableWindow (creatorWnd, FALSE);
		}

		finally_do_arg2 (HWND, creatorWnd, BOOL, bIsForeground, { if (finally_arg) { EnableWindow(finally_arg, TRUE); if (finally_arg2) BringToForeground (finally_arg);}});

		DialogBoxParamW (hInst,
					MAKEINTRESOURCEW (IDD_STATIC_MODAL_WAIT_DLG), hParent,
					(DLGPROC) WaitDlgProc, (LPARAM) &threadParam);

		WaitDialogDisplaying = FALSE;
	}
}

#ifndef SETUP
/************************************************************************/

static BOOL PerformMountIoctl (MOUNT_STRUCT* pmount, LPDWORD pdwResult, BOOL useVolumeID, BYTE volumeID[VOLUME_ID_SIZE])
{
	if (useVolumeID)
	{
		wstring devicePath = FindDeviceByVolumeID (volumeID);
		if (devicePath == L"")
		{
			if (pdwResult)
				*pdwResult = 0;
			SetLastError (ERROR_PATH_NOT_FOUND);
			return FALSE;
		}
		else
		{
			BOOL bDevice = FALSE;
			CreateFullVolumePath (pmount->wszVolume, sizeof(pmount->wszVolume), devicePath.c_str(), &bDevice);
		}
	}
	
	return DeviceIoControl (hDriver, TC_IOCTL_MOUNT_VOLUME, pmount,
			sizeof (MOUNT_STRUCT), pmount, sizeof (MOUNT_STRUCT), pdwResult, NULL);
}

// specific definitions and implementation for support of mount operation 
// in wait dialog mechanism

typedef struct
{
	MOUNT_STRUCT* pmount;
	BOOL useVolumeID;
	BYTE volumeID[VOLUME_ID_SIZE];
	BOOL* pbResult;
	DWORD* pdwResult;
	DWORD dwLastError;
} MountThreadParam;

void CALLBACK MountWaitThreadProc(void* pArg, HWND )
{
	MountThreadParam* pThreadParam = (MountThreadParam*) pArg;

	*(pThreadParam->pbResult) = PerformMountIoctl (pThreadParam->pmount, pThreadParam->pdwResult, pThreadParam->useVolumeID, pThreadParam->volumeID);

	pThreadParam->dwLastError = GetLastError ();
}

/************************************************************************/

// Use only cached passwords if password = NULL
//
// Returns:
// -1 = user aborted mount / error
// 0  = mount failed
// 1  = mount OK
// 2  = mount OK in shared mode
//
// Note that some code calling this relies on the content of the mountOptions struct
// to remain unmodified (don't remove the 'const' without proper revision).

int MountVolume (HWND hwndDlg,
				 int driveNo,
				 wchar_t *volumePath,
				 Password *password,
				 int pkcs5,
				 int pim,
				 BOOL truecryptMode,
				 BOOL cachePassword,
				 BOOL cachePim,
				 BOOL sharedAccess,
				 const MountOptions* const mountOptions,
				 BOOL quiet,
				 BOOL bReportWrongPassword)
{
	MOUNT_STRUCT mount;
	DWORD dwResult, dwLastError = ERROR_SUCCESS;
	BOOL bResult, bDevice;
	wchar_t root[MAX_PATH];
	int favoriteMountOnArrivalRetryCount = 0;
	BOOL useVolumeID = FALSE;
	BYTE volumeID[VOLUME_ID_SIZE] = {0};

#ifdef TCMOUNT
	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (!CheckSysEncMountWithoutPBA (hwndDlg, volumePath, quiet))
			return -1;
	}
#endif

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			Error ("VOL_ALREADY_MOUNTED", hwndDlg);
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
	{
		if (!quiet)
			Error ("DRIVE_LETTER_UNAVAILABLE", hwndDlg);

		return -1;
	}

	// If using cached passwords, check cache status first
	if (password == NULL && IsPasswordCacheEmpty ())
		return 0;

	ZeroMemory (&mount, sizeof (mount));
	mount.bExclusiveAccess = sharedAccess ? FALSE : TRUE;
	mount.SystemFavorite = MountVolumesAsSystemFavorite;
	mount.UseBackupHeader =  mountOptions->UseBackupHeader;
	mount.RecoveryMode = mountOptions->RecoveryMode;
	StringCbCopyW (mount.wszLabel, sizeof (mount.wszLabel), mountOptions->Label);

retry:
	mount.nDosDriveNo = driveNo;
	mount.bCache = cachePassword;
	mount.bCachePim = cachePim;

	mount.bPartitionInInactiveSysEncScope = FALSE;

	if (password != NULL)
		mount.VolumePassword = *password;
	else
		mount.VolumePassword.Length = 0;

	if (!mountOptions->ReadOnly && mountOptions->ProtectHiddenVolume)
	{
		mount.ProtectedHidVolPassword = mountOptions->ProtectedHidVolPassword;
		mount.bProtectHiddenVolume = TRUE;
		mount.ProtectedHidVolPkcs5Prf = mountOptions->ProtectedHidVolPkcs5Prf;
		mount.ProtectedHidVolPim = mountOptions->ProtectedHidVolPim;
	}
	else
		mount.bProtectHiddenVolume = FALSE;

	mount.bMountReadOnly = mountOptions->ReadOnly;
	mount.bMountRemovable = mountOptions->Removable;
	mount.bPreserveTimestamp = mountOptions->PreserveTimestamp;

	mount.bMountManager = TRUE;
	mount.pkcs5_prf = pkcs5;
	mount.bTrueCryptMode = truecryptMode;
	mount.VolumePim = pim;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		mount.bMountManager = FALSE;

	wstring path = volumePath;
	if (path.find (L"\\\\?\\") == 0)
	{
		// Remove \\?\ prefix
		path = path.substr (4);
		StringCchCopyW (volumePath, TC_MAX_PATH, path.c_str());
	}
	
	if (path.find (L"Volume{") == 0 && path.rfind (L"}\\") == path.size() - 2)
	{
		wstring resolvedPath = VolumeGuidPathToDevicePath (path);

		if (!resolvedPath.empty())
			StringCchCopyW (volumePath, TC_MAX_PATH, resolvedPath.c_str());
	}

	if ((path.length () >= 3) && (_wcsnicmp (path.c_str(), L"ID:", 3) == 0))
	{
		std::vector<byte> arr;
		if (	(path.length() == (3 + 2*VOLUME_ID_SIZE)) 
			&& HexWideStringToArray (path.c_str() + 3, arr)
			&& (arr.size() == VOLUME_ID_SIZE)
			)
		{
			useVolumeID = TRUE;
			bDevice = TRUE;
			memcpy (volumeID, &arr[0], VOLUME_ID_SIZE);
		}
		else
		{
			if (!quiet)
				Error ("VOLUME_ID_INVALID", hwndDlg);

			SetLastError (ERROR_INVALID_PARAMETER);
			return -1;
		}
	}
	else
		CreateFullVolumePath (mount.wszVolume, sizeof(mount.wszVolume), volumePath, &bDevice);

	if (!bDevice)
	{
		// put default values
		mount.BytesPerSector = 512;
		mount.BytesPerPhysicalSector = 512;
		mount.MaximumTransferLength = 65536;
		mount.MaximumPhysicalPages = 17;
		mount.AlignmentMask = 0;

		// UNC path
		if (path.find (L"\\\\") == 0)
		{
			StringCbCopyW (mount.wszVolume, sizeof (mount.wszVolume), (L"UNC" + path.substr (1)).c_str());
		}

		if (GetVolumePathName (volumePath, root, ARRAYSIZE (root) - 1))
		{
			DWORD bps, flags, d;
			if (GetDiskFreeSpace (root, &d, &bps, &d, &d))
			{
				mount.BytesPerSector = bps;
				mount.BytesPerPhysicalSector = bps;
			}
			
			if (IsOSAtLeast (WIN_VISTA))
			{
				if (	(wcslen(root) >= 2)
					&&	(root[1] == L':')
					&&	(towupper(root[0]) >= L'A' && towupper(root[0]) <= L'Z')
					)
				{
					wstring drivePath = L"\\\\.\\X:";
					HANDLE dev = INVALID_HANDLE_VALUE;
					VOLUME_DISK_EXTENTS extents = {0};
					DWORD dwResult = 0;
					drivePath[4] = root[0];

					if ((dev = CreateFile (drivePath.c_str(),0, 0, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
					{
						if (DeviceIoControl (dev, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &extents, sizeof(extents), &dwResult, NULL))
						{
							if (extents.NumberOfDiskExtents > 0)
							{
								STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR accessDesc;
								STORAGE_ADAPTER_DESCRIPTOR adapterDesc;

								if (GetPhysicalDriveStorageInformation (extents.Extents[0].DiskNumber, &accessDesc, &adapterDesc))
								{
									if (accessDesc.Size >= sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR))
									{
										mount.BytesPerSector = accessDesc.BytesPerLogicalSector;
										mount.BytesPerPhysicalSector = accessDesc.BytesPerPhysicalSector;
									}

									if (adapterDesc.Size >= sizeof (STORAGE_ADAPTER_DESCRIPTOR))
									{
										mount.MaximumTransferLength = adapterDesc.MaximumTransferLength;
										mount.MaximumPhysicalPages = adapterDesc.MaximumPhysicalPages;
										mount.AlignmentMask = adapterDesc.AlignmentMask;
									}
								}
							}
						}
						CloseHandle (dev);
					}
				}
			}

			// Read-only host filesystem
			if (!mount.bMountReadOnly && GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
				mount.bMountReadOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;
		}
	}

	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (mount.wszVolume == NULL || swscanf_s ((const wchar_t *) mount.wszVolume,
			WIDE("\\Device\\Harddisk%d\\Partition"),
			&mount.nPartitionInInactiveSysEncScopeDriveNo,
			sizeof(mount.nPartitionInInactiveSysEncScopeDriveNo)) != 1)
		{
			if (!quiet)
				Warning ("NO_SYSENC_PARTITION_SELECTED", hwndDlg);
			return -1;
		}

		mount.bPartitionInInactiveSysEncScope = TRUE;
	}

	if (!quiet)
	{
		MountThreadParam mountThreadParam;
		mountThreadParam.pmount = &mount;
		mountThreadParam.useVolumeID = useVolumeID;
		memcpy (mountThreadParam.volumeID, volumeID, VOLUME_ID_SIZE);
		mountThreadParam.pbResult = &bResult;
		mountThreadParam.pdwResult = &dwResult;
		mountThreadParam.dwLastError = ERROR_SUCCESS;

		ShowWaitDialog (hwndDlg, FALSE, MountWaitThreadProc, &mountThreadParam);

		dwLastError  = mountThreadParam.dwLastError;
	}
	else
	{
		bResult = PerformMountIoctl (&mount, &dwResult, useVolumeID, volumeID);

		dwLastError = GetLastError ();
	}

	burn (&mount.VolumePassword, sizeof (mount.VolumePassword));
	burn (&mount.ProtectedHidVolPassword, sizeof (mount.ProtectedHidVolPassword));
	burn (&mount.pkcs5_prf, sizeof (mount.pkcs5_prf));
	burn (&mount.bTrueCryptMode, sizeof (mount.bTrueCryptMode));
	burn (&mount.ProtectedHidVolPkcs5Prf, sizeof (mount.ProtectedHidVolPkcs5Prf));

	SetLastError (dwLastError);
	if (bResult == FALSE)
	{
		// Volume already open by another process
		if (GetLastError () == ERROR_SHARING_VIOLATION)
		{
			if (FavoriteMountOnArrivalInProgress && ++favoriteMountOnArrivalRetryCount < 10)
			{
				Sleep (500);
				goto retry;
			}

			if (mount.bExclusiveAccess == FALSE)
			{
				if (!quiet)
					Error ("FILE_IN_USE_FAILED", hwndDlg);

				return -1;
			}
			else
			{
				if (quiet)
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}

				// Ask user 
				if (IDYES == AskWarnNoYes ("FILE_IN_USE", hwndDlg))
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}
			}

			return -1;
		}

		if (!quiet && (!MultipleMountOperationInProgress || GetLastError() != ERROR_NOT_READY))
			handleWin32Error (hwndDlg, SRC_POS);

		return -1;
	}

	if (mount.nReturnCode != 0)
	{
		if (mount.nReturnCode == ERR_PASSWORD_WRONG)
		{
			// Do not report wrong password, if not instructed to 
			if (bReportWrongPassword)
			{
				IncreaseWrongPwdRetryCount (1);		// We increase the count here only if bReportWrongPassword is TRUE, because "Auto-Mount All Devices" and other callers do it separately

				if (WrongPwdRetryCountOverLimit () 
					&& !mount.UseBackupHeader)
				{
					// Retry using embedded header backup (if any)
					mount.UseBackupHeader = TRUE;
					goto retry;
				}

				if (bDevice && mount.bProtectHiddenVolume)
				{
					int driveNo;

					if (swscanf (volumePath, L"\\Device\\Harddisk%d\\Partition", &driveNo) == 1)
					{
						OPEN_TEST_STRUCT openTestStruct;
						memset (&openTestStruct, 0, sizeof (openTestStruct));

						openTestStruct.bDetectTCBootLoader = TRUE;
						StringCchPrintfW ((wchar_t *) openTestStruct.wszFileName, array_capacity (openTestStruct.wszFileName), L"\\Device\\Harddisk%d\\Partition0", driveNo);

						DWORD dwResult;
						if (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST, &openTestStruct, sizeof (OPEN_TEST_STRUCT), &openTestStruct, sizeof (OPEN_TEST_STRUCT), &dwResult, NULL) && openTestStruct.TCBootLoaderDetected)
							WarningDirect ((GetWrongPasswordErrorMessage (hwndDlg) + L"\n\n" + GetString ("HIDDEN_VOL_PROT_PASSWORD_US_KEYB_LAYOUT")).c_str(), hwndDlg);
						else
							handleError (hwndDlg, mount.nReturnCode, SRC_POS);
					}
				}
				else
					handleError (hwndDlg, mount.nReturnCode, SRC_POS);
			}

			return 0;
		}

		if (!quiet)
			handleError (hwndDlg, mount.nReturnCode, SRC_POS);

		return 0;
	}

	// Mount successful

	if (mount.UseBackupHeader != mountOptions->UseBackupHeader
		&& mount.UseBackupHeader)
	{
		if (bReportWrongPassword && !Silent)
			Warning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK", hwndDlg);
	}
	
	LastMountedVolumeDirty = mount.FilesystemDirty;

	if (mount.FilesystemDirty)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		StringCbPrintfW (msg, sizeof(msg), GetString ("MOUNTED_VOLUME_DIRTY"), mountPoint);

		if (AskWarnYesNoStringTopmost (msg, hwndDlg) == IDYES)
			CheckFilesystem (hwndDlg, driveNo, TRUE);
	}

	if (mount.VolumeMountedReadOnlyAfterAccessDenied
		&& !Silent
		&& !bDevice
		&& !FileHasReadOnlyAttribute (volumePath)
		&& !IsFileOnReadOnlyFilesystem (volumePath))
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		StringCbPrintfW (msg, sizeof(msg), GetString ("MOUNTED_CONTAINER_FORCED_READ_ONLY"), mountPoint);

		WarningDirect (msg, hwndDlg);
	}

	if (mount.VolumeMountedReadOnlyAfterAccessDenied
		&& !Silent
		&& bDevice)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		StringCbPrintfW (msg, sizeof(msg), GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY"), mountPoint);

		WarningDirect (msg, hwndDlg);
	}

	if (mount.VolumeMountedReadOnlyAfterDeviceWriteProtected
		&& !Silent
		&& wcsstr (volumePath, L"\\Device\\Harddisk") == volumePath)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		StringCbPrintfW (msg, sizeof(msg), GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY_WRITE_PROTECTION"), mountPoint);

		WarningDirect (msg, hwndDlg);

		if (CurrentOSMajor >= 6
			&& wcsstr (volumePath, L"\\Device\\HarddiskVolume") != volumePath
			&& AskNoYes ("ASK_REMOVE_DEVICE_WRITE_PROTECTION", hwndDlg) == IDYES)
		{
			RemoveDeviceWriteProtection (hwndDlg, volumePath);
		}
	}

	if (mount.wszLabel[0] && !mount.bDriverSetLabel)
	{
		// try setting the drive label on user-mode using registry
		UpdateDriveCustomLabel (driveNo, mount.wszLabel, TRUE);
	}

	ResetWrongPwdRetryCount ();

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (mount.bExclusiveAccess == FALSE)
		return 2;

	return 1;
}

#endif

typedef struct
{
	int nDosDriveNo;
	BOOL forced;
	int dismountMaxRetries;
	DWORD retryDelay;
	int* presult;
	DWORD dwLastError;
} UnmountThreadParam;

void CALLBACK UnmountWaitThreadProc(void* pArg, HWND hwnd)
{
	UnmountThreadParam* pThreadParam = (UnmountThreadParam*) pArg;
	int dismountMaxRetries = pThreadParam->dismountMaxRetries;
	DWORD retryDelay = pThreadParam->retryDelay;

	do
	{
		*pThreadParam->presult = DriverUnmountVolume (hwnd, pThreadParam->nDosDriveNo, pThreadParam->forced);

		if (*pThreadParam->presult == ERR_FILES_OPEN)
			Sleep (retryDelay);
		else
			break;

	} while (--dismountMaxRetries > 0);

	pThreadParam->dwLastError = GetLastError ();
}

static BOOL UnmountVolumeBase (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount, BOOL ntfsFormatCase)
{
	int result;
	BOOL forced = forceUnmount;
	int dismountMaxRetries = ntfsFormatCase? 5 : UNMOUNT_MAX_AUTO_RETRIES;
	DWORD retryDelay = ntfsFormatCase? 2000: UNMOUNT_AUTO_RETRY_DELAY;
	UnmountThreadParam param;

retry:
	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, nDosDriveNo, 0);

	param.nDosDriveNo = nDosDriveNo;
	param.forced = forced;
	param.dismountMaxRetries = dismountMaxRetries;
	param.retryDelay = retryDelay;
	param.presult = &result;

	if (Silent)
	{
		UnmountWaitThreadProc (&param, hwndDlg);
	}
	else
	{
		ShowWaitDialog (hwndDlg, FALSE, UnmountWaitThreadProc, &param);
	}

	SetLastError (param.dwLastError);

	if (result != 0)
	{
		if (result == ERR_FILES_OPEN && !Silent)
		{
			if (IDYES == AskWarnYesNoTopmost ("UNMOUNT_LOCK_FAILED", hwndDlg))
			{
				forced = TRUE;
				goto retry;
			}

			if (IsOSAtLeast (WIN_7))
			{
				// Undo SHCNE_DRIVEREMOVED
				wchar_t root[] = { (wchar_t) nDosDriveNo + L'A', L':', L'\\', 0 };
				SHChangeNotify (SHCNE_DRIVEADD, SHCNF_PATH, root, NULL);
			}

			return FALSE;
		}

		Error ("UNMOUNT_FAILED", hwndDlg);

		return FALSE;
	}

	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, nDosDriveNo, 0);

	return TRUE;
}

BOOL UnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount)
{
	return UnmountVolumeBase (hwndDlg, nDosDriveNo, forceUnmount, FALSE);
}

BOOL UnmountVolumeAfterFormatExCall (HWND hwndDlg, int nDosDriveNo)
{
	return UnmountVolumeBase (hwndDlg, nDosDriveNo, FALSE, TRUE);
}

BOOL IsPasswordCacheEmpty (void)
{
	DWORD dw;
	return !DeviceIoControl (hDriver, TC_IOCTL_GET_PASSWORD_CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
}

BOOL IsMountedVolumeID (BYTE volumeID[VOLUME_ID_SIZE])
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;

	memset (&mlist, 0, sizeof (mlist));
	if (	!DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
				sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
				NULL) 
		|| (mlist.ulMountedDrives >= (1 << 26))
		)
	{
		return FALSE; 
	}

	if (mlist.ulMountedDrives)
	{
		for (i=0 ; i<26; i++)
		{
			if ((mlist.ulMountedDrives & (1 << i)) && (0 == memcmp (mlist.volumeID[i], volumeID, VOLUME_ID_SIZE)))
				return TRUE;
		}
	}

	return FALSE;
}

BOOL IsMountedVolume (const wchar_t *volname)
{
	if ((wcslen (volname) == (3 + 2*VOLUME_ID_SIZE)) && _wcsnicmp (volname, L"ID:", 3) == 0)
	{
		/* Volume ID specified. Use it for matching mounted volumes. */
		std::vector<byte> arr;
		if (HexWideStringToArray (&volname[3], arr) && (arr.size() == VOLUME_ID_SIZE))
		{
			return IsMountedVolumeID (&arr[0]);
		}
	}
	else
	{
		MOUNT_LIST_STRUCT mlist;
		DWORD dwResult;
		int i;
		wchar_t volume[TC_MAX_PATH*2+16];

		StringCbCopyW (volume, sizeof(volume), volname);

		if (wcsstr (volname, L"\\Device\\") != volname)
			StringCbPrintfW(volume, sizeof(volume), L"\\??\\%s", volname);

		wstring resolvedPath = VolumeGuidPathToDevicePath (volname);
		if (!resolvedPath.empty())
			StringCbCopyW (volume, sizeof (volume), resolvedPath.c_str());

		memset (&mlist, 0, sizeof (mlist));
		if (	!DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
					sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
					NULL) 
			|| (mlist.ulMountedDrives >= (1 << 26))
			)
		{
			return FALSE; 
		}

		if (mlist.ulMountedDrives)
		{
			for (i=0 ; i<26; i++)
			{
				if ((mlist.ulMountedDrives & (1 << i)) 
					&& IsNullTerminateString (mlist.wszVolume[i], TC_MAX_PATH) 
					&& (0 == _wcsicmp ((wchar_t *) mlist.wszVolume[i], volume))
					)
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}


int GetMountedVolumeDriveNo (wchar_t *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	wchar_t volume[TC_MAX_PATH*2+16];

	if (volname == NULL)
		return -1;

	StringCbCopyW (volume, sizeof(volume), volname);

	if (wcsstr (volname, L"\\Device\\") != volname)
		StringCbPrintfW (volume, sizeof(volume), L"\\??\\%s", volname);

	wstring resolvedPath = VolumeGuidPathToDevicePath (volname);
	if (!resolvedPath.empty())
		StringCbCopyW (volume, sizeof (volume), resolvedPath.c_str());

	memset (&mlist, 0, sizeof (mlist));
	if (	!DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
				sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
				NULL) 
		|| (mlist.ulMountedDrives >= (1 << 26))
		)
	{
		return -1; 
	}

	if (mlist.ulMountedDrives)
	{
		for (i=0 ; i<26; i++)
		{
			if ((mlist.ulMountedDrives & (1 << i)) 
				&& IsNullTerminateString (mlist.wszVolume[i], TC_MAX_PATH)
				&& (0 == _wcsicmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
				)
			{
				return i;
			}
		}
	}

	return -1;
}

#endif //!SETUP

BOOL IsAdmin (void)
{
	return IsUserAnAdmin ();
}


BOOL IsBuiltInAdmin ()
{
	HANDLE procToken;
	DWORD size;

	if (!IsAdmin() || !OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &procToken))
		return FALSE;

	finally_do_arg (HANDLE, procToken, { CloseHandle (finally_arg); });

	if (GetTokenInformation (procToken, TokenUser, NULL, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return FALSE;

	TOKEN_USER *tokenUser = (TOKEN_USER *) malloc (size);
	if (!tokenUser)
		return FALSE;

	finally_do_arg (void *, tokenUser, { free (finally_arg); });

	if (!GetTokenInformation (procToken, TokenUser, tokenUser, size, &size))
		return FALSE;

	return IsWellKnownSid (tokenUser->User.Sid, WinAccountAdministratorSid);
}


BOOL IsUacSupported ()
{
	HKEY hkey;
	DWORD value = 1, size = sizeof (DWORD);

	if (!IsOSAtLeast (WIN_VISTA))
		return FALSE;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, L"EnableLUA", 0, 0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
			value = 1;

		RegCloseKey (hkey);
	}

	return value != 0;
}


BOOL ResolveSymbolicLink (const wchar_t *symLinkName, PWSTR targetName, size_t cbTargetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	StringCbCopyW (resolve.symLinkName, sizeof(resolve.symLinkName), symLinkName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_RESOLVED_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	StringCbCopyW (targetName, cbTargetName, resolve.targetName);

	return bResult;
}


BOOL GetPartitionInfo (const wchar_t *deviceName, PPARTITION_INFORMATION rpartInfo)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_PARTITION_INFO_STRUCT dpi;

	memset (&dpi, 0, sizeof(dpi));
	StringCbCopyW ((PWSTR) &dpi.deviceName, sizeof(dpi.deviceName), deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, &dpi,
		sizeof (dpi), &dpi, sizeof (dpi), &dwResult, NULL);

	memcpy (rpartInfo, &dpi.partInfo, sizeof (PARTITION_INFORMATION));
	return bResult;
}


BOOL GetDeviceInfo (const wchar_t *deviceName, DISK_PARTITION_INFO_STRUCT *info)
{
	DWORD dwResult;

	memset (info, 0, sizeof(*info));
	StringCbCopyW ((PWSTR) &info->deviceName, sizeof(info->deviceName), deviceName);

	return DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, info, sizeof (*info), info, sizeof (*info), &dwResult, NULL);
}

#ifndef SETUP
BOOL GetDriveGeometry (const wchar_t *deviceName, PDISK_GEOMETRY_EX diskGeometry)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_GEOMETRY_EX_STRUCT dg;

	memset (&dg, 0, sizeof(dg));
	StringCbCopyW ((PWSTR) &dg.deviceName, sizeof(dg.deviceName), deviceName);

	bResult = DeviceIoControl (hDriver, VC_IOCTL_GET_DRIVE_GEOMETRY_EX, &dg,
		sizeof (dg), &dg, sizeof (dg), &dwResult, NULL);

	if (bResult && (dwResult == sizeof (dg)) && dg.diskGeometry.BytesPerSector)
	{
		ZeroMemory (diskGeometry, sizeof (DISK_GEOMETRY_EX));
		memcpy (&diskGeometry->Geometry, &dg.diskGeometry, sizeof (DISK_GEOMETRY));
		diskGeometry->DiskSize.QuadPart = dg.DiskSize.QuadPart;
		return TRUE;
	}
	else
		return FALSE;
}

BOOL GetPhysicalDriveGeometry (int driveNumber, PDISK_GEOMETRY_EX diskGeometry)
{
	HANDLE hDev;
	BOOL bResult = FALSE;
	TCHAR devicePath[MAX_PATH];

	StringCchPrintfW (devicePath, ARRAYSIZE (devicePath), L"\\\\.\\PhysicalDrive%d", driveNumber);

	if ((hDev = CreateFileW (devicePath, 0, 0, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
	{
		DWORD bytesRead = 0;

		ZeroMemory (diskGeometry, sizeof (DISK_GEOMETRY_EX));

		if (	DeviceIoControl (hDev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, diskGeometry, sizeof (DISK_GEOMETRY_EX), &bytesRead, NULL)
			&& (bytesRead == sizeof (DISK_GEOMETRY_EX))
			&& diskGeometry->Geometry.BytesPerSector)
		{
			bResult = TRUE;
		}

		CloseHandle (hDev);
	}

	return bResult;
}
#endif

// Returns drive letter number assigned to device (-1 if none)
int GetDiskDeviceDriveLetter (PWSTR deviceName)
{
	int i;
	WCHAR link[MAX_PATH];
	WCHAR target[MAX_PATH];
	WCHAR device[MAX_PATH];

	if (!ResolveSymbolicLink (deviceName, device, sizeof(device)))
		StringCchCopyW (device, MAX_PATH, deviceName);

	for (i = 0; i < 26; i++)
	{
		WCHAR drive[] = { (WCHAR) i + L'A', L':', 0 };

		StringCchCopyW (link, MAX_PATH, L"\\DosDevices\\");
		StringCchCatW (link, MAX_PATH, drive);

		if (	ResolveSymbolicLink (link, target, sizeof(target))
			&& (wcscmp (device, target) == 0)
			)
		{
			return i;
		}
	}

	return -1;
}


// WARNING: This function does NOT provide 100% reliable results -- do NOT use it for critical/dangerous operations!
// Return values: 0 - filesystem does not appear empty, 1 - filesystem appears empty, -1 - an error occurred
int FileSystemAppearsEmpty (const wchar_t *devicePath)
{
	float percentFreeSpace = 0.0;
	__int64 occupiedBytes = 0;

	if (GetStatsFreeSpaceOnPartition (devicePath, &percentFreeSpace, &occupiedBytes, TRUE) != -1)
	{
		if (occupiedBytes > BYTES_PER_GB && percentFreeSpace < 99.99	// "percentFreeSpace < 99.99" is needed because an NTFS filesystem larger than several terabytes can have more than 1GB of data in use, even if there are no files stored on it.
			|| percentFreeSpace < 88)		// A 24-MB NTFS filesystem has 11.5% of space in use even if there are no files stored on it.
		{
			return 0;
		}
		else
			return 1;
	}
	else
		return -1;
}


// Returns the free space on the specified partition (volume) in bytes. If the 'occupiedBytes' pointer
// is not NULL, size of occupied space (in bytes) is written to the pointed location. In addition, if the
// 'percent' pointer is not NULL, % of free space is stored in the pointed location. If there's an error,
// returns -1.
__int64 GetStatsFreeSpaceOnPartition (const wchar_t *devicePath, float *percentFree, __int64 *occupiedBytes, BOOL silent)
{
	WCHAR devPath [MAX_PATH];
	int driveLetterNo = -1;
	wchar_t szRootPath[4] = {0, L':', L'\\', 0};
	ULARGE_INTEGER freeSpaceSize;
	ULARGE_INTEGER totalNumberOfBytes;
	ULARGE_INTEGER totalNumberOfFreeBytes;

	StringCbCopyW (devPath, sizeof(devPath), devicePath);

	driveLetterNo = GetDiskDeviceDriveLetter (devPath);
	szRootPath[0] = (wchar_t) driveLetterNo + L'A';


	if (!GetDiskFreeSpaceEx (szRootPath, &freeSpaceSize, &totalNumberOfBytes, &totalNumberOfFreeBytes))
	{
		if (!silent)
		{
			handleWin32Error (MainDlg, SRC_POS);
			Error ("CANNOT_CALC_SPACE", MainDlg);
		}

		return -1;
	}


	if (percentFree != NULL || occupiedBytes != NULL)
	{
		// Determine occupied space and % of free space

		PARTITION_INFORMATION partitionInfo;

		if (!GetPartitionInfo (devicePath, &partitionInfo))
		{
			if (!silent)
			{
				handleWin32Error (MainDlg, SRC_POS);
				Error ("CANT_GET_VOLSIZE", MainDlg);
			}
			return -1;
		}

		if (occupiedBytes != NULL)
			*occupiedBytes = partitionInfo.PartitionLength.QuadPart - freeSpaceSize.QuadPart;

		if (percentFree != NULL)
			*percentFree = (float) ((double) freeSpaceSize.QuadPart / (double) partitionInfo.PartitionLength.QuadPart * 100.0);
	}

	return freeSpaceSize.QuadPart;
}


// Returns -1 if there's an error.
__int64 GetDeviceSize (const wchar_t *devicePath)
{
	PARTITION_INFORMATION partitionInfo;

	if (!GetPartitionInfo (devicePath, &partitionInfo))
		return -1;

	return partitionInfo.PartitionLength.QuadPart;
}


HANDLE DismountDrive (wchar_t *devName, wchar_t *devicePath)
{
	DWORD dwResult;
	HANDLE hVolume;
	BOOL bResult = FALSE;
	int attempt = UNMOUNT_MAX_AUTO_RETRIES;
	int driveLetterNo = -1;
	WCHAR devPath [MAX_PATH];

	StringCbCopyW (devPath, sizeof(devPath), devicePath);
	driveLetterNo = GetDiskDeviceDriveLetter (devPath);


	hVolume = CreateFile (devName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hVolume == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;


	// Try to lock the volume first so that dismount is not forced.
	// If we fail, we will dismount anyway even if it needs to be forced.

	CloseVolumeExplorerWindows (MainDlg, driveLetterNo);

	while (!(bResult = DeviceIoControl (hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL))
		&& attempt > 0)
	{
		Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		attempt--;
	}


	// Try to dismount the volume

	attempt = UNMOUNT_MAX_AUTO_RETRIES;

	while (!(bResult = DeviceIoControl (hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwResult, NULL))
		&& attempt > 0)
	{
		Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		attempt--;
	}

	if (!bResult)
		CloseHandle (hVolume);

	return (bResult ? hVolume : INVALID_HANDLE_VALUE);
}

// Returns -1 if the specified string is not found in the buffer. Otherwise, returns the
// offset of the first occurrence of the string. The string and the buffer may contain zeroes,
// which do NOT terminate them.
int64 FindString (const char *buf, const char *str, int64 bufLen, int64 strLen, int64 startOffset)
{
	if (buf == NULL
		|| str == NULL
		|| strLen > bufLen
		|| bufLen < 1
		|| strLen < 1
		|| startOffset > bufLen - strLen)
	{
		return -1;
	}

	for (int64 i = startOffset; i <= bufLen - strLen; i++)
	{
		if (memcmp (buf + i, str, (size_t) strLen) == 0)
			return i;
	}

	return -1;
}

// Returns TRUE if the file or directory exists (both may be enclosed in quotation marks).
BOOL FileExists (const wchar_t *filePathPtr)
{
	wchar_t filePath [TC_MAX_PATH * 2 + 1];

	// Strip quotation marks (if any)
	if (filePathPtr [0] == L'"')
	{
		StringCbCopyW (filePath, sizeof(filePath), filePathPtr + 1);
	}
	else
	{
		StringCbCopyW (filePath, sizeof(filePath), filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath [wcslen (filePath) - 1] == L'"')
		filePath [wcslen (filePath) - 1] = 0;

    return (_waccess (filePath, 0) != -1);
}

// Searches the file from its end for the LAST occurrence of the string str.
// The string may contain zeroes, which do NOT terminate the string.
// If the string is found, its offset from the start of the file is returned.
// If the string isn't found or if any error occurs, -1 is returned.
__int64 FindStringInFile (const wchar_t *filePath, const char* str, int strLen)
{
	int bufSize = 64 * BYTES_PER_KB;
	char *buffer = (char *) err_malloc (bufSize);
	HANDLE src = NULL;
	DWORD bytesRead;
	BOOL readRetVal;
	__int64 filePos = GetFileSize64 (filePath);
	int bufPos = 0;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL bExit = FALSE;
	int filePosStep;
	__int64 retVal = -1;

	if (filePos <= 0
		|| buffer == NULL
		|| strLen > bufSize
		|| strLen < 1)
	{
	if (buffer)
		free (buffer);
		return -1;
	}

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return -1;
	}

	filePosStep = bufSize - strLen + 1;

	do
	{
		filePos -= filePosStep;

		if (filePos < 0)
		{
			filePos = 0;
			bExit = TRUE;
		}

		seekOffset.QuadPart = filePos;

		if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
			goto fsif_end;

		if ((readRetVal = ReadFile (src, buffer, bufSize, &bytesRead, NULL)) == 0
			|| bytesRead == 0)
			goto fsif_end;

		bufPos = bytesRead - strLen;

		while (bufPos > 0)
		{
			if (memcmp (buffer + bufPos, str, strLen) == 0)
			{
				// String found
				retVal = filePos + bufPos;
				goto fsif_end;
			}
			bufPos--;
		}

	} while (!bExit);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
}

// System CopyFile() copies source file attributes (like FILE_ATTRIBUTE_ENCRYPTED)
// so we need to use our own copy function
BOOL TCCopyFileBase (HANDLE src, HANDLE dst)
{
	__int8 *buffer;
	FILETIME fileTime;
	DWORD bytesRead, bytesWritten;
	BOOL res;

	buffer = (char *) malloc (64 * 1024);
	if (!buffer)
	{
		CloseHandle (src);
		CloseHandle (dst);
		return FALSE;
	}

	while (res = ReadFile (src, buffer, 64 * 1024, &bytesRead, NULL))
	{
		if (bytesRead == 0)
		{
			res = 1;
			break;
		}

		if (!WriteFile (dst, buffer, bytesRead, &bytesWritten, NULL)
			|| bytesRead != bytesWritten)
		{
			res = 0;
			break;
		}
	}

	if (GetFileTime (src, NULL, NULL, &fileTime))
		SetFileTime (dst, NULL, NULL, &fileTime);

	CloseHandle (src);
	CloseHandle (dst);

	free (buffer);
	return res != 0;
}

BOOL TCCopyFile (wchar_t *sourceFileName, wchar_t *destinationFile)
{
	HANDLE src, dst;

	src = CreateFileW (sourceFileName,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
		return FALSE;

	dst = CreateFileW (destinationFile,
		GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, 0, NULL);

	if (dst == INVALID_HANDLE_VALUE)
	{
		CloseHandle (src);
		return FALSE;
	}

	return TCCopyFileBase (src, dst);
}

BOOL DecompressZipToDir (const unsigned char *inputBuffer, DWORD inputLength, const wchar_t *destinationDir, ProgressFn progressFnPtr, HWND hwndDlg)
{
	BOOL res = TRUE;
	zip_error_t zerr;
	zip_int64_t numFiles, i;
	zip_stat_t sb;
	zip_source_t* zsrc = zip_source_buffer_create (inputBuffer, inputLength, 0, &zerr);
	if (!zsrc)
		return FALSE;
	zip_t* z = zip_open_from_source (zsrc, ZIP_CHECKCONS | ZIP_RDONLY, &zerr);
	if (!z)
	{
		zip_source_free (zsrc);
		return FALSE;
	}

	finally_do_arg (zip_t*, z, { zip_close (finally_arg); });

	numFiles = zip_get_num_entries (z, 0);
	if (numFiles <= 0)
		return FALSE;

	for (i = 0; (i < numFiles) && res; i++)
	{
		ZeroMemory (&sb, sizeof (sb));
		if ((0 == zip_stat_index (z, i, 0, &sb)) && (sb.valid & (ZIP_STAT_NAME | ZIP_STAT_SIZE)) && (sb.size > 0))
		{
			std::wstring wname = Utf8StringToWide (sb.name);
			CorrectFileName (wname);

			std::wstring filePath = destinationDir + wname;
			size_t pos = filePath.find_last_of (L"/\\");
			// create the parent directory if it doesn't exist
			if (pos != std::wstring::npos)
			{
				SHCreateDirectoryEx (NULL, filePath.substr (0, pos).c_str(), NULL);
			}

			zip_file_t *f = zip_fopen_index (z, i, 0);
			if (f)
			{
				ByteArray buffer((ByteArray::size_type) sb.size);

				zip_fread (f, buffer.data(), sb.size);
				zip_fclose (f);

				if (progressFnPtr)
					progressFnPtr (hwndDlg, filePath.c_str());

				res = SaveBufferToFile ((char *) buffer.data(), filePath.c_str(), (DWORD) buffer.size(), FALSE, TRUE);
			}			
		}
	}

	return res;
}

// If bAppend is TRUE, the buffer is appended to an existing file. If bAppend is FALSE, any existing file
// is replaced. If an error occurs, the incomplete file is deleted (provided that bAppend is FALSE).
BOOL SaveBufferToFile (const char *inputBuffer, const wchar_t *destinationFile, DWORD inputLength, BOOL bAppend, BOOL bRenameIfFailed)
{
	HANDLE dst;
	DWORD bytesWritten;
	BOOL res = TRUE;
	DWORD dwLastError = 0;

	dst = CreateFile (destinationFile,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, bAppend ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

	dwLastError = GetLastError();
	if (!bAppend && bRenameIfFailed && (dst == INVALID_HANDLE_VALUE) && (GetLastError () == ERROR_SHARING_VIOLATION))
	{
		wchar_t renamedPath[TC_MAX_PATH + 1];
		StringCbCopyW (renamedPath, sizeof(renamedPath), destinationFile);
		StringCbCatW  (renamedPath, sizeof(renamedPath), VC_FILENAME_RENAMED_SUFFIX);

		/* rename the locked file in order to be able to create a new one */
		if (MoveFileEx (destinationFile, renamedPath, MOVEFILE_REPLACE_EXISTING))
		{
			dst = CreateFile (destinationFile,
					GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
			dwLastError = GetLastError();
			if (dst == INVALID_HANDLE_VALUE)
			{
				/* restore the original file name */
				MoveFileEx (renamedPath, destinationFile, MOVEFILE_REPLACE_EXISTING);
			}
			else
			{
				/* delete the renamed file when the machine reboots */
				MoveFileEx (renamedPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
			}
		}
	}

	if (dst == INVALID_HANDLE_VALUE)
	{
		SetLastError (dwLastError);
		handleWin32Error (MainDlg, SRC_POS);
		return FALSE;
	}

	if (bAppend)
		SetFilePointer (dst, 0, NULL, FILE_END);

	if (!WriteFile (dst, inputBuffer, inputLength, &bytesWritten, NULL)
		|| inputLength != bytesWritten)
	{
		res = FALSE;
	}

	if (!res)
	{
		// If CREATE_ALWAYS is used, ERROR_ALREADY_EXISTS is returned after successful overwrite
		// of an existing file (it's not an error)
		if (! (GetLastError() == ERROR_ALREADY_EXISTS && !bAppend) )
			handleWin32Error (MainDlg, SRC_POS);
	}

	CloseHandle (dst);

	if (!res && !bAppend)
		_wremove (destinationFile);

	return res;
}


// Proper flush for Windows systems. Returns TRUE if successful.
BOOL TCFlushFile (FILE *f)
{
	HANDLE hf = (HANDLE) _get_osfhandle (_fileno (f));

	fflush (f);

	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	return FlushFileBuffers (hf) != 0;
}


// Prints a UTF-16 text (note that this involves a real printer, not a screen).
// textByteLen - length of the text in bytes
// title - printed as part of the page header and used as the filename for a temporary file
BOOL PrintHardCopyTextUTF16 (wchar_t *text, wchar_t *title, size_t textByteLen)
{
	wchar_t cl [MAX_PATH*3] = {L"/p \""};
	wchar_t path [MAX_PATH * 2] = { 0 };
	wchar_t filename [MAX_PATH + 1] = { 0 };

	StringCbCopyW (filename, sizeof(filename), title);
	//strcat (filename, ".txt");

	GetTempPath (ARRAYSIZE (path), path);

	if (!FileExists (path))
	{
		StringCbCopyW (path, sizeof(path), GetConfigPath (filename));

		if (wcslen(path) < 2)
			return FALSE;
	}
	else
	{
		StringCbCatW (path, sizeof(path), filename);
	}

	// Write the Unicode signature
	if (!SaveBufferToFile ("\xFF\xFE", path, 2, FALSE, FALSE))
	{
		_wremove (path);
		return FALSE;
	}

	// Write the actual text
	if (!SaveBufferToFile ((char *) text, path, (DWORD) textByteLen, TRUE, FALSE))
	{
		_wremove (path);
		return FALSE;
	}

	StringCbCatW (cl, sizeof(cl), path);
	StringCbCatW (cl, sizeof(cl), L"\"");

	// Get the absolute path for notepad
	if (GetWindowsDirectory(filename, MAX_PATH))
	{
		if (filename[wcslen (filename) - 1] != L'\\')
			StringCbCatW (filename, sizeof(filename), L"\\");
		StringCbCatW(filename, sizeof(filename), PRINT_TOOL);
	}
	else
		StringCbCopyW(filename, sizeof(filename), L"C:\\Windows\\" PRINT_TOOL);

	WaitCursor ();
	ShellExecute (NULL, L"open", filename, cl, NULL, SW_HIDE);
	Sleep (6000);
	NormalCursor();

	_wremove (path);

	return TRUE;
}


BOOL IsNonInstallMode ()
{
	HKEY hkey;
	DWORD dw;

	if (bPortableModeConfirmed)
		return TRUE;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		// The driver is running
		if (DeviceIoControl (hDriver, TC_IOCTL_GET_PORTABLE_MODE_STATUS, NULL, 0, NULL, 0, &dw, 0))
		{
			bPortableModeConfirmed = TRUE;
			return TRUE;
		}
		else
		{
			// This is also returned if we fail to determine the status (it does not mean that portable mode is disproved).
			return FALSE;
		}
	}
	else
	{
		// The tests in this block are necessary because this function is in some cases called before DriverAttach().

		HANDLE hDriverTmp = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hDriverTmp == INVALID_HANDLE_VALUE)
		{
			// The driver was not found in the system path

			wchar_t path[MAX_PATH * 2] = { 0 };

			// We can't use GetConfigPath() here because it would call us back (indirect recursion)
			if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path)))
			{
				StringCbCatW (path, MAX_PATH * 2, L"\\VeraCrypt\\");
				StringCbCatW (path, MAX_PATH * 2, TC_APPD_FILENAME_SYSTEM_ENCRYPTION);

				if (FileExists (path))
				{
					// To maintain consistency and safety, if the system encryption config file exits, we cannot
					// allow portable mode. (This happens e.g. when the pretest fails and the user selects
					// "Last Known Good Configuration" from the Windows boot menu.)

					// However, if UAC elevation is needed, we have to confirm portable mode first (after we are elevated, we won't).
					if (!IsAdmin () && IsUacSupported ())
						return TRUE;

					return FALSE;
				}
			}

			// As the driver was not found in the system path, we can predict that we will run in portable mode
			return TRUE;
		}
		else
			CloseHandle (hDriverTmp);
	}

	// The following test may be unreliable in some cases (e.g. after the user selects restore "Last Known Good
	// Configuration" from the Windows boot menu).
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", 0, KEY_READ | KEY_WOW64_32KEY, &hkey) == ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}
	else
		return TRUE;
}


LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state)
{
	return SendDlgItemMessage (hwndDlg, dlgItem, BM_SETCHECK, state ? BST_CHECKED : BST_UNCHECKED, 0);
}


BOOL GetCheckBox (HWND hwndDlg, int dlgItem)
{
	return IsButtonChecked (GetDlgItem (hwndDlg, dlgItem));
}


// Scroll the listview vertically so that the item with index of topMostVisibleItem is the topmost visible item.
void SetListScrollHPos (HWND hList, int topMostVisibleItem)
{
	int testedPos = 0;

	do
	{
		SendMessage (hList, LVM_SCROLL, 0, testedPos);

	} while (ListView_GetTopIndex (hList) < topMostVisibleItem && ++testedPos < 10000);
}


// Adds or removes TrueCrypt.exe to/from the system startup sequence (with appropriate command line arguments)
void ManageStartupSeq (void)
{
	if (!IsNonInstallMode ())
	{
		wchar_t regk [64];

		GetStartupRegKeyName (regk, sizeof(regk));

		if (bStartOnLogon || bMountDevicesOnLogon || bMountFavoritesOnLogon)
		{
			wchar_t exe[MAX_PATH * 2] = { L'"' };

			GetModuleFileName (NULL, exe + 1, ARRAYSIZE (exe) - 1);

#ifdef VOLFORMAT
			{
				wchar_t *tmp = NULL;

				if (tmp = wcsrchr (exe, L'\\'))
				{
					*tmp = 0;
					StringCbCatW (exe, MAX_PATH * 2, L"\\VeraCrypt.exe");
				}
			}
#endif
			StringCbCatW (exe, MAX_PATH * 2, L"\" /q preferences /a logon");

			if (bMountDevicesOnLogon) StringCbCatW (exe, MAX_PATH * 2, L" /a devices");
			if (bMountFavoritesOnLogon) StringCbCatW (exe, MAX_PATH * 2, L" /a favorites");

			WriteRegistryString (regk, L"VeraCrypt", exe);
		}
		else
			DeleteRegistryValue (regk, L"VeraCrypt");
	}
}


// Adds or removes the VeraCrypt Volume Creation Wizard to/from the system startup sequence
void ManageStartupSeqWiz (BOOL bRemove, const wchar_t *arg)
{
	wchar_t regk [64];

	GetStartupRegKeyName (regk, sizeof(regk));

	if (!bRemove)
	{
		size_t exeSize = (MAX_PATH * 2) + 3 + 20 + wcslen (arg); // enough room for all concatenation operations
		wchar_t* exe = (wchar_t*) calloc(1, exeSize * sizeof (wchar_t));
		exe[0] = L'"';
		GetModuleFileName (NULL, exe + 1, (DWORD) (exeSize - 1));

#ifndef VOLFORMAT
			{
				wchar_t *tmp = NULL;

				if (tmp = wcsrchr (exe, L'\\'))
				{
					*tmp = 0;

					StringCchCatW (exe, exeSize, L"\\VeraCrypt Format.exe");
				}
			}
#endif

		if (wcslen (arg) > 0)
		{
			StringCchCatW (exe, exeSize, L"\" ");
			StringCchCatW (exe, exeSize, arg);
		}

		WriteRegistryString (regk, L"VeraCrypt Format", exe);

		free(exe);
	}
	else
		DeleteRegistryValue (regk, L"VeraCrypt Format");
}


// Delete the last used Windows file selector path for TrueCrypt from the registry
void CleanLastVisitedMRU (void)
{
	WCHAR exeFilename[MAX_PATH];
	WCHAR *strToMatch;

	WCHAR strTmp[4096];
	WCHAR regPath[128];
	WCHAR key[64];
	int id, len;

	GetModuleFileNameW (NULL, exeFilename, sizeof (exeFilename) / sizeof(exeFilename[0]));
	strToMatch = wcsrchr (exeFilename, L'\\') + 1;

	StringCbPrintfW (regPath, sizeof(regPath), L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisited%sMRU", IsOSAtLeast (WIN_VISTA) ? L"Pidl" : L"");

	for (id = (IsOSAtLeast (WIN_VISTA) ? 0 : L'a'); id <= (IsOSAtLeast (WIN_VISTA) ? 1000 : L'z'); id++)
	{
		*strTmp = 0;
		StringCbPrintfW (key, sizeof(key), (IsOSAtLeast (WIN_VISTA) ? L"%d" : L"%c"), id);

		if ((len = ReadRegistryBytes (regPath, key, (char *) strTmp, sizeof (strTmp))) > 0)
		{
			if (_wcsicmp (strTmp, strToMatch) == 0)
			{
				char buf[65536], bufout[sizeof (buf)];

				// Overwrite the entry with zeroes while keeping its original size
				memset (strTmp, 0, len);
				if (!WriteRegistryBytes (regPath, key, (char *) strTmp, len))
					MessageBoxW (NULL, GetString ("CLEAN_WINMRU_FAILED"), lpszTitle, ICON_HAND);

				DeleteRegistryValue (regPath, key);

				// Remove ID from MRUList
				if (IsOSAtLeast (WIN_VISTA))
				{
					int *p = (int *)buf;
					int *pout = (int *)bufout;
					int l;

					l = len = ReadRegistryBytes (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", L"MRUListEx", buf, sizeof (buf));
					while (l > 0)
					{
						l -= sizeof (int);

						if (*p == id)
						{
							p++;
							len -= sizeof (int);
							continue;
						}
						*pout++ = *p++;
					}

					WriteRegistryBytes (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", L"MRUListEx", bufout, len);
				}
				else
				{
					wchar_t *p = (wchar_t*) buf;
					wchar_t *pout = (wchar_t*) bufout;

					ReadRegistryString (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", L"MRUList", L"", (wchar_t*) buf, sizeof (buf));
					while (*p)
					{
						if (*p == id)
						{
							p++;
							continue;
						}
						*pout++ = *p++;
					}
					*pout++ = 0;

					WriteRegistryString (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", L"MRUList", (wchar_t*) bufout);
				}

				break;
			}
		}
	}
}


#ifndef SETUP
void ClearHistory (HWND hwndDlgItem)
{
	ArrowWaitCursor ();

	ClearCombo (hwndDlgItem);
	DumpCombo (hwndDlgItem, TRUE);

	CleanLastVisitedMRU ();

	NormalCursor ();
}
#endif // #ifndef SETUP


LRESULT ListItemAdd (HWND list, int index, const wchar_t *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = (wchar_t*) string;
	li.iItem = index;
	li.iSubItem = 0;
	return ListView_InsertItem (list, &li);
}


LRESULT ListSubItemSet (HWND list, int index, int subIndex, const wchar_t *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = (wchar_t*) string;
	li.iItem = index;
	li.iSubItem = subIndex;
	return ListView_SetItem (list, &li);
}


BOOL GetMountList (MOUNT_LIST_STRUCT *list)
{
	DWORD dwResult;
	MOUNT_LIST_STRUCT localList = {0};

	if ( list && DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &localList,
			sizeof (localList), &localList, sizeof (localList), &dwResult,
			NULL)
			&& (localList.ulMountedDrives < (1 << 26))
		)
	{
		memcpy (list, &localList, sizeof (MOUNT_LIST_STRUCT));
		return TRUE;
	}
	else
		return FALSE;
}


int GetDriverRefCount ()
{
	DWORD dwResult;
	BOOL bResult;
	int refCount;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
		sizeof (refCount), &dwResult, NULL);

	if (bResult)
		return refCount;
	else
		return -1;
}

// Loads a 32-bit integer from the file at the specified file offset. The saved value is assumed to have been
// processed by mputLong(). The result is stored in *result. Returns TRUE if successful (otherwise FALSE).
BOOL LoadInt32 (const wchar_t *filePath, unsigned __int32 *result, __int64 fileOffset)
{
	DWORD bufSize = sizeof(__int32);
	unsigned char *buffer = (unsigned char *) malloc (bufSize);
	unsigned char *bufferPtr = buffer;
	HANDLE src = NULL;
	DWORD bytesRead;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL retVal = FALSE;

	if (buffer == NULL)
		return -1;

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return FALSE;
	}

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
		goto fsif_end;

	if (ReadFile (src, buffer, bufSize, &bytesRead, NULL) == 0
		|| bytesRead != bufSize)
		goto fsif_end;


	retVal = TRUE;

	*result = mgetLong(bufferPtr);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
}

// Loads a 16-bit integer from the file at the specified file offset. The saved value is assumed to have been
// processed by mputWord(). The result is stored in *result. Returns TRUE if successful (otherwise FALSE).
BOOL LoadInt16 (const wchar_t *filePath, int *result, __int64 fileOffset)
{
	DWORD bufSize = sizeof(__int16);
	unsigned char *buffer = (unsigned char *) malloc (bufSize);
	unsigned char *bufferPtr = buffer;
	HANDLE src = NULL;
	DWORD bytesRead;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL retVal = FALSE;

	if (buffer == NULL)
		return -1;

	src = CreateFile (filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
	{
		free (buffer);
		return FALSE;
	}

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (src, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
		goto fsif_end;

	if (ReadFile (src, buffer, bufSize, &bytesRead, NULL) == 0
		|| bytesRead != bufSize)
		goto fsif_end;


	retVal = TRUE;

	*result = mgetWord(bufferPtr);

fsif_end:
	CloseHandle (src);
	free (buffer);

	return retVal;
}

// Returns NULL if there's any error. Although the buffer can contain binary data, it is always null-terminated.
char *LoadFile (const wchar_t *fileName, DWORD *size)
{
	char *buf;
	DWORD fileSize = INVALID_FILE_SIZE;
	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	if ((fileSize = GetFileSize (h, NULL)) == INVALID_FILE_SIZE)
	{
		CloseHandle (h);
		return NULL;
	}

	*size = fileSize;
	buf = (char *) calloc (*size + 1, 1);

	if (buf == NULL)
	{
		CloseHandle (h);
		return NULL;
	}

	if (!ReadFile (h, buf, *size, size, NULL))
	{
		free (buf);
		buf = NULL;
	}

	CloseHandle (h);
	return buf;
}


// Returns NULL if there's any error.
char *LoadFileBlock (const wchar_t *fileName, __int64 fileOffset, DWORD count)
{
	char *buf;
	DWORD bytesRead = 0;
	LARGE_INTEGER seekOffset, seekOffsetNew;
	BOOL bStatus;

	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	seekOffset.QuadPart = fileOffset;

	if (SetFilePointerEx (h, seekOffset, &seekOffsetNew, FILE_BEGIN) == 0)
	{
		CloseHandle (h);
		return NULL;
	}

	buf = (char *) calloc (count, 1);

	if (buf == NULL)
	{
		CloseHandle (h);
		return NULL;
	}

	bStatus = ReadFile (h, buf, count, &bytesRead, NULL);

	CloseHandle (h);

	if (!bStatus || (bytesRead != count))
	{
		free (buf);
		return NULL;
	}

	return buf;
}


// Returns -1 if there is an error, or the size of the file.
__int64 GetFileSize64 (const wchar_t *path)
{
	HANDLE h = CreateFile (path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	LARGE_INTEGER size;
	__int64 retSize = -1;

	if (h)
	{
		if (GetFileSizeEx (h, &size))
		{
			retSize = size.QuadPart;
		}

		CloseHandle (h);
	}

	return retSize;
}


wchar_t *GetModPath (wchar_t *path, int maxSize)
{
	GetModuleFileName (NULL, path, maxSize);
	wchar_t* ptr = wcsrchr (path, L'\\');
	if (ptr)
		ptr[1] = 0;
	return path;
}


wchar_t *GetConfigPath (wchar_t *fileName)
{
	static wchar_t path[MAX_PATH * 2] = { 0 };

	if (IsNonInstallMode ())
	{
		GetModPath (path, ARRAYSIZE (path));
		StringCchCatW (path, (MAX_PATH * 2), fileName);

		return path;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		StringCchCatW (path, (MAX_PATH * 2), L"\\VeraCrypt\\");
		CreateDirectory (path, NULL);
		StringCchCatW (path, (MAX_PATH * 2), fileName);
	}
	else
		path[0] = 0;

	return path;
}


wchar_t *GetProgramConfigPath (wchar_t *fileName)
{
	static wchar_t path[MAX_PATH * 2] = { 0 };

	if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		StringCchCatW (path, (MAX_PATH * 2), L"\\VeraCrypt\\");
		CreateDirectory (path, NULL);
		StringCchCatW (path, (MAX_PATH * 2), fileName);
	}
	else
		path[0] = 0;

	return path;
}


std::wstring GetServiceConfigPath (const wchar_t *fileName, bool useLegacy)
{
	wchar_t sysPath[TC_MAX_PATH];

	if (Is64BitOs() && useLegacy)
	{
		typedef UINT (WINAPI *GetSystemWow64Directory_t) (LPWSTR lpBuffer, UINT uSize);

		GetSystemWow64Directory_t getSystemWow64Directory = (GetSystemWow64Directory_t) GetProcAddress (GetModuleHandle (L"kernel32"), "GetSystemWow64DirectoryW");
		getSystemWow64Directory (sysPath, ARRAYSIZE (sysPath));
	}
	else
		GetSystemDirectory (sysPath, ARRAYSIZE (sysPath));

	return wstring (sysPath) + L"\\" + fileName;
}


// Returns 0 if an error occurs or the drive letter (as an upper-case char) of the system partition (e.g. 'C');
wchar_t GetSystemDriveLetter (void)
{
	wchar_t systemDir [MAX_PATH];

	if (GetSystemDirectory (systemDir, ARRAYSIZE (systemDir)))
		return (wchar_t) (towupper (systemDir [0]));
	else
		return 0;
}


void TaskBarIconDisplayBalloonTooltip (HWND hwnd, wchar_t *headline, wchar_t *text, BOOL warning)
{
	if (nCurrentOS == WIN_2000)
	{
		MessageBoxW (MainDlg, text, headline, warning ? MB_ICONWARNING : MB_ICONINFORMATION);
		return;
	}

	NOTIFYICONDATAW tnid;

	ZeroMemory (&tnid, sizeof (tnid));

	tnid.cbSize = sizeof (tnid);
	tnid.hWnd = hwnd;
	tnid.uID = IDI_TRUECRYPT_ICON;
	//tnid.uVersion = (IsOSAtLeast (WIN_VISTA) ? NOTIFYICON_VERSION_4 : NOTIFYICON_VERSION);

	//Shell_NotifyIconW (NIM_SETVERSION, &tnid);

	tnid.uFlags = NIF_INFO;
	tnid.dwInfoFlags = (warning ? NIIF_WARNING : NIIF_INFO);
	tnid.uTimeout = (IsOSAtLeast (WIN_VISTA) ? 1000 : 5000); // in ms

	StringCbCopyW (tnid.szInfoTitle, sizeof(tnid.szInfoTitle), headline);
	StringCbCopyW (tnid.szInfo, sizeof(tnid.szInfo),text);

	// Display the balloon tooltip quickly twice in a row to avoid the slow and unwanted "fade-in" phase
	Shell_NotifyIconW (NIM_MODIFY, &tnid);
	Shell_NotifyIconW (NIM_MODIFY, &tnid);
}


// Either of the pointers may be NULL
void InfoBalloon (char *headingStringId, char *textStringId, HWND hwnd)
{
	if (Silent)
		return;

	TaskBarIconDisplayBalloonTooltip (hwnd,
		headingStringId == NULL ? L"VeraCrypt" : GetString (headingStringId),
		textStringId == NULL ? L" " : GetString (textStringId),
		FALSE);
}


// Either of the pointers may be NULL
void InfoBalloonDirect (wchar_t *headingString, wchar_t *textString, HWND hwnd)
{
	if (Silent)
		return;

	TaskBarIconDisplayBalloonTooltip (hwnd,
		headingString == NULL ? L"VeraCrypt" : headingString,
		textString == NULL ? L" " : textString,
		FALSE);
}


// Either of the pointers may be NULL
void WarningBalloon (char *headingStringId, char *textStringId, HWND hwnd)
{
	if (Silent)
		return;

	TaskBarIconDisplayBalloonTooltip (hwnd,
		headingStringId == NULL ? L"VeraCrypt" : GetString (headingStringId),
		textStringId == NULL ? L" " : GetString (textStringId),
		TRUE);
}


// Either of the pointers may be NULL
void WarningBalloonDirect (wchar_t *headingString, wchar_t *textString, HWND hwnd)
{
	if (Silent)
		return;

	TaskBarIconDisplayBalloonTooltip (hwnd,
		headingString == NULL ? L"VeraCrypt" : headingString,
		textString == NULL ? L" " : textString,
		TRUE);
}


int Info (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONINFORMATION);
}


int InfoTopMost (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
}


int InfoDirect (const wchar_t *msg, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, msg, lpszTitle, MB_ICONINFORMATION);
}


int Warning (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING);
}


int WarningTopMost (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


int WarningDirect (const wchar_t *warnMsg, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, warnMsg, lpszTitle, MB_ICONWARNING);
}


int Error (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONERROR);
}

int ErrorRetryCancel (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONERROR | MB_RETRYCANCEL);
}

int ErrorTopMost (char *stringId, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


int ErrorDirect (const wchar_t *errMsg, HWND hwnd)
{
	if (Silent) return 0;
	return MessageBoxW (hwnd, errMsg, lpszTitle, MB_ICONERROR);
}


int AskYesNo (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);
}


int AskYesNoString (const wchar_t *str, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, str, lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);
}


int AskYesNoTopmost (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskNoYes (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
}

int AskNoYesString (const wchar_t *string, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, string, lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
}

int AskOkCancel (char *stringId, HWND hwnd)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_OKCANCEL | MB_DEFBUTTON1);
}


int AskWarnYesNo (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
}


int AskWarnYesNoString (const wchar_t *string, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
}


int AskWarnYesNoTopmost (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnYesNoStringTopmost (const wchar_t *string, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnNoYes (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnNoYesString (const wchar_t *string, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnNoYesTopmost (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnOkCancel (char *stringId, HWND hwnd)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON1);
}


int AskWarnCancelOk (char *stringId, HWND hwnd)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2);
}


int AskErrYesNo (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1);
}


int AskErrNoYes (char *stringId, HWND hwnd)
{
	if (Silent) return IDNO;
	return MessageBoxW (hwnd, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
}


// The function accepts two input formats:
// Input format 1: {0, "MESSAGE_STRING_ID", "BUTTON_1_STRING_ID", ... "LAST_BUTTON_STRING_ID", 0};
// Input format 2: {L"", L"Message text", L"Button caption 1", ... L"Last button caption", 0};
// The second format is to be used if any of the strings contains format specification (e.g. %s, %d) or
// in any other cases where a string needs to be resolved before calling this function.
// The returned value is the ordinal number of the choice the user selected (1..MAX_MULTI_CHOICES)
int AskMultiChoice (void *strings[], BOOL bBold, HWND hwnd)
{
	MULTI_CHOICE_DLGPROC_PARAMS params;

	params.strings = &strings[0];
	params.bold = bBold;

	return (int) DialogBoxParamW (hInst,
		MAKEINTRESOURCEW (IDD_MULTI_CHOICE_DLG), hwnd,
		(DLGPROC) MultiChoiceDialogProc, (LPARAM) &params);
}


BOOL ConfigWriteBegin ()
{
	DWORD size;
	if (ConfigFileHandle != NULL)
		return FALSE;

	if (ConfigBuffer == NULL)
		ConfigBuffer = LoadFile (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), &size);

	ConfigFileHandle = _wfopen (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), L"w,ccs=UTF-8");
	if (ConfigFileHandle == NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
		return FALSE;
	}
	XmlWriteHeader (ConfigFileHandle);
	fputws (L"\n\t<configuration>", ConfigFileHandle);

	return TRUE;
}


BOOL ConfigWriteEnd (HWND hwnd)
{
	char *xml = ConfigBuffer;
	char key[128], value[2048];

	if (ConfigFileHandle == NULL) return FALSE;

	// Write unmodified values
	while (xml && (xml = XmlFindElement (xml, "config")))
	{
		XmlGetAttributeText (xml, "key", key, sizeof (key));
		XmlGetNodeText (xml, value, sizeof (value));

		fwprintf (ConfigFileHandle, L"\n\t\t<config key=\"%hs\">%hs</config>", key, value);
		xml++;
	}

	fputws (L"\n\t</configuration>", ConfigFileHandle);
	XmlWriteFooter (ConfigFileHandle);

	TCFlushFile (ConfigFileHandle);

	CheckFileStreamWriteErrors (hwnd, ConfigFileHandle, TC_APPD_FILENAME_CONFIGURATION);

	fclose (ConfigFileHandle);
	ConfigFileHandle = NULL;

	if (ConfigBuffer != NULL)
	{
		DWORD size;
		free (ConfigBuffer);
		ConfigBuffer = LoadFile (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), &size);
	}

	return TRUE;
}


BOOL ConfigWriteString (char *configKey, char *configValue)
{
	char *c;
	if (ConfigFileHandle == NULL)
		return FALSE;

	// Mark previous config value as updated
	if (ConfigBuffer != NULL)
	{
		c = XmlFindElementByAttributeValue (ConfigBuffer, "config", "key", configKey);
		if (c != NULL)
			c[1] = '!';
	}

	return 0 != fwprintf (
		ConfigFileHandle, L"\n\t\t<config key=\"%hs\">%hs</config>",
		configKey, configValue);
}

BOOL ConfigWriteStringW (char *configKey, wchar_t *configValue)
{
	char *c;
	if (ConfigFileHandle == NULL)
		return FALSE;

	// Mark previous config value as updated
	if (ConfigBuffer != NULL)
	{
		c = XmlFindElementByAttributeValue (ConfigBuffer, "config", "key", configKey);
		if (c != NULL)
			c[1] = '!';
	}

	return 0 != fwprintf (
		ConfigFileHandle, L"\n\t\t<config key=\"%hs\">%ls</config>",
		configKey, configValue);
}

BOOL ConfigWriteInt (char *configKey, int configValue)
{
	char val[32];
	StringCbPrintfA (val, sizeof(val), "%d", configValue);
	return ConfigWriteString (configKey, val);
}


static BOOL ConfigRead (char *configKey, char *configValue, int maxValueSize)
{
	DWORD size;
	char *xml;

	if (ConfigBuffer == NULL)
		ConfigBuffer = LoadFile (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), &size);

	xml = ConfigBuffer;
	if (xml != NULL)
	{
		xml = XmlFindElementByAttributeValue (xml, "config", "key", configKey);
		if (xml != NULL)
		{
			XmlGetNodeText (xml, configValue, maxValueSize);
			return TRUE;
		}
	}

	return FALSE;
}


int ConfigReadInt (char *configKey, int defaultValue)
{
	char s[32];

	if (ConfigRead (configKey, s, sizeof (s)))
		return atoi (s);
	else
		return defaultValue;
}


char *ConfigReadString (char *configKey, char *defaultValue, char *str, int maxLen)
{
	if (ConfigRead (configKey, str, maxLen))
		return str;
	else
	{
		StringCbCopyA (str, maxLen, defaultValue);
		return defaultValue;
	}
}

void ConfigReadCompareInt(char *configKey, int defaultValue, int* pOutputValue, BOOL bOnlyCheckModified, BOOL* pbModified)
{
	int intValue = ConfigReadInt (configKey, defaultValue);
	if (pOutputValue)
	{
		if (pbModified && (*pOutputValue != intValue))
			*pbModified = TRUE;
		if (!bOnlyCheckModified)
			*pOutputValue = intValue;
	}
}

void ConfigReadCompareString (char *configKey, char *defaultValue, char *str, int maxLen, BOOL bOnlyCheckModified, BOOL *pbModified)
{
	char *strValue = (char*) malloc (maxLen);
	if (strValue)
	{
		memcpy (strValue, str, maxLen);

		ConfigReadString (configKey, defaultValue, strValue, maxLen);

		if (pbModified && strcmp (str, strValue))
			*pbModified = TRUE;
		if (!bOnlyCheckModified)
			memcpy(str, strValue, maxLen);

		free (strValue);
	}
	else
	{
		/* allocation failed. Suppose that value changed */
		if (pbModified)
			*pbModified = TRUE;
		if (!bOnlyCheckModified)
			ConfigReadString (configKey, defaultValue, str, maxLen);

	}
}

void OpenPageHelp (HWND hwndDlg, int nPage)
{
	int r = (int)ShellExecuteW (NULL, L"open", szHelpFile, NULL, NULL, SW_SHOWNORMAL);

	if (r == ERROR_FILE_NOT_FOUND)
	{
		// Try the secondary help file
		r = (int)ShellExecuteW (NULL, L"open", szHelpFile2, NULL, NULL, SW_SHOWNORMAL);

		if (r == ERROR_FILE_NOT_FOUND)
		{
			// Open local HTML help. It will fallback to online help if not found.
			Applink ("help");
			return;
		}
	}

	if (r == SE_ERR_NOASSOC)
	{
		if (AskYesNo ("HELP_READER_ERROR", MainDlg) == IDYES)
			OpenOnlineHelp ();
	}
}


void OpenOnlineHelp ()
{
	Applink ("onlinehelp");
}


#ifndef SETUP

void RestoreDefaultKeyFilesParam (void)
{
	KeyFileRemoveAll (&FirstKeyFile);
	if (defaultKeyFilesParam.FirstKeyFile != NULL)
	{
		KeyFileCloneAll (defaultKeyFilesParam.FirstKeyFile, &FirstKeyFile);
		KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles;
	}
	else
		KeyFilesEnable = FALSE;
}


BOOL LoadDefaultKeyFilesParam (void)
{
	BOOL status = TRUE;
	DWORD size;
	char *defaultKeyfilesFile = LoadFile (GetConfigPath (TC_APPD_FILENAME_DEFAULT_KEYFILES), &size);
	char *xml = defaultKeyfilesFile;
	KeyFile *kf;

	if (xml == NULL)
		return FALSE;

	KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);

	while (xml = XmlFindElement (xml, "keyfile"))
	{
		kf = (KeyFile *) malloc (sizeof (KeyFile));
		if (kf)
		{
			char fileName [MAX_PATH + 1];
			if (XmlGetNodeText (xml, fileName, sizeof (fileName)) != NULL)
			{
				std::wstring wszFileName = Utf8StringToWide(fileName);
				StringCbCopyW (kf->FileName, sizeof (kf->FileName), wszFileName.c_str ());
				defaultKeyFilesParam.FirstKeyFile = KeyFileAdd (defaultKeyFilesParam.FirstKeyFile, kf);
			}
			else
				free (kf);
		}
		else
		{
			KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
			status = FALSE;
			break;
		}

		xml++;
	}

	free (defaultKeyfilesFile);
	if (status)
		KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles;

	return status;
}

#endif /* #ifndef SETUP */


void Debug (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	StringCbVPrintfA (buf, sizeof (buf), format, val);
	va_end(val);

	OutputDebugStringA (buf);
}


void DebugMsgBox (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	StringCbVPrintfA (buf, sizeof (buf), format, val);
	va_end(val);

	MessageBoxA (MainDlg, buf, "VeraCrypt debug", 0);
}


BOOL IsOSAtLeast (OSVersionEnum reqMinOS)
{
	return IsOSVersionAtLeast (reqMinOS, 0);
}


// Returns TRUE if the operating system is at least reqMinOS and service pack at least reqMinServicePack.
// Example 1: IsOSVersionAtLeast (WIN_VISTA, 1) called under Windows 2008, returns TRUE.
// Example 2: IsOSVersionAtLeast (WIN_XP, 3) called under Windows XP SP1, returns FALSE.
// Example 3: IsOSVersionAtLeast (WIN_XP, 3) called under Windows Vista SP1, returns TRUE.
BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack)
{
	/* When updating this function, update IsOSAtLeast() in Ntdriver.c too. */

	if (CurrentOSMajor <= 0)
		TC_THROW_FATAL_EXCEPTION;

	int major = 0, minor = 0;

	switch (reqMinOS)
	{
	case WIN_2000:			major = 5; minor = 0; break;
	case WIN_XP:			major = 5; minor = 1; break;
	case WIN_SERVER_2003:	major = 5; minor = 2; break;
	case WIN_VISTA:			major = 6; minor = 0; break;
	case WIN_7:				major = 6; minor = 1; break;
	case WIN_8:				major = 6; minor = 2; break;
	case WIN_8_1:			major = 6; minor = 3; break;
	case WIN_10:			major = 10; minor = 0; break;

	default:
		TC_THROW_FATAL_EXCEPTION;
		break;
	}

	return ((CurrentOSMajor << 16 | CurrentOSMinor << 8 | CurrentOSServicePack)
		>= (major << 16 | minor << 8 | reqMinServicePack));
}


BOOL Is64BitOs ()
{
#ifdef _WIN64
	return TRUE;
#else
    static BOOL isWow64 = FALSE;
	static BOOL valid = FALSE;
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS ) (HANDLE hProcess,PBOOL Wow64Process);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	if (valid)
		return isWow64;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
        if (!fnIsWow64Process (GetCurrentProcess(), &isWow64))
			isWow64 = FALSE;

	valid = TRUE;
    return isWow64;
#endif
}


BOOL IsServerOS ()
{
	OSVERSIONINFOEXW osVer;
	osVer.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXW);
	GetVersionExW ((LPOSVERSIONINFOW) &osVer);

	return (osVer.wProductType == VER_NT_SERVER || osVer.wProductType == VER_NT_DOMAIN_CONTROLLER);
}


// Returns TRUE, if the currently running operating system is installed in a hidden volume. If it's not, or if
// there's an error, returns FALSE.
BOOL IsHiddenOSRunning (void)
{
	static BOOL statusCached = FALSE;
	static BOOL hiddenOSRunning;

	if (!statusCached)
	{
		try
		{
			hiddenOSRunning = BootEncryption (MainDlg).IsHiddenSystemRunning();
		}
		catch (...)
		{
			hiddenOSRunning = FALSE;
		}

		statusCached = TRUE;
	}

	return hiddenOSRunning;
}


BOOL EnableWow64FsRedirection (BOOL enable)
{
	typedef BOOLEAN (__stdcall *Wow64EnableWow64FsRedirection_t) (BOOL enable);
	Wow64EnableWow64FsRedirection_t wow64EnableWow64FsRedirection = (Wow64EnableWow64FsRedirection_t) GetProcAddress (GetModuleHandle (L"kernel32"), "Wow64EnableWow64FsRedirection");

    if (!wow64EnableWow64FsRedirection)
		return FALSE;

    return wow64EnableWow64FsRedirection (enable);
}


BOOL RestartComputer (BOOL bShutdown)
{
	TOKEN_PRIVILEGES tokenPrivil;
	HANDLE hTkn;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hTkn))
	{
		return false;
	}

	LookupPrivilegeValue (NULL, SE_SHUTDOWN_NAME, &tokenPrivil.Privileges[0].Luid);
	tokenPrivil.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tokenPrivil.PrivilegeCount = 1;

	AdjustTokenPrivileges (hTkn, false, &tokenPrivil, 0, (PTOKEN_PRIVILEGES) NULL, 0);
	if (GetLastError() != ERROR_SUCCESS)
	{
		CloseHandle(hTkn);
		return false;
	}

	if (!ExitWindowsEx (bShutdown? EWX_POWEROFF: EWX_REBOOT,
		SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED))
	{
		CloseHandle(hTkn);
		return false;
	}

	CloseHandle(hTkn);
	return true;
}


std::wstring GetWindowsEdition ()
{
	wstring osname = L"win";

	OSVERSIONINFOEXW osVer;
	osVer.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXW);
	GetVersionExW ((LPOSVERSIONINFOW) &osVer);

	BOOL home = (osVer.wSuiteMask & VER_SUITE_PERSONAL);
	BOOL server = (osVer.wProductType == VER_NT_SERVER || osVer.wProductType == VER_NT_DOMAIN_CONTROLLER);

	HKEY hkey;
	wchar_t productName[300] = {0};
	DWORD productNameSize = sizeof (productName);
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, L"ProductName", 0, 0, (LPBYTE) &productName, &productNameSize) != ERROR_SUCCESS || productNameSize < 1)
			productName[0] = 0;

		RegCloseKey (hkey);
	}

	switch (nCurrentOS)
	{
	case WIN_2000:
		osname += L"2000";
		break;

	case WIN_XP:
	case WIN_XP64:
		osname += L"xp";
		osname += home ? L"-home" : L"-pro";
		break;

	case WIN_SERVER_2003:
		osname += L"2003";
		break;

	case WIN_VISTA:
		osname += L"vista";
		break;

	case WIN_SERVER_2008:
		osname += L"2008";
		break;

	case WIN_7:
		osname += L"7";
		break;

	case WIN_SERVER_2008_R2:
		osname += L"2008r2";
		break;

	default:
		wstringstream s;
		s << CurrentOSMajor << L"." << CurrentOSMinor;
		osname += s.str();
		break;
	}

	if (server)
		osname += L"-server";

	if (IsOSAtLeast (WIN_VISTA))
	{
		if (home)
			osname += L"-home";
		else if (wcsstr (productName, L"Standard") != 0)
			osname += L"-standard";
		else if (wcsstr (productName, L"Professional") != 0)
			osname += L"-pro";
		else if (wcsstr (productName, L"Business") != 0)
			osname += L"-business";
		else if (wcsstr (productName, L"Enterprise") != 0)
			osname += L"-enterprise";
		else if (wcsstr (productName, L"Datacenter") != 0)
			osname += L"-datacenter";
		else if (wcsstr (productName, L"Ultimate") != 0)
			osname += L"-ultimate";
	}

	if (GetSystemMetrics (SM_STARTER))
		osname += L"-starter";
	else if (wcsstr (productName, L"Basic") != 0)
		osname += L"-basic";

	if (Is64BitOs())
		osname += L"-x64";

	if (CurrentOSServicePack > 0)
	{
		wstringstream s;
		s << L"-sp" << CurrentOSServicePack;
		osname += s.str();
	}

	return osname;
}

#ifdef SETUP
extern wchar_t InstallationPath[TC_MAX_PATH];
#endif

void Applink (const char *dest)
{
	wchar_t url [MAX_URL_LENGTH] = {0};
	wchar_t page[TC_MAX_PATH] = {0};
	wchar_t installDir[TC_MAX_PATH] = {0};
	BOOL buildUrl = TRUE;
	int r;

	ArrowWaitCursor ();
	
#ifdef SETUP
	StringCbCopyW (installDir, sizeof (installDir), InstallationPath);
#else
	GetModPath (installDir, TC_MAX_PATH);
#endif

	if (strcmp(dest, "donate") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Donation.html");
	}
	else if (strcmp(dest, "main") == 0)
	{
		StringCbCopyW (url, sizeof (url), TC_HOMEPAGE);
		buildUrl = FALSE;
	}
	else if (strcmp(dest,"localizations") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Language%20Packs.html");
	}
	else if (strcmp(dest, "beginnerstutorial") == 0 || strcmp(dest,"tutorial") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Beginner%27s%20Tutorial.html");
	}
	else if (strcmp(dest, "releasenotes") == 0 || strcmp(dest, "history") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Release%20Notes.html");
	}
	else if (strcmp(dest, "hwacceleration") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Hardware%20Acceleration.html");
	}
	else if (strcmp(dest, "parallelization") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Parallelization.html");
	}
	else if (strcmp(dest, "help") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Documentation.html");
	}
	else if (strcmp(dest, "onlinehelp") == 0)
	{
		StringCbCopyW (url, sizeof (url),L"https://www.veracrypt.fr/en/Documentation.html");
		buildUrl = FALSE;
	}
	else if (strcmp(dest, "keyfiles") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Keyfiles.html");
	}
	else if (strcmp(dest, "introcontainer") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Creating%20New%20Volumes.html");
	}
	else if (strcmp(dest, "introsysenc") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"System%20Encryption.html");
	}
	else if (strcmp(dest, "hiddensysenc") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"VeraCrypt%20Hidden%20Operating%20System.html");
	}
	else if (strcmp(dest, "sysencprogressinfo") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"System%20Encryption.html");
	}
	else if (strcmp(dest, "hiddenvolume") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Hidden%20Volume.html");
	}
	else if (strcmp(dest, "aes") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"AES.html");
	}
	else if (strcmp(dest, "serpent") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Serpent.html");
	}
	else if (strcmp(dest, "twofish") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Twofish.html");
	}
	else if (strcmp(dest, "kuznyechik") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Kuznyechik.html");
	}
	else if (strcmp(dest, "camellia") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Camellia.html");
	}
	else if (strcmp(dest, "cascades") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Cascades.html");
	}
	else if (strcmp(dest, "hashalgorithms") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Hash%20Algorithms.html");
	}
	else if (strcmp(dest, "isoburning") == 0)
	{
		StringCbCopyW (url, sizeof (url),L"https://cdburnerxp.se/en/home");
		buildUrl = FALSE;
	}
	else if (strcmp(dest, "sysfavorites") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"System%20Favorite%20Volumes.html");
	}
	else if (strcmp(dest, "favorites") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Favorite%20Volumes.html");
	}
	else if (strcmp(dest, "hiddenvolprotection") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Protection%20of%20Hidden%20Volumes.html");
	}
	else if (strcmp(dest, "faq") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"FAQ.html");
	}
	else if (strcmp(dest, "downloads") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Downloads.html");
	}
	else if (strcmp(dest, "news") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"News.html");
	}
	else if (strcmp(dest, "contact") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Contact.html");
	}
	else if (strcmp(dest, "pim") == 0)
	{
		StringCbCopyW (page, sizeof (page),L"Personal%20Iterations%20Multiplier%20%28PIM%29.html");
	}
	else
	{
		StringCbCopyW (url, sizeof (url),TC_APPLINK);
		buildUrl = FALSE;
	}
	
	if (buildUrl)
	{
		StringCbPrintfW (url, sizeof (url), L"file:///%sdocs/html/en/%s", installDir, page);
		CorrectURL (url);
	}

	r = (int) ShellExecuteW (NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);

	if (((r == ERROR_FILE_NOT_FOUND) || (r == ERROR_PATH_NOT_FOUND)) && buildUrl)
	{
		// fallbacl to online resources
		StringCbPrintfW (url, sizeof (url), L"https://www.veracrypt.fr/en/%s", page);
		ShellExecuteW (NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
	}			

	Sleep (200);
	NormalCursor ();
}


wchar_t *RelativePath2Absolute (wchar_t *szFileName)
{
	if (szFileName[0] != L'\\'
		&& wcschr (szFileName, L':') == 0
		&& wcsstr (szFileName, L"Volume{") != szFileName)
	{
		wchar_t path[MAX_PATH*2];
		GetCurrentDirectory (MAX_PATH, path);

		if (path[wcslen (path) - 1] != L'\\')
			StringCbCatW (path, (MAX_PATH * 2), L"\\");

		StringCbCatW (path, (MAX_PATH * 2), szFileName);
		StringCbCopyW (szFileName, MAX_PATH + 1, path); // szFileName size is always at least (MAX_PATH + 1)
	}

	return szFileName;
}


void HandleDriveNotReadyError (HWND hwnd)
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return;

	if (RegQueryValueEx (hkey, L"NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS
		&& value != 0)
	{
		Warning ("SYS_AUTOMOUNT_DISABLED", hwnd);
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		Warning ("SYS_ASSIGN_DRIVE_LETTER", hwnd);
	else
		Warning ("DEVICE_NOT_READY_ERROR", hwnd);

	RegCloseKey (hkey);
}


BOOL CALLBACK CloseTCWindowsEnum (HWND hwnd, LPARAM lParam)
{
	LONG_PTR userDataVal = GetWindowLongPtrW (hwnd, GWLP_USERDATA);
	if ((userDataVal == (LONG_PTR) 'VERA') || (userDataVal == (LONG_PTR) 'TRUE')) // Prior to 1.0e, 'TRUE' was used for VeraCrypt dialogs
	{
		wchar_t name[1024] = { 0 };
		GetWindowText (hwnd, name, ARRAYSIZE (name) - 1);
		if (hwnd != MainDlg && wcsstr (name, L"VeraCrypt"))
		{
			PostMessage (hwnd, TC_APPMSG_CLOSE_BKG_TASK, 0, 0);

			PostMessage (hwnd, WM_CLOSE, 0, 0);

			if (lParam != 0)
				*((BOOL *)lParam) = TRUE;
		}
	}
	return TRUE;
}

BOOL CALLBACK FindTCWindowEnum (HWND hwnd, LPARAM lParam)
{
	if (*(HWND *)lParam == hwnd)
		return TRUE;

	LONG_PTR userDataVal = GetWindowLongPtrW (hwnd, GWLP_USERDATA);
	if ((userDataVal == (LONG_PTR) 'VERA') || (userDataVal == (LONG_PTR) 'TRUE')) // Prior to 1.0e, 'TRUE' was used for VeraCrypt dialogs
	{
		wchar_t name[32] = { 0 };
		GetWindowText (hwnd, name, ARRAYSIZE (name) - 1);
		if (hwnd != MainDlg && wcscmp (name, L"VeraCrypt") == 0)
		{
			if (lParam != 0)
				*((HWND *)lParam) = hwnd;
		}
	}
	return TRUE;
}


BYTE *MapResource (wchar_t *resourceType, int resourceId, PDWORD size)
{
	HGLOBAL hResL;
    HRSRC hRes;

	hRes = FindResource (NULL, MAKEINTRESOURCE(resourceId), resourceType);
	hResL = LoadResource (NULL, hRes);

	if (size != NULL)
		*size = SizeofResource (NULL, hRes);

	return (BYTE *) LockResource (hResL);
}


void InconsistencyResolved (char *techInfo)
{
	wchar_t finalMsg[8024];

	StringCbPrintfW (finalMsg, sizeof(finalMsg), GetString ("INCONSISTENCY_RESOLVED"), techInfo);
	MessageBoxW (MainDlg, finalMsg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


void ReportUnexpectedState (char *techInfo)
{
	wchar_t finalMsg[8024];

	StringCbPrintfW (finalMsg, sizeof(finalMsg), GetString ("UNEXPECTED_STATE"), techInfo);
	MessageBoxW (MainDlg, finalMsg, lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


#ifndef SETUP

int OpenVolume (OpenVolumeContext *context, const wchar_t *volumePath, Password *password, int pkcs5_prf, int pim, BOOL truecryptMode, BOOL write, BOOL preserveTimestamps, BOOL useBackupHeader)
{
	int status = ERR_PARAMETER_INCORRECT;
	int volumeType;
	wchar_t szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	wchar_t szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	LARGE_INTEGER headerOffset;
	DWORD dwResult;
	DISK_GEOMETRY_EX deviceGeometry;

	context->VolumeIsOpen = FALSE;
	context->CryptoInfo = NULL;
	context->HostFileHandle = INVALID_HANDLE_VALUE;
	context->TimestampsValid = FALSE;

	CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), volumePath, &context->IsDevice);

	if (context->IsDevice)
	{
		status = FakeDosNameForDevice (szDiskFile, szDosDevice, sizeof(szDosDevice), szCFDevice, sizeof(szCFDevice), FALSE);
		if (status != 0)
			return status;

		preserveTimestamps = FALSE;

		if (!GetDriveGeometry (volumePath, &deviceGeometry))
		{
			status = ERR_OS_ERROR;
			goto error;
		}
	}
	else
		StringCbCopyW (szCFDevice, sizeof(szCFDevice), szDiskFile);

	if (preserveTimestamps)
		write = TRUE;

	context->HostFileHandle = CreateFile (szCFDevice, GENERIC_READ | (write ? GENERIC_WRITE : 0), FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (context->HostFileHandle == INVALID_HANDLE_VALUE)
	{
		status = ERR_OS_ERROR;
		goto error;
	}

	if (context->IsDevice)
	{
		// Try to gain "raw" access to the partition in case there is a live filesystem on it (otherwise,
		// the NTFS driver guards hidden sectors and prevents e.g. header backup restore after the user
		// accidentally quick-formats a dismounted partition-hosted TrueCrypt volume as NTFS, etc.)

		DeviceIoControl (context->HostFileHandle, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &dwResult, NULL);
	}

	context->VolumeIsOpen = TRUE;

	// Remember the container modification/creation date and time
	if (!context->IsDevice && preserveTimestamps)
	{
		if (GetFileTime (context->HostFileHandle, &context->CreationTime, &context->LastAccessTime, &context->LastWriteTime) == 0)
			context->TimestampsValid = FALSE;
		else
			context->TimestampsValid = TRUE;
	}

	// Determine host size
	if (context->IsDevice)
	{
		PARTITION_INFORMATION diskInfo;

		if (GetPartitionInfo (volumePath, &diskInfo))
		{
			context->HostSize = diskInfo.PartitionLength.QuadPart;
		}
		else
		{
			DISK_GEOMETRY_EX driveInfo;

			if (!DeviceIoControl (context->HostFileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
			{
				status = ERR_OS_ERROR;
				goto error;
			}

			context->HostSize = driveInfo.DiskSize.QuadPart;
		}

		if (context->HostSize == 0)
		{
			status = ERR_VOL_SIZE_WRONG;
			goto error;
		}
	}
	else
	{
		LARGE_INTEGER fileSize;
		if (!GetFileSizeEx (context->HostFileHandle, &fileSize))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		context->HostSize = fileSize.QuadPart;
	}

	for (volumeType = TC_VOLUME_TYPE_NORMAL; volumeType < TC_VOLUME_TYPE_COUNT; volumeType++)
	{
		// Seek the volume header
		switch (volumeType)
		{
		case TC_VOLUME_TYPE_NORMAL:
			headerOffset.QuadPart = useBackupHeader ? context->HostSize - TC_VOLUME_HEADER_GROUP_SIZE : TC_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN:
			if (TC_HIDDEN_VOLUME_HEADER_OFFSET + TC_VOLUME_HEADER_SIZE > context->HostSize)
				continue;

			headerOffset.QuadPart = useBackupHeader ? context->HostSize - TC_VOLUME_HEADER_SIZE : TC_HIDDEN_VOLUME_HEADER_OFFSET;
			break;

		}

		if (!SetFilePointerEx ((HANDLE) context->HostFileHandle, headerOffset, NULL, FILE_BEGIN))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		// Read volume header
		DWORD bytesRead;
		if (!ReadEffectiveVolumeHeader (context->IsDevice, context->HostFileHandle, (byte *) buffer, &bytesRead))
		{
			status = ERR_OS_ERROR;
			goto error;
		}

		if (bytesRead != sizeof (buffer)
			&& context->IsDevice)
		{
			// If FSCTL_ALLOW_EXTENDED_DASD_IO failed and there is a live filesystem on the partition, then the
			// filesystem driver may report EOF when we are reading hidden sectors (when the filesystem is
			// shorter than the partition). This can happen for example after the user quick-formats a dismounted
			// partition-hosted TrueCrypt volume and then tries to read the embedded backup header.

			memset (buffer, 0, sizeof (buffer));
		}

		// Decrypt volume header
		status = ReadVolumeHeader (FALSE, buffer, password, pkcs5_prf, pim, truecryptMode, &context->CryptoInfo, NULL);

		if (status == ERR_PASSWORD_WRONG)
			continue;		// Try next volume type

		break;
	}

	if (status == ERR_SUCCESS)
		return status;

error:
	DWORD sysError = GetLastError ();

	CloseVolume (context);

	SetLastError (sysError);
	return status;
}


void CloseVolume (OpenVolumeContext *context)
{
	if (!context->VolumeIsOpen)
		return;

	if (context->HostFileHandle != INVALID_HANDLE_VALUE)
	{
		if (context->TimestampsValid)
			SetFileTime (context->HostFileHandle, &context->CreationTime, &context->LastAccessTime, &context->LastWriteTime);

		CloseHandle (context->HostFileHandle);
		context->HostFileHandle = INVALID_HANDLE_VALUE;
	}

	if (context->CryptoInfo)
	{
		crypto_close (context->CryptoInfo);
		context->CryptoInfo = NULL;
	}

	context->VolumeIsOpen = FALSE;
}


int ReEncryptVolumeHeader (HWND hwndDlg, char *buffer, BOOL bBoot, CRYPTO_INFO *cryptoInfo, Password *password, int pim, BOOL wipeMode)
{
	CRYPTO_INFO *newCryptoInfo = NULL;

	RandSetHashFunction (cryptoInfo->pkcs5);

	if (Randinit() != ERR_SUCCESS)
	{
		if (CryptoAPILastError == ERROR_SUCCESS)
			return ERR_RAND_INIT_FAILED;
		else
			return ERR_CAPI_INIT_FAILED;
	}

	UserEnrichRandomPool (NULL);

	int status = CreateVolumeHeaderInMemory (hwndDlg, bBoot,
		buffer,
		cryptoInfo->ea,
		cryptoInfo->mode,
		password,
		cryptoInfo->pkcs5,
		pim,
		(char *) cryptoInfo->master_keydata,
		&newCryptoInfo,
		cryptoInfo->VolumeSize.Value,
		cryptoInfo->hiddenVolume ? cryptoInfo->hiddenVolumeSize : 0,
		cryptoInfo->EncryptedAreaStart.Value,
		cryptoInfo->EncryptedAreaLength.Value,
		cryptoInfo->RequiredProgramVersion,
		cryptoInfo->HeaderFlags,
		cryptoInfo->SectorSize,
		wipeMode);

	if (newCryptoInfo != NULL)
		crypto_close (newCryptoInfo);

	return status;
}

#endif // !SETUP


BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
{
	// GlobalMemoryStatusEx() cannot be used to determine if a paging file is active

	wchar_t data[65536];
	DWORD size = sizeof (data);

	if (IsPagingFileWildcardActive())
		return TRUE;

	if (ReadLocalMachineRegistryMultiString (L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles", data, &size)
		&& size > 24 && !checkNonWindowsPartitionsOnly)
		return TRUE;

	if (!IsAdmin())
		AbortProcess ("UAC_INIT_ERROR");

	for (wchar_t drive = L'C'; drive <= L'Z'; ++drive)
	{
		// Query geometry of the drive first to prevent "no medium" pop-ups
		wstring drivePath = L"\\\\.\\X:";
		drivePath[4] = drive;

		if (checkNonWindowsPartitionsOnly)
		{
			wchar_t sysDir[MAX_PATH];
			if (GetSystemDirectory (sysDir, ARRAYSIZE (sysDir)) != 0 && towupper (sysDir[0]) == drive)
				continue;
		}

		HANDLE handle = CreateFile (drivePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (handle == INVALID_HANDLE_VALUE)
			continue;

		DISK_GEOMETRY_EX driveInfo;
		DWORD dwResult;

		if (!DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
		{
			CloseHandle (handle);
			continue;
		}

		CloseHandle (handle);

		// Test if a paging file exists and is locked by another process
		wstring path = L"X:\\pagefile.sys";
		path[0] = drive;

		handle = CreateFile (path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (handle != INVALID_HANDLE_VALUE)
			CloseHandle (handle);
		else if (GetLastError() == ERROR_SHARING_VIOLATION)
			return TRUE;
	}

	return FALSE;
}


BOOL IsPagingFileWildcardActive ()
{
	wchar_t pagingFiles[65536];
	DWORD size = sizeof (pagingFiles);
	wchar_t *mmKey = L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

	if (!ReadLocalMachineRegistryString (mmKey, L"PagingFiles", pagingFiles, &size))
	{
		size = sizeof (pagingFiles);
		if (!ReadLocalMachineRegistryMultiString (mmKey, L"PagingFiles", pagingFiles, &size))
			size = 0;
	}

	return size > 0 && wcsstr (pagingFiles, L"?:\\") == pagingFiles;
}


BOOL DisablePagingFile ()
{
	wchar_t empty[] = { 0, 0 };
	return WriteLocalMachineRegistryMultiString (L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles", empty, sizeof (empty));
}


std::wstring SingleStringToWide (const std::string &singleString)
{
	if (singleString.empty())
		return std::wstring();

	WCHAR wbuf[65536];
	int wideLen = MultiByteToWideChar (CP_ACP, 0, singleString.c_str(), -1, wbuf, array_capacity (wbuf) - 1);

   // We don't throw exception here and only return empty string.
	// All calls to this function use valid strings.
	// throw_sys_if (wideLen == 0);

	wbuf[wideLen] = 0;
	return wbuf;
}


std::wstring Utf8StringToWide (const std::string &utf8String)
{
	if (utf8String.empty())
		return std::wstring();

	WCHAR wbuf[65536];
	int wideLen = MultiByteToWideChar (CP_UTF8, 0, utf8String.c_str(), -1, wbuf, array_capacity (wbuf) - 1);
	throw_sys_if (wideLen == 0);

	wbuf[wideLen] = 0;
	return wbuf;
}


std::string WideToUtf8String (const std::wstring &wideString)
{
	if (wideString.empty())
		return std::string();

	char buf[65536];
	int len = WideCharToMultiByte (CP_UTF8, 0, wideString.c_str(), -1, buf, array_capacity (buf) - 1, NULL, NULL);
	throw_sys_if (len == 0);

	buf[len] = 0;
	return buf;
}


#ifndef SETUP

BOOL CALLBACK SecurityTokenPasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	static string *password;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			password = (string *) lParam;
			LocalizeDialog (hwndDlg, "IDD_TOKEN_PASSWORD");

			wchar_t s[1024];
			StringCbPrintfW (s, sizeof(s), GetString ("ENTER_TOKEN_PASSWORD"), Utf8StringToWide (password->c_str()).c_str());
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_TOKEN_PASSWORD_INFO), s);

			SendMessage (GetDlgItem (hwndDlg, IDC_TOKEN_PASSWORD), EM_LIMITTEXT, SecurityToken::MaxPasswordLength, 0);

			SetForegroundWindow (hwndDlg);
			SetFocus (GetDlgItem (hwndDlg, IDC_TOKEN_PASSWORD));
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDCANCEL || lw == IDOK)
		{
			if (lw == IDOK)
			{
				wchar_t passwordWide[SecurityToken::MaxPasswordLength + 1];

				if (GetWindowTextW (GetDlgItem (hwndDlg, IDC_TOKEN_PASSWORD), passwordWide, SecurityToken::MaxPasswordLength + 1) == 0)
				{
					handleWin32Error (hwndDlg, SRC_POS);
					break;
				}

				char passwordUtf8[SecurityToken::MaxPasswordLength + 1];

				int len = WideCharToMultiByte (CP_UTF8, 0, passwordWide, -1, passwordUtf8, array_capacity (passwordUtf8) - 1, nullptr, nullptr);
				passwordUtf8[len] = 0;
				*password = passwordUtf8;

				burn (passwordWide, sizeof (passwordWide));
				burn (passwordUtf8, sizeof (passwordUtf8));
			}

			// Attempt to wipe password stored in the input field buffer
			wchar_t tmp[SecurityToken::MaxPasswordLength+1];
			wmemset (tmp, 'X', SecurityToken::MaxPasswordLength);
			tmp[SecurityToken::MaxPasswordLength] = 0;
			SetWindowText (GetDlgItem (hwndDlg, IDC_TOKEN_PASSWORD), tmp);

			EndDialog (hwndDlg, lw);
		}
		return 1;
	}

	return 0;
}


struct NewSecurityTokenKeyfileDlgProcParams
{
	CK_SLOT_ID SlotId;
	string Name;
};

static BOOL CALLBACK NewSecurityTokenKeyfileDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static NewSecurityTokenKeyfileDlgProcParams *newParams;

	WORD lw = LOWORD (wParam);
	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LocalizeDialog (hwndDlg, "IDD_NEW_TOKEN_KEYFILE");

			newParams = (NewSecurityTokenKeyfileDlgProcParams *) lParam;

			WaitCursor();
			finally_do ({ NormalCursor(); });

			list <SecurityTokenInfo> tokens;

			try
			{
				tokens = SecurityToken::GetAvailableTokens();
			}
			catch (Exception &e)
			{
				e.Show (hwndDlg);
			}

			if (tokens.empty())
			{
				Error ("NO_TOKENS_FOUND", hwndDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			foreach (const SecurityTokenInfo &token, tokens)
			{
				wstringstream tokenLabel;
				tokenLabel << L"[" << token.SlotId << L"] " << token.Label;

				AddComboPair (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN), tokenLabel.str().c_str(), token.SlotId);
			}

			ComboBox_SetCurSel (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN), 0);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_TOKEN_KEYFILE_NAME), Utf8StringToWide (newParams->Name).c_str());
			return 1;
		}

	case WM_COMMAND:
		switch (lw)
		{
		case IDOK:
			{
				int selectedToken = ComboBox_GetCurSel (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN));
				if (selectedToken == CB_ERR)
				{
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}

				newParams->SlotId = (CK_SLOT_ID) ComboBox_GetItemData (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN), selectedToken);

				wchar_t name[1024];
				if (GetWindowTextW (GetDlgItem (hwndDlg, IDC_TOKEN_KEYFILE_NAME), name, array_capacity (name)) != 0)
				{
					try
					{
						newParams->Name = WideToUtf8String (name);
					}
					catch (...) { }
				}

				EndDialog (hwndDlg, IDOK);
				return 1;
			}

		case IDCANCEL:
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (HIWORD (wParam) == EN_CHANGE)
		{
			wchar_t name[2];
			EnableWindow (GetDlgItem (hwndDlg, IDOK), (GetWindowTextW (GetDlgItem (hwndDlg, IDC_TOKEN_KEYFILE_NAME), name, array_capacity (name)) != 0));
			return 1;
		}
	}

	return 0;
}


static void SecurityTokenKeyfileDlgFillList (HWND hwndDlg, const vector <SecurityTokenKeyfile> &keyfiles)
{
	HWND tokenListControl = GetDlgItem (hwndDlg, IDC_TOKEN_FILE_LIST);
	LVITEMW lvItem;
	int line = 0;

	ListView_DeleteAllItems (tokenListControl);

	foreach (const SecurityTokenKeyfile &keyfile, keyfiles)
	{
		memset (&lvItem, 0, sizeof(lvItem));
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = line++;

		wstringstream s;
		s << keyfile.SlotId;

		ListItemAdd (tokenListControl, lvItem.iItem, (wchar_t *) s.str().c_str());
		ListSubItemSet (tokenListControl, lvItem.iItem, 1, (wchar_t *) keyfile.Token.Label.c_str());
		ListSubItemSet (tokenListControl, lvItem.iItem, 2, (wchar_t *) keyfile.Id.c_str());
	}

	BOOL selected = (ListView_GetNextItem (GetDlgItem (hwndDlg, IDC_TOKEN_FILE_LIST), -1, LVIS_SELECTED) != -1);
	EnableWindow (GetDlgItem (hwndDlg, IDC_EXPORT), selected);
	EnableWindow (GetDlgItem (hwndDlg, IDC_DELETE), selected);
}


static list <SecurityTokenKeyfile> SecurityTokenKeyfileDlgGetSelected (HWND hwndDlg, const vector <SecurityTokenKeyfile> &keyfiles)
{
	HWND tokenListControl = GetDlgItem (hwndDlg, IDC_TOKEN_FILE_LIST);
	list <SecurityTokenKeyfile> selectedKeyfiles;

	int itemId = -1;
	while ((itemId = ListView_GetNextItem (tokenListControl, itemId, LVIS_SELECTED)) != -1)
	{
		selectedKeyfiles.push_back (keyfiles[itemId]);
	}

	return selectedKeyfiles;
}


BOOL CALLBACK SecurityTokenKeyfileDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static list <SecurityTokenKeyfilePath> *selectedTokenKeyfiles;
	static vector <SecurityTokenKeyfile> keyfiles;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			selectedTokenKeyfiles = (list <SecurityTokenKeyfilePath> *) lParam;

			LVCOLUMNW LvCol;
			HWND tokenListControl = GetDlgItem (hwndDlg, IDC_TOKEN_FILE_LIST);

			LocalizeDialog (hwndDlg, selectedTokenKeyfiles ? "SELECT_TOKEN_KEYFILES" : "IDD_TOKEN_KEYFILES");

			SendMessage (tokenListControl,LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_TWOCLICKACTIVATE|LVS_EX_LABELTIP
				);

			memset (&LvCol, 0, sizeof(LvCol));
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;
			LvCol.pszText = GetString ("TOKEN_SLOT_ID");
			LvCol.cx = CompensateXDPI (40);
			LvCol.fmt = LVCFMT_CENTER;
			SendMessage (tokenListControl, LVM_INSERTCOLUMNW, 1, (LPARAM)&LvCol);

			LvCol.pszText = GetString ("TOKEN_NAME");
			LvCol.cx = CompensateXDPI (128);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (tokenListControl, LVM_INSERTCOLUMNW, 2, (LPARAM)&LvCol);

			LvCol.pszText = GetString ("TOKEN_DATA_OBJECT_LABEL");
			LvCol.cx = CompensateXDPI (195);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (tokenListControl, LVM_INSERTCOLUMNW, 3, (LPARAM)&LvCol);

			keyfiles.clear();

			try
			{
				WaitCursor();
				finally_do ({ NormalCursor(); });

				keyfiles = SecurityToken::GetAvailableKeyfiles();
			}
			catch (UserAbort&)
			{
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}
			catch (Exception &e)
			{
				e.Show (hwndDlg);

				if (keyfiles.empty())
				{
					EndDialog (hwndDlg, IDCANCEL);
					return 1;
				}
			}

			SecurityTokenKeyfileDlgFillList (hwndDlg, keyfiles);
			return 1;
		}

	case WM_COMMAND:
	case WM_NOTIFY:
		if (msg == WM_COMMAND && lw == IDOK || msg == WM_NOTIFY && ((NMHDR *)lParam)->code == LVN_ITEMACTIVATE)
		{
			if (selectedTokenKeyfiles)
			{
				foreach (const SecurityTokenKeyfile &keyfile, SecurityTokenKeyfileDlgGetSelected (hwndDlg, keyfiles))
				{
					selectedTokenKeyfiles->push_back (SecurityTokenKeyfilePath (keyfile));
				}
			}

			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (msg == WM_NOTIFY && ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED)
		{
			BOOL selected = (ListView_GetNextItem (GetDlgItem (hwndDlg, IDC_TOKEN_FILE_LIST), -1, LVIS_SELECTED) != -1);
			EnableWindow (GetDlgItem (hwndDlg, IDC_EXPORT), selected);
			EnableWindow (GetDlgItem (hwndDlg, IDC_DELETE), selected);
			return 1;
		}

		if (msg == WM_COMMAND)
		{
			switch (lw)
			{
			case IDCANCEL:
				EndDialog (hwndDlg, IDCANCEL);
				return 1;

			case IDC_IMPORT_KEYFILE:
				{
					wchar_t keyfilePath[TC_MAX_PATH];

					if (BrowseFiles (hwndDlg, "SELECT_KEYFILE", keyfilePath, bHistory, FALSE, NULL))
					{
						DWORD keyfileSize;
						byte *keyfileData = (byte *) LoadFile (keyfilePath, &keyfileSize);
						if (!keyfileData)
						{
							handleWin32Error (hwndDlg, SRC_POS);
							return 1;
						}

						if (keyfileSize != 0)
						{
							NewSecurityTokenKeyfileDlgProcParams newParams;
							newParams.Name = WideToUtf8String (keyfilePath);

							size_t lastBackSlash = newParams.Name.find_last_of ('\\');
							if (lastBackSlash != string::npos)
								newParams.Name = newParams.Name.substr (lastBackSlash + 1);

							if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_NEW_TOKEN_KEYFILE), hwndDlg, (DLGPROC) NewSecurityTokenKeyfileDlgProc, (LPARAM) &newParams) == IDOK)
							{
								vector <byte> keyfileDataVector (keyfileSize);
								memcpy (&keyfileDataVector.front(), keyfileData, keyfileSize);

								try
								{
									WaitCursor();
									finally_do ({ NormalCursor(); });

									SecurityToken::CreateKeyfile (newParams.SlotId, keyfileDataVector, newParams.Name);

									keyfiles = SecurityToken::GetAvailableKeyfiles();
									SecurityTokenKeyfileDlgFillList (hwndDlg, keyfiles);
								}
								catch (Exception &e)
								{
									e.Show (hwndDlg);
								}

								burn (&keyfileDataVector.front(), keyfileSize);
							}
						}
						else
						{
							SetLastError (ERROR_HANDLE_EOF);
							handleWin32Error (hwndDlg, SRC_POS);
						}

						burn (keyfileData, keyfileSize);
						TCfree (keyfileData);
					}

					return 1;
				}

			case IDC_EXPORT:
				{
					try
					{
						foreach (const SecurityTokenKeyfile &keyfile, SecurityTokenKeyfileDlgGetSelected (hwndDlg, keyfiles))
						{
							wchar_t keyfilePath[TC_MAX_PATH];

							if (!BrowseFiles (hwndDlg, "OPEN_TITLE", keyfilePath, bHistory, TRUE, NULL))
								break;

							{
								WaitCursor();
								finally_do ({ NormalCursor(); });

								vector <byte> keyfileData;

								SecurityToken::GetKeyfileData (keyfile, keyfileData);

								if (keyfileData.empty())
								{
									SetLastError (ERROR_HANDLE_EOF);
									handleWin32Error (hwndDlg, SRC_POS);
									return 1;
								}

								finally_do_arg (vector <byte> *, &keyfileData, { burn (&finally_arg->front(), finally_arg->size()); });

								if (!SaveBufferToFile ((char *) &keyfileData.front(), keyfilePath, (DWORD) keyfileData.size(), FALSE, FALSE))
									throw SystemException (SRC_POS);
							}

							Info ("KEYFILE_EXPORTED", hwndDlg);
						}
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}

					return 1;
				}

			case IDC_DELETE:
				{
					if (AskNoYes ("CONFIRM_SEL_FILES_DELETE", hwndDlg) == IDNO)
						return 1;

					try
					{
						WaitCursor();
						finally_do ({ NormalCursor(); });

						foreach (const SecurityTokenKeyfile &keyfile, SecurityTokenKeyfileDlgGetSelected (hwndDlg, keyfiles))
						{
							SecurityToken::DeleteKeyfile (keyfile);
						}

						keyfiles = SecurityToken::GetAvailableKeyfiles();
						SecurityTokenKeyfileDlgFillList (hwndDlg, keyfiles);
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}

					return 1;
				}
			}
		}
		return 0;
	}
	return 0;
}


BOOL InitSecurityTokenLibrary (HWND hwndDlg)
{
	if (SecurityTokenLibraryPath[0] == 0)
	{
		Error ("NO_PKCS11_MODULE_SPECIFIED", hwndDlg);
		return FALSE;
	}

	struct PinRequestHandler : public GetPinFunctor
	{
		HWND m_hwnd;
		PinRequestHandler(HWND hwnd) : m_hwnd(hwnd) {}
		virtual void operator() (string &str)
		{
			if (CmdTokenPin[0])
			{
				str = CmdTokenPin;
			}
			else
			{
				HWND hParent = IsWindow (m_hwnd)? m_hwnd : GetActiveWindow();
				if (!hParent)
					hParent = GetForegroundWindow ();
				if (SecureDesktopDialogBoxParam (hInst, MAKEINTRESOURCEW (IDD_TOKEN_PASSWORD), hParent, (DLGPROC) SecurityTokenPasswordDlgProc, (LPARAM) &str) == IDCANCEL)
					throw UserAbort (SRC_POS);
			}
			if (hCursor != NULL)
				SetCursor (hCursor);
		}

		virtual void notifyIncorrectPin ()
		{
			// clear wrong PIN
			burn (&CmdTokenPin, sizeof (CmdTokenPin));
		}
	};

	struct WarningHandler : public SendExceptionFunctor
	{
		HWND m_hwnd;
		WarningHandler(HWND hwnd) : m_hwnd(hwnd) {}
		virtual void operator() (const Exception &e)
		{
			HWND hParent = IsWindow (m_hwnd)? m_hwnd : GetActiveWindow();
			if (!hParent)
				hParent = GetForegroundWindow ();
			e.Show (hParent);
		}
	};

	try
	{
		SecurityToken::InitLibrary (SecurityTokenLibraryPath, auto_ptr <GetPinFunctor> (new PinRequestHandler(MainDlg)), auto_ptr <SendExceptionFunctor> (new WarningHandler(MainDlg)));
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
		Error ("PKCS11_MODULE_INIT_FAILED", hwndDlg);
		return FALSE;
	}

	return TRUE;
}

std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties, bool singleList, bool noFloppy, bool detectUnencryptedFilesystems)
{
	vector <HostDevice> devices;
	size_t dev0;

	for (int devNumber = 0; devNumber < MAX_HOST_DRIVE_NUMBER; devNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			wstringstream strm;
			strm << L"\\Device\\Harddisk" << devNumber << L"\\Partition" << partNumber;
			wstring devPathStr (strm.str());
			const wchar_t *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest = {0};
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems && partNumber != 0, FALSE))
			{
				if (partNumber == 0)
					break;

				continue;
			}

			HostDevice device;
			device.SystemNumber = devNumber;
			device.Path = devPath;

			PARTITION_INFORMATION partInfo;

			if (GetPartitionInfo (devPath, &partInfo))
			{
				device.Bootable = partInfo.BootIndicator ? true : false;
				device.Size = partInfo.PartitionLength.QuadPart;
			}
			else
			{
				// retrieve size using DISK_GEOMETRY_EX
				DISK_GEOMETRY_EX deviceGeometry = {0};
				if (	GetDriveGeometry (devPath, &deviceGeometry)
						||	((partNumber == 0) && GetPhysicalDriveGeometry (devNumber, &deviceGeometry))
					)
				{
					device.Size = (uint64) deviceGeometry.DiskSize.QuadPart;
				}
			}

			device.HasUnencryptedFilesystem = (detectUnencryptedFilesystems && openTest.FilesystemDetected) ? true : false;

			if (!noDeviceProperties)
			{
				DISK_GEOMETRY_EX geometry;

				int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) devPathStr.c_str());

				if (driveNumber >= 0)
				{
					device.MountPoint += (wchar_t) (driveNumber + L'A');
					device.MountPoint += L":";

					wchar_t name[64];
					if (GetDriveLabel (driveNumber, name, sizeof (name)))
						device.Name = name;

					if (GetSystemDriveLetter() == L'A' + driveNumber)
						device.ContainsSystem = true;
				}

				if (partNumber == 0 && GetDriveGeometry (devPath, &geometry))
					device.Removable = (geometry.Geometry.MediaType == RemovableMedia);
			}

			if (partNumber == 0)
			{
				devices.push_back (device);
				dev0 = devices.size() - 1;
			}
			else
			{
				// System creates a virtual partition1 for some storage devices without
				// partition table. We try to detect this case by comparing sizes of
				// partition0 and partition1. If they match, no partition of the device
				// is displayed to the user to avoid confusion. Drive letter assigned by
				// system to partition1 is assigned partition0
				if (partNumber == 1 && devices[dev0].Size == device.Size)
				{
					devices[dev0].IsVirtualPartition = true;
					devices[dev0].MountPoint = device.MountPoint;
					devices[dev0].Name = device.Name;
					devices[dev0].Path = device.Path;
					devices[dev0].HasUnencryptedFilesystem = device.HasUnencryptedFilesystem;
					break;
				}

				device.IsPartition = true;
				device.SystemNumber = partNumber;
				device.Removable = devices[dev0].Removable;

				if (device.ContainsSystem)
					devices[dev0].ContainsSystem = true;

				if (singleList)
					devices.push_back (device);

				devices[dev0].Partitions.push_back (device);
			}
		}
	}

	// Vista does not create partition links for dynamic volumes so it is necessary to scan \\Device\\HarddiskVolumeX devices
	if (CurrentOSMajor >= 6)
	{
		for (int devNumber = 0; devNumber < 256; devNumber++)
		{
			wstringstream strm;
			strm << L"\\Device\\HarddiskVolume" << devNumber;
			wstring devPathStr (strm.str());
			const wchar_t *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest = {0};
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems, FALSE))
				continue;

			DISK_PARTITION_INFO_STRUCT info;
			if (GetDeviceInfo (devPath, &info) && info.IsDynamic)
			{
				HostDevice device;
				device.DynamicVolume = true;
				device.IsPartition = true;
				device.SystemNumber = devNumber;
				device.Path = devPath;
				device.Size = info.partInfo.PartitionLength.QuadPart;
				device.HasUnencryptedFilesystem = (detectUnencryptedFilesystems && openTest.FilesystemDetected) ? true : false;

				if (!noDeviceProperties)
				{
					int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) devPathStr.c_str());

					if (driveNumber >= 0)
					{
						device.MountPoint += (wchar_t) (driveNumber + L'A');
						device.MountPoint += L":";

						wchar_t name[64];
						if (GetDriveLabel (driveNumber, name, sizeof (name)))
							device.Name = name;

						if (GetSystemDriveLetter() == L'A' + driveNumber)
							device.ContainsSystem = true;
					}
				}

				devices.push_back (device);
			}
		}
	}

	return devices;
}

void AddDeviceToList (std::vector<HostDevice>& devices, int devNumber, int partNumber)
{
	wstringstream strm;
	strm << L"\\Device\\Harddisk" << devNumber << L"\\Partition" << partNumber;
	wstring devPathStr (strm.str());
	const wchar_t *devPath = devPathStr.c_str();

	HostDevice device;
	device.SystemNumber = devNumber;
	device.Path = devPath;

	devices.push_back (device);
}

std::vector <HostDevice> GetHostRawDeviceList (bool bFromService)
{
	if (bFromService)
		return GetAvailableHostDevices (true, false, true, true);

	std::vector <HostDevice> list;
	HDEVINFO diskClassDevices;
	GUID diskClassDeviceInterfaceGuid = GUID_DEVINTERFACE_DISK;
	SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
	PSP_DEVICE_INTERFACE_DETAIL_DATA deviceInterfaceDetailData;
	DWORD requiredSize;
	DWORD deviceIndex;

	STORAGE_DEVICE_NUMBER diskNumber;
	DWORD bytesReturned;

	diskClassDevices = SetupDiGetClassDevs( &diskClassDeviceInterfaceGuid,
		NULL,
		NULL,
		DIGCF_PRESENT |
		DIGCF_DEVICEINTERFACE );
	if ( INVALID_HANDLE_VALUE != diskClassDevices)
	{
		ZeroMemory( &deviceInterfaceData, sizeof( SP_DEVICE_INTERFACE_DATA ) );
		deviceInterfaceData.cbSize = sizeof( SP_DEVICE_INTERFACE_DATA );
		deviceIndex = 0;

		while ( SetupDiEnumDeviceInterfaces( diskClassDevices,
			NULL,
			&diskClassDeviceInterfaceGuid,
			deviceIndex,
			&deviceInterfaceData ) )
		{
			++deviceIndex;

			if (!SetupDiGetDeviceInterfaceDetail( diskClassDevices,
				&deviceInterfaceData,
				NULL,
				0,
				&requiredSize,
				NULL ) && ( ERROR_INSUFFICIENT_BUFFER == GetLastError()))
			{
				deviceInterfaceDetailData = ( PSP_DEVICE_INTERFACE_DETAIL_DATA ) malloc( requiredSize );
				if (deviceInterfaceDetailData)
				{
					ZeroMemory( deviceInterfaceDetailData, requiredSize );
					deviceInterfaceDetailData->cbSize = sizeof( SP_DEVICE_INTERFACE_DETAIL_DATA );
					if (SetupDiGetDeviceInterfaceDetail( diskClassDevices,
						&deviceInterfaceData,
						deviceInterfaceDetailData,
						requiredSize,
						NULL,
						NULL ))
					{
						HANDLE disk = CreateFile( deviceInterfaceDetailData->DevicePath,
							0,
							FILE_SHARE_READ | FILE_SHARE_WRITE,
							NULL,
							OPEN_EXISTING,
							0,
							NULL );
						if ( INVALID_HANDLE_VALUE != disk)
						{
							if (DeviceIoControl( disk,
								IOCTL_STORAGE_GET_DEVICE_NUMBER,
								NULL,
								0,
								&diskNumber,
								sizeof( STORAGE_DEVICE_NUMBER ),
								&bytesReturned,
								NULL ))
							{
								HostDevice device;
								device.Path = deviceInterfaceDetailData->DevicePath;
								device.SystemNumber = diskNumber.DeviceNumber;
								list.push_back (device);
							}

							CloseHandle( disk );
						}
					}

					free (deviceInterfaceDetailData);
				}
			}
		}

		SetupDiDestroyDeviceInfoList( diskClassDevices );
	}

	return list;
}

bool CompareDeviceList (const std::vector<HostDevice>& list1, const std::vector<HostDevice>& list2)
{
	if (list1.size() != list2.size())
		return false;

	for (std::vector<HostDevice>::const_iterator It1 = list1.begin(); It1 != list1.end(); It1++)
	{
		bool bFound = false;
		for (std::vector<HostDevice>::const_iterator It2 = list2.begin(); It2 != list2.end(); It2++)
		{
			if (It1->Path == It2->Path && It1->SystemNumber == It2->SystemNumber)
			{
				bFound = true;
				break;
			}
		}

		if (!bFound)
			return false;
	}

	return true;
}

void UpdateMountableHostDeviceList (bool bFromService)
{
	ByteArray buffer(4096);
	DWORD bytesReturned;
	bool dynamicVolumesPresent = false;

	EnterCriticalSection (&csMountableDevices);
	finally_do ({ LeaveCriticalSection (&csMountableDevices); });

	std::vector<HostDevice> newList = GetHostRawDeviceList (bFromService);
	std::map<DWORD, bool> existingDevicesMap;

	if (CompareDeviceList (newList, rawHostDeviceList))
		return; //no change, return

	// remove raw devices that don't exist anymore
	for (std::vector<HostDevice>::iterator It = rawHostDeviceList.begin();
		It != rawHostDeviceList.end();)
	{
		for (std::vector<HostDevice>::iterator newIt = newList.begin(); newIt != newList.end(); newIt++)
		{
			if (newIt->SystemNumber == It->SystemNumber)
			{
				existingDevicesMap[It->SystemNumber] = true;
				break;
			}
		}

		if (existingDevicesMap[It->SystemNumber])
			It++;
		else
		{
			It = rawHostDeviceList.erase (It);
		}
	}

	// remove mountable devices that don't exist anymore
	for (std::vector<HostDevice>::iterator It = mountableDevices.begin();
		It != mountableDevices.end();)
	{
		if (existingDevicesMap[It->SystemNumber])
			It++;
		else
			It = mountableDevices.erase (It);
	}

	// add new devices
	for (std::vector<HostDevice>::iterator It = newList.begin(); It != newList.end(); It++)
	{
		if (existingDevicesMap[It->SystemNumber])
			continue;

		if (bFromService)
		{
			if (It->Partitions.empty())
				mountableDevices.push_back (*It);
			else
			{
				for (std::vector<HostDevice>::iterator partIt = It->Partitions.begin(); partIt != It->Partitions.end(); partIt++)
				{
					if (!partIt->ContainsSystem && !partIt->HasUnencryptedFilesystem)
						mountableDevices.push_back (*partIt);
				}
			}
		}
		else
		{
			HANDLE disk = CreateFile( It->Path.c_str(),
				0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_EXISTING,
				0,
				NULL );
			if ( INVALID_HANDLE_VALUE != disk)
			{	
				bool bIsDynamic = false;
				bool bHasPartition = false;
				if (DeviceIoControl(
					disk,
					IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
					NULL,
					0,
					(LPVOID) buffer.data(),
					(DWORD) buffer.size(),
					(LPDWORD) &bytesReturned,
					NULL) && (bytesReturned >= sizeof (DRIVE_LAYOUT_INFORMATION_EX)))
				{
					PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX) buffer.data();
					// sanity checks
					if (layout->PartitionCount <= 256)
					{
						for (DWORD i = 0; i < layout->PartitionCount; i++)
						{
							if (layout->PartitionEntry[i].PartitionStyle == PARTITION_STYLE_MBR)
							{
								if (layout->PartitionEntry[i].Mbr.PartitionType == 0)
									continue;

								bHasPartition = true;

								/* skip dynamic volume */
								if (layout->PartitionEntry[i].Mbr.PartitionType == PARTITION_LDM)
								{
									bIsDynamic = true;
									/* remove any partition that may have been added */
									while (!mountableDevices.empty() && (mountableDevices.back().SystemNumber == It->SystemNumber))
										mountableDevices.pop_back ();
									break;
								}
							}

							if (layout->PartitionEntry[i].PartitionStyle == PARTITION_STYLE_GPT)
							{
								if (IsEqualGUID(layout->PartitionEntry[i].Gpt.PartitionType, PARTITION_ENTRY_UNUSED_GUID))
									continue;

								bHasPartition = true;

								/* skip dynamic volume */
								if (	IsEqualGUID(layout->PartitionEntry[i].Gpt.PartitionType, PARTITION_LDM_METADATA_GUID)
									||	IsEqualGUID(layout->PartitionEntry[i].Gpt.PartitionType, PARTITION_LDM_DATA_GUID)
									)
								{
									bIsDynamic = true;
									/* remove any partition that may have been added */
									while (!mountableDevices.empty() && (mountableDevices.back().SystemNumber == It->SystemNumber))
										mountableDevices.pop_back ();
									break;
								}
							}

							WCHAR path[MAX_PATH];
							StringCbPrintfW (path, sizeof(path), L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", It->SystemNumber, layout->PartitionEntry[i].PartitionNumber);
							HANDLE handle = CreateFile( path,
								0,
								FILE_SHARE_READ | FILE_SHARE_WRITE,
								NULL,
								OPEN_EXISTING,
								0,
								NULL );
							if ((handle != INVALID_HANDLE_VALUE) || (GetLastError () == ERROR_ACCESS_DENIED))
							{
								AddDeviceToList (mountableDevices, It->SystemNumber, layout->PartitionEntry[i].PartitionNumber);
								if (handle != INVALID_HANDLE_VALUE)
									CloseHandle (handle);
							}
						}
					}
				}

				if (bIsDynamic)
					dynamicVolumesPresent = true;

				if (!bHasPartition)
					AddDeviceToList (mountableDevices, It->SystemNumber, 0);

				CloseHandle (disk);
			}
		}
	}

	rawHostDeviceList = newList;

	// Starting from Vista, Windows does not create partition links for dynamic volumes so it is necessary to scan \\Device\\HarddiskVolumeX devices
	if (!bFromService && dynamicVolumesPresent && (CurrentOSMajor >= 6))
	{
		for (int devNumber = 0; devNumber < 256; devNumber++)
		{
			wstringstream strm;
			strm << L"\\Device\\HarddiskVolume" << devNumber;
			wstring devPathStr (strm.str());
			const wchar_t *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest = {0};
			if (!OpenDevice (devPath, &openTest, FALSE, FALSE))
				continue;

			DISK_PARTITION_INFO_STRUCT info;
			if (GetDeviceInfo (devPath, &info) && info.IsDynamic)
			{
				HostDevice device;
				device.SystemNumber = devNumber;
				device.Path = devPath;

				mountableDevices.push_back (device);
			}
		}
	}
}

wstring FindDeviceByVolumeID (const BYTE volumeID [VOLUME_ID_SIZE])
{
	static std::vector<HostDevice>  volumeIdCandidates;

	/* if it is already mounted, get the real path name used for mounting */
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;

	memset (&mlist, 0, sizeof (mlist));
	if (	!DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
				sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
				NULL) 
		|| (mlist.ulMountedDrives >= (1 << 26))
		)
	{
		return L""; 
	}

	if (mlist.ulMountedDrives)
	{
		for (int i=0 ; i < 26; i++)
		{
			if ((mlist.ulMountedDrives & (1 << i)) && (0 == memcmp (mlist.volumeID[i], volumeID, VOLUME_ID_SIZE)))
			{
				if (IsNullTerminateString (mlist.wszVolume[i], TC_MAX_PATH))
					return mlist.wszVolume[i];
				else
					return L"";
			}
		}
	}

	/* not mounted. Look for it in the local drives*/

	EnterCriticalSection (&csMountableDevices);
	std::vector<HostDevice> newDevices = mountableDevices;
	LeaveCriticalSection (&csMountableDevices);

	EnterCriticalSection (&csVolumeIdCandidates);
	finally_do ({ LeaveCriticalSection (&csVolumeIdCandidates); });

	/* remove any devices that don't exist anymore */
	for (std::vector<HostDevice>::iterator It = volumeIdCandidates.begin();
		It != volumeIdCandidates.end();)
	{
		bool bFound = false;
		for (std::vector<HostDevice>::iterator newIt = newDevices.begin();
			newIt != newDevices.end(); newIt++)
		{
			if (It->Path == newIt->Path)
			{
				bFound = true;
				break;
			}
		}

		if (bFound)
			It++;
		else
			It = volumeIdCandidates.erase (It);
	}

	/* Add newly inserted devices and compute their VolumeID */
	for (std::vector<HostDevice>::iterator newIt = newDevices.begin();
		newIt != newDevices.end(); newIt++)
	{
		bool bFound = false;

		for (std::vector<HostDevice>::iterator It = volumeIdCandidates.begin();
			It != volumeIdCandidates.end(); It++)
		{
			if (It->Path == newIt->Path)
			{
				bFound = true;
				break;
			}
		}

		if (!bFound)
		{
			/* new device/partition. Compute its Volume IDs */
			OPEN_TEST_STRUCT openTest = {0};
			if (OpenDevice (newIt->Path.c_str(), &openTest, TRUE, TRUE)
				&& (openTest.VolumeIDComputed[TC_VOLUME_TYPE_NORMAL] && openTest.VolumeIDComputed[TC_VOLUME_TYPE_HIDDEN])
				)
			{
				memcpy (newIt->VolumeIDs, openTest.volumeIDs, sizeof (newIt->VolumeIDs));
				newIt->HasVolumeIDs = true;
			}
			else
				newIt->HasVolumeIDs = false;
			volumeIdCandidates.push_back (*newIt);
		}
	}

	for (std::vector<HostDevice>::iterator It = volumeIdCandidates.begin();
		It != volumeIdCandidates.end(); It++)
	{
		if (	It->HasVolumeIDs &&
				(	(0 == memcmp (volumeID, It->VolumeIDs[TC_VOLUME_TYPE_NORMAL], VOLUME_ID_SIZE))
					||	(0 == memcmp (volumeID, It->VolumeIDs[TC_VOLUME_TYPE_HIDDEN], VOLUME_ID_SIZE))
				)
			)
		{
			return It->Path;
		}
	}

	return L"";
}

#endif // !SETUP

BOOL FileHasReadOnlyAttribute (const wchar_t *path)
{
	DWORD attributes = GetFileAttributes (path);
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0;
}


BOOL IsFileOnReadOnlyFilesystem (const wchar_t *path)
{
	wchar_t root[MAX_PATH];
	if (!GetVolumePathName (path, root, ARRAYSIZE (root)))
		return FALSE;

	DWORD flags, d;
	if (!GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
		return FALSE;

	return (flags & FILE_READ_ONLY_VOLUME) ? TRUE : FALSE;
}


void CheckFilesystem (HWND hwndDlg, int driveNo, BOOL fixErrors)
{
	wchar_t msg[1024], param[1024], cmdPath[MAX_PATH];
	wchar_t driveRoot[] = { L'A' + (wchar_t) driveNo, L':', 0 };

	if (fixErrors && AskWarnYesNo ("FILESYS_REPAIR_CONFIRM_BACKUP", hwndDlg) == IDNO)
		return;

	StringCbPrintfW (msg, sizeof(msg), GetString (fixErrors ? "REPAIRING_FS" : "CHECKING_FS"), driveRoot);
	StringCbPrintfW (param, sizeof(param), fixErrors ? L"/C echo %s & chkdsk %s /F /X & pause" : L"/C echo %s & chkdsk %s & pause", msg, driveRoot);

	if (GetSystemDirectoryW(cmdPath, MAX_PATH))
	{
		StringCbCatW(cmdPath, sizeof(cmdPath), L"\\cmd.exe");
	}
	else
		StringCbCopyW(cmdPath, sizeof(cmdPath), L"C:\\Windows\\System32\\cmd.exe");

	ShellExecuteW (NULL, (!IsAdmin() && IsUacSupported()) ? L"runas" : L"open", cmdPath, param, NULL, SW_SHOW);
}


BOOL BufferContainsString (const byte *buffer, size_t bufferSize, const char *str)
{
	size_t strLen = strlen (str);

	if (bufferSize < strLen)
		return FALSE;

	bufferSize -= strLen;

	for (size_t i = 0; i < bufferSize; ++i)
	{
		if (memcmp (buffer + i, str, strLen) == 0)
			return TRUE;
	}

	return FALSE;
}


#ifndef SETUP

int AskNonSysInPlaceEncryptionResume (HWND hwndDlg, BOOL *pbDecrypt)
{
	if (AskWarnYesNo ("NONSYS_INPLACE_ENC_RESUME_PROMPT", hwndDlg) == IDYES)
	{
		char *tmpStr[] = {0,
			"CHOOSE_ENCRYPT_OR_DECRYPT",
			"ENCRYPT",
			"DECRYPT",
			"IDCANCEL",
			0};

		switch (AskMultiChoice ((void **) tmpStr, FALSE, hwndDlg))
		{
		case 1:
			*pbDecrypt = FALSE;
			return IDYES;
		case 2:
			*pbDecrypt = TRUE;
			return IDYES;
		default:
			break;
		}
	}

	char *multiChoiceStr[] = { 0, "ASK_NONSYS_INPLACE_ENC_NOTIFICATION_REMOVAL", "DO_NOT_PROMPT_ME", "KEEP_PROMPTING_ME", 0 };

	switch (AskMultiChoice ((void **) multiChoiceStr, FALSE, hwndDlg))
	{
	case 1:
		RemoveNonSysInPlaceEncNotifications();
		Warning ("NONSYS_INPLACE_ENC_NOTIFICATION_REMOVAL_NOTE", hwndDlg);
		break;

	default:
		// NOP
		break;
	}

	return IDNO;
}

#endif // !SETUP


BOOL RemoveDeviceWriteProtection (HWND hwndDlg, wchar_t *devicePath)
{
	int driveNumber;
	int partitionNumber;

	wchar_t temp[MAX_PATH*2];
	wchar_t cmdBatch[MAX_PATH*2];
	wchar_t diskpartScript[MAX_PATH*2];

	if (swscanf (devicePath, L"\\Device\\Harddisk%d\\Partition%d", &driveNumber, &partitionNumber) != 2)
		return FALSE;

	if (GetTempPath (ARRAYSIZE (temp), temp) == 0)
		return FALSE;

	StringCbPrintfW (cmdBatch, sizeof (cmdBatch), L"%s\\VeraCrypt_Write_Protection_Removal.cmd", temp);
	StringCbPrintfW (diskpartScript, sizeof (diskpartScript), L"%s\\VeraCrypt_Write_Protection_Removal.diskpart", temp);

	FILE *f = _wfopen (cmdBatch, L"w");
	if (!f)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		return FALSE;
	}

	fwprintf (f, L"@diskpart /s \"%s\"\n@pause\n@del \"%s\" \"%s\"", diskpartScript, diskpartScript, cmdBatch);

	CheckFileStreamWriteErrors (hwndDlg, f, cmdBatch);
	fclose (f);

	f = _wfopen (diskpartScript, L"w");
	if (!f)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		DeleteFile (cmdBatch);
		return FALSE;
	}

	fwprintf (f, L"select disk %d\nattributes disk clear readonly\n", driveNumber);

	if (partitionNumber != 0)
		fwprintf (f, L"select partition %d\nattributes volume clear readonly\n", partitionNumber);

	fwprintf (f, L"exit\n");

	CheckFileStreamWriteErrors (hwndDlg, f, diskpartScript);
	fclose (f);

	ShellExecute (NULL, (!IsAdmin() && IsUacSupported()) ? L"runas" : L"open", cmdBatch, NULL, NULL, SW_SHOW);

	return TRUE;
}


static LRESULT CALLBACK EnableElevatedCursorChangeWndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProcW (hWnd, message, wParam, lParam);
}


void EnableElevatedCursorChange (HWND parent)
{
	// Create a transparent window to work around a UAC issue preventing change of the cursor
	if (UacElevated)
	{
		const wchar_t *className = L"VeraCryptEnableElevatedCursorChange";
		WNDCLASSEXW winClass;
		HWND hWnd;

		memset (&winClass, 0, sizeof (winClass));
		winClass.cbSize = sizeof (WNDCLASSEX);
		winClass.lpfnWndProc = (WNDPROC) EnableElevatedCursorChangeWndProc;
		winClass.hInstance = hInst;
		winClass.lpszClassName = className;
		RegisterClassExW (&winClass);

		hWnd = CreateWindowExW (WS_EX_TOOLWINDOW | WS_EX_LAYERED, className, L"VeraCrypt UAC", 0, 0, 0, GetSystemMetrics (SM_CXSCREEN), GetSystemMetrics (SM_CYSCREEN), parent, NULL, hInst, NULL);
		if (hWnd)
		{
			SetLayeredWindowAttributes (hWnd, 0, 1, LWA_ALPHA);
			ShowWindow (hWnd, SW_SHOWNORMAL);

			DestroyWindow (hWnd);
		}
		UnregisterClassW (className, hInst);
	}
}


BOOL DisableFileCompression (HANDLE file)
{
	USHORT format;
	DWORD bytesOut;

	if (!DeviceIoControl (file, FSCTL_GET_COMPRESSION, NULL, 0, &format, sizeof (format), &bytesOut, NULL))
		return FALSE;

	if (format == COMPRESSION_FORMAT_NONE)
		return TRUE;

	format = COMPRESSION_FORMAT_NONE;
	return DeviceIoControl (file, FSCTL_SET_COMPRESSION, &format, sizeof (format), NULL, 0, &bytesOut, NULL);
}

#ifndef SETUP
BOOL VolumePathExists (const wchar_t *volumePath)
{
	OPEN_TEST_STRUCT openTest = {0};
	wchar_t upperCasePath[TC_MAX_PATH + 1];

	UpperCaseCopy (upperCasePath, sizeof(upperCasePath), volumePath);

	if (wcsstr (upperCasePath, L"\\DEVICE\\") == upperCasePath)
		return OpenDevice (volumePath, &openTest, FALSE, FALSE);

	wstring path = volumePath;
	if (path.find (L"\\\\?\\Volume{") == 0 && path.rfind (L"}\\") == path.size() - 2)
	{
		wchar_t devicePath[TC_MAX_PATH];
		if (QueryDosDevice (path.substr (4, path.size() - 5).c_str(), devicePath, TC_MAX_PATH) != 0)
			return TRUE;
	}

	if (_waccess (volumePath, 0) == 0)
		return TRUE;
	else
	{
		DWORD dwResult = GetLastError ();
		if (dwResult == ERROR_SHARING_VIOLATION)
			return TRUE;
		else
			return FALSE;
	}
}


BOOL IsWindowsIsoBurnerAvailable ()
{
	wchar_t path[MAX_PATH*2] = { 0 };

	if (!IsOSAtLeast (WIN_7))
	{
		return FALSE;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_SYSTEM, NULL, 0, path)))
	{
		StringCbCatW (path, MAX_PATH*2, L"\\" ISO_BURNER_TOOL);

		return (FileExists (path));
	}

	return FALSE;
}


BOOL LaunchWindowsIsoBurner (HWND hwnd, const wchar_t *isoPath)
{
	wchar_t path[MAX_PATH*2] = { 0 };
	int r;

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_SYSTEM, NULL, 0, path)))
		StringCbCatW (path, MAX_PATH*2, L"\\" ISO_BURNER_TOOL);
	else
		StringCbCopyW (path, MAX_PATH*2, L"C:\\Windows\\System32\\" ISO_BURNER_TOOL);

	r = (int) ShellExecute (hwnd, L"open", path, (wstring (L"\"") + isoPath + L"\"").c_str(), NULL, SW_SHOWNORMAL);

	if (r <= 32)
	{
		SetLastError (r);
		handleWin32Error (hwnd, SRC_POS);

		return FALSE;
	}

	return TRUE;
}


std::wstring VolumeGuidPathToDevicePath (std::wstring volumeGuidPath)
{
	if (volumeGuidPath.find (L"\\\\?\\") == 0)
		volumeGuidPath = volumeGuidPath.substr (4);

	if (volumeGuidPath.find (L"Volume{") != 0 || volumeGuidPath.rfind (L"}\\") != volumeGuidPath.size() - 2)
		return wstring();

	wchar_t volDevPath[TC_MAX_PATH];
	if (QueryDosDevice (volumeGuidPath.substr (0, volumeGuidPath.size() - 1).c_str(), volDevPath, TC_MAX_PATH) == 0)
		return wstring();

	wstring partitionPath = HarddiskVolumePathToPartitionPath (volDevPath);

	return partitionPath.empty() ? volDevPath : partitionPath;
}


std::wstring HarddiskVolumePathToPartitionPath (const std::wstring &harddiskVolumePath)
{
	for (int driveNumber = 0; driveNumber < MAX_HOST_DRIVE_NUMBER; driveNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			wchar_t partitionPath[TC_MAX_PATH];
			StringCchPrintfW (partitionPath, ARRAYSIZE (partitionPath), L"\\Device\\Harddisk%d\\Partition%d", driveNumber, partNumber);

			wchar_t resolvedPath[TC_MAX_PATH];
			if (ResolveSymbolicLink (partitionPath, resolvedPath, sizeof(resolvedPath)))
			{
				if (harddiskVolumePath == resolvedPath)
					return partitionPath;
			}
			else if (partNumber == 0)
				break;
		}
	}

	return wstring();
}

#endif

BOOL IsApplicationInstalled (const wchar_t *appName, BOOL b32bitApp)
{
	const wchar_t *uninstallRegName = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
	BOOL installed = FALSE;
	HKEY unistallKey;
	LONG res = RegOpenKeyEx (HKEY_LOCAL_MACHINE, uninstallRegName, 0, KEY_READ | (b32bitApp? KEY_WOW64_32KEY: KEY_WOW64_64KEY), &unistallKey);
	if (res != ERROR_SUCCESS)
	{
		SetLastError (res);
		return FALSE;
	}

	wchar_t regName[1024];
	DWORD regNameSize = sizeof (regName);
	DWORD index = 0;
	while (RegEnumKeyEx (unistallKey, index++, regName, &regNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		if (wcsstr (regName, L"{") == regName)
		{
			regNameSize = sizeof (regName);
			if (!ReadLocalMachineRegistryStringNonReflected ((wstring (uninstallRegName) + L"\\" + regName).c_str(), L"DisplayName", regName, &regNameSize, b32bitApp))
				regName[0] = 0;
		}

		if (_wcsicmp (regName, appName) == 0)
		{
			installed = TRUE;
			break;
		}

		regNameSize = sizeof (regName);
	}

	RegCloseKey (unistallKey);
	return installed;
}


std::wstring FindLatestFileOrDirectory (const std::wstring &directory, const wchar_t *namePattern, bool findDirectory, bool findFile)
{
	wstring name;
	ULARGE_INTEGER latestTime;
	latestTime.QuadPart = 0;
	WIN32_FIND_DATA findData;

	HANDLE find = FindFirstFile ((directory + L"\\" + namePattern).c_str(), &findData);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (wcscmp (findData.cFileName, L".") == 0 || wcscmp (findData.cFileName, L"..") == 0)
				continue;

			ULARGE_INTEGER writeTime;
			writeTime.LowPart = findData.ftLastWriteTime.dwLowDateTime;
			writeTime.HighPart = findData.ftLastWriteTime.dwHighDateTime;

			if ((!findFile && !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				|| (!findDirectory && (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)))
				continue;

			if (latestTime.QuadPart < writeTime.QuadPart)
			{
				latestTime = writeTime;
				name = findData.cFileName;
			}
		}
		while (FindNextFile (find, &findData));

		FindClose (find);
	}

	if (name.empty())
		return name;

	return wstring (directory) + L"\\" + name;
}

int GetPim (HWND hwndDlg, UINT ctrlId, int defaultPim)
{
	int pim = defaultPim;
	HWND hCtrl = GetDlgItem (hwndDlg, ctrlId);
	if (IsWindowEnabled (hCtrl) && IsWindowVisible (hCtrl))
	{
		wchar_t szTmp[MAX_PIM + 1] = {0};
		if (GetDlgItemText (hwndDlg, ctrlId, szTmp, MAX_PIM + 1) > 0)
		{
			wchar_t* endPtr = NULL;
			pim = wcstol(szTmp, &endPtr, 10);
			if (pim < 0 || endPtr == szTmp || !endPtr || *endPtr != L'\0')
				pim = defaultPim;
		}
	}
	return pim;
}

void SetPim (HWND hwndDlg, UINT ctrlId, int pim)
{
	if (pim > 0)
	{
		wchar_t szTmp[MAX_PIM + 1];
		StringCbPrintfW (szTmp, sizeof(szTmp), L"%d", pim);
		SetDlgItemText (hwndDlg, ctrlId, szTmp);
	}
	else
		SetDlgItemText (hwndDlg, ctrlId, L"");
}

BOOL GetPassword (HWND hwndDlg, UINT ctrlID, char* passValue, int bufSize, BOOL bShowError)
{
	wchar_t tmp [MAX_PASSWORD + 1];
	int utf8Len;
	BOOL bRet = FALSE;

	GetWindowText (GetDlgItem (hwndDlg, ctrlID), tmp, ARRAYSIZE (tmp));
	utf8Len = WideCharToMultiByte (CP_UTF8, 0, tmp, -1, passValue, bufSize, NULL, NULL);
	burn (tmp, sizeof (tmp));
	if (utf8Len > 0)
	{
		bRet = TRUE;
	}
	else
	{
		passValue [0] = 0;
		if (bShowError)
		{
			SetFocus (GetDlgItem(hwndDlg, ctrlID));
			if (GetLastError () == ERROR_INSUFFICIENT_BUFFER)
				Error ("PASSWORD_UTF8_TOO_LONG", hwndDlg);
			else
				Error ("PASSWORD_UTF8_INVALID", hwndDlg);
		}
	}

	return bRet;
}

void SetPassword (HWND hwndDlg, UINT ctrlID, char* passValue)
{
	wchar_t tmp [MAX_PASSWORD + 1] = {0};
	MultiByteToWideChar (CP_UTF8, 0, passValue, -1, tmp, MAX_PASSWORD + 1);
	SetWindowText ( GetDlgItem (hwndDlg, ctrlID), tmp);
	burn (tmp, sizeof (tmp));
}

void HandleShowPasswordFieldAction (HWND hwndDlg, UINT checkBoxId, UINT edit1Id, UINT edit2Id)
{
	if ((EditPasswordChar == 0) && GetCheckBox (hwndDlg, checkBoxId))
	{
		EditPasswordChar = (WCHAR) SendMessageW (GetDlgItem (hwndDlg, edit1Id), EM_GETPASSWORDCHAR, 0, 0);
	}

	SendMessageW (GetDlgItem (hwndDlg, edit1Id),
		EM_SETPASSWORDCHAR,
		GetCheckBox (hwndDlg, checkBoxId) ? 0 : EditPasswordChar,
		0);
	InvalidateRect (GetDlgItem (hwndDlg, edit1Id), NULL, TRUE);

	if (edit2Id)
	{
		SendMessageW (GetDlgItem (hwndDlg, edit2Id),
			EM_SETPASSWORDCHAR,
			GetCheckBox (hwndDlg, checkBoxId) ? 0 : EditPasswordChar,
			0);
		InvalidateRect (GetDlgItem (hwndDlg, edit2Id), NULL, TRUE);
	}
}

void RegisterDriverInf (bool registerFilter, const string& filter, const string& filterReg, HWND ParentWindow, HKEY regKey)
{
	wstring infFileName = GetTempPathString() + L"\\veracrypt_driver_setup.inf";

	File infFile (infFileName, false, true);
	finally_do_arg (wstring, infFileName, { DeleteFile (finally_arg.c_str()); });

	string infTxt = "[veracrypt]\r\n"
					+ string (registerFilter ? "Add" : "Del") + "Reg=veracrypt_reg\r\n\r\n"
					"[veracrypt_reg]\r\n"
					"HKR,,\"" + filterReg + "\",0x0001" + string (registerFilter ? "0008" : "8002") + ",\"" + filter + "\"\r\n";

	infFile.Write ((byte *) infTxt.c_str(), (DWORD) infTxt.size());
	infFile.Close();

	HINF hInf = SetupOpenInfFileWFn (infFileName.c_str(), NULL, INF_STYLE_OLDNT | INF_STYLE_WIN4, NULL);
	throw_sys_if (hInf == INVALID_HANDLE_VALUE);
	finally_do_arg (HINF, hInf, { SetupCloseInfFileFn (finally_arg); });

	throw_sys_if (!SetupInstallFromInfSectionWFn (ParentWindow, hInf, L"veracrypt", SPINST_REGISTRY, regKey, NULL, 0, NULL, NULL, NULL, NULL));
}

HKEY OpenDeviceClassRegKey (const GUID *deviceClassGuid)
{
	return SetupDiOpenClassRegKeyFn (deviceClassGuid, KEY_READ | KEY_WRITE);
}

LSTATUS DeleteRegistryKey (HKEY hKey, LPCTSTR keyName)
{
	return SHDeleteKeyWFn(hKey, keyName);
}

HIMAGELIST  CreateImageList(int cx, int cy, UINT flags, int cInitial, int cGrow)
{
	return ImageList_CreateFn(cx, cy, flags, cInitial, cGrow);
}

int AddBitmapToImageList(HIMAGELIST himl, HBITMAP hbmImage, HBITMAP hbmMask)
{
	return ImageList_AddFn(himl, hbmImage, hbmMask);
}

HRESULT VCStrDupW(LPCWSTR psz, LPWSTR *ppwsz)
{
	return SHStrDupWFn (psz, ppwsz);
}


void ProcessEntropyEstimate (HWND hProgress, DWORD* pdwInitialValue, DWORD dwCounter, DWORD dwMaxLevel, DWORD* pdwEntropy)
{
	/* conservative estimate: 1 mouse move event brings 1 bit of entropy
	 * https://security.stackexchange.com/questions/32844/for-how-much-time-should-i-randomly-move-the-mouse-for-generating-encryption-key/32848#32848
	 */
	if (*pdwEntropy == 0xFFFFFFFF)
	{
		*pdwInitialValue = dwCounter;
		*pdwEntropy = 0;
	}
	else
	{
		if (	*pdwEntropy < dwMaxLevel
			&& (dwCounter >= *pdwInitialValue)
			&& (dwCounter - *pdwInitialValue) <= dwMaxLevel)
			*pdwEntropy = dwCounter - *pdwInitialValue;
		else
			*pdwEntropy = dwMaxLevel;

		if (IsOSAtLeast (WIN_VISTA))
		{
			int state = PBST_ERROR;
			if (*pdwEntropy >= (dwMaxLevel/2))
				state = PBST_NORMAL;
			else if (*pdwEntropy >= (dwMaxLevel/4))
				state = PBST_PAUSED;

			SendMessage (hProgress, PBM_SETSTATE, state, 0);
		}

		SendMessage (hProgress, PBM_SETPOS,
		(WPARAM) (*pdwEntropy),
		0);
	}
}

void AllowMessageInUIPI (UINT msg)
{
	if (ChangeWindowMessageFilterFn)
	{
		ChangeWindowMessageFilterFn (msg, MSGFLT_ADD);
	}
}

BOOL IsRepeatedByteArray (byte value, const byte* buffer, size_t bufferSize)
{
	if (buffer && bufferSize)
	{
		size_t i;
		for (i = 0; i < bufferSize; i++)
		{
			if (*buffer++ != value)
				return FALSE;
		}
		return TRUE;
	}
	else
		return FALSE;
}

#ifndef SETUP

BOOL TranslateVolumeID (HWND hwndDlg, wchar_t* pathValue, size_t cchPathValue)
{
	BOOL bRet = TRUE;
	size_t pathLen = pathValue? wcslen (pathValue) : 0;
	if ((pathLen >= 3) && (_wcsnicmp (pathValue, L"ID:", 3) == 0))
	{
		std::vector<byte> arr;
		if (	(pathLen == (3 + 2*VOLUME_ID_SIZE))
			&& HexWideStringToArray (pathValue + 3, arr)
			&& (arr.size() == VOLUME_ID_SIZE)
			)
		{
			std::wstring devicePath = FindDeviceByVolumeID (&arr[0]);
			if (devicePath.length() > 0)
				StringCchCopyW (pathValue, cchPathValue, devicePath.c_str());
			else
			{
				if (!Silent && !MultipleMountOperationInProgress)
					Error ("VOLUME_ID_NOT_FOUND", hwndDlg);
				SetLastError (ERROR_PATH_NOT_FOUND);
				bRet = FALSE;
			}
		}
		else
		{
			if (!Silent)
				Error ("VOLUME_ID_INVALID", hwndDlg);

			SetLastError (ERROR_INVALID_PARAMETER);
			bRet = FALSE;
		}
	}

	return bRet;
}

#endif

BOOL CopyTextToClipboard (LPCWSTR txtValue)
{
	size_t txtLen = wcslen(txtValue);
	HGLOBAL hdst;
	LPWSTR dst;
	BOOL bRet = FALSE;

	// Allocate string for cwd
	hdst = GlobalAlloc(GMEM_MOVEABLE, (txtLen + 1) * sizeof(WCHAR));
	if (hdst)
	{
		dst = (LPWSTR)GlobalLock(hdst);
		wmemcpy(dst, txtValue, txtLen + 1);
		GlobalUnlock(hdst);

		if (OpenClipboard(NULL))
		{
			EmptyClipboard();
			SetClipboardData(CF_UNICODETEXT, hdst);
			CloseClipboard();
		}
	}

	return bRet;
}

BOOL GetFreeDriveLetter(WCHAR* pCh) {
	DWORD dwUsedDrives = GetLogicalDrives();
	WCHAR l;
	for (l = L'A'; l <= L'Z'; l++) {
		if ((dwUsedDrives & 1) == 0) {
			*pCh = l;
			return TRUE;
		}
		dwUsedDrives = dwUsedDrives >> 1;
	}
	return FALSE;
}

BOOL RaisePrivileges(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	BOOL bRet = FALSE;
	DWORD dwLastError = 0;

	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME,
				&tkp.Privileges[0].Luid))
		{
			DWORD len;
			
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			
			bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, &len);
			if (!bRet)
				dwLastError = GetLastError ();
		}
		else
			dwLastError = GetLastError ();

		CloseHandle(hToken);
	}
	else
		dwLastError = GetLastError ();

	SetLastError (dwLastError);

	return bRet;
}

BOOL DeleteDirectory (const wchar_t* szDirName)
{
	BOOL bStatus = RemoveDirectory (szDirName);
	if (!bStatus)
	{
		/* force removal of the non empty directory */
		wchar_t szOpPath[TC_MAX_PATH + 1] = {0};
		SHFILEOPSTRUCTW op;

		StringCchCopyW(szOpPath, ARRAYSIZE(szOpPath)-1, szDirName);
		ZeroMemory(&op, sizeof(op));
		op.wFunc = FO_DELETE;
		op.pFrom = szOpPath;
		op.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR;

		if ((0 == SHFileOperation(&op)) && (!op.fAnyOperationsAborted))
			bStatus = TRUE;
	}
	return bStatus;
}

#if defined (TCMOUNT) || defined (VOLFORMAT)
/*********************************************************************/

static BOOL GenerateRandomString (HWND hwndDlg, LPTSTR szName, DWORD maxCharsCount)
{
	BOOL bRet = FALSE;
	if (Randinit () != ERR_SUCCESS) 
	{
		handleError (hwndDlg, (CryptoAPILastError == ERROR_SUCCESS)? ERR_RAND_INIT_FAILED : ERR_CAPI_INIT_FAILED, SRC_POS);
	}
	else
	{
		BYTE* indexes = (BYTE*) malloc (maxCharsCount + 1);
		bRet = RandgetBytesFull (hwndDlg, indexes, maxCharsCount + 1, TRUE, TRUE); 
		if (bRet)
		{
			static LPCTSTR chars = _T("0123456789@#$%^&_-*abcdefghijklmnopqrstuvwxyz");
			DWORD i, charsLen = (DWORD) _tcslen (chars);
			DWORD effectiveLen = (indexes[0] % (64 - 16)) + 16; // random length between 16 to 64
			effectiveLen = (effectiveLen > maxCharsCount)? maxCharsCount : effectiveLen;

			for (i = 0; i < effectiveLen; i++)
			{
				szName[i] = chars[indexes[i + 1] % charsLen];
			}

			szName[effectiveLen] = 0;
		}
		burn (indexes, maxCharsCount + 1);
		free (indexes);
	}

	return bRet;
}

typedef struct
{
	HDESK hDesk;
	HINSTANCE hInstance;
	LPCWSTR lpTemplateName;
	DLGPROC lpDialogFunc;
	LPARAM dwInitParam;
	INT_PTR retValue;
} SecureDesktopThreadParam;

static DWORD WINAPI SecureDesktopThread(LPVOID lpThreadParameter)
{
	SecureDesktopThreadParam* pParam = (SecureDesktopThreadParam*) lpThreadParameter;

	SetThreadDesktop (pParam->hDesk);
	SwitchDesktop (pParam->hDesk);

	pParam->retValue = DialogBoxParamW (pParam->hInstance, pParam->lpTemplateName, 
						NULL, pParam->lpDialogFunc, pParam->dwInitParam);

	return 0;
}

static void GetCtfMonProcessIdList (map<DWORD, BOOL>& processIdList)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pEntry;
	BOOL hRes;

	pEntry.dwSize = sizeof (pEntry);
	processIdList.clear();
	hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		LPTSTR szFileName = PathFindFileName (pEntry.szExeFile);
		if (_wcsicmp(szFileName, L"ctfmon.exe") == 0)
		{
			processIdList[pEntry.th32ProcessID] = TRUE;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

static void KillProcess (DWORD dwProcessId)
{
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, dwProcessId);
	if (hProcess != NULL)
	{
		TerminateProcess(hProcess, (UINT) -1);
		CloseHandle(hProcess);
	}
}

INT_PTR SecureDesktopDialogBoxParam(
    HINSTANCE hInstance,
    LPCWSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
	TCHAR szDesktopName[65] = {0};
	BOOL bSuccess = FALSE;
	INT_PTR retValue = 0;
	BOOL bEffectiveUseSecureDesktop = bCmdUseSecureDesktopValid? bCmdUseSecureDesktop : bUseSecureDesktop;

	if (bEffectiveUseSecureDesktop && GenerateRandomString (hWndParent, szDesktopName, 64))
	{
		map<DWORD, BOOL> ctfmonBeforeList, ctfmonAfterList;
		DWORD desktopAccess = DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | DESKTOP_WRITEOBJECTS;
		HDESK hSecureDesk;
		
		// get the initial list of ctfmon.exe processes before creating new desktop
		GetCtfMonProcessIdList (ctfmonBeforeList);

		hSecureDesk = CreateDesktop (szDesktopName, NULL, NULL, 0, desktopAccess, NULL);
		if (hSecureDesk)
		{
			HDESK hOriginalDesk = GetThreadDesktop (GetCurrentThreadId ());
			SecureDesktopThreadParam param;
	
			param.hDesk = hSecureDesk;
			param.hInstance = hInstance;
			param.lpTemplateName = lpTemplateName;
			param.lpDialogFunc = lpDialogFunc;
			param.dwInitParam = dwInitParam;
			param.retValue = 0;

			HANDLE hThread = ::CreateThread (NULL, 0, SecureDesktopThread, (LPVOID) &param, 0, NULL);
			if (hThread)
			{
				WaitForSingleObject (hThread, INFINITE);
				CloseHandle (hThread);

				SwitchDesktop (hOriginalDesk);
				SetThreadDesktop (hOriginalDesk);

				retValue = param.retValue;
				bSuccess = TRUE;
			}

			CloseDesktop (hSecureDesk);

			// get the new list of ctfmon.exe processes in order to find the ID of the
			// ctfmon.exe instance that corresponds to the desktop we create so that
			// we can kill it, otherwise it would remain running
			GetCtfMonProcessIdList (ctfmonAfterList);

			for (map<DWORD, BOOL>::iterator It = ctfmonAfterList.begin(); 
				It != ctfmonAfterList.end(); It++)
			{
				if (ctfmonBeforeList[It->first] != TRUE)
				{
					// Kill process
					KillProcess (It->first);
				}
			}
		}

		burn (szDesktopName, sizeof (szDesktopName));
	}

	if (!bSuccess)
	{
		// fallback to displaying in normal desktop
		retValue = DialogBoxParamW (hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam);
	}

	return retValue;
}

#endif
