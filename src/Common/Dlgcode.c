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

#include <windowsx.h>
#include <dbghelp.h>
#include <dbt.h>
#include <fcntl.h>
#include <io.h>
#include <math.h>
#include <shlobj.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>

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

#ifdef TCMOUNT
#include "Mount/Mount.h"
#endif

#ifdef VOLFORMAT
#include "Format/Tcformat.h"
#endif

#ifdef SETUP
#include "Setup/Setup.h"
#endif

using namespace VeraCrypt;

LONG DriverVersion;

char *LastDialogId;
char szHelpFile[TC_MAX_PATH];
char szHelpFile2[TC_MAX_PATH];
char SecurityTokenLibraryPath[TC_MAX_PATH];

HFONT hFixedDigitFont = NULL;
HFONT hBoldFont = NULL;
HFONT hTitleFont = NULL;
HFONT hFixedFont = NULL;

HFONT hUserFont = NULL;
HFONT hUserUnderlineFont = NULL;
HFONT hUserBoldFont = NULL;
HFONT hUserUnderlineBoldFont = NULL;

HFONT WindowTitleBarFont;

int ScreenDPI = USER_DEFAULT_SCREEN_DPI;
double DPIScaleFactorX = 1;
double DPIScaleFactorY = 1;
double DlgAspectRatio = 1;

HWND MainDlg = NULL;
wchar_t *lpszTitle = NULL;

BOOL Silent = FALSE;
BOOL bPreserveTimestamp = TRUE;
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
BOOL KeyFilesEnable = FALSE;
KeyFile	*FirstKeyFile = NULL;
KeyFilesDlgParam		defaultKeyFilesParam;

BOOL IgnoreWmDeviceChange = FALSE;
BOOL DeviceChangeBroadcastDisabled = FALSE;
BOOL LastMountedVolumeDirty;
BOOL MountVolumesAsSystemFavorite = FALSE;
BOOL FavoriteMountOnArrivalInProgress = FALSE;
BOOL MultipleMountOperationInProgress = FALSE;

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
char SysPartitionDevicePath [TC_MAX_PATH];
char SysDriveDevicePath [TC_MAX_PATH];
string ExtraBootPartitionDevicePath;
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

/* Windows dialog class */
#define WINDOWS_DIALOG_CLASS "#32770"

/* Custom class names */
#define TC_DLG_CLASS "CustomDlg"
#define TC_SPLASH_CLASS "SplashDlg"

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
	BENCHMARK_SORT_BY_NAME = 0,
	BENCHMARK_SORT_BY_SPEED
};

typedef struct 
{
	int id;
	char name[100];
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

#endif	// #ifndef SETUP


typedef struct 
{
	void *strings;
	BOOL bold;

} MULTI_CHOICE_DLGPROC_PARAMS;


void cleanup ()
{
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
		UnregisterClass (TC_DLG_CLASS, hInst);
	if (hSplashClass)
		UnregisterClass (TC_SPLASH_CLASS, hInst);

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
}


void LowerCaseCopy (char *lpszDest, const char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) tolower (lpszSource[i]);
	}

}

void UpperCaseCopy (char *lpszDest, const char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) toupper (lpszSource[i]);
	}
}


std::string ToUpperCase (const std::string &str)
{
	string u;
	foreach (char c, str)
	{
		u += (char) toupper (c);
	}

	return u;
}


BOOL IsVolumeDeviceHosted (const char *lpszDiskFile)
{
	return strstr (lpszDiskFile, "\\Device\\") == lpszDiskFile
		|| strstr (lpszDiskFile, "\\DEVICE\\") == lpszDiskFile;
}


void CreateFullVolumePath (char *lpszDiskFile, const char *lpszFileName, BOOL * bDevice)
{
	UpperCaseCopy (lpszDiskFile, lpszFileName);

	*bDevice = FALSE;

	if (memcmp (lpszDiskFile, "\\DEVICE", sizeof (char) * 7) == 0)
	{
		*bDevice = TRUE;
	}

	strcpy (lpszDiskFile, lpszFileName);

#if _DEBUG
	OutputDebugString ("CreateFullVolumePath: ");
	OutputDebugString (lpszDiskFile);
	OutputDebugString ("\n");
#endif

}

int FakeDosNameForDevice (const char *lpszDiskFile, char *lpszDosDevice, char *lpszCFDevice, BOOL bNameOnly)
{
	BOOL bDosLinkCreated = TRUE;
	sprintf (lpszDosDevice, "veracrypt%lu", GetCurrentProcessId ());

	if (bNameOnly == FALSE)
		bDosLinkCreated = DefineDosDevice (DDD_RAW_TARGET_PATH, lpszDosDevice, lpszDiskFile);

	if (bDosLinkCreated == FALSE)
		return ERR_OS_ERROR;
	else
		sprintf (lpszCFDevice, "\\\\.\\%s", lpszDosDevice);

	return 0;
}

int RemoveFakeDosName (char *lpszDiskFile, char *lpszDosDevice)
{
	BOOL bDosLinkRemoved = DefineDosDevice (DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE |
			DDD_REMOVE_DEFINITION, lpszDosDevice, lpszDiskFile);
	if (bDosLinkRemoved == FALSE)
	{
		return ERR_OS_ERROR;
	}

	return 0;
}


void AbortProcess (char *stringId)
{
	// Note that this function also causes localcleanup() to be called (see atexit())
	MessageBeep (MB_ICONEXCLAMATION);
	MessageBoxW (NULL, GetString (stringId), lpszTitle, ICON_HAND);
	exit (1);
}

void AbortProcessSilent (void)
{
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
	int j = (strlen (lpszText) + 1) * sizeof (char);
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


DWORD handleWin32Error (HWND hwndDlg)
{
	PWSTR lpMsgBuf;
	DWORD dwError = GetLastError ();

	if (Silent || dwError == 0 || dwError == ERROR_INVALID_WINDOW_HANDLE)
		return dwError;

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		Error ("ERR_ACCESS_DENIED");
		SetLastError (dwError);		// Preserve the original error code
		return dwError;
	}

	FormatMessageW (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			      NULL,
			      dwError,
			      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
			      (PWSTR) &lpMsgBuf,
			      0,
			      NULL
	    );

	MessageBoxW (hwndDlg, lpMsgBuf, lpszTitle, ICON_HAND);
	LocalFree (lpMsgBuf);

	// User-friendly hardware error explanation
	if (IsDiskError (dwError))
		Error ("ERR_HARDWARE_ERROR");

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		HandleDriveNotReadyError();

	SetLastError (dwError);		// Preserve the original error code

	return dwError;
}

BOOL translateWin32Error (wchar_t *lpszMsgBuf, int nWSizeOfBuf)
{
	DWORD dwError = GetLastError ();

	if (FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError,
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

	GetTextExtentPoint32W (hdc, text, wcslen (text), &sizes);

	GetTextMetrics(hdc, &textMetrics);	// Necessary for non-TrueType raster fonts (tmOverhang)

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cx - (int) textMetrics.tmOverhang);
}


int GetTextGfxHeight (HWND hwndDlgItem, const wchar_t *text, HFONT hFont)
{
	SIZE sizes;
	HDC hdc = GetDC (hwndDlgItem); 

	SelectObject(hdc, (HGDIOBJ) hFont);

	GetTextExtentPoint32W (hdc, text, wcslen (text), &sizes);

	ReleaseDC (hwndDlgItem, hdc); 

	return ((int) sizes.cy);
}


std::string FitPathInGfxWidth (HWND hwnd, HFONT hFont, LONG width, const std::string &path)
{
	string newPath;

	RECT rect;
	rect.left = 0;
	rect.top = 0;
	rect.right = width;
	rect.bottom = LONG_MAX;

	HDC hdc = GetDC (hwnd); 
	SelectObject (hdc, (HGDIOBJ) hFont);

	char pathBuf[TC_MAX_PATH];
	strcpy_s (pathBuf, sizeof (pathBuf), path.c_str());

	if (DrawText (hdc, pathBuf, path.size(), &rect, DT_CALCRECT | DT_MODIFYSTRING | DT_PATH_ELLIPSIS | DT_SINGLELINE) != 0)
		newPath = pathBuf;

	ReleaseDC (hwnd, hdc); 
	return newPath;
}


static LRESULT CALLBACK HyperlinkProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtr (hwnd, GWLP_USERDATA);

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

	return CallWindowProc (wp, hwnd, message, wParam, lParam);
}


BOOL ToHyperlink (HWND hwndDlg, UINT ctrlId)
{
	return ToCustHyperlink (hwndDlg, ctrlId, hUserUnderlineFont);
}


BOOL ToCustHyperlink (HWND hwndDlg, UINT ctrlId, HFONT hFont)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SendMessage (hwndCtrl, WM_SETFONT, (WPARAM) hFont, 0);

	SetWindowLongPtr (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtr (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtr (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) HyperlinkProc);

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
	BOOL bBorderlessWindow = !(GetWindowLongPtr (hwndDlg, GWL_STYLE) & (WS_BORDER | WS_DLGFRAME));

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


// Protects an input field from having its content updated by a Paste action (call ToBootPwdField() to use this).
static LRESULT CALLBACK BootPwdFieldProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC wp = (WNDPROC) GetWindowLongPtr (hwnd, GWLP_USERDATA);

	switch (message)
	{
	case WM_PASTE:
		return 1;
	}

	return CallWindowProc (wp, hwnd, message, wParam, lParam);
}


// Protects an input field from having its content updated by a Paste action. Used for pre-boot password
// input fields (only the US keyboard layout is supported in pre-boot environment so we must prevent the 
// user from pasting a password typed using a non-US keyboard layout).
void ToBootPwdField (HWND hwndDlg, UINT ctrlId)
{
	HWND hwndCtrl = GetDlgItem (hwndDlg, ctrlId);

	SetWindowLongPtr (hwndCtrl, GWLP_USERDATA, (LONG_PTR) GetWindowLongPtr (hwndCtrl, GWLP_WNDPROC));
	SetWindowLongPtr (hwndCtrl, GWLP_WNDPROC, (LONG_PTR) BootPwdFieldProc);
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

			ScreenDPI = GetDeviceCaps (hDC, LOGPIXELSY);
			ReleaseDC (hwndDlg, hDC); 

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
			char szTmp[100];
			RECT rec;

			LocalizeDialog (hwndDlg, "IDD_ABOUT_DLG");

			// Hyperlink
			SetWindowText (GetDlgItem (hwndDlg, IDC_HOMEPAGE), "www.idrix.fr");
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
			sprintf (szTmp, "VeraCrypt %s", VERSION_STRING);
#if (defined(_DEBUG) || defined(DEBUG))
			strcat (szTmp, "  (debug)");
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
			"Based on TrueCrypt, freely available at http://www.truecrypt.org/ .\r\n\r\n"

			"Portions of this software:\r\n"
			"Copyright \xA9 2003-2012 TrueCrypt Developers Association. All Rights Reserved.\r\n"
			"Copyright \xA9 1998-2000 Paul Le Roux. All Rights Reserved.\r\n"
			"Copyright \xA9 1998-2008 Brian Gladman. All Rights Reserved.\r\n"
			"Copyright \xA9 2002-2004 Mark Adler. All Rights Reserved.\r\n\r\n"

			"This software as a whole:\r\n"
			"Copyright \xA9 2013 IDRIX. All rights reserved.\r\n\r\n"

			"An IDRIX Release");

		return 1;

	case WM_COMMAND:
		if (lw == IDOK || lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}

		if (lw == IDC_HOMEPAGE)
		{
			Applink ("main", TRUE, "");
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


void LeftPadString (char *szTmp, int len, int targetLen, char filler)
{
	int i;

	if (targetLen <= len)
		return;

	for (i = targetLen-1; i >= (targetLen-len); i--)
		szTmp [i] = szTmp [i-(targetLen-len)];

	memset (szTmp, filler, targetLen-len);
	szTmp [targetLen] = 0;
}


/*****************************************************************************
  ToSBCS: converts a unicode string to Single Byte Character String (SBCS).
  ***************************************************************************/

void ToSBCS (LPWSTR lpszText)
{
	int j = wcslen (lpszText);
	if (j == 0)
	{
		strcpy ((char *) lpszText, "");
		return;
	}
	else
	{
		char *lpszNewText = (char *) err_malloc (j + 1);
		j = WideCharToMultiByte (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1, NULL, NULL);
		if (j > 0)
			strcpy ((char *) lpszText, lpszNewText);
		else
			strcpy ((char *) lpszText, "");
		free (lpszNewText);
	}
}

/*****************************************************************************
  ToUNICODE: converts a SBCS string to a UNICODE string.
  ***************************************************************************/

void ToUNICODE (char *lpszText)
{
	int j = strlen (lpszText);
	if (j == 0)
	{
		wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		return;
	}
	else
	{
		LPWSTR lpszNewText = (LPWSTR) err_malloc ((j + 1) * 2);
		j = MultiByteToWideChar (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1);
		if (j > 0)
			wcscpy ((LPWSTR) lpszText, lpszNewText);
		else
			wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		free (lpszNewText);
	}
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
		wcsncpy ((WCHAR *)metric.lfMessageFont.lfFaceName, font->FaceName, sizeof (metric.lfMessageFont.lfFaceName)/2);
	}
	else if (IsOSAtLeast (WIN_VISTA))
	{
		// Vista's new default font (size and spacing) breaks compatibility with Windows 2k/XP applications.
		// Force use of Tahoma (as Microsoft does in many dialogs) until a native Vista look is implemented.
		wcsncpy ((WCHAR *)metric.lfMessageFont.lfFaceName, L"Tahoma", sizeof (metric.lfMessageFont.lfFaceName)/2);
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
	wcscpy (lf.lfFaceName, L"Courier New");
	hFixedDigitFont = CreateFontIndirectW (&lf);
	if (hFixedDigitFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Bold
	font = GetFont ("font_bold");

	nHeight = CompensateDPIFont (!font ? -13 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_BLACK;
	wcsncpy (lf.lfFaceName, !font ? L"Arial" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hBoldFont = CreateFontIndirectW (&lf);
	if (hBoldFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	// Title
	font = GetFont ("font_title");

	nHeight = CompensateDPIFont (!font ? -21 : -font->Size);
	lf.lfHeight = nHeight;
	lf.lfWeight = FW_REGULAR;
	wcsncpy (lf.lfFaceName, !font ? L"Times New Roman" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hTitleFont = CreateFontIndirectW (&lf);
	if (hTitleFont == NULL)
	{
		handleWin32Error (hwndDlg);
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
	wcsncpy (lf.lfFaceName, !font ? L"Lucida Console" : font->FaceName, sizeof (lf.lfFaceName)/2);
	hFixedFont = CreateFontIndirectW (&lf);
	if (hFixedFont == NULL)
	{
		handleWin32Error (hwndDlg);
		AbortProcess ("NOFONT");
	}

	if (!aboutMenuAppended)
	{
		hMenu = GetSystemMenu (hwndDlg, FALSE);
		AppendMenu (hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenuW (hMenu, MF_ENABLED | MF_STRING, IDC_ABOUT, GetString ("ABOUTBOX"));

		aboutMenuAppended = TRUE;
	}
}


// The parameter maxMessagesToProcess prevents endless processing of paint messages
void ProcessPaintMessages (HWND hwnd, int maxMessagesToProcess)
{
	MSG paintMsg;
	int msgCounter = maxMessagesToProcess;	

	while (PeekMessage (&paintMsg, hwnd, 0, 0, PM_REMOVE | PM_QS_PAINT) != 0 && msgCounter-- > 0)
	{
		DispatchMessage (&paintMsg);
	}
}


HDC CreateMemBitmap (HINSTANCE hInstance, HWND hwnd, char *resource)
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
HBITMAP RenderBitmap (char *resource, HWND hwndDest, int x, int y, int nWidth, int nHeight, BOOL bDirectRender, BOOL bKeepAspectRatio)
{
	LRESULT lResult = 0;

	HDC hdcSrc = CreateMemBitmap (hInst, hwndDest, resource);

	HGDIOBJ picture = GetCurrentObject (hdcSrc, OBJ_BITMAP);

	HBITMAP hbmpRescaled;
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

		BitBlt (hdcDest, x, y, nWidth, nHeight, hdcRescaled, 0, 0, SRCCOPY);
		ReleaseDC (hwndDest, hdcDest);
	}
	else
	{
		lResult = SendMessage (hwndDest, (UINT) STM_SETIMAGE, (WPARAM) IMAGE_BITMAP, (LPARAM) (HANDLE) hbmpRescaled);
	}

	if ((HGDIOBJ) lResult != NULL && (HGDIOBJ) lResult != (HGDIOBJ) hbmpRescaled)
		DeleteObject ((HGDIOBJ) lResult);

	DeleteDC (hdcRescaled);

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
				return DefWindowProc (hwnd, uMsg, wParam, lParam);
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

	return DefWindowProc (hwnd, uMsg, wParam, lParam);
}

BOOL
RegisterRedTick (HINSTANCE hInstance)
{
  WNDCLASS wc;
  ULONG rc;

  memset(&wc, 0 , sizeof wc);

  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.cbClsExtra = 0;
  wc.cbWndExtra = 4;
  wc.hInstance = hInstance;
  wc.hIcon = LoadIcon (NULL, IDI_APPLICATION);
  wc.hCursor = NULL;
  wc.hbrBackground = (HBRUSH) GetStockObject (LTGRAY_BRUSH);
  wc.lpszClassName = "REDTICK";
  wc.lpfnWndProc = &RedTick; 
  
  rc = (ULONG) RegisterClass (&wc);

  return rc == 0 ? FALSE : TRUE;
}

BOOL
UnregisterRedTick (HINSTANCE hInstance)
{
  return UnregisterClass ("REDTICK", hInstance);
}

LRESULT CALLBACK
SplashDlgProc (HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}

void
WaitCursor ()
{
	static HCURSOR hcWait;
	if (hcWait == NULL)
		hcWait = LoadCursor (NULL, IDC_WAIT);
	SetCursor (hcWait);
	hCursor = hcWait;
}

void
NormalCursor ()
{
	static HCURSOR hcArrow;
	if (hcArrow == NULL)
		hcArrow = LoadCursor (NULL, IDC_ARROW);
	SetCursor (hcArrow);
	hCursor = NULL;
}

void
ArrowWaitCursor ()
{
	static HCURSOR hcArrowWait;
	if (hcArrowWait == NULL)
		hcArrowWait = LoadCursor (NULL, IDC_APPSTARTING);
	SetCursor (hcArrowWait);
	hCursor = hcArrowWait;
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
AddComboPair (HWND hComboBox, const char *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
	nIndex = SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) value);
}

void
AddComboPairW (HWND hComboBox, const wchar_t *lpszItem, int value)
{
	LPARAM nIndex;

	nIndex = SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) lpszItem);
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

	*algo_id = SendMessage (hComboBox, CB_GETITEMDATA, 0, 0);

	SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

}

void PopulateWipeModeCombo (HWND hComboBox, BOOL bNA, BOOL bInPlaceEncryption)
{
	if (bNA)
	{
		AddComboPairW (hComboBox, GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE"), TC_WIPE_NONE);
	}
	else
	{
		if (bInPlaceEncryption)
			AddComboPairW (hComboBox, GetString ("WIPE_MODE_NONE"), TC_WIPE_NONE);
		else
			AddComboPairW (hComboBox, GetString ("WIPE_MODE_1_RAND"), TC_WIPE_1_RAND);

		AddComboPairW (hComboBox, GetString ("WIPE_MODE_3_DOD_5220"), TC_WIPE_3_DOD_5220);
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_7_DOD_5220"), TC_WIPE_7_DOD_5220);
		AddComboPairW (hComboBox, GetString ("WIPE_MODE_35_GUTMANN"), TC_WIPE_35_GUTMANN);
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

	default:
		return GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE");
	}
}

wchar_t *GetPathType (const char *path, BOOL bUpperCase, BOOL *bIsPartition)
{
	if (strstr (path, "Partition")
		&& strstr (path, "Partition0") == NULL)
	{
		*bIsPartition = TRUE;
		return GetString (bUpperCase ? "PARTITION_UPPER_CASE" : "PARTITION_LOWER_CASE");
	}
	else if (strstr (path, "HarddiskVolume"))
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

	return DefDlgProc (hwnd, uMsg, wParam, lParam);
}


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


typedef struct
{
	EXCEPTION_POINTERS *ExceptionPointers;
	HANDLE ExceptionThread;

} ExceptionHandlerThreadArgs;


void ExceptionHandlerThread (void *threadArg)
{
	ExceptionHandlerThreadArgs *args = (ExceptionHandlerThreadArgs *) threadArg;

	EXCEPTION_POINTERS *ep = args->ExceptionPointers;
	DWORD addr;
	DWORD exCode = ep->ExceptionRecord->ExceptionCode;
	SYSTEM_INFO si;
	// wchar_t msg[8192];
	char modPath[MAX_PATH];
	int crc = 0;
	// char url[MAX_URL_LENGTH];
	char lpack[128];
	stringstream callStack;
	addr = (DWORD) ep->ExceptionRecord->ExceptionAddress;
	PDWORD sp = (PDWORD) ep->ContextRecord->Esp;
	int frameNumber = 0;

	switch (exCode)
	{
	case STATUS_IN_PAGE_ERROR:
	case 0xeedfade:
		// Exception not caused by TrueCrypt
		MessageBoxW (0, GetString ("EXCEPTION_REPORT_EXT"),
			GetString ("EXCEPTION_REPORT_TITLE"),
			MB_ICONERROR | MB_OK | MB_SETFOREGROUND | MB_TOPMOST);
		return;
	}

	// Call stack
	HMODULE dbgDll = LoadLibrary ("dbghelp.dll");
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

	/*
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
	return DefWindowProc (hWnd, message, wParam, lParam);
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
BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name)
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
BOOL MutexExistsOnSystem (char *name)
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

	if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, &configMap))
		configMap = 0;

	return configMap;
}


uint32 ReadEncryptionThreadPoolFreeCpuCountLimit ()
{
	DWORD count;

	if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, &count))
		count = 0;

	return count;
}


BOOL LoadSysEncSettings (HWND hwndDlg)
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
		remove (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC));

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE)))
		remove (GetConfigPath (TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE));

	if (!IsNonInstallMode () && SystemEncryptionStatus == SYSENC_STATUS_NONE)
		ManageStartupSeqWiz (TRUE, "");
}


void SavePostInstallTasksSettings (int command)
{
	FILE *f = NULL;

	if (IsNonInstallMode() && command != TC_POST_INSTALL_CFG_REMOVE_ALL)
		return;

	switch (command)
	{
	case TC_POST_INSTALL_CFG_REMOVE_ALL:
		remove (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL));
		remove (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES));
		break;

	case TC_POST_INSTALL_CFG_TUTORIAL:
		f = fopen (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL), "w");
		break;

	case TC_POST_INSTALL_CFG_RELEASE_NOTES:
		f = fopen (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES), "w");
		break;

	default:
		return;
	}

	if (f == NULL)
		return;

	if (fputs ("1", f) < 0)
	{
		// Error
		fclose (f);
		return;
	}

	TCFlushFile (f);

	fclose (f);
}


void DoPostInstallTasks (void)
{
	BOOL bDone = FALSE;

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL)))
	{
		if (AskYesNo ("AFTER_INSTALL_TUTORIAL") == IDYES)
			Applink ("beginnerstutorial", TRUE, "");

		bDone = TRUE;
	}

	if (FileExists (GetConfigPath (TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES)))
	{
		if (AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES") == IDYES)
			Applink ("releasenotes", TRUE, "");

		bDone = TRUE;
	}

	if (bDone)
		SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_REMOVE_ALL);
}


void InitOSVersionInfo ()
{
	OSVERSIONINFO os;
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);

	if (GetVersionEx (&os) == FALSE)
		AbortProcess ("NO_OS_VER");

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 2)
	{
		OSVERSIONINFOEX osEx;

		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		GetVersionEx ((LPOSVERSIONINFOA) &osEx);

		if (osEx.wProductType == VER_NT_SERVER || osEx.wProductType == VER_NT_DOMAIN_CONTROLLER)
			nCurrentOS = WIN_SERVER_2003;
		else
			nCurrentOS = WIN_XP64;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 0)
	{
		OSVERSIONINFOEX osEx;

		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		GetVersionEx ((LPOSVERSIONINFOA) &osEx);

		if (osEx.wProductType == VER_NT_SERVER || osEx.wProductType == VER_NT_DOMAIN_CONTROLLER)
			nCurrentOS = WIN_SERVER_2008;
		else
			nCurrentOS = WIN_VISTA;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 1)
		nCurrentOS = (IsServerOS() ? WIN_SERVER_2008_R2 : WIN_7);
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


/* InitApp - initialize the application, this function is called once in the
   applications WinMain function, but before the main dialog has been created */
void InitApp (HINSTANCE hInstance, char *lpszCommandLine)
{
	WNDCLASS wc;
	char langId[6];
	char dllPath[MAX_PATH];

	/* Save the instance handle for later */
	hInst = hInstance;

	InitOSVersionInfo();

	SetErrorMode (SetErrorMode (0) | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
	CoInitialize (NULL);

#ifndef SETUP
	// Application ID
	typedef HRESULT (WINAPI *SetAppId_t) (PCWSTR appID);
	SetAppId_t setAppId = (SetAppId_t) GetProcAddress (GetModuleHandle ("shell32.dll"), "SetCurrentProcessExplicitAppUserModelID");

	if (setAppId)
		setAppId (TC_APPLICATION_ID);
#endif

	// Language
	langId[0] = 0;
	SetPreferredLangId (ConfigReadString ("Language", "", langId, sizeof (langId)));
	
	if (langId[0] == 0)
		DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_LANGUAGE), NULL,
			(DLGPROC) LanguageDlgProc, (LPARAM) 1);

	LoadLanguageFile ();

#ifndef SETUP
	// UAC elevation moniker cannot be used in portable mode.
	// A new instance of the application must be created with elevated privileges.
	if (IsNonInstallMode () && !IsAdmin () && IsUacSupported ())
	{
		char modPath[MAX_PATH], newCmdLine[4096];
		WNDCLASSEX wcex;
		HWND hWnd;

		if (strstr (lpszCommandLine, "/q UAC ") == lpszCommandLine)
		{
			Error ("UAC_INIT_ERROR");
			exit (1);
		}

		memset (&wcex, 0, sizeof (wcex));
		wcex.cbSize = sizeof(WNDCLASSEX); 
		wcex.lpfnWndProc = (WNDPROC) NonInstallUacWndProc;
		wcex.hInstance = hInstance;
		wcex.lpszClassName = "VeraCrypt";
		RegisterClassEx (&wcex);

		// A small transparent window is necessary to bring the new instance to foreground
		hWnd = CreateWindowEx (WS_EX_TOOLWINDOW | WS_EX_LAYERED,
			"VeraCrypt", "VeraCrypt", 0,
			GetSystemMetrics (SM_CXSCREEN)/2,
			GetSystemMetrics (SM_CYSCREEN)/2,
			1, 1, NULL, NULL, hInstance, NULL);

		SetLayeredWindowAttributes (hWnd, 0, 0, LWA_ALPHA);
		ShowWindow (hWnd, SW_SHOWNORMAL);

		GetModuleFileName (NULL, modPath, sizeof (modPath));

		strcpy (newCmdLine, "/q UAC ");
		strcat_s (newCmdLine, sizeof (newCmdLine), lpszCommandLine);

		if ((int)ShellExecute (hWnd, "runas", modPath, newCmdLine, NULL, SW_SHOWNORMAL) <= 32)
			exit (1);

		Sleep (2000);
		exit (0);
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
		OSVERSIONINFOEX osEx;

		// Service pack check & warnings about critical MS issues
		osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
		if (GetVersionEx ((LPOSVERSIONINFOA) &osEx) != 0)
		{
			CurrentOSServicePack = osEx.wServicePackMajor;
			switch (nCurrentOS)
			{
			case WIN_2000:
				if (osEx.wServicePackMajor < 3)
					Warning ("LARGE_IDE_WARNING_2K");
				else
				{
					DWORD val = 0, size = sizeof(val);
					HKEY hkey;

					if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Atapi\\Parameters", 0, KEY_READ, &hkey) == ERROR_SUCCESS
						&& (RegQueryValueEx (hkey, "EnableBigLba", 0, 0, (LPBYTE) &val, &size) != ERROR_SUCCESS
						|| val != 1))

					{
						Warning ("LARGE_IDE_WARNING_2K_REGISTRY");
					}
					RegCloseKey (hkey);
				}
				break;

			case WIN_XP:
				if (osEx.wServicePackMajor < 1)
				{
					HKEY k;
					// PE environment does not report version of SP
					if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\minint", 0, KEY_READ, &k) != ERROR_SUCCESS)
						Warning ("LARGE_IDE_WARNING_XP");
					else
						RegCloseKey (k);
				}
				break;
			}
		}
	}

	/* Get the attributes for the standard dialog class */
	if ((GetClassInfo (hInst, WINDOWS_DIALOG_CLASS, &wc)) == 0)
	{
		handleWin32Error (NULL);
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

	hDlgClass = RegisterClass (&wc);
	if (hDlgClass == 0)
	{
		handleWin32Error (NULL);
		AbortProcess ("INIT_REGISTER");
	}

	wc.lpszClassName = TC_SPLASH_CLASS;
	wc.lpfnWndProc = &SplashDlgProc;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.cbWndExtra = DLGWINDOWEXTRA;

	hSplashClass = RegisterClass (&wc);
	if (hSplashClass == 0)
	{
		handleWin32Error (NULL);
		AbortProcess ("INIT_REGISTER");
	}
	
	if (GetSystemDirectory(dllPath, MAX_PATH))
		strcat(dllPath, "\\Riched20.dll");
	else
		strcpy(dllPath, "c:\\Windows\\System32\\Riched20.dll");
	// Required for RichEdit text fields to work
	if (LoadLibrary(dllPath) == NULL)
	{
		// This error is fatal e.g. because legal notices could not be displayed
		handleWin32Error (NULL);
		AbortProcess ("INIT_RICHEDIT");	
	}

	// DPI and GUI aspect ratio
	DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_AUXILIARY_DLG), NULL,
		(DLGPROC) AuxiliaryDlgProc, (LPARAM) 1);

	InitHelpFileName ();

#ifndef SETUP
	if (!EncryptionThreadPoolStart (ReadEncryptionThreadPoolFreeCpuCountLimit()))
	{
		handleWin32Error (NULL);
		exit (1);
	}
#endif
}

void InitHelpFileName (void)
{
	char *lpszTmp;

	GetModuleFileName (NULL, szHelpFile, sizeof (szHelpFile));
	lpszTmp = strrchr (szHelpFile, '\\');
	if (lpszTmp)
	{
		char szTemp[TC_MAX_PATH];

		// Primary file name
		if (strcmp (GetPreferredLangId(), "en") == 0
			|| GetPreferredLangId() == NULL)
		{
			strcpy (++lpszTmp, "VeraCrypt User Guide.pdf");
		}
		else
		{
			sprintf (szTemp, "VeraCrypt User Guide.%s.pdf", GetPreferredLangId());
			strcpy (++lpszTmp, szTemp);
		}

		// Secondary file name (used when localized documentation is not found).
		GetModuleFileName (NULL, szHelpFile2, sizeof (szHelpFile2));
		lpszTmp = strrchr (szHelpFile2, '\\');
		if (lpszTmp)
		{
			strcpy (++lpszTmp, "VeraCrypt User Guide.pdf");
		}
	}
}

BOOL OpenDevice (const char *lpszPath, OPEN_TEST_STRUCT *driver, BOOL detectFilesystem)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);
	ToUNICODE ((char *) &driver->wszFileName[0]);

	driver->bDetectTCBootLoader = FALSE;
	driver->DetectFilesystem = detectFilesystem;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
				   driver, sizeof (OPEN_TEST_STRUCT),
				   driver, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL);

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();

		if (dwResult == ERROR_SHARING_VIOLATION || dwResult == ERROR_NOT_READY)
		{
			driver->TCBootLoaderDetected = FALSE;
			driver->FilesystemDetected = FALSE;
			return TRUE;
		}
		else
			return FALSE;
	}
		
	return TRUE;
}


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
		|| strlen (SysPartitionDevicePath) <= 1 
		|| strlen (SysDriveDevicePath) <= 1)
	{
		foreach (const HostDevice &device, GetAvailableHostDevices (false, true))
		{
			if (device.ContainsSystem)
				strcpy_s (device.IsPartition ? SysPartitionDevicePath : SysDriveDevicePath, TC_MAX_PATH, device.Path.c_str()); 
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
		&& strlen (SysPartitionDevicePath) > 1 
		&& strlen (SysDriveDevicePath) > 1);
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
int IsSystemDevicePath (char *path, HWND hwndDlg, BOOL bReliableRequired)
{
	if (!bCachedSysDevicePathsValid
		&& bReliableRequired)
	{
		if (!GetSysDevicePaths (hwndDlg))
			return -1;
	}

	if (strlen (SysPartitionDevicePath) <= 1 || strlen (SysDriveDevicePath) <= 1)
		return -1;

	if (strncmp (path, SysPartitionDevicePath, max (strlen(path), strlen(SysPartitionDevicePath))) == 0)
		return 1;
	else if (strncmp (path, SysDriveDevicePath, max (strlen(path), strlen(SysDriveDevicePath))) == 0)
		return 2;
	else if (ExtraBootPartitionDevicePath == path)
		return 3;

	return 0;
}


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


BOOL TextInfoDialogBox (int nID)
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
				PrintHardCopyTextUTF16 ((wchar_t *) GetSysEncryptionPretestInfo2String ().c_str(), "Pre-Boot Troubleshooting", GetSysEncryptionPretestInfo2String ().length () * 2);
				break;

			case TC_TBXID_SYS_ENC_RESCUE_DISK:
				PrintHardCopyTextUTF16 ((wchar_t *) GetRescueDiskHelpString ().c_str(), "VeraCrypt Rescue Disk Help", GetRescueDiskHelpString ().length () * 2);
				break;

			case TC_TBXID_DECOY_OS_INSTRUCTIONS:
				PrintHardCopyTextUTF16 ((wchar_t *) GetDecoyOsInstructionsString ().c_str(), "How to Create Decoy OS", GetDecoyOsInstructionsString ().length () * 2);
				break;

			case TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS:
				PrintHardCopyTextUTF16 (GetString ("EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS"), "How to Remove Extra Boot Partition", wcslen (GetString ("EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS")) * 2);
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
					SetWindowText (GetDlgItem (hwndDlg, IDC_INFO_BOX_TEXT), r);
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
		resource = (char *) MapResource ("Text", IDR_LICENSE, &size);

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


BOOL CALLBACK RawDevicesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static char *lpszFileName;		// This is actually a pointer to a GLOBAL array
	static vector <HostDevice> devices;
	static map <int, HostDevice> itemToDeviceMap;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_DEVICELIST);

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

			WaitCursor();
			devices = GetAvailableHostDevices (false, true, false);
			NormalCursor();

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
						strcpy_s (SysPartitionDevicePath, sizeof (SysPartitionDevicePath), device.Path.c_str());
					else
						strcpy_s (SysDriveDevicePath, sizeof (SysDriveDevicePath), device.Path.c_str());
				}

				// Path
				if (!device.IsPartition || device.DynamicVolume)
				{
					if (!device.Floppy && device.Size == 0)
						continue;

					if (line > 1)
					{
						ListItemAdd (hList, item.iItem, "");
						item.iItem = line++;   
					}

					if (device.Floppy || device.DynamicVolume)
					{
						ListItemAdd (hList, item.iItem, (char *) device.Path.c_str());
					}
					else
					{
						wchar_t s[1024];
						if (device.Removable)
							wsprintfW (s, L"%s %d", GetString ("REMOVABLE_DISK"), device.SystemNumber);
						else
							wsprintfW (s, L"%s %d", GetString ("HARDDISK"), device.SystemNumber);

						if (!device.Partitions.empty())
							wcscat (s, L":");

						ListItemAddW (hList, item.iItem, s);
					}
				}
				else
				{
					ListItemAdd (hList, item.iItem, (char *) device.Path.c_str());
				}

				itemToDeviceMap[item.iItem] = device;

				// Size
				if (device.Size != 0)
				{
					wchar_t size[100] = { 0 };
					GetSizeString (device.Size, size);
					ListSubItemSetW (hList, item.iItem, 2, size);
				}

				// Mount point
				if (!device.MountPoint.empty())
					ListSubItemSet (hList, item.iItem, 1, (char *) device.MountPoint.c_str());

				// Label
				if (!device.Name.empty())
					ListSubItemSetW (hList, item.iItem, 3, (wchar_t *) device.Name.c_str());
#ifdef TCMOUNT
				else
				{
					wstring favoriteLabel = GetFavoriteVolumeLabel (device.Path);
					if (!favoriteLabel.empty())
						ListSubItemSetW (hList, item.iItem, 3, (wchar_t *) favoriteLabel.c_str());
				}
#endif

				item.iItem = line++;   
			}

			lpszFileName = (char *) lParam;

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
			LVITEM LvItem;
			memset(&LvItem,0,sizeof(LvItem));
			LvItem.mask = LVIF_TEXT | LVIF_PARAM;   
			LvItem.iItem = ((LPNMLISTVIEW) lParam)->iItem;
			LvItem.pszText = lpszFileName;
			LvItem.cchTextMax = TC_MAX_PATH;

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICELIST), LVM_GETITEM, LvItem.iItem, (LPARAM) &LvItem);
			EnableWindow (GetDlgItem ((HWND) hwndDlg, IDOK), lpszFileName[0] != 0 && lpszFileName[0] != ' ');

			return 1;
		}

		if (msg == WM_COMMAND && lw == IDOK || msg == WM_NOTIFY && ((NMHDR *)lParam)->code == LVN_ITEMACTIVATE)
		{
			int selectedItem = ListView_GetSelectionMark (GetDlgItem (hwndDlg, IDC_DEVICELIST));

			if (selectedItem == -1 || itemToDeviceMap.find (selectedItem) == itemToDeviceMap.end())
				return 1; // non-device line selected

			const HostDevice selectedDevice = itemToDeviceMap[selectedItem];
			strcpy_s (lpszFileName, TC_MAX_PATH, selectedDevice.Path.c_str());

#ifdef VOLFORMAT
			if (selectedDevice.ContainsSystem && selectedDevice.IsPartition)
			{
				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
				{
					if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE") == IDNO)
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
					&& AskWarnNoYes("FORMAT_DEVICE_FOR_ADVANCED_ONLY") == IDNO)
				{
					if (AskNoYes("CONFIRM_CHANGE_WIZARD_MODE_TO_FILE_CONTAINER") == IDYES)
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
						if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE") == IDNO)
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
						Error ("DEVICE_PARTITIONS_ERR_W_INPLACE_ENC_NOTE");
						return 1;
					}

					if (AskWarnNoYes ("WHOLE_NONSYS_DEVICE_ENC_CONFIRM") == IDNO)
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

		if (lw == IDCANCEL)
		{
			NormalCursor ();
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;
	}
	return 0;
}


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

	hService = CreateService (hManager, "veracrypt", "veracrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
		"System32\\drivers\\veracrypt.sys",
		NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
		goto error;
	else
		CloseServiceHandle (hService);

	hService = OpenService (hManager, "veracrypt", SERVICE_ALL_ACCESS);
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
		handleWin32Error (hwndDlg);
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
	char driverPath[TC_MAX_PATH*2];
	BOOL res;
	char *tmp;
	DWORD startType;

	if (ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", "Start", &startType) && startType == SERVICE_BOOT_START)
		return ERR_PARAMETER_INCORRECT;

	GetModuleFileName (NULL, driverPath, sizeof (driverPath));
	tmp = strrchr (driverPath, '\\');
	if (!tmp)
	{
		strcpy (driverPath, ".");
		tmp = driverPath + 1;
	}

	strcpy (tmp, !Is64BitOs () ? "\\veracrypt.sys" : "\\veracrypt-x64.sys");

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

	hService = OpenService (hManager, "veracrypt", SERVICE_ALL_ACCESS);
	if (hService != NULL)
	{
		// Remove stale service (driver is not loaded but service exists)
		DeleteService (hService);
		CloseServiceHandle (hService);
		Sleep (500);
	}

	hService = CreateService (hManager, "veracrypt", "veracrypt",
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

	hService = OpenService (hManager, "veracrypt", SERVICE_ALL_ACCESS);
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

		LoadSysEncSettings (NULL);

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
	char p[MAX_PATH];
	if (!IsNonInstallMode () && SHGetFolderPath (NULL, CSIDL_PROFILE, NULL, 0, p) == ERROR_SUCCESS)
	{
		SetCurrentDirectory (p);
	}
	else
	{
		GetModPath (p, sizeof (p));
		SetCurrentDirectory (p);
	}
}


BOOL BrowseFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter)
{
	return BrowseFilesInDir (hwndDlg, stringId, NULL, lpszFileName, keepHistory, saveMode, browseFilter);
}


BOOL BrowseFilesInDir (HWND hwndDlg, char *stringId, char *initialDir, char *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter, const wchar_t *initialFileName, const wchar_t *defaultExtension)
{
	OPENFILENAMEW ofn;
	wchar_t file[TC_MAX_PATH] = { 0 };
	wchar_t wInitialDir[TC_MAX_PATH] = { 0 };
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));
	*lpszFileName = 0;

	if (initialDir)
	{
		swprintf_s (wInitialDir, sizeof (wInitialDir) / 2, L"%hs", initialDir);
		ofn.lpstrInitialDir			= wInitialDir;
	}

	if (initialFileName)
		wcscpy_s (file, array_capacity (file), initialFileName);

	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;

	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.hc)%c*.hc%c%c",
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

	WideCharToMultiByte (CP_ACP, 0, file, -1, lpszFileName, MAX_PATH, NULL, NULL);

	if (!keepHistory)
		CleanLastVisitedMRU ();

	status = TRUE;

ret:
	SystemFileSelectorCallPending = FALSE;
	ResetCurrentDirectory();
	CoUninitialize();

	return status;
}


static char SelectMultipleFilesPath[131072];
static int SelectMultipleFilesOffset;

BOOL SelectMultipleFiles (HWND hwndDlg, char *stringId, char *lpszFileName, BOOL keepHistory)
{
	OPENFILENAMEW ofn;
	wchar_t file[0xffff * 2] = { 0 };	// The size must not exceed 0xffff*2 due to a bug in Windows 2000 and XP SP1
	wchar_t filter[1024];
	BOOL status = FALSE;

	CoInitialize (NULL);

	ZeroMemory (&ofn, sizeof (ofn));

	*lpszFileName = 0;
	ofn.lStructSize				= sizeof (ofn);
	ofn.hwndOwner				= hwndDlg;
	wsprintfW (filter, L"%ls (*.*)%c*.*%c%ls (*.hc)%c*.hc%c%c",
		GetString ("ALL_FILES"), 0, 0, GetString ("TC_VOLUMES"), 0, 0, 0);
	ofn.lpstrFilter				= filter;
	ofn.nFilterIndex			= 1;
	ofn.lpstrFile				= file;
	ofn.nMaxFile				= sizeof (file) / sizeof (file[0]);
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

	if (file[ofn.nFileOffset - 1] != 0)
	{
		// Single file selected
		WideCharToMultiByte (CP_ACP, 0, file, -1, lpszFileName, MAX_PATH, NULL, NULL);
		SelectMultipleFilesOffset = 0;
	}
	else
	{
		// Multiple files selected
		int n;
		wchar_t *f = file;
		char *s = SelectMultipleFilesPath;
		while ((n = WideCharToMultiByte (CP_ACP, 0, f, -1, s, MAX_PATH, NULL, NULL)) > 1)
		{
			f += n;
			s += n;
		}

		SelectMultipleFilesOffset = ofn.nFileOffset;
		SelectMultipleFilesNext (lpszFileName);
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


BOOL SelectMultipleFilesNext (char *lpszFileName)
{
	if (SelectMultipleFilesOffset == 0)
		return FALSE;

	strncpy (lpszFileName, SelectMultipleFilesPath, TC_MAX_PATH);
	lpszFileName[TC_MAX_PATH - 1] = 0;

	if (lpszFileName[strlen (lpszFileName) - 1] != '\\')
		strcat (lpszFileName, "\\");

	strcat (lpszFileName, SelectMultipleFilesPath + SelectMultipleFilesOffset);

	SelectMultipleFilesOffset += strlen (SelectMultipleFilesPath + SelectMultipleFilesOffset) + 1;
	if (SelectMultipleFilesPath[SelectMultipleFilesOffset] == 0)
		SelectMultipleFilesOffset = 0;

	return TRUE;
}


static int CALLBACK BrowseCallbackProc(HWND hwnd,UINT uMsg,LPARAM lp, LPARAM pData) 
{
	switch(uMsg) {
	case BFFM_INITIALIZED: 
	{
	  /* WParam is TRUE since we are passing a path.
	   It would be FALSE if we were passing a pidl. */
	   SendMessage (hwnd,BFFM_SETSELECTION,TRUE,(LPARAM)pData);
	   break;
	}

	case BFFM_SELCHANGED: 
	{
		char szDir[TC_MAX_PATH];

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


BOOL BrowseDirectories (HWND hwndDlg, char *lpszTitle, char *dirName)
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

	swprintf (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG"));
	if (CheckCapsLock (hwndDlg, TRUE))
		wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

#ifdef TCMOUNT
	if (TCBootLoaderOnInactiveSysEncDrive ())
	{
		swprintf (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_OR_MODE_WRONG" : "PASSWORD_OR_MODE_WRONG"));

		if (CheckCapsLock (hwndDlg, TRUE))
			wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

		wcscat (szTmp, GetString ("SYSENC_MOUNT_WITHOUT_PBA_NOTE"));
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


void handleError (HWND hwndDlg, int code)
{
	WCHAR szTmp[4096];

	if (Silent) return;

	switch (code)
	{
	case ERR_OS_ERROR:
		handleWin32Error (hwndDlg);
		break;
	case ERR_OUTOFMEMORY:
		MessageBoxW (hwndDlg, GetString ("OUTOFMEMORY"), lpszTitle, ICON_HAND);
		break;

	case ERR_PASSWORD_WRONG:
		MessageBoxW (hwndDlg, GetWrongPasswordErrorMessage (hwndDlg).c_str(), lpszTitle, MB_ICONWARNING);
		break;

	case ERR_DRIVE_NOT_FOUND:
		MessageBoxW (hwndDlg, GetString ("NOT_FOUND"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN:
		MessageBoxW (hwndDlg, GetString ("OPENFILES_DRIVER"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILES_OPEN_LOCK:
		MessageBoxW (hwndDlg, GetString ("OPENFILES_LOCK"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SIZE_WRONG:
		MessageBoxW (hwndDlg, GetString ("VOL_SIZE_WRONG"), lpszTitle, ICON_HAND);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MessageBoxW (hwndDlg, GetString ("COMPRESSION_NOT_SUPPORTED"), lpszTitle, ICON_HAND);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MessageBoxW (hwndDlg, GetString ("WRONG_VOL_TYPE"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_SEEKING:
		MessageBoxW (hwndDlg, GetString ("VOL_SEEKING"), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_FAILURE:
		MessageBoxW (hwndDlg, GetString ("ERR_CIPHER_INIT_FAILURE"), lpszTitle, ICON_HAND);
		break;
	case ERR_CIPHER_INIT_WEAK_KEY:
		MessageBoxW (hwndDlg, GetString ("ERR_CIPHER_INIT_WEAK_KEY"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		MessageBoxW (hwndDlg, GetString ("VOL_ALREADY_MOUNTED"), lpszTitle, ICON_HAND);
		break;
	case ERR_FILE_OPEN_FAILED:
		MessageBoxW (hwndDlg, GetString ("FILE_OPEN_FAILED"), lpszTitle, ICON_HAND);
		break;
	case ERR_VOL_MOUNT_FAILED:
		MessageBoxW (hwndDlg, GetString  ("VOL_MOUNT_FAILED"), lpszTitle, ICON_HAND);
		break;
	case ERR_NO_FREE_DRIVES:
		MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
		break;
	case ERR_ACCESS_DENIED:
		MessageBoxW (hwndDlg, GetString ("ACCESS_DENIED"), lpszTitle, ICON_HAND);
		break;

	case ERR_DRIVER_VERSION:
		Error ("DRIVER_VERSION");
		break;

	case ERR_NEW_VERSION_REQUIRED:
		MessageBoxW (hwndDlg, GetString ("NEW_VERSION_REQUIRED"), lpszTitle, ICON_HAND);
		break;

	case ERR_SELF_TESTS_FAILED:
		Error ("ERR_SELF_TESTS_FAILED");
		break;

	case ERR_VOL_FORMAT_BAD:
		Error ("ERR_VOL_FORMAT_BAD");
		break;

	case ERR_ENCRYPTION_NOT_COMPLETED:
		Error ("ERR_ENCRYPTION_NOT_COMPLETED");
		break;

	case ERR_NONSYS_INPLACE_ENC_INCOMPLETE:
		Error ("ERR_NONSYS_INPLACE_ENC_INCOMPLETE");
		break;

	case ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG:
		Error ("ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG");
		break;

	case ERR_PARAMETER_INCORRECT:
		Error ("ERR_PARAMETER_INCORRECT");
		break;

	case ERR_USER_ABORT:
	case ERR_DONT_REPORT:
		// A non-error
		break;

	default:
		wsprintfW (szTmp, GetString ("ERR_UNKNOWN"), code);
		MessageBoxW (hwndDlg, szTmp, lpszTitle, ICON_HAND);
	}
}


BOOL CheckFileStreamWriteErrors (FILE *file, const char *fileName)
{
	if (ferror (file))
	{
		wchar_t s[TC_MAX_PATH];
		swprintf_s (s, ARRAYSIZE (s), GetString ("CANNOT_WRITE_FILE_X"), fileName);
		ErrorDirect (s);

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
			char name[10] = { 0 };
			GetClassName (hwnd, name, sizeof (name));

			if (_stricmp (name, "Button") == 0 || _stricmp (name, "Static") == 0)
			{
				wchar_t *str = (wchar_t *) GetDictionaryValueByInt (ctrlId);
				if (str != NULL)
					SetWindowTextW (hwnd, str);
			}
		}
	}

	// Font
	SendMessage (hwnd, WM_SETFONT, (WPARAM) font, 0);
	
	return TRUE;
}

void LocalizeDialog (HWND hwnd, char *stringId)
{
	LastDialogId = stringId;
	SetWindowLongPtr (hwnd, GWLP_USERDATA, (LONG_PTR) 'VERA');
	SendMessage (hwnd, WM_SETFONT, (WPARAM) hUserFont, 0);

	if (stringId == NULL)
		SetWindowText (hwnd, "VeraCrypt");
	else
		SetWindowTextW (hwnd, GetString (stringId));
	
	if (hUserFont != 0)
		EnumChildWindows (hwnd, LocalizeDialogEnum, (LPARAM) hUserFont);
}

void OpenVolumeExplorerWindow (int driveNo)
{
	char dosName[5];
	SHFILEINFO fInfo;

	sprintf (dosName, "%c:\\", (char) driveNo + 'A');

	// Force explorer to discover the drive
	SHGetFileInfo (dosName, 0, &fInfo, sizeof (fInfo), 0);

	ShellExecute (NULL, "open", dosName, NULL, NULL, SW_SHOWNORMAL);
}

static BOOL explorerCloseSent;
static HWND explorerTopLevelWindow;

static BOOL CALLBACK CloseVolumeExplorerWindowsChildEnum (HWND hwnd, LPARAM driveStr)
{
	char s[MAX_PATH];
	SendMessage (hwnd, WM_GETTEXT, sizeof (s), (LPARAM) s);

	if (strstr (s, (char *) driveStr) != NULL)
	{
		PostMessage (explorerTopLevelWindow, WM_CLOSE, 0, 0);
		explorerCloseSent = TRUE;
		return FALSE;
	}

	return TRUE;
}

static BOOL CALLBACK CloseVolumeExplorerWindowsEnum (HWND hwnd, LPARAM driveNo)
{
	char driveStr[10];
	char s[MAX_PATH];

	sprintf (driveStr, "%c:\\", driveNo + 'A');

	GetClassName (hwnd, s, sizeof s);
	if (strcmp (s, "CabinetWClass") == 0)
	{
		GetWindowText (hwnd, s, sizeof s);
		if (strstr (s, driveStr) != NULL)
		{
			PostMessage (hwnd, WM_CLOSE, 0, 0);
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

string GetUserFriendlyVersionString (int version)
{
	char szTmp [64];
	sprintf (szTmp, "%x", version);

	string versionString (szTmp);

	versionString.insert (version > 0xfff ? 2 : 1,".");

	if (versionString[versionString.length()-1] == '0')
		versionString.erase (versionString.length()-1, 1); 

	return (versionString);
}

void GetSizeString (unsigned __int64 size, wchar_t *str)
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
		swprintf (str, L"%I64d %s", size/1024/1024/1024/1024/1024, pb);
	else if (size > 1024I64*1024*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024/1024/1024), pb);
	else if (size > 1024I64*1024*1024*1024*99)
		swprintf (str, L"%I64d %s",size/1024/1024/1024/1024, tb);
	else if (size > 1024I64*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024/1024), tb);
	else if (size > 1024I64*1024*1024*99)
		swprintf (str, L"%I64d %s",size/1024/1024/1024, gb);
	else if (size > 1024I64*1024*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024/1024), gb);
	else if (size > 1024I64*1024*99)
		swprintf (str, L"%I64d %s", size/1024/1024, mb);
	else if (size > 1024I64*1024)
		swprintf (str, L"%.1f %s",(double)(size/1024.0/1024), mb);
	else if (size >= 1024I64)
		swprintf (str, L"%I64d %s", size/1024, kb);
	else
		swprintf (str, L"%I64d %s", size, b);
}

#ifndef SETUP
void GetSpeedString (unsigned __int64 speed, wchar_t *str)
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
		swprintf (str, L"%I64d %s", speed/1024/1024/1024/1024/1024, pb);
	else if (speed > 1024I64*1024*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024/1024), pb);
	else if (speed > 1024I64*1024*1024*1024*99)
		swprintf (str, L"%I64d %s",speed/1024/1024/1024/1024, tb);
	else if (speed > 1024I64*1024*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024/1024), tb);
	else if (speed > 1024I64*1024*1024*99)
		swprintf (str, L"%I64d %s",speed/1024/1024/1024, gb);
	else if (speed > 1024I64*1024*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024/1024), gb);
	else if (speed > 1024I64*1024*99)
		swprintf (str, L"%I64d %s", speed/1024/1024, mb);
	else if (speed > 1024I64*1024)
		swprintf (str, L"%.1f %s",(double)(speed/1024.0/1024), mb);
	else if (speed > 1024I64)
		swprintf (str, L"%I64d %s", speed/1024, kb);
	else
		swprintf (str, L"%I64d %s", speed, b);
}

static void DisplayBenchmarkResults (HWND hwndDlg)
{
	wchar_t item1[100]={0};
	LVITEMW LvItem;
	HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);
	int ea, i;
	BOOL unsorted = TRUE;
	BENCHMARK_REC tmp_line;

	/* Sort the list */

	switch (benchmarkSortMethod)
	{
	case BENCHMARK_SORT_BY_SPEED:

		while (unsorted)
		{
			unsorted = FALSE;
			for (i = 0; i < benchmarkTotalItems - 1; i++)
			{
				if (benchmarkTable[i].meanBytesPerSec < benchmarkTable[i+1].meanBytesPerSec)
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
  
	/* Render the results */

	SendMessage (hList,LVM_DELETEALLITEMS,0,(LPARAM)&LvItem);

	for (i = 0; i < benchmarkTotalItems; i++)
	{
		ea = benchmarkTable[i].id;

		memset (&LvItem,0,sizeof(LvItem));
		LvItem.mask = LVIF_TEXT;
		LvItem.iItem = i;
		LvItem.iSubItem = 0;
		LvItem.pszText = (LPWSTR) benchmarkTable[i].name;
		SendMessageW (hList, LVM_INSERTITEM, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		wcscpy (item1, L"-");
#else
		GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].encSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
#endif
		LvItem.iSubItem = 1;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		wcscpy (item1, L"-");
#else
		GetSpeedString ((unsigned __int64) (benchmarkLastBufferSize / ((float) benchmarkTable[i].decSpeed / benchmarkPerformanceFrequency.QuadPart)), item1);
#endif
		LvItem.iSubItem = 2;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 

#if PKCS5_BENCHMARKS
		swprintf (item1, L"%d t", benchmarkTable[i].encSpeed);
#else
		GetSpeedString (benchmarkTable[i].meanBytesPerSec, item1);
#endif
		LvItem.iSubItem = 3;
		LvItem.pszText = item1;

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&LvItem); 
	}
}

static BOOL PerformBenchmark(HWND hwndDlg)
{
    LARGE_INTEGER performanceCountStart, performanceCountEnd;
	BYTE *lpTestBuffer;
	PCRYPTO_INFO ci = NULL;
	UINT64_STRUCT startDataUnitNo;

	startDataUnitNo.Value = 0;

#if !(PKCS5_BENCHMARKS || HASH_FNC_BENCHMARKS)
	ci = crypto_open ();
	if (!ci)
		return FALSE;
#endif

	if (QueryPerformanceFrequency (&benchmarkPerformanceFrequency) == 0)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	lpTestBuffer = (BYTE *) malloc(benchmarkBufferSize - (benchmarkBufferSize % 16));
	if (lpTestBuffer == NULL)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
		return FALSE;
	}
	VirtualLock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	WaitCursor ();
	benchmarkTotalItems = 0;

#if !(PKCS5_BENCHMARKS || HASH_FNC_BENCHMARKS)
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
#endif

#if HASH_FNC_BENCHMARKS

	/* Measures the speed at which each of the hash algorithms processes the message to produce
	   a single digest. 

	   The hash algorithm benchmarks are included here for development purposes only. Do not enable 
	   them when building a public release (the benchmark GUI strings wouldn't make sense). */

	{
		BYTE *digest [MAX_DIGESTSIZE];
		WHIRLPOOL_CTX	wctx;
		RMD160_CTX		rctx;
		sha1_ctx		sctx;
		sha512_ctx		s2ctx;
		int hid;

		for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++) 
		{
			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			switch (hid)
			{
			case SHA1:
				sha1_begin (&sctx);
				sha1_hash (lpTestBuffer, benchmarkBufferSize, &sctx);
				sha1_end ((unsigned char *) digest, &sctx);
				break;

			case SHA512:
				sha512_begin (&s2ctx);
				sha512_hash (lpTestBuffer, benchmarkBufferSize, &s2ctx);
				sha512_end ((unsigned char *) digest, &s2ctx);
				break;

			case RIPEMD160:
				RMD160Init(&rctx);
				RMD160Update(&rctx, lpTestBuffer, benchmarkBufferSize);
				RMD160Final((unsigned char *) digest, &rctx);
				break;

			case WHIRLPOOL:
				WHIRLPOOL_init (&wctx);
				WHIRLPOOL_add (lpTestBuffer, benchmarkBufferSize * 8, &wctx);
				WHIRLPOOL_finalize (&wctx, (unsigned char *) digest);
				break;
			}

			if (QueryPerformanceCounter (&performanceCountEnd) == 0)
				goto counter_error;

			benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;

			benchmarkTable[benchmarkTotalItems].decSpeed = benchmarkTable[benchmarkTotalItems].encSpeed;
			benchmarkTable[benchmarkTotalItems].id = hid;
			benchmarkTable[benchmarkTotalItems].meanBytesPerSec = ((unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].encSpeed / benchmarkPerformanceFrequency.QuadPart)) + (unsigned __int64) (benchmarkBufferSize / ((float) benchmarkTable[benchmarkTotalItems].decSpeed / benchmarkPerformanceFrequency.QuadPart))) / 2;
			sprintf (benchmarkTable[benchmarkTotalItems].name, "%s", HashGetName(hid));

			benchmarkTotalItems++;
		}
	}

#elif PKCS5_BENCHMARKS	// #if HASH_FNC_BENCHMARKS

	/* Measures the time that it takes for the PKCS-5 routine to derive a header key using
	   each of the implemented PRF algorithms. 

	   The PKCS-5 benchmarks are included here for development purposes only. Do not enable 
	   them when building a public release (the benchmark GUI strings wouldn't make sense). */
	{
		int thid, i;
		char dk[MASTER_KEYDATA_SIZE];
		char *tmp_salt = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x01\x23\x45\x67\x89\xAB\xCD\xEF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"};

		for (thid = FIRST_PRF_ID; thid <= LAST_PRF_ID; thid++) 
		{
			if (QueryPerformanceCounter (&performanceCountStart) == 0)
				goto counter_error;

			for (i = 1; i <= 5; i++) 
			{
				switch (thid)
				{
				case SHA1:
					/* PKCS-5 test with HMAC-SHA-1 used as the PRF */
					derive_key_sha1 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case SHA512:
					/* PKCS-5 test with HMAC-SHA-512 used as the PRF */
					derive_key_sha512 ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case RIPEMD160:
					/* PKCS-5 test with HMAC-RIPEMD-160 used as the PRF */
					derive_key_ripemd160 (FALSE, "passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;

				case WHIRLPOOL:
					/* PKCS-5 test with HMAC-Whirlpool used as the PRF */
					derive_key_whirlpool ("passphrase-1234567890", 21, tmp_salt, 64, get_pkcs5_iteration_count(thid, FALSE), dk, MASTER_KEYDATA_SIZE);
					break;
				}
			}

			if (QueryPerformanceCounter (&performanceCountEnd) == 0)
				goto counter_error;

			benchmarkTable[benchmarkTotalItems].encSpeed = performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
			benchmarkTable[benchmarkTotalItems].id = thid;
			sprintf (benchmarkTable[benchmarkTotalItems].name, "%s", get_pkcs5_prf_name (thid));

			benchmarkTotalItems++;
		}
	}

#else	// #elif PKCS5_BENCHMARKS

	/* Encryption algorithm benchmarks */
		
	for (ci->ea = EAGetFirst(); ci->ea != 0; ci->ea = EAGetNext(ci->ea))
	{
		if (!EAIsFormatEnabled (ci->ea))
			continue;

		EAInit (ci->ea, ci->master_keydata, ci->ks);

		ci->mode = FIRST_MODE_OF_OPERATION_ID;
		EAInitMode (ci);

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
		EAGetName (benchmarkTable[benchmarkTotalItems].name, ci->ea);

		benchmarkTotalItems++;
	}

#endif	// #elif PKCS5_BENCHMARKS (#else)

	if (ci)
		crypto_close (ci);

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	benchmarkLastBufferSize = benchmarkBufferSize;

	DisplayBenchmarkResults(hwndDlg);

	EnableWindow (GetDlgItem (hwndDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	NormalCursor ();
	return TRUE;

counter_error:
	
	if (ci)
		crypto_close (ci);

	VirtualUnlock (lpTestBuffer, benchmarkBufferSize - (benchmarkBufferSize % 16));

	free(lpTestBuffer);

	NormalCursor ();

	EnableWindow (GetDlgItem (hwndDlg, IDC_PERFORM_BENCHMARK), TRUE);
	EnableWindow (GetDlgItem (hwndDlg, IDCLOSE), TRUE);

	MessageBoxW (hwndDlg, GetString ("ERR_PERF_COUNTER"), lpszTitle, ICON_HAND);
	return FALSE;
}


BOOL CALLBACK BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	LPARAM nIndex;
	HWND hCboxSortMethod = GetDlgItem (hwndDlg, IDC_BENCHMARK_SORT_METHOD);
	HWND hCboxBufferSize = GetDlgItem (hwndDlg, IDC_BENCHMARK_BUFFER_SIZE);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			wchar_t s[128];
			HWND hList = GetDlgItem (hwndDlg, IDC_RESULTS);

			LocalizeDialog (hwndDlg, "IDD_BENCHMARK_DLG");

			benchmarkBufferSize = BENCHMARK_DEFAULT_BUF_SIZE;
			benchmarkSortMethod = BENCHMARK_SORT_BY_SPEED;

			SendMessage (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP 
				); 

			memset (&LvCol,0,sizeof(LvCol));               
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;  
			LvCol.pszText = GetString ("ALGORITHM");
			LvCol.cx = CompensateXDPI (114);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessage (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&LvCol);

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

			/* Combo boxes */

			// Sort method

			SendMessage (hCboxSortMethod, CB_RESETCONTENT, 0, 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("ALPHABETICAL_CATEGORIZED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			nIndex = SendMessageW (hCboxSortMethod, CB_ADDSTRING, 0, (LPARAM) GetString ("MEAN_SPEED"));
			SendMessage (hCboxSortMethod, CB_SETITEMDATA, nIndex, (LPARAM) 0);

			SendMessage (hCboxSortMethod, CB_SETCURSEL, 1, 0);		// Default sort method

			// Buffer size

			SendMessage (hCboxBufferSize, CB_RESETCONTENT, 0, 0);

			swprintf (s, L"100 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_KB);

			swprintf (s, L"500 %s", GetString ("KB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_KB);

			swprintf (s, L"1 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_MB);

			swprintf (s, L"5 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 5 * BYTES_PER_MB);

			swprintf (s, L"10 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 10 * BYTES_PER_MB);

			swprintf (s, L"50 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 50 * BYTES_PER_MB);

			swprintf (s, L"100 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 100 * BYTES_PER_MB);

			swprintf (s, L"200 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 200 * BYTES_PER_MB);

			swprintf (s, L"500 %s", GetString ("MB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 500 * BYTES_PER_MB);

			swprintf (s, L"1 %s", GetString ("GB"));
			nIndex = SendMessageW (hCboxBufferSize, CB_ADDSTRING, 0, (LPARAM) s);
			SendMessage (hCboxBufferSize, CB_SETITEMDATA, nIndex, (LPARAM) 1 * BYTES_PER_GB);

			SendMessage (hCboxBufferSize, CB_SETCURSEL, 5, 0);		// Default buffer size


			uint32 driverConfig = ReadDriverConfigurationFlags();

			SetDlgItemTextW (hwndDlg, IDC_HW_AES, (wstring (L" ") + (GetString (is_aes_hw_cpu_supported() ? ((driverConfig & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? "UISTR_DISABLED" : "UISTR_YES") : "NOT_APPLICABLE_OR_NOT_AVAILABLE"))).c_str());

			ToHyperlink (hwndDlg, IDC_HW_AES_LABEL_LINK);

			if (is_aes_hw_cpu_supported() && (driverConfig & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION))
			{
				Warning ("DISABLED_HW_AES_AFFECTS_PERFORMANCE");
			}

			SYSTEM_INFO sysInfo;
			GetSystemInfo (&sysInfo);

			size_t nbrThreads = GetEncryptionThreadCount();

			wchar_t nbrThreadsStr [300];
			if (sysInfo.dwNumberOfProcessors < 2)
			{
				wcscpy (nbrThreadsStr, GetString ("NOT_APPLICABLE_OR_NOT_AVAILABLE"));
			}
			else if (nbrThreads < 2)
			{
				wcscpy (nbrThreadsStr, GetString ("UISTR_DISABLED"));
			}
			else
			{
				wsprintfW (nbrThreadsStr, GetString ("NUMBER_OF_THREADS"), nbrThreads);
			}

			SetDlgItemTextW (hwndDlg, IDC_PARALLELIZATION, (wstring (L" ") + nbrThreadsStr).c_str());

			ToHyperlink (hwndDlg, IDC_PARALLELIZATION_LABEL_LINK);

			if (nbrThreads < min (sysInfo.dwNumberOfProcessors, GetMaxEncryptionThreadCount())
				&& sysInfo.dwNumberOfProcessors > 1)
			{
				Warning ("LIMITED_THREAD_COUNT_AFFECTS_PERFORMANCE");
			}

			return 1;
		}
		break;

	case WM_COMMAND:
	case WM_NOTIFY:

		switch (lw)
		{
		case IDC_BENCHMARK_SORT_METHOD:

			nIndex = SendMessage (hCboxSortMethod, CB_GETCURSEL, 0, 0);
			if (nIndex != benchmarkSortMethod)
			{
				benchmarkSortMethod = nIndex;
				DisplayBenchmarkResults (hwndDlg);
			}
			return 1;

		case IDC_PERFORM_BENCHMARK:

			nIndex = SendMessage (hCboxBufferSize, CB_GETCURSEL, 0, 0);
			benchmarkBufferSize = SendMessage (hCboxBufferSize, CB_GETITEMDATA, nIndex, 0);

			if (PerformBenchmark (hwndDlg) == FALSE)
			{
				EndDialog (hwndDlg, IDCLOSE);
			}
			return 1;

		case IDC_HW_AES_LABEL_LINK:

			Applink ("hwacceleration", TRUE, "");
			return 1;

		case IDC_PARALLELIZATION_LABEL_LINK:

			Applink ("parallelization", TRUE, "");
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
	static char outputDispBuffer [RNG_POOL_SIZE * 3 + RANDPOOL_DISPLAY_ROWS + 2];
	static BOOL bDisplayPoolContents = TRUE;
	static BOOL bRandPoolDispAscii = FALSE;
	int hash_algo = RandGetHashFunction();
	int hid;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PRF_ID);

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (lastRandPool, sizeof(lastRandPool));
			VirtualLock (outputDispBuffer, sizeof(outputDispBuffer));

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
			return 1;
		}

	case WM_TIMER:
		{
			char tmp[4];
			unsigned char tmpByte;
			int col, row;

			if (bDisplayPoolContents)
			{
				RandpeekBytes (randPool, sizeof (randPool));

				if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
				{
					outputDispBuffer[0] = 0;

					for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
					{
						for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
						{
							tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];

							sprintf (tmp, bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != '&') ? " %c " : " . ") : "%02X ", tmpByte);
							strcat (outputDispBuffer, tmp);
						}
						strcat (outputDispBuffer, "\n");
					}
					SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), outputDispBuffer);

					memcpy (lastRandPool, randPool, sizeof(lastRandPool));
				}
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
				char tmp[RNG_POOL_SIZE+1];

				memset (tmp, ' ', sizeof(tmp));
				tmp [RNG_POOL_SIZE] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);
			}

			return 1;
		}

		return 0;

	case WM_CLOSE:
		{
			char tmp[RNG_POOL_SIZE+1];
exit:
			KillTimer (hwndDlg, 0xfd);

			burn (randPool, sizeof(randPool));
			burn (lastRandPool, sizeof(lastRandPool));
			burn (outputDispBuffer, sizeof(outputDispBuffer));

			// Attempt to wipe the pool contents in the GUI text area
			memset (tmp, ' ', RNG_POOL_SIZE);
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


void UserEnrichRandomPool (HWND hwndDlg)
{
	Randinit();

	if (!IsRandomPoolEnrichedByUser())
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
	static char outputDispBuffer [RNG_POOL_SIZE * 3 + RANDPOOL_DISPLAY_ROWS + 2];
	static BOOL bDisplayPoolContents = TRUE;
	static BOOL bRandPoolDispAscii = FALSE;
	int hash_algo = RandGetHashFunction();
	int hid;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			HWND hComboBox = GetDlgItem (hwndDlg, IDC_PRF_ID);

			VirtualLock (randPool, sizeof(randPool));
			VirtualLock (lastRandPool, sizeof(lastRandPool));
			VirtualLock (outputDispBuffer, sizeof(outputDispBuffer));

			LocalizeDialog (hwndDlg, "IDD_KEYFILE_GENERATOR");

			SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
			for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
			{
				if (!HashIsDeprecated (hid))
					AddComboPair (hComboBox, HashGetName(hid), hid);
			}
			SelectAlgo (hComboBox, &hash_algo);

			SetCheckBox (hwndDlg, IDC_DISPLAY_POOL_CONTENTS, bDisplayPoolContents);

#ifndef VOLFORMAT			
			if (Randinit ()) 
			{
				Error ("INIT_RAND");
				EndDialog (hwndDlg, IDCLOSE);
			}
#endif
			SetTimer (hwndDlg, 0xfd, RANDPOOL_DISPLAY_REFRESH_INTERVAL, NULL);
			SendMessage (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			return 1;
		}

	case WM_TIMER:
		{
			char tmp[4];
			unsigned char tmpByte;
			int col, row;

			if (bDisplayPoolContents)
			{
				RandpeekBytes (randPool, sizeof (randPool));

				if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
				{
					outputDispBuffer[0] = 0;

					for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
					{
						for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
						{
							tmpByte = randPool[row * RANDPOOL_DISPLAY_COLUMNS + col];

							sprintf (tmp, bRandPoolDispAscii ? ((tmpByte >= 32 && tmpByte < 255 && tmpByte != '&') ? " %c " : " . ") : "%02X ", tmpByte);
							strcat (outputDispBuffer, tmp);
						}
						strcat (outputDispBuffer, "\n");
					}
					SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), outputDispBuffer);

					memcpy (lastRandPool, randPool, sizeof(lastRandPool));
				}
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
				char tmp[RNG_POOL_SIZE+1];

				memset (tmp, ' ', sizeof(tmp));
				tmp [RNG_POOL_SIZE] = 0;
				SetWindowText (GetDlgItem (hwndDlg, IDC_POOL_CONTENTS), tmp);
			}
			return 1;
		}

		if (lw == IDC_GENERATE_AND_SAVE_KEYFILE)
		{
			char szFileName [TC_MAX_PATH];
			unsigned char keyfile [MAX_PASSWORD];
			int fhKeyfile = -1;

			/* Select filename */
			if (!BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, TRUE, NULL))
				return 1;

			/* Conceive the file */
			if ((fhKeyfile = _open(szFileName, _O_CREAT|_O_TRUNC|_O_WRONLY|_O_BINARY, _S_IREAD|_S_IWRITE)) == -1)
			{
				handleWin32Error (hwndDlg);
				return 1;
			}

			/* Generate the keyfile */ 
			WaitCursor();
			if (!RandgetBytes (keyfile, sizeof(keyfile), TRUE))
			{
				_close (fhKeyfile);
				DeleteFile (szFileName);
				NormalCursor();
				return 1;
			}
			NormalCursor();

			/* Write the keyfile */
			if (_write (fhKeyfile, keyfile, sizeof(keyfile)) == -1)
				handleWin32Error (hwndDlg);
			else
				Info("KEYFILE_CREATED");

			burn (keyfile, sizeof(keyfile));
			_close (fhKeyfile);
			return 1;
		}
		return 0;

	case WM_CLOSE:
		{
			char tmp[RNG_POOL_SIZE+1];
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

			// Attempt to wipe the pool contents in the GUI text area
			memset (tmp, ' ', RNG_POOL_SIZE);
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
			char buf[100];

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
					AddComboPair (GetDlgItem (hwndDlg, IDC_CIPHER), EAGetName (buf, ea), EAGetFirstCipher (ea));
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
			char key[128+1], inputtext[128+1], secondaryKey[64+1], dataUnitNo[16+1], szTmp[128+1];
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
			n = GetWindowText(GetDlgItem(hwndDlg, IDC_KEY), szTmp, sizeof(szTmp));
			if (n != ks * 2)
			{
				Warning ("TEST_KEY_SIZE");
				return 1;
			}

			for (n = 0; n < ks; n ++)
			{
				char szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = strtol(szTmp2, &ptr, 16);

				key[n] = (char) x;
			}

			memset(inputtext, 0, sizeof(inputtext));
			memset(secondaryKey, 0, sizeof(secondaryKey));
			memset(dataUnitNo, 0, sizeof(dataUnitNo));
			memset(szTmp, 0, sizeof(szTmp));

			if (bEncrypt)
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), szTmp, sizeof(szTmp));
			}
			else
			{
				n = GetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), szTmp, sizeof(szTmp));
			}

			if (n != pt * 2)
			{
				if (bEncrypt)
				{
					Warning ("TEST_PLAINTEXT_SIZE");
					return 1;
				}
				else
				{
					Warning  ("TEST_CIPHERTEXT_SIZE");
					return 1;
				}
			}

			for (n = 0; n < pt; n ++)
			{
				char szTmp2[3], *ptr;
				long x;

				szTmp2[2] = 0;
				szTmp2[0] = szTmp[n * 2];
				szTmp2[1] = szTmp[n * 2 + 1];

				x = strtol(szTmp2, &ptr, 16);

				inputtext[n] = (char) x;
			}
			
			// XTS
			if (bXTSTestEnabled)
			{
				// Secondary key

				if (GetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), szTmp, sizeof(szTmp)) != 64)
				{
					Warning ("TEST_INCORRECT_SECONDARY_KEY_SIZE");
					return 1;
				}

				for (n = 0; n < 64; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

					secondaryKey[n] = (char) x;
				}

				// Data unit number

				tlen = GetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), szTmp, sizeof(szTmp));

				if (tlen > 16 || tlen < 1)
				{
					Warning ("TEST_INCORRECT_TEST_DATA_UNIT_SIZE");
					return 1;
				}

				LeftPadString (szTmp, tlen, 16, '0');

				for (n = 0; n < 16; n ++)
				{
					char szTmp2[3], *ptr;
					long x;

					szTmp2[2] = 0;
					szTmp2[0] = szTmp[n * 2];
					szTmp2[1] = szTmp[n * 2 + 1];

					x = strtol(szTmp2, &ptr, 16);

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
						handleError (hwndDlg, tmpRetVal);
						return 1;
					}

					memcpy (&ci->k2, secondaryKey, sizeof (secondaryKey));
					if (!EAInitMode (ci))
						return 1;

					structDataUnitNo.Value = BE64(((unsigned __int64 *)dataUnitNo)[0]);

					if (bEncrypt)
						EncryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);
					else
						DecryptBufferXTS ((unsigned char *) tmp, pt, &structDataUnitNo, blockNo, (unsigned char *) (ci->ks), (unsigned char *) ci->ks2, idTestCipher);

					crypto_close (ci);
				}
				else
				{
					if (idTestCipher == BLOWFISH)
					{
						/* Deprecated/legacy */

						/* Convert to little-endian, this is needed here and not in
						above auto-tests because BF_ecb_encrypt above correctly converts
						from big to little endian, and EncipherBlock does not! */
						LongReverse((unsigned int *) tmp, pt);
					}

					CipherInit2(idTestCipher, key, ks_tmp, ks);

					if (bEncrypt)
					{
						EncipherBlock(idTestCipher, tmp, ks_tmp);
					}
					else
					{
						DecipherBlock(idTestCipher, tmp, ks_tmp);
					}

					if (idTestCipher == BLOWFISH)
					{
						/* Deprecated/legacy */

						/* Convert back to big-endian */
						LongReverse((unsigned int *) tmp, pt);
					}
				}
				*szTmp = 0;

				for (n = 0; n < pt; n ++)
				{
					char szTmp2[3];
					sprintf(szTmp2, "%02x", (int)((unsigned char)tmp[n]));
					strcat(szTmp, szTmp2);
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

	ndx = SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) "64");
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
	SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

	for (ndx = 0; ndx < BLOCKS_PER_XTS_DATA_UNIT; ndx++)
	{
		char tmpStr [16];

		sprintf (tmpStr, "%d", ndx);

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_ADDSTRING, 0,(LPARAM) tmpStr);
		SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETITEMDATA, ndx,(LPARAM) ndx);
	}

	SendMessage(GetDlgItem(hwndDlg, IDC_TEST_BLOCK_NUMBER), CB_SETCURSEL, 0, 0);

	SetWindowText(GetDlgItem(hwndDlg, IDC_SECONDARY_KEY), "0000000000000000000000000000000000000000000000000000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_TEST_DATA_UNIT_NUMBER), "0");

	if (idTestCipher == BLOWFISH)
	{
		/* Deprecated/legacy */

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "448");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 56);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "256");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 32);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "64");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 8);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, 0,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	} 


	if (idTestCipher == CAST)
	{
		/* Deprecated/legacy */

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "00000000000000000000000000000000");
	}

	if (idTestCipher == TRIPLEDES)
	{
		/* Deprecated/legacy */

		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "168");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 24);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);
		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "000000000000000000000000000000000000000000000000");
	}
	
	SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), "0000000000000000");
	SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), "0000000000000000");

	if (idTestCipher == AES || idTestCipher == SERPENT || idTestCipher == TWOFISH)
	{
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_ADDSTRING, 0,(LPARAM) "256");
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 32);
		SendMessage(GetDlgItem(hwndDlg, IDC_KEY_SIZE), CB_SETCURSEL, ndx,0);

		SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_RESETCONTENT, 0,0);
		ndx = SendMessage (GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_ADDSTRING, 0,(LPARAM) "128");
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETITEMDATA, ndx,(LPARAM) 16);
		SendMessage(GetDlgItem(hwndDlg, IDC_PLAINTEXT_SIZE), CB_SETCURSEL, ndx,0);

		SetWindowText(GetDlgItem(hwndDlg, IDC_KEY), "0000000000000000000000000000000000000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_PLAINTEXT), "00000000000000000000000000000000");
		SetWindowText(GetDlgItem(hwndDlg, IDC_CIPHERTEXT), "00000000000000000000000000000000");
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
			nMainTextLenInChars = wcslen ((const wchar_t *) (bResolve ? GetString(*(pStrOrig+1)) : *(pwStrOrig+1)));

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
						wcslen (L"\n") * 2, 
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
		EndDialog (hwndDlg, 0);
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
BOOL CheckFileExtension (char *fileName)
{
	int i = 0;
	char *ext = strrchr (fileName, '.');
	static char *problemFileExt[] = {
		// These are protected by the Windows Resource Protection
		".asa", ".asp", ".aspx", ".ax", ".bas", ".bat", ".bin", ".cer", ".chm", ".clb", ".cmd", ".cnt", ".cnv",
		".com", ".cpl", ".cpx", ".crt", ".csh", ".dll", ".drv", ".dtd", ".exe", ".fxp", ".grp", ".h1s", ".hlp",
		".hta", ".ime", ".inf", ".ins", ".isp", ".its", ".js", ".jse", ".ksh", ".lnk", ".mad", ".maf", ".mag",
		".mam", ".man", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw", ".mda", ".mdb", ".mde", ".mdt",
		".mdw", ".mdz", ".msc", ".msi", ".msp", ".mst", ".mui", ".nls", ".ocx", ".ops", ".pal", ".pcd", ".pif",
		".prf", ".prg", ".pst", ".reg", ".scf", ".scr", ".sct", ".shb", ".shs", ".sys", ".tlb", ".tsp", ".url",
		".vb", ".vbe", ".vbs", ".vsmacros", ".vss", ".vst", ".vsw", ".ws", ".wsc", ".wsf", ".wsh", ".xsd", ".xsl",
		// These additional file extensions are usually watched by antivirus programs
		".386", ".acm", ".ade", ".adp", ".ani", ".app", ".asd", ".asf", ".asx", ".awx", ".ax", ".boo", ".bz2", ".cdf",
		".class", ".dhtm", ".dhtml",".dlo", ".emf", ".eml", ".flt", ".fot", ".gz", ".hlp", ".htm", ".html", ".ini", 
		".j2k", ".jar", ".jff", ".jif", ".jmh", ".jng", ".jp2", ".jpe", ".jpeg", ".jpg", ".lsp", ".mod", ".nws",
		".obj", ".olb", ".osd", ".ov1", ".ov2", ".ov3", ".ovl", ".ovl", ".ovr", ".pdr", ".pgm", ".php", ".pkg",
		".pl", ".png", ".pot", ".pps", ".ppt", ".ps1", ".ps1xml", ".psc1", ".rar", ".rpl", ".rtf", ".sbf", ".script", ".sh", ".sha", ".shtm",
		".shtml", ".spl", ".swf", ".tar", ".tgz", ".tmp", ".ttf", ".vcs", ".vlm", ".vxd", ".vxo", ".wiz", ".wll", ".wmd",
		".wmf",	".wms", ".wmz", ".wpc", ".wsc", ".wsh", ".wwk", ".xhtm", ".xhtml", ".xl", ".xml", ".zip", ".7z", 0};

	if (!ext)
		return FALSE;

	while (problemFileExt[i])
	{
		if (!_stricmp (ext, problemFileExt[i++]))
			return TRUE;
	}

	return FALSE;
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


int GetFirstAvailableDrive ()
{
	DWORD dwUsedDrives = GetLogicalDrives();
	int i;

	for (i = 3; i < 26; i++)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}


int GetLastAvailableDrive ()
{
	DWORD dwUsedDrives = GetLogicalDrives();
	int i;

	for (i = 25; i > 2; i--)
	{
		if (!(dwUsedDrives & 1 << i))
			return i;
	}

	return -1;
}


BOOL IsDriveAvailable (int driveNo)
{
	return (GetLogicalDrives() & (1 << driveNo)) == 0;
}


BOOL IsDeviceMounted (char *deviceName)
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

	BOOL bResult;
	
	unmount.nDosDriveNo = nDosDriveNo;
	unmount.ignoreOpenFiles = forced;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_VOLUME, &unmount,
		sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		handleWin32Error (hwndDlg);
		return 1;
	}

#ifdef TCMOUNT

	if (unmount.nReturnCode == ERR_SUCCESS
		&& unmount.HiddenVolumeProtectionTriggered
		&& !VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo])
	{
		wchar_t msg[4096];

		VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo] = TRUE;
		swprintf (msg, GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), nDosDriveNo + 'A');
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
				char root[] = { (char) i + 'A', ':', '\\', 0 };
				SHChangeNotify (eventId, SHCNF_PATH, root, NULL);

				if (nCurrentOS == WIN_2000 && RemoteSession)
				{
					char target[32];
					wsprintf (target, "%ls%c", TC_MOUNT_PREFIX, i + 'A');
					root[2] = 0;

					if (message == DBT_DEVICEARRIVAL)
						DefineDosDevice (DDD_RAW_TARGET_PATH, root, target);
					else if (message == DBT_DEVICEREMOVECOMPLETE)
						DefineDosDevice (DDD_RAW_TARGET_PATH| DDD_REMOVE_DEFINITION
						| DDD_EXACT_MATCH_ON_REMOVE, root, target);
				}
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
				 char *volumePath,
				 Password *password,
				 BOOL cachePassword,
				 BOOL sharedAccess,
				 const MountOptions* const mountOptions,
				 BOOL quiet,
				 BOOL bReportWrongPassword)
{
	MOUNT_STRUCT mount;
	DWORD dwResult;
	BOOL bResult, bDevice;
	char root[MAX_PATH];
	int favoriteMountOnArrivalRetryCount = 0;

#ifdef TCMOUNT
	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (!CheckSysEncMountWithoutPBA (volumePath, quiet))
			return -1;
	}
#endif

	if (IsMountedVolume (volumePath))
	{
		if (!quiet)
			Error ("VOL_ALREADY_MOUNTED");
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
	{
		if (!quiet)
			Error ("DRIVE_LETTER_UNAVAILABLE");

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

retry:
	mount.nDosDriveNo = driveNo;
	mount.bCache = cachePassword;

	mount.bPartitionInInactiveSysEncScope = FALSE;

	if (password != NULL)
		mount.VolumePassword = *password;
	else
		mount.VolumePassword.Length = 0;

	if (!mountOptions->ReadOnly && mountOptions->ProtectHiddenVolume)
	{
		mount.ProtectedHidVolPassword = mountOptions->ProtectedHidVolPassword;
		mount.bProtectHiddenVolume = TRUE;
	}
	else
		mount.bProtectHiddenVolume = FALSE;

	mount.bMountReadOnly = mountOptions->ReadOnly;
	mount.bMountRemovable = mountOptions->Removable;
	mount.bPreserveTimestamp = mountOptions->PreserveTimestamp;

	mount.bMountManager = TRUE;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		mount.bMountManager = FALSE;

	string path = volumePath;
	if (path.find ("\\\\?\\") == 0)
	{
		// Remove \\?\ prefix
		path = path.substr (4);
		strcpy_s (volumePath, TC_MAX_PATH, path.c_str());
	}
	
	if (path.find ("Volume{") == 0 && path.rfind ("}\\") == path.size() - 2)
	{
		string resolvedPath = VolumeGuidPathToDevicePath (path);

		if (!resolvedPath.empty())
			strcpy_s (volumePath, TC_MAX_PATH, resolvedPath.c_str());
	}

	CreateFullVolumePath ((char *) mount.wszVolume, volumePath, &bDevice);

	if (!bDevice)
	{
		// UNC path
		if (path.find ("\\\\") == 0)
		{
			strcpy_s ((char *)mount.wszVolume, array_capacity (mount.wszVolume), ("UNC" + path.substr (1)).c_str());
		}

		if (GetVolumePathName (volumePath, root, sizeof (root) - 1))
		{
			DWORD bps, flags, d;
			if (GetDiskFreeSpace (root, &d, &bps, &d, &d))
				mount.BytesPerSector = bps;

			// Read-only host filesystem
			if (!mount.bMountReadOnly && GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
				mount.bMountReadOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;
		}
	}

	ToUNICODE ((char *) mount.wszVolume);

	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (mount.wszVolume == NULL || swscanf_s ((const wchar_t *) mount.wszVolume,
			WIDE("\\Device\\Harddisk%d\\Partition"),
			&mount.nPartitionInInactiveSysEncScopeDriveNo,
			sizeof(mount.nPartitionInInactiveSysEncScopeDriveNo)) != 1)
		{
			return -1;
		}

		mount.bPartitionInInactiveSysEncScope = TRUE;
	}

	bResult = DeviceIoControl (hDriver, TC_IOCTL_MOUNT_VOLUME, &mount,
		sizeof (mount), &mount, sizeof (mount), &dwResult, NULL);

	burn (&mount.VolumePassword, sizeof (mount.VolumePassword));
	burn (&mount.ProtectedHidVolPassword, sizeof (mount.ProtectedHidVolPassword));

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
					Error ("FILE_IN_USE_FAILED");

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
				if (IDYES == AskWarnNoYes ("FILE_IN_USE"))
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}
			}

			return -1;
		}

		if (!quiet && (!MultipleMountOperationInProgress || GetLastError() != ERROR_NOT_READY))
			handleWin32Error (hwndDlg);

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

					if (sscanf (volumePath, "\\Device\\Harddisk%d\\Partition", &driveNo) == 1)
					{
						OPEN_TEST_STRUCT openTestStruct;
						memset (&openTestStruct, 0, sizeof (openTestStruct));

						openTestStruct.bDetectTCBootLoader = TRUE;
						_snwprintf ((wchar_t *) openTestStruct.wszFileName, array_capacity (openTestStruct.wszFileName), L"\\Device\\Harddisk%d\\Partition0", driveNo);

						DWORD dwResult;
						if (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST, &openTestStruct, sizeof (OPEN_TEST_STRUCT), &openTestStruct, sizeof (OPEN_TEST_STRUCT), &dwResult, NULL) && openTestStruct.TCBootLoaderDetected)
							WarningDirect ((GetWrongPasswordErrorMessage (hwndDlg) + L"\n\n" + GetString ("HIDDEN_VOL_PROT_PASSWORD_US_KEYB_LAYOUT")).c_str());
						else
							handleError (hwndDlg, mount.nReturnCode);
					}
				}
				else
					handleError (hwndDlg, mount.nReturnCode);
			}

			return 0;
		}

		if (!quiet)
			handleError (hwndDlg, mount.nReturnCode);

		return 0;
	}

	// Mount successful

	if (mount.UseBackupHeader != mountOptions->UseBackupHeader
		&& mount.UseBackupHeader)
	{
		if (bReportWrongPassword && !Silent)
			Warning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK");
	}
	
	LastMountedVolumeDirty = mount.FilesystemDirty;

	if (mount.FilesystemDirty)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		wsprintfW (msg, GetString ("MOUNTED_VOLUME_DIRTY"), mountPoint);

		if (AskWarnYesNoStringTopmost (msg) == IDYES)
			CheckFilesystem (driveNo, TRUE);
	}

	if (mount.VolumeMountedReadOnlyAfterAccessDenied
		&& !Silent
		&& !bDevice
		&& !FileHasReadOnlyAttribute (volumePath)
		&& !IsFileOnReadOnlyFilesystem (volumePath))
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		wsprintfW (msg, GetString ("MOUNTED_CONTAINER_FORCED_READ_ONLY"), mountPoint);

		WarningDirect (msg);
	}

	if (mount.VolumeMountedReadOnlyAfterAccessDenied
		&& !Silent
		&& bDevice)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		wsprintfW (msg, GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY"), mountPoint);

		WarningDirect (msg);
	}

	if (mount.VolumeMountedReadOnlyAfterDeviceWriteProtected
		&& !Silent
		&& strstr (volumePath, "\\Device\\Harddisk") == volumePath)
	{
		wchar_t msg[1024];
		wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
		wsprintfW (msg, GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY_WRITE_PROTECTION"), mountPoint);

		WarningDirect (msg);

		if (CurrentOSMajor >= 6
			&& strstr (volumePath, "\\Device\\HarddiskVolume") != volumePath
			&& AskNoYes ("ASK_REMOVE_DEVICE_WRITE_PROTECTION") == IDYES)
		{
			RemoveDeviceWriteProtection (hwndDlg, volumePath);
		}
	}

	ResetWrongPwdRetryCount ();

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (mount.bExclusiveAccess == FALSE)
		return 2;

	return 1;
}


BOOL UnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount)
{
	int result;
	BOOL forced = forceUnmount;
	int dismountMaxRetries = UNMOUNT_MAX_AUTO_RETRIES;

retry:
	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, nDosDriveNo, 0);

	do
	{
		result = DriverUnmountVolume (hwndDlg, nDosDriveNo, forced);

		if (result == ERR_FILES_OPEN)
			Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		else
			break;

	} while (--dismountMaxRetries > 0);

	if (result != 0)
	{
		if (result == ERR_FILES_OPEN && !Silent)
		{
			if (IDYES == AskWarnYesNoTopmost ("UNMOUNT_LOCK_FAILED"))
			{
				forced = TRUE;
				goto retry;
			}

			if (IsOSAtLeast (WIN_7))
			{
				// Undo SHCNE_DRIVEREMOVED
				char root[] = { (char) nDosDriveNo + 'A', ':', '\\', 0 };
				SHChangeNotify (SHCNE_DRIVEADD, SHCNF_PATH, root, NULL);
			}

			return FALSE;
		}

		Error ("UNMOUNT_FAILED");

		return FALSE;
	} 
	
	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, nDosDriveNo, 0);

	return TRUE;
}


BOOL IsPasswordCacheEmpty (void)
{
	DWORD dw;
	return !DeviceIoControl (hDriver, TC_IOCTL_GET_PASSWORD_CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
}


BOOL IsMountedVolume (const char *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	char volume[TC_MAX_PATH*2+16];

	strcpy (volume, volname);

	if (strstr (volname, "\\Device\\") != volname)
		sprintf(volume, "\\??\\%s", volname);

	string resolvedPath = VolumeGuidPathToDevicePath (volname);
	if (!resolvedPath.empty())
		strcpy_s (volume, sizeof (volume), resolvedPath.c_str());

	ToUNICODE (volume);

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == _wcsicmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
			return TRUE;

	return FALSE;
}


int GetMountedVolumeDriveNo (char *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	char volume[TC_MAX_PATH*2+16];

	if (volname == NULL)
		return -1;

	strcpy (volume, volname);

	if (strstr (volname, "\\Device\\") != volname)
		sprintf(volume, "\\??\\%s", volname);

	string resolvedPath = VolumeGuidPathToDevicePath (volname);
	if (!resolvedPath.empty())
		strcpy_s (volume, sizeof (volume), resolvedPath.c_str());

	ToUNICODE (volume);

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == _wcsicmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
			return i;

	return -1;
}


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

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, "EnableLUA", 0, 0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
			value = 1;

		RegCloseKey (hkey);
	}

	return value != 0;
}


BOOL ResolveSymbolicLink (const wchar_t *symLinkName, PWSTR targetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	wcscpy ((PWSTR) &resolve.symLinkName, symLinkName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_RESOLVED_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	wcscpy (targetName, (PWSTR) &resolve.targetName);

	return bResult;
}


BOOL GetPartitionInfo (const char *deviceName, PPARTITION_INFORMATION rpartInfo)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_PARTITION_INFO_STRUCT dpi;

	memset (&dpi, 0, sizeof(dpi));
	wsprintfW ((PWSTR) &dpi.deviceName, L"%hs", deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, &dpi,
		sizeof (dpi), &dpi, sizeof (dpi), &dwResult, NULL);

	memcpy (rpartInfo, &dpi.partInfo, sizeof (PARTITION_INFORMATION));
	return bResult;
}


BOOL GetDeviceInfo (const char *deviceName, DISK_PARTITION_INFO_STRUCT *info)
{
	DWORD dwResult;

	memset (info, 0, sizeof(*info));
	wsprintfW ((PWSTR) &info->deviceName, L"%hs", deviceName);

	return DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, info, sizeof (*info), info, sizeof (*info), &dwResult, NULL);
}


BOOL GetDriveGeometry (const char *deviceName, PDISK_GEOMETRY diskGeometry)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_GEOMETRY_STRUCT dg;

	memset (&dg, 0, sizeof(dg));
	wsprintfW ((PWSTR) &dg.deviceName, L"%hs", deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_GEOMETRY, &dg,
		sizeof (dg), &dg, sizeof (dg), &dwResult, NULL);

	memcpy (diskGeometry, &dg.diskGeometry, sizeof (DISK_GEOMETRY));
	return bResult;
}


// Returns drive letter number assigned to device (-1 if none)
int GetDiskDeviceDriveLetter (PWSTR deviceName)
{
	int i;
	WCHAR link[MAX_PATH];
	WCHAR target[MAX_PATH];
	WCHAR device[MAX_PATH];

	if (!ResolveSymbolicLink (deviceName, device))
		wcscpy (device, deviceName);

	for (i = 0; i < 26; i++)
	{
		WCHAR drive[] = { (WCHAR) i + 'A', ':', 0 };

		wcscpy (link, L"\\DosDevices\\");
		wcscat (link, drive);

		ResolveSymbolicLink (link, target);

		if (wcscmp (device, target) == 0)
			return i;
	}

	return -1;
}


// WARNING: This function does NOT provide 100% reliable results -- do NOT use it for critical/dangerous operations!
// Return values: 0 - filesystem does not appear empty, 1 - filesystem appears empty, -1 - an error occurred
int FileSystemAppearsEmpty (const char *devicePath)
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
__int64 GetStatsFreeSpaceOnPartition (const char *devicePath, float *percentFree, __int64 *occupiedBytes, BOOL silent)
{
	WCHAR devPath [MAX_PATH];
	int driveLetterNo = -1;
	char szRootPath[4] = {0, ':', '\\', 0};
	ULARGE_INTEGER freeSpaceSize;
	ULARGE_INTEGER totalNumberOfBytes;
	ULARGE_INTEGER totalNumberOfFreeBytes;

	strcpy ((char *) devPath, devicePath);
	ToUNICODE ((char *) devPath);

	driveLetterNo = GetDiskDeviceDriveLetter (devPath);
	szRootPath[0] = (char) driveLetterNo + 'A';


	if (!GetDiskFreeSpaceEx (szRootPath, &freeSpaceSize, &totalNumberOfBytes, &totalNumberOfFreeBytes))
	{
		if (!silent)
		{
			handleWin32Error (MainDlg);
			Error ("CANNOT_CALC_SPACE");
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
				handleWin32Error (MainDlg);
				Error ("CANT_GET_VOLSIZE");
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
__int64 GetDeviceSize (const char *devicePath)
{
	PARTITION_INFORMATION partitionInfo;

	if (!GetPartitionInfo (devicePath, &partitionInfo))
		return -1;

	return partitionInfo.PartitionLength.QuadPart;
}


HANDLE DismountDrive (char *devName, char *devicePath)
{
	DWORD dwResult;
	HANDLE hVolume;
	BOOL bResult = FALSE;
	int attempt = UNMOUNT_MAX_AUTO_RETRIES;
	int driveLetterNo = -1;
	WCHAR devPath [MAX_PATH];

	strcpy ((char *) devPath, devicePath);
	ToUNICODE ((char *) devPath);
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
int64 FindString (const char *buf, const char *str, int64 bufLen, size_t strLen, int64 startOffset)
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
		if (memcmp (buf + i, str, strLen) == 0)
			return i;
	}

	return -1;
}

// Returns TRUE if the file or directory exists (both may be enclosed in quotation marks).
BOOL FileExists (const char *filePathPtr)
{
	char filePath [TC_MAX_PATH];

	// Strip quotation marks (if any)
	if (filePathPtr [0] == '"')
	{
		strcpy (filePath, filePathPtr + 1);
	}
	else
	{
		strcpy (filePath, filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath [strlen (filePath) - 1] == '"')
		filePath [strlen (filePath) - 1] = 0;

    return (_access (filePath, 0) != -1);
}

// Searches the file from its end for the LAST occurrence of the string str.
// The string may contain zeroes, which do NOT terminate the string.
// If the string is found, its offset from the start of the file is returned. 
// If the string isn't found or if any error occurs, -1 is returned.
__int64 FindStringInFile (const char *filePath, const char* str, int strLen)
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
BOOL TCCopyFile (char *sourceFileName, char *destinationFile)
{
	__int8 *buffer;
	HANDLE src, dst;
	FILETIME fileTime;
	DWORD bytesRead, bytesWritten;
	BOOL res;

	src = CreateFile (sourceFileName,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src == INVALID_HANDLE_VALUE)
		return FALSE;

	dst = CreateFile (destinationFile,
		GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, 0, NULL);

	if (dst == INVALID_HANDLE_VALUE)
	{
		CloseHandle (src);
		return FALSE;
	}

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

	GetFileTime (src, NULL, NULL, &fileTime);
	SetFileTime (dst, NULL, NULL, &fileTime);

	CloseHandle (src);
	CloseHandle (dst);

	free (buffer);
	return res != 0;
}

// If bAppend is TRUE, the buffer is appended to an existing file. If bAppend is FALSE, any existing file 
// is replaced. If an error occurs, the incomplete file is deleted (provided that bAppend is FALSE).
BOOL SaveBufferToFile (const char *inputBuffer, const char *destinationFile, DWORD inputLength, BOOL bAppend)
{
	HANDLE dst;
	DWORD bytesWritten;
	BOOL res = TRUE;

	dst = CreateFile (destinationFile,
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, bAppend ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

	if (dst == INVALID_HANDLE_VALUE)
	{
		handleWin32Error (MainDlg);
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
			handleWin32Error (MainDlg);
	}

	CloseHandle (dst);

	if (!res && !bAppend)
		remove (destinationFile);

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
BOOL PrintHardCopyTextUTF16 (wchar_t *text, char *title, int textByteLen)
{
	char cl [MAX_PATH*3] = {"/p \""};
	char path [MAX_PATH * 2] = { 0 };
	char filename [MAX_PATH + 1] = { 0 };

	strcpy (filename, title);
	//strcat (filename, ".txt");

	GetTempPath (sizeof (path), path);

	if (!FileExists (path))
	{
		strcpy (path, GetConfigPath (filename));

		if (strlen(path) < 2)
			return FALSE;
	}
	else
	{
		strcat (path, filename);
	}

	// Write the Unicode signature
	if (!SaveBufferToFile ("\xFF\xFE", path, 2, FALSE))
	{
		remove (path);
		return FALSE;
	}

	// Write the actual text
	if (!SaveBufferToFile ((char *) text, path, textByteLen, TRUE))
	{
		remove (path);
		return FALSE;
	}

	strcat (cl, path);
	strcat (cl, "\"");

	// Get the absolute path for notepad
	if (GetWindowsDirectory(filename, MAX_PATH))
	{
		if (filename[strlen (filename) - 1] != '\\')
			strcat (filename, "\\");
		strcat(filename, PRINT_TOOL);
	}
	else
		strcpy(filename, "C:\\Windows\\" PRINT_TOOL);

	WaitCursor ();
	ShellExecute (NULL, "open", PRINT_TOOL, cl, NULL, SW_HIDE);
	Sleep (6000);
	NormalCursor();

	remove (path);

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

			char path[MAX_PATH * 2] = { 0 };

			// We can't use GetConfigPath() here because it would call us back (indirect recursion)
			if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path)))
			{
				strcat (path, "\\VeraCrypt\\");
				strcat (path, TC_APPD_FILENAME_SYSTEM_ENCRYPTION);

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
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
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
		char regk [64];

		GetStartupRegKeyName (regk);

		if (bStartOnLogon || bMountDevicesOnLogon || bMountFavoritesOnLogon)
		{
			char exe[MAX_PATH * 2] = { '"' };

			GetModuleFileName (NULL, exe + 1, sizeof (exe) - 1);

#ifdef VOLFORMAT
			{
				char *tmp = NULL;

				if (tmp = strrchr (exe, '\\'))
					strcpy (++tmp, "VeraCrypt.exe");
			}
#endif
			strcat (exe, "\" /q preferences /a logon");

			if (bMountDevicesOnLogon) strcat (exe, " /a devices");
			if (bMountFavoritesOnLogon) strcat (exe, " /a favorites");

			WriteRegistryString (regk, "VeraCrypt", exe);
		}
		else
			DeleteRegistryValue (regk, "VeraCrypt");
	}
}


// Adds or removes the TrueCrypt Volume Creation Wizard to/from the system startup sequence
void ManageStartupSeqWiz (BOOL bRemove, const char *arg)
{
	char regk [64];

	GetStartupRegKeyName (regk);

	if (!bRemove)
	{
		char exe[MAX_PATH * 2] = { '"' };
		GetModuleFileName (NULL, exe + 1, sizeof (exe) - 1);

#ifndef VOLFORMAT
			{
				char *tmp = NULL;

				if (tmp = strrchr (exe, '\\'))
					strcpy (++tmp, "VeraCrypt Format.exe");
			}
#endif

		if (strlen (arg) > 0)
		{
			strcat (exe, "\" ");
			strcat (exe, arg);
		}

		WriteRegistryString (regk, "VeraCrypt Format", exe);
	}
	else
		DeleteRegistryValue (regk, "VeraCrypt Format");
}


// Delete the last used Windows file selector path for TrueCrypt from the registry
void CleanLastVisitedMRU (void)
{
	WCHAR exeFilename[MAX_PATH];
	WCHAR *strToMatch;

	WCHAR strTmp[4096];
	char regPath[128];
	char key[64];
	int id, len;

	GetModuleFileNameW (NULL, exeFilename, sizeof (exeFilename) / sizeof(exeFilename[0]));
	strToMatch = wcsrchr (exeFilename, '\\') + 1;

	sprintf (regPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisited%sMRU", IsOSAtLeast (WIN_VISTA) ? "Pidl" : "");

	for (id = (IsOSAtLeast (WIN_VISTA) ? 0 : 'a'); id <= (IsOSAtLeast (WIN_VISTA) ? 1000 : 'z'); id++)
	{
		*strTmp = 0;
		sprintf (key, (IsOSAtLeast (WIN_VISTA) ? "%d" : "%c"), id);

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

					l = len = ReadRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "MRUListEx", buf, sizeof (buf));
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

					WriteRegistryBytes ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "MRUListEx", bufout, len);
				}
				else
				{
					char *p = buf;
					char *pout = bufout;

					ReadRegistryString ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", "MRUList", "", buf, sizeof (buf));
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

					WriteRegistryString ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU", "MRUList", bufout);
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


LRESULT ListItemAdd (HWND list, int index, char *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = 0;
	return ListView_InsertItem (list, &li);
}


LRESULT ListItemAddW (HWND list, int index, wchar_t *string)
{
	LVITEMW li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = 0;
	return SendMessageW (list, LVM_INSERTITEMW, 0, (LPARAM)(&li));
}


LRESULT ListSubItemSet (HWND list, int index, int subIndex, char *string)
{
	LVITEM li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = subIndex;
	return ListView_SetItem (list, &li);
}


LRESULT ListSubItemSetW (HWND list, int index, int subIndex, wchar_t *string)
{
	LVITEMW li;
	memset (&li, 0, sizeof(li));

	li.mask = LVIF_TEXT;
	li.pszText = string;
	li.iItem = index; 
	li.iSubItem = subIndex;
	return SendMessageW (list, LVM_SETITEMW, 0, (LPARAM)(&li));
}


BOOL GetMountList (MOUNT_LIST_STRUCT *list)
{
	DWORD dwResult;

	memset (list, 0, sizeof (*list));
	return DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, list,
		sizeof (*list), list, sizeof (*list), &dwResult,
		NULL);
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
BOOL LoadInt32 (char *filePath, unsigned __int32 *result, __int64 fileOffset)
{
	size_t bufSize = sizeof(__int32);
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
BOOL LoadInt16 (char *filePath, int *result, __int64 fileOffset)
{
	size_t bufSize = sizeof(__int16);
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
char *LoadFile (const char *fileName, DWORD *size)
{
	char *buf;
	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	*size = GetFileSize (h, NULL);
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
char *LoadFileBlock (char *fileName, __int64 fileOffset, size_t count)
{
	char *buf;
	DWORD bytesRead = 0;
	LARGE_INTEGER seekOffset, seekOffsetNew;

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

	ReadFile (h, buf, count, &bytesRead, NULL);

	CloseHandle (h);

	if (bytesRead != count)
	{
		free (buf);
		return NULL;
	}

	return buf;
}


// Returns -1 if there is an error, or the size of the file.
__int64 GetFileSize64 (const char *path)
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


char *GetModPath (char *path, int maxSize)
{
	GetModuleFileName (NULL, path, maxSize);
	strrchr (path, '\\')[1] = 0;
	return path;
}


char *GetConfigPath (char *fileName)
{
	static char path[MAX_PATH * 2] = { 0 };

	if (IsNonInstallMode ())
	{
		GetModPath (path, sizeof (path));
		strcat (path, fileName);

		return path;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		strcat (path, "\\VeraCrypt\\");
		CreateDirectory (path, NULL);
		strcat (path, fileName);
	}
	else
		path[0] = 0;

	return path;
}


char *GetProgramConfigPath (char *fileName)
{
	static char path[MAX_PATH * 2] = { 0 };

	if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		strcat (path, "\\VeraCrypt\\");
		CreateDirectory (path, NULL);
		strcat (path, fileName);
	}
	else
		path[0] = 0;

	return path;
}


std::string GetServiceConfigPath (const char *fileName)
{
	char sysPath[TC_MAX_PATH];
	
	if (Is64BitOs())
	{
		typedef UINT (WINAPI *GetSystemWow64Directory_t) (LPTSTR lpBuffer, UINT uSize);

		GetSystemWow64Directory_t getSystemWow64Directory = (GetSystemWow64Directory_t) GetProcAddress (GetModuleHandle ("kernel32"), "GetSystemWow64DirectoryA");
		getSystemWow64Directory (sysPath, sizeof (sysPath));
	}
	else
		GetSystemDirectory (sysPath, sizeof (sysPath));

	return string (sysPath) + "\\" + fileName;
}


// Returns 0 if an error occurs or the drive letter (as an upper-case char) of the system partition (e.g. 'C');
char GetSystemDriveLetter (void)
{
	char systemDir [MAX_PATH];

	if (GetSystemDirectory (systemDir, sizeof (systemDir)))
		return (char) (toupper (systemDir [0]));
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

	wcsncpy (tnid.szInfoTitle, headline, ARRAYSIZE (tnid.szInfoTitle) - 1);
	wcsncpy (tnid.szInfo, text, ARRAYSIZE (tnid.szInfo) - 1);

	// Display the balloon tooltip quickly twice in a row to avoid the slow and unwanted "fade-in" phase
	Shell_NotifyIconW (NIM_MODIFY, &tnid);
	Shell_NotifyIconW (NIM_MODIFY, &tnid);
}


// Either of the pointers may be NULL
void InfoBalloon (char *headingStringId, char *textStringId)
{
	if (Silent) 
		return;

	TaskBarIconDisplayBalloonTooltip (MainDlg,
		headingStringId == NULL ? L"VeraCrypt" : GetString (headingStringId), 
		textStringId == NULL ? L" " : GetString (textStringId), 
		FALSE);
}


// Either of the pointers may be NULL
void InfoBalloonDirect (wchar_t *headingString, wchar_t *textString)
{
	if (Silent) 
		return;

	TaskBarIconDisplayBalloonTooltip (MainDlg,
		headingString == NULL ? L"VeraCrypt" : headingString, 
		textString == NULL ? L" " : textString, 
		FALSE);
}


// Either of the pointers may be NULL
void WarningBalloon (char *headingStringId, char *textStringId)
{
	if (Silent) 
		return;

	TaskBarIconDisplayBalloonTooltip (MainDlg,
		headingStringId == NULL ? L"VeraCrypt" : GetString (headingStringId), 
		textStringId == NULL ? L" " : GetString (textStringId), 
		TRUE);
}


// Either of the pointers may be NULL
void WarningBalloonDirect (wchar_t *headingString, wchar_t *textString)
{
	if (Silent) 
		return;

	TaskBarIconDisplayBalloonTooltip (MainDlg,
		headingString == NULL ? L"VeraCrypt" : headingString, 
		textString == NULL ? L" " : textString, 
		TRUE);
}


int Info (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONINFORMATION);
}


int InfoTopMost (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
}


int InfoDirect (const wchar_t *msg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, msg, lpszTitle, MB_ICONINFORMATION);
}


int Warning (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING);
}


int WarningTopMost (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


int WarningDirect (const wchar_t *warnMsg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, warnMsg, lpszTitle, MB_ICONWARNING);
}


int Error (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR);
}


int ErrorTopMost (char *stringId)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


int ErrorDirect (const wchar_t *errMsg)
{
	if (Silent) return 0;
	return MessageBoxW (MainDlg, errMsg, lpszTitle, MB_ICONERROR);
}


int AskYesNo (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);
}


int AskYesNoString (const wchar_t *str)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, str, lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1);
}


int AskYesNoTopmost (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskNoYes (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
}


int AskOkCancel (char *stringId)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONQUESTION | MB_OKCANCEL | MB_DEFBUTTON1);
}


int AskWarnYesNo (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
}


int AskWarnYesNoString (const wchar_t *string)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
}


int AskWarnYesNoTopmost (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnYesNoStringTopmost (const wchar_t *string)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnNoYes (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnNoYesString (const wchar_t *string)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, string, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
}


int AskWarnNoYesTopmost (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST);
}


int AskWarnOkCancel (char *stringId)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON1);
}


int AskWarnCancelOk (char *stringId)
{
	if (Silent) return IDCANCEL;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2);
}


int AskErrYesNo (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON1);
}


int AskErrNoYes (char *stringId)
{
	if (Silent) return IDNO;
	return MessageBoxW (MainDlg, GetString (stringId), lpszTitle, MB_ICONERROR | MB_YESNO | MB_DEFBUTTON2);
}


// The function accepts two input formats:
// Input format 1: {0, "MESSAGE_STRING_ID", "BUTTON_1_STRING_ID", ... "LAST_BUTTON_STRING_ID", 0};
// Input format 2: {L"", L"Message text", L"Button caption 1", ... L"Last button caption", 0};
// The second format is to be used if any of the strings contains format specification (e.g. %s, %d) or
// in any other cases where a string needs to be resolved before calling this function.
// If the returned value is 0, the user closed the dialog window without making a choice. 
// If the user made a choice, the returned value is the ordinal number of the choice (1..MAX_MULTI_CHOICES)
int AskMultiChoice (void *strings[], BOOL bBold)
{
	MULTI_CHOICE_DLGPROC_PARAMS params;

	params.strings = &strings[0];
	params.bold = bBold;

	return DialogBoxParamW (hInst, 
		MAKEINTRESOURCEW (IDD_MULTI_CHOICE_DLG), MainDlg,
		(DLGPROC) MultiChoiceDialogProc, (LPARAM) &params);
}


BOOL ConfigWriteBegin ()
{
	DWORD size;
	if (ConfigFileHandle != NULL) 
		return FALSE;

	if (ConfigBuffer == NULL)
		ConfigBuffer = LoadFile (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), &size);

	ConfigFileHandle = fopen (GetConfigPath (TC_APPD_FILENAME_CONFIGURATION), "w");
	if (ConfigFileHandle == NULL)
	{
		free (ConfigBuffer);
		ConfigBuffer = NULL;
		return FALSE;
	}
	XmlWriteHeader (ConfigFileHandle);
	fputs ("\n\t<configuration>", ConfigFileHandle);

	return TRUE;
}


BOOL ConfigWriteEnd ()
{
	char *xml = ConfigBuffer;
	char key[128], value[2048];

	if (ConfigFileHandle == NULL) return FALSE;

	// Write unmodified values
	while (xml && (xml = XmlFindElement (xml, "config")))
	{
		XmlGetAttributeText (xml, "key", key, sizeof (key));
		XmlGetNodeText (xml, value, sizeof (value));

		fprintf (ConfigFileHandle, "\n\t\t<config key=\"%s\">%s</config>", key, value);
		xml++;
	}

	fputs ("\n\t</configuration>", ConfigFileHandle);
	XmlWriteFooter (ConfigFileHandle);

	TCFlushFile (ConfigFileHandle);

	CheckFileStreamWriteErrors (ConfigFileHandle, TC_APPD_FILENAME_CONFIGURATION);

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

	return 0 != fprintf (
		ConfigFileHandle, "\n\t\t<config key=\"%s\">%s</config>",
		configKey, configValue);
}


BOOL ConfigWriteInt (char *configKey, int configValue)
{
	char val[32];
	sprintf (val, "%d", configValue);
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
		return defaultValue;
}


void OpenPageHelp (HWND hwndDlg, int nPage)
{
	int r = (int)ShellExecute (NULL, "open", szHelpFile, NULL, NULL, SW_SHOWNORMAL);

	if (r == ERROR_FILE_NOT_FOUND)
	{
		// Try the secondary help file
		r = (int)ShellExecute (NULL, "open", szHelpFile2, NULL, NULL, SW_SHOWNORMAL);

		if (r == ERROR_FILE_NOT_FOUND)
		{
			OpenOnlineHelp ();
			return;
		}
	}

	if (r == SE_ERR_NOASSOC)
	{
		if (AskYesNo ("HELP_READER_ERROR") == IDYES)
			OpenOnlineHelp ();
	}
}


void OpenOnlineHelp ()
{
	Applink ("help", TRUE, "");
}


#ifndef SETUP

void RestoreDefaultKeyFilesParam (void)
{
	KeyFileRemoveAll (&FirstKeyFile);
	if (defaultKeyFilesParam.FirstKeyFile != NULL)
	{
		FirstKeyFile = KeyFileCloneAll (defaultKeyFilesParam.FirstKeyFile);
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

		if (XmlGetNodeText (xml, kf->FileName, sizeof (kf->FileName)) != NULL)
			defaultKeyFilesParam.FirstKeyFile = KeyFileAdd (defaultKeyFilesParam.FirstKeyFile, kf);
		else
			free (kf);

		xml++;
	}

	free (defaultKeyfilesFile);
	KeyFilesEnable = defaultKeyFilesParam.EnableKeyFiles;

	return status;
}

#endif /* #ifndef SETUP */


void Debug (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	_vsnprintf (buf, sizeof (buf), format, val);
	va_end(val);

	OutputDebugString (buf);
}


void DebugMsgBox (char *format, ...)
{
	char buf[1024];
	va_list val;

	va_start(val, format);
	_vsnprintf (buf, sizeof (buf), format, val);
	va_end(val);

	MessageBox (MainDlg, buf, "VeraCrypt debug", 0);
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

	default:
		TC_THROW_FATAL_EXCEPTION;
		break;
	}

	return ((CurrentOSMajor << 16 | CurrentOSMinor << 8 | CurrentOSServicePack)
		>= (major << 16 | minor << 8 | reqMinServicePack));
}


BOOL Is64BitOs ()
{
    static BOOL isWow64 = FALSE;
	static BOOL valid = FALSE;
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS ) (HANDLE hProcess,PBOOL Wow64Process);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	if (valid)
		return isWow64;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle("kernel32"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
        if (!fnIsWow64Process (GetCurrentProcess(), &isWow64))
			isWow64 = FALSE;

	valid = TRUE;
    return isWow64;
}


BOOL IsServerOS ()
{
	OSVERSIONINFOEXA osVer;
	osVer.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXA);
	GetVersionExA ((LPOSVERSIONINFOA) &osVer);

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
	Wow64EnableWow64FsRedirection_t wow64EnableWow64FsRedirection = (Wow64EnableWow64FsRedirection_t) GetProcAddress (GetModuleHandle ("kernel32"), "Wow64EnableWow64FsRedirection");

    if (!wow64EnableWow64FsRedirection)
		return FALSE;

    return wow64EnableWow64FsRedirection (enable);
}


BOOL RestartComputer (void)
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

	if (!ExitWindowsEx (EWX_REBOOT,
		SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED)) 
	{
		CloseHandle(hTkn);
		return false; 
	}

	CloseHandle(hTkn);
	return true;
}


std::string GetWindowsEdition ()
{
	string osname = "win";

	OSVERSIONINFOEXA osVer;
	osVer.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXA);
	GetVersionExA ((LPOSVERSIONINFOA) &osVer);

	BOOL home = (osVer.wSuiteMask & VER_SUITE_PERSONAL);
	BOOL server = (osVer.wProductType == VER_NT_SERVER || osVer.wProductType == VER_NT_DOMAIN_CONTROLLER);

	HKEY hkey;
	char productName[300] = {0};
	DWORD productNameSize = sizeof (productName);
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, "ProductName", 0, 0, (LPBYTE) &productName, &productNameSize) != ERROR_SUCCESS || productNameSize < 1)
			productName[0] = 0;

		RegCloseKey (hkey);
	}

	switch (nCurrentOS)
	{
	case WIN_2000:
		osname += "2000";
		break;

	case WIN_XP:
	case WIN_XP64:
		osname += "xp";
		osname += home ? "-home" : "-pro";
		break;

	case WIN_SERVER_2003:
		osname += "2003";
		break;

	case WIN_VISTA:
		osname += "vista";
		break;

	case WIN_SERVER_2008:
		osname += "2008";
		break;

	case WIN_7:
		osname += "7";
		break;

	case WIN_SERVER_2008_R2:
		osname += "2008r2";
		break;

	default:
		stringstream s;
		s << CurrentOSMajor << "." << CurrentOSMinor;
		osname += s.str();
		break;
	}

	if (server)
		osname += "-server";

	if (IsOSAtLeast (WIN_VISTA))
	{	
		if (home)
			osname += "-home";
		else if (strstr (productName, "Standard") != 0)
			osname += "-standard";
		else if (strstr (productName, "Professional") != 0)
			osname += "-pro";
		else if (strstr (productName, "Business") != 0)
			osname += "-business";
		else if (strstr (productName, "Enterprise") != 0)
			osname += "-enterprise";
		else if (strstr (productName, "Datacenter") != 0)
			osname += "-datacenter";
		else if (strstr (productName, "Ultimate") != 0)
			osname += "-ultimate";
	}

	if (GetSystemMetrics (SM_STARTER))
		osname += "-starter";
	else if (strstr (productName, "Basic") != 0)
		osname += "-basic";

	if (Is64BitOs())
		osname += "-x64";

	if (CurrentOSServicePack > 0)
	{
		stringstream s;
		s << "-sp" << CurrentOSServicePack;
		osname += s.str();
	}

	return osname;
}


void Applink (char *dest, BOOL bSendOS, char *extraOutput)
{
	char url [MAX_URL_LENGTH];

	ArrowWaitCursor ();

	// sprintf_s (url, sizeof (url), TC_APPLINK "%s%s&dest=%s", bSendOS ? ("&os=" + GetWindowsEdition()).c_str() : "", extraOutput, dest);
	sprintf_s (url, sizeof (url),"%s", "https://sourceforge.net/projects/veracrypt/");
	ShellExecute (NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

	Sleep (200);
	NormalCursor ();
}


char *RelativePath2Absolute (char *szFileName)
{
	if (szFileName[0] != '\\'
		&& strchr (szFileName, ':') == 0
		&& strstr (szFileName, "Volume{") != szFileName)
	{
		char path[MAX_PATH*2];
		GetCurrentDirectory (MAX_PATH, path);

		if (path[strlen (path) - 1] != '\\')
			strcat (path, "\\");

		strcat (path, szFileName);
		strncpy (szFileName, path, MAX_PATH-1);
	}

	return szFileName;
}


void HandleDriveNotReadyError ()
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return;

	if (RegQueryValueEx (hkey, "NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS 
		&& value != 0)
	{
		Warning ("SYS_AUTOMOUNT_DISABLED");
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		Warning ("SYS_ASSIGN_DRIVE_LETTER");
	else
		Warning ("DEVICE_NOT_READY_ERROR");

	RegCloseKey (hkey);
}


BOOL CALLBACK CloseTCWindowsEnum (HWND hwnd, LPARAM lParam)
{
	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'VERA')
	{
		char name[1024] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strstr (name, "VeraCrypt"))
		{
			PostMessage (hwnd, TC_APPMSG_CLOSE_BKG_TASK, 0, 0);

			if (DriverVersion < 0x0430)
				PostMessage (hwnd, WM_ENDSESSION, 0, 0);

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

	if (GetWindowLongPtr (hwnd, GWLP_USERDATA) == (LONG_PTR) 'VERA')
	{
		char name[32] = { 0 };
		GetWindowText (hwnd, name, sizeof (name) - 1);
		if (hwnd != MainDlg && strcmp (name, "VeraCrypt") == 0)
		{
			if (lParam != 0)
				*((HWND *)lParam) = hwnd;
		}
	}
	return TRUE;
}


BYTE *MapResource (char *resourceType, int resourceId, PDWORD size)
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

	wsprintfW (finalMsg, GetString ("INCONSISTENCY_RESOLVED"), techInfo);
	MessageBoxW (MainDlg, finalMsg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


void ReportUnexpectedState (char *techInfo)
{
	wchar_t finalMsg[8024];

	wsprintfW (finalMsg, GetString ("UNEXPECTED_STATE"), techInfo);
	MessageBoxW (MainDlg, finalMsg, lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


#ifndef SETUP

int OpenVolume (OpenVolumeContext *context, const char *volumePath, Password *password, BOOL write, BOOL preserveTimestamps, BOOL useBackupHeader)
{
	int status = ERR_PARAMETER_INCORRECT;
	int volumeType;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	LARGE_INTEGER headerOffset;
	DWORD dwResult;
	DISK_GEOMETRY deviceGeometry;

	context->VolumeIsOpen = FALSE;
	context->CryptoInfo = NULL;
	context->HostFileHandle = INVALID_HANDLE_VALUE;
	context->TimestampsValid = FALSE;

	CreateFullVolumePath (szDiskFile, volumePath, &context->IsDevice);

	if (context->IsDevice)
	{
		status = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
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
		strcpy (szCFDevice, szDiskFile);

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
			DISK_GEOMETRY driveInfo;

			if (!DeviceIoControl (context->HostFileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
			{
				status = ERR_OS_ERROR;
				goto error;
			}

			context->HostSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector * driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
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

		case TC_VOLUME_TYPE_HIDDEN_LEGACY:
			if (useBackupHeader)
			{
				status = ERR_PASSWORD_WRONG;
				goto error;
			}

			if (context->IsDevice && deviceGeometry.BytesPerSector != TC_SECTOR_SIZE_LEGACY)
				continue;

			headerOffset.QuadPart = context->HostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY;
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
		status = ReadVolumeHeader (FALSE, buffer, password, &context->CryptoInfo, NULL);

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


int ReEncryptVolumeHeader (char *buffer, BOOL bBoot, CRYPTO_INFO *cryptoInfo, Password *password, BOOL wipeMode)
{
	CRYPTO_INFO *newCryptoInfo = NULL;
	
	RandSetHashFunction (cryptoInfo->pkcs5);

	if (Randinit() != ERR_SUCCESS)
		return ERR_PARAMETER_INCORRECT;

	UserEnrichRandomPool (NULL);

	int status = CreateVolumeHeaderInMemory (bBoot,
		buffer,
		cryptoInfo->ea,
		cryptoInfo->mode,
		password,
		cryptoInfo->pkcs5,
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

	char data[65536];
	DWORD size = sizeof (data);
	
	if (IsPagingFileWildcardActive())
		return TRUE;

	if (ReadLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", data, &size)
		&& size > 12 && !checkNonWindowsPartitionsOnly)
		return TRUE;

	if (!IsAdmin())
		AbortProcess ("UAC_INIT_ERROR");

	for (char drive = 'C'; drive <= 'Z'; ++drive)
	{
		// Query geometry of the drive first to prevent "no medium" pop-ups
		string drivePath = "\\\\.\\X:";
		drivePath[4] = drive;

		if (checkNonWindowsPartitionsOnly)
		{
			char sysDir[MAX_PATH];
			if (GetSystemDirectory (sysDir, sizeof (sysDir)) != 0 && toupper (sysDir[0]) == drive)
				continue;
		}

		HANDLE handle = CreateFile (drivePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		
		if (handle == INVALID_HANDLE_VALUE)
			continue;

		DISK_GEOMETRY driveInfo;
		DWORD dwResult;

		if (!DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
		{
			CloseHandle (handle);
			continue;
		}

		CloseHandle (handle);

		// Test if a paging file exists and is locked by another process
		string path = "X:\\pagefile.sys";
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
	char pagingFiles[65536];
	DWORD size = sizeof (pagingFiles);
	char *mmKey = "System\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

	if (!ReadLocalMachineRegistryString (mmKey, "PagingFiles", pagingFiles, &size))
	{
		size = sizeof (pagingFiles);
		if (!ReadLocalMachineRegistryMultiString (mmKey, "PagingFiles", pagingFiles, &size))
			size = 0;
	}

	return size > 0 && strstr (pagingFiles, "?:\\") == pagingFiles;
}


BOOL DisablePagingFile ()
{
	char empty[] = { 0, 0 };
	return WriteLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", empty, sizeof (empty));
}


std::wstring SingleStringToWide (const std::string &singleString)
{
	if (singleString.empty())
		return std::wstring();

	WCHAR wbuf[65536];
	int wideLen = MultiByteToWideChar (CP_ACP, 0, singleString.c_str(), -1, wbuf, array_capacity (wbuf) - 1);
	throw_sys_if (wideLen == 0);

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


std::string WideToSingleString (const std::wstring &wideString)
{
	if (wideString.empty())
		return std::string();

	char buf[65536];
	int len = WideCharToMultiByte (CP_ACP, 0, wideString.c_str(), -1, buf, array_capacity (buf) - 1, NULL, NULL);
	throw_sys_if (len == 0);

	buf[len] = 0;
	return buf;
}


std::string StringToUpperCase (const std::string &str)
{
	string upperCase (str);
	_strupr ((char *) upperCase.c_str());
	return upperCase;
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
			wsprintfW (s, GetString ("ENTER_TOKEN_PASSWORD"), Utf8StringToWide (password->c_str()).c_str());
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
					handleWin32Error (hwndDlg);
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
			char tmp[SecurityToken::MaxPasswordLength+1];
			memset (tmp, 'X', SecurityToken::MaxPasswordLength);
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
				Error ("NO_TOKENS_FOUND");
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}

			foreach (const SecurityTokenInfo &token, tokens)
			{
				wstringstream tokenLabel;
				tokenLabel << L"[" << token.SlotId << L"] " << token.Label;

				AddComboPairW (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN), tokenLabel.str().c_str(), token.SlotId);
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

				newParams->SlotId = ComboBox_GetItemData (GetDlgItem (hwndDlg, IDC_SELECTED_TOKEN), selectedToken);

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

		stringstream s;
		s << keyfile.SlotId;

		ListItemAdd (tokenListControl, lvItem.iItem, (char *) s.str().c_str());
		ListSubItemSetW (tokenListControl, lvItem.iItem, 1, (wchar_t *) keyfile.Token.Label.c_str());
		ListSubItemSetW (tokenListControl, lvItem.iItem, 2, (wchar_t *) keyfile.Id.c_str());
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

		switch (lw)
		{
		case IDCANCEL:
			EndDialog (hwndDlg, IDCANCEL);
			return 1;

		case IDC_IMPORT_KEYFILE:
			{
				char keyfilePath[TC_MAX_PATH];

				if (BrowseFiles (hwndDlg, "SELECT_KEYFILE", keyfilePath, bHistory, FALSE, NULL))
				{
					DWORD keyfileSize;
					byte *keyfileData = (byte *) LoadFile (keyfilePath, &keyfileSize);
					if (!keyfileData)
					{
						handleWin32Error (hwndDlg);
						return 1;
					}

					if (keyfileSize != 0)
					{
						NewSecurityTokenKeyfileDlgProcParams newParams;
						newParams.Name = WideToUtf8String (SingleStringToWide (keyfilePath));

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
						handleWin32Error (hwndDlg);
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
						char keyfilePath[TC_MAX_PATH];

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
								handleWin32Error (hwndDlg);
								return 1;
							}

							finally_do_arg (vector <byte> *, &keyfileData, { burn (&finally_arg->front(), finally_arg->size()); });

							if (!SaveBufferToFile ((char *) &keyfileData.front(), keyfilePath, keyfileData.size(), FALSE))
								throw SystemException ();
						}

						Info ("KEYFILE_EXPORTED");
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
				if (AskNoYes ("CONFIRM_SEL_FILES_DELETE") == IDNO)
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

		return 0;
	}
	return 0;
}


BOOL InitSecurityTokenLibrary ()
{
	if (SecurityTokenLibraryPath[0] == 0)
	{
		Error ("NO_PKCS11_MODULE_SPECIFIED");
		return FALSE;
	}

	struct PinRequestHandler : public GetPinFunctor
	{
		virtual void operator() (string &str)
		{
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_PASSWORD), MainDlg, (DLGPROC) SecurityTokenPasswordDlgProc, (LPARAM) &str) == IDCANCEL)
				throw UserAbort (SRC_POS);

			if (hCursor != NULL)
				SetCursor (hCursor);
		}
	};

	struct WarningHandler : public SendExceptionFunctor
	{
		virtual void operator() (const Exception &e)
		{
			e.Show (NULL);
		}
	};

	try
	{
		SecurityToken::InitLibrary (SecurityTokenLibraryPath, auto_ptr <GetPinFunctor> (new PinRequestHandler), auto_ptr <SendExceptionFunctor> (new WarningHandler));
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		Error ("PKCS11_MODULE_INIT_FAILED");
		return FALSE;
	}

	return TRUE;
}

#endif // !SETUP

std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties, bool singleList, bool noFloppy, bool detectUnencryptedFilesystems)
{
	vector <HostDevice> devices;
	size_t dev0;

	for (int devNumber = 0; devNumber < MAX_HOST_DRIVE_NUMBER; devNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			stringstream strm;
			strm << "\\Device\\Harddisk" << devNumber << "\\Partition" << partNumber;
			string devPathStr (strm.str());
			const char *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest;
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems && partNumber != 0))
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

			device.HasUnencryptedFilesystem = (detectUnencryptedFilesystems && openTest.FilesystemDetected) ? true : false;

			if (!noDeviceProperties)
			{
				DISK_GEOMETRY geometry;

				wstringstream ws;
				ws << devPathStr.c_str();
				int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

				if (driveNumber >= 0)
				{
					device.MountPoint += (char) (driveNumber + 'A');
					device.MountPoint += ":";

					wchar_t name[64];
					if (GetDriveLabel (driveNumber, name, sizeof (name)))
						device.Name = name;

					if (GetSystemDriveLetter() == 'A' + driveNumber)
						device.ContainsSystem = true;
				}

				if (partNumber == 0 && GetDriveGeometry (devPath, &geometry))
					device.Removable = (geometry.MediaType == RemovableMedia);
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
			stringstream strm;
			strm << "\\Device\\HarddiskVolume" << devNumber;
			string devPathStr (strm.str());
			const char *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest;
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems))
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
					wstringstream ws;
					ws << devPathStr.c_str();
					int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

					if (driveNumber >= 0)
					{
						device.MountPoint += (char) (driveNumber + 'A');
						device.MountPoint += ":";

						wchar_t name[64];
						if (GetDriveLabel (driveNumber, name, sizeof (name)))
							device.Name = name;

						if (GetSystemDriveLetter() == 'A' + driveNumber)
							device.ContainsSystem = true;
					}
				}

				devices.push_back (device);
			}
		}
	}

	return devices;
}


BOOL FileHasReadOnlyAttribute (const char *path)
{
	DWORD attributes = GetFileAttributes (path);
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0;
}


BOOL IsFileOnReadOnlyFilesystem (const char *path)
{
	char root[MAX_PATH];
	if (!GetVolumePathName (path, root, sizeof (root)))
		return FALSE;

	DWORD flags, d;
	if (!GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
		return FALSE;

	return (flags & FILE_READ_ONLY_VOLUME) ? TRUE : FALSE;
}


void CheckFilesystem (int driveNo, BOOL fixErrors)
{
	wchar_t msg[1024], param[1024], cmdPath[MAX_PATH];
	char driveRoot[] = { 'A' + (char) driveNo, ':', 0 };

	if (fixErrors && AskWarnYesNo ("FILESYS_REPAIR_CONFIRM_BACKUP") == IDNO)
		return;

	wsprintfW (msg, GetString (fixErrors ? "REPAIRING_FS" : "CHECKING_FS"), driveRoot);
	wsprintfW (param, fixErrors ? L"/C echo %s & chkdsk %hs /F /X & pause" : L"/C echo %s & chkdsk %hs & pause", msg, driveRoot);

	if (GetSystemDirectoryW(cmdPath, MAX_PATH))
	{
		lstrcatW(cmdPath, L"\\cmd.exe");
	}
	else
		lstrcpyW(cmdPath, L"C:\\Windows\\System32\\cmd.exe");

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

int AskNonSysInPlaceEncryptionResume ()
{
	if (AskWarnYesNo ("NONSYS_INPLACE_ENC_RESUME_PROMPT") == IDYES)
		return IDYES;

	char *multiChoiceStr[] = { 0, "ASK_NONSYS_INPLACE_ENC_NOTIFICATION_REMOVAL", "DO_NOT_PROMPT_ME", "KEEP_PROMPTING_ME", 0 };

	switch (AskMultiChoice ((void **) multiChoiceStr, FALSE))
	{
	case 1:
		RemoveNonSysInPlaceEncNotifications();
		Warning ("NONSYS_INPLACE_ENC_NOTIFICATION_REMOVAL_NOTE");
		break;

	default:
		// NOP
		break;
	}

	return IDNO;
}

#endif // !SETUP


BOOL RemoveDeviceWriteProtection (HWND hwndDlg, char *devicePath)
{
	int driveNumber;
	int partitionNumber;

	char temp[MAX_PATH*2];
	char cmdBatch[MAX_PATH*2];
	char diskpartScript[MAX_PATH*2];

	if (sscanf (devicePath, "\\Device\\Harddisk%d\\Partition%d", &driveNumber, &partitionNumber) != 2)
		return FALSE;

	if (GetTempPath (sizeof (temp), temp) == 0)
		return FALSE;

	_snprintf (cmdBatch, sizeof (cmdBatch), "%s\\VeraCrypt_Write_Protection_Removal.cmd", temp);
	_snprintf (diskpartScript, sizeof (diskpartScript), "%s\\VeraCrypt_Write_Protection_Removal.diskpart", temp);

	FILE *f = fopen (cmdBatch, "w");
	if (!f)
	{
		handleWin32Error (hwndDlg);
		return FALSE;
	}

	fprintf (f, "@diskpart /s \"%s\"\n@pause\n@del \"%s\" \"%s\"", diskpartScript, diskpartScript, cmdBatch);

	CheckFileStreamWriteErrors (f, cmdBatch);
	fclose (f);

	f = fopen (diskpartScript, "w");
	if (!f)
	{
		handleWin32Error (hwndDlg);
		DeleteFile (cmdBatch);
		return FALSE;
	}

	fprintf (f, "select disk %d\nattributes disk clear readonly\n", driveNumber);

	if (partitionNumber != 0)
		fprintf (f, "select partition %d\nattributes volume clear readonly\n", partitionNumber);

	fprintf (f, "exit\n");

	CheckFileStreamWriteErrors (f, diskpartScript);
	fclose (f);

	ShellExecute (NULL, (!IsAdmin() && IsUacSupported()) ? "runas" : "open", cmdBatch, NULL, NULL, SW_SHOW);

	return TRUE;
}


static LRESULT CALLBACK EnableElevatedCursorChangeWndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc (hWnd, message, wParam, lParam);
}


void EnableElevatedCursorChange (HWND parent)
{
	// Create a transparent window to work around a UAC issue preventing change of the cursor
	if (UacElevated)
	{
		const char *className = "VeraCryptEnableElevatedCursorChange";
		WNDCLASSEX winClass;
		HWND hWnd;

		memset (&winClass, 0, sizeof (winClass));
		winClass.cbSize = sizeof (WNDCLASSEX); 
		winClass.lpfnWndProc = (WNDPROC) EnableElevatedCursorChangeWndProc;
		winClass.hInstance = hInst;
		winClass.lpszClassName = className;
		RegisterClassEx (&winClass);

		hWnd = CreateWindowEx (WS_EX_TOOLWINDOW | WS_EX_LAYERED, className, "VeraCrypt UAC", 0, 0, 0, GetSystemMetrics (SM_CXSCREEN), GetSystemMetrics (SM_CYSCREEN), parent, NULL, hInst, NULL);
		SetLayeredWindowAttributes (hWnd, 0, 1, LWA_ALPHA);
		ShowWindow (hWnd, SW_SHOWNORMAL);

		DestroyWindow (hWnd);
		UnregisterClass (className, hInst);
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


BOOL VolumePathExists (char *volumePath)
{
	OPEN_TEST_STRUCT openTest;
	char upperCasePath[TC_MAX_PATH];

	UpperCaseCopy (upperCasePath, volumePath);

	if (strstr (upperCasePath, "\\DEVICE\\") == upperCasePath)
		return OpenDevice (volumePath, &openTest, FALSE);

	string path = volumePath;
	if (path.find ("\\\\?\\Volume{") == 0 && path.rfind ("}\\") == path.size() - 2)
	{
		char devicePath[TC_MAX_PATH];
		if (QueryDosDevice (path.substr (4, path.size() - 5).c_str(), devicePath, TC_MAX_PATH) != 0)
			return TRUE;
	}

	return _access (volumePath, 0) == 0;
}


BOOL IsWindowsIsoBurnerAvailable ()
{
	char path[MAX_PATH*2] = { 0 };

	if (!IsOSAtLeast (WIN_7))
	{
		return FALSE;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_SYSTEM, NULL, 0, path)))
	{
		strcat (path, "\\" ISO_BURNER_TOOL);

		return (FileExists (path));
	}

	return FALSE;
}


BOOL LaunchWindowsIsoBurner (HWND hwnd, const char *isoPath)
{
	char path[MAX_PATH*2] = { 0 };
	int r;

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_SYSTEM, NULL, 0, path)))
		strcat (path, "\\" ISO_BURNER_TOOL);
	else
		strcpy (path, "C:\\Windows\\System32\\" ISO_BURNER_TOOL);

	r = (int) ShellExecute (hwnd, "open", path, (string ("\"") + isoPath + "\"").c_str(), NULL, SW_SHOWNORMAL);

	if (r <= 32)
	{
		SetLastError (r);
		handleWin32Error (hwnd);

		return FALSE;
	}

	return TRUE;
}


std::string VolumeGuidPathToDevicePath (std::string volumeGuidPath)
{
	if (volumeGuidPath.find ("\\\\?\\") == 0)
		volumeGuidPath = volumeGuidPath.substr (4);

	if (volumeGuidPath.find ("Volume{") != 0 || volumeGuidPath.rfind ("}\\") != volumeGuidPath.size() - 2)
		return string();

	char volDevPath[TC_MAX_PATH];
	if (QueryDosDevice (volumeGuidPath.substr (0, volumeGuidPath.size() - 1).c_str(), volDevPath, TC_MAX_PATH) == 0)
		return string();

	string partitionPath = HarddiskVolumePathToPartitionPath (volDevPath);

	return partitionPath.empty() ? volDevPath : partitionPath;
}


std::string HarddiskVolumePathToPartitionPath (const std::string &harddiskVolumePath)
{
	wstring volPath = SingleStringToWide (harddiskVolumePath);

	for (int driveNumber = 0; driveNumber < MAX_HOST_DRIVE_NUMBER; driveNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			wchar_t partitionPath[TC_MAX_PATH];
			swprintf_s (partitionPath, ARRAYSIZE (partitionPath), L"\\Device\\Harddisk%d\\Partition%d", driveNumber, partNumber);

			wchar_t resolvedPath[TC_MAX_PATH];
			if (ResolveSymbolicLink (partitionPath, resolvedPath))
			{
				if (volPath == resolvedPath)
					return WideToSingleString (partitionPath);
			}
			else if (partNumber == 0)
				break;
		}
	}

	return string();
}


BOOL IsApplicationInstalled (const char *appName)
{
	const char *uninstallRegName = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
	BOOL installed = FALSE;
	HKEY unistallKey;
	LONG res = RegOpenKeyEx (HKEY_LOCAL_MACHINE, uninstallRegName, 0, KEY_READ | KEY_WOW64_64KEY, &unistallKey);
	if (res != ERROR_SUCCESS)
	{
		SetLastError (res);
		return FALSE;
	}

	char regName[1024];
	DWORD regNameSize = sizeof (regName);
	DWORD index = 0;
	while (RegEnumKeyEx (unistallKey, index++, regName, &regNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		if (strstr (regName, "{") == regName)
		{
			regNameSize = sizeof (regName);
			if (!ReadLocalMachineRegistryStringNonReflected ((string (uninstallRegName) + "\\" + regName).c_str(), "DisplayName", regName, &regNameSize))
				regName[0] = 0;
		}

		if (_stricmp (regName, appName) == 0)
		{
			installed = TRUE;
			break;
		}

		regNameSize = sizeof (regName);
	}

	RegCloseKey (unistallKey);
	return installed;
}


std::string FindLatestFileOrDirectory (const std::string &directory, const char *namePattern, bool findDirectory, bool findFile)
{
	string name;
	ULARGE_INTEGER latestTime;
	latestTime.QuadPart = 0;
	WIN32_FIND_DATA findData;

	HANDLE find = FindFirstFile ((directory + "\\" + namePattern).c_str(), &findData);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (strcmp (findData.cFileName, ".") == 0 || strcmp (findData.cFileName, "..") == 0)
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

	return string (directory) + "\\" + name;
}
