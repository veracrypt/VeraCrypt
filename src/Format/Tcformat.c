/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <io.h>
#include <sys/stat.h>
#include <shlobj.h>

#include "Crypto.h"
#include "cpu.h"
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Combo.h"
#include "Registry.h"
#include "Boot/Windows/BootDefs.h"
#include "Common/Common.h"
#include "Common/BootEncryption.h"
#include "Common/Dictionary.h"
#include "Common/Endian.h"
#include "Common/resource.h"
#include "Common/Pkcs5.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include "Random.h"
#include "Fat.h"
#include "InPlace.h"
#include "Resource.h"
#include "TcFormat.h"
#include "Format.h"
#include "FormatCom.h"
#include "Password.h"
#include "Progress.h"
#include "Tests.h"
#include "Cmdline.h"
#include "Volumes.h"
#include "Wipe.h"
#include "Xml.h"
#include "SecurityToken.h"

#include <Strsafe.h>

using namespace VeraCrypt;

enum wizard_pages
{
	/* IMPORTANT: IF YOU ADD/REMOVE/MOVE ANY PAGES THAT ARE RELATED TO SYSTEM ENCRYPTION,
	REVISE THE 'DECOY_OS_INSTRUCTIONS_PORTION_??' STRINGS! */

	INTRO_PAGE,
			SYSENC_TYPE_PAGE,
					SYSENC_HIDDEN_OS_REQ_CHECK_PAGE,
			SYSENC_SPAN_PAGE,
			SYSENC_PRE_DRIVE_ANALYSIS_PAGE,
			SYSENC_DRIVE_ANALYSIS_PAGE,
			SYSENC_MULTI_BOOT_MODE_PAGE,
			SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE,
			SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE,
			SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE,
			SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE,
			SYSENC_MULTI_BOOT_OUTCOME_PAGE,
	VOLUME_TYPE_PAGE,
				HIDDEN_VOL_WIZARD_MODE_PAGE,
	VOLUME_LOCATION_PAGE,
		DEVICE_TRANSFORM_MODE_PAGE,
				HIDDEN_VOL_HOST_PRE_CIPHER_PAGE,
				HIDDEN_VOL_PRE_CIPHER_PAGE,
	CIPHER_PAGE,
	SIZE_PAGE,
				HIDDEN_VOL_HOST_PASSWORD_PAGE,
	PASSWORD_PAGE,
	PIM_PAGE,
		FILESYS_PAGE,
			SYSENC_COLLECTING_RANDOM_DATA_PAGE,
			SYSENC_KEYS_GEN_PAGE,
			SYSENC_RESCUE_DISK_CREATION_PAGE,
			SYSENC_RESCUE_DISK_BURN_PAGE,
			SYSENC_RESCUE_DISK_VERIFIED_PAGE,
			SYSENC_WIPE_MODE_PAGE,
			SYSENC_PRETEST_INFO_PAGE,
			SYSENC_PRETEST_RESULT_PAGE,
			SYSENC_ENCRYPTION_PAGE,
		NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE,
		NONSYS_INPLACE_ENC_RESUME_PARTITION_SEL_PAGE,
		NONSYS_INPLACE_ENC_RAND_DATA_PAGE,
		NONSYS_INPLACE_ENC_WIPE_MODE_PAGE,
		NONSYS_INPLACE_ENC_TRANSFORM_PAGE,
		NONSYS_INPLACE_ENC_TRANSFORM_FINISHED_PAGE,
		NONSYS_INPLACE_DEC_TRANSFORM_FINISHED_DRIVE_LETTER_PAGE,
	FORMAT_PAGE,
	FORMAT_FINISHED_PAGE,
					SYSENC_HIDDEN_OS_INITIAL_INFO_PAGE,
					SYSENC_HIDDEN_OS_WIPE_INFO_PAGE,
						DEVICE_WIPE_MODE_PAGE,
						DEVICE_WIPE_PAGE
};

#define TIMER_INTERVAL_RANDVIEW							30
#define TIMER_INTERVAL_SYSENC_PROGRESS					30
#define TIMER_INTERVAL_NONSYS_INPLACE_ENC_PROGRESS		30
#define TIMER_INTERVAL_SYSENC_DRIVE_ANALYSIS_PROGRESS	100
#define TIMER_INTERVAL_WIPE_PROGRESS					30
#define TIMER_INTERVAL_KEYB_LAYOUT_GUARD				10

enum sys_encryption_cmd_line_switches
{
	SYSENC_COMMAND_NONE = 0,
	SYSENC_COMMAND_RESUME,
	SYSENC_COMMAND_STARTUP_SEQ_RESUME,
	SYSENC_COMMAND_ENCRYPT,
	SYSENC_COMMAND_DECRYPT,
	SYSENC_COMMAND_CREATE_HIDDEN_OS,
	SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV
};

typedef struct
{
	int NumberOfSysDrives;			// Number of drives that contain an operating system. -1: unknown, 1: one, 2: two or more
	int MultipleSystemsOnDrive;		// Multiple systems are installed on the drive where the currently running system resides.  -1: unknown, 0: no, 1: yes
	int BootLoaderLocation;			// Boot loader (boot manager) installed in: 1: MBR/1st cylinder, 0: partition/bootsector: -1: unknown
	int BootLoaderBrand;			// -1: unknown, 0: Microsoft Windows, 1: any non-Windows boot manager/loader
	int SystemOnBootDrive;			// If the currently running operating system is installed on the boot drive. -1: unknown, 0: no, 1: yes
} SYSENC_MULTIBOOT_CFG;

#define SYSENC_PAUSE_RETRY_INTERVAL		100
#define SYSENC_PAUSE_RETRIES			200

// Expected duration of system drive analysis, in ms
#define SYSENC_DRIVE_ANALYSIS_ETA		(4*60000)

BootEncryption			*BootEncObj = NULL;
BootEncryptionStatus	BootEncStatus;

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
int nLastPageNo = -1;
volatile int WizardMode = DEFAULT_VOL_CREATION_WIZARD_MODE; /* IMPORTANT: Never change this value directly -- always use ChangeWizardMode() instead. */
volatile BOOL bHiddenOS = FALSE;		/* If TRUE, we are performing or (or supposed to perform) actions relating to an operating system installed in a hidden volume (i.e., encrypting a decoy OS partition or creating the outer/hidden volume for the hidden OS). To determine or set the phase of the process, call ChangeHiddenOSCreationPhase() and DetermineHiddenOSCreationPhase()) */
BOOL bDirectSysEncMode = FALSE;
BOOL bDirectSysEncModeCommand = SYSENC_COMMAND_NONE;
BOOL DirectDeviceEncMode = FALSE;
BOOL DirectNonSysInplaceDecStartMode = FALSE;
BOOL DirectNonSysInplaceEncResumeMode = FALSE;
BOOL DirectNonSysInplaceDecResumeMode = FALSE;
BOOL DirectPromptNonSysInplaceEncResumeMode = FALSE;
BOOL DirectCreationMode = FALSE;

volatile BOOL bInPlaceEncNonSys = FALSE;		/* If TRUE, existing data on a non-system partition/volume are to be encrypted (or decrypted if bInPlaceDecNonSys is TRUE) in place (for system encryption, this flag is ignored) */
volatile BOOL bInPlaceDecNonSys = FALSE;		/* If TRUE, existing data on a non-system partition/volume are to be decrypted in place (for system encryption, this flag is ignored) */
volatile BOOL bInPlaceEncNonSysResumed = FALSE;	/* If TRUE, the wizard is supposed to resume (or has resumed) process of non-system in-place encryption/decryption. */
volatile BOOL bFirstNonSysInPlaceEncResumeDone = FALSE;
__int64 NonSysInplaceEncBytesDone = 0;
__int64 NonSysInplaceEncTotalSize = 0;
BOOL bDeviceTransformModeChoiceMade = FALSE;		/* TRUE if the user has at least once manually selected the 'in-place' or 'format' option (on the 'device transform mode' page). */
int nNeedToStoreFilesOver4GB = 0;		/* Whether the user wants to be able to store files larger than 4GB on the volume: -1 = Undecided or error, 0 = No, 1 = Yes */
int nVolumeEA = 1;			/* Default encryption algorithm */
BOOL bSystemEncryptionInProgress = FALSE;		/* TRUE when encrypting/decrypting the system partition/drive (FALSE when paused). */
BOOL bWholeSysDrive = FALSE;	/* Whether to encrypt the entire system drive or just the system partition. */
static BOOL bSystemEncryptionStatusChanged = FALSE;   /* TRUE if this instance changed the value of SystemEncryptionStatus (it's set to FALSE each time the system encryption settings are saved to the config file). This value is to be treated as protected -- only the wizard can change this value (others may only read it). */
volatile BOOL bSysEncDriveAnalysisInProgress = FALSE;
volatile BOOL bSysEncDriveAnalysisTimeOutOccurred = FALSE;
int SysEncDetectHiddenSectors = -1;		/* Whether the user wants us to detect and encrypt the Host Protect Area (if any): -1 = Undecided or error, 0 = No, 1 = Yes */
int SysEncDriveAnalysisStart;
BOOL bDontVerifyRescueDisk = FALSE;
BOOL bFirstSysEncResumeDone = FALSE;
BOOL bDontCheckFileContainerSize = FALSE; /* If true, we don't check if the given size of file container is smaller than the available size on the hosting disk */
int nMultiBoot = 0;			/* The number of operating systems installed on the computer, according to the user. 0: undetermined, 1: one, 2: two or more */
volatile BOOL bHiddenVol = FALSE;	/* If true, we are (or will be) creating a hidden volume. */
volatile BOOL bHiddenVolHost = FALSE;	/* If true, we are (or will be) creating the host volume (called "outer") for a hidden volume. */
volatile BOOL bHiddenVolDirect = FALSE;	/* If true, the wizard omits creating a host volume in the course of the process of hidden volume creation. */
volatile BOOL bHiddenVolFinished = FALSE;
int hiddenVolHostDriveNo = -1;	/* Drive letter for the volume intended to host a hidden volume. */
BOOL bRemovableHostDevice = FALSE;	/* TRUE when creating a device/partition-hosted volume on a removable device. State undefined when creating file-hosted volumes. */
int realClusterSize;		/* Parameter used when determining the maximum possible size of a hidden volume. */
int hash_algo = DEFAULT_HASH_ALGORITHM;	/* Which PRF to use in header key derivation (PKCS #5) and in the RNG. */
unsigned __int64 nUIVolumeSize = 0;		/* The volume size. Important: This value is not in bytes. It has to be multiplied by nMultiplier. Do not use this value when actually creating the volume (it may chop off sector size, if it is not a multiple of 1024 bytes). */
unsigned __int64 nVolumeSize = 0;		/* The volume size, in bytes. */
unsigned __int64 nHiddenVolHostSize = 0;	/* Size of the hidden volume host, in bytes */
__int64 nMaximumHiddenVolSize = 0;		/* Maximum possible size of the hidden volume, in bytes */
__int64 nbrFreeClusters = 0;
__int64 nMultiplier = BYTES_PER_MB;		/* Size selection multiplier. */
wchar_t szFileName[TC_MAX_PATH+1];	/* The file selected by the user */
wchar_t szDiskFile[TC_MAX_PATH+1];	/* Fully qualified name derived from szFileName */
wchar_t szRescueDiskISO[TC_MAX_PATH+1];	/* The filename and path to the Rescue Disk ISO file to be burned (for boot encryption) */
BOOL bDeviceWipeInProgress = FALSE;
volatile BOOL bTryToCorrectReadErrors = FALSE;
volatile BOOL DiscardUnreadableEncryptedSectors = FALSE;

volatile BOOL bVolTransformThreadCancel = FALSE;	/* TRUE if the user cancels/pauses volume encryption/format */
volatile BOOL bVolTransformThreadRunning = FALSE;	/* Is the volume encryption/format thread running */
volatile BOOL bVolTransformThreadToRun = FALSE;		/* TRUE if the Format/Encrypt button has been clicked and we are proceeding towards launching the thread. */

volatile BOOL bConfirmQuit = FALSE;		/* If TRUE, the user is asked to confirm exit when he clicks the X icon, Exit, etc. */
volatile BOOL bConfirmQuitSysEncPretest = FALSE;

BOOL bDevice = FALSE;		/* Is this a partition volume ? */

BOOL showKeys = FALSE;
volatile HWND hMasterKey = NULL;		/* Text box showing hex dump of the master key */
volatile HWND hHeaderKey = NULL;		/* Text box showing hex dump of the header key */
volatile HWND hRandPool = NULL;		/* Text box showing hex dump of the random pool */
volatile HWND hRandPoolSys = NULL;	/* Text box showing hex dump of the random pool for system encryption */
volatile HWND hPasswordInputField = NULL;	/* Password input field */
volatile HWND hVerifyPasswordInputField = NULL;		/* Verify-password input field */

HBITMAP hbmWizardBitmapRescaled = NULL;

wchar_t OrigKeyboardLayout [KL_NAMELENGTH] = L"00000409";
BOOL bKeyboardLayoutChanged = FALSE;		/* TRUE if the keyboard layout was changed to the standard US keyboard layout (from any other layout). */
BOOL bKeybLayoutAltKeyWarningShown = FALSE;	/* TRUE if the user has been informed that it is not possible to type characters by pressing keys while the right Alt key is held down. */

#ifndef _DEBUG
	BOOL bWarnDeviceFormatAdvanced = TRUE;
#else
	BOOL bWarnDeviceFormatAdvanced = FALSE;
#endif

BOOL bWarnOuterVolSuitableFileSys = TRUE;

Password volumePassword;			/* User password */
Password outerVolumePassword;			/* Outer volume user password */
char szVerify[MAX_PASSWORD + 1];	/* Tmp password buffer */
char szRawPassword[MAX_PASSWORD + 1];	/* Password before keyfile was applied to it */

int volumePim = 0;
int outerVolumePim = 0;

BOOL bHistoryCmdLine = FALSE; /* History control is always disabled */
BOOL ComServerMode = FALSE;


Password CmdVolumePassword = {0}; /* Password passed from command line */
int CmdVolumeEA = 0;
int CmdVolumePkcs5 = 0;
int CmdVolumePim = 0;
int CmdVolumeFilesystem = FILESYS_NONE;
unsigned __int64 CmdVolumeFileSize = 0;
BOOL CmdSparseFileSwitch = FALSE;
BOOL CmdQuickFormat = FALSE;
BOOL CmdFastCreateFile = FALSE;

BOOL bForceOperation = FALSE;

BOOL bOperationSuccess = FALSE;

BOOL bGuiMode = TRUE;

BOOL bSystemIsGPT = FALSE;

KeyFile *FirstCmdKeyFile = NULL;

int nPbar = 0;			/* Control ID of progress bar:- for format code */

wchar_t HeaderKeyGUIView [KEY_GUI_VIEW_SIZE];
wchar_t MasterKeyGUIView [KEY_GUI_VIEW_SIZE];

#define RANDPOOL_DISPLAY_COLUMNS	15
#define RANDPOOL_DISPLAY_ROWS		8
#define RANDPOOL_DISPLAY_BYTE_PORTION	(RANDPOOL_DISPLAY_COLUMNS * RANDPOOL_DISPLAY_ROWS)
#define RANDPOOL_DISPLAY_SIZE	(RANDPOOL_DISPLAY_BYTE_PORTION * 3 + RANDPOOL_DISPLAY_ROWS + 2)
unsigned char randPool [RANDPOOL_DISPLAY_BYTE_PORTION];
unsigned char lastRandPool [RANDPOOL_DISPLAY_BYTE_PORTION];
static unsigned char maskRandPool [RANDPOOL_DISPLAY_BYTE_PORTION];
static BOOL bUseMask = FALSE;
static DWORD mouseEntropyGathered = 0xFFFFFFFF;
static DWORD mouseEventsInitialCount = 0;
/* max value of entropy needed to fill all random pool = 8 * RNG_POOL_SIZE = 2560 bits */
static const DWORD maxEntropyLevel = RNG_POOL_SIZE * 8;
static HWND hEntropyBar = NULL;
wchar_t outRandPoolDispBuffer [RANDPOOL_DISPLAY_SIZE];
BOOL bDisplayPoolContents = TRUE;

volatile BOOL bSparseFileSwitch = FALSE;
volatile BOOL quickFormat = FALSE;
volatile BOOL fastCreateFile = FALSE;
volatile BOOL dynamicFormat = FALSE; /* this variable represents the sparse file flag. */
volatile int fileSystem = FILESYS_NONE;
volatile int formatType = FORMAT_TYPE_FULL;
volatile int clusterSize = 0;

SYSENC_MULTIBOOT_CFG	SysEncMultiBootCfg;
wchar_t SysEncMultiBootCfgOutcome [4096] = {L'N',L'/',L'A',0};
volatile int NonSysInplaceEncStatus = NONSYS_INPLACE_ENC_STATUS_NONE;

LONGLONG nAvailableFreeSpace = -1;
BOOL bIsSparseFilesSupportedByHost = FALSE;

vector <HostDevice> DeferredNonSysInPlaceEncDevices;

int iMaxPasswordLength = MAX_PASSWORD;

// specific definitions and implementation for support of resume operation
// in wait dialog mechanism

void CALLBACK ResumeInPlaceEncWaitThreadProc(void* pArg, HWND hwndDlg)
{
	wchar_t szDevicePath[MAX_PATH] = {0};
	RawDevicesDlgParam param;
	param.devices = GetAvailableHostDevices (false, true, false);
	param.pszFileName = szDevicePath;

	DeferredNonSysInPlaceEncDevices.clear();

	if ((IDOK == DialogBoxParamW (hInst,
		MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), hwndDlg,
		(DLGPROC) RawDevicesDlgProc, (LPARAM) &param)) && wcslen(szDevicePath))
	{
		foreach (const HostDevice &device, param.devices)
		{
			if (device.Path == szDevicePath)
			{
				OpenVolumeContext volume;
				int status = OpenVolume (&volume, device.Path.c_str(), &volumePassword, hash_algo, volumePim, FALSE, FALSE, TRUE);

				if ( status == ERR_SUCCESS)
				{
					if ((volume.CryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
						&& volume.CryptoInfo->EncryptedAreaLength.Value != volume.CryptoInfo->VolumeSize.Value)
					{
						DeferredNonSysInPlaceEncDevices.push_back (device);
					}
					else if (volume.CryptoInfo->EncryptedAreaLength.Value == volume.CryptoInfo->VolumeSize.Value)
					{
						WCHAR szMsg[1024];
						StringCbPrintfW(szMsg, sizeof(szMsg), GetString ("SELECTED_PARTITION_ALREADY_INPLACE_ENC"),
							volume.CryptoInfo->HeaderFlags);
						ErrorDirect(szMsg, hwndDlg);
					}
					else
					{
						WCHAR szMsg[1024];
						StringCbPrintfW(szMsg, sizeof(szMsg), GetString ("SELECTED_PARTITION_NOT_INPLACE_ENC"),
							volume.CryptoInfo->HeaderFlags);
						ErrorDirect(szMsg, hwndDlg);
					}

					CloseVolume (&volume);
				}
				else
				{
					handleError(hwndDlg, status, SRC_POS);
				}

				break;
			}
		}
	}
	else
	{
		foreach (const HostDevice &device, param.devices)
		{
			if (	!device.ContainsSystem
				&&	(device.IsPartition || device.DynamicVolume || device.IsVirtualPartition || device.Partitions.empty())
				)
			{

				OpenVolumeContext volume;

				if (OpenVolume (&volume, device.Path.c_str(), &volumePassword, hash_algo, volumePim, FALSE, FALSE, TRUE) == ERR_SUCCESS)
				{
					if ((volume.CryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
						&& volume.CryptoInfo->EncryptedAreaLength.Value != volume.CryptoInfo->VolumeSize.Value)
					{
						DeferredNonSysInPlaceEncDevices.push_back (device);
					}

					CloseVolume (&volume);
				}
			}
		}
	}
}


static BOOL ElevateWholeWizardProcess (wstring arguments)
{
	wchar_t modPath[MAX_PATH];

	if (IsAdmin())
		return TRUE;

	if (!IsUacSupported())
		return IsAdmin();

	GetModuleFileName (NULL, modPath, ARRAYSIZE (modPath));

	while (true)
	{
		if ((intptr_t)ShellExecute (MainDlg, L"runas", modPath, (wstring(L"/q UAC ") + arguments).c_str(), NULL, SW_SHOWNORMAL) > 32)
		{
			exit (0);
		}
		else
		{
			if (IDRETRY == ErrorRetryCancel ("UAC_INIT_ERROR", MainDlg))
				continue;
			return FALSE;
		}
	}
}

static void WipePasswordsAndKeyfiles (bool bFull)
{
	wchar_t tmp[MAX_PASSWORD+1];

	// Attempt to wipe passwords stored in the input field buffers
	wmemset (tmp, L'X', MAX_PASSWORD);
	tmp [MAX_PASSWORD] = 0;
	if (hPasswordInputField)
		SetWindowText (hPasswordInputField, tmp);
	if (hVerifyPasswordInputField)
		SetWindowText (hVerifyPasswordInputField, tmp);

	burn (&szVerify[0], sizeof (szVerify));
	burn (&volumePassword, sizeof (volumePassword));
	burn (&szRawPassword[0], sizeof (szRawPassword));
	burn (&volumePim, sizeof (volumePim));
	burn (&CmdVolumePassword, sizeof (CmdVolumePassword));
	burn (&CmdVolumePim, sizeof (CmdVolumePim));

	if (bFull)
	{
		burn (&outerVolumePassword, sizeof (outerVolumePassword));
		burn (&outerVolumePim, sizeof (outerVolumePim));
	}

	if (hPasswordInputField)
		SetWindowText (hPasswordInputField, L"");
	if (hVerifyPasswordInputField)
		SetWindowText (hVerifyPasswordInputField, L"");

	KeyFileRemoveAll (&FirstKeyFile);
	KeyFileRemoveAll (&defaultKeyFilesParam.FirstKeyFile);
}

static void localcleanup (void)
{
	wchar_t tmp[RANDPOOL_DISPLAY_SIZE+1];

	// System encryption

	if (WizardMode == WIZARD_MODE_SYS_DEVICE
		&& InstanceHasSysEncMutex ())
	{
		try
		{
			BootEncStatus = BootEncObj->GetStatus();

			if (BootEncStatus.SetupInProgress)
			{
				BootEncObj->AbortSetup ();
			}
		}
		catch (...)
		{
			// NOP
		}
	}

	// Mon-system in-place encryption

	if (bInPlaceEncNonSys && (bVolTransformThreadRunning || bVolTransformThreadToRun))
	{
		NonSysInplaceEncPause ();
	}

	CloseNonSysInplaceEncMutex ();


	// Device wipe

	if (bDeviceWipeInProgress)
		WipeAbort();


	WipePasswordsAndKeyfiles (true);

	RandStop (TRUE);

	burn (HeaderKeyGUIView, sizeof(HeaderKeyGUIView));
	burn (MasterKeyGUIView, sizeof(MasterKeyGUIView));
	burn (randPool, sizeof(randPool));
	burn (lastRandPool, sizeof(lastRandPool));
	burn (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer));
	burn (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
	burn (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
	burn (maskRandPool, sizeof(maskRandPool));
	burn (szFileName, sizeof(szFileName));
	burn (szDiskFile, sizeof(szDiskFile));

	KeyFileRemoveAll (&FirstCmdKeyFile);

	// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
	wmemset (tmp, L'X', ARRAYSIZE(tmp));
	tmp [ARRAYSIZE(tmp)-1] = 0;
	SetWindowText (hRandPool, tmp);
	SetWindowText (hRandPoolSys, tmp);
	SetWindowText (hMasterKey, tmp);
	SetWindowText (hHeaderKey, tmp);

	UnregisterRedTick (hInst);

	// Delete buffered bitmaps (if any)
	if (hbmWizardBitmapRescaled != NULL)
	{
		DeleteObject ((HGDIOBJ) hbmWizardBitmapRescaled);
		hbmWizardBitmapRescaled = NULL;
	}

	// Cleanup common code resources
	cleanup ();

	if (BootEncObj != NULL)
	{
		delete BootEncObj;
		BootEncObj = NULL;
	}
}

static BOOL CALLBACK BroadcastSysEncCfgUpdateCallb (HWND hwnd, LPARAM lParam)
{
	LONG_PTR userDataVal = GetWindowLongPtrW (hwnd, GWLP_USERDATA);
	if ((userDataVal == (LONG_PTR) 'VERA') || (userDataVal == (LONG_PTR) 'TRUE')) // Prior to 1.0e, 'TRUE' was used for VeraCrypt dialogs
	{
		wchar_t name[1024] = { 0 };
		GetWindowText (hwnd, name, ARRAYSIZE (name) - 1);
		if (hwnd != MainDlg && wcsstr (name, L"VeraCrypt"))
		{
			PostMessage (hwnd, TC_APPMSG_SYSENC_CONFIG_UPDATE, 0, 0);
		}
	}
	return TRUE;
}

static BOOL BroadcastSysEncCfgUpdate (void)
{
	BOOL bSuccess = FALSE;
	EnumWindows (BroadcastSysEncCfgUpdateCallb, (LPARAM) &bSuccess);
	return bSuccess;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the system encryption config).
// Returns TRUE if successful (otherwise FALSE)
static BOOL SaveSysEncSettings (HWND hwndDlg)
{
	FILE *f;

	if (!bSystemEncryptionStatusChanged)
		return TRUE;

	if (hwndDlg == NULL && MainDlg != NULL)
		hwndDlg = MainDlg;

	if (!CreateSysEncMutex ())
		return FALSE;		// Only one instance that has the mutex can modify the system encryption settings

	if (SystemEncryptionStatus == SYSENC_STATUS_NONE)
	{
		if (_wremove (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION)) != 0)
		{
			Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS", hwndDlg);
			return FALSE;
		}

		bSystemEncryptionStatusChanged = FALSE;
		BroadcastSysEncCfgUpdate ();
		return TRUE;
	}

	f = _wfopen (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION), L"w,ccs=UTF-8");
	if (f == NULL)
	{
		Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS", hwndDlg);
		handleWin32Error (hwndDlg, SRC_POS);
		return FALSE;
	}

	if (XmlWriteHeader (f) < 0

	|| fputws (L"\n\t<sysencryption>", f) < 0

	|| fwprintf (f, L"\n\t\t<config key=\"SystemEncryptionStatus\">%d</config>", SystemEncryptionStatus) < 0

	|| fwprintf (f, L"\n\t\t<config key=\"WipeMode\">%d</config>", (int) nWipeMode) < 0

	|| fputws (L"\n\t</sysencryption>", f) < 0

	|| XmlWriteFooter (f) < 0)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		fclose (f);
		Error ("CANNOT_SAVE_SYS_ENCRYPTION_SETTINGS", hwndDlg);
		return FALSE;
	}

	TCFlushFile (f);

	fclose (f);

	bSystemEncryptionStatusChanged = FALSE;
	BroadcastSysEncCfgUpdate ();

	return TRUE;
}

// WARNING: This function may take a long time to finish
static unsigned int DetermineHiddenOSCreationPhase (void)
{
	unsigned int phase = TC_HIDDEN_OS_CREATION_PHASE_NONE;

	try
	{
		phase = BootEncObj->GetHiddenOSCreationPhase();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		AbortProcess("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS");
	}

	return phase;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the status).
// Returns TRUE if successful (otherwise FALSE)
static BOOL ChangeHiddenOSCreationPhase (int newPhase)
{
	if (!CreateSysEncMutex ())
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
		return FALSE;
	}

	try
	{
		BootEncObj->SetHiddenOSCreationPhase (newPhase);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return FALSE;
	}

	//// The contents of the following items might be inappropriate after a change of the phase
	//szFileName[0] = 0;
	//szDiskFile[0] = 0;
	//nUIVolumeSize = 0;
	//nVolumeSize = 0;

	return TRUE;
}

// IMPORTANT: This function may be called only by Format (other modules can only _read_ the system encryption status).
// Returns TRUE if successful (otherwise FALSE)
static BOOL ChangeSystemEncryptionStatus (int newStatus)
{
	if (!CreateSysEncMutex ())
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
		return FALSE;		// Only one instance that has the mutex can modify the system encryption settings
	}

	SystemEncryptionStatus = newStatus;
	bSystemEncryptionStatusChanged = TRUE;

	if (newStatus == SYSENC_STATUS_ENCRYPTING)
	{
		// If the user has created a hidden OS and now is creating a decoy OS, we must wipe the hidden OS
		// config area in the MBR.
		WipeHiddenOSCreationConfig();
	}

	if (newStatus == SYSENC_STATUS_NONE && !IsHiddenOSRunning())
	{
		if (DetermineHiddenOSCreationPhase() != TC_HIDDEN_OS_CREATION_PHASE_NONE
			&& !ChangeHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE))
			return FALSE;

		WipeHiddenOSCreationConfig();
	}

	if (!SaveSysEncSettings (MainDlg))
	{
		return FALSE;
	}

	return TRUE;
}

// If the return code of this function is ignored and newWizardMode == WIZARD_MODE_SYS_DEVICE, then this function
// may be called only after CreateSysEncMutex() returns TRUE. It returns TRUE if successful (otherwise FALSE).
static BOOL ChangeWizardMode (int newWizardMode)
{
	if (WizardMode != newWizardMode)
	{
		if (WizardMode == WIZARD_MODE_SYS_DEVICE || newWizardMode == WIZARD_MODE_SYS_DEVICE)
		{
			if (newWizardMode == WIZARD_MODE_SYS_DEVICE)
			{
				if (!CreateSysEncMutex ())
				{
					Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
					return FALSE;
				}
			}

			// If the previous mode was different, the password may have been typed using a different
			// keyboard layout (which might confuse the user and cause other problems if system encryption
			// was or will be involved).
			WipePasswordsAndKeyfiles(true);
		}

		if (newWizardMode != WIZARD_MODE_NONSYS_DEVICE)
		{
			bInPlaceEncNonSys = FALSE;
			bInPlaceDecNonSys = FALSE;
		}

		if (newWizardMode == WIZARD_MODE_NONSYS_DEVICE && !IsAdmin() && IsUacSupported())
		{
			if (!ElevateWholeWizardProcess (L"/e"))
				return FALSE;
		}

		// The contents of the following items may be inappropriate after a change of mode
		if (! (bInPlaceDecNonSys && !bInPlaceEncNonSysResumed))	// If we are starting (but not resuming) decryption of non-system volume, we actually need szFileName as it contains the command line param.
			szFileName[0] = 0;
		szDiskFile[0] = 0;
		nUIVolumeSize = 0;
		nVolumeSize = 0;

		WizardMode = newWizardMode;
	}

	bDevice = (WizardMode != WIZARD_MODE_FILE_CONTAINER);

	if (newWizardMode != WIZARD_MODE_SYS_DEVICE
		&& !bHiddenOS)
	{
		CloseSysEncMutex ();
	}

	return TRUE;
}

// Determines whether the wizard directly affects system encryption in any way.
// Note, for example, that when the user enters a password for a hidden volume that is to host a hidden OS,
// WizardMode is NOT set to WIZARD_MODE_SYS_DEVICE. The keyboard layout, however, has to be US. That's why
// this function has to be called instead of checking the value of WizardMode.
static BOOL SysEncInEffect (void)
{
	return (WizardMode == WIZARD_MODE_SYS_DEVICE
		|| CreatingHiddenSysVol());
}

static BOOL CreatingHiddenSysVol (void)
{
	return (bHiddenOS
		&& bHiddenVol && !bHiddenVolHost);
}

static void LoadSettingsAndCheckModified (HWND hwndDlg, BOOL bOnlyCheckModified, BOOL* pbSettingsModified, BOOL* pbHistoryModified)
{
	if (!bOnlyCheckModified)
		EnableHwEncryption ((ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? FALSE : TRUE);

	WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

	if (!bOnlyCheckModified)
		LoadSysEncSettings ();

	if (!bOnlyCheckModified && LoadNonSysInPlaceEncSettings (&savedWipeAlgorithm) != 0)
		bInPlaceEncNonSysPending = TRUE;

	if (!bOnlyCheckModified)
		defaultKeyFilesParam.EnableKeyFiles = FALSE;

	ConfigReadCompareInt ("StartOnLogon", FALSE, &bStartOnLogon, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("HiddenSectorDetectionStatus", 0, &HiddenSectorDetectionStatus, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("ShowDisconnectedNetworkDrives", FALSE, &bShowDisconnectedNetworkDrives, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("HideWaitingDialog", FALSE, &bHideWaitingDialog, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("SaveVolumeHistory", FALSE, &bHistory, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("UseLegacyMaxPasswordLength", FALSE, &bUseLegacyMaxPasswordLength, bOnlyCheckModified, pbSettingsModified);

	ConfigReadCompareInt ("EMVSupportEnabled", 0, &EMVSupportEnabled, bOnlyCheckModified, pbSettingsModified);

	{
		char szTmp[MAX_PATH] = {0};
		WideCharToMultiByte (CP_UTF8, 0, SecurityTokenLibraryPath, -1, szTmp, MAX_PATH, NULL, NULL);
		ConfigReadCompareString ("SecurityTokenLibrary", "", szTmp, sizeof (szTmp) - 1, bOnlyCheckModified, pbSettingsModified);
		MultiByteToWideChar (CP_UTF8, 0, szTmp, -1, SecurityTokenLibraryPath, ARRAYSIZE (SecurityTokenLibraryPath));

		if (!bOnlyCheckModified && SecurityTokenLibraryPath[0])
			InitSecurityTokenLibrary(hwndDlg);
	}

	if (bOnlyCheckModified)
	{
		char langid[6] = {0};
		if (!IsNonInstallMode ())
		{
			ConfigReadString ("Language", "", langid, sizeof (langid));
			// when installed, if no preferred language set by user, English is selected default
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

	if (hwndDlg != NULL)
	{
		LoadCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), bHistory, bOnlyCheckModified, pbHistoryModified);
		return;
	}

	if (bHistoryCmdLine)
		return;
}

static void LoadSettings (HWND hwndDlg)
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

	if (bHistoryChanged && hwndDlg != NULL)
		DumpCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), !bHistory);

	if (bSettingsChanged)
	{
		ConfigWriteBegin ();

		ConfigWriteInt ("StartOnLogon",	bStartOnLogon);
		ConfigWriteInt ("HiddenSectorDetectionStatus", HiddenSectorDetectionStatus);
		ConfigWriteInt ("SaveVolumeHistory", bHistory);
		ConfigWriteStringW ("SecurityTokenLibrary", SecurityTokenLibraryPath[0] ? SecurityTokenLibraryPath : L"");

		ConfigWriteString ("Language", GetPreferredLangId ());

		ConfigWriteEnd (hwndDlg);
	}

	NormalCursor ();
}

// WARNING: This function does NOT cause immediate application exit (use e.g. return 1 after calling it
// from a DialogProc function).
static void EndMainDlg (HWND hwndDlg)
{
	if (nCurPageNo == VOLUME_LOCATION_PAGE)
	{
		if (IsWindow(GetDlgItem(hCurPage, IDC_NO_HISTORY)))
			bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

		MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);
		SaveSettings (hCurPage);
	}
	else
	{
		SaveSettings (NULL);
	}

	SaveSysEncSettings (hwndDlg);

	if (!bHistory)
		CleanLastVisitedMRU ();

	EndDialog (hwndDlg, 0);
}

// Returns TRUE if system encryption or decryption had been or is in progress and has not been completed
static BOOL SysEncryptionOrDecryptionRequired (void)
{
	/* If you update this function, revise SysEncryptionOrDecryptionRequired() in Mount.c as well. */

	static BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return (SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		|| SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING
		||
		(
			locBootEncStatus.DriveMounted
			&&
			(
				locBootEncStatus.ConfiguredEncryptedAreaStart != locBootEncStatus.EncryptedAreaStart
				|| locBootEncStatus.ConfiguredEncryptedAreaEnd != locBootEncStatus.EncryptedAreaEnd
			)
		)
	);
}

// Returns TRUE if the system partition/drive is completely encrypted
static BOOL SysDriveOrPartitionFullyEncrypted (BOOL bSilent)
{
	/* If you update this function, revise SysDriveOrPartitionFullyEncrypted() in Mount.c as well. */

	static BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (Exception &e)
	{
		if (!bSilent)
			e.Show (MainDlg);
	}

	return (!locBootEncStatus.SetupInProgress
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd != 0
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd != -1
		&& locBootEncStatus.ConfiguredEncryptedAreaStart == locBootEncStatus.EncryptedAreaStart
		&& locBootEncStatus.ConfiguredEncryptedAreaEnd == locBootEncStatus.EncryptedAreaEnd);
}

// This functions is to be used when the wizard mode needs to be changed to WIZARD_MODE_SYS_DEVICE.
// If the function fails to switch the mode, it returns FALSE (otherwise TRUE).
BOOL SwitchWizardToSysEncMode (void)
{
	WaitCursor ();
	SystemDriveConfiguration config;

	try
	{
		BootEncStatus = BootEncObj->GetStatus();
		bWholeSysDrive = BootEncObj->SystemPartitionCoversWholeDrive();
		config = BootEncObj->GetSystemDriveConfiguration ();
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
		NormalCursor ();
		return FALSE;
	}

	// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
	if (!CreateSysEncMutex ())
	{
		Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
		NormalCursor ();
		return FALSE;
	}

	// User-mode app may have crashed and its mutex may have gotten lost, so we need to check the driver status too
	if (BootEncStatus.SetupInProgress)
	{
		if (AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT", MainDlg) == IDYES)
		{
			if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
				&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
			{
				// The config file with status was lost or not written correctly
				if (!ResolveUnknownSysEncDirection ())
				{
					CloseSysEncMutex ();
					NormalCursor ();
					return FALSE;
				}
			}

			bDirectSysEncMode = TRUE;
			ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
			LoadPage (MainDlg, SYSENC_ENCRYPTION_PAGE);
			NormalCursor ();
			return TRUE;
		}
		else
		{
			CloseSysEncMutex ();
			Error ("SYS_ENCRYPTION_OR_DECRYPTION_IN_PROGRESS", MainDlg);
			NormalCursor ();
			return FALSE;
		}
	}

	if (BootEncStatus.DriveMounted
		|| BootEncStatus.DriveEncrypted
		|| SysEncryptionOrDecryptionRequired ())
	{

		if (!SysDriveOrPartitionFullyEncrypted (FALSE)
			&& AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT", MainDlg) == IDYES)
		{
			if (SystemEncryptionStatus == SYSENC_STATUS_NONE)
			{
				// If the config file with status was lost or not written correctly, we
				// don't know whether to encrypt or decrypt (but we know that encryption or
				// decryption is required). Ask the user to select encryption, decryption,
				// or cancel
				if (!ResolveUnknownSysEncDirection ())
				{
					CloseSysEncMutex ();
					NormalCursor ();
					return FALSE;
				}
			}

			bDirectSysEncMode = TRUE;
			ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
			LoadPage (MainDlg, SYSENC_ENCRYPTION_PAGE);
			NormalCursor ();
			return TRUE;
		}
		else
		{
			CloseSysEncMutex ();
			Error ("SETUP_FAILED_BOOT_DRIVE_ENCRYPTED", MainDlg);
			NormalCursor ();
			return FALSE;
		}
	}
	else
	{
		// Check compliance with requirements for boot encryption

		if (!IsAdmin())
		{
			if (!IsUacSupported())
			{
				Warning ("ADMIN_PRIVILEGES_WARN_DEVICES", MainDlg);
			}
		}

		try
		{
			BootEncObj->CheckRequirements ();
		}
		catch (Exception &e)
		{
			CloseSysEncMutex ();
			e.Show (MainDlg);
			NormalCursor ();
			return FALSE;
		}

		if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
		{
			NormalCursor ();
			return FALSE;
		}

		if (bSysDriveSelected || bSysPartitionSelected)
		{
			// The user selected the non-sys-device wizard mode but then selected a system device

			bWholeSysDrive = (bSysDriveSelected && !bSysPartitionSelected);

			bSysDriveSelected = FALSE;
			bSysPartitionSelected = FALSE;

			try
			{
				if (!bHiddenVol)
				{
					if (bWholeSysDrive && !BootEncObj->SystemPartitionCoversWholeDrive())
					{
						if (BootEncObj->SystemDriveContainsNonStandardPartitions())
						{
							if (AskWarnYesNoString ((wstring (GetString ("SYSDRIVE_NON_STANDARD_PARTITIONS")) + L"\n\n" + GetString ("ASK_ENCRYPT_PARTITION_INSTEAD_OF_DRIVE")).c_str(), MainDlg) == IDYES)
								bWholeSysDrive = FALSE;
						}
					}
					else if (BootEncObj->SystemPartitionCoversWholeDrive()
						&& !bWholeSysDrive)
						bWholeSysDrive = (AskYesNo ("WHOLE_SYC_DEVICE_RECOM", MainDlg) == IDYES);
				}

			}
			catch (Exception &e)
			{
				e.Show (MainDlg);
				return FALSE;
			}

			if (!bHiddenVol)
			{
				// Skip SYSENC_SPAN_PAGE and SYSENC_TYPE_PAGE as the user already made the choice
				LoadPage (MainDlg, bWholeSysDrive ? SYSENC_PRE_DRIVE_ANALYSIS_PAGE : SYSENC_MULTI_BOOT_MODE_PAGE);
			}
			else
			{
				// The user selected the non-sys-device wizard mode but then selected a system device.
				// In addition, he selected the hidden volume mode.

				if (bWholeSysDrive)
					Warning ("HIDDEN_OS_PRECLUDES_SINGLE_KEY_WDE", MainDlg);

				bWholeSysDrive = FALSE;

				LoadPage (MainDlg, SYSENC_TYPE_PAGE);
			}
		}
		else
			LoadPage (MainDlg, SYSENC_TYPE_PAGE);

		NormalCursor ();
		return TRUE;
	}
}

void SwitchWizardToFileContainerMode (void)
{
	ChangeWizardMode (WIZARD_MODE_FILE_CONTAINER);

	LoadPage (MainDlg, VOLUME_LOCATION_PAGE);

	NormalCursor ();
}

void SwitchWizardToNonSysDeviceMode (void)
{
	ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE);

	LoadPage (MainDlg, VOLUME_TYPE_PAGE);

	NormalCursor ();
}

BOOL SwitchWizardToHiddenOSMode (void)
{
	if (SwitchWizardToSysEncMode())
	{
		if (nCurPageNo != SYSENC_ENCRYPTION_PAGE)	// If the user did not manually choose to resume encryption or decryption of the system partition/drive
		{
			bHiddenOS = TRUE;
			bHiddenVol = TRUE;
			bHiddenVolHost = TRUE;
			bHiddenVolDirect = FALSE;
			bWholeSysDrive = FALSE;
			bInPlaceEncNonSys = FALSE;
			bInPlaceDecNonSys = FALSE;

			if (bDirectSysEncModeCommand == SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV)
			{
				// Some of the requirements for hidden OS should have already been checked by the wizard process
				// that launched us (in order to elevate), but we must recheck them. Otherwise, an advanced user
				// could bypass the checks by using the undocumented CLI switch. Moreover, some requirements
				// can be checked only at this point (when we are elevated).
				try
				{
					BootEncObj->CheckRequirementsHiddenOS ();

					BootEncObj->InitialSecurityChecksForHiddenOS ();
				}
				catch (Exception &e)
				{
					e.Show (MainDlg);
					return FALSE;
				}

				LoadPage (MainDlg, SYSENC_MULTI_BOOT_MODE_PAGE);
			}
			else
				LoadPage (MainDlg, SYSENC_HIDDEN_OS_REQ_CHECK_PAGE);

			NormalCursor ();
		}
		else
			return TRUE;
	}
	else
		return FALSE;

	return TRUE;
}

void SwitchWizardToNonSysInplaceEncResumeMode (BOOL bDecrypt)
{
	if (!IsAdmin() && IsUacSupported())
	{
		if (!ElevateWholeWizardProcess (bDecrypt ? L"/resumeinplacedec" : L"/zinplace"))
			AbortProcessSilent ();
	}

	if (!IsAdmin())
		AbortProcess("ADMIN_PRIVILEGES_WARN_DEVICES");

	CreateNonSysInplaceEncMutex ();

	bInPlaceEncNonSys = TRUE;
	bInPlaceDecNonSys = bDecrypt;
	bInPlaceEncNonSysResumed = TRUE;

	ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE);

	LoadPage (MainDlg, NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE);
}

void SwitchWizardToNonSysInplaceDecStartMode (wchar_t *volPath)
{
	if (!IsAdmin() && IsUacSupported())
	{
		if (!ElevateWholeWizardProcess ((wstring (L"/inplacedec \"") + volPath + L"\"").c_str()))
			AbortProcessSilent ();
	}

	if (!IsAdmin())
		AbortProcess("ADMIN_PRIVILEGES_WARN_DEVICES");

	if (!CheckRequirementsForNonSysInPlaceDec (MainDlg, volPath, FALSE))
		AbortProcessSilent ();

	CreateNonSysInplaceEncMutex ();

	bInPlaceEncNonSys = TRUE;
	bInPlaceDecNonSys = TRUE;
	bInPlaceEncNonSysResumed = FALSE;

	ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE);

	LoadPage (MainDlg, NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE);
}

// Use this function e.g. if the config file with the system encryption settings was lost or not written
// correctly, and we don't know whether to encrypt or decrypt (but we know that encryption or decryption
// is required). Returns FALSE if failed or cancelled.
static BOOL ResolveUnknownSysEncDirection (void)
{
	if (CreateSysEncMutex ())
	{
		if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
			&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
		{
			try
			{
				BootEncStatus = BootEncObj->GetStatus();
			}
			catch (Exception &e)
			{
				e.Show (MainDlg);
				Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
				return FALSE;
			}

			if (BootEncStatus.SetupInProgress)
			{
				return ChangeSystemEncryptionStatus (
					(BootEncStatus.SetupMode != SetupDecryption) ? SYSENC_STATUS_ENCRYPTING : SYSENC_STATUS_DECRYPTING);
			}
			else
			{
				// Ask the user to select encryption, decryption, or cancel

				char *tmpStr[] = {0,
					!BootEncStatus.DriveEncrypted ? "CHOOSE_ENCRYPT_OR_DECRYPT_FINALIZE_DECRYPT_NOTE" : "CHOOSE_ENCRYPT_OR_DECRYPT",
					"ENCRYPT",
					"DECRYPT",
					"IDCANCEL",
					0};

				switch (AskMultiChoice ((void **) tmpStr, FALSE, MainDlg))
				{
				case 1:
					return ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
				case 2:
					return ChangeSystemEncryptionStatus (SYSENC_STATUS_DECRYPTING);
				default:
					return FALSE;
				}
			}
		}
		else
			return TRUE;
	}
	else
	{
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
		return FALSE;
	}
}

// This function should be used to resolve inconsistencies that might lead to a deadlock (inability to encrypt or
// decrypt the system partition/drive and to uninstall TrueCrypt). The function removes the system encryption key
// data ("volume header"), the TrueCrypt boot loader, restores the original system loader (if available),
// unregisters the boot driver, etc. Note that if the system partition/drive is encrypted, it will start decrypting
// it in the background (therefore, it should be used when the system partition/drive is not encrypted, ideally).
// Exceptions are handled and errors are reported within the function. Returns TRUE if successful.
static BOOL ForceRemoveSysEnc (void)
{
	if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
	{
		BootEncryptionStatus locBootEncStatus;

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();

			if (locBootEncStatus.SetupInProgress)
				BootEncObj->AbortSetupWait ();

			locBootEncStatus = BootEncObj->GetStatus();

			if (locBootEncStatus.DriveMounted)
			{
				// Remove the header
				BootEncObj->StartDecryption (DiscardUnreadableEncryptedSectors);
				locBootEncStatus = BootEncObj->GetStatus();

				while (locBootEncStatus.SetupInProgress)
				{
					Sleep (100);
					locBootEncStatus = BootEncObj->GetStatus();
				}

				BootEncObj->CheckEncryptionSetupResult ();
			}

			Sleep (50);
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();

			if (!locBootEncStatus.DriveMounted)
				BootEncObj->Deinstall (true);
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}

		return TRUE;
	}
	else
		return FALSE;
}

// Returns 0 if there's an error.
__int64 GetSystemPartitionSize (void)
{
	try
	{
		return BootEncObj->GetSystemDriveConfiguration().SystemPartition.Info.PartitionLength.QuadPart;
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return 0;
	}
}

void ComboSelChangeEA (HWND hwndDlg)
{
	int nIndex = (int) SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);

	if (nIndex == CB_ERR)
	{
		SetWindowText (GetDlgItem (hwndDlg, IDC_BOX_HELP), L"");
	}
	else
	{
		wchar_t name[100];
		wchar_t auxLine[4096];
		wchar_t hyperLink[256] = { 0 };
		int cipherIDs[5];
		int i, cnt = 0;

		nIndex = (int) SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);
		EAGetName (name, ARRAYSIZE(name),nIndex, 0);

		if (wcscmp (name, L"AES") == 0)
		{
			StringCbPrintfW (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AES_HELP"));
		}
		else if (wcscmp (name, L"Serpent") == 0)
		{
			StringCbPrintfW (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SERPENT_HELP"));
		}
		else if (wcscmp (name, L"Twofish") == 0)
		{
			StringCbPrintfW (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("TWOFISH_HELP"));
		}
		else if (wcscmp (name, L"Kuznyechik") == 0)
		{
			StringCbPrintfW (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("KUZNYECHIK_HELP"));
		}
		else if (wcscmp (name, L"Camellia") == 0)
		{
			StringCbPrintfW (hyperLink, sizeof(hyperLink) / 2, GetString ("MORE_INFO_ABOUT"), name);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("CAMELLIA_HELP"));
		}
		else if (EAGetCipherCount (nIndex) > 1)
		{
			// Cascade
			cipherIDs[cnt++] = i = EAGetLastCipher(nIndex);
			while (i = EAGetPreviousCipher(nIndex, i))
			{
				cipherIDs[cnt] = i;
				cnt++;
			}

			switch (cnt)	// Number of ciphers in the cascade
			{
			case 2:
				StringCbPrintfW (auxLine, sizeof(auxLine), GetString ("TWO_LAYER_CASCADE_HELP"),
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;

			case 3:
				StringCbPrintfW (auxLine, sizeof(auxLine), GetString ("THREE_LAYER_CASCADE_HELP"),
					CipherGetName (cipherIDs[2]),
					CipherGetKeySize (cipherIDs[2])*8,
					CipherGetName (cipherIDs[1]),
					CipherGetKeySize (cipherIDs[1])*8,
					CipherGetName (cipherIDs[0]),
					CipherGetKeySize (cipherIDs[0])*8);
				break;
			}

			StringCbCopyW (hyperLink, sizeof(hyperLink), GetString ("IDC_LINK_MORE_INFO_ABOUT_CIPHER"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), auxLine);
		}
		else
		{
			// No info available for this encryption algorithm
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), L"");
		}


		// Update hyperlink
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER), hyperLink);
		AccommodateTextField (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER, FALSE, hUserUnderlineFont);
	}
}

static void VerifySizeAndUpdate (HWND hwndDlg, BOOL bUpdate)
{
	BOOL bEnable = TRUE;
	wchar_t szTmp[50];
	__int64 lTmp;
	__int64 i;
	static unsigned __int64 nLastVolumeSize = 0;

	GetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp, ARRAYSIZE (szTmp));

	for (i = 0; i < (__int64) wcslen (szTmp); i++)
	{
		if (szTmp[i] >= L'0' && szTmp[i] <= L'9')
			continue;
		else
		{
			bEnable = FALSE;
			break;
		}
	}

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_KB)))
		nMultiplier = BYTES_PER_KB;
	else if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_MB)))
		nMultiplier = BYTES_PER_MB;
	else if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_GB)))
		nMultiplier = BYTES_PER_GB;
	else
		nMultiplier = BYTES_PER_TB;

	if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
	{
		lTmp = nVolumeSize;
		i = 1;
	}
	else
	{
		i = nMultiplier;
		lTmp = _wtoi64 (szTmp);

		DWORD sectorSize = GetFormatSectorSize();
		uint32 sectorSizeRem = (lTmp * nMultiplier) % sectorSize;

		if (sectorSizeRem != 0)
			lTmp = (lTmp * nMultiplier + (sectorSize - sectorSizeRem)) / nMultiplier;
	}

	if (bEnable)
	{
		if (lTmp * i < (bHiddenVolHost ? TC_MIN_HIDDEN_VOLUME_HOST_SIZE : (bHiddenVol ? TC_MIN_HIDDEN_VOLUME_SIZE : TC_MIN_VOLUME_SIZE)))
			bEnable = FALSE;

		if (!bHiddenVolHost && bHiddenVol)
		{
			if (lTmp * i > nMaximumHiddenVolSize)
				bEnable = FALSE;
		}
		else
		{
			if (lTmp * i > (bHiddenVolHost ? TC_MAX_HIDDEN_VOLUME_HOST_SIZE : TC_MAX_VOLUME_SIZE))
				bEnable = FALSE;
			else if (!bDevice && (lTmp * i > nAvailableFreeSpace) && !bDontCheckFileContainerSize && (!bIsSparseFilesSupportedByHost || bHiddenVolHost))
			{
				// we check container size against available free space only when creating dynamic volume is not possible
				// which is the case if filesystem doesn't allow sparce file or if we are creating outer volume of a hidden volume
				bEnable = FALSE;
			}
		}
	}

	if (bUpdate)
	{
		nUIVolumeSize = lTmp;

		if (!bDevice || (bHiddenVol && !bHiddenVolHost))	// Update only if it's not a raw device or if it's a hidden volume
			nVolumeSize = i * lTmp;
	}

	EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), bEnable);

	if (nVolumeSize != nLastVolumeSize)
	{
		// Change of volume size may make some file systems allowed or disallowed, so the default filesystem must
		// be reselected.
		fileSystem = FILESYS_NONE;
		nLastVolumeSize = nVolumeSize;
	}
}

static void UpdateWizardModeControls (HWND hwndDlg, int setWizardMode)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_FILE_CONTAINER ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_NONSYS_DEVICE ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_SYS_DEVICE),
		BM_SETCHECK,
		setWizardMode == WIZARD_MODE_SYS_DEVICE ? BST_CHECKED : BST_UNCHECKED,
		0);
}

static int GetSelectedWizardMode (HWND hwndDlg)
{
	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER)))
		return WIZARD_MODE_FILE_CONTAINER;

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE)))
		return WIZARD_MODE_NONSYS_DEVICE;

	if (IsButtonChecked (GetDlgItem (hwndDlg, IDC_SYS_DEVICE)))
		return WIZARD_MODE_SYS_DEVICE;

	return DEFAULT_VOL_CREATION_WIZARD_MODE;
}

static void RefreshMultiBootControls (HWND hwndDlg)
{
#ifdef DEBUG
	if (nMultiBoot == 0)
		nMultiBoot = 1;
#endif

	SendMessage (GetDlgItem (hwndDlg, IDC_SINGLE_BOOT),
		BM_SETCHECK,
		nMultiBoot == 1 ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hwndDlg, IDC_MULTI_BOOT),
		BM_SETCHECK,
		nMultiBoot > 1 ? BST_CHECKED : BST_UNCHECKED,
		0);
}

// -1 = Undecided or error, 0 = No, 1 = Yes
static int Get2RadButtonPageAnswer (void)
{
	if (IsButtonChecked (GetDlgItem (hCurPage, IDC_CHOICE1)))
		return 1;

	if (IsButtonChecked (GetDlgItem (hCurPage, IDC_CHOICE2)))
		return 0;

	return -1;
}

// 0 = No, 1 = Yes
static void Update2RadButtonPage (int answer)
{
	SendMessage (GetDlgItem (hCurPage, IDC_CHOICE1),
		BM_SETCHECK,
		answer == 1 ? BST_CHECKED : BST_UNCHECKED,
		0);

	SendMessage (GetDlgItem (hCurPage, IDC_CHOICE2),
		BM_SETCHECK,
		answer == 0 ? BST_CHECKED : BST_UNCHECKED,
		0);
}

// -1 = Undecided, 0 = No, 1 = Yes
static void Init2RadButtonPageYesNo (int answer)
{
	SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE1), GetString ("UISTR_YES"));
	SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE2), GetString ("UISTR_NO"));

	SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
	SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
	SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

	EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), answer >= 0);
	EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);

	Update2RadButtonPage (answer);
}

static void UpdateSysEncProgressBar (void)
{
	BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	if (locBootEncStatus.EncryptedAreaEnd == -1
		|| locBootEncStatus.EncryptedAreaStart == -1)
	{
		UpdateProgressBarProc (0);
	}
	else
	{
		UpdateProgressBarProc (locBootEncStatus.EncryptedAreaEnd - locBootEncStatus.EncryptedAreaStart + 1);

		if (locBootEncStatus.SetupInProgress)
		{
			wchar_t tmpStr[100];

			// Status

			if (locBootEncStatus.TransformWaitingForIdle)
				StringCbCopyW (tmpStr, sizeof(tmpStr), GetString ("PROGRESS_STATUS_WAITING"));
			else
				StringCbCopyW (tmpStr, sizeof(tmpStr), GetString (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING ? "PROGRESS_STATUS_DECRYPTING" : "PROGRESS_STATUS_ENCRYPTING"));

			StringCbCatW (tmpStr, sizeof(tmpStr), L" ");

			SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), tmpStr);
		}
	}
}

static void InitSysEncProgressBar (void)
{
	BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	if (locBootEncStatus.ConfiguredEncryptedAreaEnd == -1
		|| locBootEncStatus.ConfiguredEncryptedAreaStart == -1)
		return;

	InitProgressBar (locBootEncStatus.ConfiguredEncryptedAreaEnd
		- locBootEncStatus.ConfiguredEncryptedAreaStart + 1,
		(locBootEncStatus.EncryptedAreaEnd == locBootEncStatus.EncryptedAreaStart || locBootEncStatus.EncryptedAreaEnd == -1) ?
		0 :	locBootEncStatus.EncryptedAreaEnd - locBootEncStatus.EncryptedAreaStart + 1,
		SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING,
		TRUE,
		TRUE,
		TRUE);
}

static void UpdateSysEncControls (void)
{
	BootEncryptionStatus locBootEncStatus;

	try
	{
		locBootEncStatus = BootEncObj->GetStatus();
	}
	catch (...)
	{
		return;
	}

	EnableWindow (GetDlgItem (hCurPage, IDC_WIPE_MODE),
		!locBootEncStatus.SetupInProgress
		&& SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING);

	SetWindowTextW (GetDlgItem (hCurPage, IDC_PAUSE),
		GetString (locBootEncStatus.SetupInProgress ? "IDC_PAUSE" : "RESUME"));

	EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), !locBootEncStatus.SetupInProgress && !bFirstSysEncResumeDone);

	if (!locBootEncStatus.SetupInProgress)
	{
		wchar_t tmpStr[100];

		StringCbCopyW (tmpStr, sizeof(tmpStr), GetString ((SysDriveOrPartitionFullyEncrypted (TRUE) || !locBootEncStatus.DriveMounted) ?
			"PROGRESS_STATUS_FINISHED" : "PROGRESS_STATUS_PAUSED"));
		StringCbCatW (tmpStr, sizeof(tmpStr), L" ");

		// Status
		SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), tmpStr);

		if (SysDriveOrPartitionFullyEncrypted (TRUE) || SystemEncryptionStatus == SYSENC_STATUS_NONE)
		{
			StringCbCopyW (tmpStr, sizeof(tmpStr), GetString ("PROCESSED_PORTION_100_PERCENT"));
			StringCbCatW (tmpStr, sizeof(tmpStr), L" ");

			SetWindowTextW (GetDlgItem (hCurPage, IDC_BYTESWRITTEN), tmpStr);
		}

		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), L" ");
	}
}

static void SysEncPause (void)
{
	BootEncryptionStatus locBootEncStatus;

	if (CreateSysEncMutex ())
	{
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		if (!locBootEncStatus.SetupInProgress)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		WaitCursor ();

		try
		{
			int attempts = SYSENC_PAUSE_RETRIES;

			BootEncObj->AbortSetup ();

			locBootEncStatus = BootEncObj->GetStatus();

			while (locBootEncStatus.SetupInProgress && attempts > 0)
			{
				Sleep (SYSENC_PAUSE_RETRY_INTERVAL);
				attempts--;
				locBootEncStatus = BootEncObj->GetStatus();
			}

			if (!locBootEncStatus.SetupInProgress)
				BootEncObj->CheckEncryptionSetupResult ();

		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (locBootEncStatus.SetupInProgress)
		{
			SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			Error ("FAILED_TO_INTERRUPT_SYSTEM_ENCRYPTION", MainDlg);
			return;
		}

		UpdateSysEncControls ();
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
	}
	else
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
}


static void SysEncResume (void)
{
	BootEncryptionStatus locBootEncStatus;

	if (CreateSysEncMutex ())
	{
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

		try
		{
			locBootEncStatus = BootEncObj->GetStatus();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		if (locBootEncStatus.SetupInProgress)
		{
			// Prevent the OS from entering Sleep mode when idle
			SetThreadExecutionState (ES_CONTINUOUS | ES_SYSTEM_REQUIRED);

			bSystemEncryptionInProgress = TRUE;
			UpdateSysEncControls ();
			SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			return;
		}

		bVolTransformThreadCancel = FALSE;
		bSystemEncryptionInProgress = FALSE;
		WaitCursor ();

		try
		{
			switch (SystemEncryptionStatus)
			{
			case SYSENC_STATUS_ENCRYPTING:

				BootEncObj->StartEncryption (nWipeMode, bTryToCorrectReadErrors ? true : false);
				break;

			case SYSENC_STATUS_DECRYPTING:

				if (locBootEncStatus.DriveMounted)	// If the drive is not encrypted we will just deinstall
					BootEncObj->StartDecryption (DiscardUnreadableEncryptedSectors);

				break;
			}

			bSystemEncryptionInProgress = TRUE;
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (!bSystemEncryptionInProgress)
		{
			// Allow the OS to enter Sleep mode when idle
			SetThreadExecutionState (ES_CONTINUOUS);

			EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
			Error ("FAILED_TO_RESUME_SYSTEM_ENCRYPTION", MainDlg);
			return;
		}

		// Prevent the OS from entering Sleep mode when idle
		SetThreadExecutionState (ES_CONTINUOUS | ES_SYSTEM_REQUIRED);

		bFirstSysEncResumeDone = TRUE;
		InitSysEncProgressBar ();
		UpdateSysEncProgressBar ();
		UpdateSysEncControls ();
		EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), TRUE);
		SetTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS, TIMER_INTERVAL_SYSENC_PROGRESS, NULL);
	}
	else
		Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
}


static BOOL GetDevicePathForHiddenOS (void)
{
	BOOL tmpbDevice = FALSE;

	try
	{
		StringCbCopyW (szFileName, sizeof(szFileName), BootEncObj->GetPartitionForHiddenOS().DevicePath.c_str());

		CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &tmpbDevice);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
		return FALSE;
	}

	return (szFileName[0] != 0
		&& szDiskFile[0] != 0
		&& tmpbDevice);
}


// Returns TRUE if there is unallocated space greater than 64 MB (max possible slack space size) between the
// boot partition and the first partition behind it. If there's none or if an error occurs, returns FALSE.
static BOOL CheckGapBetweenSysAndHiddenOS (void)
{
	try
	{
		SystemDriveConfiguration sysDriveCfg = BootEncObj->GetSystemDriveConfiguration();

		return (sysDriveCfg.SystemPartition.Info.StartingOffset.QuadPart
			+ sysDriveCfg.SystemPartition.Info.PartitionLength.QuadPart
			+ 64 * BYTES_PER_MB
			+ 128 * BYTES_PER_KB
			<= BootEncObj->GetPartitionForHiddenOS().Info.StartingOffset.QuadPart);
	}
	catch (Exception &e)
	{
		e.Show (MainDlg);
	}

	return FALSE;
}


static void NonSysInplaceEncPause (void)
{
	bVolTransformThreadCancel = TRUE;

	WaitCursor ();

	int waitThreshold = 100;	// Do not block GUI events for more than 10 seconds. IMPORTANT: This prevents deadlocks when the thread calls us back e.g. to update GUI!

	while (bVolTransformThreadRunning || bVolTransformThreadToRun)
	{
		MSG guiMsg;

		bVolTransformThreadCancel = TRUE;

		if (waitThreshold <= 0)
		{
			while (PeekMessageW (&guiMsg, NULL, 0, 0, PM_REMOVE) != 0)
			{
				DispatchMessageW (&guiMsg);
			}
		}
		else
			waitThreshold--;

		Sleep (100);
	}
}


static void NonSysInplaceEncResume (void)
{
	if (bVolTransformThreadRunning || bVolTransformThreadToRun || bVolTransformThreadCancel)
		return;

	if (!bInPlaceEncNonSysResumed
		&& !FinalPreTransformPrompts ())
	{
		return;
	}

	CreateNonSysInplaceEncMutex ();

	bFirstNonSysInPlaceEncResumeDone = TRUE;

	SetTimer (MainDlg, TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS, TIMER_INTERVAL_NONSYS_INPLACE_ENC_PROGRESS, NULL);

	bVolTransformThreadCancel = FALSE;
	bVolTransformThreadToRun = TRUE;

	UpdateNonSysInPlaceEncControls ();

	LastDialogId = "NONSYS_INPLACE_ENC_IN_PROGRESS";

	_beginthread (volTransformThreadFunction, 0, MainDlg);

	return;
}


void ShowNonSysInPlaceEncUIStatus (void)
{
	wchar_t nonSysInplaceEncUIStatus [300] = {0};

	switch (NonSysInplaceEncStatus)
	{
	case NONSYS_INPLACE_ENC_STATUS_PAUSED:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_PAUSED"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_PREPARING:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_PREPARING"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_RESIZING:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_RESIZING"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_ENCRYPTING:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_ENCRYPTING"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_DECRYPTING:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_DECRYPTING"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_FINALIZING:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_FINALIZING"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_FINISHED:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_FINISHED"));
		break;
	case NONSYS_INPLACE_ENC_STATUS_ERROR:
		StringCbCopyW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), GetString ("PROGRESS_STATUS_ERROR"));
		break;
	}

	StringCbCatW (nonSysInplaceEncUIStatus, sizeof(nonSysInplaceEncUIStatus), L" ");

	SetWindowTextW (GetDlgItem (hCurPage, IDC_WRITESPEED), nonSysInplaceEncUIStatus);
}


void UpdateNonSysInPlaceEncControls (void)
{
	// Reduce flickering by updating a GUI element only when a relevant change affects it
	static BOOL lastbVolTransformThreadRunning = !bVolTransformThreadRunning;
	static BOOL lastbVolTransformThreadToRun = !bVolTransformThreadToRun;
	static BOOL lastbInPlaceEncNonSysResumed = !bInPlaceEncNonSysResumed;

	EnableWindow (GetDlgItem (hCurPage, IDC_WIPE_MODE), !(bVolTransformThreadRunning || bVolTransformThreadToRun) && !bInPlaceDecNonSys);

	if (lastbVolTransformThreadRunning != bVolTransformThreadRunning
		|| lastbVolTransformThreadToRun != bVolTransformThreadToRun)
	{
		SetWindowTextW (GetDlgItem (hCurPage, IDC_PAUSE),
			GetString ((bVolTransformThreadRunning || bVolTransformThreadToRun) ? "IDC_PAUSE" : "RESUME"));

		lastbVolTransformThreadRunning = bVolTransformThreadRunning;
		lastbVolTransformThreadToRun = bVolTransformThreadToRun;
	}

	if (lastbInPlaceEncNonSysResumed != bInPlaceEncNonSysResumed)
	{
		SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString (bInPlaceEncNonSysResumed ? "DEFER" : "CANCEL"));
		lastbInPlaceEncNonSysResumed = bInPlaceEncNonSysResumed;
	}

	EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), bFirstNonSysInPlaceEncResumeDone
		&& NonSysInplaceEncStatus != NONSYS_INPLACE_ENC_STATUS_FINALIZING
		&& NonSysInplaceEncStatus != NONSYS_INPLACE_ENC_STATUS_FINISHED);

	EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), !(bVolTransformThreadRunning || bVolTransformThreadToRun) && !bFirstNonSysInPlaceEncResumeDone);
	EnableWindow (GetDlgItem (MainDlg, IDC_PREV), !(bVolTransformThreadRunning || bVolTransformThreadToRun) && !bInPlaceEncNonSysResumed);
	EnableWindow (GetDlgItem (MainDlg, IDCANCEL),
		!(bVolTransformThreadToRun
		|| NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_PREPARING
		|| NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_RESIZING
		|| NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINALIZING
		|| NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINISHED));

	if (bVolTransformThreadRunning || bVolTransformThreadToRun)
	{
		switch (NonSysInplaceEncStatus)
		{
		case NONSYS_INPLACE_ENC_STATUS_PREPARING:
		case NONSYS_INPLACE_ENC_STATUS_RESIZING:
		case NONSYS_INPLACE_ENC_STATUS_FINALIZING:
			ArrowWaitCursor ();
			break;

		case NONSYS_INPLACE_ENC_STATUS_ENCRYPTING:
			NormalCursor ();
			break;

		default:
			NormalCursor ();
			break;
		}

		if (bVolTransformThreadCancel)
			WaitCursor ();
	}
	else
	{
		NormalCursor ();

		if (bInPlaceEncNonSysResumed)
		{
			SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PAUSED);
		}
		else
			SetWindowText (GetDlgItem (hCurPage, IDC_WRITESPEED), L" ");

		SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), L" ");
	}

	ShowNonSysInPlaceEncUIStatus ();

	UpdateNonSysInplaceEncProgressBar ();
}


static void UpdateNonSysInplaceEncProgressBar (void)
{
	static int lastNonSysInplaceEncStatus = NONSYS_INPLACE_ENC_STATUS_NONE;
	int nonSysInplaceEncStatus = NonSysInplaceEncStatus;
	__int64 totalSize = NonSysInplaceEncTotalSize;

	if (bVolTransformThreadRunning
		&& (nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_ENCRYPTING
		|| nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_DECRYPTING
		|| nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINALIZING
		|| nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINISHED))
	{
		if (lastNonSysInplaceEncStatus != nonSysInplaceEncStatus
			&& (nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_ENCRYPTING || nonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_DECRYPTING))
		{
			InitNonSysInplaceEncProgressBar ();
		}
		else
		{
			if (totalSize <= 0 && nVolumeSize > 0)
				totalSize = nVolumeSize;

			if (totalSize > 0)
				UpdateProgressBarProc (NonSysInplaceEncBytesDone);
		}
	}

	ShowNonSysInPlaceEncUIStatus ();

	lastNonSysInplaceEncStatus = nonSysInplaceEncStatus;
}


static void InitNonSysInplaceEncProgressBar (void)
{
	__int64 totalSize = NonSysInplaceEncTotalSize;

	if (totalSize <= 0)
	{
		if (nVolumeSize <= 0)
			return;

		totalSize = nVolumeSize;
	}

	InitProgressBar (totalSize,
		NonSysInplaceEncBytesDone,
		bInPlaceDecNonSys,
		TRUE,
		TRUE,
		TRUE);
}


void DisplayRandPool (HWND hwndDlg, HWND hPoolDisplay, BOOL bShow)
{
	wchar_t tmp[4];
	unsigned char tmpByte;
	int col, row;
	static BOOL bRandPoolDispAscii = FALSE;
	DWORD mouseEventsCounter;

	RandpeekBytes (hwndDlg, randPool, sizeof (randPool), &mouseEventsCounter);

	ProcessEntropyEstimate (hEntropyBar, &mouseEventsInitialCount, mouseEventsCounter, maxEntropyLevel, &mouseEntropyGathered);

	if (memcmp (lastRandPool, randPool, sizeof(lastRandPool)) != 0)
	{
		outRandPoolDispBuffer[0] = 0;

		for (row = 0; row < RANDPOOL_DISPLAY_ROWS; row++)
		{
			for (col = 0; col < RANDPOOL_DISPLAY_COLUMNS; col++)
			{
				if (bShow)
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


				StringCbCatW (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer), tmp);
			}
			StringCbCatW (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer), L"\n");
		}
		SetWindowText (hPoolDisplay, outRandPoolDispBuffer);

		memcpy (lastRandPool, randPool, sizeof(lastRandPool));
	}
}


void DisplayPortionsOfKeys (HWND headerKeyHandle, HWND masterKeyHandle, wchar_t *headerKeyStr, wchar_t *masterKeyStr, BOOL hideKeys)
{
	const wchar_t *hiddenKey = L"********************************                                              ";

	SetWindowTextW (headerKeyHandle, hideKeys ? hiddenKey : (std::wstring (headerKeyStr) + GetString ("TRIPLE_DOT_GLYPH_ELLIPSIS")).c_str());
	SetWindowTextW (masterKeyHandle, hideKeys ? hiddenKey : (std::wstring (masterKeyStr) + GetString ("TRIPLE_DOT_GLYPH_ELLIPSIS")).c_str());
}


static void WipeAbort (void)
{
	EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);

	if (bHiddenOS && IsHiddenOSRunning())
	{
		/* Decoy system partition wipe */

		DecoySystemWipeStatus decoySysPartitionWipeStatus;

		try
		{
			decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
			return;
		}

		if (!decoySysPartitionWipeStatus.WipeInProgress)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
			return;
		}

		WaitCursor ();

		try
		{
			int attempts = SYSENC_PAUSE_RETRIES;

			BootEncObj->AbortDecoyOSWipe ();

			decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();

			while (decoySysPartitionWipeStatus.WipeInProgress && attempts > 0)
			{
				Sleep (SYSENC_PAUSE_RETRY_INTERVAL);
				attempts--;
				decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
			}

			if (!decoySysPartitionWipeStatus.WipeInProgress)
				BootEncObj->CheckDecoyOSWipeResult ();

		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (decoySysPartitionWipeStatus.WipeInProgress)
		{
			SetTimer (MainDlg, TIMER_ID_WIPE_PROGRESS, TIMER_INTERVAL_WIPE_PROGRESS, NULL);
			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
			Error ("FAILED_TO_INTERRUPT_WIPING", MainDlg);
			return;
		}
	}
	else
	{
		/* Regular device wipe (not decoy system partition wipe) */
	}

	UpdateWipeControls ();
	EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
}


static void WipeStart (void)
{
	if (bHiddenOS && IsHiddenOSRunning())
	{
		/* Decoy system partition wipe */

		EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);

		bDeviceWipeInProgress = FALSE;
		WaitCursor ();

		try
		{
			BootEncObj->StartDecoyOSWipe (nWipeMode);

			bDeviceWipeInProgress = TRUE;
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}

		NormalCursor ();

		if (!bDeviceWipeInProgress)
		{
			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
			Error ("FAILED_TO_START_WIPING", MainDlg);
			return;
		}
	}
	else
	{
		/* Regular device wipe (not decoy system partition wipe) */
	}

	InitWipeProgressBar ();
	UpdateWipeProgressBar ();
	UpdateWipeControls ();
	EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
	SetTimer (MainDlg, TIMER_ID_WIPE_PROGRESS, TIMER_INTERVAL_WIPE_PROGRESS, NULL);
}


static void UpdateWipeProgressBar (void)
{
	if (bHiddenOS && IsHiddenOSRunning())
	{
		/* Decoy system partition wipe */

		DecoySystemWipeStatus decoySysPartitionWipeStatus;

		try
		{
			decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
			BootEncStatus = BootEncObj->GetStatus();
		}
		catch (...)
		{
			return;
		}

		if (decoySysPartitionWipeStatus.WipedAreaEnd == -1)
			UpdateProgressBarProc (0);
		else
			UpdateProgressBarProc (decoySysPartitionWipeStatus.WipedAreaEnd - BootEncStatus.ConfiguredEncryptedAreaStart + 1);
	}
	else
	{
		/* Regular device wipe (not decoy system partition wipe) */
	}
}


static void InitWipeProgressBar (void)
{
	if (bHiddenOS && IsHiddenOSRunning())
	{
		/* Decoy system partition wipe */

		DecoySystemWipeStatus decoySysPartitionWipeStatus;

		try
		{
			decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
			BootEncStatus = BootEncObj->GetStatus();
		}
		catch (...)
		{
			return;
		}

		if (BootEncStatus.ConfiguredEncryptedAreaEnd == -1
			|| BootEncStatus.ConfiguredEncryptedAreaStart == -1)
			return;

		InitProgressBar (BootEncStatus.ConfiguredEncryptedAreaEnd - BootEncStatus.ConfiguredEncryptedAreaStart + 1,
			(decoySysPartitionWipeStatus.WipedAreaEnd == BootEncStatus.ConfiguredEncryptedAreaStart || decoySysPartitionWipeStatus.WipedAreaEnd == -1) ?
			0 :	decoySysPartitionWipeStatus.WipedAreaEnd - BootEncStatus.ConfiguredEncryptedAreaStart + 1,
			FALSE,
			TRUE,
			FALSE,
			TRUE);
	}
	else
	{
		/* Regular device wipe (not decoy system partition wipe) */
	}
}


static void UpdateWipeControls (void)
{
	if (bHiddenOS && IsHiddenOSRunning())
	{
		/* Decoy system partition wipe */

		DecoySystemWipeStatus decoySysPartitionWipeStatus;

		try
		{
			decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
			BootEncStatus = BootEncObj->GetStatus();
		}
		catch (...)
		{
			return;
		}

		EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), !decoySysPartitionWipeStatus.WipeInProgress);
	}
	else
	{
		/* Regular device wipe (not decoy system partition wipe) */

		EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), bDeviceWipeInProgress);

		if (!bDeviceWipeInProgress)
		{
			SetWindowText (GetDlgItem (hCurPage, IDC_TIMEREMAIN), L" ");
		}
	}

	EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), bDeviceWipeInProgress);
	EnableWindow (GetDlgItem (MainDlg, IDC_PREV), !bDeviceWipeInProgress);

	bConfirmQuit = bDeviceWipeInProgress;
}



static void __cdecl sysEncDriveAnalysisThread (void *hwndDlgArg)
{
	// Mark the detection process as 'in progress'
	HiddenSectorDetectionStatus = 1;
	SaveSettings (NULL);
	BroadcastSysEncCfgUpdate ();

	try
	{
		BootEncObj->ProbeRealSystemDriveSize ();
		bSysEncDriveAnalysisTimeOutOccurred = FALSE;
	}
	catch (TimeOut &)
	{
		bSysEncDriveAnalysisTimeOutOccurred = TRUE;
	}
	catch (Exception &e)
	{
		// There was a problem but the system did not freeze. Mark the detection process as completed.
		HiddenSectorDetectionStatus = 0;
		SaveSettings (NULL);
		BroadcastSysEncCfgUpdate ();

		e.Show (NULL);
		EndMainDlg (MainDlg);
		exit(0);
	}

	// Mark the detection process as completed
	HiddenSectorDetectionStatus = 0;
	SaveSettings (NULL);
	BroadcastSysEncCfgUpdate ();

	// This artificial delay prevents user confusion on systems where the analysis ends almost instantly
	Sleep (3000);

	bSysEncDriveAnalysisInProgress = FALSE;
}

static void __cdecl volTransformThreadFunction (void *hwndDlgArg)
{
	int nStatus;
	DWORD dwWin32FormatError;
	BOOL bHidden;
	HWND hwndDlg = (HWND) hwndDlgArg;
	volatile FORMAT_VOL_PARAMETERS *volParams = (FORMAT_VOL_PARAMETERS *) malloc (sizeof(FORMAT_VOL_PARAMETERS));

	if (volParams == NULL)
		AbortProcess ("ERR_MEM_ALLOC");

	VirtualLock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));

	bOperationSuccess = FALSE;

	if (bGuiMode)
	{
		bVolTransformThreadRunning = TRUE;
		bVolTransformThreadToRun = FALSE;
	}

	// Check administrator privileges
	if (!IsAdmin () && !IsUacSupported ())
	{
		if (fileSystem == FILESYS_NTFS || fileSystem == FILESYS_EXFAT  || fileSystem == FILESYS_REFS)
		{
			if (Silent || (MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_NTFS"), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL))
				goto cancel;
		}
		if (bDevice)
		{
			if (Silent || (MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_DEVICES"), lpszTitle, MB_OKCANCEL|MB_ICONWARNING|MB_DEFBUTTON2) == IDCANCEL))
				goto cancel;
		}
	}

	if (!bInPlaceEncNonSys)
	{
		if (!bDevice)
		{
			int x = _waccess (szDiskFile, 06);
			if (x == 0 || errno != ENOENT)
			{
				wchar_t szTmp[512];

				if (!bForceOperation && !((bHiddenVol && !bHiddenVolHost) && errno != EACCES))	// Only ask ask for permission to overwrite an existing volume if we're not creating a hidden volume
				{
					StringCbPrintfW (szTmp, sizeof szTmp,
						GetString (errno == EACCES ? "READONLYPROMPT" : "OVERWRITEPROMPT"),
						szDiskFile);

					x = Silent? IDNO : MessageBoxW (hwndDlg, szTmp, lpszTitle, YES_NO|MB_ICONWARNING|MB_DEFBUTTON2);

					if (x != IDYES)
						goto cancel;
				}
			}

			if (_waccess (szDiskFile, 06) != 0)
			{
				if (errno == EACCES)
				{
					if (_wchmod (szDiskFile, _S_IREAD | _S_IWRITE) != 0)
					{
						if (!Silent) MessageBoxW (hwndDlg, GetString ("ACCESSMODEFAIL"), lpszTitle, ICON_HAND);
						goto cancel;
					}
				}
			}

		}
		else
		{
			// Partition / device / dynamic volume

			if (!FinalPreTransformPrompts ())
				goto cancel;
		}
	}

	// Prevent the OS from entering Sleep mode when idle
	SetThreadExecutionState (ES_CONTINUOUS | ES_SYSTEM_REQUIRED);

	bHidden = bHiddenVol && !bHiddenVolHost;

	volParams->bDevice = bDevice;
	volParams->hiddenVol = bHidden;
	volParams->volumePath = szDiskFile;
	volParams->size = nVolumeSize;
	volParams->hiddenVolHostSize = nHiddenVolHostSize;
	volParams->ea = nVolumeEA;
	volParams->pkcs5 = hash_algo;
	volParams->headerFlags = (CreatingHiddenSysVol() ? TC_HEADER_FLAG_ENCRYPTED_SYSTEM : 0);
	volParams->fileSystem = fileSystem;
	volParams->clusterSize = clusterSize;
	volParams->sparseFileSwitch = dynamicFormat;
	volParams->quickFormat = quickFormat;
	volParams->fastCreateFile = fastCreateFile;
	volParams->sectorSize = GetFormatSectorSize();
	volParams->realClusterSize = &realClusterSize;
	volParams->password = &volumePassword;
	volParams->pim = volumePim;
	volParams->hwndDlg = hwndDlg;
	volParams->bForceOperation = bForceOperation;
	volParams->bGuiMode = bGuiMode;

	if (bInPlaceDecNonSys)
	{
		// In-place decryption of non-system volume

		if (!bInPlaceEncNonSysResumed)
			DiscardUnreadableEncryptedSectors = FALSE;

		nStatus = DecryptPartitionInPlace (volParams, &DiscardUnreadableEncryptedSectors);
	}
	else if (bInPlaceEncNonSys)
	{
		// In-place encryption of non-system volume

		HANDLE hPartition = INVALID_HANDLE_VALUE;

		SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PREPARING);

		if (!bInPlaceEncNonSysResumed)
		{
			bTryToCorrectReadErrors = FALSE;

			nStatus = EncryptPartitionInPlaceBegin (volParams, &hPartition, nWipeMode);

			if (nStatus == ERR_SUCCESS)
			{
				nStatus = EncryptPartitionInPlaceResume (hPartition, volParams, nWipeMode, &bTryToCorrectReadErrors);
			}
			else if (hPartition != INVALID_HANDLE_VALUE)
			{
				CloseHandle (hPartition);
				hPartition = INVALID_HANDLE_VALUE;
			}
		}
		else
		{
			nStatus = EncryptPartitionInPlaceResume (INVALID_HANDLE_VALUE, volParams, nWipeMode, &bTryToCorrectReadErrors);
		}
	}
	else
	{
		// Format-encryption

		if (hwndDlg && bGuiMode) InitProgressBar (GetVolumeDataAreaSize (bHidden, nVolumeSize), 0, FALSE, FALSE, FALSE, TRUE);

		nStatus = TCFormatVolume (volParams);
	}

	// Allow the OS to enter Sleep mode when idle
	SetThreadExecutionState (ES_CONTINUOUS);

	if (nStatus == ERR_OUTOFMEMORY)
	{
		AbortProcess ("OUTOFMEMORY");
	}

	if (bInPlaceEncNonSys
		&& nStatus == ERR_USER_ABORT
		&& NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINISHED)
	{
		// Ignore user abort if non-system in-place encryption/decryption successfully finished
		nStatus = ERR_SUCCESS;
	}


	dwWin32FormatError = GetLastError ();

	if (bHiddenVolHost && (!bGuiMode || !bVolTransformThreadCancel) && nStatus == 0)
	{
		/* Auto mount the newly created hidden volume host */
		switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, hash_algo, volumePim, FALSE))
		{
		case ERR_NO_FREE_DRIVES:
			if (!Silent) MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
			if (bGuiMode) bVolTransformThreadCancel = TRUE;
			break;
		case ERR_VOL_MOUNT_FAILED:
		case ERR_PASSWORD_WRONG:
			if (!Silent) MessageBoxW (hwndDlg, GetString ("CANT_MOUNT_OUTER_VOL"), lpszTitle, ICON_HAND);
			if (bGuiMode) bVolTransformThreadCancel = TRUE;
			break;
		}
	}

	SetLastError (dwWin32FormatError);

	if ((bVolTransformThreadCancel || nStatus == ERR_USER_ABORT)
		&& !(bInPlaceEncNonSys && NonSysInplaceEncStatus == NONSYS_INPLACE_ENC_STATUS_FINISHED))	// Ignore user abort if non-system in-place encryption/decryption successfully finished.
	{
		if (!bDevice && !(bHiddenVol && !bHiddenVolHost))	// If we're not creating a hidden volume and if it's a file container
		{
			_wremove (szDiskFile);		// Delete the container
		}

		goto cancel;
	}

	if (nStatus != ERR_USER_ABORT)
	{
		if (nStatus != 0)
		{
			/* An error occurred */

			wchar_t szMsg[8192];

			handleError (hwndDlg, nStatus, SRC_POS);

			if (bInPlaceEncNonSys)
			{
				if (bInPlaceEncNonSysResumed)
				{
					SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_PAUSED);
					Error ("INPLACE_ENC_GENERIC_ERR_RESUME", hwndDlg);
				}
				else
				{
					SetNonSysInplaceEncUIStatus (NONSYS_INPLACE_ENC_STATUS_ERROR);

					if (bInPlaceDecNonSys)
						Error ("INPLACE_DEC_GENERIC_ERR", hwndDlg);
					else
						ShowInPlaceEncErrMsgWAltSteps (hwndDlg, "INPLACE_ENC_GENERIC_ERR_ALT_STEPS", TRUE);
				}
			}
			else if (!Silent && !(bHiddenVolHost && hiddenVolHostDriveNo < 0))  // If the error was not that the hidden volume host could not be mounted (this error has already been reported to the user)
			{
				StringCbPrintfW (szMsg, sizeof(szMsg), GetString ("CREATE_FAILED"), szDiskFile);
				MessageBoxW (hwndDlg, szMsg, lpszTitle, ICON_HAND);
			}

			if (!bDevice && !(bHiddenVol && !bHiddenVolHost))	// If we're not creating a hidden volume and if it's a file container
			{
				_wremove (szDiskFile);		// Delete the container
			}

			goto cancel;
		}
		else
		{
			/* Volume successfully created */

			RestoreDefaultKeyFilesParam ();

			PimEnable = FALSE;

			bOperationSuccess = TRUE;

			if (bDevice && !bInPlaceEncNonSys)
			{
				// Handle assigned drive letter (if any)

				HandleOldAssignedDriveLetter ();
			}

			if (!bHiddenVolHost)
			{
				if (bHiddenVol)
				{
					bHiddenVolFinished = TRUE;

					if (!bHiddenOS)
						Warning ("HIDVOL_FORMAT_FINISHED_HELP", hwndDlg);
				}
				else if (bInPlaceEncNonSys)
				{
					if (!bInPlaceDecNonSys)
					{
						Warning ("NONSYS_INPLACE_ENC_FINISHED_INFO", hwndDlg);

						HandleOldAssignedDriveLetter ();
					}
					else
					{
						// NOP - Final steps for in-place decryption are handled with the TC_APPMSG_NONSYS_INPLACE_ENC_FINISHED message.
					}
				}
				else
				{
					Info("FORMAT_FINISHED_INFO", hwndDlg);

					if (dynamicFormat)
						Warning("SPARSE_FILE_SIZE_NOTE", hwndDlg);
				}
			}
			else
			{
				/* We've just created an outer volume (to host a hidden volume within) */

				bHiddenVolHost = FALSE;
				bHiddenVolFinished = FALSE;
				nHiddenVolHostSize = nVolumeSize;

				// Clear the outer volume password
				burn(&szVerify[0], sizeof (szVerify));
				burn(&szRawPassword[0], sizeof (szRawPassword));

				if (!Silent) MessageBeep (MB_OK);
			}

			if (!bInPlaceEncNonSys && hwndDlg && bGuiMode)
				SetTimer (hwndDlg, TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);


			// volParams is ensured to be non NULL at this stage
			burn ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
			VirtualUnlock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
			free ((LPVOID) volParams);
			volParams = NULL;

			if (bGuiMode)
			{
				bVolTransformThreadRunning = FALSE;
				bVolTransformThreadCancel = FALSE;
			}

			if (hwndDlg && bGuiMode) PostMessage (hwndDlg, bInPlaceEncNonSys ? TC_APPMSG_NONSYS_INPLACE_ENC_FINISHED : TC_APPMSG_FORMAT_FINISHED, 0, 0);

			LastDialogId = "FORMAT_FINISHED";
			if (bGuiMode) _endthread ();
		}
	}

cancel:

	LastDialogId = (bInPlaceEncNonSys ? "NONSYS_INPLACE_ENC_CANCELED" : "FORMAT_CANCELED");

	if (!bInPlaceEncNonSys && hwndDlg && bGuiMode)
		SetTimer (hwndDlg, TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

	if (volParams != NULL)
	{
		burn ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
		VirtualUnlock ((LPVOID) volParams, sizeof(FORMAT_VOL_PARAMETERS));
		free ((LPVOID) volParams);
		volParams = NULL;
	}

	if (bGuiMode)
	{
		bVolTransformThreadRunning = FALSE;
		bVolTransformThreadCancel = FALSE;
	}

	// Allow the OS to enter Sleep mode when idle
	SetThreadExecutionState (ES_CONTINUOUS);

	if (hwndDlg) PostMessage (hwndDlg, TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED, 0, 0);

	if (bHiddenVolHost && hiddenVolHostDriveNo < -1 && !bVolTransformThreadCancel)	// If hidden volume host could not be mounted
		AbortProcessSilent ();

	if (bGuiMode) _endthread ();
}

static void LoadPage (HWND hwndDlg, int nPageNo)
{
	RECT rD, rW;

	nLastPageNo = nCurPageNo;

	if (hCurPage != NULL)
	{
		// WARNING: nCurPageNo must be set to a non-existent ID here before wiping the password fields below in
		// this function, etc. Otherwise, such actions (SetWindowText) would invoke the EN_CHANGE handlers, which
		// would, if keyfiles were applied, e.g. use strlen() on a buffer full of random data, in most cases
		// not null-terminated.
		nCurPageNo = -1;


		// Place here any actions that need to be performed at the latest possible time when leaving a wizard page
		// (i.e. right before "destroying" the page). Also, code that needs to be executed both on IDC_NEXT and
		// on IDC_PREV can be placed here so as to avoid code doubling.

		switch (nLastPageNo)
		{
		case PASSWORD_PAGE:
			{
				wchar_t tmp[MAX_PASSWORD+1];

				// Attempt to wipe passwords stored in the input field buffers. This is performed here (and
				// not in the IDC_PREV or IDC_NEXT sections) in order to prevent certain race conditions
				// when keyfiles are used.
				wmemset (tmp, 'X', MAX_PASSWORD);
				tmp [MAX_PASSWORD] = 0;
				SetWindowText (hPasswordInputField, tmp);
				SetWindowText (hVerifyPasswordInputField, tmp);
			}
			break;
		}

		DestroyWindow (hCurPage);
		hCurPage = NULL;
	}

	// This prevents the mouse pointer from remaining as the "hand" cursor when the user presses Enter
	// while hovering over a hyperlink.
	bHyperLinkBeingTracked = FALSE;
	NormalCursor();

	GetWindowRect (GetDlgItem (hwndDlg, IDC_POS_BOX), &rW);


	nCurPageNo = nPageNo;


	switch (nPageNo)
	{
	case INTRO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INTRO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_TYPE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_TYPE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_HIDDEN_OS_REQ_CHECK_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_SPAN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_SPAN_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_DRIVE_ANALYSIS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_DRIVE_ANALYSIS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_MULTI_BOOT_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:
	case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:
	case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:
	case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_MULTI_BOOT_OUTCOME_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case VOLUME_TYPE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_VOLUME_TYPE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case HIDDEN_VOL_WIZARD_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_HIDDEN_VOL_WIZARD_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case VOLUME_LOCATION_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_VOLUME_LOCATION_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);

		EnableWindow (GetDlgItem(hCurPage, IDC_NO_HISTORY), !bHistoryCmdLine);

		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT),
			GetWindowTextLength (GetDlgItem (hCurPage, IDC_COMBO_BOX)) > 0);

		break;

	case DEVICE_TRANSFORM_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_DEVICE_TRANSFORM_MODE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_PRE_CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case CIPHER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SIZE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SIZE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case HIDDEN_VOL_HOST_PASSWORD_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PASSWORD_ENTRY_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case PASSWORD_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PASSWORD_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case PIM_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PIM_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FILESYS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_UNIVERSAL_DUAL_CHOICE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_COLLECTING_RANDOM_DATA_PAGE:
	case NONSYS_INPLACE_ENC_RAND_DATA_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_COLLECTING_RANDOM_DATA_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_KEYS_GEN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_KEYS_GEN_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_CREATION_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_RESCUE_DISK_CREATION_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_BURN_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_RESCUE_DISK_BURN_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;
	case SYSENC_RESCUE_DISK_VERIFIED_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_WIPE_MODE_PAGE:
	case NONSYS_INPLACE_ENC_WIPE_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_SYSENC_WIPE_MODE_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;
	case SYSENC_PRETEST_INFO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_PRETEST_RESULT_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case SYSENC_ENCRYPTION_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INPLACE_ENCRYPTION_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;

	case NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PASSWORD_ENTRY_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;

	case NONSYS_INPLACE_ENC_RESUME_PARTITION_SEL_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_EXPANDED_LIST_SELECT_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;

	case NONSYS_INPLACE_ENC_TRANSFORM_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INPLACE_ENCRYPTION_PAGE_DLG), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;

	case NONSYS_INPLACE_ENC_TRANSFORM_FINISHED_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case NONSYS_INPLACE_DEC_TRANSFORM_FINISHED_DRIVE_LETTER_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_DRIVE_LETTER_SELECTION_PAGE), hwndDlg,
			(DLGPROC) PageDialogProc);
		break;

	case FORMAT_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_FORMAT_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	case FORMAT_FINISHED_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW ((bHiddenVol && !bHiddenVolHost && !bHiddenVolFinished) ? IDD_HIDVOL_HOST_FILL_PAGE_DLG : IDD_INFO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case SYSENC_HIDDEN_OS_INITIAL_INFO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg, (DLGPROC) PageDialogProc);
		break;

	case SYSENC_HIDDEN_OS_WIPE_INFO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INFO_PAGE_DLG), hwndDlg, (DLGPROC) PageDialogProc);
		break;

	case DEVICE_WIPE_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_DEVICE_WIPE_MODE_PAGE_DLG), hwndDlg, (DLGPROC) PageDialogProc);
		break;

	case DEVICE_WIPE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_DEVICE_WIPE_PAGE_DLG), hwndDlg, (DLGPROC) PageDialogProc);
		break;
	}

	rD.left = 162;
	rD.top = 25;
	rD.right = 0;
	rD.bottom = 0;
	MapDialogRect (hwndDlg, &rD);

	if (hCurPage != NULL)
	{
		MoveWindow (hCurPage, rD.left, rD.top, rW.right - rW.left, rW.bottom - rW.top, TRUE);
		ShowWindow (hCurPage, SW_SHOWNORMAL);

		// Place here any message boxes that need to be displayed as soon as a new page is displayed. This
		// ensures that the page is fully rendered (otherwise it would remain blank, until the message box
		// is closed).
		switch (nPageNo)
		{
		case PASSWORD_PAGE:

			CheckCapsLock (hwndDlg, FALSE);

			if (CreatingHiddenSysVol())
				Warning ("PASSWORD_HIDDEN_OS_NOTE", MainDlg);

			break;

		case CIPHER_PAGE:

			if (CreatingHiddenSysVol())
				Warning ("HIDDEN_OS_PRE_CIPHER_WARNING", MainDlg);

			break;
		}
	}
}


__int64 PrintFreeSpace (HWND hwndTextBox, wchar_t *lpszDrive, PLARGE_INTEGER lDiskFree)
{
	char *nResourceString;
	__int64 nPrintMultiplier;
	wchar_t szTmp2[256];

	if (lDiskFree->QuadPart < BYTES_PER_KB)
		nPrintMultiplier = 1;
	else if (lDiskFree->QuadPart < BYTES_PER_MB)
		nPrintMultiplier = BYTES_PER_KB;
	else if (lDiskFree->QuadPart < BYTES_PER_GB)
		nPrintMultiplier = BYTES_PER_MB;
	else if (lDiskFree->QuadPart < BYTES_PER_TB)
		nPrintMultiplier = BYTES_PER_GB;
	else
		nPrintMultiplier = BYTES_PER_TB;

	if (nPrintMultiplier == 1)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_BYTES";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_BYTES";
		else
			nResourceString = "DISK_FREE_BYTES";
	}
	else if (nPrintMultiplier == BYTES_PER_KB)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_KB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_KB";
		else
			nResourceString = "DISK_FREE_KB";
	}
	else if (nPrintMultiplier == BYTES_PER_MB)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_MB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_MB";
		else
			nResourceString = "DISK_FREE_MB";
	}
	else if (nPrintMultiplier == BYTES_PER_GB)
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_GB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_GB";
		else
			nResourceString = "DISK_FREE_GB";
	}
	else
	{
		if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
			nResourceString = "MAX_HIDVOL_SIZE_TB";
		else if (bDevice)
			nResourceString = "DEVICE_FREE_TB";
		else
			nResourceString = "DISK_FREE_TB";
	}

	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		StringCbPrintfW (szTmp2, sizeof szTmp2, GetString (nResourceString), ((double) lDiskFree->QuadPart) / nPrintMultiplier);
		SetWindowTextW (GetDlgItem (hwndTextBox, IDC_SIZEBOX), szTmp2);
	}
	else if (lpszDrive)
		StringCbPrintfW (szTmp2, sizeof szTmp2, GetString (nResourceString), lpszDrive, ((double) lDiskFree->QuadPart) / nPrintMultiplier);
	else
		szTmp2 [0] = 0;

	SetWindowTextW (hwndTextBox, szTmp2);

	if (lDiskFree->QuadPart % (__int64) BYTES_PER_MB != 0)
		nPrintMultiplier = BYTES_PER_KB;

	return nPrintMultiplier;
}

void DisplaySizingErrorText (HWND hwndTextBox)
{
	wchar_t szTmp[1024];

	if (translateWin32Error (szTmp, sizeof (szTmp) / sizeof(szTmp[0])))
	{
		wchar_t szTmp2[1024];
		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s\n%s", GetString ("CANNOT_CALC_SPACE"), szTmp);
		SetWindowTextW (hwndTextBox, szTmp2);
	}
	else
	{
		SetWindowText (hwndTextBox, L"");
	}
}

void EnableDisableFileNext (HWND hComboBox, HWND hMainButton)
{
	int nIndex = (int) SendMessage (hComboBox, CB_GETCURSEL, 0, 0);
	if (bHistory && nIndex == CB_ERR)
	{
		EnableWindow (hMainButton, FALSE);
		SetFocus (hComboBox);
	}
	else
	{
		EnableWindow (hMainButton, TRUE);
		SetFocus (hMainButton);
	}
}

// Returns TRUE if the file is a sparse file. If it's not a sparse file or in case of any error, returns FALSE.
BOOL IsSparseFile (HWND hwndDlg)
{
	HANDLE hFile;
	BY_HANDLE_FILE_INFORMATION bhFileInfo;

	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;

	BOOL retCode = FALSE;

	hFile = CreateFile (szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_VOL"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	if (bPreserveTimestamp)
	{
		ftLastAccessTime.dwHighDateTime = 0xFFFFFFFF;
		ftLastAccessTime.dwLowDateTime = 0xFFFFFFFF;

		SetFileTime (hFile, NULL, &ftLastAccessTime, NULL);

		if (GetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	bhFileInfo.dwFileAttributes = 0;

	GetFileInformationByHandle(hFile, &bhFileInfo);

	retCode = bhFileInfo.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE;

	if (bTimeStampValid)
		SetFileTime (hFile, NULL, &ftLastAccessTime, NULL);

	CloseHandle (hFile);
	return retCode;
}


// Note: GetFileVolSize is not to be used for devices (only for file-hosted volumes)
BOOL GetFileVolSize (HWND hwndDlg, unsigned __int64 *size)
{
	LARGE_INTEGER fileSize;
	HANDLE hFile;

	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;

	hFile = CreateFile (szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_VOL"), lpszTitle, ICON_HAND);
		return FALSE;
	}

	if (bPreserveTimestamp)
	{
		ftLastAccessTime.dwHighDateTime = 0xFFFFFFFF;
		ftLastAccessTime.dwLowDateTime = 0xFFFFFFFF;

		SetFileTime (hFile, NULL, &ftLastAccessTime, NULL);

		if (GetFileTime (hFile, NULL, &ftLastAccessTime, NULL) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	if (GetFileSizeEx(hFile, &fileSize) == 0)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_GET_VOLSIZE"), lpszTitle, ICON_HAND);

		if (bTimeStampValid)
			SetFileTime (hFile, NULL, &ftLastAccessTime, NULL);

		CloseHandle (hFile);
		return FALSE;
	}

	if (bTimeStampValid)
		SetFileTime (hFile, NULL, &ftLastAccessTime, NULL);

	CloseHandle (hFile);
	*size = fileSize.QuadPart;
	return TRUE;
}


BOOL QueryFreeSpace (HWND hwndDlg, HWND hwndTextBox, BOOL display, LONGLONG *pFreeSpaceValue, BOOL* pbIsSparceFilesSupported)
{
	if (pFreeSpaceValue)
		*pFreeSpaceValue = 0;

	if (pbIsSparceFilesSupported)
		*pbIsSparceFilesSupported = FALSE;

	if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
	{
		LARGE_INTEGER lDiskFree;

		lDiskFree.QuadPart = nMaximumHiddenVolSize;

		if (pFreeSpaceValue)
			*pFreeSpaceValue = nMaximumHiddenVolSize;

		if (display)
			PrintFreeSpace (hwndTextBox, NULL, &lDiskFree);

		return TRUE;
	}
	else if (bDevice == FALSE)
	{
		wchar_t root[TC_MAX_PATH];
		DWORD fileSystemFlags = 0;
		ULARGE_INTEGER free;

		if (!GetVolumePathName (szFileName, root, ARRAYSIZE (root)))
		{
			handleWin32Error (hwndDlg, SRC_POS);
			return FALSE;
		}

		if (	pbIsSparceFilesSupported
			&&	GetVolumeInformation (root, NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0)
			&&	(fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES)
			)
		{
			*pbIsSparceFilesSupported = TRUE;
		}

		if (!GetDiskFreeSpaceEx (root, &free, 0, 0))
		{
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}
		else
		{
			LARGE_INTEGER lDiskFree;
			// if the file pointed by szFileName already exists, we must add its size to the free space since it will be overwritten durig the volume creation
			__int64 lFileSize = GetFileSize64(szFileName);
			if (lFileSize != -1)
			{
				free.QuadPart += lFileSize;
			}

			lDiskFree.QuadPart = free.QuadPart;

			if (pFreeSpaceValue)
				*pFreeSpaceValue = free.QuadPart;

			if (display)
				PrintFreeSpace (hwndTextBox, root, &lDiskFree);

			return TRUE;
		}
	}
	else
	{
		DISK_GEOMETRY_EX driveInfo;
		PARTITION_INFORMATION diskInfo;
		BOOL piValid = FALSE;
		BOOL gValid = FALSE;

		// Query partition size
		piValid = GetPartitionInfo (szDiskFile, &diskInfo);
		gValid = GetDriveGeometry (szDiskFile, &driveInfo);

		if (!piValid && !gValid)
		{
			if (display)
				DisplaySizingErrorText (hwndTextBox);

			return FALSE;
		}

		DWORD sectorSize = GetFormatSectorSize();

		if (sectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| sectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| sectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			Error ("SECTOR_SIZE_UNSUPPORTED", hwndDlg);
			return FALSE;
		}

		if (piValid)
		{
			nVolumeSize = diskInfo.PartitionLength.QuadPart;

			if(display)
				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &diskInfo.PartitionLength);

			nUIVolumeSize = diskInfo.PartitionLength.QuadPart / nMultiplier;

			if (nVolumeSize == 0)
			{
				if (display)
					SetWindowTextW (hwndTextBox, GetString ("EXT_PARTITION"));

				return FALSE;
			}
		}
		else
		{
			LARGE_INTEGER lDiskFree;

			// Drive geometry info is used only when GetPartitionInfo() fails
			lDiskFree.QuadPart = driveInfo.DiskSize.QuadPart;

			nVolumeSize = lDiskFree.QuadPart;

			if (pFreeSpaceValue)
				*pFreeSpaceValue = lDiskFree.QuadPart;

			if (display)
				nMultiplier = PrintFreeSpace (hwndTextBox, szDiskFile, &lDiskFree);

			nUIVolumeSize = lDiskFree.QuadPart / nMultiplier;
		}

		return TRUE;
	}
}


static BOOL FinalPreTransformPrompts (void)
{
	int x;
	wchar_t szTmp[4096];
	int driveNo;
	WCHAR deviceName[MAX_PATH];

	StringCbCopyW (deviceName, sizeof(deviceName), szFileName);

	driveNo = GetDiskDeviceDriveLetter (deviceName);

	if (!bForceOperation && !(bHiddenVol && !bHiddenVolHost))	// Do not ask for permission to overwrite an existing volume if we're creating a hidden volume within it
	{
		wchar_t drive[128];
		wchar_t volumeLabel[128];
		wchar_t *type;
		BOOL bTmpIsPartition = FALSE;

		type = GetPathType (szFileName, !bInPlaceEncNonSys, &bTmpIsPartition);

		if (driveNo != -1)
		{
			if (!GetDriveLabel (driveNo, volumeLabel, sizeof (volumeLabel)))
				volumeLabel[0] = 0;

			StringCbPrintfW (drive, sizeof (drive), volumeLabel[0] ? L" (%hc: '%s')" : L" (%hc:%s)", 'A' + driveNo, volumeLabel[0] ? volumeLabel : L"");
		}
		else
		{
			drive[0] = 0;
			volumeLabel[0] = 0;
		}

		if (bHiddenOS && bHiddenVolHost)
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("OVERWRITEPROMPT_DEVICE_HIDDEN_OS_PARTITION"), szFileName, drive);
		else
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString (bInPlaceEncNonSys ? (bInPlaceDecNonSys ? "NONSYS_INPLACE_DEC_CONFIRM" : "NONSYS_INPLACE_ENC_CONFIRM") : "OVERWRITEPROMPT_DEVICE"), type, szFileName, drive);

		if (bInPlaceEncNonSys)
			x = AskWarnYesNoString (szTmp, MainDlg);
		else
			x = AskWarnNoYesString (szTmp, MainDlg);

		if (x != IDYES)
			return FALSE;


		if (driveNo != -1 && bTmpIsPartition && !bInPlaceEncNonSys)
		{
			float percentFreeSpace = 100.0;
			__int64 occupiedBytes = 0;

			// Do a second check. If we find that the partition contains more than 1GB of data or more than 12%
			// of its space is occupied, we will display an extra warning, however, this time it won't be a Yes/No
			// dialog box (because users often ignore such dialog boxes).

			if (GetStatsFreeSpaceOnPartition (szFileName, &percentFreeSpace, &occupiedBytes, TRUE) != -1)
			{
				if (occupiedBytes > BYTES_PER_GB && percentFreeSpace < 99.99	// "percentFreeSpace < 99.99" is needed because an NTFS filesystem larger than several terabytes can have more than 1GB of data in use, even if there are no files stored on it.
					|| percentFreeSpace < 88)		// A 24-MB NTFS filesystem has 11.5% of space in use even if there are no files stored on it.
				{
					wchar_t tmpMcMsg [8000];
					wchar_t tmpMcOption1 [500];
					wchar_t tmpMcOptionCancel [50];

					StringCbCopyW (tmpMcMsg, sizeof(tmpMcMsg), GetString("OVERWRITEPROMPT_DEVICE_SECOND_WARNING_LOTS_OF_DATA"));
					StringCbCopyW (tmpMcOption1, sizeof(tmpMcOption1), GetString("ERASE_FILES_BY_CREATING_VOLUME"));
					StringCbCopyW (tmpMcOptionCancel, sizeof(tmpMcOptionCancel), GetString("CANCEL"));

					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), L"\n\n");
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), GetString("DRIVE_LETTER_ITEM"));
					StringCbPrintfW (szTmp, sizeof (szTmp), L"%hc:", 'A' + driveNo);
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), szTmp);

					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), L"\n");
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), GetString("LABEL_ITEM"));
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), volumeLabel[0] != 0 ? volumeLabel : GetString("NOT_APPLICABLE_OR_NOT_AVAILABLE"));

					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), L"\n");
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), GetString("SIZE_ITEM"));
					GetSizeString (nVolumeSize, szTmp, sizeof(szTmp));
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), szTmp);

					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), L"\n");
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), GetString("PATH_ITEM"));
					StringCbCatW (tmpMcMsg, sizeof(tmpMcMsg), deviceName);

					wchar_t *tmpStr[] = {L"", tmpMcMsg, tmpMcOption1, tmpMcOptionCancel, 0};
					switch (AskMultiChoice ((void **) tmpStr, TRUE, MainDlg))
					{
					case 1:
						// Proceed

						// NOP
						break;

					default:
						return FALSE;
					}
				}
			}
		}
	}
	return TRUE;
}

void UpdateLastDialogId (void)
{
	static char PageDebugId[128];

	StringCbPrintfA (PageDebugId, sizeof(PageDebugId), "FORMAT_PAGE_%d", nCurPageNo);
	LastDialogId = PageDebugId;
}


void HandleOldAssignedDriveLetter (void)
{
	if (bDevice)
	{
		// Handle assigned drive letter (if any)

		WCHAR deviceName[MAX_PATH];
		int driveLetter = -1;

		StringCbCopyW (deviceName, sizeof(deviceName), szDiskFile);
		driveLetter = GetDiskDeviceDriveLetter (deviceName);

		if (!Silent && !bHiddenVolHost
			&& !bHiddenOS
			&& driveLetter >= 0)
		{
			wchar_t rootPath[] = { (wchar_t) (driveLetter + L'A'), L':', L'\\', 0 };
			wchar_t szTmp[8192];

			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("AFTER_FORMAT_DRIVE_LETTER_WARN"), rootPath[0], rootPath[0], rootPath[0], rootPath[0]);
			MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING);
		}
	}
}


// Returns TRUE if it makes sense to ask the user whether he wants to store files larger than 4GB in the volume.
static BOOL FileSize4GBLimitQuestionNeeded (void)
{
	uint64 dataAreaSize = GetVolumeDataAreaSize (bHiddenVol && !bHiddenVolHost, nVolumeSize);

	return (dataAreaSize > 4 * BYTES_PER_GB + TC_MIN_FAT_FS_SIZE
		&& dataAreaSize <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize());
}


void DisableIfGpt(HWND control)
{
   if (bSystemIsGPT) {
      EnableWindow(control, FALSE);
   }
}

static void UpdateClusterSizeList (HWND hwndDlg, int fsType)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_RESETCONTENT, 0, 0);
	AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), GetString ("DEFAULT"), 0);

	for (int i = 1; i <= 65536; i *= 2)
	{
		wstringstream s;
		DWORD size = GetFormatSectorSize() * i;

		/* cluster size makes sense only when there is a filesystem */
		if (fsType == FILESYS_NONE)
			break;

		/* FAT supports at maximum 64K when sector size is 512, and at maximum 256K when sector size is larger than 512 */
		/* For now we set maximum cluster size to 64K in all cases for compatibility with exiting FAT code in VeraCrypt */
		if ((fsType == FILESYS_FAT) && (size > 64*BYTES_PER_KB))
			break;

		/* ReFS supports only 4KiB and 64KiB clusters */
		if ((fsType == FILESYS_REFS) && (size != 4*BYTES_PER_KB) && (size != 64*BYTES_PER_KB))
			continue;

		/* NTFS supports at maximum 2M cluster */
		if ((fsType == FILESYS_NTFS) && (size > 2*BYTES_PER_MB))
			break;

		/* exFAT supports at maximum 32M cluster */
		if ((fsType == FILESYS_EXFAT) && (size > 32*BYTES_PER_MB))
			break;

		if (size == 512)
			s << L"0.5 " << GetString ("KB");
		else if (size < BYTES_PER_MB)
		{
			s << size / BYTES_PER_KB;
			s << L" " << GetString ("KB");
		}
		else
		{
			s << size / BYTES_PER_MB;
			s << L" " << GetString ("MB");
		}

		AddComboPair (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), s.str().c_str(), i);
	}

	SendMessage (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), CB_SETCURSEL, 0, 0);
}

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PageDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static BOOL PimValueChangedWarning = FALSE;

	hCurPage = hwndDlg;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		PimValueChangedWarning = FALSE;
		LocalizeDialog (hwndDlg, "IDD_VOL_CREATION_WIZARD_DLG");

		burn (randPool, sizeof(randPool));
		burn (lastRandPool, sizeof(lastRandPool));
		burn (maskRandPool, sizeof (maskRandPool));

		UpdateLastDialogId ();

		switch (nCurPageNo)
		{
		case INTRO_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_FILE_CONTAINER), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_NONSYS_DEVICE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_DEVICE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("INTRO_TITLE"));

			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_CONTAINERS);
			ToHyperlink (hwndDlg, IDC_MORE_INFO_ON_SYS_ENCRYPTION);

			EnableWindow (GetDlgItem (hwndDlg, IDC_STD_VOL), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDDEN_VOL), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			UpdateWizardModeControls (hwndDlg, WizardMode);
			break;

		case SYSENC_TYPE_PAGE:

			bHiddenVolHost = bHiddenVol = bHiddenOS;

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_TYPE_PAGE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_SYSENC_HIDDEN), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYSENC_NORMAL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			DisableIfGpt(GetDlgItem(hwndDlg, IDC_SYSENC_HIDDEN));

			CheckButton (GetDlgItem (hwndDlg, bHiddenOS ? IDC_SYSENC_HIDDEN : IDC_SYSENC_NORMAL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_TYPE_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP_SYSENC_NORMAL), GetString ("SYSENC_NORMAL_TYPE_HELP"));

			ToHyperlink (hwndDlg, IDC_HIDDEN_SYSENC_INFO_LINK);

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), !bDirectSysEncMode);

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			break;

		case SYSENC_HIDDEN_OS_REQ_CHECK_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_OS_REQ_CHECK_PAGE_HELP"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), bDirectSysEncModeCommand != SYSENC_COMMAND_CREATE_HIDDEN_OS && bDirectSysEncModeCommand != SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV);

			ToHyperlink (hwndDlg, IDC_HIDDEN_SYSENC_INFO_LINK);
			break;

		case SYSENC_SPAN_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_WHOLE_SYS_DRIVE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_PARTITION), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_SPAN_TITLE"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDT_WHOLE_SYS_DRIVE), GetString ("SYS_ENCRYPTION_SPAN_WHOLE_SYS_DRIVE_HELP"));

			CheckButton (GetDlgItem (hwndDlg, bWholeSysDrive ? IDC_WHOLE_SYS_DRIVE : IDC_SYS_PARTITION));
			DisableIfGpt(GetDlgItem(hwndDlg, IDC_WHOLE_SYS_DRIVE));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			break;


		case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:

			Init2RadButtonPageYesNo (SysEncDetectHiddenSectors);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_PRE_DRIVE_ANALYSIS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_PRE_DRIVE_ANALYSIS_HELP"));
			break;


		case SYSENC_DRIVE_ANALYSIS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_DRIVE_ANALYSIS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_SYSENC_DRIVE_ANALYSIS_INFO), GetString ("SYSENC_DRIVE_ANALYSIS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), FALSE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (MainDlg, IDCANCEL), FALSE);

			LoadSettings (hwndDlg);

			if (HiddenSectorDetectionStatus == 1)
			{
				// Detection of hidden sectors was already in progress but it did not finish successfully.
				// Ask the user if he wants to try again (to prevent repeated system freezing, etc.)

				char *tmpStr[] = {0, "HIDDEN_SECTOR_DETECTION_FAILED_PREVIOUSLY", "SKIP_HIDDEN_SECTOR_DETECTION", "RETRY_HIDDEN_SECTOR_DETECTION", "IDC_EXIT", 0};
				switch (AskMultiChoice ((void **) tmpStr, FALSE, MainDlg))
				{
				case 1:
					// Do not try again
					LoadPage (MainDlg, SYSENC_DRIVE_ANALYSIS_PAGE + 1);
					return 0;

				case 2:
					// Try again
					break;

				default:
					EndMainDlg (MainDlg);
					return 0;
				}
			}

			SetTimer (MainDlg, TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS, TIMER_INTERVAL_SYSENC_DRIVE_ANALYSIS_PROGRESS, NULL);
			bSysEncDriveAnalysisInProgress = TRUE;
			ArrowWaitCursor ();
			SysEncDriveAnalysisStart = GetTickCount ();
			InitProgressBar (SYSENC_DRIVE_ANALYSIS_ETA, 0, FALSE, FALSE, FALSE, TRUE);

			_beginthread (sysEncDriveAnalysisThread, 0, hwndDlg);

			break;


		case SYSENC_MULTI_BOOT_MODE_PAGE:

			SendMessage (GetDlgItem (hwndDlg, IDC_SINGLE_BOOT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_MULTI_BOOT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_MULTI_BOOT_MODE_TITLE"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

			RefreshMultiBootControls (hwndDlg);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), nMultiBoot > 0);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			break;


		case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.SystemOnBootDrive);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_SYS_EQ_BOOT_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_SYS_EQ_BOOT_HELP"));
			break;


		case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:

			SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE1), GetString ("DIGIT_ONE"));
			SetWindowTextW (GetDlgItem (hCurPage, IDC_CHOICE2), GetString ("TWO_OR_MORE"));

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));

			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), SysEncMultiBootCfg.NumberOfSysDrives > 0);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);

			if (SysEncMultiBootCfg.NumberOfSysDrives == 2)
				Update2RadButtonPage (0); // 2 or more drives contain an OS
			else if (SysEncMultiBootCfg.NumberOfSysDrives == 1)
				Update2RadButtonPage (1); // Only 1 drive contains an OS
			else
				Update2RadButtonPage (-1);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_HELP"));
			break;


		case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.MultipleSystemsOnDrive);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_ADJACENT_SYS_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_ADJACENT_SYS_HELP"));
			break;


		case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:

			Init2RadButtonPageYesNo (SysEncMultiBootCfg.BootLoaderBrand);
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_HELP"));
			break;


		case SYSENC_MULTI_BOOT_OUTCOME_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_MULTI_BOOT_OUTCOME_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), SysEncMultiBootCfgOutcome);
			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (MainDlg, IDC_PREV), TRUE);
			break;


		case VOLUME_TYPE_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("VOLUME_TYPE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_HIDDEN_VOL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_STD_VOL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bHiddenVol ? IDC_HIDDEN_VOL : IDC_STD_VOL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOLUME_TYPE_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP_NORMAL_VOL), GetString ("NORMAL_VOLUME_TYPE_HELP"));

			ToHyperlink (hwndDlg, IDC_HIDDEN_VOL_HELP);

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			SetWindowTextW (GetDlgItem (MainDlg, IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (MainDlg, IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
			break;

		case HIDDEN_VOL_WIZARD_MODE_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDDEN_VOL_WIZARD_MODE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_DIRECT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_FULL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			CheckButton (GetDlgItem (hwndDlg, bHiddenVolDirect ? IDC_HIDVOL_WIZ_MODE_DIRECT : IDC_HIDVOL_WIZ_MODE_FULL));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOL_WIZARD_MODE_NORMAL_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP2), GetString ("HIDDEN_VOL_WIZARD_MODE_DIRECT_HELP"));

			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_DIRECT), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HIDVOL_WIZ_MODE_FULL), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case VOLUME_LOCATION_PAGE:
			{
				char *nID;

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_SELECT_VOLUME_LOCATION),
					GetString (bDevice ? "IDC_SELECT_DEVICE" : "IDC_SELECT_FILE"));

				if (bHiddenVolDirect && bHiddenVolHost)
				{
					nID = "FILE_HELP_HIDDEN_HOST_VOL_DIRECT";
				}
				else
				{
					if (bDevice)
						nID = bHiddenVolHost ? "DEVICE_HELP_HIDDEN_HOST_VOL" : "DEVICE_HELP";
					else
						nID = bHiddenVolHost ? "FILE_HELP_HIDDEN_HOST_VOL" : "FILE_HELP";
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_LIMITTEXT, TC_MAX_PATH, 0);

				LoadCombo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), bHistory, FALSE, NULL);

				SendMessage (GetDlgItem (hwndDlg, IDC_NO_HISTORY), BM_SETCHECK, bHistory ? BST_UNCHECKED : BST_CHECKED, 0);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FILE_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (nID));

				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
				GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

			}
			break;

		case DEVICE_TRANSFORM_MODE_PAGE:

			if (!bDeviceTransformModeChoiceMade && !bInPlaceEncNonSys)
			{
				// The user has not chosen whether to perform in-place encryption or format yet.
				// We will preselect in-place encryption if the requirements are met and if the
				// filesystem does not appear empty.

				WaitCursor();

				if (CheckRequirementsForNonSysInPlaceEnc (hwndDlg, szDiskFile, TRUE))
				{
					bInPlaceEncNonSys = (FileSystemAppearsEmpty (szDiskFile) == 0);
				}
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("DEVICE_TRANSFORM_MODE_PAGE_TITLE"));

			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICE_TRANSFORM_MODE_INPLACE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_DEVICE_TRANSFORM_MODE_FORMAT), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("DEVICE_TRANSFORM_MODE_PAGE_FORMAT_HELP"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP2), GetString ("DEVICE_TRANSFORM_MODE_PAGE_INPLACE_HELP"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			CheckButton (GetDlgItem (hwndDlg, bInPlaceEncNonSys ? IDC_DEVICE_TRANSFORM_MODE_INPLACE : IDC_DEVICE_TRANSFORM_MODE_FORMAT));

			NormalCursor();

			break;

		case HIDDEN_VOL_HOST_PRE_CIPHER_PAGE:
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_HOST_PRE_CIPHER_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bHiddenOS ? "HIDVOL_HOST_PRE_CIPHER_HELP_SYSENC" : "HIDVOL_HOST_PRE_CIPHER_HELP"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				if (bHiddenOS)
				{
					if (!GetDevicePathForHiddenOS())
						AbortProcess ("INVALID_PATH");
				}
			}
			break;

		case HIDDEN_VOL_PRE_CIPHER_PAGE:
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_PRE_CIPHER_TITLE"));

				if (bHiddenOS)
				{
					// Verify whether the clone of the OS fits in the hidden volume (the hidden
					// volume is to host a hidden OS).
					if (nMaximumHiddenVolSize - TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH < GetSystemPartitionSize())
					{
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_VOLUME_TOO_SMALL_FOR_OS_CLONE"));

						SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("EXIT"));
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

						bConfirmQuit = FALSE;
						bConfirmQuitSysEncPretest = FALSE;
					}
					else
					{
						// The hidden volume must be as large as the system partition
						nVolumeSize = GetSystemPartitionSize() + TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH;

						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_OS_PRE_CIPHER_HELP"));
					}
				}
				else
				{
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDVOL_PRE_CIPHER_HELP"));
				}
			}
			break;

		case CIPHER_PAGE:
			{
				int ea, hid;
				wchar_t buf[100];

				// Encryption algorithms

				SendMessage (GetDlgItem (hwndDlg, IDC_COMBO_BOX), CB_RESETCONTENT, 0, 0);

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "CIPHER_HIDVOL_HOST_TITLE" : "CIPHER_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("CIPHER_TITLE"));

				for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
				{
					if (EAIsFormatEnabled (ea) && (!SysEncInEffect () || bSystemIsGPT || EAIsMbrSysEncEnabled (ea)))
						AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX), EAGetName (buf, ARRAYSIZE(buf),ea, 1), ea);
				}

				SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX), &nVolumeEA);
				ComboSelChangeEA (hwndDlg);
				SetFocus (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

				ToHyperlink (hwndDlg, IDC_LINK_MORE_INFO_ABOUT_CIPHER);

				// Hash algorithms

				if (SysEncInEffect ())
				{
					hash_algo = bSystemIsGPT? SHA512 : DEFAULT_HASH_ALGORITHM_BOOT;
					RandSetHashFunction (hash_algo);

					for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
					{
						if ((!HashIsDeprecated (hid)) && (bSystemIsGPT || HashForSystemEncryption (hid)))
							AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), HashGetName(hid), hid);
					}
				}
				else
				{
					hash_algo = RandGetHashFunction();
					for (hid = FIRST_PRF_ID; hid <= LAST_PRF_ID; hid++)
					{
						if (!HashIsDeprecated (hid))
							AddComboPair (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), HashGetName(hid), hid);
					}
				}

				SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), &hash_algo);

				ToHyperlink (hwndDlg, IDC_LINK_HASH_INFO);

				// Wizard buttons
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case SIZE_PAGE:
			{
				wchar_t str[1000];

				if (bHiddenVolHost)
				{
					StringCbCopyW (str, sizeof(str), GetString ("SIZE_HELP_HIDDEN_HOST_VOL"));
				}
				else
				{
					StringCbCopyW (str, sizeof(str), GetString (bHiddenVol ? "SIZE_HELP_HIDDEN_VOL" : "SIZE_HELP"));
				}

				if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					StringCbPrintfW (str, sizeof str, L"%s%s",
						GetString ((bHiddenOS && bHiddenVol) ? "SIZE_PARTITION_HIDDEN_SYSENC_HELP" : "SIZE_PARTITION_HELP"),
						 (bHiddenVolHost && !bHiddenOS) ? GetString ("SIZE_PARTITION_HIDDEN_VOL_HELP") : L"");
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_SPACE_LEFT), WM_SETFONT, (WPARAM) hBoldFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_SIZEBOX), EM_LIMITTEXT, 12, 0);

				if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), TRUE, &nAvailableFreeSpace, &bIsSparseFilesSupportedByHost))
				{
					nUIVolumeSize=0;
					nVolumeSize=0;
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_SIZEBOX), GetString ("UNKNOWN"));
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_GB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_TB), FALSE);
				}
				else if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_GB), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_TB), FALSE);
				}
				else
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_SIZEBOX), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_KB), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_MB), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_GB), TRUE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_TB), TRUE);
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_UNCHECKED, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_UNCHECKED, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_GB), BM_SETCHECK, BST_UNCHECKED, 0);
				SendMessage (GetDlgItem (hwndDlg, IDC_TB), BM_SETCHECK, BST_UNCHECKED, 0);

				switch (nMultiplier)
				{
				case BYTES_PER_KB:
					SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_CHECKED, 0);
					break;
				case BYTES_PER_MB:
					SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_CHECKED, 0);
					break;
				case BYTES_PER_GB:
					SendMessage (GetDlgItem (hwndDlg, IDC_GB), BM_SETCHECK, BST_CHECKED, 0);
					break;
				case BYTES_PER_TB:
					SendMessage (GetDlgItem (hwndDlg, IDC_TB), BM_SETCHECK, BST_CHECKED, 0);
					break;
				}

				if (nUIVolumeSize != 0)
				{
					wchar_t szTmp[32];
					StringCbPrintfW (szTmp, sizeof(szTmp), L"%I64u", nUIVolumeSize);
					SetWindowText (GetDlgItem (hwndDlg, IDC_SIZEBOX), szTmp);
				}

				SetFocus (GetDlgItem (hwndDlg, IDC_SIZEBOX));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), str);

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "SIZE_HIDVOL_HOST_TITLE" : "SIZE_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SIZE_TITLE"));


				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));


				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifySizeAndUpdate (hwndDlg, FALSE);
			}
			break;

		case HIDDEN_VOL_HOST_PASSWORD_PAGE:
		case NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE:
			{
				/* Populate the PRF algorithms list */
				int nIndex, i;
				HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
				SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

				nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

				for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
				{
					nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
					SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
				}

				/* make autodetection the default */
				SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

				hPasswordInputField = GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT);
				hVerifyPasswordInputField = NULL;
				ToNormalPwdField (hwndDlg, IDC_PASSWORD_DIRECT);

				SetPassword (hwndDlg, IDC_PASSWORD_DIRECT, szRawPassword);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD_DIRECT));

				SendMessage (GetDlgItem (hwndDlg, IDC_PIM), EM_LIMITTEXT, MAX_PIM, 0);
				SetPim (hwndDlg, IDC_PIM, volumePim);

				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_ENABLE), PimEnable? SW_HIDE : SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), PimEnable? SW_SHOW : SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), PimEnable? SW_SHOW : SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), PimEnable? SW_SHOW : SW_HIDE);

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bInPlaceEncNonSys ? (bInPlaceEncNonSysResumed ? "NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE_HELP" : "NONSYS_INPLACE_DEC_PASSWORD_PAGE_HELP") : "PASSWORD_HIDDENVOL_HOST_DIRECT_HELP"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bInPlaceEncNonSys ? "PASSWORD" : "PASSWORD_HIDVOL_HOST_TITLE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), !bInPlaceEncNonSys);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}

			break;

		case PASSWORD_PAGE:
			{
				wchar_t str[1000];

				hPasswordInputField = GetDlgItem (hwndDlg, IDC_PASSWORD);
				hVerifyPasswordInputField = GetDlgItem (hwndDlg, IDC_VERIFY);

				ToNormalPwdField (hwndDlg, IDC_PASSWORD);
				ToNormalPwdField (hwndDlg, IDC_VERIFY);

				if (SysEncInEffect ())
				{
					ToBootPwdField (hwndDlg, IDC_PASSWORD);
					ToBootPwdField (hwndDlg, IDC_VERIFY);

					if (!GetKeyboardLayoutNameW(OrigKeyboardLayout))
					{
						StringCbPrintfW(OrigKeyboardLayout, sizeof(OrigKeyboardLayout), L"%08X", (DWORD)(DWORD_PTR)GetKeyboardLayout(NULL) & 0xFFFF);
					}

					if ((DWORD)(DWORD_PTR)GetKeyboardLayout (NULL) != 0x00000409 && (DWORD)(DWORD_PTR)GetKeyboardLayout (NULL) != 0x04090409)
					{
						DWORD keybLayout = (DWORD)(DWORD_PTR)LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

						if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
						{
							Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", MainDlg);
							EndMainDlg (MainDlg);
							return 1;
						}
						bKeyboardLayoutChanged = TRUE;
					}


					if (SetTimer (MainDlg, TIMER_ID_KEYB_LAYOUT_GUARD, TIMER_INTERVAL_KEYB_LAYOUT_GUARD, NULL) == 0)
					{
						Error ("CANNOT_SET_TIMER", MainDlg);
						EndMainDlg (MainDlg);
						return 1;
					}
				}

				if (bHiddenVolHost)
				{
					StringCbCopyW (str, sizeof(str), GetString (bHiddenOS ? "PASSWORD_SYSENC_OUTERVOL_HELP" : "PASSWORD_HIDDENVOL_HOST_HELP"));
				}
				else if (bHiddenVol)
				{
					StringCbPrintfW (str, sizeof str, L"%s%s",
						GetString (bHiddenOS ? "PASSWORD_HIDDEN_OS_HELP" : "PASSWORD_HIDDENVOL_HELP"),
						GetString ("PASSWORD_HELP"));
				}
				else
				{
					StringCbCopyW (str, sizeof(str), GetString ("PASSWORD_HELP"));
				}

				SetPassword (hwndDlg, IDC_PASSWORD, szRawPassword);
				SetPassword (hwndDlg, IDC_VERIFY, szVerify);

				SetFocus (GetDlgItem (hwndDlg, IDC_PASSWORD));

				SetCheckBox (hwndDlg, IDC_PIM_ENABLE, PimEnable);

				SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable && !SysEncInEffect());
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable && !SysEncInEffect());
				EnableWindow (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE), !SysEncInEffect());

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), str);

				if (CreatingHiddenSysVol())
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD_HIDDEN_OS_TITLE"));
				else if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "PASSWORD_HIDVOL_HOST_TITLE" : "PASSWORD_HIDVOL_TITLE"));
				else if (WizardMode == WIZARD_MODE_SYS_DEVICE)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PASSWORD_TITLE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					 GetDlgItem (hwndDlg, IDC_PASSWORD),
					   GetDlgItem (hwndDlg, IDC_VERIFY),
						      NULL,
							  NULL,
							  KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());
				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);

			}
			break;

		case PIM_PAGE:
			{
				SendMessage (GetDlgItem (hwndDlg, IDC_PIM), EM_LIMITTEXT, SysEncInEffect()? MAX_BOOT_PIM: MAX_PIM, 0);
				if (volumePim > 0)
				{
					SetPim (hwndDlg, IDC_PIM, volumePim);

					PimValueChangedWarning = TRUE;
					SetDlgItemTextW (hwndDlg, IDC_PIM_HELP, GetString (SysEncInEffect ()? "PIM_SYSENC_CHANGE_WARNING" : "PIM_CHANGE_WARNING"));
				}

				SetFocus (GetDlgItem (hwndDlg, IDC_PIM));
                            #ifndef WOLFCRYPT_BACKEND
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (SysEncInEffect () && hash_algo != SHA512 && hash_algo != WHIRLPOOL? "PIM_SYSENC_HELP" : "PIM_HELP"));
                            #else
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (SysEncInEffect () && hash_algo != SHA512? "PIM_SYSENC_HELP" : "PIM_HELP"));
                            #endif
				ToHyperlink (hwndDlg, IDC_LINK_PIM_INFO);

				if (CreatingHiddenSysVol())
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PIM_HIDDEN_OS_TITLE"));
				else if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "PIM_HIDVOL_HOST_TITLE" : "PIM_HIDVOL_TITLE"));
				else if (WizardMode == WIZARD_MODE_SYS_DEVICE)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PIM"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("PIM_TITLE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case FILESYS_PAGE:
			{
				wchar_t szTmp[8192];

				Init2RadButtonPageYesNo (nNeedToStoreFilesOver4GB);
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FILESYS_PAGE_TITLE"));

				StringCbCopyW (szTmp, sizeof(szTmp), GetString ("FILESYS_PAGE_HELP_QUESTION"));

				if (bHiddenVolHost)
					StringCbCatW (szTmp, sizeof(szTmp), L"\n\n");
				else
				{
					StringCbCatW (szTmp, sizeof(szTmp), L"\n\n\n");
					StringCbCatW (szTmp, sizeof(szTmp), GetString ("NOTE_BEGINNING"));
				}

				StringCbCatW (szTmp, sizeof(szTmp), GetString ("FILESYS_PAGE_HELP_EXPLANATION"));

				if (bHiddenVolHost)
				{
					StringCbCatW (szTmp, sizeof(szTmp), L" ");
					StringCbCatW (szTmp, sizeof(szTmp), GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL"));
				}

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), szTmp);
			}
			break;

		case SYSENC_COLLECTING_RANDOM_DATA_PAGE:
		case NONSYS_INPLACE_ENC_RAND_DATA_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("COLLECTING_RANDOM_DATA_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			mouseEntropyGathered = 0xFFFFFFFF;
			mouseEventsInitialCount = 0;
			bUseMask = FALSE;
			{
				HCRYPTPROV hRngProv;
				if (CryptAcquireContext (&hRngProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
				{
					if (CryptGenRandom (hRngProv, sizeof (maskRandPool), maskRandPool))
						bUseMask = TRUE;
					CryptReleaseContext (hRngProv, 0);
				}
			}

			SetTimer (GetParent (hwndDlg), TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

			hRandPoolSys = GetDlgItem (hwndDlg, IDC_SYS_POOL_CONTENTS);
			hEntropyBar = GetDlgItem (hwndDlg, IDC_ENTROPY_BAR);
			SendMessage (hEntropyBar, PBM_SETRANGE32, 0, maxEntropyLevel);
			SendMessage (hEntropyBar, PBM_SETSTEP, 1, 0);

			SendMessage (GetDlgItem (hwndDlg, IDC_SYS_POOL_CONTENTS), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISPLAY_POOL_CONTENTS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);

			DisplayRandPool (hwndDlg, hRandPoolSys, showKeys);

			break;

		case SYSENC_KEYS_GEN_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("KEYS_GEN_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			hMasterKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
			hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
			SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

			SendMessage (GetDlgItem (hwndDlg, IDC_DISPLAY_KEYS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);

			DisplayPortionsOfKeys (hHeaderKey, hMasterKey, HeaderKeyGUIView, MasterKeyGUIView, !showKeys);

			break;

		case SYSENC_RESCUE_DISK_CREATION_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("RESCUE_DISK"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_RESCUE_DISK_INFO), bSystemIsGPT? GetString ("RESCUE_DISK_EFI_INFO"): GetString ("RESCUE_DISK_INFO"));
			SetCheckBox (hwndDlg, IDC_SKIP_RESCUE_VERIFICATION, bDontVerifyRescueDisk);
			SetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case SYSENC_RESCUE_DISK_BURN_PAGE:
			{
				wchar_t szTmp[8192];

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bDontVerifyRescueDisk ? "RESCUE_DISK_CREATED_TITLE" : "RESCUE_DISK_RECORDING_TITLE"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				if (bSystemIsGPT)
				{
					StringCbPrintfW (szTmp, sizeof szTmp,
						GetString (bDontVerifyRescueDisk ? "RESCUE_DISK_EFI_EXTRACT_INFO_NO_CHECK" : "RESCUE_DISK_EFI_EXTRACT_INFO"),
						szRescueDiskISO, GetString ("RESCUE_DISK_EFI_EXTRACT_INFO_NOTE"));
				}
				else
				{
					StringCbPrintfW (szTmp, sizeof szTmp,
						GetString (bDontVerifyRescueDisk ? "RESCUE_DISK_BURN_INFO_NO_CHECK" : "RESCUE_DISK_BURN_INFO"),
						szRescueDiskISO, IsWindowsIsoBurnerAvailable() ? L"" : GetString ("RESCUE_DISK_BURN_INFO_NONWIN_ISO_BURNER"));

				}
				SetWindowTextW (GetDlgItem (hwndDlg, IDT_RESCUE_DISK_BURN_INFO), szTmp);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				/* The 'Back' button must be disabled now because the user could burn a Rescue Disk, then go back, and
				generate a different master key, which would cause the Rescue Disk verification to fail (the result
				would be confusion and bug reports). */
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

				if (bSystemIsGPT)
				{
					ShowWindow (GetDlgItem (hwndDlg, IDC_DOWNLOAD_CD_BURN_SOFTWARE), SW_HIDE);
				}
				else
				{
					if (IsWindowsIsoBurnerAvailable())
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_DOWNLOAD_CD_BURN_SOFTWARE), GetString ("LAUNCH_WIN_ISOBURN"));

					ToHyperlink (hwndDlg, IDC_DOWNLOAD_CD_BURN_SOFTWARE);

					if (IsWindowsIsoBurnerAvailable() && !bDontVerifyRescueDisk)
						LaunchWindowsIsoBurner (hwndDlg, szRescueDiskISO);
				}
			}			
			break;

		case SYSENC_RESCUE_DISK_VERIFIED_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("RESCUE_DISK_DISK_VERIFIED_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("RESCUE_DISK_VERIFIED_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			// Rescue Disk has been verified, no need to go back
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);

			// Prevent losing the burned rescue disk by inadvertent exit
			bConfirmQuit = TRUE;

			break;

		case SYSENC_WIPE_MODE_PAGE:
		case NONSYS_INPLACE_ENC_WIPE_MODE_PAGE:
			{
				if (nWipeMode == TC_WIPE_1_RAND)
					nWipeMode = TC_WIPE_NONE;

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("WIPE_MODE_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDT_WIPE_MODE_INFO), GetString ("INPLACE_ENC_WIPE_MODE_INFO"));

				PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE),
					SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING && !bInPlaceEncNonSys,
					TRUE,
					FALSE);

				SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			}
			break;

		case SYSENC_PRETEST_INFO_PAGE:

			if (bHiddenOS)
			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDDEN_OS_CREATION_PREINFO_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("HIDDEN_OS_CREATION_PREINFO_HELP"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("START"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			}
			else
			{
				wchar_t finalMsg[8024] = {0};

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_PRETEST_TITLE"));

				try
				{
					StringCbPrintfW (finalMsg, sizeof(finalMsg),
						GetString ("SYS_ENCRYPTION_PRETEST_INFO"),
						BootEncObj->GetSystemDriveConfiguration().DriveNumber);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					EndMainDlg (MainDlg);
					return 0;
				}

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), finalMsg);
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("TEST"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			break;

		case SYSENC_PRETEST_RESULT_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYS_ENCRYPTION_PRETEST_RESULT_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYS_ENCRYPTION_PRETEST_RESULT_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("ENCRYPT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("DEFER"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			break;

		case SYSENC_ENCRYPTION_PAGE:

			if (CreateSysEncMutex ())
			{
				try
				{
					BootEncStatus = BootEncObj->GetStatus();
					bSystemEncryptionInProgress = BootEncStatus.SetupInProgress;
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
					EndMainDlg (MainDlg);
					return 0;
				}

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE),
					GetString (SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING ? "ENCRYPTION" : "DECRYPTION"));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_ENCRYPTION_PAGE_INFO"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("DEFER"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
					GetString (SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING ? "ENCRYPT" : "DECRYPT"));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_PAUSE),
					GetString (bSystemEncryptionInProgress ? "IDC_PAUSE" : "RESUME"));

				EnableWindow (GetDlgItem (hwndDlg, IDC_PAUSE), BootEncStatus.DriveEncrypted);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), !BootEncStatus.SetupInProgress);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);

				ToHyperlink (hwndDlg, IDC_MORE_INFO_SYS_ENCRYPTION);

				if (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING)
				{
					nWipeMode = TC_WIPE_NONE;
					EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDT_WIPE_MODE), FALSE);
					PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), TRUE, TRUE, FALSE);
					SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);
				}
				else
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_MODE), !bSystemEncryptionInProgress);
					PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE, TRUE, FALSE);
					SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);
				}

				PostMessage (hwndDlg, TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS, 0, 0);
			}
			else
			{
				Error ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", MainDlg);
				EndMainDlg (MainDlg);
				return 0;
			}
			return 0;

		case NONSYS_INPLACE_ENC_RESUME_PARTITION_SEL_PAGE:

			{
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FILE_TITLE"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("NONSYS_INPLACE_ENC_RESUME_VOL_SELECT_HELP"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);

				foreach (const HostDevice &device, DeferredNonSysInPlaceEncDevices)
				{
					SendMessage (GetDlgItem (hwndDlg, IDC_LIST_BOX), LB_ADDSTRING, 0, (LPARAM) device.Path.c_str());
				}

				// Deselect all
				SendMessage (GetDlgItem (hwndDlg, IDC_LIST_BOX), LB_SETCURSEL, (WPARAM) -1, 0);
			}

			break;

		case NONSYS_INPLACE_ENC_TRANSFORM_PAGE:

			if (bInPlaceEncNonSysResumed)
			{
				WipeAlgorithmId savedWipeAlgorithm = TC_WIPE_NONE;

				if (LoadNonSysInPlaceEncSettings (&savedWipeAlgorithm) != 0)
					nWipeMode = savedWipeAlgorithm;
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bInPlaceDecNonSys ? "DECRYPTION" : "ENCRYPTION"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bInPlaceDecNonSys ? "NONSYS_INPLACE_DEC_DECRYPTION_PAGE_INFO" : "NONSYS_INPLACE_ENC_ENCRYPTION_PAGE_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString (bInPlaceEncNonSysResumed ? "DEFER" : "CANCEL"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString (bInPlaceEncNonSysResumed ? "RESUME" : (bInPlaceDecNonSys ? "DECRYPT" : "ENCRYPT")));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_PAUSE), GetString ("IDC_PAUSE"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), !bInPlaceEncNonSysResumed && !bInPlaceDecNonSys);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PAUSE), FALSE);

			ShowWindow (GetDlgItem (hwndDlg, IDC_MORE_INFO_SYS_ENCRYPTION), SW_HIDE);

			if (bInPlaceDecNonSys)
			{
				ShowWindow(GetDlgItem(hwndDlg, IDT_FORMAT_OPTIONS), SW_HIDE);
				ShowWindow(GetDlgItem(hwndDlg, IDT_WIPE_MODE), SW_HIDE);
				ShowWindow(GetDlgItem(hwndDlg, IDC_WIPE_MODE), SW_HIDE);
			}
			else
			{
				EnableWindow (GetDlgItem (hwndDlg, IDC_WIPE_MODE), TRUE);
				PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE, TRUE, FALSE);
				SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);
			}

			break;

		case NONSYS_INPLACE_ENC_TRANSFORM_FINISHED_PAGE:

			bConfirmQuit = FALSE;

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bInPlaceDecNonSys ? "NONSYS_INPLACE_DEC_FINISHED_TITLE" : "NONSYS_INPLACE_ENC_FINISHED_TITLE"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bInPlaceDecNonSys ? "NONSYS_INPLACE_DEC_FINISHED_INFO" : "NONSYS_INPLACE_ENC_FINISHED_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("FINALIZE"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("EXIT"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);

			break;

		case NONSYS_INPLACE_DEC_TRANSFORM_FINISHED_DRIVE_LETTER_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("NONSYS_INPLACE_DEC_FINISHED_TITLE"));

			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("NONSYS_INPLACE_DEC_FINISHED_DRIVE_LETTER_SEL_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("FINALIZE"));
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

			// The Cancel button and the X button must be disabled to prevent the user from forgetting to assign a drive letter to the partition by closing
			// the window accidentally or clicking Cancel. The user is forced to click Finish to assign at least the pre-selected free drive letter.
			// This is critical because inexperienced users would not know how to access data on the decrypted volume without a drive letter.
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);
			DisableCloseButton (MainDlg);
			bConfirmQuit = TRUE;	// Alt-F4 will still work but the user will be prompted to confirm the action.

			// Decryption of non-system volume finished, no drive letter is assigned to the decrypted volume, and free drive letters are available.
			// This is critical because inexperienced users would not know how to access data on the decrypted volume. We cannot allow exit
			// until a drive letter is freed up and assigned to the decrypted volume.

			while (GetFirstAvailableDrive () == -1)
			{
				Error ("NONSYS_INPLACE_DEC_FINISHED_NO_DRIVE_LETTER_AVAILABLE", hwndDlg);
			}

			// Populate the combobox with free drive letters
			{
				DWORD dwUsedDrives = GetUsedLogicalDrives();
				wchar_t szDriveLetter[] = {L' ', L':', 0 };
				int i;

				for (i = 0; i < 26; i++)
				{
					if (!(dwUsedDrives & 1 << i))
					{
						// Add
						szDriveLetter [0] = (wchar_t) (i + L'A');
						AddComboPair (GetDlgItem (hCurPage, IDC_DRIVE_LETTER_LIST), szDriveLetter, i);
					}
				}
			}
			SendMessage (GetDlgItem (hwndDlg, IDC_DRIVE_LETTER_LIST), CB_SETCURSEL, 0, 0);
			break;

		case FORMAT_PAGE:
			{
				BOOL bNTFSallowed = FALSE;
				BOOL bFATallowed = FALSE;
				BOOL bEXFATallowed = FALSE;
				BOOL bReFSallowed = FALSE;
				BOOL bNoFSallowed = FALSE;
				HCRYPTPROV hRngProv;

				mouseEntropyGathered = 0xFFFFFFFF;
				mouseEventsInitialCount = 0;
				bUseMask = FALSE;
				if (CryptAcquireContext (&hRngProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
				{
					if (CryptGenRandom (hRngProv, sizeof (maskRandPool), maskRandPool))
						bUseMask = TRUE;
					CryptReleaseContext (hRngProv, 0);
				}

				SetTimer (GetParent (hwndDlg), TIMER_ID_RANDVIEW, TIMER_INTERVAL_RANDVIEW, NULL);

				hMasterKey = GetDlgItem (hwndDlg, IDC_DISK_KEY);
				hHeaderKey = GetDlgItem (hwndDlg, IDC_HEADER_KEY);
				hRandPool = GetDlgItem (hwndDlg, IDC_RANDOM_BYTES);
				hEntropyBar = GetDlgItem (hwndDlg, IDC_ENTROPY_BAR);
				SendMessage (hEntropyBar, PBM_SETRANGE32, 0, maxEntropyLevel);
				SendMessage (hEntropyBar, PBM_SETSTEP, 1, 0);

				SendMessage (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_DISK_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_HEADER_KEY), WM_SETFONT, (WPARAM) hFixedDigitFont, (LPARAM) TRUE);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP),
					GetString (bHiddenVolHost ? "FORMAT_HIDVOL_HOST_HELP" : "FORMAT_HELP"));

				if (bHiddenVol)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVolHost ? "FORMAT_HIDVOL_HOST_TITLE" : "FORMAT_HIDVOL_TITLE"));
				else
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("FORMAT_TITLE"));

				/* Fill the format type combobox */
				SendMessage (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), CB_RESETCONTENT, 0, 0);
				EnableWindow (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), TRUE);

				AddComboPair (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), GetString("FULL_FORMAT"), FORMAT_TYPE_FULL);
				AddComboPair (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), GetString("IDC_QUICKFORMAT"), FORMAT_TYPE_QUICK);
				if (!bDevice) // Fast Create only makes sens for file containers
					AddComboPair (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), GetString("FAST_CREATE"), FORMAT_TYPE_FAST);
				SendMessage (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), CB_SETCURSEL, 0, 0);

				formatType = FORMAT_TYPE_FULL;

				/* Quick/Dynamic */

				if (bHiddenVol)
				{
					quickFormat = !bHiddenVolHost;
					dynamicFormat = FALSE;
					bSparseFileSwitch = FALSE;

					SetCheckBox (hwndDlg, SPARSE_FILE, FALSE);
					EnableWindow (GetDlgItem (hwndDlg, SPARSE_FILE), FALSE);

					if (quickFormat)
					{
						formatType = FORMAT_TYPE_QUICK;
						SelectAlgo (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE),  (int *) &formatType);
					}
					else if (!bDevice && fastCreateFile)
					{
						formatType = FORMAT_TYPE_FAST;
						quickFormat = TRUE;
						SelectAlgo (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE),  (int *) &formatType);
					}
					EnableWindow (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), bHiddenVolHost);
				}
				else
				{
					if (bDevice)
					{
						dynamicFormat = FALSE;
						bSparseFileSwitch = FALSE;
						SetCheckBox (hwndDlg, SPARSE_FILE, FALSE);
						EnableWindow (GetDlgItem (hwndDlg, SPARSE_FILE), FALSE);
						EnableWindow (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), TRUE);
					}
					else
					{
						wchar_t root[TC_MAX_PATH];
						DWORD fileSystemFlags = 0;

						/* Check if the host file system supports sparse files */

						if (GetVolumePathName (szFileName, root, array_capacity (root)))
						{
							GetVolumeInformation (root, NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0);
							bSparseFileSwitch = fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES;
						}
						else
							bSparseFileSwitch = FALSE;
						if (!bSparseFileSwitch)
						{
							dynamicFormat = FALSE;
							SetCheckBox (hwndDlg, SPARSE_FILE, FALSE);
						}

						if (fastCreateFile)
						{
							formatType = FORMAT_TYPE_FAST;
							quickFormat = TRUE;
							SelectAlgo (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE),  (int *) &formatType);
						}
						EnableWindow (GetDlgItem (hwndDlg, SPARSE_FILE), bSparseFileSwitch);
						EnableWindow (GetDlgItem (hwndDlg, IDC_FORMAT_TYPE), TRUE);
					}
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_SHOW_KEYS), BM_SETCHECK, showKeys ? BST_CHECKED : BST_UNCHECKED, 0);
				SetWindowText (GetDlgItem (hwndDlg, IDC_RANDOM_BYTES), showKeys ? L"" : L"********************************                                              ");
				SetWindowText (GetDlgItem (hwndDlg, IDC_HEADER_KEY), showKeys ? L"" : L"********************************                                              ");
				SetWindowText (GetDlgItem (hwndDlg, IDC_DISK_KEY), showKeys ? L"" : L"********************************                                              ");

				EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), TRUE);

				/* Filesystems */

				bNTFSallowed = FALSE;
				bFATallowed = FALSE;
				bNoFSallowed = FALSE;

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_RESETCONTENT, 0, 0);

				EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), TRUE);

				uint64 dataAreaSize = GetVolumeDataAreaSize (bHiddenVol && !bHiddenVolHost, nVolumeSize);

				if (!CreatingHiddenSysVol())
				{
					if (dataAreaSize >= TC_MIN_NTFS_FS_SIZE && dataAreaSize <= TC_MAX_NTFS_FS_SIZE)
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), L"NTFS", FILESYS_NTFS);
						bNTFSallowed = TRUE;
					}

					if (dataAreaSize >= TC_MIN_FAT_FS_SIZE && dataAreaSize <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize())
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), L"FAT", FILESYS_FAT);
						bFATallowed = TRUE;
					}

					//exFAT support added starting from Vista SP1
					if (dataAreaSize >= TC_MIN_EXFAT_FS_SIZE && dataAreaSize <= TC_MAX_EXFAT_FS_SIZE)
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), L"exFAT", FILESYS_EXFAT);
						bEXFATallowed = TRUE;
					}

					//ReFS write support activated by default starting from Windows 10
					//We don't support it yet for the creation of hidden volumes
					if ((!bHiddenVolHost) && IsOSVersionAtLeast (WIN_10, 0) && dataAreaSize >= TC_MIN_REFS_FS_SIZE && dataAreaSize <= TC_MAX_REFS_FS_SIZE)
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), L"ReFS", FILESYS_REFS);
						bReFSallowed = TRUE;
					}
				}
				else
				{
					// We're creating a hidden volume for a hidden OS, so we don't need to format it with
					// any filesystem (the entire OS will be copied to the hidden volume sector by sector).
					EnableWindow (GetDlgItem (hwndDlg, IDC_FILESYS), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_CLUSTERSIZE), FALSE);
				}

				if (!bHiddenVolHost)
				{
					AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), GetString ("NONE"), FILESYS_NONE);
					bNoFSallowed = TRUE;
				}

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

				if (fileSystem == FILESYS_NONE)	// If no file system has been previously selected
				{
					// Set default file system

					if (bFATallowed && !(nNeedToStoreFilesOver4GB == 1 && (bNTFSallowed || bEXFATallowed || bReFSallowed)))
						fileSystem = FILESYS_FAT;
					else if (bEXFATallowed)
						fileSystem = FILESYS_EXFAT;
					else if (bNTFSallowed)
						fileSystem = FILESYS_NTFS;
					else if (bReFSallowed)
						fileSystem = FILESYS_REFS;
					else if (bNoFSallowed)
						fileSystem = FILESYS_NONE;
					else
					{
						AddComboPair (GetDlgItem (hwndDlg, IDC_FILESYS), L"---", 0);
						EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
					}
				}

				SendMessage (GetDlgItem (hwndDlg, IDC_FILESYS), CB_SETCURSEL, 0, 0);
				SelectAlgo (GetDlgItem (hwndDlg, IDC_FILESYS), (int *) &fileSystem);

				UpdateClusterSizeList (hwndDlg, fileSystem);

				EnableWindow (GetDlgItem (hwndDlg, IDC_ABORT_BUTTON), FALSE);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("FORMAT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

				SetFocus (GetDlgItem (GetParent (hwndDlg), IDC_NEXT));
			}
			break;

		case FORMAT_FINISHED_PAGE:
			{
				if (!bHiddenVolHost && bHiddenVol && !bHiddenVolFinished)
				{
					wchar_t msg[4096];

					nNeedToStoreFilesOver4GB = -1;

					if (bHiddenOS)
					{
						wchar_t szMaxRecomOuterVolFillSize[100];

						__int64 maxRecomOuterVolFillSize = 0;

						// Determine the maximum recommended total size of files that can be copied to the outer volume
						// while leaving enough space for the hidden volume, which must contain a clone of the OS

						maxRecomOuterVolFillSize = nVolumeSize - GetSystemPartitionSize();

						// -50% reserve for filesystem "peculiarities"
						maxRecomOuterVolFillSize /= 2;

						StringCbPrintfW (szMaxRecomOuterVolFillSize, sizeof(szMaxRecomOuterVolFillSize), L"%I64d %s", maxRecomOuterVolFillSize / BYTES_PER_MB, GetString ("MB"));

						StringCbPrintfW (msg, sizeof(msg), GetString ("HIDVOL_HOST_FILLING_HELP_SYSENC"), hiddenVolHostDriveNo + 'A', szMaxRecomOuterVolFillSize);
					}
					else
						StringCbPrintfW (msg, sizeof(msg), GetString ("HIDVOL_HOST_FILLING_HELP"), hiddenVolHostDriveNo + 'A');

					SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), msg);
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("HIDVOL_HOST_FILLING_TITLE"));
				}
				else
				{
					if (bHiddenOS)
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_VOL_FORMAT_FINISHED_HELP"));
					else
					{
						SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString (bInPlaceEncNonSys ? "NONSYS_INPLACE_ENC_FINISHED_INFO" : "FORMAT_FINISHED_HELP"));
						bConfirmQuit = FALSE;
					}

					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bHiddenVol ? "HIDVOL_FORMAT_FINISHED_TITLE" : "FORMAT_FINISHED_TITLE"));
				}


				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), (!bHiddenVol || bHiddenVolFinished) && !bHiddenOS && !bInPlaceEncNonSys);

				if ((!bHiddenVol || bHiddenVolFinished) && !bHiddenOS)
					SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("EXIT"));
			}
			break;

		case SYSENC_HIDDEN_OS_INITIAL_INFO_PAGE:

			if (!IsHiddenOSRunning() || !bHiddenOS)
			{
				ReportUnexpectedState (SRC_POS);
				EndMainDlg (MainDlg);
				return 0;
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_HIDDEN_OS_INITIAL_INFO_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("FIRST_HIDDEN_OS_BOOT_INFO"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("DEFER"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			break;

		case SYSENC_HIDDEN_OS_WIPE_INFO_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SYSENC_HIDDEN_OS_WIPE_INFO_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SYSENC_HIDDEN_OS_WIPE_INFO"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;

		case DEVICE_WIPE_MODE_PAGE:

			if (nWipeMode == TC_WIPE_NONE)
				nWipeMode = TC_WIPE_1_RAND;

			if (bHiddenOS && IsHiddenOSRunning())
			{
				// Decoy system partition wipe

				WipeAbort(); // In case the GUI previously crashed and the driver is still wiping
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
			}
			else
			{
				// Regular device wipe (not decoy system partition wipe)

				// Title bar
				SetWindowText (MainDlg, _T(TC_APP_NAME));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("WIPE_MODE_TITLE"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDT_WIPE_MODE_INFO), GetString ("WIPE_MODE_INFO"));

			PopulateWipeModeCombo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), FALSE, FALSE, TRUE);

			SelectAlgo (GetDlgItem (hwndDlg, IDC_WIPE_MODE), (int *) &nWipeMode);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			break;

		case DEVICE_WIPE_PAGE:

			if (bHiddenOS && IsHiddenOSRunning())
			{
				// Decoy system partition wipe

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("DEVICE_WIPE_PAGE_INFO_HIDDEN_OS"));
			}
			else
			{
				// Regular device wipe (not decoy system partition wipe)

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("DEVICE_WIPE_PAGE_INFO"));
			}

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("DEVICE_WIPE_PAGE_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("WIPE"));
			SetWindowTextW (GetDlgItem (hCurPage, IDC_WIPE_MODE), (wstring (L"  ") + GetWipeModeName (nWipeMode)).c_str());

			EnableWindow (GetDlgItem (hwndDlg, IDC_ABORT_BUTTON), FALSE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);

			break;
		}
		return 0;

	case WM_HELP:
		OpenPageHelp (GetParent (hwndDlg), nCurPageNo);
		return 1;

	case TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS:
		AfterSysEncProgressWMInitTasks (hwndDlg);
		return 1;

	case WM_CTLCOLORSTATIC:
		{
			if (PimValueChangedWarning && ((HWND)lParam == GetDlgItem(hwndDlg, IDC_PIM_HELP)) )
			{
				// we're about to draw the static
				// set the text colour in (HDC)lParam
				SetBkMode((HDC)wParam,TRANSPARENT);
				SetTextColor((HDC)wParam, RGB(255,0,0));
				// NOTE: per documentation as pointed out by selbie, GetSolidBrush would leak a GDI handle.
				return (BOOL) (INT_PTR)GetSysColorBrush(COLOR_MENU);
			}
		}
		return 0;

	case WM_COMMAND:

		if (nCurPageNo == INTRO_PAGE)
		{
			switch (lw)
			{
			case IDC_FILE_CONTAINER:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_FILE_CONTAINER);
				return 1;

			case IDC_NONSYS_DEVICE:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_NONSYS_DEVICE);
				return 1;

			case IDC_SYS_DEVICE:
				UpdateWizardModeControls (hwndDlg, WIZARD_MODE_SYS_DEVICE);
				return 1;

			case IDC_MORE_INFO_ON_CONTAINERS:
				Applink ("introcontainer");
				return 1;

			case IDC_MORE_INFO_ON_SYS_ENCRYPTION:
				Applink ("introsysenc");
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_TYPE_PAGE)
		{
			switch (lw)
			{
			case IDC_SYSENC_HIDDEN:
				bHiddenOS = TRUE;
				bHiddenVol = TRUE;
				bHiddenVolHost = TRUE;
				return 1;

			case IDC_SYSENC_NORMAL:
				bHiddenOS = FALSE;
				bHiddenVol = FALSE;
				bHiddenVolHost = FALSE;
				return 1;

			case IDC_HIDDEN_SYSENC_INFO_LINK:
				Applink ("hiddensysenc");
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_HIDDEN_OS_REQ_CHECK_PAGE && lw == IDC_HIDDEN_SYSENC_INFO_LINK)
		{
			Applink ("hiddensysenc");
			return 1;
		}

		if (nCurPageNo == SYSENC_SPAN_PAGE)
		{
			switch (lw)
			{
			case IDC_WHOLE_SYS_DRIVE:
				bWholeSysDrive = TRUE;
				return 1;
			case IDC_SYS_PARTITION:
				bWholeSysDrive = FALSE;
				return 1;
			}

		}

		if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
		{
			switch (lw)
			{
			case IDC_SINGLE_BOOT:
				nMultiBoot = 1;
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			case IDC_MULTI_BOOT:
				nMultiBoot = 2;
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			}
		}

		// Dual choice pages
		switch (nCurPageNo)
		{
		case SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE:
		case SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE:
		case SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE:
		case SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE:
		case SYSENC_PRE_DRIVE_ANALYSIS_PAGE:

			if (lw == IDC_CHOICE1 || lw == IDC_CHOICE2)
			{
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				return 1;
			}
			break;
		}

		if (nCurPageNo == FILESYS_PAGE && (lw == IDC_CHOICE1 || lw == IDC_CHOICE2))
		{
			if (bWarnOuterVolSuitableFileSys && lw == IDC_CHOICE1 && bHiddenVolHost)
			{
				wchar_t szTmp [4096];

				bWarnOuterVolSuitableFileSys = FALSE;	// Do not show this warning anymore (this also prevents potential endless repetition due to some race conditions)

				StringCbCopyW (szTmp, sizeof(szTmp), GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL"));
				StringCbCatW (szTmp, sizeof(szTmp), L"\n\n");
				StringCbCatW (szTmp, sizeof(szTmp), GetString ("FILESYS_PAGE_HELP_EXPLANATION_HIDVOL_CONFIRM"));

				if (MessageBoxW (MainDlg, szTmp, lpszTitle, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDNO)
				{
					nNeedToStoreFilesOver4GB = 0;
					Init2RadButtonPageYesNo (nNeedToStoreFilesOver4GB);
				}
			}

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			return 1;
		}

		if (lw == IDC_HIDDEN_VOL && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			bHiddenVol = TRUE;
			bHiddenVolHost = TRUE;
			bInPlaceEncNonSys = FALSE;
			return 1;
		}

		if (lw == IDC_STD_VOL && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			bHiddenVol = FALSE;
			bHiddenVolHost = FALSE;
			return 1;
		}

		if (nCurPageNo == SYSENC_ENCRYPTION_PAGE)
		{
			BootEncryptionStatus locBootEncStatus;

			switch (lw)
			{
			case IDC_PAUSE:
				try
				{
					locBootEncStatus = BootEncObj->GetStatus();

					if (locBootEncStatus.SetupInProgress)
						SysEncPause ();
					else
						SysEncResume ();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}
				return 1;

			case IDC_WIPE_MODE:
				if (hw == CBN_SELCHANGE)
				{
					nWipeMode = (WipeAlgorithmId) SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE),
						CB_GETITEMDATA,
						SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
						0);

					return 1;
				}
				break;

			case IDC_MORE_INFO_SYS_ENCRYPTION:
				Applink ("sysencprogressinfo");
				return 1;
			}
		}

		if (bInPlaceEncNonSys)
		{
			switch (nCurPageNo)
			{
			case NONSYS_INPLACE_ENC_RESUME_PARTITION_SEL_PAGE:

				if (lw == IDC_LIST_BOX
					&& (hw == LBN_SELCHANGE || hw == LBN_DBLCLK))
				{
					BOOL tmpbDevice = FALSE;

					EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);

					int selPartitionItemId = (int) SendMessage (GetDlgItem (hwndDlg, IDC_LIST_BOX), LB_GETCURSEL, 0, 0);

					if (selPartitionItemId == LB_ERR)
					{
						// Deselect all
						SendMessage (GetDlgItem (hwndDlg, IDC_LIST_BOX), LB_SETCURSEL, (WPARAM) -1, 0);

						SetFocus (GetDlgItem (MainDlg, IDC_NEXT));
						return 1;
					}

					SetFocus (GetDlgItem (MainDlg, IDC_NEXT));

					StringCbCopyW (szFileName, sizeof(szFileName), DeferredNonSysInPlaceEncDevices [selPartitionItemId].Path.c_str());
					CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &tmpbDevice);

					nVolumeSize = GetDeviceSize (szDiskFile);
					if (nVolumeSize == -1)
					{
						handleWin32Error (MainDlg, SRC_POS);
						return 1;
					}

					EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);

					return 1;
				}
				break;

			case  NONSYS_INPLACE_ENC_TRANSFORM_PAGE:
				{
					switch (lw)
					{
					case IDC_PAUSE:

						// Pause/resume non-system in-place encryption

						if (bVolTransformThreadRunning || bVolTransformThreadToRun)
						{
							EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);
							NonSysInplaceEncPause ();
						}
						else
							NonSysInplaceEncResume ();

						return 1;

					case IDC_WIPE_MODE:
						if (hw == CBN_SELCHANGE)
						{
							nWipeMode = (WipeAlgorithmId) SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE),
								CB_GETITEMDATA,
								SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
								0);

							return 1;
						}
						break;
					}
				}
				break;
			}
		}


		if (lw == IDC_OPEN_OUTER_VOLUME && nCurPageNo == FORMAT_FINISHED_PAGE)
		{
			OpenVolumeExplorerWindow (hiddenVolHostDriveNo);
			return 1;
		}

		if (lw == IDC_HIDDEN_VOL_HELP && nCurPageNo == VOLUME_TYPE_PAGE)
		{
			Applink ("hiddenvolume");
			return 1;
		}

		if (lw == IDC_ABORT_BUTTON && nCurPageNo == FORMAT_PAGE)
		{
			if (MessageBoxW (hwndDlg, GetString ("FORMAT_ABORT"), lpszTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 ) == IDYES)
				bVolTransformThreadCancel = TRUE;
			return 1;
		}

		if (lw == IDC_CIPHER_TEST && nCurPageNo == CIPHER_PAGE)
		{
			LPARAM nIndex;
			int c;

			nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nVolumeEA = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

			for (c = EAGetLastCipher (nVolumeEA); c != 0; c = EAGetPreviousCipher (nVolumeEA, c))
			{
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_CIPHER_TEST_DLG),
					GetParent (hwndDlg), (DLGPROC) CipherTestDialogProc, (LPARAM) c);
			}
			return 1;
		}

		if (lw == IDC_BENCHMARK && nCurPageNo == CIPHER_PAGE)
		{
			// Reduce CPU load
			bFastPollEnabled = FALSE;
			bRandmixEnabled = FALSE;

			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_BENCHMARK_DLG), hwndDlg,
				(DLGPROC) BenchmarkDlgProc, (LPARAM) bSystemIsGPT);

			bFastPollEnabled = TRUE;
			bRandmixEnabled = TRUE;

			return 1;
		}

		if (lw == IDC_LINK_MORE_INFO_ABOUT_CIPHER && nCurPageNo == CIPHER_PAGE)
		{
			wchar_t name[100];

			int nIndex = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
			nIndex = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);
			EAGetName (name, ARRAYSIZE(name),nIndex, 0);

			if (wcscmp (name, L"AES") == 0)
				Applink ("aes");
			else if (wcscmp (name, L"Serpent") == 0)
				Applink ("serpent");
			else if (wcscmp (name, L"Twofish") == 0)
				Applink ("twofish");
			else if (wcscmp (name, L"Kuznyechik") == 0)
				Applink ("kuznyechik");
			else if (wcscmp (name, L"Camellia") == 0)
				Applink ("camellia");
			else if (EAGetCipherCount (nIndex) > 1)
				Applink ("cascades");

			return 1;
		}

		if (lw == IDC_LINK_HASH_INFO && nCurPageNo == CIPHER_PAGE)
		{
			Applink ("hashalgorithms");
			return 1;
		}

		if (lw == IDC_LINK_PIM_INFO && nCurPageNo == PIM_PAGE)
		{
			Applink ("pim");
			return 1;
		}

		if (hw == CBN_EDITCHANGE && nCurPageNo == VOLUME_LOCATION_PAGE)
		{
			BOOL bValidEntry = (GetWindowTextLength (GetDlgItem (hCurPage, IDC_COMBO_BOX)) > 0)? TRUE : FALSE;

			if (bValidEntry && !bDevice)
			{
				/* check that the entered path is not for an existing directory */
				WCHAR szEnteredFilePath[TC_MAX_PATH + 1] = {0};
				GetWindowTextW (GetDlgItem (hCurPage, IDC_COMBO_BOX), szEnteredFilePath, ARRAYSIZE (szEnteredFilePath));
				RelativePath2Absolute (szEnteredFilePath);

				DWORD dwAttr = GetFileAttributes (szEnteredFilePath);
				if ((dwAttr != INVALID_FILE_ATTRIBUTES) && (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
				{
					/* this is a directory. Consider it as invalid */
					bValidEntry = FALSE;
				}
			}
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
				bValidEntry);

			bDeviceTransformModeChoiceMade = FALSE;
			bInPlaceEncNonSys = FALSE;

			return 1;
		}

		if (hw == CBN_SELCHANGE && nCurPageNo == VOLUME_LOCATION_PAGE)
		{
			LPARAM nIndex;

			nIndex = MoveEditToCombo ((HWND) lParam, bHistory);
			nIndex = UpdateComboOrder (GetDlgItem (hwndDlg, IDC_COMBO_BOX));

			if (nIndex != CB_ERR)
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			else
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);

			bDeviceTransformModeChoiceMade = FALSE;
			bInPlaceEncNonSys = FALSE;

			return 1;
		}

		if (hw == EN_CHANGE && nCurPageNo == SIZE_PAGE)
		{
			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}

		if (hw == EN_CHANGE && nCurPageNo == PASSWORD_PAGE)
		{
			VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
				GetDlgItem (hwndDlg, IDC_PASSWORD),
				GetDlgItem (hwndDlg, IDC_VERIFY),
				NULL,
				NULL,
				KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());
			volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);

			return 1;
		}

		if (hw == EN_CHANGE && nCurPageNo == PIM_PAGE)
		{
			if (lw == IDC_PIM)
			{
				if(GetPim (hwndDlg, IDC_PIM, 0) != 0)
				{
					PimValueChangedWarning = TRUE;
					SetDlgItemTextW (hwndDlg, IDC_PIM_HELP, GetString (SysEncInEffect ()? "PIM_SYSENC_CHANGE_WARNING" : "PIM_CHANGE_WARNING"));
				}
				else
				{
					PimValueChangedWarning = FALSE;
					SetDlgItemTextW (hwndDlg, IDC_PIM_HELP, (wchar_t *) GetDictionaryValueByInt (IDC_PIM_HELP));
				}
			}

			return 1;
		}

		if (lw == IDC_SHOW_PASSWORD && nCurPageNo == PASSWORD_PAGE)
		{
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD, IDC_PASSWORD, IDC_VERIFY);
			return 1;
		}

		if (lw == IDC_SHOW_PIM && nCurPageNo == PIM_PAGE)
		{
			HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PIM, IDC_PIM, 0);
			return 1;
		}

		if (lw == IDC_PIM_ENABLE)
		{
			PimEnable = GetCheckBox (hwndDlg, IDC_PIM_ENABLE);
			if (!PimEnable)
				volumePim = 0;
			if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE
				)
			{
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_ENABLE), PimEnable? SW_HIDE : SW_SHOW);
				ShowWindow (GetDlgItem( hwndDlg, IDT_PIM), PimEnable? SW_SHOW : SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM), PimEnable? SW_SHOW : SW_HIDE);
				ShowWindow (GetDlgItem( hwndDlg, IDC_PIM_HELP), PimEnable? SW_SHOW : SW_HIDE);
				if (PimEnable)
				{
					SetFocus (GetDlgItem (hwndDlg, IDC_PIM));
				}
			}
			return 1;
		}

		if (nCurPageNo == PASSWORD_PAGE
			|| nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE
			|| nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
		{
			if (lw == IDC_KEY_FILES)
			{
				if (SysEncInEffect())
				{
					Warning ("KEYFILES_NOT_SUPPORTED_FOR_SYS_ENCRYPTION", MainDlg);
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

					SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, KeyFilesEnable);

					if (nCurPageNo != HIDDEN_VOL_HOST_PASSWORD_PAGE && nCurPageNo != NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
						EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

					if (nCurPageNo != HIDDEN_VOL_HOST_PASSWORD_PAGE && nCurPageNo != NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
					{
						VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
							GetDlgItem (hCurPage, IDC_PASSWORD),
							GetDlgItem (hCurPage, IDC_VERIFY),
							volumePassword.Text, szVerify, KeyFilesEnable && FirstKeyFile!=NULL);
					}
				}

				return 1;
			}

			if (lw == IDC_KEYFILES_ENABLE)
			{
				KeyFilesEnable = GetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE);

				if (nCurPageNo != HIDDEN_VOL_HOST_PASSWORD_PAGE && nCurPageNo != NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
				{
					EnableWindow (GetDlgItem (hwndDlg, IDC_KEY_FILES), KeyFilesEnable);

					VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (GetParent (hwndDlg), IDC_NEXT),
						GetDlgItem (hCurPage, IDC_PASSWORD),
						GetDlgItem (hCurPage, IDC_VERIFY),
						volumePassword.Text, szVerify, KeyFilesEnable && FirstKeyFile!=NULL);
				}

				return 1;
			}
		}

		if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE
			|| nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
		{
			if (hw == EN_CHANGE)
			{
				GetPassword (hCurPage, IDC_PASSWORD_DIRECT, (char*) volumePassword.Text, iMaxPasswordLength + 1, FALSE, FALSE);
				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);
				return 1;
			}

			if (lw == IDC_SHOW_PASSWORD_SINGLE)
			{
				HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PASSWORD_SINGLE, IDC_PASSWORD_DIRECT, IDC_PIM);
				return 1;
			}
		}

		if ((lw == IDC_KB || lw == IDC_MB || lw == IDC_GB || lw == IDC_TB) && nCurPageNo == SIZE_PAGE)
		{
			SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_GB), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage (GetDlgItem (hwndDlg, IDC_TB), BM_SETCHECK, BST_UNCHECKED, 0);

			switch (lw)
			{
			case IDC_KB:
				SendMessage (GetDlgItem (hwndDlg, IDC_KB), BM_SETCHECK, BST_CHECKED, 0);
				break;
			case IDC_MB:
				SendMessage (GetDlgItem (hwndDlg, IDC_MB), BM_SETCHECK, BST_CHECKED, 0);
				break;
			case IDC_GB:
				SendMessage (GetDlgItem (hwndDlg, IDC_GB), BM_SETCHECK, BST_CHECKED, 0);
				break;
			case IDC_TB:
				SendMessage (GetDlgItem (hwndDlg, IDC_TB), BM_SETCHECK, BST_CHECKED, 0);
				break;
			}

			VerifySizeAndUpdate (hwndDlg, FALSE);
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_DIRECT && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = TRUE;
			return 1;
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_FULL && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = FALSE;
			return 1;
		}

		if (lw == IDC_SELECT_VOLUME_LOCATION && nCurPageNo == VOLUME_LOCATION_PAGE)
		{
			if (!bDevice)
			{
				// Select file

				if (BrowseFiles (hwndDlg, "OPEN_TITLE", szFileName, bHistory, !bHiddenVolDirect) == FALSE)
					return 1;

				AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

				EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
					GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

				return 1;
			}
			else
			{
				// Select device
				RawDevicesDlgParam param;
				param.pszFileName = szFileName;
				INT_PTR nResult = DialogBoxParamW (hInst,
					MAKEINTRESOURCEW (IDD_RAWDEVICES_DLG), GetParent (hwndDlg),
					(DLGPROC) RawDevicesDlgProc, (LPARAM) & param);

				// Check administrator privileges
				if (!wcsstr (szFileName, L"Floppy") && !IsAdmin() && !IsUacSupported ())
					MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_DEVICES"), lpszTitle, MB_OK|MB_ICONWARNING);

				if (nResult == IDOK && wcslen (szFileName) > 0)
				{
					AddComboItem (GetDlgItem (hwndDlg, IDC_COMBO_BOX), szFileName, bHistory);

					EnableDisableFileNext (GetDlgItem (hwndDlg, IDC_COMBO_BOX),
						GetDlgItem (GetParent (hwndDlg), IDC_NEXT));

					bDeviceTransformModeChoiceMade = FALSE;
					bInPlaceEncNonSys = FALSE;
				}
				return 1;
			}
		}

		if (nCurPageNo == DEVICE_TRANSFORM_MODE_PAGE)
		{
			switch (lw)
			{
			case IDC_DEVICE_TRANSFORM_MODE_FORMAT:

				bInPlaceEncNonSys = FALSE;
				bDeviceTransformModeChoiceMade = TRUE;

				return 1;

			case IDC_DEVICE_TRANSFORM_MODE_INPLACE:

				bInPlaceEncNonSys = TRUE;
				bDeviceTransformModeChoiceMade = TRUE;

				bHiddenVol = FALSE;
				bHiddenVolDirect = FALSE;
				bHiddenVolHost = FALSE;
				bSparseFileSwitch = FALSE;
				quickFormat = FALSE;
				dynamicFormat = FALSE;

				return 1;
			}
		}

		if (lw == IDC_HIDVOL_WIZ_MODE_FULL && nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
		{
			bHiddenVolDirect = FALSE;
			return 1;
		}

		if (hw == CBN_SELCHANGE && nCurPageNo == CIPHER_PAGE)
		{
			switch (lw)
			{
			case IDC_COMBO_BOX:
				ComboSelChangeEA (hwndDlg);
				break;

			case IDC_COMBO_BOX_HASH_ALGO:
				if (SysEncInEffect ())
				{
					HWND hHashAlgoItem = GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO);
					int selectedAlgo = (int) SendMessage (hHashAlgoItem, CB_GETITEMDATA, SendMessage (hHashAlgoItem, CB_GETCURSEL, 0, 0), 0);
					if (!bSystemIsGPT && !HashForSystemEncryption(selectedAlgo))
					{
						hash_algo = DEFAULT_HASH_ALGORITHM_BOOT;
						RandSetHashFunction (DEFAULT_HASH_ALGORITHM_BOOT);
						Info ("ALGO_NOT_SUPPORTED_FOR_SYS_ENCRYPTION", MainDlg);
						SelectAlgo (GetDlgItem (hwndDlg, IDC_COMBO_BOX_HASH_ALGO), &hash_algo);
					}
				}
				break;
			}
			return 1;

		}

		if (lw == IDC_FORMAT_TYPE && hw == CBN_SELCHANGE)
		{
			formatType = (int) SendMessage (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), CB_GETITEMDATA,
				SendMessage (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), CB_GETCURSEL, 0, 0) , 0);

			if (formatType == FORMAT_TYPE_QUICK)
			{
				if (AskWarnYesNo("WARN_QUICK_FORMAT", MainDlg) == IDNO)
				{
					formatType = FORMAT_TYPE_FULL;
					SelectAlgo(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), (int *) &formatType);
				}
			}
			else if (formatType == FORMAT_TYPE_FAST)
			{
				if (AskWarnYesNo("WARN_FAST_CREATE", MainDlg) == IDNO)
				{
					formatType = FORMAT_TYPE_FULL;
					SelectAlgo(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), (int *) &formatType);
				}
			}

			return 1;
		}

		if (lw == SPARSE_FILE)
		{
			if (IsButtonChecked (GetDlgItem (hCurPage, SPARSE_FILE)))
			{
				if (AskWarnYesNo("CONFIRM_SPARSE_FILE", MainDlg) == IDNO)
					SetCheckBox (hwndDlg, SPARSE_FILE, FALSE);
				else
				{
					/* sparse file require quick format */
					formatType = FORMAT_TYPE_QUICK;
					SelectAlgo(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), (int *) &formatType);
					EnableWindow(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), FALSE);
				}
			}
			else
			{
				EnableWindow(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), TRUE);
				formatType = FORMAT_TYPE_FULL;
				SelectAlgo(GetDlgItem (hCurPage, IDC_FORMAT_TYPE), (int *) &formatType);
			}
			return 1;
		}

		if (lw == IDC_FILESYS && hw == CBN_SELCHANGE)
		{
			fileSystem = (int) SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA,
				SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);

			if (nCurPageNo == FORMAT_PAGE)
			{
				UpdateClusterSizeList (hCurPage, fileSystem);
			}

			return 1;
		}

		if (lw == IDC_SHOW_KEYS && nCurPageNo == FORMAT_PAGE)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_SHOW_KEYS));

			SetWindowText (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), showKeys ? L"                                                                              " : L"********************************                                              ");
			SetWindowText (GetDlgItem (hCurPage, IDC_HEADER_KEY), showKeys ? L"" : L"********************************                                              ");
			SetWindowText (GetDlgItem (hCurPage, IDC_DISK_KEY), showKeys ? L"" : L"********************************                                              ");
			return 1;
		}

		if (lw == IDC_DISPLAY_POOL_CONTENTS
			&& (nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE || nCurPageNo == NONSYS_INPLACE_ENC_RAND_DATA_PAGE))
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_DISPLAY_POOL_CONTENTS));
			DisplayRandPool (hwndDlg, hRandPoolSys, showKeys);

			return 1;
		}

		if (lw == IDC_DISPLAY_KEYS && nCurPageNo == SYSENC_KEYS_GEN_PAGE)
		{
			showKeys = IsButtonChecked (GetDlgItem (hCurPage, IDC_DISPLAY_KEYS));

			DisplayPortionsOfKeys (GetDlgItem (hwndDlg, IDC_HEADER_KEY), GetDlgItem (hwndDlg, IDC_DISK_KEY), HeaderKeyGUIView, MasterKeyGUIView, !showKeys);
			return 1;
		}

		if (nCurPageNo == SYSENC_RESCUE_DISK_CREATION_PAGE)
		{
			if (lw == IDC_BROWSE)
			{
				wchar_t tmpszRescueDiskISO [TC_MAX_PATH+1];

				if (!BrowseFiles (hwndDlg, "OPEN_TITLE", tmpszRescueDiskISO, FALSE, TRUE))
					return 1;

				StringCbCopyW (szRescueDiskISO, sizeof(szRescueDiskISO), tmpszRescueDiskISO);

				SetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO);
				EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
				return 1;
			}

			if ( hw == EN_CHANGE )
			{
				GetDlgItemText (hwndDlg, IDC_RESCUE_DISK_ISO_PATH, szRescueDiskISO, sizeof(szRescueDiskISO));
				EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hwndDlg, IDC_RESCUE_DISK_ISO_PATH)) > 1));
				return 1;
			}
		}

		if (nCurPageNo == SYSENC_RESCUE_DISK_BURN_PAGE && lw == IDC_DOWNLOAD_CD_BURN_SOFTWARE)
		{
			if (IsWindowsIsoBurnerAvailable())
				LaunchWindowsIsoBurner (hwndDlg, szRescueDiskISO);
			else
				Applink ("isoburning");

			return 1;
		}

		if ((nCurPageNo == SYSENC_WIPE_MODE_PAGE
			|| nCurPageNo == NONSYS_INPLACE_ENC_WIPE_MODE_PAGE
			|| nCurPageNo == DEVICE_WIPE_MODE_PAGE)
			&& hw == CBN_SELCHANGE)
		{
			nWipeMode = (WipeAlgorithmId) SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE),
				CB_GETITEMDATA,
				SendMessage (GetDlgItem (hCurPage, IDC_WIPE_MODE), CB_GETCURSEL, 0, 0),
				0);

			return 1;
		}

		if (nCurPageNo == DEVICE_WIPE_PAGE)
		{
			switch (lw)
			{
			case IDC_ABORT_BUTTON:

				if (AskWarnNoYes ("CONFIRM_WIPE_ABORT", MainDlg) == IDYES)
					WipeAbort();

				return 1;
			}
		}

		if (lw == IDC_NO_HISTORY)
		{
			if (!(bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY))))
				ClearHistory (GetDlgItem (hCurPage, IDC_COMBO_BOX));

			return 1;
		}

		return 0;
	}

	return 0;
}

/* Except in response to the WM_INITDIALOG and WM_ENDSESSION messages, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does not. - see DialogProc */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	int nNewPageNo = nCurPageNo;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			MainDlg = hwndDlg;
			InitDialog (hwndDlg);
			LocalizeDialog (hwndDlg, "IDD_VOL_CREATION_WIZARD_DLG");

			if (IsTrueCryptInstallerRunning())
				AbortProcess ("TC_INSTALLER_IS_RUNNING");

			// Resize the bitmap if the user has a non-default DPI
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				hbmWizardBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_WIZARD),
					GetDlgItem (hwndDlg, IDC_BITMAP_WIZARD),
					0, 0, 0, 0, FALSE, FALSE);
			}

			LoadSettings (hwndDlg);

			// set the maximum password length based on configuration setting
			if (bUseLegacyMaxPasswordLength)
				iMaxPasswordLength = MAX_LEGACY_PASSWORD;
			else
				iMaxPasswordLength = MAX_PASSWORD;

			// Save language to XML configuration file if it has been selected in the setup
			// so that other VeraCrypt programs will pick it up
			if (bLanguageSetInSetup)
				SaveSettings (hwndDlg);

			LoadDefaultKeyFilesParam ();
			RestoreDefaultKeyFilesParam ();

			SysEncMultiBootCfg.NumberOfSysDrives = -1;
			SysEncMultiBootCfg.MultipleSystemsOnDrive = -1;
			SysEncMultiBootCfg.BootLoaderLocation = -1;
			SysEncMultiBootCfg.BootLoaderBrand = -1;
			SysEncMultiBootCfg.SystemOnBootDrive = -1;

			try
			{
				BootEncStatus = BootEncObj->GetStatus();
			}
			catch (Exception &e)
			{
				e.Show (hwndDlg);
				Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
				EndMainDlg (MainDlg);
				return 0;
			}

			try
			{
				bSystemIsGPT = BootEncObj->GetSystemDriveConfiguration().SystemPartition.IsGPT;
			}
			catch (...)
			{
			}

			SendMessageW (GetDlgItem (hwndDlg, IDC_BOX_TITLE), WM_SETFONT, (WPARAM) hTitleFont, (LPARAM) TRUE);
			SetWindowTextW (hwndDlg, lpszTitle);

			ExtractCommandLine (hwndDlg, (wchar_t *) lParam);

			if (EnableMemoryProtection)
			{
				/* Protect this process memory from being accessed by non-admin users */
				ActivateMemoryProtection ();
			}

			if (ComServerMode)
			{
				InitDialog (hwndDlg);

				if (!ComServerFormat ())
				{
					handleWin32Error (hwndDlg, SRC_POS);
					exit (1);
				}
				exit (0);
			}

			fastCreateFile = CmdFastCreateFile;

			if (DirectCreationMode)
			{
				wchar_t root[TC_MAX_PATH];
				DWORD fileSystemFlags = 0;
				uint64 dataAreaSize;
				wchar_t szFileSystemNameBuffer[256];
				ULARGE_INTEGER free;

				showKeys = FALSE;
				bGuiMode = FALSE;

				if (CmdVolumePassword.Length == 0 && !FirstCmdKeyFile)
					AbortProcess ("ERR_PASSWORD_MISSING");

				if (CmdVolumeFileSize == 0)
					AbortProcess ("ERR_SIZE_MISSING");

				CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &bDevice);

				if (bDevice)
					AbortProcess ("ERR_DEVICE_CLI_CREATE_NOT_SUPPORTED");

				volumePassword = CmdVolumePassword;
				volumePim = CmdVolumePim;

				if (CmdVolumeEA > 0)
					nVolumeEA = CmdVolumeEA;

				if (CmdVolumePkcs5 > 0)
					hash_algo = CmdVolumePkcs5;

				if (CmdVolumeFilesystem > 0)
					fileSystem = CmdVolumeFilesystem;
				else
					fileSystem = FILESYS_NTFS;

				nVolumeSize = CmdVolumeFileSize;

				// correct volume size to be multiple of sector size
				if (bDevice && !(bHiddenVol && !bHiddenVolHost))	// If raw device but not a hidden volume
				{
					// do nothing. no correction is needed
				}
				else
				{
					unsigned __int64 sectorSize = (unsigned __int64) GetFormatSectorSize();
					unsigned __int64 sectorSizeRem = nVolumeSize % sectorSize;

					if (sectorSizeRem != 0)
						nVolumeSize = nVolumeSize + (sectorSize - sectorSizeRem);
				}

				if (nVolumeSize < (bHiddenVolHost ? TC_MIN_HIDDEN_VOLUME_HOST_SIZE : (bHiddenVol ? TC_MIN_HIDDEN_VOLUME_SIZE : TC_MIN_VOLUME_SIZE)))
					AbortProcess ("ERR_VOLUME_SIZE_TOO_SMALL");

				if (	((!bHiddenVolHost && bHiddenVol) && (nVolumeSize > (unsigned __int64) nMaximumHiddenVolSize))
					||	(nVolumeSize > (unsigned __int64) (bHiddenVolHost ? TC_MAX_HIDDEN_VOLUME_HOST_SIZE : TC_MAX_VOLUME_SIZE))
					)
				{
					AbortProcess ("ERR_VOLUME_SIZE_TOO_BIG");
				}

				if (!GetVolumePathName (szFileName, root, array_capacity (root)))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					exit (1);
				}

				if (CmdSparseFileSwitch)
				{
					/* Check if the host file system supports sparse files */
					GetVolumeInformation (root, NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0);
					bSparseFileSwitch = fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES;

					if (!bSparseFileSwitch)
					{
						AbortProcess ("ERR_DYNAMIC_NOT_SUPPORTED");
					}
				}

				quickFormat = CmdQuickFormat;
				dynamicFormat = CmdSparseFileSwitch;

				if (!GetDiskFreeSpaceEx (root, &free, 0, 0))
				{
					wchar_t szTmp[1024];

					if (translateWin32Error (szTmp, sizeof (szTmp) / sizeof(szTmp[0])))
					{
						wchar_t szTmp2[1024];
						StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s\n%s", GetString ("CANNOT_CALC_SPACE"), szTmp);
						AbortProcessDirect (szTmp2);
					}
					else
					{
						handleWin32Error (hwndDlg, SRC_POS);
					}

					exit (1);
				}
				else
				{
					if (!dynamicFormat && !bDontCheckFileContainerSize && (nVolumeSize > free.QuadPart))
					{
						AbortProcess ("ERR_CONTAINER_SIZE_TOO_BIG");
					}
				}

				dataAreaSize = GetVolumeDataAreaSize (bHiddenVol && !bHiddenVolHost, nVolumeSize);

				if (	(fileSystem == FILESYS_NTFS) &&
						(dataAreaSize < TC_MIN_NTFS_FS_SIZE || dataAreaSize > TC_MAX_NTFS_FS_SIZE)
					)
				{
					AbortProcess ("ERR_NTFS_INVALID_VOLUME_SIZE");
				}

				if (	(fileSystem == FILESYS_EXFAT) &&
						(dataAreaSize < TC_MIN_EXFAT_FS_SIZE || dataAreaSize > TC_MAX_EXFAT_FS_SIZE)
					)
				{
					AbortProcess ("ERR_EXFAT_INVALID_VOLUME_SIZE");
				}

				if (	(fileSystem == FILESYS_REFS) &&
						(dataAreaSize < TC_MIN_REFS_FS_SIZE || dataAreaSize > TC_MAX_REFS_FS_SIZE)
					)
				{
					AbortProcess ("ERR_REFS_INVALID_VOLUME_SIZE");
				}

				if (	(fileSystem == FILESYS_FAT) &&
						(dataAreaSize < TC_MIN_FAT_FS_SIZE || dataAreaSize > (TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize()))
					)
				{
					AbortProcess ("ERR_FAT_INVALID_VOLUME_SIZE");
				}

				/* Verify that the volume would not be too large for the host file system */
				if (GetVolumePathName (szDiskFile, root, ARRAYSIZE (root))
					&& GetVolumeInformation (root, NULL, 0, NULL, NULL, NULL, szFileSystemNameBuffer, ARRAYSIZE(szFileSystemNameBuffer))
					&& !wcsncmp (szFileSystemNameBuffer, L"FAT32", 5))
				{
					// The host file system is FAT32
					if (nVolumeSize >= 4 * BYTES_PER_GB)
					{
						AbortProcess ("VOLUME_TOO_LARGE_FOR_FAT32");
					}
				}

				if (volumePassword.Length > 0)
				{
					// Check password length (check also done for outer volume which is not the case in TrueCrypt).
					if (!CheckPasswordLength (NULL, volumePassword.Length, volumePim, FALSE, 0, Silent, Silent))
					{
						exit (1);
					}
				}

				if (!KeyFilesApply (hwndDlg, &volumePassword, FirstCmdKeyFile, NULL))
				{
					exit (1);
				}

				volTransformThreadFunction (hwndDlg);

				exit (bOperationSuccess? 0 : 1);
			}

			SHGetFolderPath (NULL, CSIDL_MYDOCUMENTS, NULL, 0, szRescueDiskISO);
			if (bSystemIsGPT)
				StringCbCatW (szRescueDiskISO, sizeof(szRescueDiskISO), L"\\VeraCrypt Rescue Disk.zip");
			else
				StringCbCatW (szRescueDiskISO, sizeof(szRescueDiskISO), L"\\VeraCrypt Rescue Disk.iso");

			// Availability of in-place encryption (which is pre-selected by default whenever
			// possible) makes partition-hosted volume creation safer.
			bWarnDeviceFormatAdvanced = FALSE;

#ifdef _DEBUG
			// For faster testing
			StringCchCopyA (szVerify, ARRAYSIZE(szVerify), "q");
			StringCchCopyA (szRawPassword, ARRAYSIZE(szRawPassword), "q");
#endif

			PasswordEditDropTarget* pTarget = new PasswordEditDropTarget ();
			if (pTarget->Register (hwndDlg))
			{
				SetWindowLongPtr (hwndDlg, DWLP_USER, (LONG_PTR) pTarget);
			}
			else
				delete pTarget;

			PostMessage (hwndDlg, TC_APPMSG_PERFORM_POST_WMINIT_TASKS, 0, 0);
		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_TIMER:

		switch (wParam)
		{
		case TIMER_ID_RANDVIEW:

			if (WizardMode == WIZARD_MODE_SYS_DEVICE
				|| bInPlaceEncNonSys)
			{
				DisplayRandPool (hwndDlg, hRandPoolSys, showKeys);
			}
			else
			{
				int partialLen = 16;
				wchar_t tmp2[43];
				int i;
				DWORD mouseEventsCounter;

				RandpeekBytes (hwndDlg, randPool, partialLen, &mouseEventsCounter);

				ProcessEntropyEstimate (hEntropyBar, &mouseEventsInitialCount, mouseEventsCounter, maxEntropyLevel, &mouseEntropyGathered);

				tmp2[0] = 0;

				for (i = 0; i < partialLen; i++)
				{
					wchar_t tmp3[3];
					if (showKeys)
					{
						StringCbPrintfW (tmp3, sizeof(tmp3), L"%02X", (int) randPool[i]);
					}
					else if (bUseMask)
					{
						unsigned char tmpByte = randPool[i] ^ maskRandPool[i];
						tmp3[0] = (wchar_t) (((tmpByte >> 4) % 6) + L'*');
						tmp3[1] = (wchar_t) (((tmpByte & 0x0F) % 6) + L'*');
						tmp3[2] = 0;
					}
					else
						StringCbCopyW (tmp3, sizeof (tmp3), L"**");
					StringCbCatW (tmp2, sizeof(tmp2), tmp3);
				}

				tmp2[32] = 0;

				SetWindowTextW (GetDlgItem (hCurPage, IDC_RANDOM_BYTES), (wstring (tmp2) + GetString ("TRIPLE_DOT_GLYPH_ELLIPSIS")).c_str());

				burn (randPool, partialLen);
				burn (tmp2, sizeof(tmp2));
			}
			return 1;

		case TIMER_ID_SYSENC_PROGRESS:
			{
				// Manage system encryption/decryption and update related GUI

				try
				{
					BootEncStatus = BootEncObj->GetStatus();
				}
				catch (Exception &e)
				{
					KillTimer (MainDlg, TIMER_ID_SYSENC_PROGRESS);

					try
					{
						BootEncObj->AbortSetup ();
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}

					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", MainDlg);
					EndMainDlg (MainDlg);
					return 1;
				}

				if (BootEncStatus.SetupInProgress)
					UpdateSysEncProgressBar ();

				if (bSystemEncryptionInProgress != BootEncStatus.SetupInProgress)
				{
					bSystemEncryptionInProgress = BootEncStatus.SetupInProgress;

					UpdateSysEncProgressBar ();
					UpdateSysEncControls ();

					if (!bSystemEncryptionInProgress)
					{
						// The driver stopped encrypting/decrypting

						// Allow the OS to enter Sleep mode when idle
						SetThreadExecutionState (ES_CONTINUOUS);

						KillTimer (hwndDlg, TIMER_ID_SYSENC_PROGRESS);

						UpdateLastDialogId ();

						try
						{
							if (BootEncStatus.DriveMounted)	// If we had been really encrypting/decrypting (not just proceeding to deinstall)
								BootEncObj->CheckEncryptionSetupResult();
						}
						catch (SystemException &e)
						{
							if (!bTryToCorrectReadErrors
								&& SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
								&& (IsDiskReadError (e.ErrorCode)))
							{
								bTryToCorrectReadErrors = (AskWarnYesNo ("ENABLE_BAD_SECTOR_ZEROING", MainDlg) == IDYES);

								if (bTryToCorrectReadErrors)
								{
									SysEncResume();
									return 1;
								}
							}
							else if (!DiscardUnreadableEncryptedSectors
								&& SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING
								&& (IsDiskReadError (e.ErrorCode)))
							{
								DiscardUnreadableEncryptedSectors = (AskWarnYesNo ("DISCARD_UNREADABLE_ENCRYPTED_SECTORS", MainDlg) == IDYES);

								if (DiscardUnreadableEncryptedSectors)
								{
									SysEncResume();
									return 1;
								}
							}

							e.Show (hwndDlg);
						}
						catch (Exception &e)
						{
							e.Show (hwndDlg);
						}

						switch (SystemEncryptionStatus)
						{
						case SYSENC_STATUS_ENCRYPTING:

							if (BootEncStatus.ConfiguredEncryptedAreaStart == BootEncStatus.EncryptedAreaStart
								&& BootEncStatus.ConfiguredEncryptedAreaEnd == BootEncStatus.EncryptedAreaEnd)
							{
								// The partition/drive has been fully encrypted

								ManageStartupSeqWiz (TRUE, L"");

								SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
								EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
								EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_WIPE_MODE), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

								WipeHiddenOSCreationConfig();	// For extra conservative security

								ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

								Info ("SYSTEM_ENCRYPTION_FINISHED", MainDlg);
								return 1;
							}
							break;

						case SYSENC_STATUS_DECRYPTING:

							if (!BootEncStatus.DriveEncrypted)
							{
								// The partition/drive has been fully decrypted

								try
								{
									// Finalize the process
									BootEncObj->Deinstall ();
								}
								catch (Exception &e)
								{
									e.Show (hwndDlg);
								}

								ManageStartupSeqWiz (TRUE, L"");
								ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

								SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));
								EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
								EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
								EnableWindow (GetDlgItem (hCurPage, IDC_PAUSE), FALSE);

								Info ("SYSTEM_DECRYPTION_FINISHED", MainDlg);

								// Reboot is required to enable uninstallation and hibernation
								if (AskWarnYesNo ("CONFIRM_RESTART", MainDlg) == IDYES)
								{
									EndMainDlg (MainDlg);

									try
									{
										BootEncObj->RestartComputer();
									}
									catch (Exception &e)
									{
										e.Show (hwndDlg);
									}
								}

								return 1;
							}
							break;
						}
					}
				}
			}
			return 1;

		case TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS:

			if (bInPlaceEncNonSys)
			{
				// Non-system in-place encryption

				if (!bVolTransformThreadRunning && !bVolTransformThreadToRun)
				{
					KillTimer (hwndDlg, TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS);

					UpdateLastDialogId ();
				}

				UpdateNonSysInPlaceEncControls ();
			}
			return 1;

		case TIMER_ID_KEYB_LAYOUT_GUARD:
			if (SysEncInEffect ())
			{
				DWORD keybLayout = (DWORD)(DWORD_PTR) GetKeyboardLayout (NULL);

				/* Watch the keyboard layout */

				if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
				{
					// Keyboard layout is not standard US

					WipePasswordsAndKeyfiles (true);

					SetPassword (hCurPage, IDC_PASSWORD, szRawPassword);
					SetPassword (hCurPage, IDC_VERIFY, szVerify);

					keybLayout = (DWORD)(DWORD_PTR)LoadKeyboardLayout (L"00000409", KLF_ACTIVATE);

					if (keybLayout != 0x00000409 && keybLayout != 0x04090409)
					{
						KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);
						Error ("CANT_CHANGE_KEYB_LAYOUT_FOR_SYS_ENCRYPTION", MainDlg);
						EndMainDlg (MainDlg);
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

		case TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS:

			if (bSysEncDriveAnalysisInProgress)
			{
				UpdateProgressBarProc (GetTickCount() - SysEncDriveAnalysisStart);

				if (GetTickCount() - SysEncDriveAnalysisStart > SYSENC_DRIVE_ANALYSIS_ETA)
				{
					// It's taking longer than expected -- reinit the progress bar
					SysEncDriveAnalysisStart = GetTickCount ();
					InitProgressBar (SYSENC_DRIVE_ANALYSIS_ETA, 0, FALSE, FALSE, FALSE, TRUE);
				}

				ArrowWaitCursor ();
			}
			else
			{
				KillTimer (hwndDlg, TIMER_ID_SYSENC_DRIVE_ANALYSIS_PROGRESS);
				UpdateProgressBarProc (SYSENC_DRIVE_ANALYSIS_ETA);
				Sleep (1500);	// User-friendly GUI

				if (bSysEncDriveAnalysisTimeOutOccurred)
					Warning ("SYS_DRIVE_SIZE_PROBE_TIMEOUT", MainDlg);

				LoadPage (hwndDlg, SYSENC_DRIVE_ANALYSIS_PAGE + 1);
			}
			return 1;

		case TIMER_ID_WIPE_PROGRESS:

			// Manage device wipe and update related GUI

			if (bHiddenOS && IsHiddenOSRunning())
			{
				// Decoy system partition wipe

				DecoySystemWipeStatus decoySysPartitionWipeStatus;

				try
				{
					decoySysPartitionWipeStatus = BootEncObj->GetDecoyOSWipeStatus();
					BootEncStatus = BootEncObj->GetStatus();
				}
				catch (Exception &e)
				{
					KillTimer (MainDlg, TIMER_ID_WIPE_PROGRESS);

					try
					{
						BootEncObj->AbortDecoyOSWipe ();
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}

					e.Show (hwndDlg);
					EndMainDlg (MainDlg);
					return 1;
				}

				if (decoySysPartitionWipeStatus.WipeInProgress)
				{
					ArrowWaitCursor ();

					UpdateWipeProgressBar ();
				}

				if (bDeviceWipeInProgress != decoySysPartitionWipeStatus.WipeInProgress)
				{
					bDeviceWipeInProgress = decoySysPartitionWipeStatus.WipeInProgress;

					UpdateWipeProgressBar ();
					UpdateWipeControls ();

					if (!bDeviceWipeInProgress)
					{
						// The driver stopped wiping

						KillTimer (hwndDlg, TIMER_ID_WIPE_PROGRESS);
						UpdateLastDialogId ();

						try
						{
							BootEncObj->CheckDecoyOSWipeResult();
						}
						catch (Exception &e)
						{
							e.Show (hwndDlg);
							AbortProcessSilent();
						}

						if (BootEncStatus.ConfiguredEncryptedAreaEnd == decoySysPartitionWipeStatus.WipedAreaEnd)
						{
							// Decoy system partition has been fully wiped

							ChangeHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_WIPED);

							SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("EXIT"));
							EnableWindow (GetDlgItem (MainDlg, IDCANCEL), TRUE);
							EnableWindow (GetDlgItem (MainDlg, IDC_PREV), FALSE);
							EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), FALSE);
							EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);

							Info ("WIPE_FINISHED_DECOY_SYSTEM_PARTITION", MainDlg);

							TextInfoDialogBox (TC_TBXID_DECOY_OS_INSTRUCTIONS);

							if (BootEncObj->GetSystemDriveConfiguration().ExtraBootPartitionPresent)
								Warning ("DECOY_OS_VERSION_WARNING", MainDlg);

							return 1;
						}
					}
				}
			}
			else
			{
				// Regular device wipe (not decoy system partition wipe)

				//Info ("WIPE_FINISHED");
			}
			return 1;
		}

		return 0;


	case TC_APPMSG_PERFORM_POST_WMINIT_TASKS:

		AfterWMInitTasks (hwndDlg);
		return 1;

	case TC_APPMSG_FORMAT_FINISHED:
		{
			wchar_t tmp[RNG_POOL_SIZE*2+1];

			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
			SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));

			if (nCurPageNo == FORMAT_PAGE)
				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

			// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
			wmemset (tmp, 'X', ARRAYSIZE(tmp));
			tmp [ARRAYSIZE(tmp)-1] = 0;
			SetWindowText (hRandPool, tmp);
			SetWindowText (hMasterKey, tmp);
			SetWindowText (hHeaderKey, tmp);

			LoadPage (hwndDlg, FORMAT_FINISHED_PAGE);
		}
		return 1;

	case TC_APPMSG_NONSYS_INPLACE_ENC_FINISHED:

		// A partition has just been fully encrypted in place

		KillTimer (hwndDlg, TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS);

		if (bInPlaceDecNonSys)
		{
			// Decryption of non-system volume finished and free drive letters are available. Check if a drive letter is assigned to the decrypted volume.

			WCHAR deviceName[MAX_PATH + 1];

			StringCbCopyW (deviceName, sizeof(deviceName), szDiskFile);

			if (GetDiskDeviceDriveLetter (deviceName) < 0)
			{
				// No drive letter is assigned to the device
				MessageBeep (MB_OK);
				LoadPage (hwndDlg, NONSYS_INPLACE_DEC_TRANSFORM_FINISHED_DRIVE_LETTER_PAGE);
				return 1;
			}
			else
			{
				Info ("NONSYS_INPLACE_DEC_FINISHED_INFO", hwndDlg);
			}
		}

		LoadPage (hwndDlg, NONSYS_INPLACE_ENC_TRANSFORM_FINISHED_PAGE);
		return 1;

	case TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED:

		if (bInPlaceEncNonSys)
		{
			// In-place encryption was interrupted/paused (did not finish)

			KillTimer (hwndDlg, TIMER_ID_NONSYS_INPLACE_ENC_PROGRESS);

			UpdateNonSysInPlaceEncControls ();
		}
		else
		{
			// Format has been aborted (did not finish)

			EnableWindow (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), !(bHiddenVol && !bHiddenVolHost));
			EnableWindow (GetDlgItem (hCurPage, SPARSE_FILE), (bSparseFileSwitch) && !(bHiddenVol && !bHiddenVolHost));
			EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), TRUE);
			EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
			EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);
			EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
			SendMessage (GetDlgItem (hCurPage, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0L);
			SetFocus (GetDlgItem (hwndDlg, IDC_NEXT));
		}

		NormalCursor ();
		return 1;

	case WM_HELP:

		OpenPageHelp (hwndDlg, nCurPageNo);
		return 1;

	case TC_APPMSG_FORMAT_USER_QUIT:

		if (nCurPageNo == NONSYS_INPLACE_ENC_TRANSFORM_PAGE
			&& (bVolTransformThreadRunning || bVolTransformThreadToRun || bInPlaceEncNonSysResumed))
		{
			// Non-system encryption in progress
			if (AskNoYes ("NONSYS_INPLACE_ENC_DEFER_CONFIRM", hwndDlg) == IDYES)
			{
				NonSysInplaceEncPause ();

				EndMainDlg (hwndDlg);
				return 1;
			}
			else
				return 1;	// Disallow close
		}
		else if (bVolTransformThreadRunning || bVolTransformThreadToRun)
		{
			// Format (non-in-place encryption) in progress
			if (AskNoYes ("FORMAT_ABORT", hwndDlg) == IDYES)
			{
				bVolTransformThreadCancel = TRUE;

				EndMainDlg (hwndDlg);
				return 1;
			}
			else
				return 1;	// Disallow close
		}
		else if ((nCurPageNo == SYSENC_ENCRYPTION_PAGE || nCurPageNo == SYSENC_PRETEST_RESULT_PAGE)
			&& SystemEncryptionStatus != SYSENC_STATUS_NONE
			&& InstanceHasSysEncMutex ())
		{
			// System encryption/decryption in progress

			if (AskYesNo (SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING ?
				"SYSTEM_DECRYPTION_DEFER_CONFIRM" : "SYSTEM_ENCRYPTION_DEFER_CONFIRM", MainDlg) == IDYES)
			{
				if (nCurPageNo == SYSENC_PRETEST_RESULT_PAGE)
					TextInfoDialogBox (TC_TBXID_SYS_ENC_RESCUE_DISK);

				try
				{
					BootEncStatus = BootEncObj->GetStatus();

					if (BootEncStatus.SetupInProgress)
					{
						BootEncObj->AbortSetupWait ();
						Sleep (200);
						BootEncStatus = BootEncObj->GetStatus();
					}

					if (!BootEncStatus.SetupInProgress)
					{
						EndMainDlg (MainDlg);
						return 1;
					}
					else
					{
						Error ("FAILED_TO_INTERRUPT_SYSTEM_ENCRYPTION", MainDlg);
						return 1;	// Disallow close
					}
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}
				return 1;	// Disallow close
			}
			else
				return 1;	// Disallow close
		}
		else if (bConfirmQuitSysEncPretest)
		{
			if (AskWarnNoYes (bHiddenOS ? "CONFIRM_CANCEL_HIDDEN_OS_CREATION" : "CONFIRM_CANCEL_SYS_ENC_PRETEST", MainDlg) == IDNO)
				return 1;	// Disallow close
		}
		else if (bConfirmQuit)
		{
			if (AskWarnNoYes ("CONFIRM_EXIT_UNIVERSAL", MainDlg) == IDNO)
				return 1;	// Disallow close
		}

		if (hiddenVolHostDriveNo > -1)
		{
			CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);
			UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE);
		}

		EndMainDlg (hwndDlg);
		return 1;


	case WM_COMMAND:

		if (lw == IDHELP)
		{
			OpenPageHelp (hwndDlg, nCurPageNo);
			return 1;
		}
		else if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
			return 1;
		}
		else if (lw == IDC_NEXT)
		{
			if (nCurPageNo == INTRO_PAGE)
			{
				switch (GetSelectedWizardMode (hCurPage))
				{
				case WIZARD_MODE_FILE_CONTAINER:

					if (CurrentOSMajor >= 6 && IsUacSupported() && IsAdmin() && !IsBuiltInAdmin() && !IsNonInstallMode())
					{
						static bool warningConfirmed = false;
						if (!warningConfirmed)
						{
							if (AskWarnYesNo ("CONTAINER_ADMIN_WARNING", MainDlg) == IDYES)
								exit (0);

							warningConfirmed = true;
						}
					}

					WaitCursor ();
					CloseSysEncMutex ();
					ChangeWizardMode (WIZARD_MODE_FILE_CONTAINER);
					bHiddenOS = FALSE;
					bInPlaceEncNonSys = FALSE;
					nNewPageNo = VOLUME_TYPE_PAGE - 1;	// Skip irrelevant pages
					break;

				case WIZARD_MODE_NONSYS_DEVICE:

					WaitCursor ();
					CloseSysEncMutex ();

					if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					bHiddenOS = FALSE;
					nNewPageNo = VOLUME_TYPE_PAGE - 1;	// Skip irrelevant pages
					break;

				case WIZARD_MODE_SYS_DEVICE:

					WaitCursor ();
					bHiddenVol = FALSE;
					bInPlaceEncNonSys = FALSE;
					SwitchWizardToSysEncMode ();
					return 1;
				}
			}
			else if (nCurPageNo == SYSENC_TYPE_PAGE)
			{
				if (bHiddenOS)
				{
					bWholeSysDrive = FALSE;
					bHiddenVolDirect = FALSE;
				}

				if (!bHiddenOS)
					nNewPageNo = SYSENC_SPAN_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_HIDDEN_OS_REQ_CHECK_PAGE)
			{
				WaitCursor ();
				try
				{
					BootEncObj->CheckRequirementsHiddenOS ();

					if (CheckGapBetweenSysAndHiddenOS ())
						Warning ("GAP_BETWEEN_SYS_AND_HIDDEN_OS_PARTITION", MainDlg);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (AskWarnYesNo ("DECOY_OS_REINSTALL_WARNING", MainDlg) == IDNO)
				{
					NormalCursor ();
					return 1;
				}

				WarningDirect ((wstring (GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO"))
					+ L"\n\n"
					+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str(), MainDlg);

				if (!IsAdmin() && IsUacSupported())
				{
					// If UAC elevation is needed, we need to elevate the complete wizard process here, because
					// we will need to switch to the non-sys-device mode, which requires the whole wizard process
					// to have admin rights.

					CloseSysEncMutex ();

					if (!ElevateWholeWizardProcess (L"/r"))
					{
						// Failed to obtain admin rights

						NormalCursor ();

						if (!CreateSysEncMutex ())
							AbortProcess ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE");

						return 1;
					}
				}

				// This check requires admin rights
				try
				{
					BootEncObj->InitialSecurityChecksForHiddenOS ();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					EndMainDlg (MainDlg);	// Some of the checks need the wizard to be restarted (results are cached until exit and the checks would fail even if the issues were rectified).
					return 1;
				}

				nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_SPAN_PAGE)
			{
				try
				{
					if (bWholeSysDrive && !BootEncObj->SystemPartitionCoversWholeDrive())
					{
						if (BootEncObj->SystemDriveContainsNonStandardPartitions())
						{
							if (AskWarnYesNoString ((wstring (GetString ("SYSDRIVE_NON_STANDARD_PARTITIONS")) + L"\n\n" + GetString ("ASK_ENCRYPT_PARTITION_INSTEAD_OF_DRIVE")).c_str(), MainDlg) == IDYES)
								bWholeSysDrive = FALSE;
						}
					}

					if (!bWholeSysDrive && BootEncObj->SystemPartitionCoversWholeDrive())
						bWholeSysDrive = (AskYesNo ("WHOLE_SYC_DEVICE_RECOM", hwndDlg) == IDYES);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (!bWholeSysDrive)
					nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == SYSENC_PRE_DRIVE_ANALYSIS_PAGE)
			{
				if ((SysEncDetectHiddenSectors = Get2RadButtonPageAnswer()) != 1)
				{
					// Skip drive analysis
					nNewPageNo = SYSENC_DRIVE_ANALYSIS_PAGE;

					// If the user had already searched for hidden sectors, we must clear (invalidate) the
					// result because now he changed his mind and no longer wishes to encrypt the hidden sectors.
					try
					{
						BootEncObj->InvalidateCachedSysDriveProperties ();
					}
					catch (Exception &e)
					{
						e.Show (MainDlg);
						EndMainDlg (MainDlg);
						exit(0);
					}
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
			{
				if (nMultiBoot > 1)
				{
					// Multi-boot

					if (AskWarnNoYes ("MULTI_BOOT_FOR_ADVANCED_ONLY", hwndDlg) == IDNO)
						return 1;

					if (bHiddenOS)
					{
						if (AskWarnNoYes ("HIDDEN_OS_MULTI_BOOT", hwndDlg) == IDNO)
						{
							Error ("UNSUPPORTED_HIDDEN_OS_MULTI_BOOT_CFG", hwndDlg);
							return 1;
						}
					}
				}

				if (bHiddenOS)
				{
					if (BootEncObj->GetSystemDriveConfiguration().ExtraBootPartitionPresent
						&& AskWarnYesNo ("CONFIRM_HIDDEN_OS_EXTRA_BOOT_PARTITION", hwndDlg) == IDNO)
					{
						TextInfoDialogBox (TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS);
						NormalCursor ();
						return 1;
					}

					if (AskWarnYesNo ("DECOY_OS_REQUIREMENTS", hwndDlg) == IDNO)
					{
						NormalCursor ();
						return 1;
					}

					if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					// Skip irrelevant pages
					nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE - 1;
				}
				else if ((nMultiBoot <= 1) || bSystemIsGPT)
				{
					// Single-boot (not creating a hidden OS)
					// Multi-boot in case of GPT

					// Skip irrelevant pages
					nNewPageNo = CIPHER_PAGE - 1;
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_SYS_EQ_BOOT_PAGE)
			{
				SysEncMultiBootCfg.SystemOnBootDrive = Get2RadButtonPageAnswer ();

				if (!SysEncMultiBootCfg.SystemOnBootDrive)
				{
					Error ("SYS_PARTITION_MUST_BE_ON_BOOT_DRIVE", hwndDlg);
					EndMainDlg (MainDlg);
					return 1;
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE)
			{
				if (Get2RadButtonPageAnswer () == 0)
				{
					// 2 or more drives contain an OS

					SysEncMultiBootCfg.NumberOfSysDrives = 2;
				}
				else if (Get2RadButtonPageAnswer () == 1)
				{
					// Only 1 drive contains an OS

					SysEncMultiBootCfg.NumberOfSysDrives = 1;

					if (bWholeSysDrive)
					{
						// Whole-system-drive encryption is currently not supported if the drive contains
						// more than one system
						Error ("WDE_UNSUPPORTED_FOR_MULTIPLE_SYSTEMS_ON_ONE_DRIVE", hwndDlg);
						return 1;
					}

					// Ask whether there is a non-Windows boot loader in the MBR
					nNewPageNo = SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE - 1;
				}
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE)
			{
				SysEncMultiBootCfg.MultipleSystemsOnDrive = Get2RadButtonPageAnswer ();

				if (SysEncMultiBootCfg.MultipleSystemsOnDrive && bWholeSysDrive)
				{
					// Whole-system-drive encryption is currently not supported if the drive contains
					// more than one system
					Error ("WDE_UNSUPPORTED_FOR_MULTIPLE_SYSTEMS_ON_ONE_DRIVE", hwndDlg);
					return 1;
				}
			}

			else if (nCurPageNo == SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE)
			{
				SysEncMultiBootCfg.BootLoaderBrand = Get2RadButtonPageAnswer ();

				if (SysEncMultiBootCfg.BootLoaderBrand)
				{
					// A non-Windows boot manager in the MBR
					Error ("CUSTOM_BOOT_MANAGERS_IN_MBR_UNSUPPORTED", hwndDlg);
					EndMainDlg (MainDlg);
					return 1;
				}
				else
				{
					// Either a standard Windows boot manager or no boot manager
					StringCchCopyW (SysEncMultiBootCfgOutcome, sizeof(SysEncMultiBootCfgOutcome) / 2, GetString ("WINDOWS_BOOT_LOADER_HINTS"));
				}
			}

			else if (nCurPageNo == SYSENC_MULTI_BOOT_OUTCOME_PAGE)
			{
				if (bHiddenOS)
				{
					if (!ChangeWizardMode (WIZARD_MODE_NONSYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE - 1;		// Skip irrelevant pages
				}
				else
					nNewPageNo = CIPHER_PAGE - 1;	// Skip irrelevant pages
			}

			else if (nCurPageNo == VOLUME_TYPE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDDEN_VOL)))
				{
					if (!IsAdmin() && !IsUacSupported ()
						&& IDNO == MessageBoxW (hwndDlg, GetString ("ADMIN_PRIVILEGES_WARN_HIDVOL"),
						lpszTitle, MB_ICONWARNING|MB_YESNO|MB_DEFBUTTON2))
					{
						return 1;
					}
					else
					{
						bHiddenVol = TRUE;
						bHiddenVolHost = TRUE;
						bInPlaceEncNonSys = FALSE;
					}
				}
				else
				{
					bHiddenVol = FALSE;
					bHiddenVolHost = FALSE;
					bHiddenVolDirect = FALSE;
					nNewPageNo = VOLUME_LOCATION_PAGE - 1;		// Skip the hidden volume creation wizard mode selection
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)))
					bHiddenVolDirect = TRUE;
				else
				{
					if (IsHiddenOSRunning())
					{
						WarningDirect ((wstring (GetString ("HIDDEN_VOL_CREATION_UNDER_HIDDEN_OS_HOWTO"))
							+ L"\n\n"
							+ GetString ("NOTE_BEGINNING")
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO")
							+ L" "
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str(), hwndDlg);
						NormalCursor ();
						return 1;
					}

					bHiddenVolDirect = FALSE;
				}
			}

			else if (nCurPageNo == VOLUME_LOCATION_PAGE)
			{
				BOOL tmpbDevice;

				WaitCursor();

				GetWindowTextW (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, ARRAYSIZE (szFileName));
				RelativePath2Absolute (szFileName);
				CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &tmpbDevice);

				if (tmpbDevice != bDevice)
				{
					if (bDevice)
					{
						// Not a valid device path
						Error ("CANNOT_CALC_SPACE", hwndDlg);
						NormalCursor ();
						return 1;
					}
					else
					{
						if (AskWarnYesNo ("DEVICE_SELECTED_IN_NON_DEVICE_MODE", hwndDlg) == IDNO)
						{
							NormalCursor ();
							return 1;
						}

						SwitchWizardToNonSysDeviceMode ();
						NormalCursor ();
						return 1;
					}
				}

				MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);

				if (IsMountedVolume (szDiskFile))
				{
					Error ("ALREADY_MOUNTED", hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (bDevice)
				{
					switch (IsSystemDevicePath (szDiskFile, hCurPage, TRUE))
					{
					case 1:
					case 2:
					case 3:
						if (AskYesNo ("CONFIRM_SYSTEM_ENCRYPTION_MODE", hwndDlg) == IDNO)
						{
							NormalCursor ();
							return 1;
						}
						szFileName[0] = 0;
						szDiskFile[0] = 0;
						SwitchWizardToSysEncMode ();
						NormalCursor ();
						return 1;

					case -1:
						// In some environments (such as PE), the system volume is not located on a hard drive.
						// Therefore, we must interpret this return code as "Not a system device path" (otherwise,
						// non-system devices could not be TC-formatted in such environments). Note that this is
						// rather safe, because bReliableRequired is set to TRUE.

						// NOP
						break;
					}
				}
				else
				{
					if (CheckFileExtension(szFileName)
						&& AskWarnNoYes ("EXE_FILE_EXTENSION_CONFIRM", hwndDlg) == IDNO)
					{
						NormalCursor ();
						return 1;
					}
				}

				bHistory = !IsButtonChecked (GetDlgItem (hCurPage, IDC_NO_HISTORY));

				SaveSettings (hCurPage);

				if (bHiddenVolDirect && bHiddenVolHost)
				{
					nNewPageNo = HIDDEN_VOL_HOST_PASSWORD_PAGE - 1;

					if (bDevice)
					{
						if(!QueryFreeSpace (hwndDlg, GetDlgItem (hwndDlg, IDC_SPACE_LEFT), FALSE, NULL, NULL))
						{
							MessageBoxW (hwndDlg, GetString ("CANT_GET_VOLSIZE"), lpszTitle, ICON_HAND);
							NormalCursor ();
							return 1;
						}
						else
							nHiddenVolHostSize = nVolumeSize;
					}
					else
					{
						if (!GetFileVolSize (hwndDlg, &nHiddenVolHostSize))
						{
							NormalCursor ();
							return 1;
						}
						else if (IsSparseFile (hwndDlg))
						{
							// Hidden volumes must not be created within sparse file containers
							Warning ("HIDDEN_VOL_HOST_SPARSE", hwndDlg);
							NormalCursor ();
							return 1;
						}
					}
				}
				else
				{
					if (!bHiddenVol && !bDevice)
						nNewPageNo = CIPHER_PAGE - 1;
					else if (bHiddenVol)
						nNewPageNo = (bHiddenVolHost ? HIDDEN_VOL_HOST_PRE_CIPHER_PAGE : HIDDEN_VOL_PRE_CIPHER_PAGE) - 1;
				}
			}

			else if (nCurPageNo == DEVICE_TRANSFORM_MODE_PAGE)
			{
				if (bInPlaceEncNonSys)
				{
					// Check requirements for non-system in-place encryption

					if (!CheckRequirementsForNonSysInPlaceEnc (hwndDlg, szDiskFile, FALSE))
					{
						return 1;
					}

					// We are going to skip the Size page so we must get the size here
					nVolumeSize = GetDeviceSize (szDiskFile);

					if (nVolumeSize == -1)
					{
						handleWin32Error (MainDlg, SRC_POS);
						return 1;
					}

					if (AskWarnYesNo ("NONSYS_INPLACE_ENC_CONFIRM_BACKUP", hwndDlg) == IDNO)
						return 1;
				}
				nNewPageNo = CIPHER_PAGE - 1;
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PRE_CIPHER_PAGE)
			{
				if (bHiddenVolHost)
					nNewPageNo = CIPHER_PAGE - 1;		// Skip the info on the hiddem volume
			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				if (!bSystemIsGPT && SysEncInEffect ()
					&& EAGetCipherCount (nVolumeEA) > 1)		// Cascade?
				{
					if (AskWarnNoYes ("CONFIRM_CASCADE_FOR_SYS_ENCRYPTION", hwndDlg) == IDNO)
						return 1;

					if (!bHiddenOS)
						Info ("NOTE_CASCADE_FOR_SYS_ENCRYPTION", hwndDlg);
				}

				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETCURSEL, 0, 0);
				hash_algo = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETITEMDATA, nIndex, 0);

				RandSetHashFunction (hash_algo);

				if (SysEncInEffect () || bInPlaceEncNonSys)
					nNewPageNo = PASSWORD_PAGE - 1;			// Skip irrelevant pages
			}

			else if (nCurPageNo == SIZE_PAGE)
			{
				wchar_t szFileSystemNameBuffer[256];

				VerifySizeAndUpdate (hCurPage, TRUE);

				if (!bDevice)
				{
					/* Verify that the volume would not be too large for the host file system */

					wchar_t root[TC_MAX_PATH];

					if (GetVolumePathName (szDiskFile, root, ARRAYSIZE (root))
						&& GetVolumeInformation (root, NULL, 0, NULL, NULL, NULL, szFileSystemNameBuffer, ARRAYSIZE(szFileSystemNameBuffer))
						&& !wcsncmp (szFileSystemNameBuffer, L"FAT32", 5))
					{
						// The host file system is FAT32
						if (nUIVolumeSize * nMultiplier >= 4 * BYTES_PER_GB)
						{
							Error ("VOLUME_TOO_LARGE_FOR_FAT32", hwndDlg);
							return 1;
						}
					}

				}

				if (bHiddenVol && !bHiddenVolHost)	// If it's a hidden volume
				{
					/* Ask for confirmation if the hidden volume is too large for the user to be
					able to write much more data to the outer volume. */

					if (((double) nUIVolumeSize / (nMaximumHiddenVolSize / nMultiplier)) > 0.85)	// 85%
					{
						if (AskWarnNoYes ("FREE_SPACE_FOR_WRITING_TO_OUTER_VOLUME", hwndDlg) == IDNO)
							return 1;
					}
				}

				if (!(bHiddenVolDirect && bHiddenVolHost))
					nNewPageNo = PASSWORD_PAGE - 1;
			}

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (MainDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					GetDlgItem (hCurPage, IDC_VERIFY),
					volumePassword.Text,
					szVerify,
					KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect());

				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);

				if (volumePassword.Length > 0)
				{
					// Password character encoding
					if (SysEncInEffect () && !CheckPasswordCharEncoding (GetDlgItem (hCurPage, IDC_PASSWORD), NULL))
					{
						Error ("UNSUPPORTED_CHARS_IN_PWD", hwndDlg);
						return 1;
					}
					// Check password length (check also done for outer volume which is not the case in TrueCrypt).
					else if (!CheckPasswordLength (hwndDlg, volumePassword.Length, 0, SysEncInEffect(), SysEncInEffect()? hash_algo : 0, FALSE, FALSE))
					{
						return 1;
					}
				}

				// Store the password in case we need to restore it after keyfile is applied to it
				if (!GetPassword (hCurPage, IDC_PASSWORD, szRawPassword, iMaxPasswordLength + 1, FALSE, TRUE))
					return 1;

				if (!SysEncInEffect ())
				{
					if (KeyFilesEnable)
					{
						WaitCursor ();

						if (!KeyFilesApply (hwndDlg, &volumePassword, FirstKeyFile, NULL))
						{
							NormalCursor ();
							return 1;
						}

						NormalCursor ();
					}

				}
				else
				{
					KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);

					if (bKeyboardLayoutChanged)
					{
						// Restore the original keyboard layout
						if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL)
							Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT", hwndDlg);
						else
							bKeyboardLayoutChanged = FALSE;
					}

				}

				if (!PimEnable)
				{
					// PIM not activated. Skip PIM page
					nNewPageNo = PIM_PAGE;
					volumePim = 0;

					if (!CreatingHiddenSysVol() && bHiddenVol && !bHiddenVolHost)
					{
						if (	(volumePim == outerVolumePim)
							&&	(volumePassword.Length == outerVolumePassword.Length)
							&&	(0 == memcmp (volumePassword.Text, outerVolumePassword.Text, volumePassword.Length))
							)
						{
							Warning ("HIDDEN_CREDS_SAME_AS_OUTER", hwndDlg);
							return 1;
						}
					}

					if (SysEncInEffect ())
					{
						nNewPageNo = SYSENC_COLLECTING_RANDOM_DATA_PAGE - 1;	// Skip irrelevant pages
					}

					if (bInPlaceEncNonSys)
					{
						nNewPageNo = NONSYS_INPLACE_ENC_RAND_DATA_PAGE - 1;		// Skip irrelevant pages
					}
					else if (WizardMode != WIZARD_MODE_SYS_DEVICE
						&& !FileSize4GBLimitQuestionNeeded ()
						|| CreatingHiddenSysVol())		// If we're creating a hidden volume for a hidden OS, we don't need to format it with any filesystem (the entire OS will be copied to the hidden volume sector by sector).
					{
						nNewPageNo = FORMAT_PAGE - 1;				// Skip irrelevant pages
					}

				}
			}

			else if (nCurPageNo == PIM_PAGE)
			{
				volumePim = GetPim (hCurPage, IDC_PIM, 0);

				if (!SysEncInEffect() && (volumePim > MAX_PIM_VALUE))
				{
					SetFocus (GetDlgItem(hCurPage, IDC_PIM));
					Error ("PIM_TOO_BIG", hwndDlg);
					return 1;
				}

				if (!CreatingHiddenSysVol() && bHiddenVol && !bHiddenVolHost)
				{
					if (	(volumePim == outerVolumePim)
						&&	(volumePassword.Length == outerVolumePassword.Length)
						&&	(0 == memcmp (volumePassword.Text, outerVolumePassword.Text, volumePassword.Length))
						)
					{
						Warning ("HIDDEN_CREDS_SAME_AS_OUTER", hwndDlg);
						return 1;
					}
				}

				if (volumePassword.Length > 0)
				{
					// Password character encoding
					if (SysEncInEffect() && (volumePim > MAX_BOOT_PIM_VALUE))
					{
						SetFocus (GetDlgItem(hCurPage, IDC_PIM));
						Error ("PIM_SYSENC_TOO_BIG", hwndDlg);
						return 1;
					}
					// Check password length (check also done for outer volume which is not the case in TrueCrypt).
					else if (!CheckPasswordLength (hwndDlg, volumePassword.Length, volumePim, SysEncInEffect(), SysEncInEffect()? hash_algo : 0, TRUE, FALSE))
					{
						return 1;
					}
				}

				if (SysEncInEffect ())
				{

					nNewPageNo = SYSENC_COLLECTING_RANDOM_DATA_PAGE - 1;	// Skip irrelevant pages
				}

				if (bInPlaceEncNonSys)
				{
					nNewPageNo = NONSYS_INPLACE_ENC_RAND_DATA_PAGE - 1;		// Skip irrelevant pages
				}
				else if (WizardMode != WIZARD_MODE_SYS_DEVICE
					&& !FileSize4GBLimitQuestionNeeded ()
					|| CreatingHiddenSysVol())		// If we're creating a hidden volume for a hidden OS, we don't need to format it with any filesystem (the entire OS will be copied to the hidden volume sector by sector).
				{
					nNewPageNo = FORMAT_PAGE - 1;				// Skip irrelevant pages
				}
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
			{
				WaitCursor ();

				if (!GetPassword (hCurPage, IDC_PASSWORD_DIRECT, (char*) volumePassword.Text, iMaxPasswordLength + 1, FALSE, TRUE))
				{
					NormalCursor ();
					return 1;
				}
				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);

				hash_algo = (int) SendMessage (GetDlgItem (hCurPage, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, SendMessage (GetDlgItem (hCurPage, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0), 0);

				volumePim = GetPim (hCurPage, IDC_PIM, 0);

				// Store the password in case we need to restore it after keyfile is applied to it
				if (!GetPassword (hCurPage, IDC_PASSWORD_DIRECT, szRawPassword, iMaxPasswordLength + 1, FALSE, TRUE))
				{
					NormalCursor ();
					return 1;
				}

				if (KeyFilesEnable)
				{
					KeyFilesApply (hwndDlg, &volumePassword, FirstKeyFile, NULL);
				}

				if (!bInPlaceEncNonSys)
				{

					/* Mount the volume which is to host the new hidden volume as read only */

					if (hiddenVolHostDriveNo >= 0)		// If the hidden volume host is currently mounted (e.g. after previous unsuccessful dismount attempt)
					{
						BOOL tmp_result;

						// Dismount the hidden volume host (in order to remount it as read-only subsequently)
						while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE)))
						{
							if (MessageBoxW (hwndDlg, GetString ("CANT_UNMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
							{
								// Cancel
								NormalCursor();
								return 1;
							}
						}
						if (tmp_result)		// If dismounted
							hiddenVolHostDriveNo = -1;
					}

					if (hiddenVolHostDriveNo < 0)		// If the hidden volume host is not mounted
					{
						int retCode;

						// Mount the hidden volume host as read-only (to ensure consistent and secure
						// results of the volume bitmap scanning)
						switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, hash_algo, volumePim, TRUE))
						{
						case ERR_NO_FREE_DRIVES:
							NormalCursor ();
							MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
							return 1;
						case ERR_VOL_MOUNT_FAILED:
						case ERR_PASSWORD_WRONG:
							NormalCursor ();
							return 1;
						case 0:

							/* Hidden volume host successfully mounted as read-only */

							// Verify that the outer volume contains a suitable file system, retrieve cluster size, and
							// scan the volume bitmap
							if (!IsAdmin () && IsUacSupported ())
								retCode = UacAnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);
							else
								retCode = AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);

							switch (retCode)
							{
							case -1:	// Fatal error
								CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

								if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE))
									hiddenVolHostDriveNo = -1;

								AbortProcessSilent ();
								break;

							case 0:		// Unsupported file system (or other non-fatal error which has already been reported)
								if (bHiddenVolDirect)
								{
									CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

									if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE))
										hiddenVolHostDriveNo = -1;
								}
								NormalCursor ();
								return 1;

							case 1:

								// Determine the maximum possible size of the hidden volume
								if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
								{
									// Non-fatal error while determining maximum possible size of the hidden volume
									NormalCursor();
									return 1;
								}
								else
								{
									BOOL tmp_result;

									/* Maximum possible size of the hidden volume successfully determined */

									// Dismount the hidden volume host
									while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE)))
									{
										if (MessageBoxW (hwndDlg, GetString ("CANT_UNMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
										{
											// Cancel
											NormalCursor();
											return 1;
										}
									}

									if (tmp_result)		// If dismounted
									{
										hiddenVolHostDriveNo = -1;

										bHiddenVolHost = FALSE;
										bHiddenVolFinished = FALSE;

										// save the outer volume password to use it for comparison with hidden volume one
										memcpy (&outerVolumePassword, &volumePassword, sizeof (volumePassword));
										outerVolumePim = volumePim;

										// Clear the outer volume password
										WipePasswordsAndKeyfiles (false);

										RestoreDefaultKeyFilesParam ();

										EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
										NormalCursor ();

										nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;
									}
								}
								break;
							}
							break;
						}
					}
				}
				else if (bInPlaceEncNonSysResumed)
				{
					/* Scan all available partitions to discover all partitions where non-system in-place
					encryption/decryption has been interrupted. */

					BOOL tmpbDevice;

					NormalCursor ();

					ShowWaitDialog (hwndDlg, TRUE, ResumeInPlaceEncWaitThreadProc, NULL);

					WaitCursor();

					if (DeferredNonSysInPlaceEncDevices.empty())
					{
						Warning ("FOUND_NO_PARTITION_W_DEFERRED_INPLACE_ENC", hwndDlg);

						NormalCursor();
						return 1;
					}
					else if (DeferredNonSysInPlaceEncDevices.size() == 1)
					{
						CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), DeferredNonSysInPlaceEncDevices.front().Path.c_str(), &tmpbDevice);

						nVolumeSize = GetDeviceSize (szDiskFile);
						if (nVolumeSize == -1)
						{
							handleWin32Error (MainDlg, SRC_POS);
							NormalCursor();
							return 1;
						}

						nNewPageNo = NONSYS_INPLACE_ENC_TRANSFORM_PAGE - 1;	// Skip irrelevant pages
					}

					NormalCursor();
				}
				else
				{
					/* Try to mount the non-system volume to decrypt in place (the process has not started yet, we are NOT trying to resume it).
					   We will try to mount it using the backup header, which we require to work (i.e. be non-damaged) before we start writing
					   to the volume (the primary header will be overwritten by decrypted data soon after the decryption process begins, so the
					   backup header will contain the only copy of the master key). */

					int driveNo = -1;

					// The volume may already be mounted. We need to dismount it first in order to verify the supplied password/keyfile(s) is/are correct.
					if (IsMountedVolume (szFileName))
					{
						driveNo = GetMountedVolumeDriveNo (szFileName);

						if (driveNo == -1
							|| !UnmountVolume (hwndDlg, driveNo, TRUE))
						{
							handleWin32Error (MainDlg, SRC_POS);
							AbortProcess ("CANT_UNMOUNT_VOLUME");
						}
					}

					driveNo = GetLastAvailableDrive ();

					if (driveNo < 0)
						AbortProcess ("NO_FREE_DRIVES");

					MountOptions mountOptions;
					ZeroMemory (&mountOptions, sizeof (mountOptions));

					mountOptions.UseBackupHeader = FALSE;	// This must be FALSE at this point because otherwise we wouldn't be able to detect a legacy volume
					mountOptions.ReadOnly = TRUE;
					mountOptions.Removable = ConfigReadInt ("MountVolumesRemovable", FALSE);

					// Check that it is not a hidden or legacy volume

					if (MountVolume (hwndDlg, driveNo, szFileName, &volumePassword, hash_algo, volumePim, FALSE, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
					{
						NormalCursor();
						return 1;
					}

					{
						DWORD dwResult;
						VOLUME_PROPERTIES_STRUCT volProp;

						memset (&volProp, 0, sizeof(volProp));
						volProp.driveNo = driveNo;
						if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &volProp, sizeof (volProp), &volProp, sizeof (volProp), &dwResult, NULL) || dwResult == 0)
						{
							handleWin32Error (hwndDlg, SRC_POS);
							UnmountVolume (hwndDlg, driveNo, TRUE);
							AbortProcess ("CANT_GET_VOL_INFO");
						}

						if (volProp.volFormatVersion == TC_VOLUME_FORMAT_VERSION_PRE_6_0)
						{
							UnmountVolume (hwndDlg, driveNo, TRUE);
							AbortProcess ("NONSYS_INPLACE_DECRYPTION_BAD_VOL_FORMAT");
						}

						if (volProp.hiddenVolume)
						{
							UnmountVolume (hwndDlg, driveNo, TRUE);
							AbortProcess ("NONSYS_INPLACE_DECRYPTION_CANT_DECRYPT_HID_VOL");
						}
					}

					// Remount the volume using the backup header to verify it is working

					if (!UnmountVolume (hwndDlg, driveNo, TRUE))
					{
						handleWin32Error (MainDlg, SRC_POS);
						AbortProcess ("CANT_UNMOUNT_VOLUME");
					}

					mountOptions.UseBackupHeader = TRUE;	// This must be TRUE at this point (we won't be using the regular header, which will be lost soon after the decryption process starts)

					if (MountVolume (hwndDlg, driveNo, szFileName, &volumePassword, hash_algo, volumePim, FALSE, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
					{
						NormalCursor();
						return 1;
					}

					if (!UnmountVolume (hwndDlg, driveNo, TRUE))
					{
						handleWin32Error (MainDlg, SRC_POS);
						AbortProcess ("CANT_UNMOUNT_VOLUME");
					}

					BOOL tmpbDevice;

					CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &tmpbDevice);

					nVolumeSize = GetDeviceSize (szDiskFile);
					if (nVolumeSize == -1)
					{
						handleWin32Error (MainDlg, SRC_POS);
						AbortProcessSilent ();
					}

					nNewPageNo = NONSYS_INPLACE_ENC_TRANSFORM_PAGE - 1;	// Skip irrelevant pages
					NormalCursor();
				}
			}

			else if (nCurPageNo == FILESYS_PAGE)
			{
				if (!bHiddenVol && IsHiddenOSRunning() && Get2RadButtonPageAnswer() == 1)
				{
					// The user wants to store files larger than 4GB on the non-hidden volume about to be created and a hidden OS is running

					WarningDirect ((wstring (GetString ("CANNOT_SATISFY_OVER_4G_FILE_SIZE_REQ"))
						+ L" "
						+ GetString ("CANNOT_CREATE_NON_HIDDEN_NTFS_VOLUMES_UNDER_HIDDEN_OS")
						+ L"\n\n"
						+ GetString ("NOTE_BEGINNING")
						+ GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO")
						+ L" "
						+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str(), hwndDlg);

					return 1;
				}

				if (nNeedToStoreFilesOver4GB != Get2RadButtonPageAnswer())
					fileSystem = FILESYS_NONE;	// The user may have gone back and changed the answer, so default file system must be reselected

				nNeedToStoreFilesOver4GB = Get2RadButtonPageAnswer();

				nNewPageNo = FORMAT_PAGE - 1;	// Skip irrelevant pages
			}

			else if (nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_RAND_DATA_PAGE)
			{
				wchar_t tmp[RANDPOOL_DISPLAY_SIZE+1];

				if (!bInPlaceEncNonSys)
				{
					/* Generate master key and other related data (except the rescue disk) for system encryption. */

					try
					{
						WaitCursor();
						BootEncObj->PrepareInstallation (!bWholeSysDrive, volumePassword, nVolumeEA, FIRST_MODE_OF_OPERATION_ID, hash_algo, volumePim, L"");
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
						NormalCursor ();
						return 1;
					}
				}

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI field showing portions of randpool
				wmemset (tmp, L'X', ARRAYSIZE(tmp));
				tmp [ARRAYSIZE(tmp)-1] = 0;
				SetWindowText (hRandPoolSys, tmp);

				NormalCursor ();
			}

			else if (nCurPageNo == SYSENC_KEYS_GEN_PAGE)
			{
				wchar_t tmp[KEY_GUI_VIEW_SIZE+1];

				// Attempt to wipe the GUI fields showing portions of the master and header keys
				wmemset (tmp, L'X', ARRAYSIZE(tmp));
				tmp [ARRAYSIZE(tmp)-1] = 0;
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);
			}

			else if (nCurPageNo == SYSENC_RESCUE_DISK_CREATION_PAGE)
			{
				/* Generate rescue disk for boot encryption */

				GetWindowText (GetDlgItem (hCurPage, IDC_RESCUE_DISK_ISO_PATH), szRescueDiskISO, ARRAYSIZE (szRescueDiskISO));

				bDontVerifyRescueDisk = GetCheckBox (hCurPage, IDC_SKIP_RESCUE_VERIFICATION);

				try
				{
					WaitCursor();
					BootEncObj->CreateRescueIsoImage (true, szRescueDiskISO);

				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					NormalCursor ();
					return 1;
				}

				if (!bSystemIsGPT)
				{
retryCDDriveCheck:
					if (!bDontVerifyRescueDisk && !BootEncObj->IsCDRecorderPresent())
					{
						char *multiChoiceStr[] = { 0, "CD_BURNER_NOT_PRESENT",
							"CD_BURNER_NOT_PRESENT_WILL_STORE_ISO",
							"CD_BURNER_NOT_PRESENT_WILL_CONNECT_LATER",
							"CD_BURNER_NOT_PRESENT_CONNECTED_NOW",
							0 };

						switch (AskMultiChoice ((void **) multiChoiceStr, FALSE, hwndDlg))
						{
						case 1:
							wchar_t msg[8192];
							StringCchPrintfW (msg, array_capacity (msg), GetString ("CD_BURNER_NOT_PRESENT_WILL_STORE_ISO_INFO"), szRescueDiskISO);
							WarningDirect (msg, hwndDlg);

							Warning ("RESCUE_DISK_BURN_NO_CHECK_WARN", hwndDlg);
							bDontVerifyRescueDisk = TRUE;
							nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE;
							break;

						case 2:
							AbortProcessSilent();

						case 3:
							break;

						default:
							goto retryCDDriveCheck;
						}
					}

					if (IsWindowsIsoBurnerAvailable() && !bDontVerifyRescueDisk)
						Info ("RESCUE_DISK_WIN_ISOBURN_PRELAUNCH_NOTE", hwndDlg);
				}

				NormalCursor ();
			}

			else if (nCurPageNo == SYSENC_RESCUE_DISK_BURN_PAGE)
			{
				if (!bDontVerifyRescueDisk)
				{
					/* Verify that the rescue disk has been written correctly */

					try
					{
						WaitCursor();
						if (!BootEncObj->VerifyRescueDisk ())
						{
							wchar_t szTmp[8000];

							if (bSystemIsGPT)
							{
								StringCbCopyW (szTmp, sizeof(szTmp), GetString ("RESCUE_DISK_EFI_CHECK_FAILED"));
							}
							else
							{
								StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("RESCUE_DISK_CHECK_FAILED"),
									IsWindowsIsoBurnerAvailable () ? L"" : GetString ("RESCUE_DISK_CHECK_FAILED_SENTENCE_APPENDIX"));
							}

							ErrorDirect (szTmp, hwndDlg);

							NormalCursor ();
#ifndef _DEBUG
							return 1;
#endif
						}
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
						NormalCursor ();
						return 1;
					}
					NormalCursor ();
				}
				else
				{
					Warning ("RESCUE_DISK_BURN_NO_CHECK_WARN", hwndDlg);
					nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE;		// Skip irrelevant pages
				}
			}

			else if (nCurPageNo == SYSENC_WIPE_MODE_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_WIPE_MODE_PAGE)
			{
				if (nWipeMode > 0
					&& AskWarnYesNo ("WIPE_MODE_WARN", hwndDlg) == IDNO)
					return 1;
			}

			else if (nCurPageNo == SYSENC_PRETEST_INFO_PAGE)
			{
				if (LocalizationActive
					&& AskWarnYesNo ("PREBOOT_NOT_LOCALIZED", hwndDlg) == IDNO)
					return 1;

				bConfirmQuitSysEncPretest = TRUE;

				if (!bHiddenOS)	// This text is not tailored to hidden OS
					TextInfoDialogBox (TC_TBXID_SYS_ENCRYPTION_PRETEST);

				if (AskWarnYesNo ("CONFIRM_RESTART", hwndDlg) == IDNO)
					return 1;

				/* Install the pre-boot authentication component and initiate the system encryption pretest.
				   If we are creating a hidden OS, pretest is omitted and OS cloning will follow. */

				try
				{
					WaitCursor();

#if 0
					// Make sure the Rescue Disk is not in the drive
					while (BootEncObj->VerifyRescueDisk ())
					{
						Error ("REMOVE_RESCUE_DISK_FROM_DRIVE");
					}
#endif

					BootEncObj->Install (bHiddenOS ? true : false, hash_algo);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error (bHiddenOS ? "CANNOT_INITIATE_HIDDEN_OS_CREATION" : "CANNOT_INITIATE_SYS_ENCRYPTION_PRETEST", hwndDlg);
					NormalCursor ();
					return 1;
				}


				/* Add the main TrueCrypt app to the system startup sequence (the TrueCrypt Background Task), which
				we need e.g. for notifications about prevented hibernation, about hidden OS leak protection, about
				inconsistent hidden OS installs (TrueCrypt upgraded in the decoy system but not in the hidden one), etc.
				Note that this must be done before calling ChangeSystemEncryptionStatus(), which broadcasts the change,
				so that the main app (if it's running with different cached settings) will not overwrite our new
				settings when it exits. */
				bStartOnLogon = TRUE;
				SaveSettings (NULL);
				ManageStartupSeq ();


				if (bHiddenOS)
				{
					/* When we are going to create a hidden OS, the system encryption status is set
					to SYSENC_STATUS_PRETEST (not to any special hidden-OS status), in case the XML
					configuration file and its properties somehow leaks somewhere outside the system
					partition (which will be wiped later on) indicating that a hidden OS has been created
					on the computer. Instead, we update our raw config flags in the master boot record
					(which is also altered when our boot loader is installed). */

					if (!ChangeSystemEncryptionStatus (SYSENC_STATUS_PRETEST)
						|| !ChangeHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_CLONING))
					{
						ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
						Error ("CANNOT_INITIATE_HIDDEN_OS_CREATION", hwndDlg);
						NormalCursor ();
						return 1;
					}
				}
				else if (!ChangeSystemEncryptionStatus (SYSENC_STATUS_PRETEST))
				{
					Error ("CANNOT_INITIATE_SYS_ENCRYPTION_PRETEST", hwndDlg);
					NormalCursor ();
					return 1;
				}

				// Add the wizard to the system startup sequence
				ManageStartupSeqWiz (FALSE, L"/acsysenc");

				EndMainDlg (MainDlg);

				try
				{
					BootEncObj->RestartComputer ();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
				}

				return 1;
			}

			else if (nCurPageNo == SYSENC_PRETEST_RESULT_PAGE)
			{
				TextInfoDialogBox (TC_TBXID_SYS_ENC_RESCUE_DISK);

				// Begin the actual encryption process

				ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
			}

			else if (nCurPageNo == SYSENC_ENCRYPTION_PAGE
				&& CreateSysEncMutex ())
			{
				// The 'Next' button functions as Finish or Resume

				if (SystemEncryptionStatus != SYSENC_STATUS_NONE)
				{
					try
					{
						// Resume
						SysEncResume ();
					}
					catch (Exception &e)
					{
						e.Show (hwndDlg);
					}
				}
				else
				{
					// Finish
					PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
				}

				return 1;
			}
			else if (nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PARTITION_SEL_PAGE)
			{
				nNewPageNo = NONSYS_INPLACE_ENC_TRANSFORM_PAGE - 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == NONSYS_INPLACE_ENC_TRANSFORM_PAGE)
			{
				/* In-place encryption start  (the 'Next' button has been clicked) */
				if (bInPlaceDecNonSys
					&& !bInPlaceEncNonSysResumed
					&& AskWarnYesNo ("NONSYS_INPLACE_ENC_CONFIRM_BACKUP", hwndDlg) == IDNO)
				{
					// Cancel
					return 1;
				}

				NonSysInplaceEncResume ();
				return 1;
			}
			else if (nCurPageNo == NONSYS_INPLACE_ENC_TRANSFORM_FINISHED_PAGE)
			{
				PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
				return 1;
			}
			else if (nCurPageNo == NONSYS_INPLACE_DEC_TRANSFORM_FINISHED_DRIVE_LETTER_PAGE)
			{
				BOOL bDrvLetterAssignResult = FALSE;

				int tmpDriveLetter = (int) SendMessage (GetDlgItem (hCurPage, IDC_DRIVE_LETTER_LIST),
						CB_GETITEMDATA,
						SendMessage (GetDlgItem (hCurPage, IDC_DRIVE_LETTER_LIST), CB_GETCURSEL, 0, 0),
						0);

				if (tmpDriveLetter < 0)
					tmpDriveLetter = GetFirstAvailableDrive ();

				do
				{
					wchar_t szDriveLetter[] = {L'A', L':', 0 };
					wchar_t rootPath[] = {L'A', L':', L'\\', 0 };
					wchar_t uniqVolName[MAX_PATH+1] = { 0 };

					rootPath[0] += (wchar_t) tmpDriveLetter;
					szDriveLetter[0] += (wchar_t) tmpDriveLetter;

					if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, szDiskFile))
					{
						bDrvLetterAssignResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

						DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
							szDriveLetter,
							szDiskFile);

						if (bDrvLetterAssignResult)
						{
							if (SetVolumeMountPoint (rootPath, uniqVolName) == 0)
								bDrvLetterAssignResult = FALSE;
						}
					}

					if (!bDrvLetterAssignResult)
					{
						if (AskErrYesNo ("ERR_CANNOT_ASSIGN_DRIVE_LETTER_NONSYS_DEC", hwndDlg) == IDNO)
							break;
					}

				} while (bDrvLetterAssignResult == FALSE);

				bConfirmQuit = FALSE;

				PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
				return 1;
			}
			else if (nCurPageNo == FORMAT_PAGE)
			{
				/* Format start  (the 'Next' button has been clicked on the Format page) */
				static BOOL g_bFastStartupCheckDone = FALSE;

				if (bVolTransformThreadRunning || bVolTransformThreadToRun)
					return 1;

				bVolTransformThreadCancel = FALSE;

				bVolTransformThreadToRun = TRUE;

				// check if Fast Startup is enabled and if yes then offer to disable it
				if (!g_bFastStartupCheckDone)
				{
					BOOL bHibernateEnabled = FALSE, bHiberbootEnabled = FALSE;
					if (GetHibernateStatus (bHibernateEnabled, bHiberbootEnabled) && bHiberbootEnabled)
					{
						if (AskWarnYesNo ("CONFIRM_DISABLE_FAST_STARTUP", hwndDlg) == IDYES)
						{
							if (!IsAdmin () && IsUacSupported ())
								UacWriteLocalMachineRegistryDword (hwndDlg, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", L"HiberbootEnabled", 0);
							else
								WriteLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", L"HiberbootEnabled", 0);
						}
					}
					g_bFastStartupCheckDone = true;
				}

				fileSystem = (int) SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hCurPage, IDC_FILESYS), CB_GETCURSEL, 0, 0) , 0);

				clusterSize = (int) SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), CB_GETCURSEL, 0, 0) , 0);

				formatType = (int) SendMessage (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), CB_GETITEMDATA,
					SendMessage (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), CB_GETCURSEL, 0, 0) , 0);
				quickFormat = (formatType == FORMAT_TYPE_QUICK) || (formatType == FORMAT_TYPE_FAST);
				fastCreateFile = (formatType == FORMAT_TYPE_FAST);
				dynamicFormat = IsButtonChecked (GetDlgItem (hCurPage, SPARSE_FILE));

				if (!dynamicFormat && !bDevice && !(bHiddenVol && !bHiddenVolHost) && (nVolumeSize > (ULONGLONG) nAvailableFreeSpace))
				{
					Error("VOLUME_TOO_LARGE_FOR_HOST", hwndDlg);
					bVolTransformThreadToRun = FALSE;
					return 1;
				}

				if (!bHiddenVol && IsHiddenOSRunning())
				{
					// Creating a non-hidden volume under a hidden OS

					if (fileSystem == FILESYS_NTFS || fileSystem == FILESYS_EXFAT || fileSystem == FILESYS_REFS)
					{
						WarningDirect ((wstring (GetString ("CANNOT_CREATE_NON_HIDDEN_NTFS_VOLUMES_UNDER_HIDDEN_OS"))
							+ L"\n\n"
							+ GetString ("NOTE_BEGINNING")
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_BRIEF_INFO")
							+ L" "
							+ GetString ("HIDDEN_OS_WRITE_PROTECTION_EXPLANATION")).c_str(), hwndDlg);

						if (GetVolumeDataAreaSize (FALSE, nVolumeSize) <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize()
							&& AskYesNo("OFFER_FAT_FORMAT_ALTERNATIVE", hwndDlg) == IDYES)
						{
							fileSystem = FILESYS_FAT;
							SelectAlgo (GetDlgItem (hCurPage, IDC_FILESYS), (int *) &fileSystem);
						}
						else
						{
							if (GetVolumeDataAreaSize (FALSE, nVolumeSize) > TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize())
								Info ("FAT_NOT_AVAILABLE_FOR_SO_LARGE_VOLUME", hwndDlg);

							bVolTransformThreadToRun = FALSE;
							return 1;
						}
					}
				}

				if (bHiddenVolHost)
				{
					hiddenVolHostDriveNo = -1;
					nMaximumHiddenVolSize = 0;

					if (fileSystem == FILESYS_NTFS || fileSystem == FILESYS_EXFAT)
					{
						if (bHiddenOS && (fileSystem == FILESYS_NTFS)
							&& (double) nVolumeSize / GetSystemPartitionSize() < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS)
						{
							Error("OUTER_VOLUME_TOO_SMALL_FOR_HIDDEN_OS_NTFS", hwndDlg);

							if (GetVolumeDataAreaSize (FALSE, nVolumeSize) <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize()
								&& AskYesNo("OFFER_FAT_FORMAT_ALTERNATIVE", hwndDlg) == IDYES)
							{
								fileSystem = FILESYS_FAT;
								SelectAlgo (GetDlgItem (hCurPage, IDC_FILESYS), (int *) &fileSystem);
							}
							else
							{
								if (GetVolumeDataAreaSize (FALSE, nVolumeSize) > TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize())
									Info ("FAT_NOT_AVAILABLE_FOR_SO_LARGE_VOLUME", hwndDlg);

								bVolTransformThreadToRun = FALSE;
								return 1;
							}
						}

						if (fileSystem == FILESYS_NTFS || fileSystem == FILESYS_EXFAT)	// The file system may have been changed in the previous block
						{
							if ((fileSystem == FILESYS_NTFS) && (GetVolumeDataAreaSize (FALSE, nVolumeSize) <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize())
								&& AskYesNo("HIDDEN_VOL_HOST_NTFS_ASK", hwndDlg) == IDNO)
							{
								bVolTransformThreadToRun = FALSE;
								return 1;
							}
						}
					}
				}
				else if (bHiddenVol)
				{
					// Hidden volume is always quick-formatted.
					quickFormat = TRUE;
					dynamicFormat = FALSE;
				}


				if (fileSystem == FILESYS_FAT
					&& nNeedToStoreFilesOver4GB == 1
					&& AskWarnNoYes("CONFIRM_FAT_FOR_FILES_OVER_4GB", hwndDlg) == IDNO)
				{
					bVolTransformThreadToRun = FALSE;
					return 1;
				}

				EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_FORMAT_TYPE), FALSE);
				EnableWindow (GetDlgItem (hCurPage, SPARSE_FILE), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_CLUSTERSIZE), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_FILESYS), FALSE);
				EnableWindow (GetDlgItem (hCurPage, IDC_ABORT_BUTTON), TRUE);
				SetFocus (GetDlgItem (hCurPage, IDC_ABORT_BUTTON));

				// Increase cluster size if it's too small for this volume size (causes size of
				// free space to be 0). Note that the below constant 0x2000000 is based on
				// results of tests performed under Windows XP.
				if (fileSystem == FILESYS_FAT && clusterSize > 0)
				{
					BOOL fixed = FALSE;
					while (clusterSize < 128
						&& nVolumeSize / (clusterSize * GetFormatSectorSize()) > 0x2000000)
					{
						clusterSize *= 2;
						fixed = TRUE;
					}
					if (fixed)
						MessageBoxW (hwndDlg, GetString ("CLUSTER_TOO_SMALL"), lpszTitle, MB_ICONWARNING);
				}

				LastDialogId = "FORMAT_IN_PROGRESS";
				ArrowWaitCursor ();
				_beginthread (volTransformThreadFunction, 0, MainDlg);

				return 1;
			}

			else if (nCurPageNo == FORMAT_FINISHED_PAGE)
			{
				if (!bHiddenVol || bHiddenVolFinished)
				{
					/* Wizard loop restart */

					if (bHiddenOS)
					{
						if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
							return 1;

						// Hidden volume for hidden OS has been created. Now we will prepare our boot loader
						// that will handle the OS cloning.
						try
						{
							WaitCursor();

							BootEncObj->PrepareHiddenOSCreation (nVolumeEA, FIRST_MODE_OF_OPERATION_ID, hash_algo);
						}
						catch (Exception &e)
						{
							e.Show (MainDlg);
							NormalCursor();
							return 1;
						}

						bHiddenVol = FALSE;

						LoadPage (hwndDlg, SYSENC_PRETEST_INFO_PAGE);
					}
					else
						LoadPage (hwndDlg, INTRO_PAGE);

					SetWindowTextW (GetDlgItem (MainDlg, IDCANCEL), GetString ("CANCEL"));
					bHiddenVolFinished = FALSE;
					WipePasswordsAndKeyfiles (true);

					return 1;
				}
				else
				{
					/* We're going to scan the bitmap of the hidden volume host (in the non-Direct hidden volume wizard mode) */
					int retCode;
					WaitCursor ();

					if (hiddenVolHostDriveNo != -1)		// If the hidden volume host is mounted
					{
						BOOL tmp_result;

						// Dismount the hidden volume host (in order to remount it as read-only subsequently)
						CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);
						while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE)))
						{
							if (MessageBoxW (hwndDlg, GetString ("CANT_UNMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL | MB_ICONERROR | MB_SETFOREGROUND) != IDRETRY)
							{
								// Cancel
								NormalCursor();
								return 1;
							}
						}
						if (tmp_result)		// If dismounted
							hiddenVolHostDriveNo = -1;
					}

					if (hiddenVolHostDriveNo < 0)		// If the hidden volume host is not mounted
					{
						// Remount the hidden volume host as read-only (to ensure consistent and secure
						// results of the volume bitmap scanning)
						switch (MountHiddenVolHost (hwndDlg, szDiskFile, &hiddenVolHostDriveNo, &volumePassword, hash_algo, volumePim, TRUE))
						{
						case ERR_NO_FREE_DRIVES:
							MessageBoxW (hwndDlg, GetString ("NO_FREE_DRIVE_FOR_OUTER_VOL"), lpszTitle, ICON_HAND);
							NormalCursor ();
							return 1;

						case ERR_VOL_MOUNT_FAILED:
						case ERR_PASSWORD_WRONG:
							NormalCursor ();
							return 1;

						case 0:

							/* Hidden volume host successfully mounted as read-only */

							// Verify that the outer volume contains a suitable file system, retrieve cluster size, and
							// scan the volume bitmap
							if (!IsAdmin () && IsUacSupported ())
								retCode = UacAnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);
							else
								retCode = AnalyzeHiddenVolumeHost (hwndDlg, &hiddenVolHostDriveNo, GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize), &realClusterSize, &nbrFreeClusters);

							switch (retCode)
							{
							case -1:	// Fatal error
								CloseVolumeExplorerWindows (hwndDlg, hiddenVolHostDriveNo);

								if (UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE))
									hiddenVolHostDriveNo = -1;

								AbortProcessSilent ();
								break;

							case 0:		// Unsupported file system (or other non-fatal error which has already been reported)
								NormalCursor ();
								return 1;

							case 1:		// Success
								{
									BOOL tmp_result;

									// Determine the maximum possible size of the hidden volume
									if (DetermineMaxHiddenVolSize (hwndDlg) < 1)
									{
										NormalCursor ();
										goto ovf_end;
									}

									/* Maximum possible size of the hidden volume successfully determined */

									// Dismount the hidden volume host
									while (!(tmp_result = UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE)))
									{
										if (MessageBoxW (hwndDlg, GetString ("CANT_UNMOUNT_OUTER_VOL"), lpszTitle, MB_RETRYCANCEL) != IDRETRY)
										{
											// Cancel
											NormalCursor ();
											goto ovf_end;
										}
									}

									// Prevent having to recreate the outer volume due to inadvertent exit
									bConfirmQuit = TRUE;

									hiddenVolHostDriveNo = -1;

									nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE;

									// save the outer volume password to use it for comparison with hidden volume one
									memcpy (&outerVolumePassword, &volumePassword, sizeof (volumePassword));
									outerVolumePim = volumePim;

									// Clear the outer volume password
									WipePasswordsAndKeyfiles (false);

									EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), TRUE);
									NormalCursor ();

								}
								break;
							}
							break;
						}
					}
				}
			}

			else if (nCurPageNo == DEVICE_WIPE_PAGE)
			{
				if (AskWarnOkCancel (bHiddenOS && IsHiddenOSRunning() ? "CONFIRM_WIPE_START_DECOY_SYS_PARTITION" : "CONFIRM_WIPE_START", hwndDlg) == IDOK)
				{
					WipeStart ();
					ArrowWaitCursor();
				}
				return 1;
			}

			LoadPage (hwndDlg, nNewPageNo + 1);
ovf_end:
			return 1;
		}
		else if (lw == IDC_PREV)
		{
			if (nCurPageNo == SYSENC_SPAN_PAGE)
			{
				// Skip irrelevant pages when going back
				if (!bHiddenOS)
					nNewPageNo = SYSENC_TYPE_PAGE + 1;
			}
			if (nCurPageNo == SYSENC_MULTI_BOOT_MODE_PAGE)
			{
				// Skip the drive analysis page(s) or other irrelevant pages when going back
				if (bHiddenOS)
					nNewPageNo = SYSENC_HIDDEN_OS_REQ_CHECK_PAGE + 1;
				else if (bWholeSysDrive)
					nNewPageNo = SYSENC_PRE_DRIVE_ANALYSIS_PAGE + 1;
				else
					nNewPageNo = SYSENC_SPAN_PAGE + 1;
			}
			else if (nCurPageNo == SYSENC_MULTI_BOOT_NONWIN_BOOT_LOADER_PAGE)
			{
				if (SysEncMultiBootCfg.NumberOfSysDrives == 1)
				{
					// We can skip SYSENC_MULTI_BOOT_ADJACENT_SYS_PAGE (it is implied that there are multiple systems on the drive)
					nNewPageNo = SYSENC_MULTI_BOOT_NBR_SYS_DRIVES_PAGE + 1;
				}
			}
			else if (nCurPageNo == HIDDEN_VOL_HOST_PRE_CIPHER_PAGE)
			{
				if (bHiddenOS)
				{
					if (!ChangeWizardMode (WIZARD_MODE_SYS_DEVICE))
					{
						NormalCursor ();
						return 1;
					}

					// Skip irrelevant pages.
					// Note that we're ignoring nMultiBoot here, as the multi-boot question pages are skipped
					// when creating a hidden OS (only a single message box is displayed with requirements).
					nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE + 1;
				}
				else
				{
					nNewPageNo = VOLUME_LOCATION_PAGE + 1;
				}
			}
			else if (nCurPageNo == HIDDEN_VOL_WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_HIDVOL_WIZ_MODE_DIRECT)))
					bHiddenVolDirect = TRUE;
				else
					bHiddenVolDirect = FALSE;
			}
			else if (nCurPageNo == VOLUME_TYPE_PAGE)
			{
				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
					nNewPageNo = INTRO_PAGE + 1;	// Skip irrelevant pages
			}
			else if (nCurPageNo == VOLUME_LOCATION_PAGE)
			{
				BOOL tmpbDevice;

				GetWindowText (GetDlgItem (hCurPage, IDC_COMBO_BOX), szFileName, ARRAYSIZE (szFileName));
				CreateFullVolumePath (szDiskFile, sizeof(szDiskFile), szFileName, &tmpbDevice);

				if (tmpbDevice == bDevice)
				{
					MoveEditToCombo (GetDlgItem (hCurPage, IDC_COMBO_BOX), bHistory);
					SaveSettings (hCurPage);
				}

				if (!bHiddenVol)
					nNewPageNo = VOLUME_TYPE_PAGE + 1;		// Skip the hidden volume creation wizard mode selection
			}

			else if (nCurPageNo == CIPHER_PAGE)
			{
				LPARAM nIndex;
				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETCURSEL, 0, 0);
				nVolumeEA = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX), CB_GETITEMDATA, nIndex, 0);

				nIndex = SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETCURSEL, 0, 0);
				hash_algo = (int) SendMessage (GetDlgItem (hCurPage, IDC_COMBO_BOX_HASH_ALGO), CB_GETITEMDATA, nIndex, 0);

				RandSetHashFunction (hash_algo);

				if (WizardMode == WIZARD_MODE_SYS_DEVICE)
				{
					if ((nMultiBoot > 1) && !bSystemIsGPT)
						nNewPageNo = SYSENC_MULTI_BOOT_OUTCOME_PAGE + 1;	// Skip irrelevant pages
					else
						nNewPageNo = SYSENC_MULTI_BOOT_MODE_PAGE + 1;		// Skip irrelevant pages
				}
				else if (!bHiddenVol)
					nNewPageNo = (bDevice ? DEVICE_TRANSFORM_MODE_PAGE : VOLUME_LOCATION_PAGE) + 1;
				else if (bHiddenVolHost)
					nNewPageNo = HIDDEN_VOL_HOST_PRE_CIPHER_PAGE + 1;		// Skip the info on the hidden volume
			}

			else if (nCurPageNo == SIZE_PAGE)
			{
				VerifySizeAndUpdate (hCurPage, TRUE);
			}

			else if (nCurPageNo == FILESYS_PAGE)
			{
				if (nNeedToStoreFilesOver4GB != Get2RadButtonPageAnswer())
					fileSystem = FILESYS_NONE;	// The user may have gone back and changed the answer, so default file system must be reselected

				nNeedToStoreFilesOver4GB = Get2RadButtonPageAnswer();

				nNewPageNo = (PimEnable? PIM_PAGE : PASSWORD_PAGE) + 1; // Skip PIM page if it is not enabled
			}

			else if (nCurPageNo == PASSWORD_PAGE)
			{
				// Store the password in case we need to restore it after keyfile is applied to it
				GetPassword (hCurPage, IDC_PASSWORD, szRawPassword, iMaxPasswordLength + 1, FALSE, FALSE);

				VerifyPasswordAndUpdate (hwndDlg, GetDlgItem (MainDlg, IDC_NEXT),
					GetDlgItem (hCurPage, IDC_PASSWORD),
					GetDlgItem (hCurPage, IDC_VERIFY),
					volumePassword.Text,
					szVerify,
					KeyFilesEnable && FirstKeyFile!=NULL && !SysEncInEffect ());

				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);


				nNewPageNo = SIZE_PAGE + 1;		// Skip the hidden volume host password page

				if (SysEncInEffect ())
				{
					nNewPageNo = CIPHER_PAGE + 1;				// Skip irrelevant pages

					KillTimer (hwndDlg, TIMER_ID_KEYB_LAYOUT_GUARD);

					if (bKeyboardLayoutChanged)
					{
						// Restore the original keyboard layout
						if (LoadKeyboardLayout (OrigKeyboardLayout, KLF_ACTIVATE | KLF_SUBSTITUTE_OK) == NULL)
							Warning ("CANNOT_RESTORE_KEYBOARD_LAYOUT", hwndDlg);
						else
							bKeyboardLayoutChanged = FALSE;
					}
				}
				else if (bInPlaceEncNonSys)
					nNewPageNo = CIPHER_PAGE + 1;
			}

			else if (nCurPageNo == PIM_PAGE)
			{
				volumePim = GetPim (hCurPage, IDC_PIM, 0);
			}

			else if (nCurPageNo == HIDDEN_VOL_HOST_PASSWORD_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_RESUME_PASSWORD_PAGE)
			{
				// Store the password in case we need to restore it after keyfile is applied to it
				GetPassword (hCurPage, IDC_PASSWORD_DIRECT, szRawPassword, iMaxPasswordLength + 1, FALSE, FALSE);

				memcpy (volumePassword.Text, szRawPassword, iMaxPasswordLength + 1);
				volumePassword.Length = (unsigned __int32) strlen ((char *) volumePassword.Text);

				if (!bInPlaceEncNonSys)
					nNewPageNo = VOLUME_LOCATION_PAGE + 1;
			}

			else if (nCurPageNo == SYSENC_COLLECTING_RANDOM_DATA_PAGE
				|| nCurPageNo == NONSYS_INPLACE_ENC_RAND_DATA_PAGE)
			{
				wchar_t tmp[RANDPOOL_DISPLAY_SIZE+1];

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI field showing portions of randpool
				wmemset (tmp, L'X', ARRAYSIZE(tmp));
				tmp [ARRAYSIZE(tmp)-1] = 0;
				SetWindowText (hRandPoolSys, tmp);

				nNewPageNo = (PimEnable? PIM_PAGE : PASSWORD_PAGE) + 1;		// Skip irrelevant pages
			}

			else if (nCurPageNo == SYSENC_KEYS_GEN_PAGE)
			{
				wchar_t tmp[KEY_GUI_VIEW_SIZE+1];

				// Attempt to wipe the GUI fields showing portions of the master and header keys
				wmemset (tmp, L'X', ARRAYSIZE(tmp));
				tmp [ARRAYSIZE(tmp)-1] = 0;
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);
			}

			else if (nCurPageNo == SYSENC_WIPE_MODE_PAGE)
			{
				if (bDontVerifyRescueDisk)
					nNewPageNo = SYSENC_RESCUE_DISK_VERIFIED_PAGE;	// Skip irrelevant pages
			}

			else if (nCurPageNo == FORMAT_PAGE)
			{
				wchar_t tmp[RNG_POOL_SIZE*2+1];

				KillTimer (hwndDlg, TIMER_ID_RANDVIEW);

				// Attempt to wipe the GUI fields showing portions of randpool, of the master and header keys
				wmemset (tmp, L'X', ARRAYSIZE(tmp));
				tmp [ARRAYSIZE(tmp)-1] = 0;
				SetWindowText (hRandPool, tmp);
				SetWindowText (hMasterKey, tmp);
				SetWindowText (hHeaderKey, tmp);

				if (WizardMode != WIZARD_MODE_SYS_DEVICE)
				{
					// Skip irrelevant pages

					if (FileSize4GBLimitQuestionNeeded ()
						&& !CreatingHiddenSysVol()		// If we're creating a hidden volume for a hidden OS, we don't need to format it with any filesystem (the entire OS will be copied to the hidden volume sector by sector).
						&& !bInPlaceEncNonSys)
					{
						nNewPageNo = FILESYS_PAGE + 1;
					}
					else
						nNewPageNo = (PimEnable? PIM_PAGE : PASSWORD_PAGE) + 1;
				}
			}

			LoadPage (hwndDlg, nNewPageNo - 1);

			return 1;
		}

		return 0;

	case WM_ENDSESSION:
		EndMainDlg (MainDlg);
		localcleanup ();
		return 0;

	case WM_CLOSE:
		PostMessage (hwndDlg, TC_APPMSG_FORMAT_USER_QUIT, 0, 0);
		return 1;

	case WM_NCDESTROY:
		{
			hPasswordInputField = NULL;
			hVerifyPasswordInputField = NULL;

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

void ExtractCommandLine (HWND hwndDlg, wchar_t *lpszCommandLine)
{
	wchar_t **lpszCommandLineArgs = NULL;	/* Array of command line arguments */
	int nNoCommandLineArgs;	/* The number of arguments in the array */

	if (_wcsicmp (lpszCommandLine, L"-Embedding") == 0)
	{
		ComServerMode = TRUE;
		return;
	}

	/* Extract command line arguments */
	nNoCommandLineArgs = Win32CommandLine (&lpszCommandLineArgs);
	if (nNoCommandLineArgs > 0)
	{
		int i;

		for (i = 0; i < nNoCommandLineArgs; i++)
		{
			enum
			{
				OptionHistory,
				OptionNoIsoCheck,
				OptionQuit,
				OptionTokenLib,
				OptionTokenPin,
				CommandResumeSysEncLogOn,
				CommandResumeSysEnc,
				CommandDecryptSysEnc,
				CommandEncDev,
				CommandHiddenSys,
				CommandResumeNonSysInplaceLogOn,
				CommandResumeHiddenSys,
				CommandSysEnc,
				CommandInplaceDec,
				CommandResumeInplaceDec,
				CommandResumeInplace,
				OptionEncryption,
				OptionFilesystem,
				OptionPkcs5,
				OptionPassword,
				OptionPim,
				OptionSize,
				OptionCreate,
				OptionSilent,
				OptionDynamic,
				OptionForce,
				OptionNoSizeCheck,
				OptionQuickFormat,
				OptionFastCreateFile,
				OptionEnableMemoryProtection,
				OptionKeyfile,
				OptionSecureDesktop,
			};

			argument args[]=
			{
				// Public
				{ OptionHistory,				L"/history",			L"/h", FALSE },
				{ OptionNoIsoCheck,				L"/noisocheck",		L"/n", FALSE },
				{ OptionTokenLib,				L"/tokenlib",		NULL, FALSE },
				{ OptionTokenPin,				L"/tokenpin",		NULL, FALSE },
				{ OptionQuit,					L"/quit",			L"/q", FALSE },
				{ OptionEncryption,			L"/encryption",			NULL , FALSE },
				{ OptionFilesystem,			L"/filesystem",			NULL , FALSE },
				{ OptionPkcs5,					L"/hash",			NULL , FALSE },
				{ OptionPassword,				L"/password",		NULL, FALSE },
				{ OptionPim,					L"/pim",				NULL, FALSE },
				{ OptionSize,					L"/size",				NULL, FALSE },
				{ OptionCreate,				L"/create",			NULL, FALSE },
				{ OptionSilent,				L"/silent",			NULL, FALSE },
				{ OptionDynamic,				L"/dynamic",			NULL, FALSE },
				{ OptionForce,					L"/force",			NULL, FALSE },
				{ OptionNoSizeCheck,			L"/nosizecheck",	NULL, FALSE },
				{ OptionQuickFormat,			L"/quick",	NULL, FALSE },
				{ OptionFastCreateFile,			L"/fastcreatefile",	NULL, FALSE },
				{ OptionEnableMemoryProtection,	L"/protectMemory",	NULL, FALSE },
				{ OptionKeyfile,				L"/keyfile",		L"/k", FALSE },
				{ OptionSecureDesktop,			L"/secureDesktop",	NULL, FALSE },

				// Internal
				{ CommandResumeSysEncLogOn,		L"/acsysenc",		L"/a", TRUE },
				{ CommandResumeSysEnc,			L"/csysenc",			L"/c", TRUE },
				{ CommandDecryptSysEnc,			L"/dsysenc",			L"/d", TRUE },
				{ CommandEncDev,				L"/encdev",			L"/e", TRUE },
				{ CommandHiddenSys,				L"/isysenc",			L"/i", TRUE },
				{ CommandResumeNonSysInplaceLogOn,	L"/prinplace",		L"/p", TRUE },
				{ CommandResumeHiddenSys,		L"/risysenc",		L"/r", TRUE },
				{ CommandSysEnc,				L"/sysenc",			L"/s", TRUE },
				{ CommandInplaceDec,				L"/inplacedec",		NULL, TRUE },
				{ CommandResumeInplaceDec,			L"/resumeinplacedec",NULL, TRUE },
				{ CommandResumeInplace,			L"/zinplace",		L"/z", TRUE }
			};

			argumentspec as;

			int x;

			if (lpszCommandLineArgs[i] == NULL)
				continue;

			as.args = args;
			as.arg_cnt = sizeof(args)/ sizeof(args[0]);

			x = GetArgumentID (&as, lpszCommandLineArgs[i]);

			switch (x)
			{
			case OptionCreate:
				{
					DirectCreationMode = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						szFileName, ARRAYSIZE (szFileName)))
					{
						RelativePath2Absolute (szFileName);
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;
			case OptionEncryption:
				{
					wchar_t szTmp[64] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						CmdVolumeEA = EAGetByName (szTmp);
						if (CmdVolumeEA == 0)
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
					}
				break;
			case OptionFilesystem:
				{
					wchar_t szTmp[8] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
						&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
					{
						if (_wcsicmp(szTmp, L"NONE") == 0)
							CmdVolumeFilesystem = FILESYS_NONE;
						else if (_wcsicmp(szTmp, L"FAT32") == 0 || _wcsicmp(szTmp, L"FAT") == 0)
							CmdVolumeFilesystem = FILESYS_FAT;
						else if (_wcsicmp(szTmp, L"NTFS") == 0)
							CmdVolumeFilesystem = FILESYS_NTFS;
						else if (_wcsicmp(szTmp, L"EXFAT") == 0)
							CmdVolumeFilesystem = FILESYS_EXFAT;
						else if (IsOSVersionAtLeast (WIN_10, 0) && _wcsicmp(szTmp, L"ReFS") == 0)
							CmdVolumeFilesystem = FILESYS_REFS;
						else
						{
							AbortProcess ("COMMAND_LINE_ERROR");
						}
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
						int iLen = WideCharToMultiByte (CP_UTF8, 0, szTmp, -1, (LPSTR) CmdVolumePassword.Text, iMaxPasswordLength + 1, NULL, NULL);
						burn (szTmp, sizeof (szTmp));
						if (iLen > 0)
							CmdVolumePassword.Length = (unsigned __int32) (iLen - 1);
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
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
						else if ((_wcsicmp(szTmp, L"blake2s") == 0) || (_wcsicmp(szTmp, L"blake2s-256") == 0))
							CmdVolumePkcs5 = BLAKE2S;
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
			case OptionSilent:
				Silent = TRUE;
				break;
			case OptionDynamic:
				CmdSparseFileSwitch = TRUE;
				break;
			case OptionForce:
				bForceOperation = TRUE;
				break;
			case OptionSize:
				{
					wchar_t szTmp[32] = {0};
					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs,
									&i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp))
						 && (wcslen (szTmp) >= 2)
						)
					{
						/* size can be expressed in bytes or with suffixes K, M,G or T
						 * to indicate the unit to use
						 */
						unsigned __int64 multiplier;
						wchar_t* endPtr = NULL;
						wchar_t lastChar = szTmp [wcslen (szTmp) - 1];
						if (lastChar >= L'0' && lastChar <= L'9')
							multiplier = 1;
						else if (lastChar == L'K' || lastChar == L'k')
							multiplier = BYTES_PER_KB;
						else if (lastChar == L'M' || lastChar == L'm')
							multiplier = BYTES_PER_MB;
						else if (lastChar == L'G' || lastChar == L'g')
							multiplier = BYTES_PER_GB;
						else if (lastChar == L'T' || lastChar == L't')
							multiplier = BYTES_PER_TB;
						else
							AbortProcess ("COMMAND_LINE_ERROR");

						if (multiplier != 1)
							szTmp [wcslen (szTmp) - 1] = 0;

						CmdVolumeFileSize = _wcstoui64(szTmp, &endPtr, 0);
						if (CmdVolumeFileSize == 0 || CmdVolumeFileSize == _UI64_MAX
							|| endPtr == szTmp || *endPtr != L'\0')
						{
							AbortProcess ("COMMAND_LINE_ERROR");
						}

						CmdVolumeFileSize *= multiplier;
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;
			case CommandSysEnc:
				// Encrypt system partition/drive (passed by Mount if system encryption hasn't started or to reverse decryption)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_ENCRYPT;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}

				break;

			case CommandDecryptSysEnc:
				// Decrypt system partition/drive (passed by Mount, also to reverse encryption in progress, when paused)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_DECRYPT;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}
				break;

			case CommandHiddenSys:
				// Create a hidden operating system (passed by Mount when the user selects System -> Create Hidden Operating System)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_CREATE_HIDDEN_OS;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}

				break;

			case CommandResumeHiddenSys:
				// Resume process of creation of a hidden operating system (passed by Wizard when the user needs to UAC-elevate the whole wizard process)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}

				break;

			case CommandResumeSysEnc:
				// Resume previous system-encryption operation (passed by Mount) e.g. encryption, decryption, or pretest

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_RESUME;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}
				break;

			case CommandResumeSysEncLogOn:
				// Same as csysenc but passed only by the system (from the startup sequence)

				// From now on, we should be the only instance of the TC wizard allowed to deal with system encryption
				if (CreateSysEncMutex ())
				{
					bDirectSysEncMode = TRUE;
					bDirectSysEncModeCommand = SYSENC_COMMAND_STARTUP_SEQ_RESUME;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
				}
				else
				{
					Warning ("SYSTEM_ENCRYPTION_IN_PROGRESS_ELSEWHERE", hwndDlg);
					exit(0);
				}
				break;

			case CommandEncDev:
				// Resume process of creation of a non-sys-device-hosted volume (passed by Wizard when the user needs to UAC-elevate)
				DirectDeviceEncMode = TRUE;
				break;

			case CommandInplaceDec:
				// Start (not resume) decrypting the specified non-system volume in place
				{
					wchar_t szTmp [TC_MAX_PATH + 8000] = {0};

					if ((HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)))
						&& (wcslen (szTmp) >= 1)
						)
					{
						memset (szFileName, 0, sizeof (szFileName));
						StringCbCopyW (szFileName, sizeof (szFileName), szTmp);
						DirectNonSysInplaceDecStartMode = TRUE;
					}
					else
					{
						// No valid volume path specified as command-line parameter
						AbortProcess ("ERR_PARAMETER_INCORRECT");
					}
				}
				break;

			case CommandResumeInplace:
				// Resume interrupted process of non-system in-place encryption of a partition
				DirectNonSysInplaceEncResumeMode = TRUE;
				break;

			case CommandResumeInplaceDec:
				// Resume interrupted process of non-system in-place decryption of a partition
				DirectNonSysInplaceDecResumeMode = TRUE;
				break;

			case CommandResumeNonSysInplaceLogOn:
				// Ask the user whether to resume interrupted process of non-system in-place encryption of a partition
				// This switch is passed only by the system (from the startup sequence).
				DirectPromptNonSysInplaceEncResumeMode = TRUE;
				break;

			case OptionNoIsoCheck:
				bDontVerifyRescueDisk = TRUE;
				break;

			case OptionNoSizeCheck:
				bDontCheckFileContainerSize = TRUE;
				break;

			case OptionQuickFormat:
				CmdQuickFormat = TRUE;
				break;

			case OptionFastCreateFile:
				CmdFastCreateFile = TRUE;
				break;

			case OptionEnableMemoryProtection:
				EnableMemoryProtection = TRUE;
				break;

			case OptionHistory:
				{
					wchar_t szTmp[8] = {0};
					bHistory = bHistoryCmdLine = TRUE;

					if (HAS_ARGUMENT == GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs,
						     szTmp, ARRAYSIZE (szTmp)))
					{
						if (!_wcsicmp(szTmp,L"y") || !_wcsicmp(szTmp,L"yes"))
						{
							bHistory = TRUE;
						}

						else if (!_wcsicmp(szTmp,L"n") || !_wcsicmp(szTmp,L"no"))
						{
							bHistory = FALSE;
						}
						else
							AbortProcess ("COMMAND_LINE_ERROR");
					}
				}
				break;

			case OptionTokenLib:
				if (GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, SecurityTokenLibraryPath, ARRAYSIZE (SecurityTokenLibraryPath)) == HAS_ARGUMENT)
					InitSecurityTokenLibrary(hwndDlg);
				else
					AbortProcess ("COMMAND_LINE_ERROR");

				break;

			case OptionTokenPin:
				{
					wchar_t szTmp[SecurityToken::MaxPasswordLength + 1] = {0};  // TODO Use Token
					if (GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)) == HAS_ARGUMENT)
					{
						if (0 == WideCharToMultiByte (CP_UTF8, 0, szTmp, -1, CmdTokenPin, TC_MAX_PATH, nullptr, nullptr))
							AbortProcess ("COMMAND_LINE_ERROR");
					}
					else
						AbortProcess ("COMMAND_LINE_ERROR");
				}

				break;

			case OptionQuit:
				{
					// Used to indicate non-install elevation
					wchar_t szTmp[32];
					if (GetArgumentValue (lpszCommandLineArgs, &i, nNoCommandLineArgs, szTmp, ARRAYSIZE (szTmp)) != HAS_ARGUMENT)
						AbortProcess ("COMMAND_LINE_ERROR");
				}
				break;

			case OptionKeyfile:
				{
					wchar_t tmpPath [2 * TC_MAX_PATH] = {0};
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

			default:
				DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_COMMANDHELP_DLG), hwndDlg, (DLGPROC)
						CommandHelpDlgProc, (LPARAM) &as);

				exit(0);
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


int DetermineMaxHiddenVolSize (HWND hwndDlg)
{
	__int64 nbrReserveBytes;

	if (nbrFreeClusters * realClusterSize < TC_MIN_HIDDEN_VOLUME_SIZE)
	{
		MessageBoxW (hwndDlg, GetString ("NO_SPACE_FOR_HIDDEN_VOL"), lpszTitle, ICON_HAND);
		UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE);
		AbortProcessSilent ();
	}

	// Add a reserve (in case the user mounts the outer volume and creates new files
	// on it by accident or OS writes some new data behind his or her back, such as
	// System Restore etc.)
	nbrReserveBytes = GetVolumeDataAreaSize (FALSE, nHiddenVolHostSize) / 200;
	if (nbrReserveBytes > BYTES_PER_MB * 10)
		nbrReserveBytes = BYTES_PER_MB * 10;

	// Compute the final value

	nMaximumHiddenVolSize = nbrFreeClusters * realClusterSize - TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE - nbrReserveBytes;
	nMaximumHiddenVolSize -= nMaximumHiddenVolSize % realClusterSize;		// Must be a multiple of the sector size

	if (nMaximumHiddenVolSize < TC_MIN_HIDDEN_VOLUME_SIZE)
	{
		MessageBoxW (hwndDlg, GetString ("NO_SPACE_FOR_HIDDEN_VOL"), lpszTitle, ICON_HAND);
		UnmountVolume (hwndDlg, hiddenVolHostDriveNo, TRUE);
		AbortProcessSilent ();
	}

	// Prepare the hidden volume size parameters
	if (nMaximumHiddenVolSize < BYTES_PER_MB)
		nMultiplier = BYTES_PER_KB;
	else if (nMaximumHiddenVolSize < BYTES_PER_GB)
		nMultiplier = BYTES_PER_MB;
	else if (nMaximumHiddenVolSize < BYTES_PER_TB)
		nMultiplier = BYTES_PER_GB;
	else
		nMultiplier = BYTES_PER_TB;

	nUIVolumeSize = 0;								// Set the initial value for the hidden volume size input field to the max
	nVolumeSize = nUIVolumeSize * nMultiplier;		// Chop off possible remainder

	return 1;
}


// Tests whether the file system of the given volume is suitable to host a hidden volume,
// retrieves the cluster size, and scans the volume cluster bitmap. In addition, checks
// the TrueCrypt volume format version and the type of volume.
int AnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *pRealClusterSize, __int64 *pnbrFreeClusters)
{
	HANDLE hDevice;
	DWORD bytesReturned;
	DWORD dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters;
	DWORD dwResult;
	int result;
	wchar_t szFileSystemNameBuffer[256];
	wchar_t tmpPath[7] = {L'\\',L'\\',L'.',L'\\',(wchar_t) (*driveNo + L'A'),L':',0};
	wchar_t szRootPathName[4] = {(wchar_t) (*driveNo + L'A'), L':', L'\\', 0};
	BYTE readBuffer[TC_MAX_VOLUME_SECTOR_SIZE * 2];
	LARGE_INTEGER offset, offsetNew;
	VOLUME_PROPERTIES_STRUCT volProp;

	memset (&volProp, 0, sizeof(volProp));
	volProp.driveNo = *driveNo;
	if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &volProp, sizeof (volProp), &volProp, sizeof (volProp), &dwResult, NULL) || dwResult == 0)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		Error ("CANT_ACCESS_OUTER_VOL", hwndDlg);
		goto efsf_error;
	}

	if (volProp.volFormatVersion < TC_VOLUME_FORMAT_VERSION)
	{
		// We do not support creating hidden volumes within volumes created by TrueCrypt 5.1a or earlier.
		Error ("ERR_VOL_FORMAT_BAD", hwndDlg);
		return 0;
	}

	if (volProp.hiddenVolume)
	{
		// The user entered a password for a hidden volume
		Error ("ERR_HIDDEN_NOT_NORMAL_VOLUME", hwndDlg);
		return 0;
	}

	if (volProp.volumeHeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC
		|| volProp.volumeHeaderFlags & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)
	{
		Warning ("ERR_HIDDEN_VOL_HOST_ENCRYPTED_INPLACE", hwndDlg);
		return 0;
	}

	hDevice = CreateFile (tmpPath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto efsf_error;
	}

	offset.QuadPart = 0;

	if (SetFilePointerEx (hDevice, offset, &offsetNew, FILE_BEGIN) == 0)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		goto efs_error;
	}

	result = ReadFile (hDevice, &readBuffer, TC_MAX_VOLUME_SECTOR_SIZE, &bytesReturned, NULL);

	if (result == 0)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto efs_error;
	}

	CloseHandle (hDevice);
	hDevice = INVALID_HANDLE_VALUE;

	// Determine file system type

	GetVolumeInformation(szRootPathName, NULL, 0, NULL, NULL, NULL, szFileSystemNameBuffer, ARRAYSIZE(szFileSystemNameBuffer));

	// The Windows API sometimes fails to indentify the file system correctly so we're using "raw" analysis too.
	if (!wcsncmp (szFileSystemNameBuffer, L"FAT", 3)
		|| (readBuffer[0x36] == 'F' && readBuffer[0x37] == 'A' && readBuffer[0x38] == 'T')
		|| (readBuffer[0x52] == 'F' && readBuffer[0x53] == 'A' && readBuffer[0x54] == 'T'))
	{
		// FAT12/FAT16/FAT32

		// Retrieve the cluster size
		*pRealClusterSize = ((int) readBuffer[0xb] + ((int) readBuffer[0xc] << 8)) * (int) readBuffer[0xd];

		// Get the map of the clusters that are free and in use on the outer volume.
		// The map will be scanned to determine the size of the uninterrupted block of free
		// space (provided there is any) whose end is aligned with the end of the volume.
		// The value will then be used to determine the maximum possible size of the hidden volume.
		if (*pRealClusterSize > 0)
		{
			return ScanVolClusterBitmap (hwndDlg,
				driveNo,
				hiddenVolHostSize / *pRealClusterSize,
				pnbrFreeClusters);
		}
		else
		{
			// should never happen
			return -1;
		}
	}
	else if (!wcsncmp (szFileSystemNameBuffer, L"NTFS", 4) || !_wcsnicmp (szFileSystemNameBuffer, L"exFAT", 5))
	{
		// NTFS
		bool bIsNtfs = (0 == wcsncmp (szFileSystemNameBuffer, L"NTFS", 4));

		if (bIsNtfs && bHiddenVolDirect && GetVolumeDataAreaSize (FALSE, hiddenVolHostSize) <= TC_MAX_FAT_SECTOR_COUNT * GetFormatSectorSize())
			Info ("HIDDEN_VOL_HOST_NTFS", hwndDlg);

		if (!GetDiskFreeSpace(szRootPathName,
			&dwSectorsPerCluster,
			&dwBytesPerSector,
			&dwNumberOfFreeClusters,
			&dwTotalNumberOfClusters))
		{
			handleWin32Error (hwndDlg, SRC_POS);
			Error ("CANT_GET_OUTER_VOL_INFO", hwndDlg);
			return -1;
		};

		*pRealClusterSize = dwBytesPerSector * dwSectorsPerCluster;

		// Get the map of the clusters that are free and in use on the outer volume.
		// The map will be scanned to determine the size of the uninterrupted block of free
		// space (provided there is any) whose end is aligned with the end of the volume.
		// The value will then be used to determine the maximum possible size of the hidden volume.

		return ScanVolClusterBitmap (hwndDlg,
			driveNo,
			hiddenVolHostSize / *pRealClusterSize,
			pnbrFreeClusters);
	}
	else
	{
		// Unsupported file system

		Error ("HIDDEN_VOL_HOST_UNSUPPORTED_FILESYS", hwndDlg);
		return 0;
	}

efs_error:
	CloseHandle (hDevice);

efsf_error:
	CloseVolumeExplorerWindows (hwndDlg, *driveNo);

	return -1;
}


// Mounts a volume within which the user intends to create a hidden volume
int MountHiddenVolHost (HWND hwndDlg, wchar_t *volumePath, int *driveNo, Password *password, int pkcs5_prf, int pim, BOOL bReadOnly)
{
	MountOptions mountOptions;
	ZeroMemory (&mountOptions, sizeof (mountOptions));

	*driveNo = GetLastAvailableDrive ();

	if (*driveNo == -1)
	{
		*driveNo = -2;
		return ERR_NO_FREE_DRIVES;
	}

	mountOptions.ReadOnly = bReadOnly;
	mountOptions.Removable = ConfigReadInt ("MountVolumesRemovable", FALSE);
	mountOptions.ProtectHiddenVolume = FALSE;
	mountOptions.PreserveTimestamp = bPreserveTimestamp;
	mountOptions.PartitionInInactiveSysEncScope = FALSE;
	mountOptions.UseBackupHeader = FALSE;

	if (MountVolume (hwndDlg, *driveNo, volumePath, password, pkcs5_prf, pim, FALSE, FALSE, TRUE, &mountOptions, FALSE, TRUE) < 1)
	{
		*driveNo = -3;
		return ERR_VOL_MOUNT_FAILED;
	}
	return 0;
}


/* Gets the map of the clusters that are free and in use on a volume that is to host
   a hidden volume. The map is scanned to determine the size of the uninterrupted
   area of free space (provided there is any) whose end is aligned with the end
   of the volume. The value will then be used to determine the maximum possible size
   of the hidden volume. */
int ScanVolClusterBitmap (HWND hwndDlg, int *driveNo, __int64 nbrClusters, __int64 *pnbrFreeClusters)
{
	PVOLUME_BITMAP_BUFFER lpOutBuffer;
	STARTING_LCN_INPUT_BUFFER lpInBuffer;

	HANDLE hDevice;
	DWORD lBytesReturned;
	BYTE rmnd;
	wchar_t tmpPath[7] = {L'\\',L'\\',L'.',L'\\', (wchar_t) (*driveNo + L'A'), L':', 0};

	DWORD bufLen;
	__int64 bitmapCnt;

	hDevice = CreateFile (tmpPath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBoxW (hwndDlg, GetString ("CANT_ACCESS_OUTER_VOL"), lpszTitle, ICON_HAND);
		goto vcmf_error;
	}

	bufLen = (DWORD) (nbrClusters / 8 + 2 * sizeof(LARGE_INTEGER));
	bufLen += 100000 + bufLen/10;	// Add reserve

	lpOutBuffer = (PVOLUME_BITMAP_BUFFER) malloc (bufLen);

	if (lpOutBuffer == NULL)
	{
		MessageBoxW (hwndDlg, GetString ("ERR_MEM_ALLOC"), lpszTitle, ICON_HAND);
		goto vcm_error;
	}

	lpInBuffer.StartingLcn.QuadPart = 0;

	if ( !DeviceIoControl (hDevice,
		FSCTL_GET_VOLUME_BITMAP,
		&lpInBuffer,
		sizeof(lpInBuffer),
		lpOutBuffer,
		bufLen,
		&lBytesReturned,
		NULL))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		MessageBoxW (hwndDlg, GetString ("CANT_GET_CLUSTER_BITMAP"), lpszTitle, ICON_HAND);

		goto vcm_error;
	}

	rmnd = (BYTE) (lpOutBuffer->BitmapSize.QuadPart % 8);

	if ((rmnd != 0)
	&& ((lpOutBuffer->Buffer[lpOutBuffer->BitmapSize.QuadPart / 8] & ((1 << rmnd)-1) ) != 0))
	{
		*pnbrFreeClusters = 0;
	}
	else
	{
		*pnbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart;
		bitmapCnt = lpOutBuffer->BitmapSize.QuadPart / 8;

		// Scan the bitmap from the end
		while (--bitmapCnt >= 0)
		{
			if (lpOutBuffer->Buffer[bitmapCnt] != 0)
			{
				// There might be up to 7 extra free clusters in this byte of the bitmap.
				// These are ignored because there is always a cluster reserve added anyway.
				*pnbrFreeClusters = lpOutBuffer->BitmapSize.QuadPart - ((bitmapCnt + 1) * 8);
				break;
			}
		}
	}

	CloseHandle (hDevice);
	free(lpOutBuffer);
	return 1;

vcm_error:
	CloseHandle (hDevice);
	if (lpOutBuffer) free(lpOutBuffer);

vcmf_error:
	return -1;
}


// Wipe the hidden OS config flag bits in the MBR
static BOOL WipeHiddenOSCreationConfig (void)
{
	if (!IsHiddenOSRunning())
	{
		try
		{
			WaitCursor();
			finally_do ({ NormalCursor(); });

			BootEncObj->WipeHiddenOSCreationConfig();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
			return FALSE;
		}
	}

	return TRUE;
}


// Tasks that need to be performed after the WM_INITDIALOG message for the SYSENC_ENCRYPTION_PAGE dialog is
// handled should be done here (otherwise the UAC prompt causes the GUI to be only half-rendered).
static void AfterSysEncProgressWMInitTasks (HWND hwndDlg)
{
	try
	{
		switch (SystemEncryptionStatus)
		{
		case SYSENC_STATUS_ENCRYPTING:

			if (BootEncStatus.ConfiguredEncryptedAreaStart == BootEncStatus.EncryptedAreaStart
				&& BootEncStatus.ConfiguredEncryptedAreaEnd == BootEncStatus.EncryptedAreaEnd)
			{
				// The partition/drive had been fully encrypted

				ManageStartupSeqWiz (TRUE, L"");
				WipeHiddenOSCreationConfig();	// For extra conservative security
				ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

				Info ("SYSTEM_ENCRYPTION_FINISHED", hwndDlg);
				EndMainDlg (MainDlg);
				return;
			}
			else
			{
				SysEncResume ();
			}

			break;

		case SYSENC_STATUS_DECRYPTING:
			SysEncResume ();
			break;

		default:

			// Unexpected mode here -- fix the inconsistency

			ManageStartupSeqWiz (TRUE, L"");
			ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
			EndMainDlg (MainDlg);
			InconsistencyResolved (SRC_POS);
			return;
		}
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
		EndMainDlg (MainDlg);
		return;
	}

	InitSysEncProgressBar ();

	UpdateSysEncProgressBar ();

	UpdateSysEncControls ();
}


// Tasks that need to be performed after the WM_INITDIALOG message is handled must be done here.
// For example, any tasks that may invoke the UAC prompt (otherwise the UAC dialog box would not be on top).
static void AfterWMInitTasks (HWND hwndDlg)
{
	// Note that if bDirectSysEncModeCommand is not SYSENC_COMMAND_NONE, we already have the mutex.

	// SYSENC_COMMAND_DECRYPT has the highest priority because it also performs uninstallation (restores the
	// original contents of the first drive cylinder, etc.) so it must be attempted regardless of the phase
	// or content of configuration files.
	if (bDirectSysEncModeCommand == SYSENC_COMMAND_DECRYPT)
	{
		if (IsHiddenOSRunning())
		{
			Warning ("CANNOT_DECRYPT_HIDDEN_OS", hwndDlg);
			AbortProcessSilent();
		}

		// Add the wizard to the system startup sequence
		ManageStartupSeqWiz (FALSE, L"/acsysenc");

		ChangeSystemEncryptionStatus (SYSENC_STATUS_DECRYPTING);
		LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
		return;
	}


	if (SystemEncryptionStatus == SYSENC_STATUS_ENCRYPTING
		|| SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING)
	{
		try
		{
			BootEncStatus = BootEncObj->GetStatus();

			if (!BootEncStatus.DriveMounted)
			{
				if (!BootEncStatus.DeviceFilterActive)
				{
					// This is an inconsistent state. SystemEncryptionStatus should never be SYSENC_STATUS_ENCRYPTING
					// or SYSENC_STATUS_DECRYPTING when the drive filter is not active. Possible causes: 1) corrupted
					// or stale config file, 2) corrupted system

					// Fix the inconsistency
					ManageStartupSeqWiz (TRUE, L"");
					ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
					EndMainDlg (MainDlg);
					InconsistencyResolved (SRC_POS);
					return;
				}
				else if (bDirectSysEncMode)
				{
					// This is an inconsistent state. We have a direct system encryption command,
					// SystemEncryptionStatus is SYSENC_STATUS_ENCRYPTING or SYSENC_STATUS_DECRYPTING, the
					// system drive is not 'mounted' and drive filter is active.  Possible causes: 1) The drive had
					// been decrypted in the pre-boot environment. 2) The OS is not located on the lowest partition,
					// the drive is to be fully encrypted, but the user rebooted before encryption reached the
					// system partition and then pressed Esc in the boot loader screen. 3) Corrupted or stale config
					// file. 4) Damaged system.

					Warning ("SYSTEM_ENCRYPTION_SCHEDULED_BUT_PBA_FAILED", hwndDlg);
					EndMainDlg (MainDlg);
					return;
				}
			}
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}
	}


	if (SystemEncryptionStatus != SYSENC_STATUS_PRETEST)
	{
		// Handle system encryption command line arguments (if we're not in the Pretest phase).
		// Note that if bDirectSysEncModeCommand is not SYSENC_COMMAND_NONE, we already have the mutex.
		// Also note that SYSENC_COMMAND_DECRYPT is handled above.

		switch (bDirectSysEncModeCommand)
		{
		case SYSENC_COMMAND_RESUME:
		case SYSENC_COMMAND_STARTUP_SEQ_RESUME:

			if (bDirectSysEncModeCommand == SYSENC_COMMAND_STARTUP_SEQ_RESUME
				&& AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT", hwndDlg) == IDNO)
			{
				EndMainDlg (MainDlg);
				return;
			}

			if (SysEncryptionOrDecryptionRequired ())
			{
				if (SystemEncryptionStatus != SYSENC_STATUS_ENCRYPTING
					&& SystemEncryptionStatus != SYSENC_STATUS_DECRYPTING)
				{
					// If the config file with status was lost or not written correctly, we
					// don't know whether to encrypt or decrypt (but we know that encryption or
					// decryption is required). Ask the user to select encryption, decryption,
					// or cancel
					if (!ResolveUnknownSysEncDirection ())
					{
						EndMainDlg (MainDlg);
						return;
					}
				}

				LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
				return;
			}
			else
			{
				// Nothing to resume
				Warning ("NO_SYS_ENC_PROCESS_TO_RESUME", hwndDlg);
				EndMainDlg (MainDlg);

				return;
			}
			break;

		case SYSENC_COMMAND_ENCRYPT:

			if (SysDriveOrPartitionFullyEncrypted (FALSE))
			{
				Info ("SYS_PARTITION_OR_DRIVE_APPEARS_FULLY_ENCRYPTED", hwndDlg);
				EndMainDlg (MainDlg);
				return;
			}

			if (SysEncryptionOrDecryptionRequired ())
			{
				// System partition/drive encryption process already initiated but is incomplete.
				// If we were encrypting, resume the process directly. If we were decrypting, reverse
				// the process and start encrypting.

				ChangeSystemEncryptionStatus (SYSENC_STATUS_ENCRYPTING);
				LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
				return;
			}
			else
			{
				// Initiate the Pretest preparation phase
				if (!SwitchWizardToSysEncMode ())
				{
					bDirectSysEncMode = FALSE;
					EndMainDlg (MainDlg);
				}
				return;
			}

			break;

		case SYSENC_COMMAND_CREATE_HIDDEN_OS_ELEV:
		case SYSENC_COMMAND_CREATE_HIDDEN_OS:

			if (!SwitchWizardToHiddenOSMode ())
			{
				bDirectSysEncMode = FALSE;
				EndMainDlg (MainDlg);
			}
			return;
		}
	}


	if (!bDirectSysEncMode
		|| bDirectSysEncMode && SystemEncryptionStatus == SYSENC_STATUS_NONE)
	{
		// Handle system encryption cases where the wizard did not start even though it
		// was added to the startup sequence, as well as other weird cases and "leftovers"

		if (SystemEncryptionStatus != SYSENC_STATUS_NONE
			&& SystemEncryptionStatus != SYSENC_STATUS_PRETEST
			&& SysEncryptionOrDecryptionRequired ())
		{
			// System encryption/decryption had been in progress and did not finish

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				if (AskWarnYesNo ("SYSTEM_ENCRYPTION_RESUME_PROMPT", hwndDlg) == IDYES)
				{
					bDirectSysEncMode = TRUE;
					ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);
					LoadPage (hwndDlg, SYSENC_ENCRYPTION_PAGE);
					return;
				}
				else
					CloseSysEncMutex ();
			}
		}

		else if (SystemEncryptionStatus == SYSENC_STATUS_PRETEST)
		{
			// System pretest had been in progress but we were not launched during the startup seq

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				// The pretest has "priority handling"
				bDirectSysEncMode = TRUE;
				ChangeWizardMode (WIZARD_MODE_SYS_DEVICE);

				/* Do not return yet -- the principal pretest handler is below. */
			}
		}

		else if ((SystemEncryptionStatus == SYSENC_STATUS_NONE || SystemEncryptionStatus == SYSENC_STATUS_DECRYPTING)
			&& !BootEncStatus.DriveEncrypted
			&& (BootEncStatus.DriveMounted || BootEncStatus.VolumeHeaderPresent))
		{
			// The pretest may have been in progress but we can't be sure (it is not in the config file).
			// Another possibility is that the user had finished decrypting the drive, but the config file
			// was not correctly updated. In both cases the best thing we can do is remove the header and
			// deinstall. Otherwise, the result might be some kind of deadlock.

			if (CreateSysEncMutex ())	// If no other instance is currently taking care of system encryption
			{
				WaitCursor ();

				ForceRemoveSysEnc();

				InconsistencyResolved (SRC_POS);

				NormalCursor();
				CloseSysEncMutex ();
			}
		}
	}

	if (bDirectSysEncMode && CreateSysEncMutex ())
	{
		// We were launched either by Mount or by the system (startup sequence). Most of such cases should have
		// been handled above already. Here we handle only the pretest phase (which can also be a hidden OS
		// creation phase actually) and possible inconsistencies.

		switch (SystemEncryptionStatus)
		{
		case SYSENC_STATUS_PRETEST:
			{
				unsigned int hiddenOSCreationPhase = DetermineHiddenOSCreationPhase();

				bHiddenOS = (hiddenOSCreationPhase != TC_HIDDEN_OS_CREATION_PHASE_NONE);

				// Evaluate the results of the system encryption pretest (or of the hidden OS creation process)

				try
				{
					BootEncStatus = BootEncObj->GetStatus();
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					Error ("ERR_GETTING_SYSTEM_ENCRYPTION_STATUS", hwndDlg);
					EndMainDlg (MainDlg);
					return;
				}

				if (BootEncStatus.DriveMounted)
				{
					/* Pretest successful or hidden OS has been booted during the process of hidden OS creation. */

					switch (hiddenOSCreationPhase)
					{
					case TC_HIDDEN_OS_CREATION_PHASE_NONE:

						// Pretest successful (or the hidden OS has been booted for the first time since the user started installing a new decoy OS)

						if (IsHiddenOSRunning())
						{
							// The hidden OS has been booted for the first time since the user started installing a
							// new decoy OS (presumably, our MBR config flags have been erased).

							// As for things we are responsible for, the process of hidden OS creation is completed
							// (the rest is up to the user).

							ManageStartupSeqWiz (TRUE, L"");
							ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);

							EndMainDlg (MainDlg);

							return;
						}

						// Pretest successful (no hidden operating system involved)

						LoadPage (hwndDlg, SYSENC_PRETEST_RESULT_PAGE);
						return;

					case TC_HIDDEN_OS_CREATION_PHASE_WIPING:

						// Hidden OS has been booted when we are supposed to wipe the original OS

						LoadPage (hwndDlg, SYSENC_HIDDEN_OS_INITIAL_INFO_PAGE);
						return;

					case TC_HIDDEN_OS_CREATION_PHASE_WIPED:

						// Hidden OS has been booted and the original OS wiped. Now the user is required to install a new, decoy, OS.

						TextInfoDialogBox (TC_TBXID_DECOY_OS_INSTRUCTIONS);

						EndMainDlg (MainDlg);
						return;

					default:

						// Unexpected/unknown status
						ReportUnexpectedState (SRC_POS);
						EndMainDlg (MainDlg);
						return;
					}
				}
				else
				{
					BOOL bAnswerTerminate = FALSE, bAnswerRetry = FALSE;

					/* Pretest failed
					or hidden OS cloning has been interrupted (and non-hidden OS is running)
					or wiping of the original OS has not been started (and non-hidden OS is running) */

					if (hiddenOSCreationPhase == TC_HIDDEN_OS_CREATION_PHASE_NONE)
					{
						// Pretest failed (no hidden operating system involved)

						if (AskWarnYesNo ("BOOT_PRETEST_FAILED_RETRY", hwndDlg) == IDYES)
						{
							// User wants to retry the pretest
							bAnswerTerminate = FALSE;
							bAnswerRetry = TRUE;
						}
						else
						{
							// User doesn't want to retry the pretest
							bAnswerTerminate = TRUE;
							bAnswerRetry = FALSE;
						}
					}
					else
					{
						// Hidden OS cloning was interrupted or wiping of the original OS has not been started

						char *tmpStr[] = {0,
							hiddenOSCreationPhase == TC_HIDDEN_OS_CREATION_PHASE_WIPING ? "OS_WIPING_NOT_FINISHED_ASK" : "HIDDEN_OS_CREATION_NOT_FINISHED_ASK",
							"HIDDEN_OS_CREATION_NOT_FINISHED_CHOICE_RETRY",
							"HIDDEN_OS_CREATION_NOT_FINISHED_CHOICE_TERMINATE",
							"HIDDEN_OS_CREATION_NOT_FINISHED_CHOICE_ASK_LATER",
							0};

						switch (AskMultiChoice ((void **) tmpStr, FALSE, hwndDlg))
						{
						case 1:
							// User wants to restart and continue/retry
							bAnswerTerminate = FALSE;
							bAnswerRetry = TRUE;
							break;

						case 2:
							// User doesn't want to retry but wants to terminate the entire process of hidden OS creation
							bAnswerTerminate = TRUE;
							bAnswerRetry = FALSE;
							break;

						default:
							// User doesn't want to do anything now
							bAnswerTerminate = FALSE;
							bAnswerRetry = FALSE;
						}
					}


					if (bAnswerRetry)
					{
						// User wants to restart and retry the pretest (or hidden OS creation)

						// We re-register the driver for boot because the user may have selected
						// "Last Known Good Configuration" from the Windows boot menu.
						// Note that we need to do this even when creating a hidden OS (because
						// the hidden OS needs our boot driver and it will be a clone of this OS).
						try
						{
							BootEncObj->RegisterBootDriver (bHiddenOS ? true : false);
						}
						catch (Exception &e)
						{
							e.Show (NULL);
						}

						if (AskWarnYesNo ("CONFIRM_RESTART", hwndDlg) == IDYES)
						{
							EndMainDlg (MainDlg);

							try
							{
								BootEncObj->RestartComputer ();
							}
							catch (Exception &e)
							{
								e.Show (hwndDlg);
							}

							return;
						}

						EndMainDlg (MainDlg);
						return;
					}
					else if (bAnswerTerminate)
					{
						// User doesn't want to retry pretest (or OS cloning), but to terminate the entire process

						try
						{
							BootEncObj->Deinstall (true);
						}
						catch (Exception &e)
						{
							e.Show (hwndDlg);
							AbortProcessSilent();
						}

						ManageStartupSeqWiz (TRUE, L"");
						ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
						EndMainDlg (MainDlg);
						return;
					}
					else
					{
						// User doesn't want to take any action now

						AbortProcessSilent();
					}
				}
			}
			break;

		default:

			// Unexpected progress status -- fix the inconsistency

			ManageStartupSeqWiz (TRUE, L"");
			ChangeSystemEncryptionStatus (SYSENC_STATUS_NONE);
			EndMainDlg (MainDlg);
			InconsistencyResolved (SRC_POS);
			return;
		}
	}
	else
	{
		if (DirectDeviceEncMode)
		{
			SwitchWizardToNonSysDeviceMode();
			return;
		}

		if (DirectPromptNonSysInplaceEncResumeMode
			&& !bInPlaceEncNonSysPending)
		{
			// This instance of the wizard has been launched via the system startup sequence to prompt for resume of
			// a non-system in-place encryption/decryption process. However, no config file indicates that any such process
			// has been interrupted. This inconsistency may occur, for example, when the process is finished
			// but the wizard is not removed from the startup sequence because system encryption is in progress.
			// Therefore, we remove it from the startup sequence now if possible.

			if (!IsNonInstallMode () && SystemEncryptionStatus == SYSENC_STATUS_NONE)
				ManageStartupSeqWiz (TRUE, L"");

			AbortProcessSilent ();
		}

		BOOL bDecrypt = FALSE;

		if (DirectNonSysInplaceDecStartMode)
		{
			SwitchWizardToNonSysInplaceDecStartMode (szFileName);
			return;
		}
		else if (DirectNonSysInplaceEncResumeMode || DirectNonSysInplaceDecResumeMode)
		{
			SwitchWizardToNonSysInplaceEncResumeMode (DirectNonSysInplaceDecResumeMode);
			return;
		}
		else if (DirectPromptNonSysInplaceEncResumeMode)
		{
			if (NonSysInplaceEncInProgressElsewhere ())
				AbortProcessSilent ();

			if (AskNonSysInPlaceEncryptionResume(hwndDlg, &bDecrypt) == IDYES)
				SwitchWizardToNonSysInplaceEncResumeMode(bDecrypt);
			else
				AbortProcessSilent ();

			return;
		}
		else if (bInPlaceEncNonSysPending
			&& !NonSysInplaceEncInProgressElsewhere ()
			&& AskNonSysInPlaceEncryptionResume(hwndDlg, &bDecrypt) == IDYES)
		{
			SwitchWizardToNonSysInplaceEncResumeMode(bDecrypt);
			return;
		}

		LoadPage (hwndDlg, INTRO_PAGE);
	}
}

int WINAPI wWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, wchar_t *lpszCommandLine, int nCmdShow)
{
	int status;
	atexit (localcleanup);

	VirtualLock (&volumePassword, sizeof(volumePassword));
	VirtualLock (&outerVolumePassword, sizeof(outerVolumePassword));
	VirtualLock (szVerify, sizeof(szVerify));
	VirtualLock (szRawPassword, sizeof(szRawPassword));
	VirtualLock (&volumePim, sizeof(volumePim));
	VirtualLock (&outerVolumePim, sizeof(outerVolumePim));
	VirtualLock (&CmdVolumePassword, sizeof (CmdVolumePassword));

	VirtualLock (MasterKeyGUIView, sizeof(MasterKeyGUIView));
	VirtualLock (HeaderKeyGUIView, sizeof(HeaderKeyGUIView));

	VirtualLock (randPool, sizeof(randPool));
	VirtualLock (lastRandPool, sizeof(lastRandPool));
	VirtualLock (outRandPoolDispBuffer, sizeof(outRandPoolDispBuffer));
	VirtualLock (&mouseEntropyGathered, sizeof(mouseEntropyGathered));
	VirtualLock (&mouseEventsInitialCount, sizeof(mouseEventsInitialCount));
	VirtualLock (maskRandPool, sizeof(maskRandPool));

	VirtualLock (&szFileName, sizeof(szFileName));
	VirtualLock (&szDiskFile, sizeof(szDiskFile));

#ifndef _M_ARM64
	DetectX86Features();
#else
	DetectArmFeatures();
#endif

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

#if TC_MAX_VOLUME_SECTOR_SIZE > 64 * 1024
#error TC_MAX_VOLUME_SECTOR_SIZE > 64 * 1024
#endif

	nPbar = IDC_PROGRESS_BAR;

	if (Randinit ())
	{
		DWORD dwLastError = GetLastError ();
		wchar_t szTmp[4096];
		if (CryptoAPILastError == ERROR_SUCCESS)
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("INIT_RAND"), SRC_POS, dwLastError);
		else
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CAPI_RAND"), SRC_POS, CryptoAPILastError);
		AbortProcessDirect (szTmp);
	}

	RegisterRedTick(hInstance);

	/* Allocate, dup, then store away the application title */
	lpszTitle = GetString ("IDD_VOL_CREATION_WIZARD_DLG");

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR)
			handleWin32Error (NULL, SRC_POS);
		else
			handleError (NULL, status, SRC_POS);

		AbortProcess ("NODRIVER");
	}

	if (!AutoTestAlgorithms())
		AbortProcess ("ERR_SELF_TESTS_FAILED");

	/* Create the main dialog box */
	DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_VOL_CREATION_WIZARD_DLG), NULL, (DLGPROC) MainDialogProc,
		(LPARAM)lpszCommandLine);

	return 0;
}


static DWORD GetFormatSectorSize ()
{
	if (!bDevice)
		return TC_SECTOR_SIZE_FILE_HOSTED_VOLUME;

	DISK_GEOMETRY_EX geometry;

	if (!GetDriveGeometry (szDiskFile, &geometry))
	{
		handleWin32Error (MainDlg, SRC_POS);
		AbortProcessSilent();
	}

	return geometry.Geometry.BytesPerSector;
}
