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

#ifndef TC_HEADER_DLGCODE
#define TC_HEADER_DLGCODE

#include "Common.h"
#include "Apidrvr.h"
#include "Keyfiles.h"
#include "Wipe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IDs for dynamically generated GUI elements */
enum dynamic_gui_element_ids
{
	IDPM_CHECK_FILESYS = 500001,
	IDPM_REPAIR_FILESYS,
	IDPM_OPEN_VOLUME,
	IDPM_SELECT_FILE_AND_MOUNT,
	IDPM_SELECT_DEVICE_AND_MOUNT,
	IDPM_ADD_TO_FAVORITES,
	IDPM_ADD_TO_SYSTEM_FAVORITES,
	IDM_SHOW_HIDE,
	IDM_HOMEPAGE_SYSTRAY,
	IDPM_COPY_VALUE_TO_CLIPBOARD
};

enum
{
	TC_TBXID_LEGAL_NOTICES,
	TC_TBXID_SYS_ENCRYPTION_PRETEST,
	TC_TBXID_SYS_ENC_RESCUE_DISK,
	TC_TBXID_DECOY_OS_INSTRUCTIONS,
	TC_TBXID_EXTRA_BOOT_PARTITION_REMOVAL_INSTRUCTIONS
};

#define TC_APPLICATION_ID	L"IDRIX.VeraCrypt"

#define TC_MUTEX_NAME_SYSENC				L"Global\\VeraCrypt System Encryption Wizard"
#define TC_MUTEX_NAME_NONSYS_INPLACE_ENC	L"Global\\VeraCrypt In-Place Encryption Wizard"
#define TC_MUTEX_NAME_APP_SETUP				L"Global\\VeraCrypt Setup"
#define TC_MUTEX_NAME_DRIVER_SETUP			L"Global\\VeraCrypt Driver Setup"

#define IDC_ABOUT 0x7fff	/* ID for AboutBox on system menu in wm_user range */

#define EXCL_ACCESS_MAX_AUTO_RETRIES 500
#define EXCL_ACCESS_AUTO_RETRY_DELAY 10

#define UNMOUNT_MAX_AUTO_RETRIES 30
#define UNMOUNT_AUTO_RETRY_DELAY 50

// After the user receives the "Incorrect password" error this number of times in a row, we should automatically
// try using the embedded header backup (if any). This ensures that the "Incorrect password" message is reported faster
// initially (most such errors are really caused by supplying an incorrect password, not by header corruption).
#define TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES		2

#define MAX_MULTI_CHOICES		10		/* Maximum number of options for mutliple-choice dialog */

#define TC_APPD_FILENAME_CONFIGURATION						L"Configuration.xml"
#define TC_APPD_FILENAME_SYSTEM_ENCRYPTION					L"System Encryption.xml"
#define TC_APPD_FILENAME_DEFAULT_KEYFILES					L"Default Keyfiles.xml"
#define TC_APPD_FILENAME_HISTORY							L"History.xml"
#define TC_APPD_FILENAME_FAVORITE_VOLUMES					L"Favorite Volumes.xml"
#define TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES			_T(TC_APP_NAME) L" System Favorite Volumes.xml"
#define TC_APPD_FILENAME_NONSYS_INPLACE_ENC					L"In-Place Encryption"
#define TC_APPD_FILENAME_NONSYS_INPLACE_ENC_WIPE			L"In-Place Encryption Wipe Algo"
#define TC_APPD_FILENAME_POST_INSTALL_TASK_TUTORIAL			L"Post-Install Task - Tutorial"
#define TC_APPD_FILENAME_POST_INSTALL_TASK_RELEASE_NOTES	L"Post-Install Task - Release Notes"
#define TC_APPD_FILENAME_POST_INSTALL_TASK_RESCUE_DISK		L"Post-Install Task - Rescue Disk"

#define VC_FILENAME_RENAMED_SUFFIX				L"_old"

#ifndef USER_DEFAULT_SCREEN_DPI
#define USER_DEFAULT_SCREEN_DPI 96
#endif

#if (USER_DEFAULT_SCREEN_DPI != 96)
#	error Revision of GUI and graphics necessary, since everything assumes default screen DPI as 96 (note that 96 is the default on Windows 2000, XP, and Vista).
#endif

enum
{
	TC_POST_INSTALL_CFG_REMOVE_ALL = 0,
	TC_POST_INSTALL_CFG_TUTORIAL,
	TC_POST_INSTALL_CFG_RELEASE_NOTES,
	TC_POST_INSTALL_CFG_RESCUE_DISK,
};

extern char *LastDialogId;
extern char *ConfigBuffer;
extern wchar_t szHelpFile[TC_MAX_PATH];
extern wchar_t szHelpFile2[TC_MAX_PATH];
extern wchar_t SecurityTokenLibraryPath[TC_MAX_PATH];
extern char CmdTokenPin [TC_MAX_PATH];
extern HFONT hFixedDigitFont;
extern HFONT hBoldFont;
extern HFONT hTitleFont;
extern HFONT hFixedFont;
extern HFONT hUserFont;
extern HFONT hUserUnderlineFont;
extern HFONT hUserBoldFont;
extern HFONT WindowTitleBarFont;
extern int ScreenDPI;
extern double DlgAspectRatio;
extern HWND MainDlg;
extern BOOL Silent;
extern BOOL bHistory;
extern BOOL bPreserveTimestamp;
extern BOOL bShowDisconnectedNetworkDrives;
extern BOOL bHideWaitingDialog;
extern BOOL bCmdHideWaitingDialog;
extern BOOL bCmdHideWaitingDialogValid;
extern BOOL bUseSecureDesktop;
extern BOOL bCmdUseSecureDesktop;
extern BOOL bCmdUseSecureDesktopValid;
extern BOOL bStartOnLogon;
extern BOOL bMountDevicesOnLogon;
extern BOOL bMountFavoritesOnLogon;
extern int HiddenSectorDetectionStatus;
extern wchar_t *lpszTitle;
extern OSVersionEnum nCurrentOS;
extern int CurrentOSMajor;
extern int CurrentOSMinor;
extern int CurrentOSServicePack;
extern BOOL RemoteSession;
extern HANDLE hDriver;
extern HINSTANCE hInst;
extern int SystemEncryptionStatus;
extern WipeAlgorithmId nWipeMode;
extern BOOL bSysPartitionSelected;
extern BOOL bSysDriveSelected;

extern wchar_t SysPartitionDevicePath [TC_MAX_PATH];
extern wchar_t SysDriveDevicePath [TC_MAX_PATH];
extern char bCachedSysDevicePathsValid;

extern BOOL bHyperLinkBeingTracked;
extern BOOL bInPlaceEncNonSysPending;

extern BOOL PimEnable;
extern BOOL	KeyFilesEnable;
extern KeyFile	*FirstKeyFile;
extern KeyFilesDlgParam		defaultKeyFilesParam;
extern BOOL UacElevated;
extern BOOL IgnoreWmDeviceChange;
extern BOOL DeviceChangeBroadcastDisabled;
extern BOOL LastMountedVolumeDirty;
extern BOOL MountVolumesAsSystemFavorite;
extern BOOL FavoriteMountOnArrivalInProgress;
extern BOOL MultipleMountOperationInProgress;


enum tc_app_msg_ids
{
	/* WARNING: Changing these values or their meanings may cause incompatibility with other versions
	(for example, if a new version of the TrueCrypt installer needed to shut down this version of
	TrueCrypt during upgrade, it could fail or do something unwanted because the signal value would
	be incorrect). When adding a new constant, verify that the value is unique within this block and
	that it is less than WM_APP+16383. */

	// Common (inter-app)
	TC_APPMSG_CLOSE_BKG_TASK =						WM_APP + 4,	// Changing this value will prevent smooth upgrades from pre-5.x versions
	TC_APPMSG_SYSENC_CONFIG_UPDATE =				WM_APP + 101,
	TC_APPMSG_TASKBAR_ICON =						WM_APP + 102,
	TC_APPMSG_LOAD_TEXT_BOX_CONTENT =				WM_APP + 103,
	// Mount
	TC_APPMSG_MOUNT_ENABLE_DISABLE_CONTROLS =		WM_APP + 201,
	TC_APPMSG_MOUNT_SHOW_WINDOW =					WM_APP + 202,
	TC_APPMSG_PREBOOT_PASSWORD_MODE =				WM_APP + 203,
	VC_APPMSG_CREATE_RESCUE_DISK =					WM_APP + 204,
	// Format
	TC_APPMSG_VOL_TRANSFORM_THREAD_ENDED =			WM_APP + 301,
	TC_APPMSG_FORMAT_FINISHED =						WM_APP + 302,
	TC_APPMSG_FORMAT_USER_QUIT =					WM_APP + 303,
	TC_APPMSG_PERFORM_POST_WMINIT_TASKS =			WM_APP + 304,
	TC_APPMSG_PERFORM_POST_SYSENC_WMINIT_TASKS =	WM_APP + 305,
	TC_APPMSG_NONSYS_INPLACE_ENC_FINISHED =			WM_APP + 306,
	// Setup
	TC_APPMSG_INSTALL_SUCCESS =						WM_APP + 401,
	TC_APPMSG_UNINSTALL_SUCCESS =					WM_APP + 402,
	TC_APPMSG_EXTRACTION_SUCCESS =					WM_APP + 403,
	TC_APPMSG_INSTALL_FAILURE =						WM_APP + 404,
	TC_APPMSG_UNINSTALL_FAILURE =					WM_APP + 405,
	TC_APPMSG_EXTRACTION_FAILURE =					WM_APP + 406
};

enum system_encryption_status
{
	/* WARNING: As these values are written to config files, if they or their meanings
	are changed, incompatiblity with other versions may arise (upgrade, downgrade, etc.).
	When adding a new constant, verify that the value is unique within this block. */
	SYSENC_STATUS_NONE = 0,
	SYSENC_STATUS_PRETEST = 200,	// This may also mean that the OS is to be (or has been) copied to a hidden volume (to create a hidden OS).
	SYSENC_STATUS_ENCRYPTING = 400,
	SYSENC_STATUS_DECRYPTING = 600
};

enum vol_creation_wizard_modes
{
	WIZARD_MODE_FILE_CONTAINER = 0,
	WIZARD_MODE_NONSYS_DEVICE,
	WIZARD_MODE_SYS_DEVICE
};


typedef struct
{
	BOOL VolumeIsOpen;

	CRYPTO_INFO *CryptoInfo;
	BOOL IsDevice;
	HANDLE HostFileHandle;
	uint64 HostSize;

	BOOL TimestampsValid;
	FILETIME CreationTime;
	FILETIME LastWriteTime;
	FILETIME LastAccessTime;

} OpenVolumeContext;


#define DEFAULT_VOL_CREATION_WIZARD_MODE	WIZARD_MODE_FILE_CONTAINER

#define ICON_HAND MB_ICONHAND
#define YES_NO MB_YESNO

#define	ISO_BURNER_TOOL L"isoburn.exe"
#define PRINT_TOOL L"notepad.exe"

void InitGlobalLocks ();
void FinalizeGlobalLocks ();
void cleanup ( void );
void LowerCaseCopy ( wchar_t *lpszDest , const wchar_t *lpszSource );
void UpperCaseCopy ( wchar_t *lpszDest , size_t cbDest, const wchar_t *lpszSource );
BOOL IsNullTerminateString (const wchar_t* str, size_t cbSize);
void CreateFullVolumePath ( wchar_t *lpszDiskFile , size_t cbDiskFile, const wchar_t *lpszFileName , BOOL *bDevice );
int FakeDosNameForDevice ( const wchar_t *lpszDiskFile , wchar_t *lpszDosDevice , size_t cbDosDevice, wchar_t *lpszCFDevice , size_t cbCFDevice, BOOL bNameOnly );
int RemoveFakeDosName ( wchar_t *lpszDiskFile , wchar_t *lpszDosDevice );
void AbortProcessDirect ( wchar_t *abortMsg );
void AbortProcess ( char *stringId );
void AbortProcessSilent ( void );
void *err_malloc ( size_t size );
char *err_strdup ( char *lpszText );
DWORD handleWin32Error ( HWND hwndDlg, const char* srcPos );
BOOL IsDiskReadError (DWORD error);
BOOL IsDiskWriteError (DWORD error);
BOOL IsDiskError (DWORD error);
BOOL translateWin32Error ( wchar_t *lpszMsgBuf , int nWSizeOfBuf );
BOOL CALLBACK AboutDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
static BOOL CALLBACK StaticModelessWaitDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void DisplayStaticModelessWaitDlg (HWND parent);
void CloseStaticModelessWaitDlg (void);
BOOL IsButtonChecked ( HWND hButton );
void CheckButton ( HWND hButton );
void LeftPadString (wchar_t *szTmp, int len, int targetLen, wchar_t filler);
void InitDialog ( HWND hwndDlg );
void ProcessPaintMessages (HWND hwnd, int maxMessagesToProcess);
HDC CreateMemBitmap ( HINSTANCE hInstance , HWND hwnd , wchar_t *resource );
HBITMAP RenderBitmap ( wchar_t *resource , HWND hwndDest , int x , int y , int nWidth , int nHeight , BOOL bDirectRender , BOOL bKeepAspectRatio);
LRESULT CALLBACK RedTick ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL RegisterRedTick ( HINSTANCE hInstance );
BOOL UnregisterRedTick ( HINSTANCE hInstance );
LRESULT CALLBACK SplashDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
void WaitCursor ( void );
void NormalCursor ( void );
void ArrowWaitCursor ( void );
void HandCursor ();
void AddComboPair (HWND hComboBox, const wchar_t *lpszItem, int value);
void SelectAlgo ( HWND hComboBox , int *nCipher );
void PopulateWipeModeCombo (HWND hComboBox, BOOL bNA, BOOL bInPlaceEncryption, BOOL bHeaderWipe);
wchar_t *GetWipeModeName (WipeAlgorithmId modeId);
wchar_t *GetPathType (const wchar_t *path, BOOL bUpperCase, BOOL *bIsPartition);
LRESULT CALLBACK CustomDlgProc ( HWND hwnd , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL TCCreateMutex (volatile HANDLE *hMutex, wchar_t *name);
void TCCloseMutex (volatile HANDLE *hMutex);
BOOL MutexExistsOnSystem (wchar_t *name);
BOOL CreateSysEncMutex (void);
BOOL InstanceHasSysEncMutex (void);
void CloseSysEncMutex (void);
BOOL CreateNonSysInplaceEncMutex (void);
BOOL InstanceHasNonSysInplaceEncMutex (void);
void CloseNonSysInplaceEncMutex (void);
BOOL NonSysInplaceEncInProgressElsewhere (void);
BOOL CreateDriverSetupMutex (void);
void CloseDriverSetupMutex (void);
BOOL CreateAppSetupMutex (void);
BOOL InstanceHasAppSetupMutex (void);
void CloseAppSetupMutex (void);
BOOL IsTrueCryptInstallerRunning (void);
uint32 ReadDriverConfigurationFlags ();
uint32 ReadEncryptionThreadPoolFreeCpuCountLimit ();
BOOL LoadSysEncSettings ();
int LoadNonSysInPlaceEncSettings (WipeAlgorithmId *wipeAlgorithm);
void RemoveNonSysInPlaceEncNotifications (void);
void SavePostInstallTasksSettings (int command);
void DoPostInstallTasks (HWND hwndDlg);
void InitOSVersionInfo ();
void InitApp ( HINSTANCE hInstance, wchar_t *lpszCommandLine );
void FinalizeApp (void);
void InitHelpFileName (void);
BOOL OpenDevice (const wchar_t *lpszPath, OPEN_TEST_STRUCT *driver, BOOL detectFilesystem, BOOL computeVolumeID);
void NotifyDriverOfPortableMode (void);
int GetAvailableFixedDisks ( HWND hComboBox , char *lpszRootPath );
int GetAvailableRemovables ( HWND hComboBox , char *lpszRootPath );
int IsSystemDevicePath (const wchar_t *path, HWND hwndDlg, BOOL bReliableRequired);
int IsNonSysPartitionOnSysDrive (const wchar_t *path);
BOOL CALLBACK RawDevicesDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK TextEditDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR TextInfoDialogBox (int nID);
BOOL CALLBACK TextInfoDialogBoxDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
char * GetLegalNotices ();
BOOL CALLBACK BenchmarkDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void UserEnrichRandomPool (HWND hwndDlg);
BOOL CALLBACK KeyfileGeneratorDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK MultiChoiceDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
int DriverAttach ( void );
BOOL CALLBACK CipherTestDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ResetCipherTest ( HWND hwndDlg , int idTestCipher );
void ResetCurrentDirectory ();
BOOL BrowseFiles (HWND hwndDlg, char *stringId, wchar_t *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter);
BOOL BrowseDirectories (HWND hWnd, char *lpszTitle, wchar_t *dirName);
void handleError ( HWND hwndDlg , int code, const char* srcPos );
BOOL CheckFileStreamWriteErrors (HWND hwndDlg, FILE *file, const wchar_t *fileName);
void LocalizeDialog ( HWND hwnd, char *stringId );
void OpenVolumeExplorerWindow (int driveNo);
static BOOL CALLBACK CloseVolumeExplorerWindowsEnum( HWND hwnd, LPARAM driveNo);
BOOL CloseVolumeExplorerWindows (HWND hwnd, int driveNo);
BOOL UpdateDriveCustomLabel (int driveNo, wchar_t* effectiveLabel, BOOL bSetValue);
BOOL CheckCapsLock (HWND hwnd, BOOL quiet);
BOOL CheckFileExtension (wchar_t *fileName);
void CorrectFileName (wchar_t* fileName);
void CorrectURL (wchar_t* fileName);
void IncreaseWrongPwdRetryCount (int count);
void ResetWrongPwdRetryCount (void);
BOOL WrongPwdRetryCountOverLimit (void);
DWORD GetUsedLogicalDrives (void);
int GetFirstAvailableDrive ();
int GetLastAvailableDrive ();
BOOL IsDriveAvailable (int driveNo);
BOOL IsDeviceMounted (wchar_t *deviceName);
int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced);
void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap);
int MountVolume (HWND hwndDlg, int driveNo, wchar_t *volumePath, Password *password, int pkcs5, int pim, BOOL truecryptMode, BOOL cachePassword, BOOL cachePim, BOOL sharedAccess,  const MountOptions* const mountOptions, BOOL quiet, BOOL bReportWrongPassword);
BOOL UnmountVolume (HWND hwndDlg , int nDosDriveNo, BOOL forceUnmount);
BOOL UnmountVolumeAfterFormatExCall (HWND hwndDlg, int nDosDriveNo);
BOOL IsPasswordCacheEmpty (void);
BOOL IsMountedVolumeID (BYTE volumeID[VOLUME_ID_SIZE]);
BOOL IsMountedVolume (const wchar_t *volname);
int GetMountedVolumeDriveNo (wchar_t *volname);
BOOL IsAdmin (void);
BOOL IsBuiltInAdmin ();
BOOL IsUacSupported ();
BOOL ResolveSymbolicLink (const wchar_t *symLinkName, PWSTR targetName, size_t cbTargetName);
int GetDiskDeviceDriveLetter (PWSTR deviceName);
int FileSystemAppearsEmpty (const wchar_t *devicePath);
__int64 GetStatsFreeSpaceOnPartition (const wchar_t *devicePath, float *percent, __int64 *occupiedBytes, BOOL silent);
__int64 GetDeviceSize (const wchar_t *devicePath);
HANDLE DismountDrive (wchar_t *devName, wchar_t *devicePath);
int64 FindString (const char *buf, const char *str, int64 bufLen, int64 strLen, int64 startOffset);
BOOL FileExists (const wchar_t *filePathPtr);
__int64 FindStringInFile (const wchar_t *filePath, const char *str, int strLen);
BOOL TCCopyFile (wchar_t *sourceFileName, wchar_t *destinationFile);
BOOL SaveBufferToFile (const char *inputBuffer, const wchar_t *destinationFile, DWORD inputLength, BOOL bAppend, BOOL bRenameIfFailed);
typedef void (_cdecl *ProgressFn) ( HWND hwndDlg , const wchar_t *txt );
BOOL DecompressZipToDir (const unsigned char *inputBuffer, DWORD inputLength, const wchar_t *destinationFile, ProgressFn progressFnPtr, HWND hwndDlg);
BOOL TCFlushFile (FILE *f);
BOOL PrintHardCopyTextUTF16 (wchar_t *text, wchar_t *title, size_t byteLen);
void GetSpeedString (unsigned __int64 speed, wchar_t *str, size_t cbStr);
BOOL IsNonInstallMode ();
BOOL DriverUnload ();
LRESULT SetCheckBox (HWND hwndDlg, int dlgItem, BOOL state);
BOOL GetCheckBox (HWND hwndDlg, int dlgItem);
void SetListScrollHPos (HWND hList, int topMostVisibleItem);
void ManageStartupSeq (void);
void ManageStartupSeqWiz (BOOL bRemove, const wchar_t *arg);
void CleanLastVisitedMRU (void);
void ClearHistory (HWND hwndDlgItem);
LRESULT ListItemAdd (HWND list, int index, const wchar_t *string);
LRESULT ListSubItemSet (HWND list, int index, int subIndex, const wchar_t *string);
BOOL GetMountList (MOUNT_LIST_STRUCT *list);
int GetDriverRefCount ();
void GetSizeString (unsigned __int64 size, wchar_t *str, size_t cbStr);
__int64 GetFileSize64 (const wchar_t *path);
BOOL LoadInt16 (const wchar_t *filePath, int *result, __int64 fileOffset);
BOOL LoadInt32 (const wchar_t *filePath, unsigned __int32 *result, __int64 fileOffset);
char *LoadFile (const wchar_t *fileName, DWORD *size);
char *LoadFileBlock (const wchar_t *fileName, __int64 fileOffset, DWORD count);
wchar_t *GetModPath (wchar_t *path, int maxSize);
wchar_t *GetConfigPath (wchar_t *fileName);
wchar_t *GetProgramConfigPath (wchar_t *fileName);
wchar_t GetSystemDriveLetter (void);
void OpenPageHelp (HWND hwndDlg, int nPage);
void TaskBarIconDisplayBalloonTooltip (HWND hwnd, wchar_t *headline, wchar_t *text, BOOL warning);
void InfoBalloon (char *headingStringId, char *textStringId, HWND hwnd);
void InfoBalloonDirect (wchar_t *headingString, wchar_t *textString, HWND hwnd);
void WarningBalloon (char *headingStringId, char *textStringId, HWND hwnd);
void WarningBalloonDirect (wchar_t *headingString, wchar_t *textString, HWND hwnd);
int Info (char *stringId, HWND hwnd);
int InfoTopMost (char *stringId, HWND hwnd);
int InfoDirect (const wchar_t *msg, HWND hwnd);
int Warning (char *stringId, HWND hwnd);
int WarningTopMost (char *stringId, HWND hwnd);
int WarningDirect (const wchar_t *warnMsg, HWND hwnd);
int Error (char *stringId, HWND hwnd);
int ErrorRetryCancel (char *stringId, HWND hwnd);
int ErrorDirect (const wchar_t *errMsg, HWND hwnd);
int ErrorTopMost (char *stringId, HWND hwnd);
int AskYesNo (char *stringId, HWND hwnd);
int AskYesNoString (const wchar_t *str, HWND hwnd);
int AskYesNoTopmost (char *stringId, HWND hwnd);
int AskNoYes (char *stringId, HWND hwnd);
int AskNoYesString (const wchar_t *string, HWND hwnd);
int AskOkCancel (char *stringId, HWND hwnd);
int AskWarnYesNo (char *stringId, HWND hwnd);
int AskWarnYesNoString (const wchar_t *string, HWND hwnd);
int AskWarnYesNoTopmost (char *stringId, HWND hwnd);
int AskWarnYesNoStringTopmost (const wchar_t *string, HWND hwnd);
int AskWarnNoYes (char *stringId, HWND hwnd);
int AskWarnNoYesString (const wchar_t *string, HWND hwnd);
int AskWarnNoYesTopmost (char *stringId, HWND hwnd);
int AskWarnOkCancel (char *stringId, HWND hwnd);
int AskWarnCancelOk (char *stringId, HWND hwnd);
int AskErrYesNo (char *stringId, HWND hwnd);
int AskErrNoYes (char *stringId, HWND hwnd);
int AskMultiChoice (void *strings[], BOOL bBold, HWND hwnd);
BOOL ConfigWriteBegin ();
BOOL ConfigWriteEnd (HWND hwnd);
BOOL ConfigWriteString (char *configKey, char *configValue);
BOOL ConfigWriteStringW (char *configKey, wchar_t *configValue);
BOOL ConfigWriteInt (char *configKey, int configValue);
int ConfigReadInt (char *configKey, int defaultValue);
char *ConfigReadString (char *configKey, char *defaultValue, char *str, int maxLen);
void ConfigReadCompareInt(char *configKey, int defaultValue, int* pOutputValue, BOOL bOnlyCheckModified, BOOL* pbModified);
void ConfigReadCompareString (char *configKey, char *defaultValue, char *str, int maxLen, BOOL bOnlyCheckModified, BOOL *pbModified);
void RestoreDefaultKeyFilesParam (void);
BOOL LoadDefaultKeyFilesParam (void);
void Debug (char *format, ...);
void DebugMsgBox (char *format, ...);
BOOL IsOSAtLeast (OSVersionEnum reqMinOS);
BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack);
BOOL Is64BitOs ();
BOOL IsServerOS ();
BOOL IsHiddenOSRunning (void);
BOOL EnableWow64FsRedirection (BOOL enable);
BOOL RestartComputer (BOOL bShutdown);
void Applink (const char *dest);
wchar_t *RelativePath2Absolute (wchar_t *szFileName);
void HandleDriveNotReadyError (HWND hwnd);
BOOL CALLBACK CloseTCWindowsEnum( HWND hwnd, LPARAM lParam);
BOOL CALLBACK FindTCWindowEnum (HWND hwnd, LPARAM lParam);
BYTE *MapResource (wchar_t *resourceType, int resourceId, PDWORD size);
void InconsistencyResolved (char *msg);
void ReportUnexpectedState (char *techInfo);
BOOL SelectMultipleFiles (HWND hwndDlg, const char *stringId, wchar_t *lpszFileName, size_t cbFileName, BOOL keepHistory);
BOOL SelectMultipleFilesNext (wchar_t *lpszFileName, size_t cbFileName);
void OpenOnlineHelp ();
BOOL GetPartitionInfo (const wchar_t *deviceName, PPARTITION_INFORMATION rpartInfo);
BOOL GetDeviceInfo (const wchar_t *deviceName, DISK_PARTITION_INFO_STRUCT *info);
BOOL GetDriveGeometry (const wchar_t *deviceName, PDISK_GEOMETRY_EX diskGeometry);
BOOL GetPhysicalDriveGeometry (int driveNumber, PDISK_GEOMETRY diskGeometry);
BOOL IsVolumeDeviceHosted (const wchar_t *lpszDiskFile);
int CompensateXDPI (int val);
int CompensateYDPI (int val);
int CompensateDPIFont (int val);
int GetTextGfxWidth (HWND hwndDlgItem, const wchar_t *text, HFONT hFont);
int GetTextGfxHeight (HWND hwndDlgItem, const wchar_t *text, HFONT hFont);
BOOL ToHyperlink (HWND hwndDlg, UINT ctrlId);
BOOL ToCustHyperlink (HWND hwndDlg, UINT ctrlId, HFONT hFont);
void DisableCloseButton (HWND hwndDlg);
void EnableCloseButton (HWND hwndDlg);
void ToBootPwdField (HWND hwndDlg, UINT ctrlId);
void AccommodateTextField (HWND hwndDlg, UINT ctrlId, BOOL bFirstUpdate, HFONT hFont);
BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize);
BOOL GetSysDevicePaths (HWND hwndDlg);
BOOL DoDriverInstall (HWND hwndDlg);
int OpenVolume (OpenVolumeContext *context, const wchar_t *volumePath, Password *password, int pkcs5_prf, int pim, BOOL truecryptMode, BOOL write, BOOL preserveTimestamps, BOOL useBackupHeader);
void CloseVolume (OpenVolumeContext *context);
int ReEncryptVolumeHeader (HWND hwndDlg, char *buffer, BOOL bBoot, CRYPTO_INFO *cryptoInfo, Password *password, int pim, BOOL wipeMode);
BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
BOOL IsPagingFileWildcardActive ();
BOOL DisablePagingFile ();
BOOL CALLBACK SecurityTokenPasswordDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK SecurityTokenKeyfileDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL InitSecurityTokenLibrary (HWND hwndDlg);
BOOL FileHasReadOnlyAttribute (const wchar_t *path);
BOOL IsFileOnReadOnlyFilesystem (const wchar_t *path);
void CheckFilesystem (HWND hwndDlg, int driveNo, BOOL fixErrors);
BOOL BufferContainsString (const byte *buffer, size_t bufferSize, const char *str);
int AskNonSysInPlaceEncryptionResume (HWND hwndDlg, BOOL* pbDecrypt);
BOOL RemoveDeviceWriteProtection (HWND hwndDlg, wchar_t *devicePath);
void EnableElevatedCursorChange (HWND parent);
BOOL DisableFileCompression (HANDLE file);
BOOL VolumePathExists (const wchar_t *volumePath);
BOOL IsWindowsIsoBurnerAvailable ();
BOOL LaunchWindowsIsoBurner (HWND hwnd, const wchar_t *isoPath);
BOOL IsApplicationInstalled (const wchar_t *appName);
int GetPim (HWND hwndDlg, UINT ctrlId, int defaultPim);
void SetPim (HWND hwndDlg, UINT ctrlId, int pim);
BOOL GetPassword (HWND hwndDlg, UINT ctrlID, char* passValue, int bufSize, BOOL bShowError);
void SetPassword (HWND hwndDlg, UINT ctrlID, char* passValue);
void HandleShowPasswordFieldAction (HWND hwndDlg, UINT checkBoxId, UINT edit1Id, UINT edit2Id);
HKEY OpenDeviceClassRegKey (const GUID *deviceClassGuid);
LSTATUS DeleteRegistryKey (HKEY, LPCTSTR);
HIMAGELIST  CreateImageList(int cx, int cy, UINT flags, int cInitial, int cGrow);
int AddBitmapToImageList(HIMAGELIST himl, HBITMAP hbmImage, HBITMAP hbmMask);
HRESULT VCStrDupW(LPCWSTR psz, LPWSTR *ppwsz);
void ProcessEntropyEstimate (HWND hProgress, DWORD* pdwInitialValue, DWORD dwCounter, DWORD dwMaxLevel, DWORD* pdwEntropy);
void AllowMessageInUIPI (UINT msg);
BOOL IsRepeatedByteArray (byte value, const byte* buffer, size_t bufferSize);
BOOL TranslateVolumeID (HWND hwndDlg, wchar_t* pathValue, size_t cchPathValue);
BOOL CopyTextToClipboard (const wchar_t* txtValue);
BOOL LaunchElevatedProcess (HWND hwndDlg, const wchar_t* szModPath, const wchar_t* args);
BOOL GetFreeDriveLetter(WCHAR* pCh);
BOOL RaisePrivileges(void);
BOOL DeleteDirectory (const wchar_t* szDirName);
INT_PTR SecureDesktopDialogBoxParam (HINSTANCE, LPCWSTR, HWND, DLGPROC, LPARAM);

#ifdef __cplusplus
}

#include <vector>
#include <string>

typedef std::vector<unsigned char> ByteArray;

struct HostDevice
{
	HostDevice ()
		:
		Bootable (false),
		ContainsSystem (false),
		DynamicVolume (false),
		Floppy (false),
		IsPartition (false),
		IsVirtualPartition (false),
		HasUnencryptedFilesystem (false),
		Removable (false),
		Size (0),
		SystemNumber((uint32) -1),
		HasVolumeIDs (false)
	{
		ZeroMemory (VolumeIDs, sizeof (VolumeIDs));
	}

	HostDevice (const HostDevice& device)
		:
		Bootable (device.Bootable),
		ContainsSystem (device.ContainsSystem),
		DynamicVolume (device.DynamicVolume),
		Floppy (device.Floppy),
		IsPartition (device.IsPartition),
		IsVirtualPartition (device.IsVirtualPartition),
		HasUnencryptedFilesystem (device.HasUnencryptedFilesystem),
		MountPoint (device.MountPoint),
		Name (device.Name),
		Path (device.Path),
		Removable (device.Removable),
		Size (device.Size),
		SystemNumber (device.SystemNumber),	
		HasVolumeIDs (device.HasVolumeIDs),
		Partitions (device.Partitions)
	{
		memcpy (VolumeIDs, device.VolumeIDs, sizeof (VolumeIDs));
	}

	~HostDevice () {}

	bool Bootable;
	bool ContainsSystem;
	bool DynamicVolume;
	bool Floppy;
	bool IsPartition;
	bool IsVirtualPartition;
	bool HasUnencryptedFilesystem;
	std::wstring MountPoint;
	std::wstring Name;
	std::wstring Path;
	bool Removable;
	uint64 Size;
	uint32 SystemNumber;
	BYTE VolumeIDs[TC_VOLUME_TYPE_COUNT][VOLUME_ID_SIZE];
	bool HasVolumeIDs;

	std::vector <HostDevice> Partitions;
};

struct RawDevicesDlgParam
{
	std::vector <HostDevice> devices;
	wchar_t *pszFileName;
};

BOOL BrowseFilesInDir (HWND hwndDlg, char *stringId, wchar_t *initialDir, wchar_t *lpszFileName, BOOL keepHistory, BOOL saveMode, wchar_t *browseFilter, const wchar_t *initialFileName = NULL, const wchar_t *defaultExtension = NULL);
std::wstring SingleStringToWide (const std::string &singleString);
std::wstring Utf8StringToWide (const std::string &utf8String);
std::string WideToUtf8String (const std::wstring &wideString);
std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties = false, bool singleList = false, bool noFloppy = true, bool detectUnencryptedFilesystems = false);
std::wstring ToUpperCase (const std::wstring &str);
std::wstring GetWrongPasswordErrorMessage (HWND hwndDlg);
std::wstring GetWindowsEdition ();
std::wstring FitPathInGfxWidth (HWND hwnd, HFONT hFont, LONG width, const std::wstring &path);
std::wstring GetServiceConfigPath (const wchar_t *fileName, bool useLegacy);
std::wstring VolumeGuidPathToDevicePath (std::wstring volumeGuidPath);
std::wstring HarddiskVolumePathToPartitionPath (const std::wstring &harddiskVolumePath);
std::wstring FindLatestFileOrDirectory (const std::wstring &directory, const wchar_t *namePattern, bool findDirectory, bool findFile);
std::wstring GetUserFriendlyVersionString (int version);
std::wstring IntToWideString (int val);
std::wstring ArrayToHexWideString (const unsigned char* pbData, int cbData);
bool HexWideStringToArray (const wchar_t* hexStr, std::vector<byte>& arr);
std::wstring FindDeviceByVolumeID (const BYTE volumeID [VOLUME_ID_SIZE], BOOL bFromService);
void RegisterDriverInf (bool registerFilter, const std::string& filter, const std::string& filterReg, HWND ParentWindow, HKEY regKey);
std::wstring GetTempPathString ();
void CorrectFileName (std::wstring& fileName);
inline std::wstring AppendSrcPos (const wchar_t* msg, const char* srcPos)
{
	return std::wstring (msg? msg : L"") + L"\n\nSource: " + SingleStringToWide (srcPos);
}
void UpdateMountableHostDeviceList ();
INT_PTR TextEditDialogBox (BOOL readOnly, HWND parent, const WCHAR* Title, std::string& text);

// Display a wait dialog while calling the provided callback with the given parameter
typedef void (CALLBACK* WaitThreadProc)(void* pArg, HWND hWaitDlg);
void BringToForeground(HWND hWnd);
void ShowWaitDialog(HWND hwnd, BOOL bUseHwndAsParent, WaitThreadProc callback, void* pArg);

#endif // __cplusplus

#endif // TC_HEADER_DLGCODE
