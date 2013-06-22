/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifdef __cplusplus

#include "Favorites.h"

extern "C" {
#endif

enum mount_list_item_types
{
	TC_MLIST_ITEM_FREE = 0,
	TC_MLIST_ITEM_NONSYS_VOL,
	TC_MLIST_ITEM_SYS_PARTITION,
	TC_MLIST_ITEM_SYS_DRIVE
};

#define TC_MAIN_WINDOW_FLAG_ADMIN_PRIVILEGES	0x1

#define TRAYICON_MENU_DRIVE_OFFSET	9000
#define TC_FAVORITE_MENU_CMD_ID_OFFSET 10000
#define TC_FAVORITE_MENU_CMD_ID_OFFSET_END (TC_FAVORITE_MENU_CMD_ID_OFFSET + 1000)

#define WM_COPY_SET_VOLUME_NAME		"VNAM"

#define ENC_SYSDRIVE_PSEUDO_DRIVE_LETTER	('A' - 1)

/* Password Change dialog modes */
enum
{
	PCDM_CHANGE_PASSWORD = 0,
	PCDM_CHANGE_PKCS5_PRF,
	PCDM_ADD_REMOVE_VOL_KEYFILES,
	PCDM_REMOVE_ALL_KEYFILES_FROM_VOL
};

typedef struct
{
	BOOL bHidVolDamagePrevReported[26];
} VOLUME_NOTIFICATIONS_LIST;


extern VOLUME_NOTIFICATIONS_LIST VolumeNotificationsList;

extern BOOL bEnableBkgTask;
extern BOOL bCloseBkgTaskWhenNoVolumes;
extern BOOL bPlaySoundOnSuccessfulHkDismount;
extern BOOL bDisplayBalloonOnSuccessfulHkDismount;
extern BOOL bExplore;

static void localcleanup ( void );
void EndMainDlg ( HWND hwndDlg );
void EnableDisableButtons ( HWND hwndDlg );
BOOL VolumeSelected (HWND hwndDlg );
void LoadSettings ( HWND hwndDlg );
void SaveSettings ( HWND hwndDlg );
BOOL SelectItem ( HWND hTree , char nLetter );
void LoadDriveLetters ( HWND hTree, int drive );
BOOL CALLBACK PasswordChangeDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK PasswordDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MountOptionsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void BuildTree ( HWND hTree );
LPARAM GetSelectedLong ( HWND hTree );
LPARAM GetItemLong ( HWND hTree, int itemNo );
BOOL CALLBACK CommandHelpDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
void ExtractCommandLine ( HWND hwndDlg , char *lpszCommandLine );
static void WipeCache (HWND hwndDlg, BOOL silent);
void OpenVolumeExplorerWindow (int driveNo);
BOOL TaskBarIconAdd (HWND hwnd);
BOOL TaskBarIconRemove (HWND hwnd);
BOOL TaskBarIconChange (HWND hwnd, int iconId);
void DismountIdleVolumes ();
static void SaveDefaultKeyFilesParam (void);
static BOOL Dismount (HWND hwndDlg, int nDosDriveNo);
static BOOL DismountAll (HWND hwndDlg, BOOL forceUnmount, BOOL interact, int dismountMaxRetries, int dismountAutoRetryDelay);
static void KeyfileDefaultsDlg (HWND hwndDlg);
static void HandleHotKey (HWND hwndDlg, WPARAM wParam);
static BOOL CheckMountList ();
int GetCipherBlockSizeByDriveNo (int nDosDriveNo);
int GetModeOfOperationByDriveNo (int nDosDriveNo);
void ChangeMainWindowVisibility ();
void LaunchVolCreationWizard (HWND hwndDlg);
BOOL WholeSysDriveEncryption (BOOL bSilent);
BOOL CheckSysEncMountWithoutPBA (const char *devicePath, BOOL quiet);
BOOL TCBootLoaderOnInactiveSysEncDrive (void);
void CreateRescueDisk (void);
int BackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume);
int RestoreVolumeHeader (HWND hwndDlg, char *lpszVolume);
void SecurityTokenPreferencesDialog (HWND hwndDlg);
static BOOL CALLBACK PerformanceSettingsDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL CALLBACK BootLoaderPreferencesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void MountSelectedVolume (HWND hwndDlg, BOOL mountWithOptions);
uint32 ReadDriverConfigurationFlags ();
void AnalyzeKernelMiniDump (HWND hwndDlg);
void HookMouseWheel (HWND hwndDlg, UINT ctrlId);
static BOOL HandleDriveListMouseWheelEvent (UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL bListMustBePointed);

#ifdef __cplusplus
}

void SetDriverConfigurationFlag (uint32 flag, BOOL state);
BOOL MountFavoriteVolumes (BOOL systemFavorites = FALSE, BOOL logOnMount = FALSE, BOOL hotKeyMount = FALSE, const TrueCrypt::FavoriteVolume &favoriteVolumeToMount = TrueCrypt::FavoriteVolume());
BOOL GetExecutableImageInformation (const string &path, string &version, string &description, string &companyName, string &productName);

#endif
