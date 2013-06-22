/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef SETUP_H
#define SETUP_H

#ifdef __cplusplus
extern "C" {
#endif

// Specifies what files to install, where (determined by the prefix), and in what order
static char *szFiles[]=
{
	"ATrueCrypt User Guide.pdf",
	"ALicense.txt",
	"ATrueCrypt.exe",
	"ATrueCrypt Format.exe",
	"Atruecrypt.sys",
	"Atruecrypt-x64.sys",
	"Dtruecrypt.sys",
	"ATrueCrypt Setup.exe"
};

// Specifies what files are included in self-extracting packages (no other files will be packaged or extracted).
static char *szCompressedFiles[]=
{
	"TrueCrypt User Guide.pdf",
	"License.txt",
	"TrueCrypt.exe",
	"TrueCrypt Format.exe",
	"truecrypt.sys",
	"truecrypt-x64.sys"
};

#define FILENAME_64BIT_DRIVER	"truecrypt-x64.sys"
#define NBR_COMPRESSED_FILES (sizeof(szCompressedFiles) / sizeof(szCompressedFiles[0]))

void localcleanup (void);
BOOL StatDeleteFile ( char *lpszFile );
BOOL StatRemoveDirectory ( char *lpszDir );
HRESULT CreateLink ( char *lpszPathObj , char *lpszArguments , char *lpszPathLink );
void GetProgramPath ( HWND hwndDlg , char *path );
void StatusMessage (HWND hwndDlg, char *stringId);
void StatusMessageParam (HWND hwndDlg, char *stringId, char *param);
void ClearLogWindow (HWND hwndDlg);
void StatusMessage ( HWND hwndDlg , char *stringId );
void StatusMessageParam ( HWND hwndDlg , char *stringId , char *param );
void RegMessage ( HWND hwndDlg , char *txt );
void RegRemoveMessage (HWND hwndDlg, char *txt);
void CopyMessage ( HWND hwndDlg , char *txt );
void RemoveMessage ( HWND hwndDlg , char *txt );
void IconMessage ( HWND hwndDlg , char *txt );
static int CALLBACK BrowseCallbackProc ( HWND hwnd , UINT uMsg , LPARAM lp , LPARAM pData );
void LoadLicense ( HWND hwndDlg );
void DetermineUpgradeDowngradeStatus (BOOL bCloseDriverHandle, LONG *driverVersionPtr);
BOOL DoFilesInstall ( HWND hwndDlg , char *szDestDir );
BOOL DoRegInstall ( HWND hwndDlg , char *szDestDir , BOOL bInstallType );
BOOL DoRegUninstall (HWND hwndDlg, BOOL bRemoveDeprecated);
BOOL DoServiceUninstall ( HWND hwndDlg , char *lpszService );
BOOL DoDriverUnload ( HWND hwndDlg );
BOOL DoShortcutsInstall ( HWND hwndDlg , char *szDestDir , BOOL bProgGroup, BOOL bDesktopIcon );
BOOL DoShortcutsUninstall (HWND hwndDlg, char *szDestDir);
void OutcomePrompt ( HWND hwndDlg , BOOL bOK );
void DoUninstall ( void *hwndDlg );
void DoInstall ( void *hwndDlg );
void SetInstallationPath (HWND hwndDlg);
BOOL UpgradeBootLoader (HWND hwndDlg);
BOOL CALLBACK InstallDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );

extern BOOL bDevm;
extern BOOL Rollback;
extern BOOL bUpgrade;
extern BOOL bPossiblyFirstTimeInstall;
extern BOOL bRepairMode;
extern BOOL bSystemRestore;
extern BOOL bDisableSwapFiles;
extern BOOL bForAllUsers;
extern BOOL bRegisterFileExt;
extern BOOL bAddToStartMenu;
extern BOOL bDesktopIcon;
extern BOOL bDesktopIconStatusDetermined;
extern BOOL SystemEncryptionUpdate;
extern BOOL bRestartRequired;
extern HMODULE volatile SystemRestoreDll;
extern char InstallationPath[TC_MAX_PATH];
extern char SetupFilesDir[TC_MAX_PATH];

#ifdef __cplusplus
}
#endif

#endif	// #ifndef SETUP_H
