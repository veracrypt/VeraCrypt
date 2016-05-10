/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifndef SETUP_H
#define SETUP_H

#ifdef __cplusplus
extern "C" {
#endif

// Specifies what files to install, where (determined by the prefix), and in what order
static wchar_t *szFiles[]=
{
	L"AVeraCrypt User Guide.pdf",
	L"ALicense.txt",
	L"ALICENSE",
	L"ANOTICE",
	L"AVeraCrypt.exe",
	L"AVeraCryptExpander.exe",
	L"AVeraCrypt Format.exe",
	L"AVeraCrypt-x86.exe",
	L"AVeraCryptExpander-x86.exe",
	L"AVeraCrypt Format-x86.exe",
	L"AVeraCrypt-x64.exe",
	L"AVeraCryptExpander-x64.exe",
	L"AVeraCrypt Format-x64.exe",
	L"Averacrypt.sys",
	L"Averacrypt-x64.sys",
	L"Dveracrypt.sys",
	L"AVeraCrypt Setup.exe",
	L"ALanguage.ar.xml",
	L"ALanguage.be.xml",
	L"ALanguage.bg.xml",
	L"ALanguage.ca.xml",
	L"ALanguage.cs.xml",
	L"ALanguage.da.xml",
	L"ALanguage.de.xml",
	L"ALanguage.el.xml",
	L"ALanguage.es.xml",
	L"ALanguage.et.xml",
	L"ALanguage.eu.xml",
	L"ALanguage.fa.xml",
	L"ALanguage.fi.xml",
	L"ALanguage.fr.xml",
	L"ALanguage.hu.xml",
	L"ALanguage.id.xml",
	L"ALanguage.it.xml",
	L"ALanguage.ja.xml",
	L"ALanguage.ka.xml",
	L"ALanguage.ko.xml",
	L"ALanguage.lv.xml",
	L"ALanguage.my.xml",
	L"ALanguage.nl.xml",
	L"ALanguage.nn.xml",
	L"ALanguage.pl.xml",
	L"ALanguage.pt-br.xml",
	L"ALanguage.ru.xml",
	L"ALanguage.sk.xml",
	L"ALanguage.sl.xml",
	L"ALanguage.sv.xml",
	L"ALanguage.tr.xml",
	L"ALanguage.uk.xml",
	L"ALanguage.uz.xml",
	L"ALanguage.vi.xml",
	L"ALanguage.zh-cn.xml",
	L"ALanguage.zh-hk.xml",
	L"ALanguage.zh-tw.xml"
};

// Specifies what files are included in self-extracting packages (no other files will be packaged or extracted).
static wchar_t *szCompressedFiles[]=
{
	L"VeraCrypt User Guide.pdf",
	L"License.txt",
	L"LICENSE",
	L"NOTICE",
	L"VeraCrypt.exe",
	L"VeraCryptExpander.exe",
	L"VeraCrypt Format.exe",
	L"VeraCrypt-x64.exe",
	L"VeraCryptExpander-x64.exe",
	L"VeraCrypt Format-x64.exe",
	L"veracrypt.sys",
	L"veracrypt-x64.sys",
	L"Language.ar.xml",
	L"Language.be.xml",
	L"Language.bg.xml",
	L"Language.ca.xml",
	L"Language.cs.xml",
	L"Language.da.xml",
	L"Language.de.xml",
	L"Language.el.xml",
	L"Language.es.xml",
	L"Language.et.xml",
	L"Language.eu.xml",
	L"Language.fa.xml",
	L"Language.fi.xml",
	L"Language.fr.xml",
	L"Language.hu.xml",
	L"Language.id.xml",
	L"Language.it.xml",
	L"Language.ja.xml",
	L"Language.ka.xml",
	L"Language.ko.xml",
	L"Language.lv.xml",
	L"Language.my.xml",
	L"Language.nl.xml",
	L"Language.nn.xml",
	L"Language.pl.xml",
	L"Language.pt-br.xml",
	L"Language.ru.xml",
	L"Language.sk.xml",
	L"Language.sl.xml",
	L"Language.sv.xml",
	L"Language.tr.xml",
	L"Language.uk.xml",
	L"Language.uz.xml",
	L"Language.vi.xml",
	L"Language.zh-cn.xml",
	L"Language.zh-hk.xml",
	L"Language.zh-tw.xml"
};

#define FILENAME_64BIT_DRIVER	L"veracrypt-x64.sys"
#define NBR_COMPRESSED_FILES (sizeof(szCompressedFiles) / sizeof(szCompressedFiles[0]))

void localcleanup (void);
BOOL StatDeleteFile ( wchar_t *lpszFile, BOOL bCheckForOldFile );
BOOL StatRemoveDirectory ( wchar_t *lpszDir );
HRESULT CreateLink ( wchar_t *lpszPathObj , wchar_t *lpszArguments , wchar_t *lpszPathLink );
void GetProgramPath ( HWND hwndDlg , wchar_t *path );
void StatusMessage (HWND hwndDlg, char *stringId);
void StatusMessageParam (HWND hwndDlg, char *stringId, wchar_t *param);
void ClearLogWindow (HWND hwndDlg);
void RegMessage ( HWND hwndDlg , wchar_t *txt );
void RegRemoveMessage (HWND hwndDlg, wchar_t *txt);
void CopyMessage ( HWND hwndDlg , wchar_t *txt );
void RemoveMessage ( HWND hwndDlg , wchar_t *txt );
void IconMessage ( HWND hwndDlg , wchar_t *txt );
static int CALLBACK BrowseCallbackProc ( HWND hwnd , UINT uMsg , LPARAM lp , LPARAM pData );
void LoadLicense ( HWND hwndDlg );
void DetermineUpgradeDowngradeStatus (BOOL bCloseDriverHandle, LONG *driverVersionPtr);
BOOL DoFilesInstall ( HWND hwndDlg , wchar_t *szDestDir );
BOOL DoRegInstall ( HWND hwndDlg , wchar_t *szDestDir , BOOL bInstallType );
BOOL DoRegUninstall (HWND hwndDlg, BOOL bRemoveDeprecated);
BOOL DoServiceUninstall ( HWND hwndDlg , wchar_t *lpszService );
BOOL DoDriverUnload ( HWND hwndDlg );
BOOL DoShortcutsInstall ( HWND hwndDlg , wchar_t *szDestDir , BOOL bProgGroup, BOOL bDesktopIcon );
BOOL DoShortcutsUninstall (HWND hwndDlg, wchar_t *szDestDir);
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
extern BOOL bReinstallMode;
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
extern wchar_t InstallationPath[TC_MAX_PATH];
extern wchar_t SetupFilesDir[TC_MAX_PATH];

#ifdef __cplusplus
}
#endif

#endif	// #ifndef SETUP_H
