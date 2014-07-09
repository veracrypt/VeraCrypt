/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2012 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include <SrRestorePtApi.h>
#include <io.h>
#include <propkey.h>
#include <propvarutil.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "Apidrvr.h"
#include "BootEncryption.h"
#include "Boot/Windows/BootCommon.h"
#include "Combo.h"
#include "ComSetup.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Registry.h"
#include "Resource.h"

#include "Dir.h"
#include "Setup.h"
#include "SelfExtract.h"
#include "Wizard.h"

#include "../Common/Resource.h"

using namespace VeraCrypt;

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

char InstallationPath[TC_MAX_PATH];
char SetupFilesDir[TC_MAX_PATH];
char UninstallBatch[MAX_PATH];

BOOL bUninstall = FALSE;
BOOL bRestartRequired = FALSE;
BOOL bMakePackage = FALSE;
BOOL bDone = FALSE;
BOOL Rollback = FALSE;
BOOL bUpgrade = FALSE;
BOOL bDowngrade = FALSE;
BOOL SystemEncryptionUpdate = FALSE;
BOOL PortableMode = FALSE;
BOOL bRepairMode = FALSE;
BOOL bChangeMode = FALSE;
BOOL bDevm = FALSE;
BOOL bPossiblyFirstTimeInstall = FALSE;
BOOL bUninstallInProgress = FALSE;
BOOL UnloadDriver = TRUE;

BOOL bSystemRestore = TRUE;
BOOL bDisableSwapFiles = FALSE;
BOOL bForAllUsers = TRUE;
BOOL bRegisterFileExt = TRUE;
BOOL bAddToStartMenu = TRUE;
BOOL bDesktopIcon = TRUE;

BOOL bDesktopIconStatusDetermined = FALSE;

HMODULE volatile SystemRestoreDll = 0;

void localcleanup (void)
{
	localcleanupwiz ();
	cleanup ();

	CloseAppSetupMutex ();
}

BOOL StatDeleteFile (char *lpszFile)
{
	struct __stat64 st;

	if (_stat64 (lpszFile, &st) == 0)
		return DeleteFile (lpszFile);
	else
		return TRUE;
}

BOOL StatRemoveDirectory (char *lpszDir)
{
	struct __stat64 st;

	if (_stat64 (lpszDir, &st) == 0)
		return RemoveDirectory (lpszDir);
	else
		return TRUE;
}

HRESULT CreateLink (char *lpszPathObj, char *lpszArguments,
	    char *lpszPathLink)
{
	HRESULT hres;
	IShellLink *psl;

	/* Get a pointer to the IShellLink interface.  */
	hres = CoCreateInstance (CLSID_ShellLink, NULL,
			       CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID *) &psl);
	if (SUCCEEDED (hres))
	{
		IPersistFile *ppf;

		/* Set the path to the shortcut target, and add the
		   description.  */
		psl->SetPath (lpszPathObj);
		psl->SetArguments (lpszArguments);

		// Application ID
		if (strstr (lpszPathObj, TC_APP_NAME ".exe"))
		{
			IPropertyStore *propStore;

			if (SUCCEEDED (psl->QueryInterface (IID_PPV_ARGS (&propStore))))
			{
				PROPVARIANT propVariant;
				if (SUCCEEDED (InitPropVariantFromString (TC_APPLICATION_ID, &propVariant)))
				{
					if (SUCCEEDED (propStore->SetValue (PKEY_AppUserModel_ID, propVariant)))
						propStore->Commit();

					PropVariantClear (&propVariant);
				}

				propStore->Release();
			}
		}

		/* Query IShellLink for the IPersistFile interface for saving
		   the shortcut in persistent storage.  */
		hres = psl->QueryInterface (IID_IPersistFile,
						    (void **) &ppf);

		if (SUCCEEDED (hres))
		{
			wchar_t wsz[TC_MAX_PATH];

			/* Ensure that the string is ANSI.  */
			MultiByteToWideChar (CP_ACP, 0, lpszPathLink, -1,
					     wsz, sizeof(wsz) / sizeof(wsz[0]));

			/* Save the link by calling IPersistFile::Save.  */
			hres = ppf->Save (wsz, TRUE);
			ppf->Release ();
		}
		psl->Release ();
	}
	return hres;
}

void GetProgramPath (HWND hwndDlg, char *path)
{
	ITEMIDLIST *i;
	HRESULT res;

	if (bForAllUsers)
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_COMMON_PROGRAMS, &i);
	else
        res = SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAMS, &i);

	SHGetPathFromIDList (i, path);
}

void StatusMessage (HWND hwndDlg, char *stringId)
{
	if (Rollback)
		return;

	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) GetString (stringId));

	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

void StatusMessageParam (HWND hwndDlg, char *stringId, char *param)
{
	wchar_t szTmp[1024];

	if (Rollback)
		return;

	wsprintfW (szTmp, L"%s %hs", GetString (stringId), param);
	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) szTmp);
		
	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX, 
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

void ClearLogWindow (HWND hwndDlg)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_RESETCONTENT, 0, 0);
}

void RegMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_REG", txt);
}

void CopyMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "INSTALLING", txt);
}

void RemoveMessage (HWND hwndDlg, char *txt)
{
	if (!Rollback)
		StatusMessageParam (hwndDlg, "REMOVING", txt);
}

void IconMessage (HWND hwndDlg, char *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_ICON", txt);
}

void DetermineUpgradeDowngradeStatus (BOOL bCloseDriverHandle, LONG *driverVersionPtr)
{
	LONG driverVersion = VERSION_NUM;

	if (hDriver == INVALID_HANDLE_VALUE)
		DriverAttach();

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;
		BOOL bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);

		if (!bResult)
			bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);


		bUpgrade = (bResult && driverVersion < VERSION_NUM);
		bDowngrade = (bResult && driverVersion > VERSION_NUM);

		PortableMode = DeviceIoControl (hDriver, TC_IOCTL_GET_PORTABLE_MODE_STATUS, NULL, 0, NULL, 0, &dwResult, NULL);

		if (bCloseDriverHandle)
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
	}

	*driverVersionPtr = driverVersion;
}


static BOOL IsFileInUse (const string &filePath)
{
	HANDLE useTestHandle = CreateFile (filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (useTestHandle != INVALID_HANDLE_VALUE)
		CloseHandle (useTestHandle);
	else if (GetLastError() == ERROR_SHARING_VIOLATION)
		return TRUE;

	return FALSE;
}


BOOL DoFilesInstall (HWND hwndDlg, char *szDestDir)
{
	/* WARNING: Note that, despite its name, this function is used during UNinstallation as well. */

	char szTmp[TC_MAX_PATH];
	BOOL bOK = TRUE;
	int i, x, fileNo;
	char curFileName [TC_MAX_PATH] = {0};

	if (!bUninstall && !bDevm)
	{
		// Self-extract all files to memory

		GetModuleFileName (NULL, szTmp, sizeof (szTmp));

		if (!SelfExtractInMemory (szTmp))
			return FALSE;
	}

	x = strlen (szDestDir);
	if (x < 2)
		return FALSE;

	if (szDestDir[x - 1] != '\\')
		strcat (szDestDir, "\\");

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult;
		char szDir[TC_MAX_PATH];

		if (strstr (szFiles[i], "VeraCrypt Setup") != 0)
		{
			if (bUninstall)
				continue;	// Prevent 'access denied' error

			if (bRepairMode)
				continue;	// Destination = target
		}

		if (*szFiles[i] == 'A')
			strcpy (szDir, szDestDir);
		else if (*szFiles[i] == 'D')
		{
			GetSystemDirectory (szDir, sizeof (szDir));

			x = strlen (szDir);
			if (szDir[x - 1] != '\\')
				strcat (szDir, "\\");

			strcat (szDir, "Drivers\\");
		}
		else if (*szFiles[i] == 'W')
			GetWindowsDirectory (szDir, sizeof (szDir));

		if (*szFiles[i] == 'I')
			continue;

		sprintf (szTmp, "%s%s", szDir, szFiles[i] + 1);

		if (bUninstall == FALSE)
			CopyMessage (hwndDlg, szTmp);
		else
			RemoveMessage (hwndDlg, szTmp);

		if (bUninstall == FALSE)
		{
			SetCurrentDirectory (SetupFilesDir);

			if (strstr (szFiles[i], "VeraCrypt Setup") != 0)
			{
				// Copy ourselves (the distribution package) to the destination location as 'VeraCrypt Setup.exe'

				char mp[MAX_PATH];

				GetModuleFileName (NULL, mp, sizeof (mp));
				bResult = TCCopyFile (mp, szTmp);
			}
			else
			{
				BOOL driver64 = FALSE;

				strncpy (curFileName, szFiles[i] + 1, strlen (szFiles[i]) - 1);
				curFileName [strlen (szFiles[i]) - 1] = 0;

				if (Is64BitOs ()
					&& strcmp (szFiles[i], "Dveracrypt.sys") == 0)
				{
					driver64 = TRUE;
					strncpy (curFileName, FILENAME_64BIT_DRIVER, sizeof (FILENAME_64BIT_DRIVER));
				}

				if (!bDevm)
				{
					bResult = FALSE;

					// Find the correct decompressed file in memory
					for (fileNo = 0; fileNo < NBR_COMPRESSED_FILES; fileNo++)
					{
						// Write the file (stored in memory) directly to the destination location 
						// (there will be no temporary files).
						if (memcmp (
							curFileName, 
							Decompressed_Files[fileNo].fileName, 
							min (strlen (curFileName), (size_t) Decompressed_Files[fileNo].fileNameLength)) == 0)
						{
							// Dump filter driver cannot be installed to SysWOW64 directory
							if (driver64 && !EnableWow64FsRedirection (FALSE))
							{
								handleWin32Error (hwndDlg);
								bResult = FALSE;
								goto err;
							}

							bResult = SaveBufferToFile (
								(char *) Decompressed_Files[fileNo].fileContent,
								szTmp,
								Decompressed_Files[fileNo].fileLength, 
								FALSE);

							if (driver64)
							{
								if (!EnableWow64FsRedirection (TRUE))
								{
									handleWin32Error (hwndDlg);
									bResult = FALSE;
									goto err;
								}

								if (!bResult)
									goto err;

							}

							break;
						}
					}
				}
				else
				{
					if (driver64)
						EnableWow64FsRedirection (FALSE);

					bResult = TCCopyFile (curFileName, szTmp);

					if (driver64)
						EnableWow64FsRedirection (TRUE);
				}

				if (bResult && strcmp (szFiles[i], "AVeraCrypt.exe") == 0)
				{
					string servicePath = GetServiceConfigPath (TC_APP_NAME ".exe");
					if (FileExists (servicePath.c_str()))
					{
						CopyMessage (hwndDlg, (char *) servicePath.c_str());
						bResult = CopyFile (szTmp, servicePath.c_str(), FALSE);
					}
				}
			}
		}
		else
		{
			bResult = StatDeleteFile (szTmp);
		}

err:
		if (bResult == FALSE)
		{
			LPVOID lpMsgBuf;
			DWORD dwError = GetLastError ();
			wchar_t szTmp2[700];

			FormatMessage (
					      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					      NULL,
					      dwError,
				 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
					      (char *) &lpMsgBuf,
					      0,
					      NULL
				);


			if (bUninstall == FALSE)
				wsprintfW (szTmp2, GetString ("INSTALL_OF_FAILED"), szTmp, lpMsgBuf);
			else
				wsprintfW (szTmp2, GetString ("UNINSTALL_OF_FAILED"), szTmp, lpMsgBuf);

			LocalFree (lpMsgBuf);

			if (!Silent && MessageBoxW (hwndDlg, szTmp2, lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
				return FALSE;
		}
	}

	// Language pack
	if (bUninstall == FALSE)
	{
		WIN32_FIND_DATA f;
		HANDLE h;
		
		SetCurrentDirectory (SetupFilesDir);
		h = FindFirstFile ("Language.*.xml", &f);

		if (h != INVALID_HANDLE_VALUE)
		{
			char d[MAX_PATH*2];
			sprintf (d, "%s%s", szDestDir, f.cFileName);
			CopyMessage (hwndDlg, d);
			TCCopyFile (f.cFileName, d);
			FindClose (h);
		}

		SetCurrentDirectory (SetupFilesDir);
		SetCurrentDirectory ("Setup files");
		h = FindFirstFile ("VeraCrypt User Guide.*.pdf", &f);
		if (h != INVALID_HANDLE_VALUE)
		{
			char d[MAX_PATH*2];
			sprintf (d, "%s%s", szDestDir, f.cFileName);
			CopyMessage (hwndDlg, d);
			TCCopyFile (f.cFileName, d);
			FindClose (h);
		}
		SetCurrentDirectory (SetupFilesDir);
	}

	return bOK;
}

BOOL DoRegInstall (HWND hwndDlg, char *szDestDir, BOOL bInstallType)
{
	char szDir[TC_MAX_PATH], *key;
	char szTmp[TC_MAX_PATH*4];
	HKEY hkey = 0;
	BOOL bSlash, bOK = FALSE;
	DWORD dw;
	int x;

	if (SystemEncryptionUpdate)
	{
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt",
			0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			strcpy (szTmp, VERSION_STRING);
			RegSetValueEx (hkey, "DisplayVersion", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1);

			strcpy (szTmp, TC_HOMEPAGE);
			RegSetValueEx (hkey, "URLInfoAbout", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1);

			RegCloseKey (hkey);
		}

		return TRUE;
	}

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	if (bInstallType)
	{

		key = "Software\\Classes\\VeraCryptVolume";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "VeraCrypt Volume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "%ws", TC_APPLICATION_ID);
		if (RegSetValueEx (hkey, "AppUserModelID", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "Software\\Classes\\VeraCryptVolume\\DefaultIcon";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "%sVeraCrypt.exe,1", szDir);
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "Software\\Classes\\VeraCryptVolume\\Shell\\open\\command";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		sprintf (szTmp, "\"%sVeraCrypt.exe\" /v \"%%1\"", szDir );
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = "Software\\Classes\\.hc";
		BOOL typeClassChanged = TRUE;
		char typeClass[256];
		DWORD typeClassSize = sizeof (typeClass);

		if (ReadLocalMachineRegistryString (key, "", typeClass, &typeClassSize) && typeClassSize > 0 && strcmp (typeClass, "VeraCryptVolume") == 0)
			typeClassChanged = FALSE;

		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		strcpy (szTmp, "VeraCryptVolume");
		if (RegSetValueEx (hkey, "", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
			goto error;
		
		RegCloseKey (hkey);
		hkey = 0;

		if (typeClassChanged)
			SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt";
	RegMessage (hwndDlg, key);
	if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
		key,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
		goto error;

	/* IMPORTANT: IF YOU CHANGE THIS IN ANY WAY, REVISE AND UPDATE SetInstallationPath() ACCORDINGLY! */ 
	sprintf (szTmp, "\"%sVeraCrypt Setup.exe\" /u", szDir);
	if (RegSetValueEx (hkey, "UninstallString", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sVeraCrypt Setup.exe\" /c", szDir);
	if (RegSetValueEx (hkey, "ModifyPath", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	sprintf (szTmp, "\"%sVeraCrypt Setup.exe\"", szDir);
	if (RegSetValueEx (hkey, "DisplayIcon", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, VERSION_STRING);
	if (RegSetValueEx (hkey, "DisplayVersion", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;
		
	strcpy (szTmp, "VeraCrypt");
	if (RegSetValueEx (hkey, "DisplayName", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, "IDRIX");
	if (RegSetValueEx (hkey, "Publisher", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	strcpy (szTmp, TC_HOMEPAGE);
	if (RegSetValueEx (hkey, "URLInfoAbout", 0, REG_SZ, (BYTE *) szTmp, strlen (szTmp) + 1) != ERROR_SUCCESS)
		goto error;

	bOK = TRUE;

error:
	if (hkey != 0)
		RegCloseKey (hkey);

	if (bOK == FALSE)
	{
		handleWin32Error (hwndDlg);
		Error ("REG_INSTALL_FAILED");
	}
	
	// Register COM servers for UAC
	if (IsOSAtLeast (WIN_VISTA))
	{
		if (!RegisterComServers (szDir))
		{
			Error ("COM_REG_FAILED");
			return FALSE;
		}
	}

	return bOK;
}

BOOL DoApplicationDataUninstall (HWND hwndDlg)
{
	char path[MAX_PATH];
	char path2[MAX_PATH];
	BOOL bOK = TRUE;

	StatusMessage (hwndDlg, "REMOVING_APPDATA");

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	strcat (path, "\\VeraCrypt\\");

	// Delete favorite volumes file
	sprintf (path2, "%s%s", path, TC_APPD_FILENAME_FAVORITE_VOLUMES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	// Delete keyfile defaults
	sprintf (path2, "%s%s", path, TC_APPD_FILENAME_DEFAULT_KEYFILES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	// Delete history file
	sprintf (path2, "%s%s", path, TC_APPD_FILENAME_HISTORY);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);
	
	// Delete configuration file
	sprintf (path2, "%s%s", path, TC_APPD_FILENAME_CONFIGURATION);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	// Delete system encryption configuration file
	sprintf (path2, "%s%s", path, TC_APPD_FILENAME_SYSTEM_ENCRYPTION);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2);

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	strcat (path, "\\VeraCrypt");
	RemoveMessage (hwndDlg, path);
	if (!StatRemoveDirectory (path))
	{
		handleWin32Error (hwndDlg);
		bOK = FALSE;
	}

	return bOK;
}

BOOL DoRegUninstall (HWND hwndDlg, BOOL bRemoveDeprecated)
{
	BOOL bOK = FALSE;
	char regk [64];

	// Unregister COM servers
	if (!bRemoveDeprecated && IsOSAtLeast (WIN_VISTA))
	{
		if (!UnregisterComServers (InstallationPath))
			StatusMessage (hwndDlg, "COM_DEREG_FAILED");
	}

	if (!bRemoveDeprecated)
		StatusMessage (hwndDlg, "REMOVING_REG");

	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\VeraCryptVolume\\Shell\\open\\command");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\VeraCryptVolume\\Shell\\open");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\VeraCryptVolume\\Shell");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\VeraCryptVolume\\DefaultIcon");
	RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\VeraCryptVolume");
	RegDeleteKey (HKEY_CURRENT_USER, "Software\\VeraCrypt");

	if (!bRemoveDeprecated)
	{
		GetStartupRegKeyName (regk);
		DeleteRegistryValue (regk, "VeraCrypt");

		RegDeleteKey (HKEY_LOCAL_MACHINE, "Software\\Classes\\.hc");
		SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	bOK = TRUE;

	if (bOK == FALSE && GetLastError ()!= ERROR_NO_TOKEN && GetLastError ()!= ERROR_FILE_NOT_FOUND
	    && GetLastError ()!= ERROR_PATH_NOT_FOUND)
	{
		handleWin32Error (hwndDlg);
	}
	else
		bOK = TRUE;

	return bOK;
}


BOOL DoServiceUninstall (HWND hwndDlg, char *lpszService)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status;
	BOOL firstTry = TRUE;
	int x;

	memset (&status, 0, sizeof (status));	/* Keep VC6 quiet */

retry:

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	if (strcmp ("veracrypt", lpszService) == 0)
	{
		try
		{
			BootEncryption bootEnc (hwndDlg);
			if (bootEnc.GetDriverServiceStartType() == SERVICE_BOOT_START)
			{
				try { bootEnc.RegisterFilterDriver (false, BootEncryption::DriveFilter); } catch (...) { }
				try { bootEnc.RegisterFilterDriver (false, BootEncryption::VolumeFilter); } catch (...) { }
				try { bootEnc.RegisterFilterDriver (false, BootEncryption::DumpFilter); } catch (...) { }
			}
		}
		catch (...) { }

		StatusMessage (hwndDlg, "STOPPING_DRIVER");
	}
	else
		StatusMessageParam (hwndDlg, "STOPPING", lpszService);

#define WAIT_PERIOD 3

	for (x = 0; x < WAIT_PERIOD; x++)
	{
		bRet = QueryServiceStatus (hService, &status);
		if (bRet != TRUE)
			goto error;

		if (status.dwCurrentState != SERVICE_START_PENDING &&
		    status.dwCurrentState != SERVICE_STOP_PENDING &&
		    status.dwCurrentState != SERVICE_CONTINUE_PENDING)
			break;

		Sleep (1000);
	}

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		bRet = ControlService (hService, SERVICE_CONTROL_STOP, &status);
		if (bRet == FALSE)
			goto try_delete;

		for (x = 0; x < WAIT_PERIOD; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState != SERVICE_START_PENDING &&
			    status.dwCurrentState != SERVICE_STOP_PENDING &&
			  status.dwCurrentState != SERVICE_CONTINUE_PENDING)
				break;

			Sleep (1000);
		}

		if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
			goto error;
	}

try_delete:

	if (strcmp ("veracrypt", lpszService) == 0)
		StatusMessage (hwndDlg, "REMOVING_DRIVER");
	else
		StatusMessageParam (hwndDlg, "REMOVING", lpszService);

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = DeleteService (hService);
	if (bRet == FALSE)
	{
		if (firstTry && GetLastError () == ERROR_SERVICE_MARKED_FOR_DELETE)
		{
			// Second try for an eventual no-install driver instance
			CloseServiceHandle (hService);
			CloseServiceHandle (hManager);

			Sleep(1000);
			firstTry = FALSE;
			goto retry;
		}

		goto error;
	}

	bOK = TRUE;

error:

	if (bOK == FALSE && GetLastError ()!= ERROR_SERVICE_DOES_NOT_EXIST)
	{
		handleWin32Error (hwndDlg);
		MessageBoxW (hwndDlg, GetString ("DRIVER_UINSTALL_FAILED"), lpszTitle, MB_ICONHAND);
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}


BOOL DoDriverUnload (HWND hwndDlg)
{
	BOOL bOK = TRUE;
	int status;

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR && GetLastError () != ERROR_FILE_NOT_FOUND)
		{
			handleWin32Error (hwndDlg);
			AbortProcess ("NODRIVER");
		}

		if (status != ERR_OS_ERROR)
		{
			handleError (NULL, status);
			AbortProcess ("NODRIVER");
		}
	}

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		MOUNT_LIST_STRUCT driver;
		LONG driverVersion = VERSION_NUM;
		int refCount;
		DWORD dwResult;
		BOOL bResult;

		// Try to determine if it's upgrade (and not reinstall, downgrade, or first-time install).
		DetermineUpgradeDowngradeStatus (FALSE, &driverVersion);

		// Test for encrypted boot drive
		try
		{
			BootEncryption bootEnc (hwndDlg);
			if (bootEnc.GetDriverServiceStartType() == SERVICE_BOOT_START)
			{
				try
				{
					// Check hidden OS update consistency
					if (IsHiddenOSRunning())
					{
						if (bootEnc.GetInstalledBootLoaderVersion() != VERSION_NUM)
						{
							if (AskWarnNoYes ("UPDATE_TC_IN_DECOY_OS_FIRST") == IDNO)
								AbortProcessSilent ();
						}
					}
				}
				catch (...) { }

				if (bUninstallInProgress && driverVersion >= 0x500 && !bootEnc.GetStatus().DriveMounted)
				{
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::DriveFilter); } catch (...) { }
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::VolumeFilter); } catch (...) { }
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::DumpFilter); } catch (...) { }
					bootEnc.SetDriverServiceStartType (SERVICE_SYSTEM_START);
				}
				else if (bUninstallInProgress || bDowngrade)
				{
					Error (bDowngrade ? "SETUP_FAILED_BOOT_DRIVE_ENCRYPTED_DOWNGRADE" : "SETUP_FAILED_BOOT_DRIVE_ENCRYPTED");
					return FALSE;
				}
				else
				{
					if (CurrentOSMajor == 6 && CurrentOSMinor == 0 && CurrentOSServicePack < 1)
						AbortProcess ("SYS_ENCRYPTION_UPGRADE_UNSUPPORTED_ON_VISTA_SP0");

					SystemEncryptionUpdate = TRUE;
					PortableMode = FALSE;
				}
			}
		}
		catch (...)	{ }

		if (!bUninstall
			&& (bUpgrade || SystemEncryptionUpdate)
			&& (!bDevm || SystemEncryptionUpdate))
		{
			UnloadDriver = FALSE;
		}

		if (PortableMode && !SystemEncryptionUpdate)
			UnloadDriver = TRUE;

		if (UnloadDriver)
		{
			int volumesMounted = 0;

			// Check mounted volumes
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
				{
					bOK = FALSE;
					MessageBoxW (hwndDlg, GetString ("DISMOUNT_ALL_FIRST"), lpszTitle, MB_ICONHAND);
				}
			}
			else
			{
				bOK = FALSE;
				handleWin32Error (hwndDlg);
			}
		}

		// Try to close all open TC windows
		if (bOK)
		{
			BOOL TCWindowClosed = FALSE;

			EnumWindows (CloseTCWindowsEnum, (LPARAM) &TCWindowClosed);

			if (TCWindowClosed) 
				Sleep (2000);
		}

		// Test for any applications attached to driver
		if (!bUpgrade)
		{
			bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
				sizeof (refCount), &dwResult, NULL);

			if (bOK && bResult && refCount > 1)
			{
				MessageBoxW (hwndDlg, GetString ("CLOSE_TC_FIRST"), lpszTitle, MB_ICONSTOP);
				bOK = FALSE;
			}
		}

		if (!bOK || UnloadDriver)
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
	}
	else
	{
		// Note that the driver may have already been unloaded during this session (e.g. retry after an error, etc.) so it is not 
		// guaranteed that the user is installing VeraCrypt for the first time now (we also cannot know if the user has already
		// installed and used VeraCrypt on another system before).
		bPossiblyFirstTimeInstall = TRUE;
	}

	return bOK;
}


BOOL UpgradeBootLoader (HWND hwndDlg)
{
	if (!SystemEncryptionUpdate)
		return TRUE;

	try
	{
		BootEncryption bootEnc (hwndDlg);
		if (bootEnc.GetInstalledBootLoaderVersion() < VERSION_NUM)
		{
			StatusMessage (hwndDlg, "INSTALLER_UPDATING_BOOT_LOADER");

			bootEnc.InstallBootLoader (true);

			if (bootEnc.GetInstalledBootLoaderVersion() <= TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION)
				Info (IsHiddenOSRunning() ? "BOOT_LOADER_UPGRADE_OK_HIDDEN_OS" : "BOOT_LOADER_UPGRADE_OK");
		}
		return TRUE;
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
	}
	catch (...) { }

	Error ("BOOT_LOADER_UPGRADE_FAILED");
	return FALSE;
}


BOOL DoShortcutsUninstall (HWND hwndDlg, char *szDestDir)
{
	char szLinkDir[TC_MAX_PATH];
	char szTmp2[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;
	BOOL allUsers = FALSE;

	hOle = OleInitialize (NULL);

	// User start menu
    SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_PROGRAMS, 0);
	x = strlen (szLinkDir);
	if (szLinkDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szLinkDir, "\\");

	strcat (szLinkDir, "VeraCrypt");

	// Global start menu
	{
		struct _stat st;
		char path[TC_MAX_PATH];

		SHGetSpecialFolderPath (hwndDlg, path, CSIDL_COMMON_PROGRAMS, 0);
		strcat (path, "\\VeraCrypt");

		if (_stat (path, &st) == 0)
		{
			strcpy (szLinkDir, path);
			allUsers = TRUE;
		}
	}

	// Start menu entries
	sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt Website.url");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall VeraCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;
	
	sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt User's Guide.lnk");
	DeleteFile (szTmp2);

	// Start menu group
	RemoveMessage ((HWND) hwndDlg, szLinkDir);
	if (StatRemoveDirectory (szLinkDir) == FALSE)
		handleWin32Error ((HWND) hwndDlg);

	// Desktop icon

	if (allUsers)
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
	else
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

	sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt.lnk");

	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2) == FALSE)
		goto error;

	bOK = TRUE;

error:
	OleUninitialize ();

	return bOK;
}

BOOL DoShortcutsInstall (HWND hwndDlg, char *szDestDir, BOOL bProgGroup, BOOL bDesktopIcon)
{
	char szLinkDir[TC_MAX_PATH], szDir[TC_MAX_PATH];
	char szTmp[TC_MAX_PATH], szTmp2[TC_MAX_PATH], szTmp3[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;

	if (bProgGroup == FALSE && bDesktopIcon == FALSE)
		return TRUE;

	hOle = OleInitialize (NULL);

	GetProgramPath (hwndDlg, szLinkDir);

	x = strlen (szLinkDir);
	if (szLinkDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szLinkDir, "\\");

	strcat (szLinkDir, "VeraCrypt");

	strcpy (szDir, szDestDir);
	x = strlen (szDestDir);
	if (szDestDir[x - 1] == '\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		strcat (szDir, "\\");

	if (bProgGroup)
	{
		FILE *f;

		if (mkfulldir (szLinkDir, TRUE) != 0)
		{
			if (mkfulldir (szLinkDir, FALSE) != 0)
			{
				wchar_t szTmp[TC_MAX_PATH];

				handleWin32Error (hwndDlg);
				wsprintfW (szTmp, GetString ("CANT_CREATE_FOLDER"), szLinkDir);
				MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
				goto error;
			}
		}

		sprintf (szTmp, "%s%s", szDir, "VeraCrypt.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;

		sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt Website.url");
		IconMessage (hwndDlg, szTmp2);
		f = fopen (szTmp2, "w");
		if (f)
		{
			fprintf (f, "[InternetShortcut]\nURL=%s\n", TC_HOMEPAGE);

			CheckFileStreamWriteErrors (f, szTmp2);
			fclose (f);
		}
		else
			goto error;

		sprintf (szTmp, "%s%s", szDir, "VeraCrypt Setup.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\Uninstall VeraCrypt.lnk");
		strcpy (szTmp3, "/u");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, szTmp3, szTmp2) != S_OK)
			goto error;

		sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt User's Guide.lnk");
		DeleteFile (szTmp2);
	}

	if (bDesktopIcon)
	{
		strcpy (szDir, szDestDir);
		x = strlen (szDestDir);
		if (szDestDir[x - 1] == '\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			strcat (szDir, "\\");

		if (bForAllUsers)
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
		else
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

		sprintf (szTmp, "%s%s", szDir, "VeraCrypt.exe");
		sprintf (szTmp2, "%s%s", szLinkDir, "\\VeraCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, "", szTmp2) != S_OK)
			goto error;
	}

	bOK = TRUE;

error:
	OleUninitialize ();

	return bOK;
}


void OutcomePrompt (HWND hwndDlg, BOOL bOK)
{
	if (bOK)
	{
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDCANCEL), FALSE);

		bDone = TRUE;

		if (bUninstall == FALSE)
		{
			if (bDevm)
				PostMessage (MainDlg, WM_CLOSE, 0, 0);
			else if (bPossiblyFirstTimeInstall || bRepairMode || (!bUpgrade && !bDowngrade))
				Info ("INSTALL_OK");
			else
				Info ("SETUP_UPDATE_OK");
		}
		else
		{
			wchar_t str[4096];

			swprintf (str, GetString ("UNINSTALL_OK"), InstallationPath);
			MessageBoxW (hwndDlg, str, lpszTitle, MB_ICONASTERISK);
		}
	}
	else
	{
		if (bUninstall == FALSE)
			Error ("INSTALL_FAILED");
		else
			Error ("UNINSTALL_FAILED");
	}
}

static void SetSystemRestorePoint (HWND hwndDlg, BOOL finalize)
{
	static RESTOREPOINTINFO RestPtInfo;
	static STATEMGRSTATUS SMgrStatus;
	static BOOL failed = FALSE;
	static BOOL (__stdcall *_SRSetRestorePoint)(PRESTOREPOINTINFO, PSTATEMGRSTATUS);
	
	if (!SystemRestoreDll) return;

	_SRSetRestorePoint = (BOOL (__stdcall *)(PRESTOREPOINTINFO, PSTATEMGRSTATUS))GetProcAddress (SystemRestoreDll,"SRSetRestorePointA");
	if (_SRSetRestorePoint == 0)
	{
		FreeLibrary (SystemRestoreDll);
		SystemRestoreDll = 0;
		return;
	}

	if (!finalize)
	{
		StatusMessage (hwndDlg, "CREATING_SYS_RESTORE");

		RestPtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
		RestPtInfo.dwRestorePtType = bUninstall ? APPLICATION_UNINSTALL : APPLICATION_INSTALL | DEVICE_DRIVER_INSTALL;
		RestPtInfo.llSequenceNumber = 0;
		strcpy (RestPtInfo.szDescription, bUninstall ? "VeraCrypt uninstallation" : "VeraCrypt installation");

		if(!_SRSetRestorePoint (&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "FAILED_SYS_RESTORE");
			failed = TRUE;
		}
	}
	else if (!failed)
	{
		RestPtInfo.dwEventType = END_SYSTEM_CHANGE;
		RestPtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

		if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus)) 
		{
			StatusMessage (hwndDlg, "FAILED_SYS_RESTORE");
		}
	}
}

void DoUninstall (void *arg)
{
	HWND hwndDlg = (HWND) arg;
	BOOL bOK = TRUE;
	BOOL bTempSkipSysRestore = FALSE;

	if (!Rollback)
		EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), FALSE);

	WaitCursor ();

	if (!Rollback)
	{
		ClearLogWindow (hwndDlg);
	}

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		bOK = FALSE;
		bTempSkipSysRestore = TRUE;		// Volumes are possibly mounted; defer System Restore point creation for this uninstall attempt.
	}
	else
	{
		if (!Rollback && bSystemRestore && !bTempSkipSysRestore)
			SetSystemRestorePoint (hwndDlg, FALSE);

		if (DoServiceUninstall (hwndDlg, "veracrypt") == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoRegUninstall ((HWND) hwndDlg, FALSE) == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoFilesInstall ((HWND) hwndDlg, InstallationPath) == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoShortcutsUninstall (hwndDlg, InstallationPath) == FALSE)
		{
			bOK = FALSE;
		}
		else if (!DoApplicationDataUninstall (hwndDlg))
		{
			bOK = FALSE;
		}
		else
		{
			char temp[MAX_PATH];
			FILE *f;

			// Deprecated service
			DoServiceUninstall (hwndDlg, "VeraCryptService");

			GetTempPath (sizeof (temp), temp);
			_snprintf (UninstallBatch, sizeof (UninstallBatch), "%s\\VeraCrypt-Uninstall.bat", temp);

			UninstallBatch [sizeof(UninstallBatch)-1] = 0;

			// Create uninstall batch
			f = fopen (UninstallBatch, "w");
			if (!f)
				bOK = FALSE;
			else
			{
				fprintf (f, ":loop\n"
					"del \"%s%s\"\n"
					"if exist \"%s%s\" goto loop\n"
					"rmdir \"%s\"\n"
					"del \"%s\"",
					InstallationPath, "VeraCrypt Setup.exe",
					InstallationPath, "VeraCrypt Setup.exe",
					InstallationPath,
					UninstallBatch
					);

				CheckFileStreamWriteErrors (f, UninstallBatch);
				fclose (f);
			}
		}
	}

	NormalCursor ();

	if (Rollback)
		return;

	if (bSystemRestore && !bTempSkipSysRestore)
		SetSystemRestorePoint (hwndDlg, TRUE);

	if (bOK)
		PostMessage (hwndDlg, TC_APPMSG_UNINSTALL_SUCCESS, 0, 0);
	else
		bUninstallInProgress = FALSE;

	EnableWindow (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), TRUE);
	OutcomePrompt (hwndDlg, bOK);
}

void DoInstall (void *arg)
{
	HWND hwndDlg = (HWND) arg;
	BOOL bOK = TRUE;
	char path[MAX_PATH];

	BootEncryption bootEnc (hwndDlg);

	// Refresh the main GUI (wizard thread)
	InvalidateRect (MainDlg, NULL, TRUE);

	ClearLogWindow (hwndDlg);

	if (mkfulldir (InstallationPath, TRUE) != 0)
	{
		if (mkfulldir (InstallationPath, FALSE) != 0)
		{
			wchar_t szTmp[TC_MAX_PATH];

			handleWin32Error (hwndDlg);
			wsprintfW (szTmp, GetString ("CANT_CREATE_FOLDER"), InstallationPath);
			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
			Error ("INSTALL_FAILED");
			PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
			return;
		}
	}

	UpdateProgressBarProc(2);

	if (DoDriverUnload (hwndDlg) == FALSE)
	{
		NormalCursor ();
		PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
		return;
	}

	if (bUpgrade
		&& (IsFileInUse (string (InstallationPath) + '\\' + TC_APP_NAME ".exe")
			|| IsFileInUse (string (InstallationPath) + '\\' + TC_APP_NAME " Format.exe")
			|| IsFileInUse (string (InstallationPath) + '\\' + TC_APP_NAME " Setup.exe")
			)
		)
	{
		NormalCursor ();
		Error ("CLOSE_TC_FIRST");
		PostMessage (MainDlg, TC_APPMSG_INSTALL_FAILURE, 0, 0);
		return;
	}

	UpdateProgressBarProc(12);
	
	if (bSystemRestore)
		SetSystemRestorePoint (hwndDlg, FALSE);

	UpdateProgressBarProc(48);
	
	if (bDisableSwapFiles
		&& IsPagingFileActive (FALSE))
	{
		if (!DisablePagingFile())
		{
			handleWin32Error (hwndDlg);
			Error ("FAILED_TO_DISABLE_PAGING_FILES");
		}
		else
			bRestartRequired = TRUE;
	}

	UpdateProgressBarProc(50);

	// Remove deprecated
	DoServiceUninstall (hwndDlg, "VeraCryptService");
	
	UpdateProgressBarProc(55);

	if (!SystemEncryptionUpdate)
		DoRegUninstall ((HWND) hwndDlg, TRUE);

	UpdateProgressBarProc(61);

	GetWindowsDirectory (path, sizeof (path));
	strcat_s (path, sizeof (path), "\\VeraCrypt Setup.exe");
	DeleteFile (path);

	if (UpdateProgressBarProc(63) && UnloadDriver && DoServiceUninstall (hwndDlg, "veracrypt") == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(72) && DoFilesInstall ((HWND) hwndDlg, InstallationPath) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(80) && DoRegInstall ((HWND) hwndDlg, InstallationPath, bRegisterFileExt) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(85) && UnloadDriver && DoDriverInstall (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(90) && SystemEncryptionUpdate && UpgradeBootLoader (hwndDlg) == FALSE)
	{
		bOK = FALSE;
	}
	else if (UpdateProgressBarProc(93) && DoShortcutsInstall (hwndDlg, InstallationPath, bAddToStartMenu, bDesktopIcon) == FALSE)
	{
		bOK = FALSE;
	}

	if (!UnloadDriver)
		bRestartRequired = TRUE;

	try
	{
		bootEnc.RenameDeprecatedSystemLoaderBackup();
	}
	catch (...)	{ }

	if (bOK)
		UpdateProgressBarProc(97);

	if (bSystemRestore)
		SetSystemRestorePoint (hwndDlg, TRUE);

	if (bOK)
	{
		UpdateProgressBarProc(100);
		UninstallBatch[0] = 0;
		StatusMessage (hwndDlg, "INSTALL_COMPLETED");
	}
	else
	{
		UpdateProgressBarProc(0);

		if (!SystemEncryptionUpdate)
		{
			bUninstall = TRUE;
			Rollback = TRUE;
			Silent = TRUE;

			DoUninstall (hwndDlg);

			bUninstall = FALSE;
			Rollback = FALSE;
			Silent = FALSE;

			StatusMessage (hwndDlg, "ROLLBACK");
		}
		else
		{
			Warning ("SYS_ENC_UPGRADE_FAILED");
		}
	}

outcome:
	OutcomePrompt (hwndDlg, bOK);

	if (bOK && !bUninstall && !bDowngrade && !bRepairMode && !bDevm)
	{
		if (!IsHiddenOSRunning())	// A hidden OS user should not see the post-install notes twice (on decoy OS and then on hidden OS).
		{
			if (bRestartRequired || SystemEncryptionUpdate)
			{
				// Restart required

				if (bUpgrade)
				{
					SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_RELEASE_NOTES);
				}
				else if (bPossiblyFirstTimeInstall)
				{
					SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_TUTORIAL);
				}
			}
			else
			{
				// No restart will be required

				if (bUpgrade)
				{
					bPromptReleaseNotes = TRUE;
				}
				else if (bPossiblyFirstTimeInstall)
				{
					bPromptTutorial = TRUE;
				}
			}
		}
	}

	PostMessage (MainDlg, bOK ? TC_APPMSG_INSTALL_SUCCESS : TC_APPMSG_INSTALL_FAILURE, 0, 0);
}


void SetInstallationPath (HWND hwndDlg)
{
	HKEY hkey;
	BOOL bInstallPathDetermined = FALSE;
	char path[MAX_PATH+20];
	ITEMIDLIST *itemList;

	memset (InstallationPath, 0, sizeof (InstallationPath));

	// Determine if VeraCrypt is already installed and try to determine its "Program Files" location
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		/* Default 'UninstallString' registry strings written by past versions of VeraCrypt:
		------------------------------------------------------------------------------------
		1.0		C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		1.0a	C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		2.0		C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		2.1		C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		2.1a	C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		3.0		C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		3.0a	C:\WINDOWS\VeraCrypt Setup.exe /u			[optional]
		3.1		The UninstallString was NEVER written (fortunately, 3.1a replaced 3.1 after 2 weeks)
		3.1a	C:\WINDOWS\VeraCrypt Setup.exe /u
		4.0		C:\WINDOWS\VeraCrypt Setup.exe /u C:\Program Files\VeraCrypt
		4.1		C:\WINDOWS\VeraCrypt Setup.exe /u C:\Program Files\VeraCrypt
		4.2		C:\WINDOWS\VeraCrypt Setup.exe /u C:\Program Files\VeraCrypt
		4.2a	C:\WINDOWS\VeraCrypt Setup.exe /u C:\Program Files\VeraCrypt
		4.3		"C:\Program Files\VeraCrypt\VeraCrypt Setup.exe" /u C:\Program Files\VeraCrypt\
		4.3a	"C:\Program Files\VeraCrypt\VeraCrypt Setup.exe" /u C:\Program Files\VeraCrypt\
		5.0+	"C:\Program Files\VeraCrypt\VeraCrypt Setup.exe" /u

		Note: In versions 1.0-3.0a the user was able to choose whether to install the uninstaller.
			  The default was to install it. If it wasn't installed, there was no UninstallString.
		*/

		char rv[MAX_PATH*4];
		DWORD size = sizeof (rv);
		if (RegQueryValueEx (hkey, "UninstallString", 0, 0, (LPBYTE) &rv, &size) == ERROR_SUCCESS && strrchr (rv, '/'))
		{
			size_t len = 0;

			// Cut and paste the location (path) where VeraCrypt is installed to InstallationPath
			if (rv[0] == '"')
			{
				// 4.3 or later

				len = strrchr (rv, '/') - rv - 2;
				strncpy (InstallationPath, rv + 1, len);
				InstallationPath [len] = 0;
				bInstallPathDetermined = TRUE;

				if (InstallationPath [strlen (InstallationPath) - 1] != '\\')
				{
					len = strrchr (InstallationPath, '\\') - InstallationPath;
					InstallationPath [len] = 0;
				}
			}
			else
			{
				// 1.0-4.2a (except 3.1)

				len = strrchr (rv, '/') - rv;
				if (rv[len+2] == ' ')
				{
					// 4.0-4.2a

					strncpy (InstallationPath, rv + len + 3, strlen (rv) - len - 3);
					InstallationPath [strlen (rv) - len - 3] = 0;
					bInstallPathDetermined = TRUE;
				}
				else
				{
					// 1.0-3.1a (except 3.1)

					// We know that VeraCrypt is installed but don't know where. It's not safe to continue installing
					// over the old version.

					Error ("UNINSTALL_OLD_VERSION_FIRST");

					len = strrchr (rv, '/') - rv - 1;
					strncpy (InstallationPath, rv, len);	// Path and filename of the uninstaller
					InstallationPath [len] = 0;
					bInstallPathDetermined = FALSE;

					ShellExecute (NULL, "open", InstallationPath, "/u", NULL, SW_SHOWNORMAL);
					RegCloseKey (hkey);
					exit (1);
				}
			}

		}
		RegCloseKey (hkey);
	}

	if (bInstallPathDetermined)
	{
		char mp[MAX_PATH];

		// Determine whether we were launched from the folder where VeraCrypt is installed
		GetModuleFileName (NULL, mp, sizeof (mp));
		if (strncmp (InstallationPath, mp, min (strlen(InstallationPath), strlen(mp))) == 0)
		{
			// We were launched from the folder where VeraCrypt is installed

			if (!IsNonInstallMode() && !bDevm)
				bChangeMode = TRUE;
		}
	}
	else
	{
		/* TrueCypt is not installed or it wasn't possible to determine where it is installed. */

		// Default "Program Files" path. 
		SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &itemList);
		SHGetPathFromIDList (itemList, path);

		if (Is64BitOs())
		{
			// Use a unified default installation path (registry redirection of %ProgramFiles% does not work if the installation path is user-selectable)
			string s = path;
			size_t p = s.find (" (x86)");
			if (p != string::npos)
			{
				s = s.substr (0, p);
				if (_access (s.c_str(), 0) != -1)
					strcpy_s (path, sizeof (path), s.c_str());
			}
		}

		strncat (path, "\\VeraCrypt\\", min (strlen("\\VeraCrypt\\"), sizeof(path)-strlen(path)-1));
		strncpy (InstallationPath, path, sizeof(InstallationPath)-1);
	}

	// Make sure the path ends with a backslash
	if (InstallationPath [strlen (InstallationPath) - 1] != '\\')
	{
		strcat (InstallationPath, "\\");
	}
}


// Handler for uninstall only (install is handled by the wizard)
BOOL CALLBACK UninstallDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:

		MainDlg = hwndDlg;

		if (!CreateAppSetupMutex ())
			AbortProcess ("TC_INSTALLER_IS_RUNNING");

		InitDialog (hwndDlg);
		LocalizeDialog (hwndDlg, NULL);

		SetWindowTextW (hwndDlg, lpszTitle);

		// System Restore
		SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, bSystemRestore);
		if (SystemRestoreDll == 0)
		{
			SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), FALSE);
		}

		SetFocus (GetDlgItem (hwndDlg, IDC_UNINSTALL));

		return 1;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);
			return 1;
		}
		return 0;

	case WM_COMMAND:
		if (lw == IDC_UNINSTALL)
		{
			if (bDone)
			{
				bUninstallInProgress = FALSE;
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			bUninstallInProgress = TRUE;

			WaitCursor ();

			if (bUninstall)
				_beginthread (DoUninstall, 0, (void *) hwndDlg);

			return 1;
		}

		if (lw == IDC_SYSTEM_RESTORE)
		{
			bSystemRestore = IsButtonChecked (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE));
			return 1;
		}

		if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}

		return 0;

	case TC_APPMSG_UNINSTALL_SUCCESS:
		SetWindowTextW (GetDlgItem ((HWND) hwndDlg, IDC_UNINSTALL), GetString ("FINALIZE"));
		NormalCursor ();
		return 1;

	case WM_CLOSE:
		if (bUninstallInProgress)
		{
			NormalCursor();
			if (AskNoYes("CONFIRM_EXIT_UNIVERSAL") == IDNO)
			{
				return 1;
			}
			WaitCursor ();
		}
		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, char *lpszCommandLine, int nCmdShow)
{
	atexit (localcleanup);

	SelfExtractStartupInit();

	lpszTitle = L"VeraCrypt Setup";

	InitCommonControls ();

	/* Call InitApp to initialize the common code */
	InitApp (hInstance, NULL);

	if (IsAdmin () != TRUE)
		if (MessageBoxW (NULL, GetString ("SETUP_ADMIN"), lpszTitle, MB_YESNO | MB_ICONQUESTION) != IDYES)
		{
			exit (1);
		}

	/* Setup directory */
	{
		char *s;
		GetModuleFileName (NULL, SetupFilesDir, sizeof (SetupFilesDir));
		s = strrchr (SetupFilesDir, '\\');
		if (s)
			s[1] = 0;
	}

	/* Parse command line arguments */

	if (lpszCommandLine[0] == '/')
	{
		if (lpszCommandLine[1] == 'u')
		{
			// Uninstall:	/u

			bUninstall = TRUE;
		}
		else if (lpszCommandLine[1] == 'c')
		{
			// Change:	/c

			bChangeMode = TRUE;
		}
		else if (lpszCommandLine[1] == 'p')
		{
			// Create self-extracting package:	/p

			bMakePackage = TRUE;
		}
		else if (lpszCommandLine[1] == 'd')
		{
			// Dev mode:	/d
			bDevm = TRUE;
		}
	}

	if (bMakePackage)
	{
		/* Create self-extracting package */

		MakeSelfExtractingPackage (NULL, SetupFilesDir);
	}
	else
	{
		SetInstallationPath (NULL);

		if (!bUninstall)
		{
			if (IsSelfExtractingPackage())
			{
				if (!VerifyPackageIntegrity())
				{
					// Package corrupted 
					exit (1);
				}
				bDevm = FALSE;
			}
			else if (!bDevm)
			{
				MessageBox (NULL, "Error: This installer file does not contain any compressed files.\n\nTo create a self-extracting installation package (with embedded compressed files), run:\n\"VeraCrypt Setup.exe\" /p", "VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
				exit (1);
			}

			if (bChangeMode)
			{
				/* VeraCrypt is already installed on this system and we were launched from the Program Files folder */

				char *tmpStr[] = {0, "SELECT_AN_ACTION", "REPAIR_REINSTALL", "UNINSTALL", "EXIT", 0};

				// Ask the user to select either Repair or Unistallation
				switch (AskMultiChoice ((void **) tmpStr, FALSE))
				{
				case 1:
					bRepairMode = TRUE;
					break;
				case 2:
					bUninstall = TRUE;
					break;
				default:
					exit (1);
				}
			}
		}

		// System Restore
		char dllPath[MAX_PATH];
		if (GetSystemDirectory (dllPath, MAX_PATH))
		{
			strcat(dllPath, "\\srclient.dll");
		}
		else
			strcpy(dllPath, "C:\\Windows\\System32\\srclient.dll");
		SystemRestoreDll = LoadLibrary (dllPath);

		if (!bUninstall)
		{
			/* Create the main dialog for install */

			DialogBoxParamW (hInstance, MAKEINTRESOURCEW (IDD_INSTL_DLG), NULL, (DLGPROC) MainDialogProc, 
				(LPARAM)lpszCommandLine);
		}
		else
		{
			/* Create the main dialog for uninstall  */

			DialogBoxW (hInstance, MAKEINTRESOURCEW (IDD_UNINSTALL), NULL, (DLGPROC) UninstallDlgProc);

			if (UninstallBatch[0])
			{
				STARTUPINFO si;
				PROCESS_INFORMATION pi;

				ZeroMemory (&si, sizeof (si));
				si.cb = sizeof (si);
				si.dwFlags = STARTF_USESHOWWINDOW;
				si.wShowWindow = SW_HIDE;

				if (!CreateProcess (UninstallBatch, NULL, NULL, NULL, FALSE, IDLE_PRIORITY_CLASS, NULL, NULL, &si, &pi))
					DeleteFile (UninstallBatch);
				else
				{
					CloseHandle (pi.hProcess);
					CloseHandle (pi.hThread);
				}
			}
		}
	}

	return 0;
}
