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
#include <SrRestorePtApi.h>
#include <io.h>
#include <propkey.h>
#include <propvarutil.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tchar.h>

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

#include <Strsafe.h>

wchar_t InstallationPath[TC_MAX_PATH];
wchar_t SetupFilesDir[TC_MAX_PATH];
wchar_t UninstallBatch[MAX_PATH];

BOOL bUninstall = FALSE;
BOOL bRestartRequired = FALSE;
BOOL bMakePackage = FALSE;
BOOL bDone = FALSE;
BOOL Rollback = FALSE;
BOOL bUpgrade = FALSE;
BOOL bUpdateRescueDisk = FALSE;
BOOL bDowngrade = FALSE;
BOOL SystemEncryptionUpdate = FALSE;
BOOL PortableMode = FALSE;
BOOL bRepairMode = FALSE;
BOOL bReinstallMode = FALSE;
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

BOOL ForceDeleteFile (LPCWSTR szFileName)
{
	if (!DeleteFile (szFileName))
	{
		/* delete the renamed file when the machine reboots */
		return MoveFileEx (szFileName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
	}
	else
		return TRUE;
}

BOOL StatDeleteFile (wchar_t *lpszFile, BOOL bCheckForOldFile)
{
	struct __stat64 st;

	if (bCheckForOldFile)
	{
		wchar_t szOldPath[MAX_PATH + 1];
		StringCbCopyW (szOldPath, sizeof(szOldPath), lpszFile);
		StringCbCatW  (szOldPath, sizeof(szOldPath), VC_FILENAME_RENAMED_SUFFIX);

		if (_wstat64 (szOldPath, &st) == 0)
		{
			ForceDeleteFile (szOldPath);
		}
	}

	if (_wstat64 (lpszFile, &st) == 0)
		return ForceDeleteFile (lpszFile);
	else
		return TRUE;
}

BOOL StatRemoveDirectory (wchar_t *lpszDir)
{
	struct __stat64 st;

	if (_wstat64 (lpszDir, &st) == 0)
	{
		return DeleteDirectory (lpszDir);
	}
	else
		return TRUE;
}


/* Recursively set the given OWNER security descriptor to the key and its subkeys */
static void RecursiveSetOwner (HKEY hKey, PSECURITY_DESCRIPTOR pSD)
{
	LSTATUS status = 0;
	DWORD dwIndex = 0, dwMaxNameLen = 0, dwNameLen = 0, numberSubKeys = 0;
	HKEY hSubKey;

	if (	(ERROR_SUCCESS == status) && (ERROR_SUCCESS == RegQueryInfoKey(hKey, NULL, NULL, NULL, &numberSubKeys, &dwMaxNameLen, NULL, NULL, NULL, NULL, NULL, NULL))
		&&	(numberSubKeys >= 1)
		)
	{
		dwMaxNameLen++;
		wchar_t* szNameValue = new wchar_t[dwMaxNameLen];
		while (true)
		{
			dwNameLen = dwMaxNameLen;
			status = RegEnumKeyExW (hKey, dwIndex++, szNameValue, &dwNameLen, NULL, NULL, NULL, NULL);
			if (status == ERROR_SUCCESS)
			{
				status = RegOpenKeyExW (hKey, szNameValue, 0, WRITE_OWNER | KEY_READ , &hSubKey);
				if (ERROR_SUCCESS == status)
				{
					RecursiveSetOwner (hSubKey, pSD);
					RegCloseKey(hSubKey);
				}
			}
			else
				break;
		}
		delete [] szNameValue;
	}

	RegSetKeySecurity (hKey, OWNER_SECURITY_INFORMATION, pSD);
}

/* Recursively set the given DACL security descriptor to the key and its subkeys */
static void RecursiveSetDACL (HKEY hKey, const wchar_t* SubKeyName, PSECURITY_DESCRIPTOR pSD)
{
	HKEY hSubKey;
	DWORD dwIndex = 0, dwMaxNameLen = 0, dwNameLen = 0, numberSubKeys = 0;
	LSTATUS status = RegOpenKeyExW(hKey, SubKeyName, 0, WRITE_DAC | KEY_READ /*| ACCESS_SYSTEM_SECURITY*/, &hSubKey);
	if (status == ERROR_SUCCESS)
	{
		status = RegSetKeySecurity (hSubKey, DACL_SECURITY_INFORMATION, pSD);
		if (status == ERROR_SUCCESS)
		{
			RegCloseKey(hSubKey);
			status = RegOpenKeyExW(hKey, SubKeyName, 0, WRITE_DAC | KEY_READ , &hSubKey);
		}

		if ( (ERROR_SUCCESS == status)
			&&	(ERROR_SUCCESS == RegQueryInfoKeyW(hSubKey, NULL, NULL, NULL, &numberSubKeys, &dwMaxNameLen, NULL, NULL, NULL, NULL, NULL, NULL))
			&&	(numberSubKeys >= 1)
			)
		{
			dwMaxNameLen++;
			wchar_t* szNameValue = new wchar_t[dwMaxNameLen];
			while (true)
			{
				dwNameLen = dwMaxNameLen;
				status = RegEnumKeyExW (hSubKey, dwIndex++, szNameValue, &dwNameLen, NULL, NULL, NULL, NULL);
				if (status == ERROR_SUCCESS)
			 	{
					RecursiveSetDACL (hSubKey, szNameValue, pSD);
				}
				else
					break;
			}
			delete [] szNameValue;
		}
	}
}

/* Correct the key permissions to allow its deletion */
static void AllowKeyAccess(HKEY Key,const wchar_t* SubKeyName)
{
	LSTATUS RegResult;
	HKEY SvcKey = NULL;
	DWORD dwLength = 0;
	HANDLE Token = NULL;
	PTOKEN_USER pTokenUser = NULL;
	std::string sNewSD;

	RegResult = RegOpenKeyExW(Key, SubKeyName, 0, WRITE_OWNER | KEY_READ, &SvcKey);
	if (RegResult==ERROR_SUCCESS)
	{
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
		{
			if (!GetTokenInformation(Token, TokenUser, pTokenUser, 0, &dwLength))
			{
				if (GetLastError() ==ERROR_INSUFFICIENT_BUFFER)
				{
					pTokenUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
					if (pTokenUser)
					{
						if (GetTokenInformation(Token, TokenUser, pTokenUser, dwLength, &dwLength))
						{
							SECURITY_DESCRIPTOR SecDesc;
							if (	InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION)
								&&	SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE) // NULL DACL: full access to everyone
								&& SetSecurityDescriptorOwner(&SecDesc, pTokenUser->User.Sid, FALSE)
								)
							{
								RecursiveSetOwner(SvcKey, &SecDesc);
							}
						}

					}
				}
			}
		}
		RegCloseKey(SvcKey);
	}

	if (pTokenUser)
	{
		PSID pSid = pTokenUser->User.Sid;
		DWORD dwAclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(pSid) - sizeof(DWORD);
		PACL pDacl = (PACL) new BYTE[dwAclSize];
		if (pDacl)
		{
			if (TRUE == ::InitializeAcl(pDacl, dwAclSize, ACL_REVISION))
			{
				if (TRUE == AddAccessAllowedAceEx(pDacl, ACL_REVISION, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, WRITE_DAC | KEY_ALL_ACCESS, pSid))
				{
					SECURITY_DESCRIPTOR SecDesc;
					if (TRUE == ::InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION))
					{
						if (TRUE == ::SetSecurityDescriptorDacl(&SecDesc, TRUE, pDacl, FALSE))
						{
							RecursiveSetDACL (Key, SubKeyName, &SecDesc);
						}
					}
				}
			}
			delete [] pDacl;
		}
	}

	if (pTokenUser)
		HeapFree(GetProcessHeap(), 0, pTokenUser);
	if (Token)
		CloseHandle(Token);
}

void SearchAndDeleteRegistrySubString (HKEY hKey, const wchar_t *subKey, const wchar_t *str, BOOL bEnumSubKeys, const wchar_t* enumMatchSubStr)
{
	HKEY hSubKey = 0;
	LSTATUS status = 0;
	DWORD dwIndex = 0, dwType, dwValueNameLen, dwDataLen;
	std::list<std::wstring> subKeysList;
	size_t subStringLength = str? wcslen(str) : 0;

	if (bEnumSubKeys)
	{
         DWORD dwMaxNameLen = 0;
         if (ERROR_SUCCESS == RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, &dwMaxNameLen, NULL, NULL, NULL, NULL, NULL, NULL))
         {
            dwMaxNameLen++;
            wchar_t* szNameValue = new wchar_t[dwMaxNameLen];
			   dwIndex = 0;
			   while (true)
			   {
				   dwValueNameLen = dwMaxNameLen;
				   status = RegEnumKeyExW (hKey, dwIndex++, szNameValue, &dwValueNameLen, NULL, NULL, NULL, NULL);
				   if (status == ERROR_SUCCESS)
				   {
						if (enumMatchSubStr && !wcsstr(szNameValue, enumMatchSubStr))
							continue;
					std::wstring entryName = szNameValue;
					entryName += L"\\";
					entryName += subKey;
					entryName += L"\\";
					subKeysList.push_back(entryName);
				   }
				   else
					   break;
			   }
            delete [] szNameValue;
         }
	}
	else
	{
		subKeysList.push_back(subKey);
	}

	for (std::list<std::wstring>::iterator ItSubKey = subKeysList.begin(); ItSubKey != subKeysList.end(); ItSubKey++)
	{
		// if the string to search for is empty, delete the sub key, otherwise, look for matching value and delete them
		if (subStringLength == 0)
		{
			if (ERROR_ACCESS_DENIED == DeleteRegistryKey (hKey, ItSubKey->c_str()))
			{
				// grant permission to delete
				AllowKeyAccess (hKey, ItSubKey->c_str());

				// try again
				DeleteRegistryKey (hKey, ItSubKey->c_str());
			}
		}
		else
		{
			if (RegOpenKeyExW (hKey, ItSubKey->c_str(), 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
			{
            DWORD dwMaxNameLen = 0, dwMaxDataLen = 0;
            if (ERROR_SUCCESS == RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &dwMaxNameLen, &dwMaxDataLen, NULL, NULL))
            {
               dwMaxNameLen++;
               wchar_t* szNameValue = new wchar_t[dwMaxNameLen];
               LPBYTE pbData = new BYTE[dwMaxDataLen];

				   std::list<std::wstring> foundEntries;
				   dwIndex = 0;
				   do
				   {
					   dwValueNameLen = dwMaxNameLen;
					   dwDataLen = dwMaxDataLen;
					   status = RegEnumValueW(hSubKey, dwIndex++, szNameValue, &dwValueNameLen, NULL, &dwType, pbData, &dwDataLen);
					   if (status == ERROR_SUCCESS)
					   {
						   if (	(wcslen(szNameValue) >= subStringLength && wcsstr(szNameValue, str))
							   ||	(dwType == REG_SZ && wcslen((wchar_t*) pbData) >= subStringLength && wcsstr((wchar_t*) pbData, str))
							   )
						   {
							   foundEntries.push_back(szNameValue);
						   }
					   }
				   } while ((status == ERROR_SUCCESS) || (status == ERROR_MORE_DATA)); // we ignore ERROR_MORE_DATA errors since
                                                                                   // we are sure to use the correct sizes

				   // delete the entries
				   if (!foundEntries.empty())
				   {
					   for (std::list<std::wstring>::iterator It = foundEntries.begin();
						   It != foundEntries.end(); It++)
					   {
						   RegDeleteValueW (hSubKey, It->c_str());
					   }
				   }

               delete [] szNameValue;
               delete [] pbData;
            }


				RegCloseKey (hSubKey);
			}
		}
	}
}

/* Set the given privilege of the current process */
BOOL SetPrivilege(LPTSTR szPrivilegeName, BOOL bEnable)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hProcessToken;
	BOOL bStatus = FALSE;

	if ( OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			&hProcessToken) )
	{
		if ( LookupPrivilegeValue(
				NULL,
				szPrivilegeName,
				&luid ) )
		{

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = bEnable? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

			// Enable the privilege
			bStatus = AdjustTokenPrivileges(
				hProcessToken,
				FALSE,
				&tp,
				sizeof(TOKEN_PRIVILEGES),
				(PTOKEN_PRIVILEGES) NULL,
				(PDWORD) NULL);
		}

		CloseHandle(hProcessToken);
	}

	return bStatus;
}

/*
 * Creates a VT_LPWSTR propvariant.
 * we use our own implementation to use SHStrDupW function pointer
 * that we retreive ourselves to avoid dll hijacking attacks
 */
inline HRESULT VCInitPropVariantFromString(__in PCWSTR psz, __out PROPVARIANT *ppropvar)
{
    ppropvar->vt = VT_LPWSTR;
    HRESULT hr = VCStrDupW(psz, &ppropvar->pwszVal);
    if (FAILED(hr))
    {
        PropVariantInit(ppropvar);
    }
    return hr;
}

HRESULT CreateLink (wchar_t *lpszPathObj, wchar_t *lpszArguments,
	    wchar_t *lpszPathLink, const wchar_t* iconFile, int iconIndex)
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
		if (iconFile)
		{
			psl->SetIconLocation (iconFile, iconIndex);
		}

		// Application ID
		if (_tcsstr (lpszPathObj, _T(TC_APP_NAME) _T(".exe")))
		{
			IPropertyStore *propStore;

			if (SUCCEEDED (psl->QueryInterface (IID_PPV_ARGS (&propStore))))
			{
				PROPVARIANT propVariant;
				if (SUCCEEDED (VCInitPropVariantFromString (TC_APPLICATION_ID, &propVariant)))
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
			/* Save the link by calling IPersistFile::Save.  */
			hres = ppf->Save (lpszPathLink, TRUE);
			ppf->Release ();
		}
		psl->Release ();
	}
	return hres;
}

BOOL IsSystemRestoreEnabled ()
{
	BOOL bEnabled = FALSE;
	HKEY hKey;
	DWORD dwValue = 0, cbValue = sizeof (DWORD);
	wchar_t szRegPath[MAX_PATH];
	GetRestorePointRegKeyName (szRegPath, sizeof (szRegPath));
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, szRegPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
	{
		if (IsOSAtLeast (WIN_VISTA))
		{
			if (	(ERROR_SUCCESS == RegQueryValueEx (hKey, L"RPSessionInterval", NULL, NULL, (LPBYTE) &dwValue, &cbValue))
				&&	(dwValue == 1)
				)
			{
				bEnabled = TRUE;
			}
		}
		else
		{
			if (	(ERROR_SUCCESS == RegQueryValueEx (hKey, L"DisableSR", NULL, NULL, (LPBYTE) &dwValue, &cbValue))
				&&	(dwValue == 0)
				)
			{
				bEnabled = TRUE;
			}
		}


		RegCloseKey (hKey);
	}

	return bEnabled;
}

void GetProgramPath (HWND hwndDlg, wchar_t *path)
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

void StatusMessageParam (HWND hwndDlg, char *stringId, const wchar_t *param)
{
	wchar_t szTmp[1024];

	if (Rollback)
		return;

	StringCbPrintfW (szTmp, sizeof(szTmp), L"%s %s", GetString (stringId), param);
	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) szTmp);

	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX,
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

void ClearLogWindow (HWND hwndDlg)
{
	SendMessage (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_RESETCONTENT, 0, 0);
}

void RegMessage (HWND hwndDlg, const wchar_t *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_REG", txt);
}

void _cdecl CopyMessage (HWND hwndDlg, const wchar_t *txt)
{
	StatusMessageParam (hwndDlg, "INSTALLING", txt);
}

void RemoveMessage (HWND hwndDlg, const wchar_t *txt)
{
	if (!Rollback)
		StatusMessageParam (hwndDlg, "REMOVING", txt);
}

void IconMessage (HWND hwndDlg, const wchar_t *txt)
{
	StatusMessageParam (hwndDlg, "ADDING_ICON", txt);
}

void DetermineUpgradeDowngradeStatus (BOOL bCloseDriverHandle, LONG *driverVersionPtr)
{
	LONG driverVersion = VERSION_NUM;
	int status = 0;

	if (hDriver == INVALID_HANDLE_VALUE)
		status = DriverAttach();

	if ((status == 0) && (hDriver != INVALID_HANDLE_VALUE))
	{
		DWORD dwResult;
		BOOL bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);

		if (!bResult)
			bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &driverVersion, sizeof (driverVersion), &dwResult, NULL);


		bUpgrade = (bResult && driverVersion <= VERSION_NUM);
		bDowngrade = (bResult && driverVersion > VERSION_NUM);
		bReinstallMode = (bResult && driverVersion == VERSION_NUM);

		PortableMode = DeviceIoControl (hDriver, TC_IOCTL_GET_PORTABLE_MODE_STATUS, NULL, 0, NULL, 0, &dwResult, NULL);

		if (bCloseDriverHandle)
		{
			CloseHandle (hDriver);
			hDriver = INVALID_HANDLE_VALUE;
		}
	}

	*driverVersionPtr = driverVersion;
}


static BOOL IsFileInUse (const wstring &filePath)
{
	HANDLE useTestHandle = CreateFile (filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (useTestHandle != INVALID_HANDLE_VALUE)
		CloseHandle (useTestHandle);
	else if (GetLastError() == ERROR_SHARING_VIOLATION)
		return TRUE;

	return FALSE;
}


BOOL DoFilesInstall (HWND hwndDlg, wchar_t *szDestDir)
{
	/* WARNING: Note that, despite its name, this function is used during UNinstallation as well. */

	wchar_t szTmp[TC_MAX_PATH];
	BOOL bOK = TRUE;
	int i, x, fileNo;
	wchar_t curFileName [TC_MAX_PATH] = {0};

	if (!bUninstall && !bDevm)
	{
		// Self-extract all files to memory

		GetModuleFileName (NULL, szTmp, ARRAYSIZE (szTmp));

		if (!SelfExtractInMemory (szTmp))
			return FALSE;
	}

	x = wcslen (szDestDir);
	if (x < 2)
		return FALSE;

	if (szDestDir[x - 1] != L'\\')
		StringCbCatW (szDestDir, MAX_PATH, L"\\");

	for (i = 0; i < sizeof (szFiles) / sizeof (szFiles[0]); i++)
	{
		BOOL bResult, driver64 = FALSE, zipFile = FALSE;
		wchar_t szDir[TC_MAX_PATH];

		if (wcsstr (szFiles[i], L"VeraCrypt Setup") != 0)
		{
			if (bUninstall)
				continue;	// Prevent 'access denied' error

			if (bRepairMode)
				continue;	// Destination = target
		}

		// skip files that don't apply to the current architecture
		if (	(Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCrypt-x64.exe") == 0))
			|| (Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCryptExpander-x64.exe") == 0))
			|| (Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCrypt Format-x64.exe") == 0))
			||	(!Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCrypt-x86.exe") == 0))
			||	(!Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCryptExpander-x86.exe") == 0))
			||	(!Is64BitOs () && (wcscmp (szFiles[i], L"AVeraCrypt Format-x86.exe") == 0))
			)
		{
			continue;
		}

		if ((*szFiles[i] == L'A') || (*szFiles[i] == L'X'))
			StringCbCopyW (szDir, sizeof(szDir), szDestDir);
		else if (*szFiles[i] == L'D')
		{
			if (Is64BitOs ())
				driver64 = TRUE;

			GetSystemDirectory (szDir, ARRAYSIZE (szDir));

			x = wcslen (szDir);
			if (szDir[x - 1] != L'\\')
				StringCbCatW (szDir, sizeof(szDir), L"\\");

			StringCbCatW (szDir, sizeof(szDir), L"Drivers\\");
		}
		else if (*szFiles[i] == L'W')
			GetWindowsDirectory (szDir, ARRAYSIZE (szDir));

		if (*szFiles[i] == L'I')
			continue;

		if (*szFiles[i] == L'X')
			zipFile = TRUE;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szDir, szFiles[i] + 1);
		if (zipFile)
		{
			// build folder name by removing .zip extension
			wchar_t* ptr = wcsrchr (szTmp, L'.');
			if (ptr)
				*ptr = 0;
		}

		if (bUninstall == FALSE)
			CopyMessage (hwndDlg, szTmp);
		else
			RemoveMessage (hwndDlg, szTmp);

		if (bUninstall == FALSE)
		{
			SetCurrentDirectory (SetupFilesDir);

			if (wcsstr (szFiles[i], L"VeraCrypt Setup") != 0)
			{
				// Copy ourselves (the distribution package) to the destination location as 'VeraCrypt Setup.exe'

				wchar_t mp[MAX_PATH];

				GetModuleFileName (NULL, mp, ARRAYSIZE (mp));
				bResult = TCCopyFile (mp, szTmp);
			}
			else
			{
				StringCchCopyNW (curFileName, ARRAYSIZE(curFileName), szFiles[i] + 1, wcslen (szFiles[i]) - 1);
				curFileName [wcslen (szFiles[i]) - 1] = 0;

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"Dveracrypt.sys") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), FILENAME_64BIT_DRIVER, sizeof (FILENAME_64BIT_DRIVER));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCrypt.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCrypt-x64.exe", sizeof (L"VeraCrypt-x64.exe"));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCrypt-x86.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCrypt.exe", sizeof (L"VeraCrypt.exe"));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCryptExpander.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCryptExpander-x64.exe", sizeof (L"VeraCryptExpander-x64.exe"));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCryptExpander-x86.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCryptExpander.exe", sizeof (L"VeraCryptExpander.exe"));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCrypt Format.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCrypt Format-x64.exe", sizeof (L"VeraCrypt Format-x64.exe"));
				}

				if (Is64BitOs ()
					&& wcscmp (szFiles[i], L"AVeraCrypt Format-x86.exe") == 0)
				{
					StringCbCopyNW (curFileName, sizeof(curFileName), L"VeraCrypt Format.exe", sizeof (L"VeraCrypt Format.exe"));
				}

				if (!bDevm)
				{
					bResult = FALSE;

					// Find the correct decompressed file in memory
					for (fileNo = 0; fileNo < NBR_COMPRESSED_FILES; fileNo++)
					{
						// Write the file (stored in memory) directly to the destination location
						// (there will be no temporary files).
						if (wmemcmp (
							curFileName,
							Decompressed_Files[fileNo].fileName,
							min (wcslen (curFileName), (size_t) Decompressed_Files[fileNo].fileNameLength)) == 0)
						{
							// Dump filter driver cannot be installed to SysWOW64 directory
							if (driver64 && !EnableWow64FsRedirection (FALSE))
							{
								handleWin32Error (hwndDlg, SRC_POS);
								bResult = FALSE;
								goto err;
							}
							if (zipFile)
							{
								bResult = DecompressZipToDir (
									Decompressed_Files[fileNo].fileContent,
									Decompressed_Files[fileNo].fileLength,
									szDir,
									CopyMessage,
									hwndDlg);
							}
							else
							{
								bResult = SaveBufferToFile (
									(char *) Decompressed_Files[fileNo].fileContent,
									szTmp,
									Decompressed_Files[fileNo].fileLength,
									FALSE,
									TRUE);
							}

							if (driver64)
							{
								if (!EnableWow64FsRedirection (TRUE))
								{
									handleWin32Error (hwndDlg, SRC_POS);
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

				if (bResult && wcscmp (szFiles[i], L"AVeraCrypt.exe") == 0)
				{
					if (Is64BitOs ())
						EnableWow64FsRedirection (FALSE);

					wstring servicePath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", false);
					wstring serviceLegacyPath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", true);
					wstring favoritesFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false);
					wstring favoritesLegacyFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, true);

					if (	FileExists (servicePath.c_str())
						||	(Is64BitOs () && FileExists (serviceLegacyPath.c_str()))
						)
					{
						CopyMessage (hwndDlg, (wchar_t *) servicePath.c_str());
						bResult = CopyFile (szTmp, servicePath.c_str(), FALSE);
					}

					if (bResult && Is64BitOs ()
						&& FileExists (favoritesLegacyFile.c_str())
						&& !FileExists (favoritesFile.c_str()))
					{
						// copy the favorites XML file to the native system directory
						bResult = CopyFile (favoritesLegacyFile.c_str(), favoritesFile.c_str(), FALSE);
					}

					if (bResult && Is64BitOs () && FileExists (favoritesFile.c_str()) && FileExists (servicePath.c_str()))
					{
						// Update the path of the service
						BootEncryption BootEncObj (hwndDlg);

						try
						{
							if (BootEncObj.GetDriverServiceStartType() == SERVICE_BOOT_START)
							{
								BootEncObj.UpdateSystemFavoritesService ();
							}
						}
						catch (...) {}
					}

					if (Is64BitOs ())
					{
						// delete files from legacy path
						if (FileExists (favoritesLegacyFile.c_str()))
						{
							RemoveMessage (hwndDlg, (wchar_t *) favoritesLegacyFile.c_str());
							ForceDeleteFile (favoritesLegacyFile.c_str());
						}

						if (FileExists (serviceLegacyPath.c_str()))
						{
							RemoveMessage (hwndDlg, (wchar_t *) serviceLegacyPath.c_str());
							ForceDeleteFile (serviceLegacyPath.c_str());
						}

						EnableWow64FsRedirection (TRUE);
					}
				}
			}
		}
		else
		{
			if (driver64)
				EnableWow64FsRedirection (FALSE);
			if (zipFile)
				bResult = StatRemoveDirectory (szTmp);
			else
				bResult = StatDeleteFile (szTmp, TRUE);
			if (driver64)
				EnableWow64FsRedirection (TRUE);

			if (bResult && wcscmp (szFiles[i], L"AVeraCrypt.exe") == 0)
			{
				if (Is64BitOs ())
					EnableWow64FsRedirection (FALSE);

				wstring servicePath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", false);
				wstring serviceLegacyPath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", true);
				wstring favoritesFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false);
				wstring favoritesLegacyFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, true);

				// delete all files related to system favorites service
				if (FileExists (favoritesFile.c_str()))
				{
					RemoveMessage (hwndDlg, (wchar_t *) favoritesFile.c_str());
					ForceDeleteFile (favoritesFile.c_str());
				}

				if (FileExists (servicePath.c_str()))
				{
					RemoveMessage (hwndDlg, (wchar_t *) servicePath.c_str());
					ForceDeleteFile (servicePath.c_str());
				}

				if (Is64BitOs ())
				{
					if (FileExists (favoritesLegacyFile.c_str()))
					{
						RemoveMessage (hwndDlg, (wchar_t *) favoritesLegacyFile.c_str());
						ForceDeleteFile (favoritesLegacyFile.c_str());
					}

					if (FileExists (serviceLegacyPath.c_str()))
					{
						RemoveMessage (hwndDlg, (wchar_t *) serviceLegacyPath.c_str());
						ForceDeleteFile (serviceLegacyPath.c_str());
					}

					EnableWow64FsRedirection (TRUE);
				}
			}
		}

err:
		if (bResult == FALSE)
		{
			LPVOID lpMsgBuf;
			DWORD dwError = GetLastError ();
			wchar_t szTmp2[700];
			wchar_t szErrorValue[16];
			wchar_t* pszDesc;

			FormatMessage (
					      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					      NULL,
					      dwError,
				 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),	/* Default language */
					      (wchar_t *) &lpMsgBuf,
					      0,
					      NULL
				);

			if (lpMsgBuf)
				pszDesc = (wchar_t*) lpMsgBuf;
			else
			{
				StringCbPrintfW (szErrorValue, sizeof (szErrorValue), L"0x%.8X", dwError);
				pszDesc = szErrorValue;
			}

			if (bUninstall == FALSE)
				StringCbPrintfW (szTmp2, sizeof(szTmp2), GetString ("INSTALL_OF_FAILED"), szTmp, pszDesc);
			else
				StringCbPrintfW (szTmp2, sizeof(szTmp2), GetString ("UNINSTALL_OF_FAILED"), szTmp, pszDesc);

			if (lpMsgBuf) LocalFree (lpMsgBuf);

			if (!Silent && MessageBoxW (hwndDlg, szTmp2, lpszTitle, MB_YESNO | MB_ICONHAND) != IDYES)
				return FALSE;
		}
	}
	
	if (bUninstall == FALSE)
	{
		WIN32_FIND_DATA f;
		HANDLE h;

		SetCurrentDirectory (szDestDir);

		// remove PDF from previous version if any
		h = FindFirstFile (L"VeraCrypt User Guide*.pdf", &f);

		if (h != INVALID_HANDLE_VALUE)
		{
			do
			{
				StatDeleteFile (f.cFileName, TRUE);
			}
			while (FindNextFile(h, &f) != 0);

			FindClose (h);
		}

		// remove language XML files from previous version if any
		h = FindFirstFile (L"Language*.xml", &f);

		if (h != INVALID_HANDLE_VALUE)
		{
			do
			{
				StatDeleteFile (f.cFileName, TRUE);
			}
			while (FindNextFile(h, &f) != 0);

			FindClose (h);
		}

		SetCurrentDirectory (SetupFilesDir);
	}

	return bOK;
}

BOOL DoRegInstall (HWND hwndDlg, wchar_t *szDestDir, BOOL bInstallType)
{
	wchar_t szDir[TC_MAX_PATH], *key;
	wchar_t szTmp[TC_MAX_PATH*4];
	HKEY hkey = 0;
	BOOL bSlash, bOK = FALSE;
	DWORD dw;
	int x;

	if (SystemEncryptionUpdate)
	{
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt",
			0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_32KEY, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			StringCbCopyW (szTmp, sizeof(szTmp), _T(VERSION_STRING));
			RegSetValueEx (hkey, L"DisplayVersion", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t));

			StringCbCopyW (szTmp, sizeof(szTmp), TC_HOMEPAGE);
			RegSetValueEx (hkey, L"URLInfoAbout", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t));

			RegCloseKey (hkey);
		}

		return TRUE;
	}

	StringCbCopyW (szDir, sizeof(szDir), szDestDir);
	x = wcslen (szDestDir);
	if (szDestDir[x - 1] == L'\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		StringCbCatW (szDir, sizeof(szDir), L"\\");

	if (bInstallType)
	{

		key = L"Software\\Classes\\VeraCryptVolume";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		StringCbCopyW (szTmp, sizeof(szTmp), L"VeraCrypt Volume");
		if (RegSetValueEx (hkey, L"", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
			goto error;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%ws", TC_APPLICATION_ID);
		if (RegSetValueEx (hkey, L"AppUserModelID", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = L"Software\\Classes\\VeraCryptVolume\\DefaultIcon";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%sVeraCrypt.exe,1", szDir);
		if (RegSetValueEx (hkey, L"", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = L"Software\\Classes\\VeraCryptVolume\\Shell\\open\\command";
		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"\"%sVeraCrypt.exe\" /v \"%%1\"", szDir );
		if (RegSetValueEx (hkey, L"", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		key = L"Software\\Classes\\.hc";
		BOOL typeClassChanged = TRUE;
		wchar_t typeClass[256];
		DWORD typeClassSize = sizeof (typeClass);

		if (ReadLocalMachineRegistryString (key, L"", typeClass, &typeClassSize) && typeClassSize > 0 && wcscmp (typeClass, L"VeraCryptVolume") == 0)
			typeClassChanged = FALSE;

		RegMessage (hwndDlg, key);
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
				    key,
				    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) != ERROR_SUCCESS)
			goto error;

		StringCbCopyW (szTmp, sizeof(szTmp), L"VeraCryptVolume");
		if (RegSetValueEx (hkey, L"", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
			goto error;

		RegCloseKey (hkey);
		hkey = 0;

		if (typeClassChanged)
			SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	key = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt";
	RegMessage (hwndDlg, key);
	if (RegCreateKeyEx (HKEY_LOCAL_MACHINE,
		key,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_32KEY, NULL, &hkey, &dw) != ERROR_SUCCESS)
		goto error;

	/* IMPORTANT: IF YOU CHANGE THIS IN ANY WAY, REVISE AND UPDATE SetInstallationPath() ACCORDINGLY! */
	StringCbPrintfW (szTmp, sizeof(szTmp), L"\"%sVeraCrypt Setup.exe\" /u", szDir);
	if (RegSetValueEx (hkey, L"UninstallString", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbPrintfW (szTmp, sizeof(szTmp), L"\"%sVeraCrypt Setup.exe\" /c", szDir);
	if (RegSetValueEx (hkey, L"ModifyPath", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbPrintfW (szTmp, sizeof(szTmp), L"\"%sVeraCrypt Setup.exe\"", szDir);
	if (RegSetValueEx (hkey, L"DisplayIcon", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbCopyW (szTmp, sizeof(szTmp), _T(VERSION_STRING));
	if (RegSetValueEx (hkey, L"DisplayVersion", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbCopyW (szTmp, sizeof(szTmp), L"VeraCrypt");
	if (RegSetValueEx (hkey, L"DisplayName", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbCopyW (szTmp, sizeof(szTmp), L"IDRIX");
	if (RegSetValueEx (hkey, L"Publisher", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	StringCbCopyW (szTmp, sizeof(szTmp), TC_HOMEPAGE);
	if (RegSetValueEx (hkey, L"URLInfoAbout", 0, REG_SZ, (BYTE *) szTmp, (wcslen (szTmp) + 1) * sizeof (wchar_t)) != ERROR_SUCCESS)
		goto error;

	bOK = TRUE;

error:
	if (hkey != 0)
		RegCloseKey (hkey);

	if (bOK == FALSE)
	{
		handleWin32Error (hwndDlg, SRC_POS);
		Error ("REG_INSTALL_FAILED", hwndDlg);
	}

	// Register COM servers for UAC
	if (IsOSAtLeast (WIN_VISTA))
	{
		if (!RegisterComServers (szDir))
		{
			Error ("COM_REG_FAILED", hwndDlg);
			return FALSE;
		}
	}

	return bOK;
}

BOOL DoApplicationDataUninstall (HWND hwndDlg)
{
	wchar_t path[MAX_PATH];
	wchar_t path2[MAX_PATH];
	BOOL bOK = TRUE;

	StatusMessage (hwndDlg, "REMOVING_APPDATA");

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	StringCbCatW (path, sizeof(path), L"\\VeraCrypt\\");

	// Delete favorite volumes file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_FAVORITE_VOLUMES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2, FALSE);

	// Delete keyfile defaults
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_DEFAULT_KEYFILES);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2, FALSE);

	// Delete history file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_HISTORY);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2, FALSE);

	// Delete configuration file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_CONFIGURATION);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2, FALSE);

	// Delete system encryption configuration file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_SYSTEM_ENCRYPTION);
	RemoveMessage (hwndDlg, path2);
	StatDeleteFile (path2, FALSE);

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	StringCbCatW (path, sizeof(path), L"\\VeraCrypt");
	RemoveMessage (hwndDlg, path);
	if (!StatRemoveDirectory (path))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		bOK = FALSE;
	}

	// remove VeraCrypt under common appdata
	if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		StringCbCatW (path, sizeof(path), L"\\VeraCrypt");

		// Delete original bootloader
		StringCbPrintfW (path2, sizeof(path2), L"%s\\%s", path, TC_SYS_BOOT_LOADER_BACKUP_NAME);
		RemoveMessage (hwndDlg, path2);
		StatDeleteFile (path2, FALSE);

		// remove VeraCrypt folder
		RemoveMessage (hwndDlg, path);
		StatRemoveDirectory (path);
	}


	return bOK;
}

BOOL DoRegUninstall (HWND hwndDlg, BOOL bRemoveDeprecated)
{
	wchar_t regk [64];
	typedef LSTATUS (WINAPI *RegDeleteKeyExWFn) (HKEY hKey,LPCWSTR lpSubKey,REGSAM samDesired,WORD Reserved);
	RegDeleteKeyExWFn RegDeleteKeyExWPtr = NULL;
	HMODULE hAdvapiDll = LoadLibrary (L"Advapi32.dll");
	if (hAdvapiDll)
	{
		RegDeleteKeyExWPtr = (RegDeleteKeyExWFn) GetProcAddress(hAdvapiDll, "RegDeleteKeyExW");
	}

	// Unregister COM servers
	if (!bRemoveDeprecated && IsOSAtLeast (WIN_VISTA))
	{
		if (!UnregisterComServers (InstallationPath))
			StatusMessage (hwndDlg, "COM_DEREG_FAILED");
	}

	if (!bRemoveDeprecated)
		StatusMessage (hwndDlg, "REMOVING_REG");

	if (RegDeleteKeyExWPtr)
	{
		RegDeleteKeyExWPtr (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", KEY_WOW64_32KEY, 0);
		RegDeleteKeyExWPtr (HKEY_CURRENT_USER, L"Software\\VeraCrypt", KEY_WOW64_32KEY, 0);
	}
	else
	{
		RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt");
		RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\VeraCrypt");
	}
	RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\VeraCryptVolume\\Shell\\open\\command");
	RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\VeraCryptVolume\\Shell\\open");
	RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\VeraCryptVolume\\Shell");
	RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\VeraCryptVolume\\DefaultIcon");
	RegDeleteKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\VeraCryptVolume");

	if (!bRemoveDeprecated)
	{
		HKEY hKey;
		GetStartupRegKeyName (regk, sizeof(regk));
		DeleteRegistryValue (regk, L"VeraCrypt");

		DeleteRegistryKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\.hc");

		// enable the SE_TAKE_OWNERSHIP_NAME privilege for this operation
		SetPrivilege (SE_TAKE_OWNERSHIP_NAME, TRUE);

		// clean MuiCache list from VeraCrypt entries
		SearchAndDeleteRegistrySubString (HKEY_CLASSES_ROOT, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", L"VeraCrypt", FALSE, NULL);

		// clean other VeraCrypt entries from all users
		SearchAndDeleteRegistrySubString (HKEY_USERS, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.hc", NULL, TRUE, NULL);
		SearchAndDeleteRegistrySubString (HKEY_USERS, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted", L"VeraCrypt", TRUE, NULL);
		SearchAndDeleteRegistrySubString (HKEY_USERS, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage\\NewShortcuts", L"VeraCrypt", TRUE, NULL);

		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_ALL_ACCESS | WRITE_DAC | WRITE_OWNER, &hKey) == ERROR_SUCCESS)
		{
			SearchAndDeleteRegistrySubString (hKey, L"Enum\\Root\\LEGACY_VERACRYPT", NULL, TRUE, L"ControlSet");
			SearchAndDeleteRegistrySubString (hKey, L"services\\veracrypt", NULL, TRUE, L"ControlSet");
			RegCloseKey(hKey);
		}

		// disable the SE_TAKE_OWNERSHIP_NAME privilege for this operation
		SetPrivilege (SE_TAKE_OWNERSHIP_NAME, FALSE);

		SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	if (hAdvapiDll)
		FreeLibrary (hAdvapiDll);

	return TRUE;
}


BOOL DoServiceUninstall (HWND hwndDlg, wchar_t *lpszService)
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

	if (wcscmp (L"veracrypt", lpszService) == 0)
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

	if (wcscmp (L"veracrypt", lpszService) == 0)
		StatusMessage (hwndDlg, "REMOVING_DRIVER");
	else
		StatusMessageParam (hwndDlg, "REMOVING", lpszService);

	if (hService != NULL)
	{
		CloseServiceHandle (hService);
		hService = NULL;
	}

	if (hManager != NULL)
	{
		CloseServiceHandle (hManager);
		hManager = NULL;
	}

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
			hService = NULL;
			hManager = NULL;

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
		handleWin32Error (hwndDlg, SRC_POS);
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
			handleWin32Error (hwndDlg, SRC_POS);
			AbortProcess ("NODRIVER");
		}

		if (status != ERR_OS_ERROR)
		{
			handleError (NULL, status, SRC_POS);
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
							if (AskWarnNoYes ("UPDATE_TC_IN_DECOY_OS_FIRST", hwndDlg) == IDNO)
								AbortProcessSilent ();
						}
					}
				}
				catch (...) { }

				if (bUninstallInProgress && !bootEnc.GetStatus().DriveMounted)
				{
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::DriveFilter); } catch (...) { }
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::VolumeFilter); } catch (...) { }
					try { bootEnc.RegisterFilterDriver (false, BootEncryption::DumpFilter); } catch (...) { }
					bootEnc.SetDriverServiceStartType (SERVICE_SYSTEM_START);
				}
				else if (bUninstallInProgress || bDowngrade)
				{
					Error (bDowngrade ? "SETUP_FAILED_BOOT_DRIVE_ENCRYPTED_DOWNGRADE" : "SETUP_FAILED_BOOT_DRIVE_ENCRYPTED", hwndDlg);
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
				handleWin32Error (hwndDlg, SRC_POS);
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
		uint64 bootLoaderVersion = bootEnc.GetInstalledBootLoaderVersion();
		if ((bootLoaderVersion < VERSION_NUM) || (bReinstallMode && (bootLoaderVersion == VERSION_NUM)))
		{
			StatusMessage (hwndDlg, "INSTALLER_UPDATING_BOOT_LOADER");

			bootEnc.InstallBootLoader (true);

			if (bootEnc.GetInstalledBootLoaderVersion() <= TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION)
			{
				bUpdateRescueDisk = TRUE;
				Info (IsHiddenOSRunning() ? "BOOT_LOADER_UPGRADE_OK_HIDDEN_OS" : "BOOT_LOADER_UPGRADE_OK", hwndDlg);
			}
		}
		return TRUE;
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
	}
	catch (...) { }

	Error ("BOOT_LOADER_UPGRADE_FAILED", hwndDlg);
	return FALSE;
}


BOOL DoShortcutsUninstall (HWND hwndDlg, wchar_t *szDestDir)
{
	wchar_t szLinkDir[TC_MAX_PATH];
	wchar_t szTmp2[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;
	BOOL allUsers = FALSE;

	hOle = OleInitialize (NULL);

	// User start menu
    SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_PROGRAMS, 0);
	x = wcslen (szLinkDir);
	if (szLinkDir[x - 1] == L'\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		StringCbCatW (szLinkDir, sizeof(szLinkDir), L"\\");

	StringCbCatW (szLinkDir, sizeof(szLinkDir), L"VeraCrypt");

	// Global start menu
	{
		struct _stat st;
		wchar_t path[TC_MAX_PATH];

		SHGetSpecialFolderPath (hwndDlg, path, CSIDL_COMMON_PROGRAMS, 0);
		StringCbCatW (path, sizeof(path), L"\\VeraCrypt");

		if (_wstat (path, &st) == 0)
		{
			StringCbCopyW (szLinkDir, sizeof(szLinkDir), path);
			allUsers = TRUE;
		}
	}

	// Start menu entries
	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2, FALSE) == FALSE)
		goto error;

	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCryptExpander.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2, FALSE) == FALSE)
		goto error;

	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt Website.url");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2, FALSE) == FALSE)
		goto error;

	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\Uninstall VeraCrypt.lnk");
	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2, FALSE) == FALSE)
		goto error;

	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt User's Guide.lnk");
	StatDeleteFile (szTmp2, FALSE);

	// Start menu group
	RemoveMessage ((HWND) hwndDlg, szLinkDir);
	if (StatRemoveDirectory (szLinkDir) == FALSE)
		handleWin32Error ((HWND) hwndDlg, SRC_POS);

	// Desktop icon

	if (allUsers)
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
	else
		SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

	StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt.lnk");

	RemoveMessage (hwndDlg, szTmp2);
	if (StatDeleteFile (szTmp2, FALSE) == FALSE)
		goto error;

	bOK = TRUE;

error:
	OleUninitialize ();

	return bOK;
}

BOOL DoShortcutsInstall (HWND hwndDlg, wchar_t *szDestDir, BOOL bProgGroup, BOOL bDesktopIcon)
{
	wchar_t szLinkDir[TC_MAX_PATH], szDir[TC_MAX_PATH];
	wchar_t szTmp[TC_MAX_PATH], szTmp2[TC_MAX_PATH], szTmp3[TC_MAX_PATH];
	BOOL bSlash, bOK = FALSE;
	HRESULT hOle;
	int x;

	if (bProgGroup == FALSE && bDesktopIcon == FALSE)
		return TRUE;

	hOle = OleInitialize (NULL);

	GetProgramPath (hwndDlg, szLinkDir);

	x = wcslen (szLinkDir);
	if (szLinkDir[x - 1] == L'\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		StringCbCatW (szLinkDir, sizeof(szLinkDir), L"\\");

	StringCbCatW (szLinkDir, sizeof(szLinkDir), L"VeraCrypt");

	StringCbCopyW (szDir, sizeof(szDir), szDestDir);
	x = wcslen (szDestDir);
	if (szDestDir[x - 1] == L'\\')
		bSlash = TRUE;
	else
		bSlash = FALSE;

	if (bSlash == FALSE)
		StringCbCatW (szDir, sizeof(szDir), L"\\");

	if (bProgGroup)
	{
		FILE *f;

		if (mkfulldir (szLinkDir, TRUE) != 0)
		{
			if (mkfulldir (szLinkDir, FALSE) != 0)
			{
				wchar_t szTmpW[TC_MAX_PATH];

				handleWin32Error (hwndDlg, SRC_POS);
				StringCbPrintfW (szTmpW, sizeof(szTmpW), GetString ("CANT_CREATE_FOLDER"), szLinkDir);
				MessageBoxW (hwndDlg, szTmpW, lpszTitle, MB_ICONHAND);
				goto error;
			}
		}

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szDir, L"VeraCrypt.exe");
		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, L"", szTmp2, NULL, -1) != S_OK)
			goto error;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szDir, L"VeraCryptExpander.exe");
		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCryptExpander.lnk");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp, L"", szTmp2, NULL, -1) != S_OK)
			goto error;

		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt Website.url");
		IconMessage (hwndDlg, szTmp2);
		f = _wfopen (szTmp2, L"w");
		if (f)
		{
			fwprintf (f, L"[InternetShortcut]\nURL=%s\n", TC_APPLINK);

			CheckFileStreamWriteErrors (hwndDlg, f, szTmp2);
			fclose (f);
		}
		else
			goto error;

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szDir, L"VeraCrypt Setup.exe");
		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\Uninstall VeraCrypt.lnk");
		if (GetSystemDirectory (szTmp3, ARRAYSIZE(szTmp3)))
		{
			StringCbCatW (szTmp3, sizeof(szTmp3), L"\\control.exe");
		}
		else
			StringCbCopyW(szTmp3, sizeof(szTmp3), L"C:\\Windows\\System32\\control.exe");

		IconMessage (hwndDlg, szTmp2);
		if (CreateLink (szTmp3, L"appwiz.cpl", szTmp2, szTmp, 0) != S_OK)
			goto error;

		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt User's Guide.lnk");
		StatDeleteFile (szTmp2, FALSE);
	}

	if (bDesktopIcon)
	{
		StringCbCopyW (szDir, sizeof(szDir), szDestDir);
		x = wcslen (szDestDir);
		if (szDestDir[x - 1] == L'\\')
			bSlash = TRUE;
		else
			bSlash = FALSE;

		if (bSlash == FALSE)
			StringCbCatW (szDir, sizeof(szDir), L"\\");

		if (bForAllUsers)
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_COMMON_DESKTOPDIRECTORY, 0);
		else
			SHGetSpecialFolderPath (hwndDlg, szLinkDir, CSIDL_DESKTOPDIRECTORY, 0);

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szDir, L"VeraCrypt.exe");
		StringCbPrintfW (szTmp2, sizeof(szTmp2), L"%s%s", szLinkDir, L"\\VeraCrypt.lnk");

		IconMessage (hwndDlg, szTmp2);

		if (CreateLink (szTmp, L"", szTmp2, NULL, -1) != S_OK)
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
				Info ("INSTALL_OK", hwndDlg);
			else
				Info ("SETUP_UPDATE_OK", hwndDlg);
		}
		else
		{
			wchar_t str[4096];

			StringCbPrintfW (str, sizeof(str), GetString ("UNINSTALL_OK"), InstallationPath);
			MessageBoxW (hwndDlg, str, lpszTitle, MB_ICONASTERISK);
		}
	}
	else
	{
		if (bUninstall == FALSE)
			Error ("INSTALL_FAILED", hwndDlg);
		else
			Error ("UNINSTALL_FAILED", hwndDlg);
	}
}

static void SetSystemRestorePoint (HWND hwndDlg, BOOL finalize)
{
	static RESTOREPOINTINFO RestPtInfo;
	static STATEMGRSTATUS SMgrStatus;
	static BOOL failed = FALSE;
	static BOOL (__stdcall *_SRSetRestorePoint)(PRESTOREPOINTINFO, PSTATEMGRSTATUS);

	if (!SystemRestoreDll) return;

	_SRSetRestorePoint = (BOOL (__stdcall *)(PRESTOREPOINTINFO, PSTATEMGRSTATUS))GetProcAddress (SystemRestoreDll,"SRSetRestorePointW");
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
		StringCbCopyW (RestPtInfo.szDescription, sizeof(RestPtInfo.szDescription), bUninstall ? L"VeraCrypt uninstallation" : L"VeraCrypt installation");

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

		if (DoServiceUninstall (hwndDlg, L"veracrypt") == FALSE)
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
			wchar_t temp[MAX_PATH];
			FILE *f;

			// Deprecated service
			DoServiceUninstall (hwndDlg, L"VeraCryptService");

			GetTempPath (ARRAYSIZE (temp), temp);
			StringCbPrintfW (UninstallBatch, sizeof (UninstallBatch), L"%sVeraCrypt-Uninstall.bat", temp);

			UninstallBatch [ARRAYSIZE(UninstallBatch)-1] = 0;

			// Create uninstall batch
			f = _wfopen (UninstallBatch, L"w");
			if (!f)
				bOK = FALSE;
			else
			{
				fwprintf (f,L":loop\n"
					L"del \"%s%s\"\n"
					L"if exist \"%s%s\" goto loop\n"
					L"rmdir \"%s\"\n"
					L"del \"%s\"",
					InstallationPath, L"VeraCrypt Setup.exe",
					InstallationPath, L"VeraCrypt Setup.exe",
					InstallationPath,
					UninstallBatch
					);

				CheckFileStreamWriteErrors (hwndDlg, f, UninstallBatch);
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
	wchar_t path[MAX_PATH];

	BootEncryption bootEnc (hwndDlg);

	// Refresh the main GUI (wizard thread)
	InvalidateRect (MainDlg, NULL, TRUE);

	ClearLogWindow (hwndDlg);

	if (mkfulldir (InstallationPath, TRUE) != 0)
	{
		if (mkfulldir (InstallationPath, FALSE) != 0)
		{
			wchar_t szTmp[TC_MAX_PATH];

			handleWin32Error (hwndDlg, SRC_POS);
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CANT_CREATE_FOLDER"), InstallationPath);
			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
			Error ("INSTALL_FAILED", hwndDlg);
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
		&& (IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L".exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L"-x86.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L"-x64.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L" Format.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L" Format-x86.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L" Format-x64.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L"Expander.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L"Expander-x86.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L"Expander-x64.exe")
			|| IsFileInUse (wstring (InstallationPath) + L'\\' + _T(TC_APP_NAME) L" Setup.exe")
			)
		)
	{
		NormalCursor ();
		Error ("CLOSE_TC_FIRST", hwndDlg);
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
			handleWin32Error (hwndDlg, SRC_POS);
			Error ("FAILED_TO_DISABLE_PAGING_FILES", hwndDlg);
		}
		else
			bRestartRequired = TRUE;
	}

	UpdateProgressBarProc(50);

	// Remove deprecated
	DoServiceUninstall (hwndDlg, L"VeraCryptService");

	UpdateProgressBarProc(55);

	if (!SystemEncryptionUpdate)
		DoRegUninstall ((HWND) hwndDlg, TRUE);

	UpdateProgressBarProc(61);

	GetWindowsDirectory (path, ARRAYSIZE (path));
	StringCbCatW (path, sizeof (path), L"\\VeraCrypt Setup.exe");
	StatDeleteFile (path, FALSE);

	if (UpdateProgressBarProc(63) && UnloadDriver && DoServiceUninstall (hwndDlg, L"veracrypt") == FALSE)
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
			Warning ("SYS_ENC_UPGRADE_FAILED", hwndDlg);
		}
	}

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
					if (bUpdateRescueDisk)
					{
						SavePostInstallTasksSettings (TC_POST_INSTALL_CFG_RESCUE_DISK);
					}
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
	wchar_t path[MAX_PATH+20];
	ITEMIDLIST *itemList;

	memset (InstallationPath, 0, sizeof (InstallationPath));

	// Determine if VeraCrypt is already installed and try to determine its "Program Files" location
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", 0, KEY_READ | KEY_WOW64_32KEY, &hkey) == ERROR_SUCCESS)
	{
		/* Default 'UninstallString' registry strings written by VeraCrypt:
		------------------------------------------------------------------------------------
		5.0+	"C:\Program Files\VeraCrypt\VeraCrypt Setup.exe" /u
		*/

		wchar_t rv[MAX_PATH*4];
		DWORD size = sizeof (rv);
		if (RegQueryValueEx (hkey, L"UninstallString", 0, 0, (LPBYTE) &rv, &size) == ERROR_SUCCESS && wcsrchr (rv, L'/'))
		{
			size_t len = 0;

			// Cut and paste the location (path) where VeraCrypt is installed to InstallationPath
			if (rv[0] == L'"')
			{
				len = wcsrchr (rv, L'/') - rv - 2;
				StringCchCopyNW (InstallationPath, ARRAYSIZE(InstallationPath), rv + 1, len);
				InstallationPath [len] = 0;
				bInstallPathDetermined = TRUE;

				if (InstallationPath [wcslen (InstallationPath) - 1] != L'\\')
				{
					len = wcsrchr (InstallationPath, L'\\') - InstallationPath;
					InstallationPath [len] = 0;
				}
			}

		}
		RegCloseKey (hkey);
	}

	if (bInstallPathDetermined)
	{
		wchar_t mp[MAX_PATH];

		// Determine whether we were launched from the folder where VeraCrypt is installed
		GetModuleFileName (NULL, mp, ARRAYSIZE (mp));
		if (wcsncmp (InstallationPath, mp, min (wcslen(InstallationPath), wcslen(mp))) == 0)
		{
			// We were launched from the folder where VeraCrypt is installed

			if (!IsNonInstallMode() && !bDevm)
				bChangeMode = TRUE;
		}
	}
	else
	{
		/* VeraCrypt is not installed or it wasn't possible to determine where it is installed. */

		// Default "Program Files" path.
		SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &itemList);
		SHGetPathFromIDList (itemList, path);

		if (Is64BitOs())
		{
			// Use a unified default installation path (registry redirection of %ProgramFiles% does not work if the installation path is user-selectable)
			wstring s = path;
			size_t p = s.find (L" (x86)");
			if (p != wstring::npos)
			{
				s = s.substr (0, p);
				if (_waccess (s.c_str(), 0) != -1)
					StringCbCopyW (path, sizeof (path), s.c_str());
			}
		}

		StringCbCatW (path, sizeof(path), L"\\VeraCrypt\\");
		StringCbCopyW (InstallationPath, sizeof(InstallationPath), path);
	}

	// Make sure the path ends with a backslash
	if (InstallationPath [wcslen (InstallationPath) - 1] != L'\\')
	{
		StringCbCatW (InstallationPath, sizeof(InstallationPath), L"\\");
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
			if (AskNoYes("CONFIRM_EXIT_UNIVERSAL", hwndDlg) == IDNO)
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


int WINAPI wWinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, wchar_t *lpszCommandLine, int nCmdShow)
{
	atexit (localcleanup);

	SelfExtractStartupInit();

	lpszTitle = L"VeraCrypt Setup";

	/* Call InitApp to initialize the common code */
	InitApp (hInstance, NULL);

	if (IsAdmin () != TRUE)
		if (MessageBoxW (NULL, GetString ("SETUP_ADMIN"), lpszTitle, MB_YESNO | MB_ICONQUESTION) != IDYES)
		{
			FinalizeApp ();
			exit (1);
		}

	/* Setup directory */
	{
		wchar_t *s;
		GetModuleFileName (NULL, SetupFilesDir, ARRAYSIZE (SetupFilesDir));
		s = wcsrchr (SetupFilesDir, L'\\');
		if (s)
			s[1] = 0;
	}

	/* Parse command line arguments */

	if (lpszCommandLine[0] == L'/')
	{
		if (lpszCommandLine[1] == L'u')
		{
			// Uninstall:	/u

			bUninstall = TRUE;
		}
		else if (lpszCommandLine[1] == L'c')
		{
			// Change:	/c

			bChangeMode = TRUE;
		}
		else if (lpszCommandLine[1] == L'p')
		{
			// Create self-extracting package:	/p

			bMakePackage = TRUE;
		}
		else if (lpszCommandLine[1] == L'd')
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
				MessageBox (NULL, L"Error: This installer file does not contain any compressed files.\n\nTo create a self-extracting installation package (with embedded compressed files), run:\n\"VeraCrypt Setup.exe\" /p", L"VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
				FinalizeApp ();
				exit (1);
			}

			if (bChangeMode)
			{
				/* VeraCrypt is already installed on this system and we were launched from the Program Files folder */

				char *tmpStr[] = {0, "SELECT_AN_ACTION", "REPAIR_REINSTALL", "UNINSTALL", "EXIT", 0};

				// Ask the user to select either Repair or Unistallation
				switch (AskMultiChoice ((void **) tmpStr, FALSE, NULL))
				{
				case 1:
					bRepairMode = TRUE;
					break;
				case 2:
					bUninstall = TRUE;
					break;
				default:
					FinalizeApp ();
					exit (1);
				}
			}
		}

		// System Restore
		if (IsSystemRestoreEnabled ())
		{
			wchar_t dllPath[MAX_PATH];
			if (GetSystemDirectory (dllPath, MAX_PATH))
			{
				StringCbCatW(dllPath, sizeof(dllPath), L"\\srclient.dll");
			}
			else
				StringCbCopyW(dllPath, sizeof(dllPath), L"C:\\Windows\\System32\\srclient.dll");
			SystemRestoreDll = LoadLibrary (dllPath);
		}
		else
			SystemRestoreDll = 0;

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
	FinalizeApp ();
	return 0;
}
