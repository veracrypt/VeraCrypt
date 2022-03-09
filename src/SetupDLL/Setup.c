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
#include <Setupapi.h>

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

#include "../Common/Resource.h"

#pragma comment(lib, "Shlwapi.lib")

using namespace VeraCrypt;

#pragma warning( disable : 4201 )
#pragma warning( disable : 4115 )

#include <shlobj.h>

#pragma warning( default : 4201 )
#pragma warning( default : 4115 )

#include <Strsafe.h>

#include <Msi.h>
#include <MsiQuery.h>
#include <wtsapi32.h>

#include <cstdarg>
#if !defined(va_copy)
#define va_copy(d, s) ((d) = (s))
#endif

typedef enum 
{
	MSI_INFO_LEVEL = 0,
	MSI_WARNING_LEVEL,
	MSI_ERROR_LEVEL
} eMSILogLevel;

#define WAIT_PERIOD 3

extern HMODULE hRichEditDll;
extern HMODULE hComctl32Dll;
extern HMODULE hSetupDll;
extern HMODULE hShlwapiDll;
extern HMODULE hProfApiDll;
extern HMODULE hUsp10Dll;
extern HMODULE hCryptSpDll;
extern HMODULE hUXThemeDll;
extern HMODULE hUserenvDll;
extern HMODULE hRsaenhDll;
extern HMODULE himm32dll;
extern HMODULE hMSCTFdll;
extern HMODULE hfltlibdll;
extern HMODULE hframedyndll;
extern HMODULE hpsapidll;
extern HMODULE hsecur32dll;
extern HMODULE hnetapi32dll;
extern HMODULE hauthzdll;
extern HMODULE hxmllitedll;
extern HMODULE hmprdll;
extern HMODULE hsppdll;
extern HMODULE vssapidll;
extern HMODULE hvsstracedll;
extern HMODULE hcfgmgr32dll;
extern HMODULE hdevobjdll;
extern HMODULE hpowrprofdll;
extern HMODULE hsspiclidll;
extern HMODULE hcryptbasedll;
extern HMODULE hdwmapidll;
extern HMODULE hmsasn1dll;
extern HMODULE hcrypt32dll;
extern HMODULE hbcryptdll;
extern HMODULE hbcryptprimitivesdll;
extern HMODULE hMsls31;
extern HMODULE hntmartadll;
extern HMODULE hwinscarddll;
extern HMODULE hmsvcrtdll;
extern HMODULE hWinTrustLib;
extern HMODULE hAdvapi32Dll;

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

typedef BOOL (WINAPI *CreateProcessWithTokenWFn)(
    __in        HANDLE hToken,
    __in        DWORD dwLogonFlags,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation
      );

extern SetDllDirectoryPtr SetDllDirectoryFn;
extern SetSearchPathModePtr SetSearchPathModeFn;
extern SetDefaultDllDirectoriesPtr SetDefaultDllDirectoriesFn;

extern ImageList_CreatePtr ImageList_CreateFn;
extern ImageList_AddPtr ImageList_AddFn;

extern SetupCloseInfFilePtr SetupCloseInfFileFn;
extern SetupDiOpenClassRegKeyPtr SetupDiOpenClassRegKeyFn;
extern SetupInstallFromInfSectionWPtr SetupInstallFromInfSectionWFn;
extern SetupOpenInfFileWPtr SetupOpenInfFileWFn;
extern SHDeleteKeyWPtr SHDeleteKeyWFn;
extern SHStrDupWPtr SHStrDupWFn;
extern ChangeWindowMessageFilterPtr ChangeWindowMessageFilterFn;
extern CreateProcessWithTokenWFn CreateProcessWithTokenWPtr;

wchar_t InstallationPath[TC_MAX_PATH];

BOOL bUninstall = FALSE;
BOOL bDowngrade = FALSE;
BOOL bUninstallInProgress = FALSE;
BOOL PortableMode = FALSE;
BOOL UnloadDriver = TRUE;

BOOL Rollback = FALSE;
BOOL bReinstallMode = FALSE;
BOOL bUpgrade = FALSE;
BOOL bPossiblyFirstTimeInstall = FALSE;
BOOL bDevm = FALSE;
BOOL SystemEncryptionUpdate = FALSE;
BOOL bRestartRequired = FALSE;
BOOL bDisableSwapFiles = FALSE;
BOOL bSystemRestore = TRUE;
HMODULE volatile SystemRestoreDll = 0;

BOOL bPromptFastStartup = FALSE;
BOOL bPromptReleaseNotes = FALSE;
BOOL bPromptTutorial = FALSE;
BOOL bUpdateRescueDisk = FALSE;
BOOL bRepairMode = FALSE;
BOOL bUserSetLanguage = FALSE;

/*
BOOL bMakePackage = FALSE;
BOOL bDone = FALSE;

BOOL bForAllUsers = TRUE;
BOOL bRegisterFileExt = TRUE;
BOOL bAddToStartMenu = TRUE;
BOOL bDesktopIcon = TRUE;
BOOL bDesktopIconStatusDetermined = FALSE;

*/

/* **************************************************************************** */

/* Defined in this file, but a little bit late */
BOOL IsSystemRestoreEnabled ();

/* 
 * Same as in Setup.c
 */
BOOL ForceCopyFile (LPCWSTR szSrcFile, LPCWSTR szDestFile)
{
	BOOL bRet = CopyFileW (szSrcFile, szDestFile, FALSE);
	if (!bRet)
	{
		wstring renamedPath = szDestFile;
		renamedPath += VC_FILENAME_RENAMED_SUFFIX;

		/* rename the locked file in order to be able to create a new one */
		if (MoveFileExW (szDestFile, renamedPath.c_str(), MOVEFILE_REPLACE_EXISTING))
		{
			bRet = CopyFileW (szSrcFile, szDestFile, FALSE);
			if (bRet)
			{
				/* delete the renamed file when the machine reboots */
				MoveFileEx (renamedPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
			}
			else
			{
				/* restore the original file name */
				MoveFileEx (renamedPath.c_str(), szDestFile, MOVEFILE_REPLACE_EXISTING);
			}
		}
	}

	return bRet;
}

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
void StatusMessage (HWND hwndDlg, char *stringId)
{
	if (Rollback)
		return;

	SendMessageW (GetDlgItem (hwndDlg, IDC_LOG_WINDOW), LB_ADDSTRING, 0, (LPARAM) GetString (stringId));

	SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_SETTOPINDEX,
		SendDlgItemMessage (hwndDlg, IDC_LOG_WINDOW, LB_GETCOUNT, 0, 0) - 1, 0);
}

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* 
 * Same as in Setup.c
 */
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

/* **************************************************************************** */

// Adds a line to the log file of the installer.
void MSILog(MSIHANDLE hInstall, eMSILogLevel level, const wchar_t* zcFormat, ...)
{
    std::wstring wszMessage;

    // initialize use of the variable argument array
    va_list vaArgs;
    va_start(vaArgs, zcFormat);

    // reliably acquire the size
    // from a copy of the variable argument array
    // and a functionally reliable call to mock the formatting
    va_list vaArgsCopy;
    va_copy(vaArgsCopy, vaArgs);
    const int iLen = vswprintf(NULL, 0, zcFormat, vaArgsCopy);
    va_end(vaArgsCopy);

    // return a formatted string without risking memory mismanagement
    // and without assuming any compiler or platform specific behavior
    std::vector<wchar_t> zc(iLen + 1);
    vswprintf(zc.data(), zc.size(), zcFormat, vaArgs);
    va_end(vaArgs);

    wszMessage.assign(zc.data(), iLen);

#ifdef TEST_HARNESS
    if (!hInstall)
    {
        MessageBox(NULL, pszMessage, wszMessage.c_str(), 0);
        return;
    }
#endif

    PMSIHANDLE hRecord = MsiCreateRecord(1);
    // field 0 is the template
    MsiRecordSetString(hRecord, 0, (level == MSI_INFO_LEVEL) ? L"VeraCryptCustomAction_INFO: [1]" : ((level == MSI_WARNING_LEVEL) ? L"VeraCryptCustomAction_WARNING: [1]" : L"VeraCryptCustomAction_ERROR: [1]"));
    // field 1, to be placed in [1] placeholder
    MsiRecordSetString(hRecord, 1, wszMessage.c_str());
    // send message to running installer
    MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord);
}

// Adds a line to the log file of the installer and shows a popup.
// Since MsiProcessMessage() takes the UILEVEL into account,
// this won't cause a deadlock in case of a silent install.
void MSILogAndShow(MSIHANDLE hInstall, eMSILogLevel level, const wchar_t* zcFormat, ...)
{
    std::wstring wszMessage;

    // initialize use of the variable argument array
    va_list vaArgs;
    va_start(vaArgs, zcFormat);

    // reliably acquire the size
    // from a copy of the variable argument array
    // and a functionally reliable call to mock the formatting
    va_list vaArgsCopy;
    va_copy(vaArgsCopy, vaArgs);
    const int iLen = vswprintf(NULL, 0, zcFormat, vaArgsCopy);
    va_end(vaArgsCopy);

    // return a formatted string without risking memory mismanagement
    // and without assuming any compiler or platform specific behavior
    std::vector<wchar_t> zc(iLen + 1);
    vswprintf(zc.data(), zc.size(), zcFormat, vaArgs);
    va_end(vaArgs);

    wszMessage.assign(zc.data(), iLen);

#ifdef TEST_HARNESS
    if (!hInstall)
    {
        MessageBox(NULL, pszMessage, wszMessage.c_str(), 0);
        return;
    }
#endif

	PMSIHANDLE hRecord0 = MsiCreateRecord(1);
    // field 0 is the template
    MsiRecordSetString(hRecord0, 0, (level == MSI_INFO_LEVEL) ? L"VeraCryptCustomAction_INFO: [1]" : ((level == MSI_WARNING_LEVEL) ? L"VeraCryptCustomAction_WARNING: [1]" : L"VeraCryptCustomAction_ERROR: [1]"));
    // field 1, to be placed in [1] placeholder
    MsiRecordSetString(hRecord0, 1, wszMessage.c_str());
    // send message to running installer
    MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord0);

	PMSIHANDLE hRecord1 = MsiCreateRecord(0);
    MsiRecordSetString(hRecord1, 0, wszMessage.c_str());
	if (level == MSI_INFO_LEVEL)
		MsiProcessMessage(hInstall, INSTALLMESSAGE(INSTALLMESSAGE_INFO + MB_OK), hRecord1);
	else if (level == MSI_WARNING_LEVEL)
		MsiProcessMessage(hInstall, INSTALLMESSAGE(INSTALLMESSAGE_WARNING + MB_OK), hRecord1);
	else
		MsiProcessMessage(hInstall, INSTALLMESSAGE(INSTALLMESSAGE_ERROR + MB_OK), hRecord1);
}

/* **************************************************************************** */

/* 
 * Defined in Dlgcode.c.
 */
extern void ExceptionHandlerThread (void *threadArg);
extern LONG __stdcall ExceptionHandler (EXCEPTION_POINTERS *ep);
extern void InvalidParameterHandler (const wchar_t *expression, const wchar_t *function, const wchar_t *file, unsigned int line, uintptr_t reserved);
extern BOOL SystemFileSelectorCallPending;
extern DWORD SystemFileSelectorCallerThreadId;

/* **************************************************************************** */

/* 
 * Same as in Dlgcode.c, Applink() , but 
 * removed unnecessary code.
 */
void Applink_Dll (MSIHANDLE hInstaller, const char *dest)
{
	wchar_t url [MAX_URL_LENGTH] = {0};
	wchar_t page[TC_MAX_PATH] = {0};
	wchar_t installDir[TC_MAX_PATH] = {0};
	BOOL buildUrl = TRUE;
	int r;

	StringCbCopyW (installDir, sizeof (installDir), InstallationPath);

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

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Applink_Dll: url(%s)", url);

	if (IsAdmin ())
	{
		// TODO: FileExists always returns FALSE
		//		 This is due to the fact that waccess does not like url encoded as 'file:///%sdocs/html/en/%s'.
		//		 It fails with '0x0000007B: The filename, directory name, or volume label syntax is incorrect.'.
		if (buildUrl && !FileExists (url))
		{
			// fallbacl to online resources
			StringCbPrintfW (url, sizeof (url), L"https://www.veracrypt.fr/en/%s", page);
			SafeOpenURL (url);
		}
		else
		{
			SafeOpenURL (url);
		}
	}
	else
	{
		r = (int) ShellExecuteW (NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);

		if (((r == ERROR_FILE_NOT_FOUND) || (r == ERROR_PATH_NOT_FOUND)) && buildUrl)
		{
			// fallbacl to online resources
			StringCbPrintfW (url, sizeof (url), L"https://www.veracrypt.fr/en/%s", page);
			ShellExecuteW (NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
		}			
	}
}

/* 
 * Same as in Dlgcode.c, CheckCapsLock(), but 
 * replaced MessageBoxW() with MSILogAndShow().
 */
BOOL CheckCapsLock_Dll (MSIHANDLE hInstaller, BOOL quiet)
{
	if ((GetKeyState(VK_CAPITAL) & 1) != 0)	
	{
		MSILogAndShow(hInstaller, MSI_WARNING_LEVEL, GetString ("CAPSLOCK_ON"));
		return TRUE;
	}
	return FALSE;
}

/* 
 * Same as in Dlgcode.c, GetWrongPasswordErrorMessage(), but 
 * replaced CheckCapsLock() with CheckCapsLock_Dll().
 */
std::wstring GetWrongPasswordErrorMessage_Dll (MSIHANDLE hInstaller)
{
	WCHAR szTmp[8192];

	StringCbPrintfW (szTmp, sizeof(szTmp), GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG"));
	if (CheckCapsLock_Dll (hInstaller, TRUE))
		StringCbCatW (szTmp, sizeof(szTmp), GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

	wstring msg = szTmp;
	return msg;
}

/* 
 * Same as in Dlgcode.c, HandleDriveNotReadyError(), but 
 * replaced Warning() with MSILogAndShow().
 */
void HandleDriveNotReadyError_Dll (MSIHANDLE hInstaller)
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return;

	if (RegQueryValueEx (hkey, L"NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS
		&& value != 0)
	{
		MSILogAndShow (hInstaller, MSI_WARNING_LEVEL, GetString("SYS_AUTOMOUNT_DISABLED"));
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		MSILogAndShow (hInstaller, MSI_WARNING_LEVEL, GetString("SYS_ASSIGN_DRIVE_LETTER"));
	else
		MSILogAndShow (hInstaller, MSI_WARNING_LEVEL, GetString("DEVICE_NOT_READY_ERROR"));

	RegCloseKey (hkey);
}

/* 
 * Same as in Dlgcode.c, handleWin32Error(), but 
 * replaced ErrorDirect(), Error() and MessageBoxW with MSILogAndShow(),
 * replaced HandleDriveNotReadyError() with HandleDriveNotReadyError_Dll().
 */
DWORD handleWin32Error_Dll (MSIHANDLE hInstaller, const char* srcPos)
{
	PWSTR lpMsgBuf;
	DWORD dwError = GetLastError ();	
	wchar_t szErrorValue[32];
	wchar_t* pszDesc;

	if (dwError == 0 || dwError == ERROR_INVALID_WINDOW_HANDLE)
		return dwError;

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("ERR_ACCESS_DENIED"), srcPos).c_str ());
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

	MSILogAndShow (hInstaller, MSI_INFO_LEVEL, AppendSrcPos (pszDesc, srcPos).c_str ());
	if (lpMsgBuf) LocalFree (lpMsgBuf);

	// User-friendly hardware error explanation
	if (IsDiskError (dwError))
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("ERR_HARDWARE_ERROR"));

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		HandleDriveNotReadyError_Dll(hInstaller);

	SetLastError (dwError);		// Preserve the original error code

	return dwError;
}

/* 
 * Same as in Dlgcode.c, handleError(), but 
 * replaced ErrorDirect(), Error() and MessageBoxW with MSILogAndShow(),
 * replaced handleWin32Error() with handleWin32Error_Dll().
 */
void handleError_Dll (MSIHANDLE hInstaller, int code, const char* srcPos)
{
	WCHAR szTmp[4096];

	switch (code & 0x0000FFFF)
	{
	case ERR_OS_ERROR:
		handleWin32Error_Dll (hInstaller, srcPos);
		break;
	case ERR_OUTOFMEMORY:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("OUTOFMEMORY"), srcPos).c_str());
		break;

	case ERR_PASSWORD_WRONG:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetWrongPasswordErrorMessage_Dll (hInstaller).c_str(), srcPos).c_str());
		break;

	case ERR_DRIVE_NOT_FOUND:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("NOT_FOUND"), srcPos).c_str());
		break;
	case ERR_FILES_OPEN:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("OPENFILES_DRIVER"), srcPos).c_str());
		break;
	case ERR_FILES_OPEN_LOCK:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("OPENFILES_LOCK"), srcPos).c_str());
		break;
	case ERR_VOL_SIZE_WRONG:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("VOL_SIZE_WRONG"), srcPos).c_str());
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("COMPRESSION_NOT_SUPPORTED"), srcPos).c_str());
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("WRONG_VOL_TYPE"), srcPos).c_str());
		break;
	case ERR_VOL_SEEKING:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("VOL_SEEKING"), srcPos).c_str());
		break;
	case ERR_CIPHER_INIT_FAILURE:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("ERR_CIPHER_INIT_FAILURE"), srcPos).c_str());
		break;
	case ERR_CIPHER_INIT_WEAK_KEY:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("ERR_CIPHER_INIT_WEAK_KEY"), srcPos).c_str());
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("VOL_ALREADY_MOUNTED"), srcPos).c_str());
		break;
	case ERR_FILE_OPEN_FAILED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("FILE_OPEN_FAILED"), srcPos).c_str());
		break;
	case ERR_VOL_MOUNT_FAILED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString  ("VOL_MOUNT_FAILED"), srcPos).c_str());
		break;
	case ERR_NO_FREE_DRIVES:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("NO_FREE_DRIVES"), srcPos).c_str());
		break;
	case ERR_ACCESS_DENIED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("ACCESS_DENIED"), srcPos).c_str());
		break;

	case ERR_DRIVER_VERSION:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("DRIVER_VERSION"));
		break;

	case ERR_NEW_VERSION_REQUIRED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (GetString ("NEW_VERSION_REQUIRED"), srcPos).c_str());
		break;

	case ERR_SELF_TESTS_FAILED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("ERR_SELF_TESTS_FAILED"));
		break;

	case ERR_VOL_FORMAT_BAD:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("ERR_VOL_FORMAT_BAD"));
		break;

	case ERR_ENCRYPTION_NOT_COMPLETED:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("ERR_ENCRYPTION_NOT_COMPLETED"));
		break;

	case ERR_NONSYS_INPLACE_ENC_INCOMPLETE:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("ERR_NONSYS_INPLACE_ENC_INCOMPLETE"));
		break;

	case ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG"));
		break;

	case ERR_PARAMETER_INCORRECT:
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("ERR_PARAMETER_INCORRECT"));
		break;

	case ERR_USER_ABORT:
	case ERR_DONT_REPORT:
		// A non-error
		break;

	case ERR_UNSUPPORTED_TRUECRYPT_FORMAT:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("UNSUPPORTED_TRUECRYPT_FORMAT"), (code >> 24), (code >> 16) & 0x000000FF);
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (szTmp, srcPos).c_str());
		break;

	default:
		StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("ERR_UNKNOWN"), code);
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, AppendSrcPos (szTmp, srcPos).c_str());
	}
}

/* 
 * Same as in Dlgcode.c, LoadSystemDll() , but 
 * replaced AbortProcess() with MSILogAndShow() + return,
 */
static void LoadSystemDll_Dll (MSIHANDLE hInstaller, LPCTSTR szModuleName, HMODULE *pHandle, BOOL bIgnoreError, const char* srcPos)
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
		handleWin32Error_Dll (hInstaller, srcPos);
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString ("INIT_DLL"));
	}
}

/* 
 * Same as in Dlgcode.c, handleWin32Error(), but 
 * replaced AbortProcess() with MSILogAndShow() + return,
 */
BOOL IsPagingFileActive_Dll (MSIHANDLE hInstaller, BOOL checkNonWindowsPartitionsOnly)
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
	{
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("UAC_INIT_ERROR"));
		return FALSE;
	}

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

		BYTE dgBuffer[256];
		DWORD dwResult;

		if (!DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, dgBuffer, sizeof (dgBuffer), &dwResult, NULL)
			&& !DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, dgBuffer, sizeof (dgBuffer), &dwResult, NULL))
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

/* 
 * Same as in Dlgcode.c, DoDriverInstall(), but 
 * replaced StatusMessage() with MSILog().
 */
BOOL DoDriverInstall_Dll (MSIHANDLE hInstaller)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoDriverInstall_Dll");

	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;

#ifdef SETUP
	if (SystemEncryptionUpdate)
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"SystemEncryptionUpdate == TRUE");
		bOK = TRUE;
		goto end;
	}
#endif

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

#ifdef SETUP
	MSILog (hInstaller, MSI_INFO_LEVEL, GetString("INSTALLING_DRIVER"));
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
	MSILog (hInstaller, MSI_INFO_LEVEL, GetString("STARTING_DRIVER"));
#endif

	bRet = StartService (hService, 0, NULL);
	if (bRet == FALSE)
		goto error;

	bOK = TRUE;

error:
	if (bOK == FALSE && GetLastError () != ERROR_SERVICE_ALREADY_RUNNING)
	{
		handleWin32Error_Dll (hInstaller, SRC_POS);
		MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, GetString("DRIVER_INSTALL_FAILED"));
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoDriverInstall_Dll");
	return bOK;
}

/* **************************************************************************** */

/* 
 * Same as in Setup.c, StartStopService(), but 
 * replaced StatusMessage() with MSILog().
 */
BOOL StartStopService_Dll (MSIHANDLE hInstaller, wchar_t *lpszService, BOOL bStart, DWORD argc, LPCWSTR* argv)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status = {0};
	int x;
	DWORD dwExpectedState = bStart? SERVICE_RUNNING : SERVICE_STOPPED;

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, lpszService, SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	if (bStart)
		MSILog(hInstaller, MSI_INFO_LEVEL, L"STARTING %s", lpszService);
	else
		MSILog(hInstaller, MSI_INFO_LEVEL, L"STOPPING %s", lpszService);

	if (bStart)
	{
		if (!StartService (hService, argc, argv) && (GetLastError () != ERROR_SERVICE_ALREADY_RUNNING))
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"Failed to start %s. Error 0x%.8X", lpszService, GetLastError ());
			goto error;
		}
	}
	else
		ControlService (hService, SERVICE_CONTROL_STOP, &status);

	for (x = 0; x < WAIT_PERIOD; x++)
	{
		bRet = QueryServiceStatus (hService, &status);
		if (bRet != TRUE)
			goto error;

		if (status.dwCurrentState == dwExpectedState)
			break;

		Sleep (1000);
	}

	bRet = QueryServiceStatus (hService, &status);
	if (bRet != TRUE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"Failed to query status of %s. Error 0x%.8X", lpszService, GetLastError ());
		goto error;
	}

	if (status.dwCurrentState != dwExpectedState)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"Current state of %s (0x%.8X) is different from expected one (0x%.8X).", lpszService, status.dwCurrentState, dwExpectedState);
		goto error;
	}

	bOK = TRUE;

error:

	if (bOK == FALSE && GetLastError () == ERROR_SERVICE_DOES_NOT_EXIST)
	{
		bOK = TRUE;
	}

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	return bOK;
}

/* 
 * Same as in Setup.c, SetSystemRestorePoint(), but 
 * replaced StatusMessage() with MSILog().
 */
static void SetSystemRestorePoint_Dll (MSIHANDLE hInstaller, BOOL finalize)
{
	static RESTOREPOINTINFO RestPtInfo;
	static STATEMGRSTATUS SMgrStatus;
	static BOOL failed = FALSE;
	static BOOL (__stdcall *_SRSetRestorePoint)(PRESTOREPOINTINFO, PSTATEMGRSTATUS);

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin SetSystemRestorePoint_Dll");

	if (!SystemRestoreDll)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"SystemRestoreDll NULL");
		goto end;
	}

	_SRSetRestorePoint = (BOOL (__stdcall *)(PRESTOREPOINTINFO, PSTATEMGRSTATUS))GetProcAddress (SystemRestoreDll,"SRSetRestorePointW");
	if (_SRSetRestorePoint == 0)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"_SRSetRestorePoint NULL");
		FreeLibrary (SystemRestoreDll);
		SystemRestoreDll = 0;
		goto end;
	}

	if (!finalize)
	{
		MSILog (hInstaller, MSI_INFO_LEVEL, GetString("CREATING_SYS_RESTORE"));

		RestPtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
		RestPtInfo.dwRestorePtType = bUninstall ? APPLICATION_UNINSTALL : APPLICATION_INSTALL | DEVICE_DRIVER_INSTALL;
		RestPtInfo.llSequenceNumber = 0;
		StringCbCopyW (RestPtInfo.szDescription, sizeof(RestPtInfo.szDescription), bUninstall ? L"VeraCrypt uninstallation" : L"VeraCrypt installation");

		if(!_SRSetRestorePoint (&RestPtInfo, &SMgrStatus))
		{
			MSILog (hInstaller, MSI_ERROR_LEVEL, GetString("FAILED_SYS_RESTORE"));
			failed = TRUE;
		}
	}
	else if (!failed)
	{
		RestPtInfo.dwEventType = END_SYSTEM_CHANGE;
		RestPtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

		if(!_SRSetRestorePoint(&RestPtInfo, &SMgrStatus))
		{
			MSILog (hInstaller, MSI_ERROR_LEVEL, GetString("FAILED_SYS_RESTORE"));
		}
	}

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End SetSystemRestorePoint_Dll");
}

/* 
 * Same as in Setup.c, DoDriverUnload(), but 
 * replaced AbortProcess() and AbortProcessSilent() with MSILogAndShow() + return,
 * replaced Error(), MessageBoxW() with MSILogAndShow(),
 * replaced StatusMessage() with MSILog(),
 * replaced handleWin32Error() with handleWin32Error_Dll().
 */
BOOL DoDriverUnload_Dll (MSIHANDLE hInstaller, HWND hwnd)
{
	BOOL	bOK		= TRUE;
	int		status	= 0;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoDriverUnload_Dll");

	status = DriverAttach ();
	if (status != 0)
	{
		if (status == ERR_OS_ERROR && GetLastError () != ERROR_FILE_NOT_FOUND)
		{
			handleWin32Error_Dll (hInstaller, SRC_POS);
			MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, GetString("NODRIVER"));
			bOK = FALSE;
			goto end;
		}

		if (status != ERR_OS_ERROR)
		{
			handleError_Dll (hInstaller, status, SRC_POS);
			MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, GetString("NODRIVER"));
			bOK = FALSE;
			goto end;
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
			BootEncryption bootEnc (hwnd);
			if (bootEnc.GetDriverServiceStartType() == SERVICE_BOOT_START)
			{
				try
				{
					// Check hidden OS update consistency
					if (IsHiddenOSRunning())
					{
						if (bootEnc.GetInstalledBootLoaderVersion() != VERSION_NUM)
						{
							if (AskWarnNoYes ("UPDATE_TC_IN_DECOY_OS_FIRST", hwnd) == IDNO)
							{
								MSILog(hInstaller, MSI_ERROR_LEVEL, L"User denied request");
								bOK = FALSE;
								goto end;
							}
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
					MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, (bDowngrade ? GetString("SETUP_FAILED_BOOT_DRIVE_ENCRYPTED_DOWNGRADE") : GetString("SETUP_FAILED_BOOT_DRIVE_ENCRYPTED")));
					bOK = FALSE;
					goto end;
				}
				else
				{
					if (CurrentOSMajor == 6 && CurrentOSMinor == 0 && CurrentOSServicePack < 1)
					{
						MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, GetString("SYS_ENCRYPTION_UPGRADE_UNSUPPORTED_ON_VISTA_SP0"));
						bOK = FALSE;
						goto end;
					}

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
					MSILogAndShow(hInstaller, MSI_WARNING_LEVEL, GetString ("DISMOUNT_ALL_FIRST"));
				}
			}
			else
			{
				bOK = FALSE;
				handleWin32Error_Dll (hInstaller, SRC_POS);
			}
		}

		// Try to close all open TC windows
		if (bOK)
		{
			BOOL TCWindowClosed = FALSE;

			EnumWindows (CloseTCWindowsEnum, (LPARAM) &TCWindowClosed);

			if (TCWindowClosed)
				Sleep (2000);

			// stop service
			if (SystemEncryptionUpdate)
			{
				StartStopService_Dll (hInstaller, TC_SYSTEM_FAVORITES_SERVICE_NAME, FALSE, 0, NULL);
			}
		}

		// Test for any applications attached to driver
		if (!bUpgrade)
		{
			bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
				sizeof (refCount), &dwResult, NULL);

			if (bOK && bResult && refCount > 1)
			{
				MSILogAndShow(hInstaller, MSI_WARNING_LEVEL, GetString ("CLOSE_TC_FIRST"));
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

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoDriverUnload_Dll");
	return bOK;
}

/* 
 * Same as in Setup.c,  DoServiceUninstall(), but 
 * replaced AbortProcess() and AbortProcessSilent() with MSILogAndShow() + return,
 * replaced Error(), MessageBoxW() with MSILogAndShow(),
 * replaced StatusMessage() with MSILog(),
 * replaced handleWin32Error() with handleWin32Error_Dll().
 */
BOOL DoServiceUninstall_Dll (MSIHANDLE hInstaller, HWND hwndDlg, wchar_t *lpszService)
{
	SC_HANDLE hManager, hService = NULL;
	BOOL bOK = FALSE, bRet;
	SERVICE_STATUS status;
	BOOL firstTry = TRUE;
	int x;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoServiceUninstall_Dll");

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

		MSILog (hInstaller, MSI_INFO_LEVEL, GetString("STOPPING_DRIVER"));
	}
	else
		MSILog (hInstaller, MSI_INFO_LEVEL, L"STOPPING %s", lpszService);

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
		MSILog (hInstaller, MSI_INFO_LEVEL, GetString("REMOVING_DRIVER"));
	else
		MSILog (hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", lpszService);

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
		handleWin32Error_Dll (hInstaller, SRC_POS);
		MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("DRIVER_UINSTALL_FAILED"));
	}
	else
		bOK = TRUE;

	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoServiceUninstall_Dll");
	return bOK;
}

/* 
 * Same as in Setup.c, DoRegUninstall(), but 
 * replaced StatusMessage() with MSILog(),
 * removed unnecessary code that is done by MSI.
 */
BOOL DoRegUninstall_Dll (MSIHANDLE hInstaller, BOOL bRemoveDeprecated)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoRegUninstall_Dll");

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
			MSILog (hInstaller, MSI_ERROR_LEVEL, GetString("COM_DEREG_FAILED"));
	}

	if (!bRemoveDeprecated)
		MSILog (hInstaller, MSI_INFO_LEVEL, GetString("REMOVING_REG"));

	/* The following is done by MSI, so we skip it */
	/*
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
	*/

	if (!bRemoveDeprecated)
	{
		HKEY hKey;

		GetStartupRegKeyName (regk, sizeof(regk));
		DeleteRegistryValue (regk, L"VeraCrypt");

		// The following is done by MSI, so we skip it
		// DeleteRegistryKey (HKEY_LOCAL_MACHINE, L"Software\\Classes\\.hc");

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

		// The following is done by MSI, so we skip it
		//SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	if (hAdvapiDll)
		FreeLibrary (hAdvapiDll);

	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoRegUninstall_Dll");
	return TRUE;
}

/* 
 * Same as in Setup.c, UpgradeBootLoader(), but 
 * replaced StatusMessage() with MSILog().
 */
BOOL UpgradeBootLoader_Dll (MSIHANDLE hInstaller, HWND hwndDlg)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin UpgradeBootLoader_Dll");

	BOOL bOK = FALSE, bNeedUnloadDriver = FALSE;
	int status;

	if (!SystemEncryptionUpdate)
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"SystemEncryptionUpdate == FALSE");
		bOK = TRUE;
		goto end;
	}

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		status = DriverAttach();
		if ((status == 0) && (hDriver != INVALID_HANDLE_VALUE))
		{
			bNeedUnloadDriver = TRUE;
		}
		else
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"UpgradeBootLoader_Dll: failed to attach to driver");
		}
	}

	try
	{
		BootEncryption bootEnc (hwndDlg);
		uint64 bootLoaderVersion = bootEnc.GetInstalledBootLoaderVersion();
		if ((bootLoaderVersion < VERSION_NUM) || (bReinstallMode && (bootLoaderVersion == VERSION_NUM)))
		{
			MSILog (hInstaller, MSI_INFO_LEVEL, GetString("INSTALLER_UPDATING_BOOT_LOADER"));

			// this is done by the service now
			//bootEnc.InstallBootLoader (true);

			if (bootEnc.GetInstalledBootLoaderVersion() <= TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION)
			{
				bUpdateRescueDisk = TRUE;
				MSILog (hInstaller, MSI_INFO_LEVEL, GetString(IsHiddenOSRunning() ? "BOOT_LOADER_UPGRADE_OK_HIDDEN_OS" : "BOOT_LOADER_UPGRADE_OK"));
			}
		}
		bOK = TRUE;
		goto end;
	}
	catch (Exception &e)
	{
		e.Show (hwndDlg);
	}
	catch (...) { }

	MSILog (hInstaller, MSI_ERROR_LEVEL, GetString("BOOT_LOADER_UPGRADE_FAILED"));

end:
	if (bNeedUnloadDriver)
	{
		CloseHandle (hDriver);
		hDriver = INVALID_HANDLE_VALUE;
	}
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End UpgradeBootLoader_Dll");
	return bOK;
}

/* 
 * Same as Setup.c, function DoApplicationDataUninstall(), but 
 * replaced StatusMessage() and RemoveMessage() with MSILog().
 */
BOOL DoApplicationDataUninstall_Dll (MSIHANDLE hInstaller)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoApplicationDataUninstall");

	wchar_t path[MAX_PATH];
	wchar_t path2[MAX_PATH];
	BOOL bOK = TRUE;

	MSILog(hInstaller, MSI_INFO_LEVEL, GetString("REMOVING_APPDATA"));

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	StringCbCatW (path, sizeof(path), L"\\VeraCrypt\\");

	// Delete favorite volumes file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_FAVORITE_VOLUMES);
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
	StatDeleteFile (path2, FALSE);

	// Delete keyfile defaults
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_DEFAULT_KEYFILES);
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
	StatDeleteFile (path2, FALSE);

	// Delete history file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_HISTORY);
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
	StatDeleteFile (path2, FALSE);

	// Delete configuration file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_CONFIGURATION);
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
	StatDeleteFile (path2, FALSE);

	// Delete system encryption configuration file
	StringCbPrintfW (path2, sizeof(path2), L"%s%s", path, TC_APPD_FILENAME_SYSTEM_ENCRYPTION);
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
	StatDeleteFile (path2, FALSE);

	SHGetFolderPath (NULL, CSIDL_APPDATA, NULL, 0, path);
	StringCbCatW (path, sizeof(path), L"\\VeraCrypt");
	MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path);
	if (!StatRemoveDirectory (path))
	{
		handleWin32Error_Dll (hInstaller, SRC_POS);
		bOK = FALSE;
	}

	// remove VeraCrypt under common appdata
	if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		StringCbCatW (path, sizeof(path), L"\\VeraCrypt");

		// Delete original bootloader
		StringCbPrintfW (path2, sizeof(path2), L"%s\\%s", path, TC_SYS_BOOT_LOADER_BACKUP_NAME);
		MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path2);
		StatDeleteFile (path2, FALSE);

		// remove VeraCrypt folder
		MSILog(hInstaller, MSI_INFO_LEVEL, L"REMOVING %s", path);
		StatRemoveDirectory (path);
	}

	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoApplicationDataUninstall");
	return bOK;
}

/* 
 * Same as Setup.c, function DoUninstall(), but 
 * removed uninstall of files and registry as it will be 
 * done by MSI.
 */
BOOL DoUninstall_Dll (MSIHANDLE hInstaller, HWND hwndDlg)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin DoUninstall_Dll");

	BOOL bOK = TRUE;
	BOOL bTempSkipSysRestore = FALSE;

	if (DoDriverUnload_Dll (hInstaller, hwndDlg) == FALSE)
	{
		bOK = FALSE;
		bTempSkipSysRestore = TRUE;		// Volumes are possibly mounted; defer System Restore point creation for this uninstall attempt.
	}
	else
	{
		if (!Rollback && bSystemRestore && !bTempSkipSysRestore)
			SetSystemRestorePoint_Dll (hInstaller, FALSE);

		if (DoServiceUninstall_Dll (hInstaller, hwndDlg, L"veracrypt") == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoRegUninstall_Dll (hInstaller, FALSE) == FALSE)
		{
			bOK = FALSE;
		}
		/* Following skipped because done by MSI */
		/*
		else if (DoFilesInstall ((HWND) hwndDlg, InstallationPath) == FALSE)
		{
			bOK = FALSE;
		}
		else if (DoShortcutsUninstall (hwndDlg, InstallationPath) == FALSE)
		{
			bOK = FALSE;
		}
		*/
		else if (!DoApplicationDataUninstall_Dll (hInstaller))
		{
			bOK = FALSE;
		}
		else
		{
			// Deprecated service
			DoServiceUninstall_Dll (hInstaller, hwndDlg, L"VeraCryptService");
		}
	}

	if (Rollback)
		goto end;

	if (bSystemRestore && !bTempSkipSysRestore)
		SetSystemRestorePoint_Dll (hInstaller, TRUE);

	if (!bOK)
		bUninstallInProgress = FALSE;

end:

	MSILog(hInstaller, MSI_INFO_LEVEL, L"End DoUninstall_Dll");
	return bOK;
}

/* 
 * Same as Setup.c, function InitApp(), but 
 * replaced unnecessary calls,
 * forced english as language,
 * replaced LoadLanguageFile() with LoadLanguageFromResource() to be able to set bForceSilent.
 */
BOOL InitDll (MSIHANDLE hInstaller)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin InitDll");

	BOOL bOK = TRUE;
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
	InitGlobalLocks ();

	LoadSystemDll_Dll (hInstaller, L"msvcrt.dll", &hmsvcrtdll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"ntmarta.dll", &hntmartadll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"MPR.DLL", &hmprdll, TRUE, SRC_POS);
	if (IsOSAtLeast (WIN_7))
	{
		LoadSystemDll_Dll (hInstaller, L"ProfApi.DLL", &hProfApiDll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"cryptbase.dll", &hcryptbasedll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"sspicli.dll", &hsspiclidll, TRUE, SRC_POS);
	}
	LoadSystemDll_Dll (hInstaller, L"psapi.dll", &hpsapidll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"secur32.dll", &hsecur32dll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"msasn1.dll", &hmsasn1dll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"Usp10.DLL", &hUsp10Dll, TRUE, SRC_POS);
	if (IsOSAtLeast (WIN_7))
		LoadSystemDll_Dll (hInstaller, L"dwmapi.dll", &hdwmapidll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"UXTheme.dll", &hUXThemeDll, TRUE, SRC_POS);   

	LoadSystemDll_Dll (hInstaller, L"msls31.dll", &hMsls31, TRUE, SRC_POS);	
	LoadSystemDll_Dll (hInstaller, L"SETUPAPI.DLL", &hSetupDll, FALSE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"SHLWAPI.DLL", &hShlwapiDll, FALSE, SRC_POS);	

	LoadSystemDll_Dll (hInstaller, L"userenv.dll", &hUserenvDll, TRUE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"rsaenh.dll", &hRsaenhDll, TRUE, SRC_POS);

	if (nCurrentOS < WIN_7)
	{
		if (nCurrentOS == WIN_XP)
		{
			LoadSystemDll_Dll (hInstaller, L"imm32.dll", &himm32dll, TRUE, SRC_POS);
			LoadSystemDll_Dll (hInstaller, L"MSCTF.dll", &hMSCTFdll, TRUE, SRC_POS);
			LoadSystemDll_Dll (hInstaller, L"fltlib.dll", &hfltlibdll, TRUE, SRC_POS);
			LoadSystemDll_Dll (hInstaller, L"wbem\\framedyn.dll", &hframedyndll, TRUE, SRC_POS);
		}

		if (IsOSAtLeast (WIN_VISTA))
		{					
			LoadSystemDll_Dll (hInstaller, L"netapi32.dll", &hnetapi32dll, TRUE, SRC_POS);
			LoadSystemDll_Dll (hInstaller, L"authz.dll", &hauthzdll, TRUE, SRC_POS);
			LoadSystemDll_Dll (hInstaller, L"xmllite.dll", &hxmllitedll, TRUE, SRC_POS);
		}
	}

	if (IsOSAtLeast (WIN_VISTA))
	{					
		LoadSystemDll_Dll (hInstaller, L"atl.dll", &hsppdll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"vsstrace.dll", &hvsstracedll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"vssapi.dll", &vssapidll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"spp.dll", &hsppdll, TRUE, SRC_POS);
	}

	LoadSystemDll_Dll (hInstaller, L"crypt32.dll", &hcrypt32dll, TRUE, SRC_POS);
	
	if (IsOSAtLeast (WIN_7))
	{
		LoadSystemDll_Dll (hInstaller, L"CryptSP.dll", &hCryptSpDll, TRUE, SRC_POS);

		LoadSystemDll_Dll (hInstaller, L"cfgmgr32.dll", &hcfgmgr32dll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"devobj.dll", &hdevobjdll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"powrprof.dll", &hpowrprofdll, TRUE, SRC_POS);

		LoadSystemDll_Dll (hInstaller, L"bcrypt.dll", &hbcryptdll, TRUE, SRC_POS);
		LoadSystemDll_Dll (hInstaller, L"bcryptprimitives.dll", &hbcryptprimitivesdll, TRUE, SRC_POS);								
	}	

	LoadSystemDll_Dll (hInstaller, L"COMCTL32.DLL", &hComctl32Dll, FALSE, SRC_POS);
	
	// call InitCommonControls function
	InitCommonControlsFn = (InitCommonControlsPtr) GetProcAddress (hComctl32Dll, "InitCommonControls");
	ImageList_AddFn = (ImageList_AddPtr) GetProcAddress (hComctl32Dll, "ImageList_Add");
	ImageList_CreateFn = (ImageList_CreatePtr) GetProcAddress (hComctl32Dll, "ImageList_Create");

	if (InitCommonControlsFn && ImageList_AddFn && ImageList_CreateFn)
	{
		InitCommonControlsFn();
	}
	else
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, GetString("INIT_DLL"));
		bOK = FALSE;
		goto end;
	}

	LoadSystemDll_Dll (hInstaller, L"Riched20.dll", &hRichEditDll, FALSE, SRC_POS);
	LoadSystemDll_Dll (hInstaller, L"Advapi32.dll", &hAdvapi32Dll, FALSE, SRC_POS);

	// Get SetupAPI functions pointers
	SetupCloseInfFileFn = (SetupCloseInfFilePtr) GetProcAddress (hSetupDll, "SetupCloseInfFile");
	SetupDiOpenClassRegKeyFn = (SetupDiOpenClassRegKeyPtr) GetProcAddress (hSetupDll, "SetupDiOpenClassRegKey");
	SetupInstallFromInfSectionWFn = (SetupInstallFromInfSectionWPtr) GetProcAddress (hSetupDll, "SetupInstallFromInfSectionW");
	SetupOpenInfFileWFn = (SetupOpenInfFileWPtr) GetProcAddress (hSetupDll, "SetupOpenInfFileW");

	if (!SetupCloseInfFileFn || !SetupDiOpenClassRegKeyFn || !SetupInstallFromInfSectionWFn || !SetupOpenInfFileWFn)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, GetString("INIT_DLL"));
		bOK = FALSE;
		goto end;
	}

	// Get SHDeleteKeyW function pointer
	SHDeleteKeyWFn = (SHDeleteKeyWPtr) GetProcAddress (hShlwapiDll, "SHDeleteKeyW");
	SHStrDupWFn = (SHStrDupWPtr) GetProcAddress (hShlwapiDll, "SHStrDupW");
	if (!SHDeleteKeyWFn || !SHStrDupWFn)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, GetString("INIT_DLL"));
		bOK = FALSE;
		goto end;
	}

	if (IsOSAtLeast (WIN_VISTA))
	{
		/* Get ChangeWindowMessageFilter used to enable some messages bypasss UIPI (User Interface Privilege Isolation) */
		ChangeWindowMessageFilterFn = (ChangeWindowMessageFilterPtr) GetProcAddress (GetModuleHandle (L"user32.dll"), "ChangeWindowMessageFilter");
	}

	// Get CreateProcessWithTokenW function pointer
	CreateProcessWithTokenWPtr = (CreateProcessWithTokenWFn) GetProcAddress(hAdvapi32Dll, "CreateProcessWithTokenW");

	SetErrorMode (SetErrorMode (0) | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
	CoInitialize (NULL);

	// Force language to english to read strings from the default Language.xml embedded in the DLL.
	SetPreferredLangId ("en");
	bUserSetLanguage = TRUE;
	LoadLanguageFromResource (0, FALSE, TRUE);

	SetUnhandledExceptionFilter (ExceptionHandler);
	_set_invalid_parameter_handler (InvalidParameterHandler);
	RemoteSession = GetSystemMetrics (SM_REMOTESESSION) != 0;

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End InitDll");
	return bOK;
}

/* **************************************************************************** */

/* 
 * Same as Setup.c, function wWinMain(), but 
 * replaced unnecessary calls.
 * This should be called at the beginning of each operation (install, uninstall...),
 * before atexit(VC_CustomAction_Cleanup()) call.
 */
BOOL VC_CustomAction_Init(MSIHANDLE hInstaller, const wchar_t* szInstallDir)
{
	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_Init");
	
	BOOL bOK = TRUE;

	if (!InitDll(hInstaller))
	{
		bOK = FALSE;
		goto end;
	}

	// System Restore
	if (IsSystemRestoreEnabled ())
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"System Restore is enabled");

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
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"System Restore is not enabled");
		SystemRestoreDll = 0;
	}

	// Set InstallationPath
	wcsncpy(InstallationPath, szInstallDir, min(wcslen(szInstallDir), ARRAYSIZE(InstallationPath)));

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_Init");
	return bOK;
}

/* 
 * Same as Setup.c, function localcleanup(), but 
 * replaced unnecessary calls.
 * This should be called at the beginning of each operation (install, uninstall...),
 * as an argument to atexit() before VC_CustomAction_Init() call.
 */
void VC_CustomAction_Cleanup ()
{
	//MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_Cleanup");

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

	CoUninitialize ();

	CloseSysEncMutex ();

	FinalizeGlobalLocks ();

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
	FREE_DLL (hmsvcrtdll);
	FREE_DLL (hAdvapi32Dll);

	//MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_Cleanup");
}

void Tokenize(const wchar_t* szInput, std::vector<std::wstring>& szTokens)
{
    std::wstringstream check(szInput); 
    std::wstring intermediate; 
    while(std::getline(check, intermediate, L'?')) 
    { 
        szTokens.push_back(intermediate);
    }
}

/* 
 * Same as Setup.c, function DoInstall(), but 
 * without the actual installation, it only prepares the system 
 * before the installation (before DoFilesInstall).
 * It runs as a Deferred CA.
 */
EXTERN_C UINT STDAPICALLTYPE VC_CustomAction_PreInstall(MSIHANDLE hInstaller)
{
	HWND			hwndDlg			= NULL;
	std::wstring    szValueBuf		= L"";
	DWORD           cchValueBuf		= 0;
	UINT            uiStat			= 0;
	HKEY			hkey			= 0;
	DWORD			dw				= 0;
	BootEncryption	bootEnc(NULL);
	std::wstring	szInstallDir	= L"";
	UINT			uiRet           = ERROR_INSTALL_FAILURE;
	BOOL			bOK				= TRUE;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_PreInstall");

	//  Get UILevel to see whether we're being installed silently or not.
	//	Also get INSTALLDIR to see where we're being installed.
	//	Since this is a Deferred CA, they are to be setup in its CustomActionData.
	uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: CustomActionData = '%s'", szValueBuf.c_str());

			std::vector<std::wstring> szTokens;
			Tokenize(szValueBuf.c_str(), szTokens);

			for (size_t i = 0; i < szTokens.size(); i++)
			{
				std::wstring szToken = szTokens[i];

				if (wcsncmp(szToken.c_str(), L"UILEVEL=", wcslen(L"UILEVEL=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						std::wstring uiLevel = szToken.substr(index0 + 1);
						Silent = (stoi(uiLevel) <= 3);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: UILEVEL = '%s', bSilent = '%d'", uiLevel.c_str(), Silent);
					}
				}
				else if (wcsncmp(szToken.c_str(), L"INSTALLDIR=", wcslen(L"INSTALLDIR=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						szInstallDir = szToken.substr(index0 + 1);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: INSTALLDIR = '%s'", szInstallDir.c_str());
					}
				}
				else if (wcsncmp(szToken.c_str(), L"REINSTALL=", wcslen(L"REINSTALL=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						std::wstring szReinstall = szToken.substr(index0 + 1);
						bRepairMode = (wcslen(szReinstall.c_str()) != 0);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: REINSTALL = '%s', bRepairMode = '%s'", szReinstall.c_str(), bRepairMode ? L"TRUE" : L"FALSE");
					}
				}
			}
		}
	}

	//	Get this MSI Installer HWND.
	//	There cannot be 2 MSIs or more running at the same time, so we're sure we'll get ours.
	//	This is only possible in case of non silent install.
	hwndDlg = FindWindow(L"MsiDialogCloseClass", NULL);
	if (!hwndDlg && !Silent)
	{
        MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreInstall: MsiDialogCloseClass not found");
		goto end;
    }

	/*	Start actual work */

	if (!VC_CustomAction_Init(hInstaller, szInstallDir.c_str()))
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreInstall: VC_CustomAction_Init() failed");
		goto end;
	}
	atexit(VC_CustomAction_Cleanup);

	bootEnc.SetParentWindow(hwndDlg);

	if (DoDriverUnload_Dll (hInstaller, hwndDlg) == FALSE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreInstall: DoDriverUnload_Dll() failed");
		goto end;
	}

	if (bSystemRestore)
	{
		SetSystemRestorePoint_Dll (hInstaller, FALSE);
	}

	if (bDisableSwapFiles && IsPagingFileActive_Dll (hInstaller, FALSE))
	{
		if (!DisablePagingFile())
		{
			handleWin32Error_Dll (hInstaller, SRC_POS);
			MSILogAndShow(hInstaller, MSI_ERROR_LEVEL, GetString("FAILED_TO_DISABLE_PAGING_FILES"));
		}
		else
		{
			bRestartRequired = TRUE;
		}
	}

	// Remove deprecated
	DoServiceUninstall_Dll (hInstaller, hwndDlg, L"VeraCryptService");
	
	if (!SystemEncryptionUpdate)
		DoRegUninstall_Dll (hInstaller, TRUE);

	if (UnloadDriver && DoServiceUninstall_Dll(hInstaller, hwndDlg, L"veracrypt") == FALSE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreInstall: DoServiceUninstall_Dll(veracrypt) failed");
		bOK = FALSE;
	}

	//	uiRet = MsiSetProperty(hInstaller, TEXT("ISREBOOTREQUIRED"), TEXT("1"));
	//		Cannot do this because this is a Deferred CA (we need Deferred so that it runs with admin privileges).
	//		MsiGetProperty and MsiSetProperty properties cannot be used for deferred InstallScript custom actions,
	//		which do not have access to the active .msi database and do not recognize any Windows Installer properties. 
	//		They can access only the information that has been written into the execution script (CustomActionData).
	//		Therefore, we set the values in RegKeys that are volatile.
	if (bOK)
	{
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			RegSetValueEx (hkey, L"Silent", 0, REG_DWORD, (const BYTE*)(&Silent), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstall", 0, REG_DWORD, (const BYTE*)(&bUninstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDowngrade", 0, REG_DWORD, (const BYTE*)(&bDowngrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstallInProgress", 0, REG_DWORD, (const BYTE*)(&bUninstallInProgress), sizeof(BOOL));
			RegSetValueEx (hkey, L"PortableMode", 0, REG_DWORD, (const BYTE*)(&PortableMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"UnloadDriver", 0, REG_DWORD, (const BYTE*)(&UnloadDriver), sizeof(BOOL));

			RegSetValueEx (hkey, L"Rollback", 0, REG_DWORD, (const BYTE*)(&Rollback), sizeof(BOOL));
			RegSetValueEx (hkey, L"bReinstallMode", 0, REG_DWORD, (const BYTE*)(&bReinstallMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpgrade", 0, REG_DWORD, (const BYTE*)(&bUpgrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPossiblyFirstTimeInstall", 0, REG_DWORD, (const BYTE*)(&bPossiblyFirstTimeInstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDevm", 0, REG_DWORD, (const BYTE*)(&bDevm), sizeof(BOOL));
			RegSetValueEx (hkey, L"SystemEncryptionUpdate", 0, REG_DWORD, (const BYTE*)(&SystemEncryptionUpdate), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRestartRequired", 0, REG_DWORD, (const BYTE*)(&bRestartRequired), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDisableSwapFiles", 0, REG_DWORD, (const BYTE*)(&bDisableSwapFiles), sizeof(BOOL));
			RegSetValueEx (hkey, L"bSystemRestore", 0, REG_DWORD, (const BYTE*)(&bSystemRestore), sizeof(BOOL));

			RegSetValueEx (hkey, L"bPromptFastStartup", 0, REG_DWORD, (const BYTE*)(&bPromptFastStartup), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptReleaseNotes", 0, REG_DWORD, (const BYTE*)(&bPromptReleaseNotes), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptTutorial", 0, REG_DWORD, (const BYTE*)(&bPromptTutorial), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpdateRescueDisk", 0, REG_DWORD, (const BYTE*)(&bUpdateRescueDisk), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRepairMode", 0, REG_DWORD, (const BYTE*)(&bRepairMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUserSetLanguage", 0, REG_DWORD, (const BYTE*)(&bUserSetLanguage), sizeof(BOOL));

			RegCloseKey (hkey);

			uiRet = ERROR_SUCCESS;
		}
		else 
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PreInstall: Could not write to registry");
		}
	}

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_PreInstall");
	return uiRet;
}

/* 
 * Same as Setup.c, function DoInstall(), but 
 * without the actual installation, it only performs 
 * post install operations (after DoRegInstall and last parts 
 * of DoFilesInstall / DoRegInstall).
 * It also does the Fast Startup check, shows Release Notes and 
 * Beginner's Tutorial if needed and sets regkey accordingly.
 * It runs as a Deferred CA.
 */
EXTERN_C UINT STDAPICALLTYPE VC_CustomAction_PostInstall(MSIHANDLE hInstaller)
{
	HWND			hwndDlg			= NULL;
	std::wstring    szValueBuf		= L"";
	DWORD           cchValueBuf		= 0;
	UINT            uiStat			= 0;
	HKEY			hkey			= 0;
	DWORD			dw				= 0;
	BootEncryption	bootEnc(NULL);
	std::wstring	szInstallDir	= L"";
	UINT			uiRet           = ERROR_INSTALL_FAILURE;
	BOOL			bOK				= TRUE;
	WCHAR			szCurrentDir[MAX_PATH];

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_PostInstall");

	//  Get INSTALLDIR to see where we're being installed.
	uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PostInstall: CustomActionData = '%s'", szValueBuf.c_str());
			if (wcsncmp(szValueBuf.c_str(), L"INSTALLDIR=", wcslen(L"INSTALLDIR=")) == 0)
			{
				size_t index0 = szValueBuf.find_first_of(L"=");
				if (index0 != std::wstring::npos)
				{
					szInstallDir = szValueBuf.substr(index0 + 1);
					MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PostInstall: INSTALLDIR = '%s'", szInstallDir.c_str());
				}
			}
		}
	}

	//	Read RegKeys previously setup by PreInstall
	if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		DWORD cbValue = sizeof(DWORD);
		DWORD dwValue = 0;

		RegQueryValueEx (hkey, L"Silent", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Silent = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDowngrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDowngrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstallInProgress", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstallInProgress = (dwValue == 1);
		RegQueryValueEx (hkey, L"PortableMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		PortableMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"UnloadDriver", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		UnloadDriver = (dwValue == 1);

		RegQueryValueEx (hkey, L"Rollback", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Rollback = (dwValue == 1);
		RegQueryValueEx (hkey, L"bReinstallMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bReinstallMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpgrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpgrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPossiblyFirstTimeInstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPossiblyFirstTimeInstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDevm", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDevm = (dwValue == 1);
		RegQueryValueEx (hkey, L"SystemEncryptionUpdate", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		SystemEncryptionUpdate = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRestartRequired", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRestartRequired = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDisableSwapFiles", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDisableSwapFiles = (dwValue == 1);
		RegQueryValueEx (hkey, L"bSystemRestore", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bSystemRestore = (dwValue == 1);

		RegQueryValueEx (hkey, L"bPromptFastStartup", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptFastStartup = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptReleaseNotes", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptReleaseNotes = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptTutorial", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptTutorial = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpdateRescueDisk", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpdateRescueDisk = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRepairMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRepairMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUserSetLanguage", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUserSetLanguage = (dwValue == 1);

		RegCloseKey (hkey);
	}
	else 
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PostInstall: Could not read from registry");
		goto end;
	}

	//	Get this MSI Installer HWND.
	//	There cannot be 2 MSIs or more running at the same time, so we're sure we'll get ours.
	//	This is only possible in case of non silent install.
	hwndDlg = FindWindow(L"MsiDialogCloseClass", NULL);
	if (!hwndDlg && !Silent)
	{
        MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: MsiDialogCloseClass not found");
		goto end;
    }

	/*	Start actual work */

	if (!VC_CustomAction_Init(hInstaller, szInstallDir.c_str()))
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: VC_CustomAction_Init() failed");
		goto end;
	}
	atexit(VC_CustomAction_Cleanup);
	bootEnc.SetParentWindow(hwndDlg);
	
	//	Last part of DoFilesInstall()
	{
		BOOL bResult = FALSE;
		WIN32_FIND_DATA f;
		HANDLE h;
		wchar_t szTmp[TC_MAX_PATH];

		// delete "VeraCrypt Setup.exe" if it exists
		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szInstallDir.c_str(), L"VeraCrypt Setup.exe");
		if (FileExists(szTmp))
		{
			ForceDeleteFile(szTmp);
		}

		StringCbPrintfW (szTmp, sizeof(szTmp), L"%s%s", szInstallDir.c_str(), L"VeraCrypt.exe");

		if (Is64BitOs ())
			EnableWow64FsRedirection (FALSE);

		wstring servicePath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", false);
		wstring serviceLegacyPath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", true);
		wstring favoritesFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false);
		wstring favoritesLegacyFile = GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, true);

		if (Is64BitOs ()
			&& FileExists (favoritesLegacyFile.c_str())
			&& !FileExists (favoritesFile.c_str()))
		{
			// copy the favorites XML file to the native system directory
			bResult = CopyFile (favoritesLegacyFile.c_str(), favoritesFile.c_str(), FALSE);
		}
		else 
		{
			bResult = TRUE;
		}

		if (bResult)
		{
			// Update the path of the service
			BootEncryption BootEncObj (hwndDlg);

			try
			{
				if (BootEncObj.GetDriverServiceStartType() == SERVICE_BOOT_START)
				{
					uint32 driverFlags = ReadDriverConfigurationFlags ();
					uint32 serviceFlags = BootEncObj.ReadServiceConfigurationFlags ();

					BootEncObj.UpdateSystemFavoritesService ();

					MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: INSTALLING %s", servicePath.c_str());

					// Tell the service not to update loader on stop
					BootEncObj.SetServiceConfigurationFlag (VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_UPDATE_LOADER, true);

					if (StartStopService_Dll (hInstaller, TC_SYSTEM_FAVORITES_SERVICE_NAME, FALSE, 0, NULL))
					{
						// we tell the service not to load system favorites on startup and to update bootloader on startup
						LPCWSTR szArgs[3] = { TC_SYSTEM_FAVORITES_SERVICE_NAME, VC_SYSTEM_FAVORITES_SERVICE_ARG_SKIP_MOUNT, VC_SYSTEM_FAVORITES_SERVICE_ARG_UPDATE_LOADER};
						if (!CopyFile (szTmp, servicePath.c_str(), FALSE))
							ForceCopyFile (szTmp, servicePath.c_str());

						MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: SystemEncryptionUpdate = %s", SystemEncryptionUpdate? L"TRUE" : L"FALSE");

						StartStopService_Dll (hInstaller, TC_SYSTEM_FAVORITES_SERVICE_NAME, TRUE, SystemEncryptionUpdate? 3 : 2, szArgs);
					}
					else
					{
						MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: failed to stop %S", servicePath.c_str());
						ForceCopyFile (szTmp, servicePath.c_str());
					}

					BootEncObj.SetDriverConfigurationFlag (driverFlags, true);

					// remove the service flag if it was set originally
					if (!(serviceFlags & VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_UPDATE_LOADER))
						BootEncObj.SetServiceConfigurationFlag (VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_UPDATE_LOADER, false);
				}
			}
			catch (...) {}
		}

		if (Is64BitOs ())
		{
			// delete files from legacy path
			if (FileExists (favoritesLegacyFile.c_str()))
			{
				MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: REMOVING %s", favoritesLegacyFile.c_str());
				ForceDeleteFile (favoritesLegacyFile.c_str());
			}

			if (FileExists (serviceLegacyPath.c_str()))
			{
				MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: REMOVING %s", serviceLegacyPath.c_str());
				ForceDeleteFile (serviceLegacyPath.c_str());
			}

			EnableWow64FsRedirection (TRUE);
		}

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
				goto end;
		}

		if (bUninstall == FALSE)
		{
			GetCurrentDirectory (MAX_PATH, szCurrentDir);	//	Save current dir since it will be changed
			SetCurrentDirectory (szInstallDir.c_str());

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
		
			// remvove legacy files that are not needed anymore
			for (int i = 0; i < sizeof (szLegacyFiles) / sizeof (szLegacyFiles[0]); i++)
			{
				StatDeleteFile (szLegacyFiles [i], TRUE);
			}

			SetCurrentDirectory(szCurrentDir);
		}
	}
	
	//	Last part of DoRegInstall()
	{
		//	Register COM servers for UAC
		if (IsOSAtLeast (WIN_VISTA))
		{
			if (!RegisterComServers ((wchar_t*)szInstallDir.c_str()))
			{
				MSILogAndShow (hInstaller, MSI_ERROR_LEVEL, GetString("COM_REG_FAILED"));
				goto end;
			}
		}
	}

	if (UnloadDriver && DoDriverInstall_Dll(hInstaller) == FALSE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: DoDriverInstall_Dll() failed");
		bOK = FALSE;
	}
	else if (SystemEncryptionUpdate && UpgradeBootLoader_Dll(hInstaller, hwndDlg) == FALSE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostInstall: UpgradeBootLoader_Dll() failed");
		bOK = FALSE;
	}

	//	Shortcuts are installed by MSI, so we skip that.

	if (!UnloadDriver)
		bRestartRequired = TRUE;

	try
	{
		bootEnc.RenameDeprecatedSystemLoaderBackup();
	}
	catch (...)	{ }

	if (bSystemRestore)
		SetSystemRestorePoint_Dll (hInstaller, TRUE);

	if (bOK)
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, GetString("INSTALL_COMPLETED"));
	}
	else
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"Post install failed");
		if (!SystemEncryptionUpdate)
		{
			bUninstall = TRUE;
			Rollback = TRUE;
			Silent = TRUE;

			DoUninstall_Dll (hInstaller, hwndDlg);

			bUninstall = FALSE;
			Rollback = FALSE;
			Silent = FALSE;

			MSILog(hInstaller, MSI_INFO_LEVEL, GetString("ROLLBACK"));
		}
		else
		{
			MSILog(hInstaller, MSI_WARNING_LEVEL, GetString("SYS_ENC_UPGRADE_FAILED"));
		}
	}

	if (bOK && !bUninstall && !bDowngrade && !bRepairMode && !bDevm)
	{
		BOOL bHibernateEnabled = FALSE, bHiberbootEnabled = FALSE;
		if (GetHibernateStatus (bHibernateEnabled, bHiberbootEnabled))
		{
			if (bHiberbootEnabled)
			{
				bPromptFastStartup = TRUE;
			}
		}

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

	if (bOK)
	{
		//	This is part of MainDialogProc, WM_CLOSE, after PostMessage (MainDlg, bOK ? TC_APPMSG_INSTALL_SUCCESS : TC_APPMSG_INSTALL_FAILURE, 0, 0);

		/* if user selected a language, use for GUI in the next run */
		if (bUserSetLanguage)
		{
			WCHAR langId[6];
			MultiByteToWideChar (CP_ACP, 0, GetPreferredLangId(), -1, langId, ARRAYSIZE (langId));
			WriteRegistryString (L"Software\\VeraCrypt", L"SetupUILanguage", langId);
		}

		if (bPromptFastStartup && AskWarnYesNo ("CONFIRM_DISABLE_FAST_STARTUP", hwndDlg) == IDYES)
		{
			WriteLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", L"HiberbootEnabled", 0);
			bRestartRequired = TRUE;
		}
		bPromptFastStartup = FALSE;

		if (bPromptReleaseNotes && AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES", hwndDlg) == IDYES)
		{
			Applink_Dll (hInstaller, "releasenotes");
		}
		bPromptReleaseNotes = FALSE;

		if (bPromptTutorial && AskYesNo ("AFTER_INSTALL_TUTORIAL", hwndDlg) == IDYES)
		{
			Applink_Dll (hInstaller, "beginnerstutorial");
		}
		bPromptTutorial = FALSE;

		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			RegSetValueEx (hkey, L"Silent", 0, REG_DWORD, (const BYTE*)(&Silent), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstall", 0, REG_DWORD, (const BYTE*)(&bUninstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDowngrade", 0, REG_DWORD, (const BYTE*)(&bDowngrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstallInProgress", 0, REG_DWORD, (const BYTE*)(&bUninstallInProgress), sizeof(BOOL));
			RegSetValueEx (hkey, L"PortableMode", 0, REG_DWORD, (const BYTE*)(&PortableMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"UnloadDriver", 0, REG_DWORD, (const BYTE*)(&UnloadDriver), sizeof(BOOL));

			RegSetValueEx (hkey, L"Rollback", 0, REG_DWORD, (const BYTE*)(&Rollback), sizeof(BOOL));
			RegSetValueEx (hkey, L"bReinstallMode", 0, REG_DWORD, (const BYTE*)(&bReinstallMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpgrade", 0, REG_DWORD, (const BYTE*)(&bUpgrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPossiblyFirstTimeInstall", 0, REG_DWORD, (const BYTE*)(&bPossiblyFirstTimeInstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDevm", 0, REG_DWORD, (const BYTE*)(&bDevm), sizeof(BOOL));
			RegSetValueEx (hkey, L"SystemEncryptionUpdate", 0, REG_DWORD, (const BYTE*)(&SystemEncryptionUpdate), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRestartRequired", 0, REG_DWORD, (const BYTE*)(&bRestartRequired), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDisableSwapFiles", 0, REG_DWORD, (const BYTE*)(&bDisableSwapFiles), sizeof(BOOL));
			RegSetValueEx (hkey, L"bSystemRestore", 0, REG_DWORD, (const BYTE*)(&bSystemRestore), sizeof(BOOL));

			RegSetValueEx (hkey, L"bPromptFastStartup", 0, REG_DWORD, (const BYTE*)(&bPromptFastStartup), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptReleaseNotes", 0, REG_DWORD, (const BYTE*)(&bPromptReleaseNotes), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptTutorial", 0, REG_DWORD, (const BYTE*)(&bPromptTutorial), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpdateRescueDisk", 0, REG_DWORD, (const BYTE*)(&bUpdateRescueDisk), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRepairMode", 0, REG_DWORD, (const BYTE*)(&bRepairMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUserSetLanguage", 0, REG_DWORD, (const BYTE*)(&bUserSetLanguage), sizeof(BOOL));

			RegCloseKey (hkey);

			uiRet = ERROR_SUCCESS;
		}
		else 
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PostInstall: Could not write to registry");
		}
		
		// delete entry of EXE installation if it exists
		RegDeleteKeyExW (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", KEY_WOW64_32KEY, 0);
	}
end:

	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_PostInstall");
	return uiRet;
}

/* 
 * Same as Setup.c, function DoUninstall(), but 
 * without the actual uninstall, it only prepares the system 
 * before the uninstall (before DoFilesInstall).
 * It runs as a Deferred CA.
 */
EXTERN_C UINT STDAPICALLTYPE VC_CustomAction_PreUninstall(MSIHANDLE hInstaller)
{
	HWND			hwndDlg			= NULL;
	std::wstring    szValueBuf		= L"";
	DWORD           cchValueBuf		= 0;
	UINT            uiStat			= 0;
	HKEY			hkey			= 0;
	DWORD			dw				= 0;
	BootEncryption	bootEnc(NULL);
	std::wstring	szInstallDir	= L"";
	UINT			uiRet           = ERROR_INSTALL_FAILURE;
	BOOL			bTempSkipSysRestore = FALSE;
	BOOL			bOK				= TRUE;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_PreUninstall");

	//  Get UILevel to see whether we're being installed silently or not.
	//	Also get INSTALLDIR to see where we're being installed.
	//	Since this is a Deferred CA, they are to be setup in its CustomActionData.
	uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreUninstall: CustomActionData = '%s'", szValueBuf.c_str());
			
			std::vector<std::wstring> szTokens;
			Tokenize(szValueBuf.c_str(), szTokens);

			for (size_t i = 0; i < szTokens.size(); i++)
			{
				std::wstring szToken = szTokens[i];

				if (wcsncmp(szToken.c_str(), L"UILEVEL=", wcslen(L"UILEVEL=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						std::wstring uiLevel = szToken.substr(index0 + 1);
						Silent = (stoi(uiLevel) <= 3);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: UILEVEL = '%s', bSilent = '%d'", uiLevel.c_str(), Silent);
					}
				}
				else if (wcsncmp(szToken.c_str(), L"INSTALLDIR=", wcslen(L"INSTALLDIR=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						szInstallDir = szToken.substr(index0 + 1);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: INSTALLDIR = '%s'", szInstallDir.c_str());
					}
				}
				else if (wcsncmp(szToken.c_str(), L"REINSTALL=", wcslen(L"REINSTALL=")) == 0)
				{
					size_t index0 = szToken.find_first_of(L"=");
					if (index0 != std::wstring::npos)
					{
						std::wstring szReinstall = szToken.substr(index0 + 1);
						bRepairMode = (wcslen(szReinstall.c_str()) != 0);

						MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PreInstall: REINSTALL = '%s', bRepairMode = '%s'", szReinstall.c_str(), bRepairMode ? L"TRUE" : L"FALSE");
					}
				}
			}
		}
	}

	//	Get this MSI Installer HWND.
	//	There cannot be 2 MSIs or more running at the same time, so we're sure we'll get ours.
	//	This is only possible in case of non silent install.
	hwndDlg = FindWindow(L"MsiDialogCloseClass", NULL);
	if (!hwndDlg && !Silent)
	{
        MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreUninstall: MsiDialogCloseClass not found");
		goto end;
    }

	/*	Start actual work */

	bUninstall = TRUE;
	if (!VC_CustomAction_Init(hInstaller, szInstallDir.c_str()))
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreUninstall: VC_CustomAction_Init() failed");
		goto end;
	}
	atexit(VC_CustomAction_Cleanup);
	bootEnc.SetParentWindow(hwndDlg);

	if (DoDriverUnload_Dll(hInstaller, hwndDlg) == FALSE)
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreUninstall: DoDriverUnload_Dll() failed");
		bOK = FALSE;
		bTempSkipSysRestore = TRUE;		// Volumes are possibly mounted; defer System Restore point creation for this uninstall attempt.
	}
	else
	{
		if (!Rollback && bSystemRestore && !bTempSkipSysRestore)
			SetSystemRestorePoint_Dll (hInstaller, FALSE);

		if (DoServiceUninstall_Dll (hInstaller, hwndDlg, L"veracrypt") == FALSE)
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreUninstall: DoServiceUninstall_Dll(veracrypt) failed");
			bOK = FALSE;
		}
		//	DoRegUninstall_Dll removes regkeys that are not linked to MSI
		//	We need to do this in PreUninstall instead of in PostUninstall so that UnregisterComServers works,
		//	because in PostUninstall the "VeraCrypt COMReg.exe" is removed and UnregisterComServers will fail.
		else if (DoRegUninstall_Dll (hInstaller, FALSE) == FALSE)
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PreUninstall: DoRegUninstall_Dll() failed");
			bOK = FALSE;
		}
	}

	if (bOK)
	{
		//	uiRet = MsiSetProperty(hInstaller, TEXT("ISREBOOTREQUIRED"), TEXT("1"));
		//		Cannot do this because this is a Deferred CA (we need Deferred so that it runs with admin privileges).
		//		MsiGetProperty and MsiSetProperty properties cannot be used for deferred InstallScript custom actions,
		//		which do not have access to the active .msi database and do not recognize any Windows Installer properties. 
		//		They can access only the information that has been written into the execution script (CustomActionData).
		//		Therefore, we set the values in RegKeys that are volatile.
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			RegSetValueEx (hkey, L"Silent", 0, REG_DWORD, (const BYTE*)(&Silent), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstall", 0, REG_DWORD, (const BYTE*)(&bUninstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDowngrade", 0, REG_DWORD, (const BYTE*)(&bDowngrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstallInProgress", 0, REG_DWORD, (const BYTE*)(&bUninstallInProgress), sizeof(BOOL));
			RegSetValueEx (hkey, L"PortableMode", 0, REG_DWORD, (const BYTE*)(&PortableMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"UnloadDriver", 0, REG_DWORD, (const BYTE*)(&UnloadDriver), sizeof(BOOL));

			RegSetValueEx (hkey, L"Rollback", 0, REG_DWORD, (const BYTE*)(&Rollback), sizeof(BOOL));
			RegSetValueEx (hkey, L"bReinstallMode", 0, REG_DWORD, (const BYTE*)(&bReinstallMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpgrade", 0, REG_DWORD, (const BYTE*)(&bUpgrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPossiblyFirstTimeInstall", 0, REG_DWORD, (const BYTE*)(&bPossiblyFirstTimeInstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDevm", 0, REG_DWORD, (const BYTE*)(&bDevm), sizeof(BOOL));
			RegSetValueEx (hkey, L"SystemEncryptionUpdate", 0, REG_DWORD, (const BYTE*)(&SystemEncryptionUpdate), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRestartRequired", 0, REG_DWORD, (const BYTE*)(&bRestartRequired), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDisableSwapFiles", 0, REG_DWORD, (const BYTE*)(&bDisableSwapFiles), sizeof(BOOL));
			RegSetValueEx (hkey, L"bSystemRestore", 0, REG_DWORD, (const BYTE*)(&bSystemRestore), sizeof(BOOL));

			RegSetValueEx (hkey, L"bPromptFastStartup", 0, REG_DWORD, (const BYTE*)(&bPromptFastStartup), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptReleaseNotes", 0, REG_DWORD, (const BYTE*)(&bPromptReleaseNotes), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptTutorial", 0, REG_DWORD, (const BYTE*)(&bPromptTutorial), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpdateRescueDisk", 0, REG_DWORD, (const BYTE*)(&bUpdateRescueDisk), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRepairMode", 0, REG_DWORD, (const BYTE*)(&bRepairMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUserSetLanguage", 0, REG_DWORD, (const BYTE*)(&bUserSetLanguage), sizeof(BOOL));

			RegCloseKey (hkey);

			uiRet = ERROR_SUCCESS;
		}
		else 
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PreUninstall: Could not write to registry");
		}
	}

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_PreUninstall");
	return uiRet;
}

/* 
 * Same as Setup.c, function DoUninstall(), but 
 * without the actual installation, it only performs 
 * post install operations (after DoFilesInstall and last parts 
 * of DoFilesInstall / DoRegUninstall).
 * It also sets regkey accordingly.
 * It runs as a Deferred CA.
 */
EXTERN_C UINT STDAPICALLTYPE VC_CustomAction_PostUninstall(MSIHANDLE hInstaller)
{
	HWND			hwndDlg			= NULL;
	std::wstring    szValueBuf		= L"";
	DWORD           cchValueBuf		= 0;
	UINT            uiStat			= 0;
	HKEY			hkey			= 0;
	DWORD			dw				= 0;
	BootEncryption	bootEnc(NULL);
	std::wstring	szInstallDir	= L"";
	UINT			uiRet           = ERROR_INSTALL_FAILURE;
	BOOL			bTempSkipSysRestore = FALSE;
	BOOL			bOK				= TRUE;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_PostUninstall");

	//  Get INSTALLDIR to see where we're being installed.
	uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("CustomActionData"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PostUninstall: CustomActionData = '%s'", szValueBuf.c_str());
			if (wcsncmp(szValueBuf.c_str(), L"INSTALLDIR=", wcslen(L"INSTALLDIR=")) == 0)
			{
				size_t index0 = szValueBuf.find_first_of(L"=");
				if (index0 != std::wstring::npos)
				{
					szInstallDir = szValueBuf.substr(index0 + 1);
					MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_PostUninstall: INSTALLDIR = '%s'", szInstallDir.c_str());
				}
			}
		}
	}

	//	Read RegKeys previously setup by PreInstall
	if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		DWORD cbValue = sizeof(DWORD);
		DWORD dwValue = 0;

		RegQueryValueEx (hkey, L"Silent", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Silent = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDowngrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDowngrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstallInProgress", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstallInProgress = (dwValue == 1);
		RegQueryValueEx (hkey, L"PortableMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		PortableMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"UnloadDriver", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		UnloadDriver = (dwValue == 1);

		RegQueryValueEx (hkey, L"Rollback", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Rollback = (dwValue == 1);
		RegQueryValueEx (hkey, L"bReinstallMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bReinstallMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpgrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpgrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPossiblyFirstTimeInstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPossiblyFirstTimeInstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDevm", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDevm = (dwValue == 1);
		RegQueryValueEx (hkey, L"SystemEncryptionUpdate", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		SystemEncryptionUpdate = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRestartRequired", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRestartRequired = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDisableSwapFiles", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDisableSwapFiles = (dwValue == 1);
		RegQueryValueEx (hkey, L"bSystemRestore", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bSystemRestore = (dwValue == 1);

		RegQueryValueEx (hkey, L"bPromptFastStartup", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptFastStartup = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptReleaseNotes", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptReleaseNotes = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptTutorial", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptTutorial = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpdateRescueDisk", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpdateRescueDisk = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRepairMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRepairMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUserSetLanguage", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUserSetLanguage = (dwValue == 1);

		RegCloseKey (hkey);
	}
	else 
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PostUninstall: Could not read from registry");
		goto end;
	}

	//	Get this MSI Installer HWND.
	//	There cannot be 2 MSIs or more running at the same time, so we're sure we'll get ours.
	//	This is only possible in case of non silent install.
	hwndDlg = FindWindow(L"MsiDialogCloseClass", NULL);
	if (!hwndDlg && !Silent)
	{
        MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: MsiDialogCloseClass not found");
		goto end;
    }

	/*	Start actual work */

	bUninstall = TRUE;
	if (!VC_CustomAction_Init(hInstaller, szInstallDir.c_str()))
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: VC_CustomAction_Init() failed");
		goto end;
	}
	atexit(VC_CustomAction_Cleanup);
	bootEnc.SetParentWindow(hwndDlg);

	if (!DoApplicationDataUninstall_Dll (hInstaller))
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: DoApplicationDataUninstall_Dll() failed");
		bOK = FALSE;
	}
	else
	{
		// Deprecated service
		DoServiceUninstall_Dll (hInstaller, hwndDlg, L"VeraCryptService");
	}

	//	Last part of DoFilesInstall()
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
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: REMOVING %s", favoritesFile.c_str());
			ForceDeleteFile (favoritesFile.c_str());
		}

		if (FileExists (servicePath.c_str()))
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: REMOVING %s", servicePath.c_str());
			ForceDeleteFile (servicePath.c_str());
		}

		if (Is64BitOs ())
		{
			if (FileExists (favoritesLegacyFile.c_str()))
			{
				MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: REMOVING %s", favoritesLegacyFile.c_str());
				ForceDeleteFile (favoritesLegacyFile.c_str());
			}

			if (FileExists (serviceLegacyPath.c_str()))
			{
				MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_PostUninstall: REMOVING %s", serviceLegacyPath.c_str());
				ForceDeleteFile (serviceLegacyPath.c_str());
			}

			EnableWow64FsRedirection (TRUE);
		}
	}

	if (bSystemRestore && !bTempSkipSysRestore)
		SetSystemRestorePoint_Dll (hInstaller, TRUE);

	if (bOK)
	{
		//	uiRet = MsiSetProperty(hInstaller, TEXT("ISREBOOTREQUIRED"), TEXT("1"));
		//		Cannot do this because this is a Deferred CA (we need Deferred so that it runs with admin privileges).
		//		MsiGetProperty and MsiSetProperty properties cannot be used for deferred InstallScript custom actions,
		//		which do not have access to the active .msi database and do not recognize any Windows Installer properties. 
		//		They can access only the information that has been written into the execution script (CustomActionData).
		//		Therefore, we set the values in RegKeys that are volatile.
		if (RegCreateKeyEx (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hkey, &dw) == ERROR_SUCCESS)
		{
			RegSetValueEx (hkey, L"Silent", 0, REG_DWORD, (const BYTE*)(&Silent), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstall", 0, REG_DWORD, (const BYTE*)(&bUninstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDowngrade", 0, REG_DWORD, (const BYTE*)(&bDowngrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUninstallInProgress", 0, REG_DWORD, (const BYTE*)(&bUninstallInProgress), sizeof(BOOL));
			RegSetValueEx (hkey, L"PortableMode", 0, REG_DWORD, (const BYTE*)(&PortableMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"UnloadDriver", 0, REG_DWORD, (const BYTE*)(&UnloadDriver), sizeof(BOOL));

			RegSetValueEx (hkey, L"Rollback", 0, REG_DWORD, (const BYTE*)(&Rollback), sizeof(BOOL));
			RegSetValueEx (hkey, L"bReinstallMode", 0, REG_DWORD, (const BYTE*)(&bReinstallMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpgrade", 0, REG_DWORD, (const BYTE*)(&bUpgrade), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPossiblyFirstTimeInstall", 0, REG_DWORD, (const BYTE*)(&bPossiblyFirstTimeInstall), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDevm", 0, REG_DWORD, (const BYTE*)(&bDevm), sizeof(BOOL));
			RegSetValueEx (hkey, L"SystemEncryptionUpdate", 0, REG_DWORD, (const BYTE*)(&SystemEncryptionUpdate), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRestartRequired", 0, REG_DWORD, (const BYTE*)(&bRestartRequired), sizeof(BOOL));
			RegSetValueEx (hkey, L"bDisableSwapFiles", 0, REG_DWORD, (const BYTE*)(&bDisableSwapFiles), sizeof(BOOL));
			RegSetValueEx (hkey, L"bSystemRestore", 0, REG_DWORD, (const BYTE*)(&bSystemRestore), sizeof(BOOL));

			RegSetValueEx (hkey, L"bPromptFastStartup", 0, REG_DWORD, (const BYTE*)(&bPromptFastStartup), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptReleaseNotes", 0, REG_DWORD, (const BYTE*)(&bPromptReleaseNotes), sizeof(BOOL));
			RegSetValueEx (hkey, L"bPromptTutorial", 0, REG_DWORD, (const BYTE*)(&bPromptTutorial), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUpdateRescueDisk", 0, REG_DWORD, (const BYTE*)(&bUpdateRescueDisk), sizeof(BOOL));
			RegSetValueEx (hkey, L"bRepairMode", 0, REG_DWORD, (const BYTE*)(&bRepairMode), sizeof(BOOL));
			RegSetValueEx (hkey, L"bUserSetLanguage", 0, REG_DWORD, (const BYTE*)(&bUserSetLanguage), sizeof(BOOL));

			RegCloseKey (hkey);

			uiRet = ERROR_SUCCESS;
		}
		else 
		{
			MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_PostUninstall: Could not write to registry");
		}
	}
	else
		bUninstallInProgress = FALSE;

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_PostUninstall");
	return uiRet;
}

/* Runs as a Commit CA : therefore, we can get / set properties that are defined in WiX.
 * It sets ISREBOOTREQUIRED Wix Property accordingly and refreshes extensions list
 * if REGISTERVCFILEEXT is set.
 */
EXTERN_C UINT STDAPICALLTYPE VC_CustomAction_DoChecks(MSIHANDLE hInstaller)
{
	HWND			hwndDlg			= NULL;
	std::wstring    szValueBuf		= L"";
	DWORD           cchValueBuf		= 0;
	UINT            uiStat			= 0;
	HKEY			hkey			= 0;
	std::wstring	szInstallDir	= L"";
	BOOL			bRefreshExts	= FALSE;
	BOOL			bDisableReboot	= FALSE;
	UINT			uiRet           = ERROR_INSTALL_FAILURE;

	MSILog(hInstaller, MSI_INFO_LEVEL, L"Begin VC_CustomAction_DoChecks");

	//  Get WIXUI_INSTALLDIR to see where we're being installed
	uiStat = MsiGetProperty(hInstaller, TEXT("APPLICATIONROOTFOLDER"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("APPLICATIONROOTFOLDER"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: APPLICATIONROOTFOLDER = '%s'", szValueBuf.c_str());
			szInstallDir = szValueBuf;
		}
	}

	//  Get REGISTERVCFILEEXT to see whether we should refresh extensions list.
	szValueBuf.clear();
	cchValueBuf = 0;
	uiStat = MsiGetProperty(hInstaller, TEXT("REGISTERVCFILEEXT"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("REGISTERVCFILEEXT"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: REGISTERVCFILEEXT = '%s'", szValueBuf.c_str());
			bRefreshExts = (szValueBuf[0] == L'1');
		}
	}

	//  Get REBOOT to see whether it specified "ReallySuppress" which means no automatic reboot
	szValueBuf.clear();
	cchValueBuf = 0;
	uiStat = MsiGetProperty(hInstaller, TEXT("REBOOT"), (LPWSTR)TEXT(""), &cchValueBuf);
	if (ERROR_MORE_DATA == uiStat)
	{
		++cchValueBuf; // add 1 for null termination
		szValueBuf.resize(cchValueBuf);
		uiStat = MsiGetProperty(hInstaller, TEXT("REBOOT"), &szValueBuf[0], &cchValueBuf);
		if ((ERROR_SUCCESS == uiStat))
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: REBOOT = '%s'", szValueBuf.c_str());
			bDisableReboot = (szValueBuf[0] == L'R' || szValueBuf[0] == L'r');
		}
	}

	//	Read RegKeys previously setup by Pre/Post-Install
	if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt\\Values", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		DWORD cbValue = sizeof(DWORD);
		DWORD dwValue = 0;
		
		RegQueryValueEx (hkey, L"Silent", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Silent = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDowngrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDowngrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUninstallInProgress", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUninstallInProgress = (dwValue == 1);
		RegQueryValueEx (hkey, L"PortableMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		PortableMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"UnloadDriver", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		UnloadDriver = (dwValue == 1);

		RegQueryValueEx (hkey, L"Rollback", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		Rollback = (dwValue == 1);
		RegQueryValueEx (hkey, L"bReinstallMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bReinstallMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpgrade", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpgrade = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPossiblyFirstTimeInstall", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPossiblyFirstTimeInstall = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDevm", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDevm = (dwValue == 1);
		RegQueryValueEx (hkey, L"SystemEncryptionUpdate", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		SystemEncryptionUpdate = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRestartRequired", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRestartRequired = (dwValue == 1);
		RegQueryValueEx (hkey, L"bDisableSwapFiles", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bDisableSwapFiles = (dwValue == 1);
		RegQueryValueEx (hkey, L"bSystemRestore", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bSystemRestore = (dwValue == 1);

		RegQueryValueEx (hkey, L"bPromptFastStartup", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptFastStartup = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptReleaseNotes", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptReleaseNotes = (dwValue == 1);
		RegQueryValueEx (hkey, L"bPromptTutorial", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bPromptTutorial = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUpdateRescueDisk", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUpdateRescueDisk = (dwValue == 1);
		RegQueryValueEx (hkey, L"bRepairMode", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bRepairMode = (dwValue == 1);
		RegQueryValueEx (hkey, L"bUserSetLanguage", NULL, NULL, (LPBYTE) &dwValue, &cbValue);
		bUserSetLanguage = (dwValue == 1);

		RegCloseKey (hkey);
	}
	else 
	{
		MSILog(hInstaller, MSI_ERROR_LEVEL, L"End VC_CustomAction_DoChecks: Could not read from registry");
		goto end;
	}

	//	Get this MSI Installer HWND.
	//	There cannot be 2 MSIs or more running at the same time, so we're sure we'll get ours.
	//	This is only possible in case of non silent install.
	hwndDlg = FindWindow(L"MsiDialogCloseClass", NULL);
	if (!hwndDlg && !Silent)
	{
        MSILog(hInstaller, MSI_ERROR_LEVEL, L"VC_CustomAction_DoChecks: MsiDialogCloseClass not found");
		goto end;
    }

	/*	Start actual work */

	if (bRefreshExts)
	{
		MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: Will refresh file extensions");
		SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	}

	//	Check if reboot was required by the pre/post-install and set Wix property ISREBOOTREQUIRED accordingly.
	if (bRestartRequired)
	{		
		if (bDisableReboot)
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: reboot is required but it is disabled because \"REBOOT\" specifies ReallySuppress");
		}
		else
		{
			MSILog(hInstaller, MSI_INFO_LEVEL, L"VC_CustomAction_DoChecks: reboot is required");
			uiRet = MsiSetProperty(hInstaller, L"ISREBOOTREQUIRED", L"1");
		}
	}
	else 
	{
		uiRet = ERROR_SUCCESS;
	}

	//	Remove volatile regkeys
	SHDeleteKey(HKEY_LOCAL_MACHINE, L"Software\\.VeraCrypt");

end:
	MSILog(hInstaller, MSI_INFO_LEVEL, L"End VC_CustomAction_DoChecks");
	return uiRet;
}

BOOL
WINAPI
DllMain(
    HMODULE hInstDLL,
    DWORD dwReason,
    LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    /* Save the instance handle for later, 
	 * especially for loading embedded Language.xml file 
	 * in Dlgcode.c, MapResource() function.
	 */
	hInst = hInstDLL;

    return TRUE;
}