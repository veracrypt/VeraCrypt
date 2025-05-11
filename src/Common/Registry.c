/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Tcdefs.h"
#include "Registry.h"
#include <Strsafe.h>

BOOL ReadLocalMachineRegistryDword (wchar_t *subKey, wchar_t *name, DWORD *value)
{
	HKEY hkey = 0;
	DWORD size = sizeof (*value);
	DWORD type;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return FALSE;

	if (RegQueryValueEx (hkey, name, NULL, &type, (BYTE *) value, &size) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}

	RegCloseKey (hkey);
	return type == REG_DWORD;
}

BOOL ReadLocalMachineRegistryMultiString (wchar_t *subKey, wchar_t *name, wchar_t *value, DWORD *size)
{
	HKEY hkey = 0;
	DWORD type;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return FALSE;

	if (RegQueryValueEx (hkey, name, NULL, &type, (BYTE *) value, size) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}

	RegCloseKey (hkey);
	return type == REG_MULTI_SZ;
}

BOOL ReadLocalMachineRegistryString (const wchar_t *subKey, wchar_t *name, wchar_t *str, DWORD *size)
{
	HKEY hkey = 0;
	DWORD type;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return FALSE;

	if (RegQueryValueEx (hkey, name, NULL, &type, (BYTE *) str, size) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}

	RegCloseKey (hkey);
	return type == REG_SZ;
}

BOOL ReadLocalMachineRegistryStringNonReflected (const wchar_t *subKey, wchar_t *name, wchar_t *str, DWORD *size, BOOL b32bitApp)
{
	HKEY hkey = 0;
	DWORD type;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | (b32bitApp? KEY_WOW64_32KEY: KEY_WOW64_64KEY), &hkey) != ERROR_SUCCESS)
		return FALSE;

	if (RegQueryValueEx (hkey, name, NULL, &type, (BYTE *) str, size) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}

	RegCloseKey (hkey);
	return type == REG_SZ;
}

int ReadRegistryInt (wchar_t *subKey, wchar_t *name, int defaultValue)
{
	HKEY hkey = 0;
	DWORD value, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey,
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return defaultValue;

	if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
		value = defaultValue;

	RegCloseKey (hkey);
	return value;
}

wchar_t *ReadRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *defaultValue, wchar_t *str, int maxLen)
{
	HKEY hkey = 0;
	wchar_t value[MAX_PATH*4];
	DWORD size = sizeof (value);

   str[maxLen/2-1] = 0;
	StringCbCopyW (str, maxLen, defaultValue);

	ZeroMemory (value, sizeof value);
	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey,
		0, KEY_READ, &hkey) == ERROR_SUCCESS)
		if (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) value,	&size) == ERROR_SUCCESS)
			StringCbCopyW (str, maxLen,value);

	if (hkey)
		RegCloseKey (hkey);
	return str;
}

DWORD ReadRegistryBytes (wchar_t *path, wchar_t *name, char *value, int maxLen)
{
	HKEY hkey = 0;
	DWORD size = maxLen;
	BOOL success = FALSE;

	if (RegOpenKeyEx (HKEY_CURRENT_USER, path, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return 0;

	success = (RegQueryValueEx (hkey, name, 0,	0, (LPBYTE) value,	&size) == ERROR_SUCCESS);
	RegCloseKey (hkey);

	return success ? size : 0;
}

void WriteRegistryInt (wchar_t *subKey, wchar_t *name, int value)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_DWORD, (BYTE *) &value, sizeof value);
	RegCloseKey (hkey);
}

BOOL WriteLocalMachineRegistryDword (wchar_t *subKey, wchar_t *name, DWORD value)
{
	HKEY hkey = 0;
	DWORD disp;
	LONG status;

	if ((status = RegCreateKeyEx (HKEY_LOCAL_MACHINE, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp)) != ERROR_SUCCESS)
	{
		SetLastError (status);
		return FALSE;
	}

	if ((status = RegSetValueEx (hkey, name, 0, REG_DWORD, (BYTE *) &value, sizeof value)) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		SetLastError (status);
		return FALSE;
	}

	RegCloseKey (hkey);
	return TRUE;
}

BOOL WriteLocalMachineRegistryMultiString (wchar_t *subKey, wchar_t *name, wchar_t *multiString, DWORD size)
{
	HKEY hkey = 0;
	DWORD disp;
	LONG status;

	if ((status = RegCreateKeyEx (HKEY_LOCAL_MACHINE, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp)) != ERROR_SUCCESS)
	{
		SetLastError (status);
		return FALSE;
	}

	if ((status = RegSetValueEx (hkey, name, 0, REG_MULTI_SZ, (BYTE *) multiString, size)) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		SetLastError (status);
		return FALSE;
	}

	RegCloseKey (hkey);
	return TRUE;
}

BOOL WriteLocalMachineRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *str, BOOL expandable)
{
	HKEY hkey = 0;
	DWORD disp;
	LONG status;

	if ((status = RegCreateKeyEx (HKEY_LOCAL_MACHINE, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp)) != ERROR_SUCCESS)
	{
		SetLastError (status);
		return FALSE;
	}

	if ((status = RegSetValueEx (hkey, name, 0, expandable ? REG_EXPAND_SZ : REG_SZ, (BYTE *) str, (DWORD) (wcslen (str) + 1) * sizeof (wchar_t))) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		SetLastError (status);
		return FALSE;
	}

	RegCloseKey (hkey);
	return TRUE;
}

void WriteRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *str)
{
	HKEY hkey = 0;
	DWORD disp;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, subKey,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return;

	RegSetValueEx (hkey, name, 0, REG_SZ, (BYTE *) str, (DWORD) (wcslen (str) + 1) * sizeof (wchar_t));
	RegCloseKey (hkey);
}

BOOL WriteRegistryBytes (wchar_t *path, wchar_t *name, char *str, DWORD size)
{
	HKEY hkey = 0;
	DWORD disp;
	BOOL res;

	if (RegCreateKeyEx (HKEY_CURRENT_USER, path,
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, &disp) != ERROR_SUCCESS)
		return FALSE;

	res = RegSetValueEx (hkey, name, 0, REG_BINARY, (BYTE *) str, size);
	RegCloseKey (hkey);
	return res == ERROR_SUCCESS;
}

BOOL DeleteLocalMachineRegistryKey (wchar_t *parentKey, wchar_t *subKeyToDelete)
{
	LONG status;
	HKEY hkey = 0;

	if ((status = RegOpenKeyEx (HKEY_LOCAL_MACHINE, parentKey, 0, KEY_WRITE, &hkey)) != ERROR_SUCCESS)
	{
		SetLastError (status);
		return FALSE;
	}

	if ((status = RegDeleteKey (hkey, subKeyToDelete)) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		SetLastError (status);
		return FALSE;
	}

	RegCloseKey (hkey);
	return TRUE;
}

void DeleteRegistryValue (wchar_t *subKey, wchar_t *name)
{
	HKEY hkey = 0;

	if (RegOpenKeyEx (HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hkey) != ERROR_SUCCESS)
		return;

	RegDeleteValue (hkey, name);
	RegCloseKey (hkey);
}


void GetStartupRegKeyName (wchar_t *regk, size_t cbRegk)
{
	// The string is split in order to prevent some antivirus packages from falsely reporting
	// VeraCrypt.exe to contain a possible Trojan horse because of this string (heuristic scan).
	StringCbPrintfW (regk, cbRegk,L"%s%s", L"Software\\Microsoft\\Windows\\Curren", L"tVersion\\Run");
}

void GetRestorePointRegKeyName (wchar_t *regk, size_t cbRegk)
{
	// The string is split in order to prevent some antivirus packages from falsely reporting
	// VeraCrypt.exe to contain a possible Trojan horse because of this string (heuristic scan).
	StringCbPrintfW (regk, cbRegk,L"%s%s%s%s", L"Software\\Microsoft\\Windows", L" NT\\Curren", L"tVersion\\Sy", L"stemRestore");
}