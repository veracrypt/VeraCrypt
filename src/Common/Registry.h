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

#ifdef  __cplusplus
extern "C" {
#endif

BOOL ReadLocalMachineRegistryDword (wchar_t *subKey, wchar_t *name, DWORD *value);
BOOL ReadLocalMachineRegistryMultiString (wchar_t *subKey, wchar_t *name, wchar_t *value, DWORD *size);
BOOL ReadLocalMachineRegistryString (const wchar_t *subKey, wchar_t *name, wchar_t *value, DWORD *size);
BOOL ReadLocalMachineRegistryStringNonReflected (const wchar_t *subKey, wchar_t *name, wchar_t *str, DWORD *size, BOOL b32bitApp);
int ReadRegistryInt (wchar_t *subKey, wchar_t *name, int defaultValue);
wchar_t *ReadRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *defaultValue, wchar_t *str, int maxLen);
DWORD ReadRegistryBytes (wchar_t *path, wchar_t *name, char *value, int maxLen);
void WriteRegistryInt (wchar_t *subKey, wchar_t *name, int value);
BOOL WriteLocalMachineRegistryDword (wchar_t *subKey, wchar_t *name, DWORD value);
BOOL WriteLocalMachineRegistryMultiString (wchar_t *subKey, wchar_t *name, wchar_t *multiString, DWORD size);
BOOL WriteLocalMachineRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *str, BOOL expandable);
void WriteRegistryString (wchar_t *subKey, wchar_t *name, wchar_t *str);
BOOL WriteRegistryBytes (wchar_t *path, wchar_t *name, char *str, DWORD size);
BOOL DeleteLocalMachineRegistryKey (wchar_t *parentKey, wchar_t *subKeyToDelete);
void DeleteRegistryValue (wchar_t *subKey, wchar_t *name);
void GetStartupRegKeyName (wchar_t *regk, size_t cbRegk);
void GetRestorePointRegKeyName (wchar_t *regk, size_t cbRegk);

#ifdef  __cplusplus
}
#endif
