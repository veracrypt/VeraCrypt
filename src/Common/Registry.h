/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifdef  __cplusplus
extern "C" {
#endif

BOOL ReadLocalMachineRegistryDword (char *subKey, char *name, DWORD *value);
BOOL ReadLocalMachineRegistryMultiString (char *subKey, char *name, char *value, DWORD *size);
BOOL ReadLocalMachineRegistryString (const char *subKey, char *name, char *value, DWORD *size);
BOOL ReadLocalMachineRegistryStringNonReflected (const char *subKey, char *name, char *str, DWORD *size, BOOL b32bitApp);
int ReadRegistryInt (char *subKey, char *name, int defaultValue);
char *ReadRegistryString (char *subKey, char *name, char *defaultValue, char *str, int maxLen);
DWORD ReadRegistryBytes (char *path, char *name, char *value, int maxLen);
void WriteRegistryInt (char *subKey, char *name, int value);
BOOL WriteLocalMachineRegistryDword (char *subKey, char *name, DWORD value);
BOOL WriteLocalMachineRegistryDwordW (WCHAR *subKey, WCHAR *name, DWORD value);
BOOL WriteLocalMachineRegistryMultiString (char *subKey, char *name, char *multiString, DWORD size);
BOOL WriteLocalMachineRegistryString (char *subKey, char *name, char *str, BOOL expandable);
void WriteRegistryString (char *subKey, char *name, char *str);
BOOL WriteRegistryBytes (char *path, char *name, char *str, DWORD size);
BOOL DeleteLocalMachineRegistryKey (char *parentKey, char *subKeyToDelete);
void DeleteRegistryValue (char *subKey, char *name);
void GetStartupRegKeyName (char *regk, size_t cbRegk);
void GetRestorePointRegKeyName (char *regk, size_t cbRegk);

#ifdef  __cplusplus
}
#endif
