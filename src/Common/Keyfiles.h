/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef KEYFILES_H
#define	KEYFILES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "Common.h"

#define KEYFILE_POOL_SIZE	64
#define	KEYFILE_MAX_READ_LEN	(1024*1024)

typedef struct KeyFileStruct
{
	wchar_t FileName[MAX_PATH + 1];
	struct KeyFileStruct *Next;
} KeyFile;

typedef struct
{
	wchar_t VolumeFileName[MAX_PATH + 1];
	BOOL EnableKeyFiles;
	KeyFile *FirstKeyFile;
} KeyFilesDlgParam;

KeyFile *KeyFileAdd (KeyFile *firstKeyFile, KeyFile *keyFile);
void KeyFileRemoveAll (KeyFile **firstKeyFile);
KeyFile *KeyFileClone (KeyFile *keyFile);
void KeyFileCloneAll (KeyFile *firstKeyFile, KeyFile **outputKeyFile);
BOOL KeyFilesApply (HWND hwndDlg, Password *password, KeyFile *firstKeyFilem, const wchar_t* volumeFileName);

BOOL CALLBACK KeyFilesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL KeyfilesPopupMenu (HWND hwndDlg, POINT popupPosition, KeyFilesDlgParam *dialogParam);

extern BOOL HiddenFilesPresentInKeyfilePath;

#ifdef __cplusplus
}
#endif

#endif	/* #ifndef KEYFILES_H */
