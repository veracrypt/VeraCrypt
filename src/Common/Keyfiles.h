/*
 Copyright (c) 2005 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
	char FileName[MAX_PATH + 1];
	struct KeyFileStruct *Next;
} KeyFile;

typedef struct
{
	BOOL EnableKeyFiles;
	KeyFile *FirstKeyFile;
} KeyFilesDlgParam;

KeyFile *KeyFileAdd (KeyFile *firstKeyFile, KeyFile *keyFile);
void KeyFileRemoveAll (KeyFile **firstKeyFile);
KeyFile *KeyFileClone (KeyFile *keyFile);
KeyFile *KeyFileCloneAll (KeyFile *firstKeyFile);
BOOL KeyFilesApply (Password *password, KeyFile *firstKeyFile);

BOOL CALLBACK KeyFilesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL KeyfilesPopupMenu (HWND hwndDlg, POINT popupPosition, KeyFilesDlgParam *dialogParam);

extern BOOL HiddenFilesPresentInKeyfilePath;

#ifdef __cplusplus
}
#endif

#endif	/* #ifndef KEYFILES_H */ 
