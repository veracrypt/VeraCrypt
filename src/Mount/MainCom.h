/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_MAIN_COM
#define TC_HEADER_MAIN_COM

#include <windows.h>

#ifdef __cplusplus

#include "MainCom_h.h"
ITrueCryptMainCom *GetElevatedInstance (HWND parent);

extern "C" {
#endif

BOOL ComServerMain ();
int UacBackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, wchar_t *lpszVolume);
int UacRestoreVolumeHeader (HWND hwndDlg, wchar_t *lpszVolume);
int UacChangePwd (wchar_t *lpszVolume, Password *oldPassword, int old_pkcs5, int old_pim, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg);

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_MAIN_COM
