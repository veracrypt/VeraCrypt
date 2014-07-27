/*
 Copyright (c) 2007-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
void UacAnalyzeKernelMiniDump (HWND hwndDlg);
int UacBackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume);
int UacRestoreVolumeHeader (HWND hwndDlg, char *lpszVolume);
int UacChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, int wipePassCount, HWND hwndDlg);

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_MAIN_COM
