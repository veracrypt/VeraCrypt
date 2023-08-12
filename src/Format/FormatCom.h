/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_FORMAT_COM
#define TC_HEADER_FORMAT_COM

#include <windows.h>

#ifdef __cplusplus

#include "FormatCom_h.h"
ITrueCryptFormatCom *GetElevatedInstance (HWND parent);

extern "C" {
#endif

BOOL ComServerFormat ();
int UacFormatNtfs (HWND hWnd, int driveNo, int clusterSize);
int UacFormatFs (HWND hWnd, int driveNo, int clusterSize, int fsType);
int UacAnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters);
int UacFormatVolume (char *cvolumePath , BOOL bDevice , unsigned __int64 size , unsigned __int64 hiddenVolHostSize , Password *password , int cipher , int pkcs5 , BOOL quickFormat, BOOL sparseFileSwitch, int fileSystem , int clusterSize, HWND hwndDlg , BOOL hiddenVol , int *realClusterSize);
BOOL UacUpdateProgressBar (__int64 nSecNo, BOOL *bVolTransformThreadCancel);
BOOL UacWriteLocalMachineRegistryDword (HWND hwndDlg, wchar_t *keyPath, wchar_t *valueName, DWORD value);
DWORD UacFastFileCreation (HWND hWnd, wchar_t* filePath, __int64 fileSize);

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_FORMAT_COM