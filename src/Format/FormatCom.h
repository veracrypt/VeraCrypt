/*
 Copyright (c) 2007-2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
int UacAnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters);
int UacFormatVolume (char *cvolumePath , BOOL bDevice , unsigned __int64 size , unsigned __int64 hiddenVolHostSize , Password *password , int cipher , int pkcs5 , BOOL quickFormat, BOOL sparseFileSwitch, int fileSystem , int clusterSize, HWND hwndDlg , BOOL hiddenVol , int *realClusterSize);
BOOL UacUpdateProgressBar (__int64 nSecNo, BOOL *bVolTransformThreadCancel);

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_FORMAT_COM