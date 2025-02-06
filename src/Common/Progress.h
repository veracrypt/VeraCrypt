/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PBM_SETSTATE

#define PBM_SETSTATE            (WM_USER+16) // wParam = PBST_[State] (NORMAL, ERROR, PAUSED)
#define PBST_NORMAL             0x0001
#define PBST_ERROR              0x0002
#define PBST_PAUSED             0x0003

#endif

void InitProgressBar (__int64 totalBytes, __int64 bytesDone, BOOL bReverse, BOOL bIOThroughput, BOOL bDisplayStatus, BOOL bShowPercent);
BOOL UpdateProgressBar (__int64 byteOffset);
BOOL UpdateProgressBarProc (__int64 byteOffset);

#ifdef __cplusplus
}
#endif
