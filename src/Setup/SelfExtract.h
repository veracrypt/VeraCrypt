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

#include "Setup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	// WARNING: file name is NOT null-terminated (use fileNameLength).
	wchar_t *fileName;
	int fileNameLength;
	uint32 crc;
	__int32 fileLength;
	unsigned char *fileContent;
} DECOMPRESSED_FILE;

extern DECOMPRESSED_FILE	Decompressed_Files [NBR_COMPRESSED_FILES];
extern int Decompressed_Files_Count;

void SelfExtractStartupInit (void);
BOOL SelfExtractInMemory (wchar_t *path, BOOL bSkipCountCheck);
void __cdecl ExtractAllFilesThread (void *hwndDlg);
BOOL MakeSelfExtractingPackage (HWND hwndDlg, wchar_t *szDestDir, BOOL bSkipX64);
BOOL VerifyPackageIntegrity (const wchar_t *path);
BOOL VerifySelfPackageIntegrity (void);
BOOL IsSelfExtractingPackage (void);
void FreeAllFileBuffers (void);
void DeobfuscateMagEndMarker (void);

extern wchar_t DestExtractPath [TC_MAX_PATH];

#ifdef __cplusplus
}
#endif
