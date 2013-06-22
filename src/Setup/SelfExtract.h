/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Setup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	// WARNING: file name is NOT null-terminated (use fileNameLength).
	unsigned char *fileName;
	int fileNameLength;
	uint32 crc;
	__int32 fileLength;
	unsigned char *fileContent;
} DECOMPRESSED_FILE;

extern DECOMPRESSED_FILE	Decompressed_Files [NBR_COMPRESSED_FILES];

void SelfExtractStartupInit (void);
BOOL SelfExtractInMemory (char *path);
void __cdecl ExtractAllFilesThread (void *hwndDlg);
BOOL MakeSelfExtractingPackage (HWND hwndDlg, char *szDestDir);
BOOL VerifyPackageIntegrity (void);
BOOL IsSelfExtractingPackage (void);
static void DeobfuscateMagEndMarker (void);

extern char DestExtractPath [TC_MAX_PATH];

#ifdef __cplusplus
}
#endif
