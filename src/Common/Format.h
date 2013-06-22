/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_Format
#define TC_HEADER_Format

#include "Password.h"

#ifdef __cplusplus
extern "C" {
#endif

// FMIFS
typedef BOOLEAN (__stdcall *PFMIFSCALLBACK)( int command, DWORD subCommand, PVOID parameter ); 
typedef VOID (__stdcall *PFORMATEX)( PWCHAR DriveRoot, DWORD MediaFlag, PWCHAR Format, PWCHAR Label, BOOL QuickFormat, DWORD ClusterSize, PFMIFSCALLBACK Callback );

typedef struct
{
	BOOL bDevice;
	BOOL hiddenVol;
	char *volumePath;
	unsigned __int64 size;
	unsigned __int64 hiddenVolHostSize;
	int ea;
	int pkcs5;
	uint32 headerFlags;
	int fileSystem;
	int clusterSize;
	BOOL sparseFileSwitch;
	BOOL quickFormat;
	int sectorSize;
	int *realClusterSize;
	Password *password;
	HWND hwndDlg;
}
FORMAT_VOL_PARAMETERS;

#define FMIFS_DONE		0xB
#define FMIFS_HARDDISK	0xC

extern int FormatWriteBufferSize;

int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams);
BOOL FormatNtfs (int driveNo, int clusterSize);
uint64 GetVolumeDataAreaSize (BOOL hiddenVolume, uint64 volumeSize);
int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, void *dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);
BOOL WriteSector ( void *dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , PCRYPTO_INFO cryptoInfo );
BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo);
static BOOL StartFormatWriteThread ();
static void StopFormatWriteThread ();

#define FILESYS_NONE	0
#define FILESYS_FAT		1
#define FILESYS_NTFS	2

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_Format
