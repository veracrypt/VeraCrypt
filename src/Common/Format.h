/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
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
	wchar_t *volumePath;
	unsigned __int64 size;
	unsigned __int64 hiddenVolHostSize;
	int ea;
	int pkcs5;
	uint32 headerFlags;
	int fileSystem;
	unsigned int clusterSize;
	BOOL sparseFileSwitch;
	BOOL quickFormat;
	BOOL fastCreateFile;
	DWORD sectorSize;
	int *realClusterSize;
	Password *password;
	int pim;
	HWND hwndDlg;
	BOOL bForceOperation;
	BOOL bGuiMode;
}
FORMAT_VOL_PARAMETERS;

#define FMIFS_PROGRESS 0x00
#define FMIFS_DONE_WITH_STRUCTURE 0x01
#define FMIFS_INCOMPATIBLE_FILE_SYSTEM 0x03
#define FMIFS_ACCESS_DENIED 0x06
#define FMIFS_MEDIA_WRITE_PROTECTED 0x07
#define FMIFS_VOLUME_IN_USE 0x08
#define FMIFS_CANT_QUICK_FORMAT 0x09
#define FMIFS_DONE 0x0B
#define FMIFS_BAD_LABEL 0x0C
#define FMIFS_OUTPUT 0x0E
#define FMIFS_STRUCTURE_PROGRESS 0x0F
#define FMIFS_CLUSTER_SIZE_TOO_SMALL 0x10
#define FMIFS_CLUSTER_SIZE_TOO_BIG 0x11
#define FMIFS_VOLUME_TOO_SMALL 0x12
#define FMIFS_VOLUME_TOO_BIG 0x13
#define FMIFS_NO_MEDIA_IN_DRIVE 0x14
#define FMIFS_DEVICE_NOT_READY 0x18
#define FMIFS_CHECKDISK_PROGRESS 0x19
#define FMIFS_READ_ONLY_MODE 0x20

#define FMIFS_HARDDISK	0xC

extern int FormatWriteBufferSize;

int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams);
BOOL FormatNtfs (int driveNo, int clusterSize);
BOOL FormatFs (int driveNo, int clusterSize, int fsType);
BOOL ExternalFormatFs (int driveNo, int clusterSize, int fsType);
uint64 GetVolumeDataAreaSize (BOOL hiddenVolume, uint64 volumeSize);
int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, __int64 num_sectors, void *dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);
BOOL WriteSector ( void *dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , PCRYPTO_INFO cryptoInfo );
BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo);
static BOOL StartFormatWriteThread ();
static void StopFormatWriteThread ();

#define FILESYS_NONE	0
#define FILESYS_FAT		1
#define FILESYS_NTFS	2
#define FILESYS_EXFAT	3
#define FILESYS_REFS	4

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_Format
