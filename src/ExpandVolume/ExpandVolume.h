/*

Some portions of the source code contained in this file were derived from the
source code of TrueCrypt 7.0a, which is governed by the TrueCrypt License 3.0
that can be found in the file 'License.txt' in the folder 'TrueCrypt-License'.

Modifications and additions to the original source code (contained in this file)
and all other portions of this file are Copyright (c) 2009-2010 by Kih-Oskh or
Copyright (c) 2012-2013 Josef Schneider <josef@netpage.dk>

TrueCrypt source files used to derive some portions of the source code in this
file are:

    - 'Mount\Mount.c'
    - 'Common\Format.c'
	- 'Common\Password.c'
    - 'Format\Tcformat.c'

-------------------------------------------------------------------------------

Original legal notice of the TrueCrypt source files:

	 Legal Notice: Some portions of the source code contained in this file were
	 derived from the source code of Encryption for the Masses 2.02a, which is
	 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
	 Agreement for Encryption for the Masses'. Modifications and additions to
	 the original source code (contained in this file) and all other portions
	 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
	 and are governed by the TrueCrypt License 3.0 the full text of which is
	 contained in the file License.txt included in TrueCrypt binary and source
	 code distribution packages.

*/

#ifndef TC_HEADER_ExpandVolume
#define TC_HEADER_ExpandVolume

/*  NTFS must be extended at least by one cluster (max. cluster size is 64kB) */
#define TC_MINVAL_FS_EXPAND	(64*1024LL)

enum EV_FileSystem
{
	EV_FS_TYPE_RAW = 0,
	EV_FS_TYPE_FAT = 1,
	EV_FS_TYPE_NTFS = 2,
};

extern const char * szFileSystemStr[3];

typedef struct
{
	uint64 oldSize;
	uint64 newSize;
	uint64 hostSizeFree;
	const char *szVolumeName;
	enum EV_FileSystem FileSystem;
	BOOL bIsDevice;
	BOOL bIsLegacy;
	BOOL bInitFreeSpace;
	Password *pVolumePassword;
	int VolumePkcs5;
	HWND hwndDlg;
} EXPAND_VOL_THREAD_PARAMS;

#ifdef __cplusplus
extern "C" {
#endif

extern HWND hCurPage;		/* Handle to current wizard page */
extern int nPbar;			/* Control ID of progress bar:- for format code */
extern volatile BOOL bVolTransformThreadCancel; /* TRUE if the user cancels/pauses volume expansion */

/* defined in ExpandVolume.c */
uint64 GetVolumeDataAreaSize (uint64 volumeSize, BOOL legacyVolume);
uint64 GetVolumeSizeByDataAreaSize (uint64 dataSize, BOOL legacyVolume);
int QueryVolumeInfo (HWND hwndDlg, const char *lpszVolume, uint64 * pHostSizeFree, uint64 * pSizeLimitFS );
int MountVolTemp (HWND hwndDlg, char *volumePath, int *driveNo, Password *password, int pkcs5);
BOOL GetFileSystemType(const char *szFileName, enum EV_FileSystem *pFS);
BOOL GetNtfsNumberOfSectors(char *rootPath, uint64 *pNumberOfSectors, DWORD *pBytesPerSector);
void __cdecl volTransformThreadFunction (void *hwndDlgArg);

/* defined in DlgExpandVolume.cpp */
void AddProgressDlgStatus(HWND hwndDlg, const char* szText);
void SetProgressDlgStatus(HWND hwndDlg, const char* szText);

#ifdef __cplusplus
}
#endif

/* defined in DlgExpandVolume.cpp */
void ExpandVolumeWizard (HWND hwndDlg, char *lpszVolume);


#endif /* TC_HEADER_ExpandVolume */