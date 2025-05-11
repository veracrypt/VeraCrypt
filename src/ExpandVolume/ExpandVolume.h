/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 and also from the source code of extcv, which is Copyright (c) 2009-2010 Kih-Oskh
 or Copyright (c) 2012-2013 Josef Schneider <josef@netpage.dk>

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_ExpandVolume
#define TC_HEADER_ExpandVolume

/*  NTFS must be extended at least by one cluster (max. cluster size is 64kB) */
#define TC_MINVAL_FS_EXPAND	(64*1024LL)

enum EV_FileSystem
{
	EV_FS_TYPE_RAW = 0,
	EV_FS_TYPE_FAT = 1,
	EV_FS_TYPE_NTFS = 2,
	EV_FS_TYPE_EXFAT = 3,
};

extern const wchar_t * szFileSystemStr[4];

typedef struct
{
	uint64 oldSize;
	uint64 newSize;
	uint64 hostSizeFree;
	const wchar_t *szVolumeName;
	enum EV_FileSystem FileSystem;
	BOOL bIsDevice;
	BOOL bIsLegacy;
	BOOL bInitFreeSpace;
	BOOL bQuickExpand;
	BOOL bDisableQuickExpand;
	Password *pVolumePassword;
	int VolumePkcs5;
	int VolumePim;
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
int QueryVolumeInfo (HWND hwndDlg, const wchar_t *lpszVolume, uint64 * pHostSizeFree, uint64 * pSizeLimitFS );
int MountVolTemp (HWND hwndDlg, wchar_t *volumePath, int *driveNo, Password *password, int pkcs5, int pim);
BOOL GetFileSystemType(const wchar_t *szFileName, enum EV_FileSystem *pFS);
BOOL GetNtfsNumberOfSectors(wchar_t *rootPath, uint64 *pNumberOfSectors, DWORD *pBytesPerSector);
void __cdecl volTransformThreadFunction (void *hwndDlgArg);

/* defined in DlgExpandVolume.cpp */
void AddProgressDlgStatus(HWND hwndDlg, const wchar_t* szText);
void SetProgressDlgStatus(HWND hwndDlg, const wchar_t* szText);

#ifdef __cplusplus
}
#endif

/* defined in DlgExpandVolume.cpp */
void ExpandVolumeWizard (HWND hwndDlg, wchar_t *lpszVolume);


#endif /* TC_HEADER_ExpandVolume */