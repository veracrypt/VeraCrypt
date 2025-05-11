/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "Format.h"

enum nonsys_inplace_enc_status
{
	NONSYS_INPLACE_ENC_STATUS_NONE = 0,
	NONSYS_INPLACE_ENC_STATUS_PREPARING,
	NONSYS_INPLACE_ENC_STATUS_RESIZING,
	NONSYS_INPLACE_ENC_STATUS_ENCRYPTING,
	NONSYS_INPLACE_ENC_STATUS_DECRYPTING,
	NONSYS_INPLACE_ENC_STATUS_FINALIZING,
	NONSYS_INPLACE_ENC_STATUS_PAUSED,
	NONSYS_INPLACE_ENC_STATUS_FINISHED,
	NONSYS_INPLACE_ENC_STATUS_ERROR
};

BOOL CheckRequirementsForNonSysInPlaceEnc (HWND hwndDlg, const wchar_t *devicePath, BOOL silent);
BOOL CheckRequirementsForNonSysInPlaceDec (HWND hwndDlg, const wchar_t *devicePath, BOOL silent);
int EncryptPartitionInPlaceBegin (volatile FORMAT_VOL_PARAMETERS *volParams, volatile HANDLE *outHandle, WipeAlgorithmId wipeAlgorithm);
int EncryptPartitionInPlaceResume (HANDLE dev, volatile FORMAT_VOL_PARAMETERS *volParams, WipeAlgorithmId wipeAlgorithm, volatile BOOL *bTryToCorrectReadErrors);
int DecryptPartitionInPlace (volatile FORMAT_VOL_PARAMETERS *volParams, volatile BOOL *DiscardUnreadableEncryptedSectors);
void ShowInPlaceEncErrMsgWAltSteps (HWND hwndDlg, char *iniStrId, BOOL bErr);
void SetNonSysInplaceEncUIStatus (int nonSysInplaceEncStatus);
int FastVolumeHeaderUpdate (HANDLE dev, CRYPTO_INFO *headerCryptoInfo, CRYPTO_INFO *masterCryptoInfo, __int64 deviceSize);

static HANDLE OpenPartitionVolume (HWND hwndDlg, const wchar_t *devName, BOOL bExclusiveRequired, BOOL bSharedRequired, BOOL bSharedRequiresConfirmation, BOOL bShowAlternativeSteps, BOOL bSilent);
static int DismountFileSystem (HWND hwndDlg, HANDLE dev, int driveLetter, BOOL bForcedAllowed, BOOL bForcedRequiresConfirmation, BOOL bSilent);
static int ConcealNTFS (HANDLE dev);
BOOL SaveNonSysInPlaceEncSettings (int delta, WipeAlgorithmId wipeAlgorithm, BOOL bDecrypting);
static void ExportProgressStats (__int64 bytesDone, __int64 totalSize);
int ZeroUnreadableSectors (HANDLE dev, LARGE_INTEGER startOffset, int64 size, int sectorSize, uint64 *zeroedSectorCount);
static int OpenBackupHeader (HANDLE dev, const wchar_t *devicePath, Password *password, int pkcs5, int pim, PCRYPTO_INFO *retCryptoInfo, CRYPTO_INFO *headerCryptoInfo, __int64 deviceSize);
BOOL MoveClustersBeforeThreshold (HANDLE volumeHandle, PWSTR volumeDevicePath, int64 clusterThreshold);

#ifdef __cplusplus
}
#endif
