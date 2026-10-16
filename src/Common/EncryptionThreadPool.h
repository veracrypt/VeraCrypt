/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_ENCRYPTION_THREAD_POOL
#define TC_HEADER_ENCRYPTION_THREAD_POOL

#include "Tcdefs.h"
#include "Crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	EncryptDataUnitsWork,
	DecryptDataUnitsWork,
	DeriveKeyWork
} EncryptionThreadPoolWorkType;

#ifndef DEVICE_DRIVER
size_t GetCpuCount (WORD* pGroupCount);
#endif

/*
 * The caller initializes outstandingWorkItemCount to 1 and noOutstandingWorkItemEvent
 * to non-signaled, retaining its own reference while submissions are possible.
 * After the last possible submission, it decrements the count and waits on the
 * event if the result is nonzero, before releasing any caller-owned buffers.
 * Each worker releases its reference after publishing completion. A worker that
 * drops the count to zero signals the event, which must not be reset during submission.
 * derivationResult receives 0 on success; PRFs that can fail store their native nonzero result.
 */
void EncryptionThreadPoolBeginKeyDerivation (TC_EVENT *completionEvent, TC_EVENT *noOutstandingWorkItemEvent, LONG *completionFlag, LONG *outstandingWorkItemCount, int pkcs5Prf, unsigned char *password, int passwordLength, unsigned char *salt, int iterationCount,  int memoryCost, unsigned char *derivedKey, LONG *derivationResult, LONG volatile *pAbortKeyDerivation);
void EncryptionThreadPoolDoWork (EncryptionThreadPoolWorkType type, uint8 *data, const UINT64_STRUCT *startUnitNo, uint32 unitCount, PCRYPTO_INFO cryptoInfo);
BOOL EncryptionThreadPoolStart (size_t encryptionFreeCpuCount);
void EncryptionThreadPoolStop ();
size_t GetEncryptionThreadCount ();
size_t GetMaxEncryptionThreadCount ();
BOOL IsEncryptionThreadPoolRunning ();

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_ENCRYPTION_THREAD_POOL
