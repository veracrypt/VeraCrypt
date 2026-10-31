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

#include "EncryptionThreadPool.h"
#include "Pkcs5.h"
#ifdef DEVICE_DRIVER
#include "Driver/Ntdriver.h"
#endif

//Increasing the maximum number of threads 
#define TC_ENC_THREAD_POOL_MAX_THREAD_COUNT 256 //64
#define TC_ENC_THREAD_POOL_QUEUE_SIZE (TC_ENC_THREAD_POOL_MAX_THREAD_COUNT * 2)

#define TC_ENC_THREAD_POOL_LEGACY_MAX_THREAD_COUNT 64
#define TC_ENC_THREAD_POOL_LEGACY_QUEUE_SIZE (TC_ENC_THREAD_POOL_LEGACY_MAX_THREAD_COUNT * 2)

static volatile size_t ThreadPoolCount = TC_ENC_THREAD_POOL_LEGACY_MAX_THREAD_COUNT;
static volatile int ThreadQueueSize = TC_ENC_THREAD_POOL_LEGACY_QUEUE_SIZE;

#ifdef DEVICE_DRIVER

#define TC_THREAD_HANDLE PKTHREAD
#define TC_THREAD_PROC VOID

#define TC_SET_EVENT(EVENT) KeSetEvent (&EVENT, IO_DISK_INCREMENT, FALSE)

#define TC_MUTEX FAST_MUTEX
#define TC_ACQUIRE_MUTEX(MUTEX) ExAcquireFastMutex (MUTEX)
#define TC_RELEASE_MUTEX(MUTEX) ExReleaseFastMutex (MUTEX)

#else // !DEVICE_DRIVER

#define TC_THREAD_HANDLE HANDLE
#define TC_THREAD_PROC unsigned __stdcall

#define TC_SET_EVENT(EVENT) SetEvent (EVENT)

#define TC_MUTEX HANDLE
#define TC_ACQUIRE_MUTEX(MUTEX) WaitForSingleObject (*(MUTEX), INFINITE)
#define TC_RELEASE_MUTEX(MUTEX) ReleaseMutex (*(MUTEX))

typedef BOOL (WINAPI *SetThreadGroupAffinityFn)(
  HANDLE               hThread,
  const GROUP_AFFINITY *GroupAffinity,
  PGROUP_AFFINITY      PreviousGroupAffinity
);

typedef WORD (WINAPI* GetActiveProcessorGroupCountFn)();

typedef DWORD (WINAPI *GetActiveProcessorCountFn)(
  WORD GroupNumber
);

#endif // !DEVICE_DRIVER


typedef enum
{
	WorkItemFree,
	WorkItemReady,
	WorkItemBusy
} WorkItemState;


typedef struct EncryptionThreadPoolWorkItemStruct
{
	WorkItemState State;
	EncryptionThreadPoolWorkType Type;

	TC_EVENT ItemCompletedEvent;

	struct EncryptionThreadPoolWorkItemStruct *FirstFragment;
	LONG OutstandingFragmentCount;

	union
	{
		struct
		{
			PCRYPTO_INFO CryptoInfo;
			uint8 *Data;
			UINT64_STRUCT StartUnitNo;
			uint32 UnitCount;

		} Encryption;

		struct
		{
			TC_EVENT *CompletionEvent;
			LONG *CompletionFlag;
			LONG *DerivationResult;
			unsigned char *DerivedKey;
			int IterationCount;
			int Memorycost;
			TC_EVENT *NoOutstandingWorkItemEvent;
			LONG *OutstandingWorkItemCount;
			unsigned char *Password;
			int PasswordLength;
			int Pkcs5Prf;
			unsigned char *Salt;
			LONG volatile *pAbortKeyDerivation; 
		} KeyDerivation;
	};

} EncryptionThreadPoolWorkItem;


static volatile BOOL ThreadPoolRunning = FALSE;
static volatile BOOL StopPending = FALSE;

static uint32 ThreadCount;
static TC_THREAD_HANDLE ThreadHandles[TC_ENC_THREAD_POOL_MAX_THREAD_COUNT];
static WORD ThreadProcessorGroups[TC_ENC_THREAD_POOL_MAX_THREAD_COUNT];

static EncryptionThreadPoolWorkItem WorkItemQueue[TC_ENC_THREAD_POOL_QUEUE_SIZE];

static volatile int EnqueuePosition;
static volatile int DequeuePosition;

static TC_MUTEX EnqueueMutex;
static TC_MUTEX DequeueMutex;

static TC_EVENT WorkItemReadyEvent;
static TC_EVENT WorkItemCompletedEvent;
static TC_EVENT ThreadPoolDrainedEvent;

// The high bit closes admission; the remaining bits count users of pool resources.
#define TC_THREAD_POOL_CLOSING ((LONG) 0x80000000)
static volatile LONG ThreadPoolReferences = TC_THREAD_POOL_CLOSING;

static void EncryptionThreadPoolCleanup (void);

static BOOL AcquireThreadPoolReference (void)
{
	LONG references = InterlockedCompareExchange (&ThreadPoolReferences, 0, 0);
	for (;;)
	{
		LONG previous;
		if (references & TC_THREAD_POOL_CLOSING)
			return FALSE;
		previous = InterlockedCompareExchange (&ThreadPoolReferences, references + 1, references);
		if (previous == references)
			return TRUE;
		references = previous;
	}
}

static void ReleaseThreadPoolReference (void)
{
	if (InterlockedDecrement (&ThreadPoolReferences) == TC_THREAD_POOL_CLOSING)
		TC_SET_EVENT (ThreadPoolDrainedEvent);
}

void EncryptDataUnitsCurrentThreadEx (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
{
	if (IsRamEncryptionEnabled())
	{
		CRYPTO_INFO tmpCI;
		memcpy (&tmpCI, ci, sizeof (CRYPTO_INFO));
		VcUnprotectKeys (&tmpCI, VcGetEncryptionID (ci));

		EncryptDataUnitsCurrentThread (buf, structUnitNo, nbrUnits, &tmpCI);

		burn (&tmpCI, sizeof(CRYPTO_INFO));
	}
	else
		EncryptDataUnitsCurrentThread (buf, structUnitNo, nbrUnits, ci);
}

void DecryptDataUnitsCurrentThreadEx (unsigned __int8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci)
{
	if (IsRamEncryptionEnabled())
	{
		CRYPTO_INFO tmpCI;
		memcpy (&tmpCI, ci, sizeof (CRYPTO_INFO));
		VcUnprotectKeys (&tmpCI, VcGetEncryptionID (ci));

		DecryptDataUnitsCurrentThread (buf, structUnitNo, nbrUnits, &tmpCI);

		burn (&tmpCI, sizeof(CRYPTO_INFO));
	}
	else
		DecryptDataUnitsCurrentThread (buf, structUnitNo, nbrUnits, ci);
}

static WorkItemState GetWorkItemState (EncryptionThreadPoolWorkItem *workItem)
{
	return InterlockedExchangeAdd ((LONG *) &workItem->State, 0);
}


static void SetWorkItemState (EncryptionThreadPoolWorkItem *workItem, WorkItemState newState)
{
	InterlockedExchange ((LONG *) &workItem->State, (LONG) newState);
}


static void DeriveKey (EncryptionThreadPoolWorkItem *workItem)
{
	int derivationResult = 0;

	switch (workItem->KeyDerivation.Pkcs5Prf)
	{
	case BLAKE2S:
		derive_key_blake2s (workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.DerivedKey, GetMaxPkcs5OutSize(), workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	case SHA512:
		derive_key_sha512 (workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.DerivedKey, GetMaxPkcs5OutSize(), workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	case WHIRLPOOL:
		derive_key_whirlpool (workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.DerivedKey, GetMaxPkcs5OutSize(), workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	case SHA256:
		derive_key_sha256 (workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.DerivedKey, GetMaxPkcs5OutSize(), workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	case STREEBOG:
		derive_key_streebog(workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.DerivedKey, GetMaxPkcs5OutSize(), workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	case ARGON2:
		derivationResult = derive_key_argon2(workItem->KeyDerivation.Password, workItem->KeyDerivation.PasswordLength, workItem->KeyDerivation.Salt, PKCS5_SALT_SIZE,
			workItem->KeyDerivation.IterationCount, workItem->KeyDerivation.Memorycost, workItem->KeyDerivation.DerivedKey, ARGON2_HEADER_KEYDATA_SIZE, workItem->KeyDerivation.pAbortKeyDerivation);
		break;

	default:
		TC_THROW_FATAL_EXCEPTION;
	}

	if (workItem->KeyDerivation.DerivationResult)
		InterlockedExchange (workItem->KeyDerivation.DerivationResult, derivationResult);

	InterlockedExchange (workItem->KeyDerivation.CompletionFlag, TRUE);
	TC_SET_EVENT (*workItem->KeyDerivation.CompletionEvent);

	// The requester retains a reference until it has finished submitting work.
	if (InterlockedDecrement (workItem->KeyDerivation.OutstandingWorkItemCount) == 0)
		TC_SET_EVENT (*workItem->KeyDerivation.NoOutstandingWorkItemEvent);
}


static TC_THREAD_PROC EncryptionThreadProc (void *threadArg)
{
	EncryptionThreadPoolWorkItem *workItem;
	EncryptionThreadPoolWorkItem *firstFragment;
	if (threadArg)
	{
#ifdef DEVICE_DRIVER
		SetThreadCpuGroupAffinity ((USHORT) *(WORD*)(threadArg));
#else
		if (threadArg)
		{
			GROUP_AFFINITY oldAffinity;
			GROUP_AFFINITY groupAffinity = {0};
			WORD groupIndex = *(WORD*)(threadArg);
			DWORD activeProcessorCount = GetActiveProcessorCount(groupIndex);
			KAFFINITY mask = (activeProcessorCount >= 64) ? ~0ULL : ((1ULL << activeProcessorCount) - 1);
			groupAffinity.Mask = mask;
			groupAffinity.Group = groupIndex;
			SetThreadGroupAffinity(GetCurrentThread(), &groupAffinity, &oldAffinity);
		}
	
#endif
	}


	while (!StopPending)
	{
		TC_ACQUIRE_MUTEX (&DequeueMutex);

		workItem = &WorkItemQueue[DequeuePosition++];

		if (DequeuePosition >= ThreadQueueSize)
			DequeuePosition = 0;

		while (!StopPending && GetWorkItemState (workItem) != WorkItemReady)
		{
			TC_WAIT_EVENT (WorkItemReadyEvent);
		}

		if (StopPending)
		{
			TC_RELEASE_MUTEX (&DequeueMutex);
			break;
		}

		SetWorkItemState (workItem, WorkItemBusy);

		TC_RELEASE_MUTEX (&DequeueMutex);

		switch (workItem->Type)
		{
		case DecryptDataUnitsWork:
			DecryptDataUnitsCurrentThreadEx (workItem->Encryption.Data, &workItem->Encryption.StartUnitNo, workItem->Encryption.UnitCount, workItem->Encryption.CryptoInfo);
			break;

		case EncryptDataUnitsWork:
			EncryptDataUnitsCurrentThreadEx (workItem->Encryption.Data, &workItem->Encryption.StartUnitNo, workItem->Encryption.UnitCount, workItem->Encryption.CryptoInfo);
			break;

		case DeriveKeyWork:
			DeriveKey (workItem);
			SetWorkItemState (workItem, WorkItemFree);
			TC_SET_EVENT (WorkItemCompletedEvent);
			ReleaseThreadPoolReference();
			continue;

		default:
			TC_THROW_FATAL_EXCEPTION;
		}

		// Keep the parent reference before releasing this queue slot.
		firstFragment = workItem->FirstFragment;
		if (workItem != firstFragment)
		{
			SetWorkItemState (workItem, WorkItemFree);
			TC_SET_EVENT (WorkItemCompletedEvent);
		}

		if (InterlockedDecrement (&firstFragment->OutstandingFragmentCount) == 0)
			TC_SET_EVENT (firstFragment->ItemCompletedEvent);
	}

#ifdef DEVICE_DRIVER
	PsTerminateSystemThread (STATUS_SUCCESS);
#else
	_endthreadex (0);
    return 0;
#endif
}

#ifndef DEVICE_DRIVER

size_t GetCpuCount (WORD* pGroupCount)
{
	size_t cpuCount = 0;
	SYSTEM_INFO sysInfo;
	GetActiveProcessorGroupCountFn GetActiveProcessorGroupCountPtr = (GetActiveProcessorGroupCountFn) GetProcAddress (GetModuleHandle (L"Kernel32.dll"), "GetActiveProcessorGroupCount");
	GetActiveProcessorCountFn GetActiveProcessorCountPtr = (GetActiveProcessorCountFn) GetProcAddress (GetModuleHandle (L"Kernel32.dll"), "GetActiveProcessorCount");
	if (GetActiveProcessorGroupCountPtr && GetActiveProcessorCountPtr)
	{
		WORD j, groupCount = GetActiveProcessorGroupCountPtr();
		size_t totalProcessors = 0;
		for (j = 0; j < groupCount; ++j)
		{
			totalProcessors += (size_t) GetActiveProcessorCountPtr(j);
		}
		cpuCount = totalProcessors;
		if (pGroupCount)
			*pGroupCount = groupCount;
	}
	else
	{
		GetSystemInfo(&sysInfo);
		cpuCount = (size_t) sysInfo.dwNumberOfProcessors;
		if (pGroupCount)
			*pGroupCount = 1;
	}

	return cpuCount;
}

#endif


BOOL EncryptionThreadPoolStart (size_t encryptionFreeCpuCount)
{
	size_t cpuCount = 0, i = 0;
	WORD groupCount = 1;

	cpuCount = GetCpuCount(&groupCount);

	if (ThreadPoolRunning)
		return TRUE;

	if (groupCount > 1)
	{
		ThreadPoolCount = TC_ENC_THREAD_POOL_MAX_THREAD_COUNT;
		ThreadQueueSize = TC_ENC_THREAD_POOL_QUEUE_SIZE;
	}

	if (cpuCount > encryptionFreeCpuCount)
		cpuCount -= encryptionFreeCpuCount;

	if (cpuCount < 2)
		return TRUE;

	if (cpuCount > ThreadPoolCount)
		cpuCount = ThreadPoolCount;

	StopPending = FALSE;
	DequeuePosition = 0;
	EnqueuePosition = 0;

#ifdef DEVICE_DRIVER
	KeInitializeEvent (&WorkItemReadyEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&WorkItemCompletedEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&ThreadPoolDrainedEvent, SynchronizationEvent, FALSE);
#else
	WorkItemReadyEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!WorkItemReadyEvent)
		goto err;

	WorkItemCompletedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!WorkItemCompletedEvent)
		goto err;

	ThreadPoolDrainedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!ThreadPoolDrainedEvent)
		goto err;
#endif

#ifdef DEVICE_DRIVER
	ExInitializeFastMutex (&DequeueMutex);
	ExInitializeFastMutex (&EnqueueMutex);
#else
	DequeueMutex = CreateMutex (NULL, FALSE, NULL);
	if (!DequeueMutex)
		goto err;

	EnqueueMutex = CreateMutex (NULL, FALSE, NULL);
	if (!EnqueueMutex)
		goto err;
#endif

	memset (WorkItemQueue, 0, sizeof (WorkItemQueue));

	for (i = 0; i < sizeof (WorkItemQueue) / sizeof (WorkItemQueue[0]); ++i)
	{
		WorkItemQueue[i].State = WorkItemFree;

#ifdef DEVICE_DRIVER
		KeInitializeEvent (&WorkItemQueue[i].ItemCompletedEvent, SynchronizationEvent, FALSE);
#else
		WorkItemQueue[i].ItemCompletedEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
		if (!WorkItemQueue[i].ItemCompletedEvent)
			goto err;
#endif
	}

	for (ThreadCount = 0; ThreadCount < cpuCount; ++ThreadCount)
	{
		WORD* pThreadArg = NULL;
		if (groupCount > 1)
		{
#ifdef DEVICE_DRIVER
			ThreadProcessorGroups[ThreadCount] = GetCpuGroup ((size_t) ThreadCount);
#else
			GetActiveProcessorCountFn GetActiveProcessorCountPtr = (GetActiveProcessorCountFn) GetProcAddress (GetModuleHandle (L"Kernel32.dll"), "GetActiveProcessorCount");
			// Determine which processor group to bind the thread to.
			if (GetActiveProcessorCountPtr)
			{
				WORD j;
				uint32 totalProcessors = 0U;
				for (j = 0U; j < groupCount; j++)
				{
					totalProcessors += (uint32) GetActiveProcessorCountPtr(j);
					if (totalProcessors > ThreadCount)
					{
						ThreadProcessorGroups[ThreadCount] = j;
						break;
					}
				}
			}
			else
				ThreadProcessorGroups[ThreadCount] = 0;
#endif
			pThreadArg = &ThreadProcessorGroups[ThreadCount];
		}

#ifdef DEVICE_DRIVER
		if (!NT_SUCCESS(TCStartThread(EncryptionThreadProc, (void*) pThreadArg, &ThreadHandles[ThreadCount])))
#else
		if (!(ThreadHandles[ThreadCount] = (HANDLE)_beginthreadex(NULL, 0, EncryptionThreadProc, (void*) pThreadArg, 0, NULL)))
#endif

		{
			goto err;
		}
	}

	InterlockedExchange (&ThreadPoolReferences, 0);
	ThreadPoolRunning = TRUE;
	return TRUE;

err:
	EncryptionThreadPoolCleanup();
	return FALSE;
}


void EncryptionThreadPoolStop ()
{
	if (!ThreadPoolRunning)
		return;

	ThreadPoolRunning = FALSE;
	// Accepted requests retain their resources through completion and requester wakeup.
	if (InterlockedOr (&ThreadPoolReferences, TC_THREAD_POOL_CLOSING) != 0)
		TC_WAIT_EVENT (ThreadPoolDrainedEvent);

	EncryptionThreadPoolCleanup();
}


// Also used before ThreadPoolRunning is published if startup fails partway through.
static void EncryptionThreadPoolCleanup (void)
{
	size_t i;

	StopPending = TRUE;
	if (ThreadCount > 0)
		TC_SET_EVENT (WorkItemReadyEvent);

	for (i = 0; i < ThreadCount; ++i)
	{
#ifdef DEVICE_DRIVER
		TCStopThread (ThreadHandles[i], &WorkItemReadyEvent);
#else
		TC_WAIT_EVENT (ThreadHandles[i]);
		CloseHandle (ThreadHandles[i]);
#endif
		ThreadHandles[i] = NULL;
	}

	ThreadCount = 0;

#ifndef DEVICE_DRIVER
	if (DequeueMutex)
		CloseHandle (DequeueMutex);
	DequeueMutex = NULL;
	if (EnqueueMutex)
		CloseHandle (EnqueueMutex);
	EnqueueMutex = NULL;

	if (WorkItemReadyEvent)
		CloseHandle (WorkItemReadyEvent);
	WorkItemReadyEvent = NULL;
	if (WorkItemCompletedEvent)
		CloseHandle (WorkItemCompletedEvent);
	WorkItemCompletedEvent = NULL;
	if (ThreadPoolDrainedEvent)
		CloseHandle (ThreadPoolDrainedEvent);
	ThreadPoolDrainedEvent = NULL;

	for (i = 0; i < sizeof (WorkItemQueue) / sizeof (WorkItemQueue[0]); ++i)
	{
		if (WorkItemQueue[i].ItemCompletedEvent)
			CloseHandle (WorkItemQueue[i].ItemCompletedEvent);
		WorkItemQueue[i].ItemCompletedEvent = NULL;
	}
#endif

	ThreadPoolRunning = FALSE;
}


void EncryptionThreadPoolBeginKeyDerivation (TC_EVENT *completionEvent, TC_EVENT *noOutstandingWorkItemEvent, LONG *completionFlag, LONG *outstandingWorkItemCount, int pkcs5Prf, unsigned char *password, int passwordLength, unsigned char *salt, int iterationCount, int memoryCost, unsigned char *derivedKey, LONG *derivationResult, LONG volatile *pAbortKeyDerivation)
{
	EncryptionThreadPoolWorkItem *workItem;
	EncryptionThreadPoolWorkItem localWorkItem;
	BOOL usePool = AcquireThreadPoolReference();

	if (usePool)
	{
		TC_ACQUIRE_MUTEX (&EnqueueMutex);

		workItem = &WorkItemQueue[EnqueuePosition++];
		if (EnqueuePosition >= ThreadQueueSize)
			EnqueuePosition = 0;

		while (GetWorkItemState (workItem) != WorkItemFree)
		{
			TC_WAIT_EVENT (WorkItemCompletedEvent);
		}
	}
	else
		workItem = &localWorkItem;

	workItem->Type = DeriveKeyWork;
	workItem->KeyDerivation.CompletionEvent = completionEvent;
	workItem->KeyDerivation.CompletionFlag = completionFlag;
	workItem->KeyDerivation.DerivationResult = derivationResult;
	workItem->KeyDerivation.DerivedKey = derivedKey;
	workItem->KeyDerivation.IterationCount = iterationCount;
	workItem->KeyDerivation.Memorycost = memoryCost;
	workItem->KeyDerivation.NoOutstandingWorkItemEvent = noOutstandingWorkItemEvent;
	workItem->KeyDerivation.OutstandingWorkItemCount = outstandingWorkItemCount;
	workItem->KeyDerivation.Password = password;
	workItem->KeyDerivation.PasswordLength = passwordLength;
	workItem->KeyDerivation.Pkcs5Prf = pkcs5Prf;
	workItem->KeyDerivation.Salt = salt;
	workItem->KeyDerivation.pAbortKeyDerivation = pAbortKeyDerivation;

	InterlockedIncrement (outstandingWorkItemCount);

	if (usePool)
	{
		// Keep a separate reference for the worker, which can finish before enqueue returns.
		InterlockedIncrement (&ThreadPoolReferences);
		SetWorkItemState (workItem, WorkItemReady);
		TC_SET_EVENT (WorkItemReadyEvent);
		TC_RELEASE_MUTEX (&EnqueueMutex);
		ReleaseThreadPoolReference();
	}
	else
		DeriveKey (workItem);
}

void EncryptionThreadPoolDoWork (EncryptionThreadPoolWorkType type, uint8 *data, const UINT64_STRUCT *startUnitNo, uint32 unitCount, PCRYPTO_INFO cryptoInfo)
{
	uint32 fragmentCount;
	uint32 unitsPerFragment;
	uint32 remainder;

	uint8 *fragmentData;
	uint64 fragmentStartUnitNo;

	EncryptionThreadPoolWorkItem *workItem;
	EncryptionThreadPoolWorkItem *firstFragmentWorkItem;

	if (unitCount == 0)
		return;

	if (unitCount == 1 || !AcquireThreadPoolReference())
	{
		switch (type)
		{
		case DecryptDataUnitsWork:
			DecryptDataUnitsCurrentThreadEx (data, startUnitNo, unitCount, cryptoInfo);
			break;

		case EncryptDataUnitsWork:
			EncryptDataUnitsCurrentThreadEx (data, startUnitNo, unitCount, cryptoInfo);
			break;

		default:
			TC_THROW_FATAL_EXCEPTION;
		}

		return;
	}

	if (unitCount <= ThreadCount)
	{
		fragmentCount = unitCount;
		unitsPerFragment = 1;
		remainder = 0;
	}
	else
	{
		/* Note that it is not efficient to divide the data into fragments smaller than a few hundred bytes.
		The reason is that the overhead associated with thread handling would in most cases make a multi-threaded
		process actually slower than a single-threaded process. */

		fragmentCount = ThreadCount;
		unitsPerFragment = unitCount / ThreadCount;
		remainder = unitCount % ThreadCount;

		if (remainder > 0)
			++unitsPerFragment;
	}

	fragmentData = data;
	fragmentStartUnitNo = startUnitNo->Value;

	TC_ACQUIRE_MUTEX (&EnqueueMutex);
	firstFragmentWorkItem = &WorkItemQueue[EnqueuePosition];

	while (GetWorkItemState (firstFragmentWorkItem) != WorkItemFree)
	{
		TC_WAIT_EVENT (WorkItemCompletedEvent);
	}

	firstFragmentWorkItem->OutstandingFragmentCount = fragmentCount;

	while (fragmentCount-- > 0)
	{
		workItem = &WorkItemQueue[EnqueuePosition++];
		if (EnqueuePosition >= ThreadQueueSize)
			EnqueuePosition = 0;

		while (GetWorkItemState (workItem) != WorkItemFree)
		{
			TC_WAIT_EVENT (WorkItemCompletedEvent);
		}

		workItem->Type = type;
		workItem->FirstFragment = firstFragmentWorkItem;

		workItem->Encryption.CryptoInfo = cryptoInfo;
		workItem->Encryption.Data = fragmentData;
		workItem->Encryption.UnitCount = unitsPerFragment;
		workItem->Encryption.StartUnitNo.Value = fragmentStartUnitNo;

		fragmentData += ((uint64)unitsPerFragment) * ENCRYPTION_DATA_UNIT_SIZE;
		fragmentStartUnitNo += unitsPerFragment;

		if (remainder > 0 && --remainder == 0)
			--unitsPerFragment;

		SetWorkItemState (workItem, WorkItemReady);
		TC_SET_EVENT (WorkItemReadyEvent);
	}

	TC_RELEASE_MUTEX (&EnqueueMutex);

	TC_WAIT_EVENT (firstFragmentWorkItem->ItemCompletedEvent);
	SetWorkItemState (firstFragmentWorkItem, WorkItemFree);
	TC_SET_EVENT (WorkItemCompletedEvent);
	ReleaseThreadPoolReference();
}


size_t GetEncryptionThreadCount ()
{
	return ThreadPoolRunning ? ThreadCount : 0;
}


size_t GetMaxEncryptionThreadCount ()
{
	return ThreadPoolCount;
}


BOOL IsEncryptionThreadPoolRunning ()
{
	return ThreadPoolRunning;
}
