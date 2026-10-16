/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0.
 * Bounded user-mode checks of the production Windows KDF reference protocol.
 * Build through test_windows_kdf_completion.py, which supplies caller excerpts.
 */
#include "Common/EncryptionThreadPool.h"
#include "Common/Pkcs5.h"
#include <process.h>
#include <stdio.h>

static BOOL TestSetEvent (HANDLE event);
static DWORD TestWait (HANDLE event);
static HANDLE WINAPI TestCreateEvent (LPSECURITY_ATTRIBUTES attributes, BOOL manualReset, BOOL initialState, LPCWSTR name);
static HANDLE WINAPI TestCreateMutex (LPSECURITY_ATTRIBUTES attributes, BOOL initialOwner, LPCWSTR name);
static uintptr_t TestBeginThread (void *security, unsigned stackSize, unsigned (__stdcall *proc) (void *), void *arg, unsigned flags, unsigned *id);
static BOOL WINAPI TestCloseHandle (HANDLE handle);
#undef TC_WAIT_EVENT
#define TC_WAIT_EVENT(event) TestWait (event)
#define SetEvent TestSetEvent
#define CreateEventW TestCreateEvent
#define CreateMutexW TestCreateMutex
#define _beginthreadex TestBeginThread
#define CloseHandle TestCloseHandle
#include "Common/EncryptionThreadPool.c"
#undef CloseHandle
#undef _beginthreadex
#undef CreateMutexW
#undef CreateEventW
#undef SetEvent
#include "kdf_item.inc"

#define MAX_REQUESTS 16
#define PRF_COUNT (LAST_PRF_ID - FIRST_PRF_ID + 1)
typedef struct Request Request;
typedef struct
{
    Request *Owner;
    KeyDerivationWorkItem *Item;
    HANDLE Started, MayReturn, ReadyPublished, MayReleaseReference, WorkerDone;
    int Result;
    BOOL HoldAfterReady;
} Job;

struct Request
{
    TC_EVENT *Ready, *Drained;
    LONG *References;
    KeyDerivationWorkItem *Items;
    LONG volatile Abort;
    LONG volatile Signals;
    HANDLE WaitEntered, FinishDone, SignalEntered, MaySignal;
    HANDLE RequesterThread;
    BOOL HoldFinalSignal;
    int JobCount;
    Job Jobs[PRF_COUNT];
};

static Request Requests[MAX_REQUESTS];
static int RequestCount;
static __declspec(thread) Job *CurrentJob;
static __declspec(thread) Request *DrainingRequest;
typedef struct
{
    unsigned char Data[6 * ENCRYPTION_DATA_UNIT_SIZE];
    LONG volatile Started, Processed;
    HANDLE BothStarted, MayProcess, Waiting, Paused, MayReturn, Done, Thread;
    BOOL HoldWorkers, HoldRequester;
    uint32 Units;
    EncryptionThreadPoolWorkType Type;
} CipherJob;
static __declspec(thread) CipherJob *CurrentCipherJob;
static HANDLE StopWaiting, StopDone;

typedef struct
{
    HANDLE Handle;
    BOOL Thread, Open;
} PoolResource;
static PoolResource Resources[1024];
static int ResourceCount, OpenResources, CreateAttempts, FailCreateAt;

static void Require (BOOL condition, const char *message)
{
    if (!condition)
    {
        fprintf (stderr, "FAIL: %s\n", message);
        ExitProcess (1);
    }
}

static BOOL FailCreation (void)
{
    if (++CreateAttempts == FailCreateAt)
    {
        SetLastError (ERROR_NOT_ENOUGH_MEMORY);
        return TRUE;
    }
    return FALSE;
}

static HANDLE TrackResource (HANDLE handle, BOOL thread)
{
    if (handle)
    {
        PoolResource *resource;
        Require (ResourceCount < sizeof (Resources) / sizeof (Resources[0]), "resource fixture capacity");
        resource = &Resources[ResourceCount++];
        resource->Handle = handle;
        resource->Thread = thread;
        resource->Open = TRUE;
        ++OpenResources;
    }
    return handle;
}

static HANDLE WINAPI TestCreateEvent (LPSECURITY_ATTRIBUTES attributes, BOOL manualReset, BOOL initialState, LPCWSTR name)
{
    return FailCreation () ? NULL : TrackResource (CreateEventW (attributes, manualReset, initialState, name), FALSE);
}

static HANDLE WINAPI TestCreateMutex (LPSECURITY_ATTRIBUTES attributes, BOOL initialOwner, LPCWSTR name)
{
    return FailCreation () ? NULL : TrackResource (CreateMutexW (attributes, initialOwner, name), FALSE);
}

static uintptr_t TestBeginThread (void *security, unsigned stackSize, unsigned (__stdcall *proc) (void *), void *arg, unsigned flags, unsigned *id)
{
    return FailCreation () ? 0 : (uintptr_t) TrackResource ((HANDLE) _beginthreadex (security, stackSize, proc, arg, flags, id), TRUE);
}

static BOOL WINAPI TestCloseHandle (HANDLE handle)
{
    int i;
    for (i = ResourceCount - 1; i >= 0; --i)
    {
        PoolResource *resource = &Resources[i];
        if (resource->Open && resource->Handle == handle)
        {
            if (resource->Thread)
                Require (WaitForSingleObject (handle, 0) == WAIT_OBJECT_0, "worker handle closed before join");
            resource->Open = FALSE;
            --OpenResources;
            Require (CloseHandle (handle), "close pool resource");
            return TRUE;
        }
    }
    Require (FALSE, "closing unknown pool resource");
    return FALSE;
}

static HANDLE Event (void)
{
    HANDLE event = CreateEvent (NULL, FALSE, FALSE, NULL);
    Require (event != NULL, "create test event");
    return event;
}

static void Wait (HANDLE event)
{
    Require (WaitForSingleObject (event, 10000) == WAIT_OBJECT_0, "test barrier timed out");
}

static LONG References (Request *request)
{
    return InterlockedCompareExchange (request->References, 0, 0);
}

static DWORD TestWait (HANDLE event)
{
    DWORD result;
    if (DrainingRequest && event == *DrainingRequest->Drained)
        SetEvent (DrainingRequest->WaitEntered);
    if (StopWaiting && event == ThreadPoolDrainedEvent)
        SetEvent (StopWaiting);
    if (CurrentCipherJob && event != WorkItemCompletedEvent)
        SetEvent (CurrentCipherJob->Waiting);
    result = WaitForSingleObject (event, INFINITE);
    if (CurrentCipherJob && CurrentCipherJob->HoldRequester && event != WorkItemCompletedEvent)
    {
        SetEvent (CurrentCipherJob->Paused);
        Wait (CurrentCipherJob->MayReturn);
    }
    return result;
}

static BOOL TestSetEvent (HANDLE event)
{
    Job *job = CurrentJob;
    if (job)
    {
        Request *request = job->Owner;
        if (event == *request->Drained)
        {
            Require (References (request) == 0, "completion signaled with outstanding references");
            Require (InterlockedIncrement (&request->Signals) == 1, "completion signaled twice");
            if (request->HoldFinalSignal)
            {
                SetEvent (request->SignalEntered);
                Wait (request->MaySignal);
            }
        }
        if (event == *request->Ready && job->HoldAfterReady)
        {
            BOOL result = SetEvent (event);
            SetEvent (job->ReadyPublished);
            Wait (job->MayReleaseReference);
            return result;
        }
        if (event == WorkItemCompletedEvent)
        {
            BOOL result = SetEvent (event);
            CurrentJob = NULL;
            SetEvent (job->WorkerDone);
            return result;
        }
    }
    return SetEvent (event);
}

static int InitializeRequest (Request *request)
{
    TC_EVENT *keyDerivationCompletedEvent = NULL, *noOutstandingWorkItemEvent = NULL;
    LONG *outstandingWorkItemCount = NULL;
    KeyDerivationWorkItem *keyDerivationWorkItems = NULL;
    int keyDerivationWorkItemsSize = 0, pkcs5PrfCount = PRF_COUNT, i, status;
#include "kdf_init.inc"
    request->Ready = keyDerivationCompletedEvent;
    request->Drained = noOutstandingWorkItemEvent;
    request->References = outstandingWorkItemCount;
    request->Items = keyDerivationWorkItems;
    return 0;
err_early:
    return status;
}

static Request *NewRequest (void)
{
    Request *request;
    Require (RequestCount < MAX_REQUESTS, "request fixture capacity");
    request = &Requests[RequestCount++];
    Require (InitializeRequest (request) == 0, "initialize request");
    /* Refuse to exercise an implementation without the caller reference. */
    Require (References (request) == 1, "missing requester reference");
    Require (WaitForSingleObject (*request->Drained, 0) == WAIT_TIMEOUT, "initial completion event signaled");
    request->WaitEntered = Event ();
    request->FinishDone = Event ();
    request->SignalEntered = Event ();
    request->MaySignal = Event ();
    return request;
}

static unsigned __stdcall FinishRequest (void *context)
{
    Request *request = (Request *) context;
    LONG *outstandingWorkItemCount = request->References;
    TC_EVENT *noOutstandingWorkItemEvent = request->Drained;
    DrainingRequest = request;
#include "kdf_drain.inc"
    Require (References (request) == 0, "request finished with workers outstanding");
    DrainingRequest = NULL;
    SetEvent (request->FinishDone);
    return 0;
}

static void BeginFinish (Request *request)
{
    request->RequesterThread = (HANDLE) _beginthreadex (NULL, 0, FinishRequest, request, 0, NULL);
    Require (request->RequesterThread != NULL, "start requester thread");
    Wait (request->WaitEntered);
    Require (WaitForSingleObject (request->FinishDone, 0) == WAIT_TIMEOUT, "request did not wait for workers");
}

static void EndFinish (Request *request)
{
    Wait (request->FinishDone);
    Wait (request->RequesterThread);
    Require (References (request) == 0 && request->Signals == 1, "last worker completion");
}

static Job *NewJob (Request *request, int prf, BOOL holdAfterReady, int result)
{
    Job *job;
    Require (request->JobCount < PRF_COUNT, "job fixture capacity");
    job = &request->Jobs[request->JobCount];
    job->Owner = request;
    job->Item = &request->Items[request->JobCount++];
    job->Item->Free = FALSE;
    job->Item->KeyReady = FALSE;
    job->Item->DerivationResult = 0;
    job->Item->Pkcs5Prf = prf;
    job->Result = result;
    job->HoldAfterReady = holdAfterReady;
    job->Started = Event (); job->MayReturn = Event (); job->ReadyPublished = Event ();
    job->MayReleaseReference = Event (); job->WorkerDone = Event ();
    return job;
}

static void SubmitJob (Job *job)
{
    Request *request = job->Owner;
    EncryptionThreadPoolBeginKeyDerivation (request->Ready, request->Drained, &job->Item->KeyReady,
        request->References, job->Item->Pkcs5Prf, (unsigned char *) job, sizeof (*job), NULL, 1, 8,
        job->Item->DerivedKey, &job->Item->DerivationResult, &request->Abort);
}

static Job *Submit (Request *request, int prf, BOOL holdAfterReady, int result)
{
    Job *job = NewJob (request, prf, holdAfterReady, result);
    SubmitJob (job);
    return job;
}

static void JobDone (Job *job)
{
    Wait (job->WorkerDone);
    Require (job->Item->KeyReady == TRUE && job->Item->DerivationResult == job->Result,
        "result was not published before completion");
}

static void FakeKdf (const unsigned char *password, unsigned char *output, int length)
{
    Job *job = (Job *) password;
    CurrentJob = job;
    SetEvent (job->Started);
    Wait (job->MayReturn);
    memset (output, job->Owner->Abort || job->Result ? 0 : 0x5a, length);
}

#define FAKE_KDF(name) \
void name (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len, \
    uint32 iterations, unsigned char *dk, int dklen, long volatile *abortFlag) \
{ FakeKdf (pwd, dk, dklen); }
FAKE_KDF (derive_key_blake2s)
FAKE_KDF (derive_key_sha512)
FAKE_KDF (derive_key_whirlpool)
FAKE_KDF (derive_key_sha256)
FAKE_KDF (derive_key_streebog)
int derive_key_argon2 (const unsigned char *pwd, int pwd_len, const unsigned char *salt, int salt_len,
    uint32 iterations, uint32 memory, unsigned char *dk, int dklen, long volatile *abortFlag)
{ FakeKdf (pwd, dk, dklen); return ((Job *) pwd)->Result; }

int GetMaxPkcs5OutSize (void) { return MASTER_KEYDATA_SIZE; }
BOOL IsRamEncryptionEnabled (void) { return FALSE; }
uint64 VcGetEncryptionID (PCRYPTO_INFO ci) { return 0; }
void VcUnprotectKeys (PCRYPTO_INFO ci, uint64 id) { }
static void FakeCrypt (unsigned char *data, TC_LARGEST_COMPILER_UINT count, PCRYPTO_INFO ci, int value)
{
    CipherJob *job = (CipherJob *) ci;
    if (job->HoldWorkers)
    {
        if (InterlockedIncrement (&job->Started) == 2) SetEvent (job->BothStarted);
        Wait (job->MayProcess);
    }
    memset (data, value, (size_t) count * ENCRYPTION_DATA_UNIT_SIZE);
    InterlockedExchangeAdd (&job->Processed, (LONG) count);
}
void EncryptDataUnitsCurrentThread (unsigned __int8 *data, const UINT64_STRUCT *start, TC_LARGEST_COMPILER_UINT count, PCRYPTO_INFO ci)
{ FakeCrypt (data, count, ci, 0xa5); }
void DecryptDataUnitsCurrentThread (unsigned __int8 *data, const UINT64_STRUCT *start, TC_LARGEST_COMPILER_UINT count, PCRYPTO_INFO ci)
{ FakeCrypt (data, count, ci, 0x5a); }

static void RequesterLast (int count)
{
    Request *request = NewRequest ();
    int i;
    for (i = 0; i < count; ++i)
    {
        Job *job = Submit (request, FIRST_PRF_ID + i, FALSE, 0);
        SetEvent (job->MayReturn);
        JobDone (job);
        Require (References (request) == 1 && request->Signals == 0, "idle submission phase completed");
        Require (WaitForSingleObject (*request->Drained, 0) == WAIT_TIMEOUT, "stale idle notification");
    }
    FinishRequest (request);
    Wait (request->FinishDone);
    Require (request->Signals == 0, "requester-last path unnecessarily signaled");
}

static void WorkerLast (int count, BOOL cancel, int argonResult)
{
    Request *request = NewRequest ();
    int i;
    for (i = 0; i < count; ++i)
        Submit (request, i == count - 1 ? ARGON2 : SHA512, FALSE, i == count - 1 ? argonResult : 0);
    BeginFinish (request);
    InterlockedExchange (&request->Abort, cancel);
    for (i = 0; i < count; ++i)
        SetEvent (request->Jobs[i].MayReturn);
    EndFinish (request);
    for (i = 0; i < count; ++i)
        JobDone (&request->Jobs[i]);
}

static void PublicationBoundaries (void)
{
    Request *request = NewRequest ();
    Job *job = Submit (request, SHA256, TRUE, 0);
    SetEvent (job->MayReturn);
    Wait (job->ReadyPublished);
    BeginFinish (request);
    Require (References (request) == 1, "ready result released reference too early");
    SetEvent (job->MayReleaseReference);
    EndFinish (request);
    JobDone (job);

    request = NewRequest ();
    request->HoldFinalSignal = TRUE;
    job = Submit (request, SHA512, FALSE, 0);
    BeginFinish (request);
    SetEvent (job->MayReturn);
    Wait (request->SignalEntered);
    Require (References (request) == 0, "final notification boundary");
    Require (WaitForSingleObject (request->FinishDone, 0) == WAIT_TIMEOUT, "zero count bypassed final notification");
    SetEvent (request->MaySignal);
    EndFinish (request);
    JobDone (job);
}

static void ResetResources (int failurePoint)
{
    Require (OpenResources == 0, "pool resources leaked");
    ResourceCount = CreateAttempts = 0;
    FailCreateAt = failurePoint;
}

static void StartupFailures (size_t available)
{
    int i, creationCount;
    Require (EncryptionThreadPoolStart (available - 2), "start baseline pool");
    creationCount = CreateAttempts;
    EncryptionThreadPoolStop ();
    ResetResources (0);
    for (i = 1; i <= creationCount; ++i)
    {
        ResetResources (i);
        Require (!EncryptionThreadPoolStart (available - 2), "injected startup failure accepted");
        Require (!IsEncryptionThreadPoolRunning () && GetEncryptionThreadCount () == 0, "failed pool published");
        EncryptionThreadPoolStop ();
        ResetResources (0);
        Require (EncryptionThreadPoolStart (available - 2), "restart after failure");
        EncryptionThreadPoolStop ();
    }
    ResetResources (0);
    printf ("PASS: %d startup failure points, each followed by a successful restart\n", creationCount);
}

static unsigned __stdcall StopPool (void *unused)
{
    EncryptionThreadPoolStop ();
    SetEvent (StopDone);
    return 0;
}

static HANDLE BeginStop (void)
{
    HANDLE thread;
    StopWaiting = Event (); StopDone = Event ();
    thread = (HANDLE) _beginthreadex (NULL, 0, StopPool, NULL, 0, NULL);
    Require (thread != NULL, "start shutdown thread");
    Wait (StopWaiting);
    Require (!IsEncryptionThreadPoolRunning (), "shutdown still accepts pool work");
    Require (WaitForSingleObject (StopDone, 0) == WAIT_TIMEOUT, "shutdown did not drain accepted work");
    return thread;
}

static void EndStop (HANDLE thread)
{
    Wait (StopDone); Wait (thread);
    CloseHandle (thread); CloseHandle (StopWaiting); CloseHandle (StopDone);
    StopWaiting = StopDone = NULL;
    ResetResources (0);
}

static unsigned __stdcall RunCipher (void *context)
{
    CipherJob *job = (CipherJob *) context;
    UINT64_STRUCT start = { 0 };
    CurrentCipherJob = job;
    EncryptionThreadPoolDoWork (job->Type, job->Data, &start, job->Units, (PCRYPTO_INFO) job);
    CurrentCipherJob = NULL;
    SetEvent (job->Done);
    return 0;
}

static void StartCipher (CipherJob *job, BOOL hold, EncryptionThreadPoolWorkType type)
{
    memset (job, 0, sizeof (*job));
    job->Units = 6; job->Type = type;
    job->HoldWorkers = job->HoldRequester = hold;
    job->BothStarted = Event (); job->MayProcess = CreateEvent (NULL, TRUE, FALSE, NULL);
    Require (job->MayProcess != NULL, "create cipher gate");
    job->Waiting = Event (); job->Paused = Event (); job->MayReturn = Event (); job->Done = Event ();
    job->Thread = (HANDLE) _beginthreadex (NULL, 0, RunCipher, job, 0, NULL);
    Require (job->Thread != NULL, "start cipher requester");
    Wait (job->Waiting);
}

static void CheckCipher (CipherJob *job)
{
    size_t i;
    unsigned char expected = job->Type == EncryptDataUnitsWork ? 0xa5 : 0x5a;
    Require (job->Processed == job->Units, "incorrect number of processed units");
    for (i = 0; i < job->Units * ENCRYPTION_DATA_UNIT_SIZE; ++i)
        Require (job->Data[i] == expected, "incomplete cipher output");
}

static void EndCipher (CipherJob *job)
{
    Wait (job->Done); Wait (job->Thread);
    CheckCipher (job);
    CloseHandle (job->Thread); CloseHandle (job->BothStarted); CloseHandle (job->MayProcess);
    CloseHandle (job->Waiting); CloseHandle (job->Paused); CloseHandle (job->MayReturn); CloseHandle (job->Done);
}

static void InlineKdf (void)
{
    Request *request = NewRequest ();
    Job *job = NewJob (request, SHA512, FALSE, 0);
    SetEvent (job->MayReturn);
    SubmitJob (job);
    CurrentJob = NULL;
    Require (job->Item->KeyReady && job->Item->DerivationResult == 0 && References (request) == 1,
        "synchronous KDF fallback");
    FinishRequest (request);
    Wait (request->FinishDone);
}

static void ShutdownInFlight (size_t available)
{
    CipherJob first, queued, synchronous = { 0 };
    UINT64_STRUCT start = { 0 };
    HANDLE stop;
    Request *request;
    int i;
    Require (EncryptionThreadPoolStart (available - 2), "start cipher pool");
    StartCipher (&first, TRUE, EncryptDataUnitsWork);
    Wait (first.BothStarted);
    StartCipher (&queued, FALSE, DecryptDataUnitsWork);
    stop = BeginStop ();
    synchronous.Units = 6; synchronous.Type = EncryptDataUnitsWork;
    EncryptionThreadPoolDoWork (synchronous.Type, synchronous.Data, &start, synchronous.Units, (PCRYPTO_INFO) &synchronous);
    CheckCipher (&synchronous);
    SetEvent (first.MayProcess);
    Wait (first.Paused);
    Require (WaitForSingleObject (StopDone, 0) == WAIT_TIMEOUT, "shutdown closed a requester's completion handle");
    SetEvent (first.MayReturn);
    EndCipher (&first); EndCipher (&queued); EndStop (stop);

    Require (EncryptionThreadPoolStart (available - 2), "restart for KDF shutdown");
    request = NewRequest ();
    for (i = 0; i < PRF_COUNT; ++i) Submit (request, FIRST_PRF_ID + i, FALSE, 0);
    BeginFinish (request);
    stop = BeginStop ();
    InlineKdf ();
    for (i = 0; i < request->JobCount; ++i) SetEvent (request->Jobs[i].MayReturn);
    EndFinish (request);
    for (i = 0; i < request->JobCount; ++i) JobDone (&request->Jobs[i]);
    EndStop (stop);
    InlineKdf ();
    puts ("PASS: shutdown drains active and queued encryption, KDFs and requesters; synchronous fallback and restart");
}

static void FreeRequests (void)
{
    int i, j;
    Require (OpenResources == 0, "pool resources leaked");
    for (i = 0; i < RequestCount; ++i)
    {
        Request *r = &Requests[i];
        for (j = 0; j < r->JobCount; ++j)
        {
            Job *job = &r->Jobs[j];
            CloseHandle (job->Started); CloseHandle (job->MayReturn); CloseHandle (job->ReadyPublished);
            CloseHandle (job->MayReleaseReference); CloseHandle (job->WorkerDone);
        }
        if (r->RequesterThread) CloseHandle (r->RequesterThread);
        CloseHandle (r->WaitEntered); CloseHandle (r->FinishDone); CloseHandle (r->SignalEntered); CloseHandle (r->MaySignal);
        CloseHandle (*r->Ready); CloseHandle (*r->Drained);
        VirtualUnlock (r->Items, sizeof (*r->Items) * PRF_COUNT);
        free (r->Ready); free (r->Drained); free (r->References); free (r->Items);
    }
}

int main (int argc, char **argv)
{
    WORD groups;
    size_t available = GetCpuCount (&groups);
    size_t wanted = argc > 1 ? (size_t) atoi (argv[1]) : 2;
    if (available < 2) { puts ("SKIP: at least two logical CPUs required"); return 0; }
    if (argc > 1 && strcmp (argv[1], "startup") == 0)
    {
        StartupFailures (available);
        return 0;
    }
    if (argc > 1 && strcmp (argv[1], "shutdown") == 0)
    {
        ShutdownInFlight (available);
        FreeRequests ();
        return 0;
    }
    if (wanted > available) wanted = available;
    Require (EncryptionThreadPoolStart (available - wanted), "start production pool");
    Require (GetEncryptionThreadCount () == wanted, "pool worker count");
    RequesterLast (0); RequesterLast (1); RequesterLast (5); RequesterLast (6);
    WorkerLast (2, FALSE, 0); WorkerLast (6, FALSE, 0);
    WorkerLast (2, TRUE, ARGON2_OPERATION_CANCELLED); WorkerLast (6, TRUE, ARGON2_OPERATION_CANCELLED);
    WorkerLast (2, FALSE, ARGON2_MEMORY_ALLOCATION_ERROR);
    PublicationBoundaries ();

    /* Join every worker before releasing any request-owned allocation or event. */
    EncryptionThreadPoolStop ();
    FreeRequests ();
    printf ("PASS: %d KDF lifetime scenarios with %u workers\n", RequestCount, (unsigned) wanted);
    return 0;
}
