/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0.
 * Bounded user-mode checks of the production Windows KDF reference protocol.
 * Build through test_windows_kdf_completion.py, which supplies caller excerpts.
 */
#include "Common/EncryptionThreadPool.h"
#include "Common/Pkcs5.h"
#include <stdio.h>

static BOOL TestSetEvent (HANDLE event);
static DWORD TestWait (HANDLE event);
#undef TC_WAIT_EVENT
#define TC_WAIT_EVENT(event) TestWait (event)
#define SetEvent TestSetEvent
#include "Common/EncryptionThreadPool.c"
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

static void Require (BOOL condition, const char *message)
{
    if (!condition)
    {
        fprintf (stderr, "FAIL: %s\n", message);
        ExitProcess (1);
    }
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
    if (DrainingRequest && event == *DrainingRequest->Drained)
        SetEvent (DrainingRequest->WaitEntered);
    return WaitForSingleObject (event, INFINITE);
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
    int keyDerivationWorkItemsSize = 0, pkcs5PrfCount = PRF_COUNT, i;
#include "kdf_init.inc"
    request->Ready = keyDerivationCompletedEvent;
    request->Drained = noOutstandingWorkItemEvent;
    request->References = outstandingWorkItemCount;
    request->Items = keyDerivationWorkItems;
    return 0;
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

static Job *Submit (Request *request, int prf, BOOL holdAfterReady, int result)
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
    EncryptionThreadPoolBeginKeyDerivation (request->Ready, request->Drained, &job->Item->KeyReady,
        request->References, prf, (unsigned char *) job, sizeof (*job), NULL, 1, 8,
        job->Item->DerivedKey, &job->Item->DerivationResult, &request->Abort);
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
void EncryptDataUnitsCurrentThread (unsigned __int8 *data, const UINT64_STRUCT *start, TC_LARGEST_COMPILER_UINT count, PCRYPTO_INFO ci) { }
void DecryptDataUnitsCurrentThread (unsigned __int8 *data, const UINT64_STRUCT *start, TC_LARGEST_COMPILER_UINT count, PCRYPTO_INFO ci) { }

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

int main (int argc, char **argv)
{
    WORD groups;
    size_t available = GetCpuCount (&groups);
    size_t wanted = argc > 1 ? (size_t) atoi (argv[1]) : 2;
    int i, j;
    if (available < 2) { puts ("SKIP: at least two logical CPUs required"); return 0; }
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
    printf ("PASS: %d KDF lifetime scenarios with %u workers\n", RequestCount, (unsigned) wanted);
    return 0;
}
