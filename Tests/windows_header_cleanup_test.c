/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0. */
#include "Common/EncryptionThreadPool.h"
#include "Common/Password.h"
#include "Common/Volumes.h"
#include <stdio.h>

typedef struct { void *Pointer; size_t Size; BOOL Open; } Allocation;
typedef struct { void *Pointer; size_t Size; BOOL Locked; } LockedRange;
static Allocation Allocations[32];
static LockedRange Locks[32];
static HANDLE Events[8];
static int AllocationCount, LockCount, EventCount, Attempts, FailAt, TestHeaderError, Checks;
static size_t PoolThreads;
static CRYPTO_INFO BorrowedCrypto;

static void Require (BOOL condition, const char *message)
{
    if (!condition) { fprintf (stderr, "FAIL: %s (failure point %d)\n", message, FailAt); ExitProcess (1); }
}

static BOOL Fail (void) { return ++Attempts == FailAt; }

static void *TestAlloc (size_t size)
{
    void *memory;
    Allocation *allocation;
    if (Fail()) return NULL;
    Require (AllocationCount < 32, "allocation fixture capacity");
    memory = malloc (size);
    Require (memory != NULL, "fixture allocation");
    memset (memory, 0xa6, size);
    allocation = &Allocations[AllocationCount++];
    allocation->Pointer = memory;
    allocation->Size = size;
    allocation->Open = TRUE;
    return memory;
}

static void TestFree (void *memory)
{
    int i;
    for (i = AllocationCount - 1; i >= 0; --i)
        if (Allocations[i].Open && Allocations[i].Pointer == memory)
        {
            Allocations[i].Open = FALSE;
            free (memory);
            return;
        }
    Require (FALSE, "unknown allocation or double free");
}

static BOOL TestLock (void *memory, size_t size)
{
    LockedRange *range;
    Require (LockCount < 32, "lock fixture capacity");
    range = &Locks[LockCount++];
    range->Pointer = memory;
    range->Size = size;
    range->Locked = TRUE;
    return TRUE;
}

static BOOL TestUnlock (void *memory, size_t size)
{
    int i;
    for (i = LockCount - 1; i >= 0; --i)
        if (Locks[i].Locked && Locks[i].Pointer == memory && Locks[i].Size == size)
        {
            Locks[i].Locked = FALSE;
            return TRUE;
        }
    Require (FALSE, "unlock of an uninitialized range");
    return FALSE;
}

static HANDLE TestCreateEvent (void *attributes, BOOL manual, BOOL initial, void *name)
{
    HANDLE event;
    if (Fail()) return NULL;
    Require (EventCount < 8, "event fixture capacity");
    event = CreateEventW (attributes, manual, initial, name);
    Require (event != NULL, "fixture event creation");
    Events[EventCount++] = event;
    return event;
}

static BOOL TestClose (HANDLE event)
{
    int i;
    for (i = 0; i < EventCount; ++i)
        if (Events[i] == event && event != NULL)
        {
            Events[i] = NULL;
            return CloseHandle (event);
        }
    Require (FALSE, "close of an uninitialized event");
    return FALSE;
}

static PCRYPTO_INFO TestCryptoOpen (void) { return TestAlloc (sizeof (CRYPTO_INFO)); }
static void TestCryptoClose (PCRYPTO_INFO cryptoInfo)
{
    Require (cryptoInfo != &BorrowedCrypto, "closed a borrowed crypto context");
    TestFree (cryptoInfo);
}
static size_t TestThreads (void) { return PoolThreads; }
static void TestWait (HANDLE event) { (void) event; Require (FALSE, "wait without submitted workers"); }

#undef TCalloc
#undef TCfree
#undef TC_WAIT_EVENT
#undef burn
#define TCalloc TestAlloc
#define TCfree TestFree
#define TC_WAIT_EVENT(event) TestWait (event)
#define burn(memory,size) memset (memory, 0, size)
#define crypto_open TestCryptoOpen
#define crypto_close TestCryptoClose
#define VirtualLock TestLock
#define VirtualUnlock TestUnlock
#define CreateEventW TestCreateEvent
#define CloseHandle TestClose
#define GetEncryptionThreadCount TestThreads
#include "kdf_item.inc"
#include "header_cleanup.inc"

static int Run (int failure, BOOL borrowed, BOOL missingOutput, int prf, size_t threads, BOOL headerError)
{
    PCRYPTO_INFO result = NULL;
    int status, i;
    AllocationCount = LockCount = EventCount = Attempts = 0;
    FailAt = failure;
    PoolThreads = threads;
    TestHeaderError = headerError;
    status = ReadVolumeHeaderWithAbort (FALSE, NULL, NULL, prf, 0,
        missingOutput ? NULL : &result, borrowed ? &BorrowedCrypto : NULL, NULL, NULL);
    if (failure) Require (status == ERR_OUTOFMEMORY, "allocation failure returned the wrong status");
    else if (missingOutput && !borrowed) Require (status == ERR_PARAMETER_INCORRECT, "missing output accepted");
    else Require (status == (headerError ? ERR_PASSWORD_WRONG : ERR_SUCCESS), "header status changed");
    if (status != ERR_SUCCESS) Require (result == NULL, "failed header retained owned crypto context");
    if (result) TestCryptoClose (result);
    for (i = 0; i < AllocationCount; ++i) Require (!Allocations[i].Open, "allocation leaked");
    for (i = 0; i < LockCount; ++i) Require (!Locks[i].Locked, "locked range leaked");
    for (i = 0; i < EventCount; ++i) Require (!Events[i], "event leaked");
    ++Checks;
    return Attempts;
}

int main (void)
{
    int borrowed, setup, error;
    for (borrowed = 0; borrowed <= 1; ++borrowed)
        for (setup = 0; setup < 3; ++setup)
            for (error = 0; error <= 1; ++error)
            {
                int prf = setup == 1 ? 1 : 0;
                size_t threads = setup == 2 ? 1 : 2;
                int attempts = Run (0, borrowed, borrowed, prf, threads, error), failure;
                for (failure = 1; failure <= attempts; ++failure)
                    Run (failure, borrowed, borrowed, prf, threads, error);
            }
    Run (0, FALSE, TRUE, 0, 2, FALSE);
    printf ("PASS: %d header setup/cleanup scenarios, including every allocation/event failure and borrowed contexts\n", Checks);
    return 0;
}
