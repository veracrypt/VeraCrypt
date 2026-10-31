/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0. */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>
#include <unistd.h>
#include "Volume/EncryptionThreadPool.h"
#include "Volume/Pkcs5Kdf.h"

using namespace VeraCrypt;

static thread_local int AllocationCalls, FailAllocationAt;
void *operator new (size_t size)
{
    if (++AllocationCalls == FailAllocationAt)
    {
        FailAllocationAt = 0;
        throw std::bad_alloc();
    }
    void *memory = std::malloc (size ? size : 1);
    if (!memory) throw std::bad_alloc();
    return memory;
}
void operator delete (void *memory) noexcept { std::free (memory); }
void *operator new[] (size_t size) { return ::operator new (size); }
void operator delete[] (void *memory) noexcept { ::operator delete (memory); }

static void Check (bool condition, const char *message)
{
    if (!condition) { std::cerr << "FAIL: " << message << std::endl; std::exit (1); }
}

template <class Predicate> static void Until (Predicate predicate)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds (10);
    while (!predicate())
    {
        Check (std::chrono::steady_clock::now() < deadline, "barrier timed out");
        std::this_thread::yield();
    }
}

class Gate
{
public:
    Gate () : Arrivals (0), Open (false) { }
    void Enter ()
    {
        std::unique_lock<std::mutex> lock (Mutex);
        ++Arrivals;
        Changed.notify_all();
        Check (Changed.wait_for (lock, std::chrono::seconds (10), [this] { return Open; }), "gate timed out");
    }
    void Wait (size_t count = 1)
    {
        std::unique_lock<std::mutex> lock (Mutex);
        Check (Changed.wait_for (lock, std::chrono::seconds (10), [=] { return Arrivals >= count; }), "arrival timed out");
    }
    void Release () { std::lock_guard<std::mutex> lock (Mutex); Open = true; Changed.notify_all(); }
private:
    std::mutex Mutex;
    std::condition_variable Changed;
    size_t Arrivals;
    bool Open;
};

class PoolView : public EncryptionThreadPool
{
public:
    static void LockQueue () { DequeueMutex.Lock(); }
    static void UnlockQueue () { DequeueMutex.Unlock(); }
    static void LockSubmit () { EnqueueMutex.Lock(); }
    static void UnlockSubmit () { EnqueueMutex.Unlock(); }
    static bool Closing () { return (PoolReferences.load() & PoolClosing) != 0; }
    static size_t References () { return PoolReferences.load() & ~PoolClosing; }
    static bool Empty () { return RunningThreads.empty() && ThreadCount == 0 && References() == 0; }
    static SyncEvent *NextCompletion () { return &WorkItemQueue[EnqueuePosition].ItemCompletedEvent; }
    static SyncEvent *SlotAvailable () { return &WorkItemCompletedEvent; }
    static size_t Ready ()
    {
        size_t count = 0;
        for (size_t i = 0; i < QueueSize; ++i) if (WorkItemQueue[i].State == WorkItem::State::Ready) ++count;
        return count;
    }
};

static int CpuCount = 2, CreateCalls, JoinCalls, FailCreateAt;
static std::atomic<SyncEvent *> PausedWait (nullptr), PausedSignal (nullptr);
static Gate *WaitGate, *SignalGate;
extern "C" long __real_sysconf (int);
extern "C" long __wrap_sysconf (int name) { return name == _SC_NPROCESSORS_ONLN ? CpuCount : __real_sysconf (name); }
extern "C" int __real_pthread_create (pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern "C" int __wrap_pthread_create (pthread_t *thread, const pthread_attr_t *attr, void *(*proc)(void *), void *arg)
{
    if (++CreateCalls == FailCreateAt) return EAGAIN;
    return __real_pthread_create (thread, attr, proc, arg);
}
extern "C" int __real_pthread_join (pthread_t, void **);
extern "C" int __wrap_pthread_join (pthread_t thread, void **result)
{
    ++JoinCalls;
    int status = __real_pthread_join (thread, result);
    Check (status == 0, "invalid/repeated worker join");
    return status;
}
extern "C" void __real__ZN9VeraCrypt9SyncEvent4WaitEv (SyncEvent *);
extern "C" void __wrap__ZN9VeraCrypt9SyncEvent4WaitEv (SyncEvent *event)
{
    __real__ZN9VeraCrypt9SyncEvent4WaitEv (event);
    if (event == PausedWait.load()) WaitGate->Enter();
}
extern "C" void __real__ZN9VeraCrypt9SyncEvent6SignalEv (SyncEvent *);
extern "C" void __wrap__ZN9VeraCrypt9SyncEvent6SignalEv (SyncEvent *event)
{
    __real__ZN9VeraCrypt9SyncEvent6SignalEv (event);
    SyncEvent *expected = event;
    if (PausedSignal.compare_exchange_strong (expected, nullptr)) SignalGate->Enter();
}

class TestMode : public EncryptionMode
{
public:
    explicit TestMode (Gate *gate = nullptr) : Calls (0), Barrier (gate) { }
    void Encrypt (uint8 *, uint64) const override { throw NotApplicable(); }
    void Decrypt (uint8 *, uint64) const override { throw NotApplicable(); }
    void EncryptSectorsCurrentThread (uint8 *data, uint64, uint64 count, size_t size) const override { Process (data, count * size); }
    void DecryptSectorsCurrentThread (uint8 *data, uint64, uint64 count, size_t size) const override { Process (data, count * size); }
    size_t GetKeySize () const override { return 0; }
    std::wstring GetName () const override { return L"lifecycle-test"; }
    shared_ptr<EncryptionMode> GetNew () const override { return shared_ptr<EncryptionMode>(); }
    void SetKey (const ConstBufferPtr &) override { }
    mutable std::atomic<int> Calls;
private:
    void Process (uint8 *data, size_t size) const
    {
        ++Calls;
        if (Barrier) Barrier->Enter();
        std::memset (data, 0xa5, size);
    }
    Gate *Barrier;
};

class TestKdf : public Pkcs5Kdf
{
public:
    explicit TestKdf (Gate *gate = nullptr) : Barrier (gate) { }
    int DeriveKey (const BufferPtr &key, const VolumePassword &, const ConstBufferPtr &, int) const override
    { if (Barrier) Barrier->Enter(); std::memset (key.Get(), 0x5a, key.Size()); return 0; }
    int DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int count, long volatile *) const override
    { return DeriveKey (key, password, salt, count); }
    shared_ptr<VeraCrypt::Hash> GetHash () const override { return shared_ptr<VeraCrypt::Hash>(); }
    int GetIterationCount (int) const override { return 1; }
    std::wstring GetName () const override { return L"lifecycle-test"; }
    Pkcs5Kdf *Clone () const override { return new TestKdf (Barrier); }
private:
    Gate *Barrier;
};

struct KdfRequest
{
    VolumePassword Password;
    uint8 Salt[64] = {};
    SyncEvent Completed, Drained;
    SharedVal<size_t> Outstanding;
    std::vector<shared_ptr<EncryptionThreadPool::KeyDerivationWorkItem>> Items;
    KdfRequest () : Outstanding (0) { }
    void Submit (Gate *gate = nullptr)
    {
        shared_ptr<Pkcs5Kdf> kdf (new TestKdf (gate));
        shared_ptr<EncryptionThreadPool::KeyDerivationWorkItem> item (new EncryptionThreadPool::KeyDerivationWorkItem (kdf, 64));
        Items.push_back (item);
        EncryptionThreadPool::BeginKeyDerivation (*item, Password, 0, ConstBufferPtr (Salt, sizeof Salt), Completed, Drained, Outstanding, nullptr);
    }
    void Verify ()
    {
        Drained.Wait();
        Check (Outstanding.Get() == 0, "KDF drain returned early");
        for (const auto &item : Items)
        {
            Check (item->Completed.Get() && item->Result == 0 && !item->ItemException.get(), "KDF completion lost");
            for (size_t i = 0; i < item->DerivedKey.Size(); ++i) Check (item->DerivedKey[i] == 0x5a, "KDF output incomplete");
        }
    }
};

static void Join (std::future<void> &task)
{
    Check (task.wait_for (std::chrono::seconds (10)) == std::future_status::ready, "task hung");
    task.get();
}
static void StillWaiting (std::future<void> &stop)
{ Check (stop.wait_for (std::chrono::milliseconds (50)) == std::future_status::timeout, "shutdown returned before its users"); }

static void CipherShutdown (bool queued, EncryptionThreadPool::WorkType::Enum type)
{
    if (queued) PoolView::LockQueue();
    EncryptionThreadPool::Start();
    Gate workers, requester;
    TestMode mode (queued ? nullptr : &workers);
    std::vector<uint8> data (CpuCount * 2 * ENCRYPTION_DATA_UNIT_SIZE);
    WaitGate = &requester;
    PausedWait = PoolView::NextCompletion();
    auto work = std::async (std::launch::async, [&] { EncryptionThreadPool::DoWork (type, &mode, data.data(), 0, CpuCount * 2, ENCRYPTION_DATA_UNIT_SIZE); });
    if (queued) Until ([] { return PoolView::Ready() == static_cast<size_t> (CpuCount); });
    else workers.Wait (CpuCount);
    auto stop = std::async (std::launch::async, [] { EncryptionThreadPool::Stop(); });
    Until ([] { return PoolView::Closing(); });
    StillWaiting (stop);
    TestMode inlineMode;
    uint8 inlineData[2 * ENCRYPTION_DATA_UNIT_SIZE] = {};
    EncryptionThreadPool::DoWork (type, &inlineMode, inlineData, 0, 2, ENCRYPTION_DATA_UNIT_SIZE);
    Check (inlineMode.Calls == 1 && inlineData[sizeof inlineData - 1] == 0xa5, "late cipher did not run inline");
    if (queued) PoolView::UnlockQueue(); else workers.Release();
    requester.Wait();
    StillWaiting (stop);
    requester.Release();
    Join (work);
    Join (stop);
    PausedWait = nullptr;
    for (uint8 byte : data) Check (byte == 0xa5, "accepted cipher work was abandoned");
    Check (PoolView::Empty(), "cipher shutdown retained pool users");
}

static void KdfShutdown ()
{
    EncryptionThreadPool::Start();
    Gate workers, finishing;
    KdfRequest request;
    for (int i = 0; i < CpuCount + 2; ++i) request.Submit (&workers);
    workers.Wait (CpuCount);
    SignalGate = &finishing;
    PausedSignal = PoolView::SlotAvailable();
    auto stop = std::async (std::launch::async, [] { EncryptionThreadPool::Stop(); });
    Until ([] { return PoolView::Closing(); });
    StillWaiting (stop);
    KdfRequest inlineRequest;
    inlineRequest.Submit();
    inlineRequest.Verify();
    request.Submit();
    auto drain = std::async (std::launch::async, [&] { request.Verify(); });
    StillWaiting (drain);
    workers.Release();
    finishing.Wait();
    Join (drain);
    StillWaiting (stop);
    finishing.Release();
    Join (stop);
    Check (PoolView::Empty(), "KDF shutdown retained pool users");
}

static void BlockedSubmitter ()
{
    EncryptionThreadPool::Start();
    PoolView::LockSubmit();
    KdfRequest request;
    auto submit = std::async (std::launch::async, [&] { request.Submit(); });
    Until ([] { return PoolView::References() == 1; });
    auto stop = std::async (std::launch::async, [] { EncryptionThreadPool::Stop(); });
    Until ([] { return PoolView::Closing(); });
    StillWaiting (stop);
    PoolView::UnlockSubmit();
    Join (submit);
    request.Verify();
    Join (stop);
    Check (PoolView::Empty(), "submitter shutdown retained pool users");
}

static void StartupFailures ()
{
    for (int failure = 1; failure <= CpuCount; ++failure)
    {
        CreateCalls = JoinCalls = 0;
        FailCreateAt = failure;
        bool failed = false;
        try { EncryptionThreadPool::Start(); } catch (const SystemException &) { failed = true; }
        Check (failed && !EncryptionThreadPool::IsRunning(), "thread failure did not fail startup");
        Check (JoinCalls == failure - 1 && PoolView::Empty(), "partial startup did not join its workers");
        FailCreateAt = 0;
        EncryptionThreadPool::Start();
        EncryptionThreadPool::Stop();
        Check (PoolView::Empty(), "restart retained joined threads");
    }
    AllocationCalls = 0;
    EncryptionThreadPool::Start();
    int allocations = AllocationCalls;
    EncryptionThreadPool::Stop();
    for (int failure = 1; failure <= allocations; ++failure)
    {
        AllocationCalls = CreateCalls = JoinCalls = 0;
        FailAllocationAt = failure;
        bool failed = false;
        try { EncryptionThreadPool::Start(); } catch (const std::bad_alloc &) { failed = true; }
        Check (failed && !EncryptionThreadPool::IsRunning(), "allocation failure did not fail startup");
        Check (CreateCalls == JoinCalls && PoolView::Empty(), "allocation failure left an unjoined worker");
        EncryptionThreadPool::Start();
        EncryptionThreadPool::Stop();
        Check (PoolView::Empty(), "allocation-failure restart retained joined threads");
    }
}

int main (int argc, char **argv)
{
    if (argc > 1) CpuCount = std::atoi (argv[1]);
    StartupFailures();
    for (auto type : { EncryptionThreadPool::WorkType::EncryptDataUnits, EncryptionThreadPool::WorkType::DecryptDataUnits })
    {
        CipherShutdown (true, type);
        CipherShutdown (false, type);
    }
    KdfShutdown();
    BlockedSubmitter();
    KdfRequest stopped;
    stopped.Submit();
    stopped.Verify();
    std::cout << "PASS: " << CpuCount << " workers: startup failures/restarts, queued/active cipher work, requester drain, KDF drain, blocked submitter and inline fallback" << std::endl;
}
