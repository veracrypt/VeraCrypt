/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0. */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <clocale>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>
#include "Volume/EncryptionThreadPool.h"
#include "Volume/Pkcs5Kdf.h"

using namespace VeraCrypt;

static std::atomic<int> Clones (0), LiveClones (0);
static thread_local bool FailNextAllocation;

void *operator new (size_t size)
{
    if (FailNextAllocation) { FailNextAllocation = false; throw std::bad_alloc(); }
    void *memory = std::malloc (size ? size : 1);
    if (!memory) throw std::bad_alloc();
    return memory;
}
void operator delete (void *memory) noexcept { std::free (memory); }
void *operator new[] (size_t size) { return ::operator new (size); }
void operator delete[] (void *memory) noexcept { ::operator delete (memory); }

static void Check (bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << message << std::endl;
        std::exit (1);
    }
}

struct TrackedException : Exception
{
    explicit TrackedException (bool stored = false) : Stored (stored)
    { if (Stored) ++LiveClones; }
    TrackedException (const TrackedException &other) : Exception (other), Stored (false) { }
    ~TrackedException () throw () { if (Stored) --LiveClones; }
    Exception *CloneNew () override { ++Clones; return new TrackedException (true); }
    void Throw () const override { throw *this; }
    bool Stored;
};

struct UncopyableException : Exception
{
    Exception *CloneNew () override { throw std::bad_alloc(); }
};

struct InvalidMessageException : std::exception
{
    // Invalid in the C locale: exercise the real exception formatter's failure.
    const char *what () const noexcept override { return "\xff"; }
};

class PoolView : public EncryptionThreadPool
{
public:
    static size_t Workers () { return ThreadCount; }
};

class TestMode : public EncryptionMode
{
public:
    enum Failure { None, Native, Standard, Unknown, CloneFailure, FormattingFailure, AllocationFailure };
    TestMode (size_t fragments, Failure failure)
        : Expected (fragments), Arrived (0), Kind (failure) { }

    void Encrypt (uint8 *, uint64) const override { throw NotApplicable (); }
    void Decrypt (uint8 *, uint64) const override { throw NotApplicable (); }
    void EncryptSectorsCurrentThread (uint8 *data, uint64, uint64 count, size_t sectorSize) const override
    { Process (data, count, sectorSize); }
    void DecryptSectorsCurrentThread (uint8 *data, uint64, uint64 count, size_t sectorSize) const override
    { Process (data, count, sectorSize); }
    size_t GetKeySize () const override { return 0; }
    std::wstring GetName () const override { return L"exception-test"; }
    shared_ptr<EncryptionMode> GetNew () const override { return shared_ptr<EncryptionMode> (); }
    void SetKey (const ConstBufferPtr &) override { }

private:
    void Process (uint8 *data, uint64 count, size_t sectorSize) const
    {
        FailNextAllocation = false;
        {
            std::unique_lock<std::mutex> lock (Gate);
            ++Arrived;
            Ready.notify_all ();
            Check (Ready.wait_for (lock, std::chrono::seconds (10), [this] { return Arrived == Expected; }),
                "fragment barrier timed out");
        }
        switch (Kind)
        {
        case Native: throw TrackedException ();
        case Standard: throw std::runtime_error ("fragment failure");
        case Unknown: throw 7;
        case CloneFailure: throw UncopyableException();
        case FormattingFailure: throw InvalidMessageException();
        case AllocationFailure: FailNextAllocation = true; throw 7;
        case None: std::memset (data, 0xa5, count * sectorSize); break;
        }
    }

    size_t Expected;
    mutable size_t Arrived;
    Failure Kind;
    mutable std::mutex Gate;
    mutable std::condition_variable Ready;
};

class TestKdf : public Pkcs5Kdf
{
public:
    explicit TestKdf (TestMode &mode) : Mode (mode) { }
    int DeriveKey (const BufferPtr &key, const VolumePassword &, const ConstBufferPtr &, int) const override
    { Mode.EncryptSectorsCurrentThread (key.Get(), 0, 1, key.Size()); return 0; }
    int DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterations, long volatile *) const override
    { return DeriveKey (key, password, salt, iterations); }
    shared_ptr<VeraCrypt::Hash> GetHash () const override { return shared_ptr<VeraCrypt::Hash>(); }
    int GetIterationCount (int) const override { return 1; }
    std::wstring GetName () const override { return L"exception-test"; }
    Pkcs5Kdf *Clone () const override { return new TestKdf (Mode); }
private:
    TestMode &Mode;
};

// The runner extracts the actual drain and exception checks from VolumeHeader.cpp.
#include "kdf_exception_completion.inc"

static int KdfExceptions (size_t width)
{
    for (int kind = TestMode::None; kind <= TestMode::AllocationFailure; ++kind)
    {
        TestMode mode (width, static_cast<TestMode::Failure> (kind));
        shared_ptr<Pkcs5Kdf> kdf (new TestKdf (mode));
        VolumePassword password;
        uint8 salt[64] = {};
        SyncEvent completed, noOutstandingWorkItemEvent;
        SharedVal<size_t> outstanding (0);
        long volatile abortKeyDerivation = 0;
        bool workItemsDrained = false;
        std::vector<shared_ptr<EncryptionThreadPool::KeyDerivationWorkItem>> items;
        for (size_t i = 0; i < width; ++i)
        {
            shared_ptr<EncryptionThreadPool::KeyDerivationWorkItem> item (new EncryptionThreadPool::KeyDerivationWorkItem (kdf, 64));
            items.push_back (item);
            EncryptionThreadPool::BeginKeyDerivation (*item, password, 0, ConstBufferPtr (salt, sizeof salt), completed, noOutstandingWorkItemEvent, outstanding, &abortKeyDerivation);
        }
        while (!std::all_of (items.begin(), items.end(), [] (const shared_ptr<EncryptionThreadPool::KeyDerivationWorkItem> &item) { return item->Completed.Get(); }))
            completed.Wait();
        for (const auto &item : items)
        {
            int observed = TestMode::None;
            try { HandleKdfFailure (item, noOutstandingWorkItemEvent, width, workItemsDrained, abortKeyDerivation); }
            catch (const TrackedException &) { observed = TestMode::Native; }
            catch (const ExternalException &) { observed = TestMode::Standard; }
            catch (const UnknownException &) { observed = TestMode::Unknown; }
            Check (observed == std::min (kind, static_cast<int> (TestMode::Unknown)), "KDF failure was lost or changed");
            Check (item->ExceptionCaptureFailed == (kind >= TestMode::CloneFailure), "KDF capture failure was not recorded");
            if (kind == TestMode::None)
                for (size_t i = 0; i < item->DerivedKey.Size(); ++i) Check (item->DerivedKey[i] == 0xa5, "KDF recovery failed");
        }
        DrainKeyDerivationWorkItems (noOutstandingWorkItemEvent, width, workItemsDrained);
        Check (outstanding.Get() == 0, "KDF drain returned early");
        Check (kind == TestMode::None || abortKeyDerivation == 1, "KDF failure did not abort the header read");
    }
    return TestMode::AllocationFailure + 1;
}

int main ()
{
    std::setlocale (LC_CTYPE, "C");
    EncryptionThreadPool::Start ();
    if (!EncryptionThreadPool::IsRunning ())
    {
        std::cout << "SKIP: at least two logical CPUs required" << std::endl;
        return 77;
    }
    size_t widths[] = { 2, std::min<size_t> (8, PoolView::Workers ()) };
    int checks = 0;
    for (size_t width : widths)
    {
        std::vector<uint8> data (width * ENCRYPTION_DATA_UNIT_SIZE);
        for (int direction = 0; direction < 2; ++direction)
        {
            auto type = direction ? EncryptionThreadPool::WorkType::DecryptDataUnits : EncryptionThreadPool::WorkType::EncryptDataUnits;
            for (int kind = TestMode::Native; kind <= TestMode::AllocationFailure; ++kind)
            {
                TestMode mode (width, static_cast<TestMode::Failure> (kind));
                int observed = TestMode::None;
                Clones = 0;
                try { EncryptionThreadPool::DoWork (type, &mode, data.data (), 0, width, ENCRYPTION_DATA_UNIT_SIZE); }
                catch (const TrackedException &) { observed = TestMode::Native; }
                catch (const ExternalException &) { observed = TestMode::Standard; }
                catch (const UnknownException &) { observed = TestMode::Unknown; }
                Check (observed == std::min (kind, static_cast<int> (TestMode::Unknown)), "requester received the wrong exception");
                Check (LiveClones == 0, "stored exception leaked");
                if (kind == TestMode::Native) Check (Clones == 1, "more than one fragment exception retained");
                ++checks;
            }
            std::fill (data.begin (), data.end (), 0);
            TestMode success (width, TestMode::None);
            EncryptionThreadPool::DoWork (type, &success, data.data (), 0, width, ENCRYPTION_DATA_UNIT_SIZE);
            for (uint8 byte : data) Check (byte == 0xa5, "pool failed after exception propagation");
            ++checks;
        }
        checks += KdfExceptions (width);
    }
    EncryptionThreadPool::Stop ();
    Check (LiveClones == 0, "stored KDF exception leaked");
    std::cout << "PASS: " << checks << " fragment/KDF exception, capture-failure and recovery checks" << std::endl;
}
