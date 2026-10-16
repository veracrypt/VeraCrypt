/* Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0. */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>
#include "Volume/EncryptionThreadPool.h"

using namespace VeraCrypt;

static std::atomic<int> Clones (0), LiveClones (0);

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

class PoolView : public EncryptionThreadPool
{
public:
    static size_t Workers () { return ThreadCount; }
};

class TestMode : public EncryptionMode
{
public:
    enum Failure { None, Native, Standard, Unknown };
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
        case None: std::memset (data, 0xa5, count * sectorSize); break;
        }
    }

    size_t Expected;
    mutable size_t Arrived;
    Failure Kind;
    mutable std::mutex Gate;
    mutable std::condition_variable Ready;
};

int main ()
{
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
            for (int kind = TestMode::Native; kind <= TestMode::Unknown; ++kind)
            {
                TestMode mode (width, static_cast<TestMode::Failure> (kind));
                int observed = TestMode::None;
                Clones = 0;
                try { EncryptionThreadPool::DoWork (type, &mode, data.data (), 0, width, ENCRYPTION_DATA_UNIT_SIZE); }
                catch (const TrackedException &) { observed = TestMode::Native; }
                catch (const ExternalException &) { observed = TestMode::Standard; }
                catch (const UnknownException &) { observed = TestMode::Unknown; }
                Check (observed == kind, "requester received the wrong exception");
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
    }
    EncryptionThreadPool::Stop ();
    std::cout << "PASS: " << checks << " fragment exception and recovery checks" << std::endl;
}
