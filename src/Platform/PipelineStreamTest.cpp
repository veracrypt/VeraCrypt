/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Testing.h"
#include "PipelineStream.h"
#include "MemoryStream.h"
#include "Exception.h"

using namespace VeraCrypt;

namespace
{
    class EmptyStream : public Stream
    {
    public:
        uint64 Read (const BufferPtr &) { return 0; }
        void ReadCompleteBuffer (const BufferPtr &buffer)
        {
            if (buffer.Size() != 0) throw InsufficientData (SRC_POS);
        }
        void Write (const ConstBufferPtr &) { throw NotApplicable (SRC_POS); }
    };

    class ShortReadStream : public MemoryStream
    {
    public:
        explicit ShortReadStream (const ConstBufferPtr &data) : MemoryStream (data) { }
        uint64 Read (const BufferPtr &buffer)
        {
            return MemoryStream::Read (buffer.GetRange (0, std::min<size_t> (2, buffer.Size())));
        }
    };

    class FailingStream : public EmptyStream
    {
    public:
        FailingStream () : Reads (0) { }
        uint64 Read (const BufferPtr &)
        {
            ++Reads;
            throw InsufficientData (SRC_POS);
        }
        size_t Reads;
    };

    shared_ptr<Stream> Bytes (const string &bytes)
    {
        return make_shared<MemoryStream> (ConstBufferPtr (
            reinterpret_cast<const uint8*> (bytes.data()), bytes.size()));
    }

    void EmptyAndRepeatedEof (shared_ptr<TestResult> result)
    {
        PipelineStream stream;
        Buffer buffer (8);
        if (stream.Read (buffer) != 0) result->Failed ("Empty pipeline returned data");
        stream.AddStream (make_shared<EmptyStream>());
        stream.AddStream (Bytes ("abc"));
        stream.AddStream (make_shared<EmptyStream>());
        if (stream.Read (buffer) != 3 || memcmp (buffer.Ptr(), "abc", 3) != 0)
            result->Failed ("Empty source changed concatenated data");
        if (stream.Read (buffer) != 0 || stream.Read (buffer) != 0)
            result->Failed ("EOF was not stable");
        stream.AddStream (Bytes ("d"));
        if (stream.Read (buffer) != 1 || buffer[0] != 'd')
            result->Failed ("Source appended after EOF was lost");
    }

    void Concatenation (shared_ptr<TestResult> result)
    {
        for (size_t chunkSize : {size_t (1), size_t (3), size_t (16)})
        {
            PipelineStream stream;
            stream.AddStream (Bytes ("abc"));
            stream.AddStream (make_shared<EmptyStream>());
            stream.AddStream (Bytes ("defgh"));
            string actual;
            Buffer buffer (chunkSize);
            uint64 length;
            while ((length = stream.Read (buffer)) != 0)
                actual.append (reinterpret_cast<const char*> (buffer.Ptr()), static_cast<size_t> (length));
            if (actual != "abcdefgh") result->Failed ("Concatenated bytes differ");
        }
    }

    void CompleteBufferAcrossShortReads (shared_ptr<TestResult> result)
    {
        PipelineStream stream;
        stream.AddStream (Bytes ("abc"));
        string suffix = "defgh";
        stream.AddStream (make_shared<ShortReadStream> (ConstBufferPtr (
            reinterpret_cast<const uint8*> (suffix.data()), suffix.size())));
        Buffer buffer (8);
        stream.ReadCompleteBuffer (buffer);
        if (memcmp (buffer.Ptr(), "abcdefgh", 8) != 0)
            result->Failed ("ReadCompleteBuffer lost bytes across sources or short reads");
        bool rejected = false;
        try { stream.ReadCompleteBuffer (buffer); }
        catch (const InsufficientData &) { rejected = true; }
        if (!rejected) result->Failed ("Incomplete read was accepted");
    }

    void ZeroLengthRead (shared_ptr<TestResult> result)
    {
        PipelineStream stream;
        stream.AddStream (Bytes ("a"));
        stream.AddStream (Bytes ("b"));
        if (stream.Read (BufferPtr()) != 0) result->Failed ("Zero-length read returned bytes");
        stream.ReadCompleteBuffer (BufferPtr());
        Buffer buffer (2);
        stream.ReadCompleteBuffer (buffer);
        if (memcmp (buffer.Ptr(), "ab", 2) != 0)
            result->Failed ("Zero-length read advanced a source");
    }

    void RejectNullSource (shared_ptr<TestResult> result)
    {
        PipelineStream stream;
        bool rejected = false;
        try { stream.AddStream (shared_ptr<Stream>()); }
        catch (const ParameterIncorrect &) { rejected = true; }
        if (!rejected) result->Failed ("Null source accepted");
    }

    void PropagateReadFailure (shared_ptr<TestResult> result)
    {
        PipelineStream stream;
        auto failing = make_shared<FailingStream>();
        stream.AddStream (Bytes ("a"));
        stream.AddStream (failing);
        stream.AddStream (Bytes ("b"));
        Buffer buffer (2);
        for (size_t attempt = 0; attempt < 2; ++attempt)
        {
            bool rejected = false;
            try { stream.ReadCompleteBuffer (buffer); }
            catch (const InsufficientData &) { rejected = true; }
            if (!rejected) result->Failed ("Read error was hidden");
        }
        if (failing->Reads != 1) result->Failed ("Failed source was retried after partial consumption");
    }
}

int main ()
{
    Testing tests;
    tests.AddTest ("empty sources and stable EOF", EmptyAndRepeatedEof);
    tests.AddTest ("concatenation contents and read sizes", Concatenation);
    tests.AddTest ("complete buffer across sources and short reads", CompleteBufferAcrossShortReads);
    tests.AddTest ("zero-length reads preserve position", ZeroLengthRead);
    tests.AddTest ("null source rejection", RejectNullSource);
    tests.AddTest ("read failures remain fatal", PropagateReadFailure);
    return tests.Main();
}
