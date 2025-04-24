#include <cstddef>

#include "Testing.h"
#include "PipelineStream.h"
#include "MemoryStream.h"
#include "Stream.h"


using namespace VeraCrypt; 

#define MK(type, name) shared_ptr<type> name = shared_ptr<type>(new type());

size_t ReadFully(shared_ptr<Stream> s, Buffer *rb, int chunkSize = 10) {
    vector<Buffer*> buffers;
    vector<int> lengths;
    size_t n = 0;
    size_t tot = 0;
    Buffer *buff = new Buffer(chunkSize);
    while ((n = s->Read(*buff)) > 0) {
        buffers.push_back(buff);
        lengths.push_back(n);
        buff = new Buffer(chunkSize);
        tot += n;
    }

    Buffer *buffer = new Buffer(tot);
    size_t offset = 0;
    for (size_t i = 0; i < buffers.size(); i++) {
        memcpy(buffer->Ptr()+offset, buffers[i]->GetRange(0, lengths[i]), lengths[i]);
        offset += lengths[i];
    }
    rb = buffer;
    return tot;
}


void FillBuffer(Buffer &buff) {
    uint8 *b = buff.Ptr();
    for (auto i = 0; i < buff.Size(); ++i) {
        b[i] = i+1;
    }
}

void EmptyTest(shared_ptr<TestResult> r) {
    PipelineStream s;

    Buffer buff(1);
    size_t n = s.Read(buff);

    r->Info("N" + to_string(n));
    if (n != 0) {
        r->Failed("read some data, expected none");
    }
}

void SingleByteSingleStreamTest(shared_ptr<TestResult> r) {
    Buffer buff(1);
    FillBuffer(buff);

    auto m = make_shared<MemoryStream>(buff);

    MK(PipelineStream, s);
    s->AddStream(m);

    Buffer *rb = nullptr;
    size_t n = ReadFully(s, rb);
    r->Info("N" + to_string(n));
    if (n != 1) {
        r->Failed("Expected 1 byte");
    }

}

void SingleByteTwoStreamsTest(shared_ptr<TestResult> r) {
    Buffer buf1(1);
    Buffer buf2(1);

    FillBuffer(buf1);
    FillBuffer(buf2);

    auto m1 = make_shared<MemoryStream>(buf1);
    auto m2 = make_shared<MemoryStream>(buf2);

    MK(PipelineStream, s);
    s->AddStream(m1);
    s->AddStream(m2);


    Buffer *rb = nullptr;
    size_t n = ReadFully(s, rb);
    r->Info("N" + to_string(n));
    if (n != 2) {
        r->Failed("Expected 2 bytes");
    }

}



void LongStreamAndSingleByteStreamTest(shared_ptr<TestResult> r) {
    Buffer buf1(10);
    Buffer buf2(1);
    FillBuffer(buf1);
    FillBuffer(buf2);

    auto m1 = make_shared<MemoryStream>(buf1);
    auto m2 = make_shared<MemoryStream>(buf2);

    MK(PipelineStream,s);
    s->AddStream(m1);
    s->AddStream(m2);

    Buffer *rb = nullptr;
    size_t n = ReadFully(s, rb);
    r->Info("N" + to_string(n));
    if (n != 11) {
        r->Failed("Expected 11 bytes");
    }
}

void ReadWholeStreamAtOnceTest(shared_ptr<TestResult> r) {
    Buffer buf1(10);
    Buffer buf2(5);
    FillBuffer(buf1);
    FillBuffer(buf2);

    auto m1 = make_shared<MemoryStream>(buf1);
    auto m2 = make_shared<MemoryStream>(buf2);

    MK(PipelineStream, s);
    s->AddStream(m1);
    s->AddStream(m2);

    Buffer *rb = nullptr;
    size_t n = ReadFully(s, rb, 20);
    r->Info("N" + to_string(n));
    if (n != 15) {
        r->Failed("Expected 15 bytes");
    }
}

void ReadStreamByteByByteTest(shared_ptr<TestResult> r) {
    Buffer buf1(10);
    Buffer buf2(1);
    FillBuffer(buf1);
    FillBuffer(buf2);

    auto m1 = make_shared<MemoryStream>(buf1);
    auto m2 = make_shared<MemoryStream>(buf2);

    MK(PipelineStream, s);
    s->AddStream(m1);
    s->AddStream(m2);

    Buffer *rb = nullptr;
    size_t n = ReadFully(s, rb, 1);
    r->Info("N" + to_string(n));
    if (n != 11) {
        r->Failed("Expected 11 bytes");
    }
}

int main() {
    VeraCrypt::Testing t;
    t.AddTest("empty", &EmptyTest);
    t.AddTest("single byte single stream", &SingleByteSingleStreamTest);
    t.AddTest("two single byte streams", &SingleByteTwoStreamsTest);
    t.AddTest("long stream and single byte stream", &LongStreamAndSingleByteStreamTest);
    t.AddTest("read full stream at once", &ReadWholeStreamAtOnceTest);
    t.AddTest("read byte by byte", &ReadStreamByteByByteTest);
    t.Main();
};

