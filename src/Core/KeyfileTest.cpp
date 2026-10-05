/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Testing.h"
#include "Volume/Keyfile.h"
#include "Volume/VolumeException.h"
#include "Common/MockSecurityToken.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace VeraCrypt;

namespace
{
    const wstring TokenDescriptor = L"test token key";

    class TestToken : public MockSecurityTokenImpl
    {
    public:
        enum Fault { None, EmptyScheme, HugeScheme, WrongEncryptSize, WrongDecryptSize, EncryptError, DecryptError };
        TestToken () : Failure (None) { }
        void GetSecurityTokenScheme (wstring descriptor, SecurityTokenScheme &scheme, SecurityTokenKeyOperation operation)
        {
            MockSecurityTokenImpl::GetSecurityTokenScheme (descriptor, scheme, operation);
            if (Failure == EmptyScheme) scheme.DecryptOutputSize = 0;
            if (Failure == HugeScheme) scheme.EncryptOutputSize = Keyfile::MaxProcessedLength + 1;
        }
        void GetEncryptedData (const SecurityTokenScheme &scheme, const vector<uint8> &plaintext, vector<uint8> &ciphertext)
        {
            if (Failure == EncryptError) throw Pkcs11Exception (CKR_FUNCTION_FAILED);
            MockSecurityTokenImpl::GetEncryptedData (scheme, plaintext, ciphertext);
            if (Failure == WrongEncryptSize) ciphertext.resize (ciphertext.size() - 1);
        }
        void GetDecryptedData (const SecurityTokenScheme &scheme, const vector<uint8> &ciphertext, vector<uint8> &plaintext)
        {
            if (Failure == DecryptError) throw Pkcs11Exception (CKR_FUNCTION_FAILED);
            MockSecurityTokenImpl::GetDecryptedData (scheme, ciphertext, plaintext);
            if (Failure == WrongDecryptSize) plaintext.resize (plaintext.size() - 1);
        }
        Fault Failure;
    };

    class Fixture
    {
    public:
        Fixture () : Token (make_shared<TestToken>())
        {
            char name[] = "/tmp/veracrypt-keyfile-test-XXXXXX";
            char *directory = mkdtemp (name);
            if (!directory) throw SystemException (SRC_POS);
            Directory = directory;
            SecurityToken::UseImpl (Token);
        }
        ~Fixture ()
        {
            DIR *directory = opendir (Directory.c_str());
            if (directory)
            {
                while (dirent *entry = readdir (directory))
                {
                    string name = entry->d_name;
                    if (name == "." || name == "..") continue;
                    string path = Directory + "/" + name;
                    unlink (path.c_str());
                    rmdir (path.c_str());
                }
                closedir (directory);
            }
            rmdir (Directory.c_str());
        }
        FilePath Path (const string &name) const { return Directory + "/" + name; }
        bool HasTemporaryFiles () const
        {
            DIR *directory = opendir (Directory.c_str());
            if (!directory) throw SystemException (SRC_POS);
            bool found = false;
            while (dirent *entry = readdir (directory))
                if (string (entry->d_name).find (".tmp-") != string::npos) found = true;
            closedir (directory);
            return found;
        }
        shared_ptr<TestToken> Token;
    private:
        string Directory;
    };

    void Fill (SecureBuffer &buffer)
    {
        for (size_t i = 0; i < buffer.Size(); ++i) buffer[i] = static_cast<uint8> (i * 29 + 7);
    }

    void WriteFile (const FilePath &path, const ConstBufferPtr &data)
    {
        File file;
        file.Open (path, File::CreateWrite);
        if (data.Size()) file.Write (data);
    }

    bool FileEquals (const FilePath &path, const ConstBufferPtr &expected)
    {
        File file;
        file.Open (path);
        if (file.Length() != expected.Size()) return false;
        if (expected.Size() == 0) return true;
        SecureBuffer actual (expected.Size());
        file.ReadCompleteBuffer (actual);
        return ConstBufferPtr (actual).IsDataEqual (expected);
    }

    shared_ptr<VolumePassword> Apply (const FilePath &path, const wstring &descriptor = L"", const string &password = "password")
    {
        auto keyfiles = make_shared<KeyfileList>();
        keyfiles->push_back (make_shared<Keyfile> (path));
        auto original = make_shared<VolumePassword> (reinterpret_cast<const uint8*> (password.data()), password.size());
        return Keyfile::ApplyListToPassword (keyfiles, original, descriptor);
    }

    template<class Expected, class Action>
    void ExpectFailure (shared_ptr<TestResult> result, Action action)
    {
        bool failed = false;
        try { action(); }
        catch (const Expected &) { failed = true; }
        if (!failed) result->Failed ("Operation unexpectedly succeeded");
    }

    void LegacyMixing (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (381);
        Fill (data);
        WriteFile (fixture.Path ("plain"), data);
        for (size_t passwordSize : {size_t (8), size_t (80)})
        {
            string password (passwordSize, 'p');
            vector<uint8> expected (passwordSize <= 64 ? 64 : 128, 0);
            std::copy (password.begin(), password.end(), expected.begin());
            // Independent bitwise CRC calculation checks compatibility with the
            // established keyfile algorithm, including both password pool sizes.
            uint32 crc = 0xffffffff;
            size_t position = 0;
            for (size_t i = 0; i < data.Size(); ++i)
            {
                crc ^= data[i];
                for (unsigned bit = 0; bit < 8; ++bit)
                    crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
                for (int shift = 24; shift >= 0; shift -= 8)
                {
                    expected[position++] += static_cast<uint8> (crc >> shift);
                    position %= expected.size();
                }
            }
            auto actual = Apply (fixture.Path ("plain"), L"", password);
            if (actual->Size() != expected.size() || memcmp (actual->DataPtr(), expected.data(), expected.size()) != 0)
                result->Failed ("Legacy keyfile password mixing changed");
        }
    }

    void ProcessingLimit (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (Keyfile::MaxProcessedLength + File::GetOptimalReadSize() * 2);
        Fill (data);
        WriteFile (fixture.Path ("prefix"), data.GetRange (0, Keyfile::MaxProcessedLength));
        WriteFile (fixture.Path ("long"), data);
        if (*Apply (fixture.Path ("prefix")) != *Apply (fixture.Path ("long")))
            result->Failed ("Bytes after the 1 MiB keyfile limit affected the password");
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        if (*Apply (fixture.Path ("prefix")) != *Apply (fixture.Path ("encrypted"), TokenDescriptor))
            result->Failed ("Encrypted keyfile processing limit differs");
    }

    void EmptyAndMissingKeyfiles (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        WriteFile (fixture.Path ("empty"), ConstBufferPtr());
        ExpectFailure<InsufficientData> (result, [&] { Apply (fixture.Path ("empty")); });
        ExpectFailure<EncryptedKeyfileKeyfilesRequired> (result, [&] {
            Keyfile::ApplyListToPassword (shared_ptr<KeyfileList>(), shared_ptr<VolumePassword>(), TokenDescriptor);
        });
        ExpectFailure<EncryptedKeyfileKeyfilesRequired> (result, [&] {
            Keyfile::ApplyListToPassword (make_shared<KeyfileList>(), shared_ptr<VolumePassword>(), TokenDescriptor);
        });
    }

    void EncryptedRoundTrips (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        const size_t minimum = MockSecurityTokenImpl::GetPlaintextSize();
        for (size_t size : {minimum, minimum + 1, File::GetOptimalReadSize(), File::GetOptimalReadSize() + minimum + 1})
        {
            SecureBuffer data (size);
            Fill (data);
            WriteFile (fixture.Path ("plain"), data);
            Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
            File encrypted;
            encrypted.Open (fixture.Path ("encrypted"));
            if (encrypted.Length() != size - minimum + MockSecurityTokenImpl::GetCiphertextSize())
                result->Failed ("Unexpected encrypted keyfile layout");
            encrypted.Close();
            Keyfile keyfile (fixture.Path ("encrypted"));
            keyfile.RevealRedkey (fixture.Path ("revealed"), TokenDescriptor);
            if (!FileEquals (fixture.Path ("revealed"), data)) result->Failed ("Round-trip bytes differ");
            if (*Apply (fixture.Path ("plain")) != *Apply (fixture.Path ("encrypted"), TokenDescriptor))
                result->Failed ("Encrypted and plaintext keyfiles produced different passwords");
        }
    }

    void IndependentKeyfiles (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer first (MockSecurityTokenImpl::GetPlaintextSize() + 1);
        SecureBuffer second (first.Size());
        Fill (first);
        second.Zero();
        Keyfile::CreateBluekey (fixture.Path ("first"), TokenDescriptor, first);
        Keyfile::CreateBluekey (fixture.Path ("second"), TokenDescriptor, second);
        Keyfile (fixture.Path ("first")).RevealRedkey (fixture.Path ("revealed"), TokenDescriptor);
        if (!FileEquals (fixture.Path ("revealed"), first))
            result->Failed ("Creating another keyfile changed decryption of the first");
    }

    void InvalidLengths (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer marker (7);
        Fill (marker);
        WriteFile (fixture.Path ("output"), marker);
        SecureBuffer tooSmall (MockSecurityTokenImpl::GetPlaintextSize() - 1);
        ExpectFailure<InsufficientData> (result, [&] { Keyfile::CreateBluekey (fixture.Path ("output"), TokenDescriptor, tooSmall); });
        SecureBuffer ciphertext (MockSecurityTokenImpl::GetCiphertextSize());
        ciphertext.Zero();
        for (size_t size : {size_t (0), size_t (1), ciphertext.Size() - 1})
        {
            WriteFile (fixture.Path ("short"), ciphertext.GetRange (0, size));
            ExpectFailure<EncryptedKeyfileInvalid> (result, [&] {
                Keyfile (fixture.Path ("short")).RevealRedkey (fixture.Path ("output"), TokenDescriptor);
            });
        }
        if (!FileEquals (fixture.Path ("output"), marker)) result->Failed ("Invalid input altered existing output");
        if (fixture.HasTemporaryFiles()) result->Failed ("Invalid input left a temporary file");
    }

    void InvalidSchemes (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize());
        Fill (data);
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        WriteFile (fixture.Path ("output"), data);
        for (TestToken::Fault fault : {TestToken::EmptyScheme, TestToken::HugeScheme})
        {
            fixture.Token->Failure = fault;
            ExpectFailure<ParameterIncorrect> (result, [&] { Keyfile::CreateBluekey (fixture.Path ("output"), TokenDescriptor, data); });
            ExpectFailure<ParameterIncorrect> (result, [&] { Apply (fixture.Path ("encrypted"), TokenDescriptor); });
        }
        if (!FileEquals (fixture.Path ("output"), data)) result->Failed ("Invalid scheme altered existing output");
    }

    void TokenFailures (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize());
        Fill (data);
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        WriteFile (fixture.Path ("output"), data);
        fixture.Token->Failure = TestToken::EncryptError;
        ExpectFailure<Pkcs11Exception> (result, [&] { Keyfile::CreateBluekey (fixture.Path ("output"), TokenDescriptor, data); });
        fixture.Token->Failure = TestToken::DecryptError;
        ExpectFailure<Pkcs11Exception> (result, [&] { Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("output"), TokenDescriptor); });
        fixture.Token->Failure = TestToken::WrongEncryptSize;
        ExpectFailure<InsufficientData> (result, [&] { Keyfile::CreateBluekey (fixture.Path ("output"), TokenDescriptor, data); });
        fixture.Token->Failure = TestToken::WrongDecryptSize;
        ExpectFailure<EncryptedKeyfileInvalid> (result, [&] { Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("output"), TokenDescriptor); });
        if (!FileEquals (fixture.Path ("output"), data)) result->Failed ("Token failure altered existing output");
        if (fixture.HasTemporaryFiles()) result->Failed ("Token failure left a temporary file");
    }

    void OutputAliases (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize() + 1);
        Fill (data);
        FilePath source = fixture.Path ("encrypted");
        Keyfile::CreateBluekey (source, TokenDescriptor, data);
        if (link (string (source).c_str(), string (fixture.Path ("hardlink")).c_str()) != 0
            || symlink (string (source).c_str(), string (fixture.Path ("symlink")).c_str()) != 0)
            throw SystemException (SRC_POS);
        Keyfile keyfile (source);
        for (const char *name : {"encrypted", "hardlink", "symlink"})
            ExpectFailure<ParameterIncorrect> (result, [&] { keyfile.RevealRedkey (fixture.Path (name), TokenDescriptor); });
        keyfile.RevealRedkey (fixture.Path ("revealed"), TokenDescriptor);
        if (!FileEquals (fixture.Path ("revealed"), data)) result->Failed ("Alias rejection changed the source");
    }

    void OutputPermissions (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize());
        Fill (data);
        WriteFile (fixture.Path ("output"), data);
        if (chmod (string (fixture.Path ("output")).c_str(), 0644) != 0) throw SystemException (SRC_POS);
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("output"), TokenDescriptor);
        for (const char *name : {"encrypted", "output"})
        {
            struct stat info;
            if (stat (string (fixture.Path (name)).c_str(), &info) != 0) throw SystemException (SRC_POS);
            if ((info.st_mode & 0777) != 0600) result->Failed ("Exported keyfile permissions are not 0600");
        }
    }

    void PublicationFailure (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize());
        Fill (data);
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        if (mkdir (string (fixture.Path ("directory")).c_str(), 0700) != 0) throw SystemException (SRC_POS);
        ExpectFailure<AtomicFileDestinationNotRegular> (result, [&] {
            Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("directory"), TokenDescriptor);
        });
        if (fixture.HasTemporaryFiles()) result->Failed ("Failed publication left a temporary keyfile");
        Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("output"), TokenDescriptor);
        if (!FileEquals (fixture.Path ("output"), data)) result->Failed ("Failed publication damaged the source");
    }

    void DescriptorRequired (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecureBuffer data (MockSecurityTokenImpl::GetPlaintextSize());
        Fill (data);
        Keyfile::CreateBluekey (fixture.Path ("encrypted"), TokenDescriptor, data);
        ExpectFailure<ParameterIncorrect> (result, [&] { Keyfile::CreateBluekey (fixture.Path ("output"), L"", data); });
        ExpectFailure<ParameterIncorrect> (result, [&] { Keyfile (fixture.Path ("encrypted")).RevealRedkey (fixture.Path ("output"), L""); });
        if (fixture.Path ("output").IsFile()) result->Failed ("Missing token descriptor created output");
    }
}

int main ()
{
    Testing tests;
    tests.AddTest ("legacy keyfile mixing", LegacyMixing);
    tests.AddTest ("1 MiB processing limit", ProcessingLimit);
    tests.AddTest ("empty files and missing keyfiles", EmptyAndMissingKeyfiles);
    tests.AddTest ("encrypted prefix and remainder round trips", EncryptedRoundTrips);
    tests.AddTest ("independent encrypted keyfiles", IndependentKeyfiles);
    tests.AddTest ("input length validation", InvalidLengths);
    tests.AddTest ("scheme size validation", InvalidSchemes);
    tests.AddTest ("token failures preserve output", TokenFailures);
    tests.AddTest ("source and destination aliases", OutputAliases);
    tests.AddTest ("private output permissions", OutputPermissions);
    tests.AddTest ("failed publication cleanup", PublicationFailure);
    tests.AddTest ("token descriptor required", DescriptorRequired);
    return tests.Main();
}
