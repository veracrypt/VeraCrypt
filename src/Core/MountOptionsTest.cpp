#include <Testing.h>
#include "Core.h"
#include "Platform/MemoryStream.h"
#include "Platform/SerializerFactory.h"
#include "Volume/VolumePasswordCache.h"
#include <sys/stat.h>
#include <unistd.h>

using namespace VeraCrypt;

namespace
{
    void Require(shared_ptr<TestResult> result, bool condition, const string &message)
    {
        if (!condition) result->Failed(message);
    }

    void CopyAndSerialize(shared_ptr<TestResult> result)
    {
        MountOptions source;
        source.SecurityTokenSchemeSpec = L"token-key:53455249414c:01:RSA PKCS#1 OAEP";
        source.ProtectionSecurityTokenSchemeSpec = L"token-key:53455249414c:02:RSA PKCS#1 OAEP";
        source.Protection = VolumeProtection::HiddenVolumeReadOnly;
        source.Keyfiles = make_shared<KeyfileList>();
        source.Keyfiles->push_back(make_shared<Keyfile>(FilePath(L"outer-key")));
        source.ProtectionKeyfiles = make_shared<KeyfileList>();
        source.ProtectionKeyfiles->push_back(make_shared<Keyfile>(FilePath(L"hidden-key")));
        source.Password = make_shared<VolumePassword>(reinterpret_cast<const uint8 *>("outer"), 5);
        source.ProtectionPassword = make_shared<VolumePassword>(reinterpret_cast<const uint8 *>("hidden"), 6);
        source.Pim = 11;
        source.ProtectionPim = 22;

        MountOptions copy(source);
        Require(result, copy.SecurityTokenSchemeSpec == source.SecurityTokenSchemeSpec
            && copy.ProtectionSecurityTokenSchemeSpec == source.ProtectionSecurityTokenSchemeSpec,
            "Mount options copy lost token descriptors");
        copy.Keyfiles->clear();
        copy.ProtectionKeyfiles->clear();
        copy.SecurityTokenSchemeSpec.clear();
        copy.ProtectionSecurityTokenSchemeSpec.clear();
        Require(result, source.Keyfiles->size() == 1 && source.ProtectionKeyfiles->size() == 1
            && !source.SecurityTokenSchemeSpec.empty() && !source.ProtectionSecurityTokenSchemeSpec.empty(),
            "Preparing mount credentials changed the caller's options");

        shared_ptr<MemoryStream> stream = make_shared<MemoryStream>();
        source.Serialize(stream);
        shared_ptr<MountOptions> decoded = Serializable::DeserializeNew<MountOptions>(stream);
        Require(result, decoded->SecurityTokenSchemeSpec == source.SecurityTokenSchemeSpec
            && decoded->ProtectionSecurityTokenSchemeSpec == source.ProtectionSecurityTokenSchemeSpec
            && decoded->Protection == source.Protection && decoded->Pim == source.Pim
            && decoded->ProtectionPim == source.ProtectionPim && decoded->Keyfiles->size() == 1
            && decoded->ProtectionKeyfiles->size() == 1 && *decoded->Password == *source.Password
            && *decoded->ProtectionPassword == *source.ProtectionPassword,
            "Serialized mount options did not preserve independent outer and hidden credentials");
    }

    void DescriptorWithCachedPassword(shared_ptr<TestResult> result)
    {
        // Nothing is mounted, and CoreService is never started. If outer validation
        // regresses, opening the nonexistent hidden keyfile stops the request too.
        char directoryTemplate[] = "/tmp/veracrypt-mount-options-test-XXXXXX";
        char *directory = mkdtemp(directoryTemplate);
        if (!directory) throw SystemException(SRC_POS);
        string directoryPath(directory);
        finally_do_arg(string, directoryPath, { rmdir(finally_arg.c_str()); });
        VolumePassword password(reinterpret_cast<const uint8 *>("cached"), 6);
        VolumePasswordCache::Store(password);
        finally_do({ VolumePasswordCache::Clear(); });
        MountOptions options;
        options.SecurityTokenSchemeSpec = L"slot-key:1:42:RSA PKCS#1 OAEP";
        options.Protection = VolumeProtection::HiddenVolumeReadOnly;
        options.ProtectionKeyfiles = make_shared<KeyfileList>();
        options.ProtectionKeyfiles->push_back(make_shared<Keyfile>(FilePath(string(directory) + "/nonexistent")));
        bool rejected = false;
        try { Core->MountVolume(options); }
        catch (const ParameterIncorrect &) { rejected = true; }
        Require(result, rejected, "A token descriptor without keyfiles bypassed validation through password cache");
        Require(result, !options.SecurityTokenSchemeSpec.empty(), "Rejected mount changed caller's token descriptor");
    }

    void HiddenDescriptorWithoutKeyfiles(shared_ptr<TestResult> result)
    {
        MountOptions options;
        options.Password = make_shared<VolumePassword>(reinterpret_cast<const uint8 *>("outer"), 5);
        options.Protection = VolumeProtection::HiddenVolumeReadOnly;
        options.ProtectionSecurityTokenSchemeSpec = L"slot-key:1:42:RSA PKCS#1 OAEP";
        bool rejected = false;
        try { Core->MountVolume(options); }
        catch (const ParameterIncorrect &) { rejected = true; }
        Require(result, rejected, "Hidden-volume token descriptor without keyfiles was ignored");
    }
}

int main()
{
    SerializerFactory::Initialize();
    Testing tests;
    tests.AddTest("independent token options copy and serialization", CopyAndSerialize);
    tests.AddTest("descriptor-only mount with cached password", DescriptorWithCachedPassword);
    tests.AddTest("hidden-volume descriptor requires keyfiles", HiddenDescriptorWithoutKeyfiles);
    int status = tests.Main();
    SerializerFactory::Deinitialize();
    return status;
}
