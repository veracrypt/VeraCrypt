// Exercise the linked Linux backend with command execution intercepted. No mounts are made.
#include "Core/Unix/Linux/CoreLinux.h"
#include "Platform/Unix/Process.h"
#include "Volume/EncryptionModeXTS.h"
#include <algorithm>
#include <iostream>

using namespace VeraCrypt;

static bool ReadOnly;
static unsigned LoopCalls, LoopFailures, Layers, ExpectedLayers;
static string VolumeFilePath;
struct StopBeforeDeviceIO { };

static void Require (bool condition, const char *message)
{
    if (!condition) throw std::runtime_error (message);
}

// The Python runner resolves the mangled names from the matching build archives.
extern "C" string WrapExecute (const string &program, const list<string> &args,
    int, ProcessExecFunctor *, const Buffer *input)
{
    vector<string> a (args.begin(), args.end());
    if (program == "modprobe") return "";
    if (program == "losetup")
    {
        if (a == vector<string> {"-f"}) return "";
        ++LoopCalls;
        vector<string> expected;
        if (ReadOnly) expected.push_back ("-r");
        expected.push_back ("--");
        expected.push_back ("/dev/loop" + StringConverter::ToSingle (LoopCalls - 1));
        expected.push_back (VolumeFilePath);
        Require (a == expected, "loop retry changed protection or arguments");
        if (LoopCalls <= LoopFailures)
            throw ExecutedProcessFailed (SRC_POS, "losetup", 1, "injected failure");
        return "";
    }
    Require (program == "dmsetup" && !a.empty() && a[0] == "create", "unexpected command");
    string name = "veracrypt64";
    if (Layers + 1 != ExpectedLayers)
        name += "_" + StringConverter::ToSingle (ExpectedLayers - Layers - 2);
    vector<string> expected {"create"};
    if (ReadOnly) expected.push_back ("--readonly");
    expected.push_back ("--uuid");
    expected.push_back ("VERACRYPT-987654321-" + name);
    expected.push_back (name);
    Require (a == expected, "device-mapper access mode, name or UUID changed");
    Require (input && input->Size() > 0, "missing device-mapper table");
    if (++Layers == ExpectedLayers) throw StopBeforeDeviceIO();
    return "";
}

extern "C" string WrapFindBinary (const char *, string &) { return "/test/dmsetup"; }
extern "C" FilesystemPathType::Enum WrapGetType (const FilesystemPath *)
{
    return FilesystemPathType::BlockDevice;
}
extern "C" shared_ptr<VolumeInfo> WrapAuxInfo (const DirectoryPath &)
{
    shared_ptr<VolumeInfo> info (new VolumeInfo);
    info->SerialInstanceNumber = 987654321;
    return info;
}

struct TestLayout : VolumeLayoutV2Normal
{
    uint64 GetDataOffset (uint64) const override { return 128 * 1024; }
};

struct TestVolume : Volume
{
    TestVolume (bool cascade, VolumeProtection::Enum protection, bool incomplete = false)
    {
        Protection = protection;
        EncryptionNotCompleted = incomplete;
        VolumeFile.reset (new File);
        VolumeFile->Open (VolumeFilePath, File::OpenRead);
        EA.reset (cascade ? static_cast<VeraCrypt::EncryptionAlgorithm *> (new SerpentTwofishAES) : new VeraCrypt::AES);
        SecureBuffer key (EA->GetKeySize());
        key.Zero();
        EA->SetKey (key);
        shared_ptr<EncryptionMode> mode (new EncryptionModeXTS);
        mode->SetKey (key);
        EA->SetMode (mode);
        Layout.reset (new TestLayout);
        VolumeHostSize = 16 * 1024 * 1024;
        VolumeDataSize = VolumeHostSize - 256 * 1024;
        SectorSize = 512;
    }
};

struct TestCore : CoreLinux
{
    using CoreLinux::AttachFileToLoopDevice;
    using CoreLinux::MountVolumeNative;
    using CoreUnix::MountAuxVolumeImage;
};

int main (int argc, char **argv)
{
    try
    {
        Require (argc == 2, "expected temporary file");
        VolumeFilePath = argv[1];
        TestCore core;
        for (bool readOnly : {false, true})
        {
            ReadOnly = readOnly;
            for (unsigned failures : {0u, 2u, 256u})
            {
                LoopCalls = 0;
                LoopFailures = failures;
                try
                {
                    core.AttachFileToLoopDevice (VolumeFilePath, readOnly);
                    Require (failures < 256, "failed loop setup unexpectedly succeeded");
                }
                catch (LoopDeviceSetupFailed &) { Require (failures == 256, "early loop failure"); }
                Require (LoopCalls == std::min (failures + 1, 256u), "unexpected loop attempts");
            }
            for (bool cascade : {false, true})
            for (bool noFilesystem : {false, true})
            {
                Layers = 0;
                ExpectedLayers = cascade ? 3 : 1;
                shared_ptr<Volume> volume (new TestVolume (cascade,
                    readOnly ? VolumeProtection::ReadOnly : VolumeProtection::None));
                MountOptions options;
                options.SlotNumber = 64;
                options.NoFilesystem = noFilesystem;
                // Deliberately differ: the opened volume is authoritative.
                options.Protection = readOnly ? VolumeProtection::None : VolumeProtection::ReadOnly;
                try { core.MountVolumeNative (volume, options, "/test/aux"); }
                catch (StopBeforeDeviceIO &) { }
                Require (Layers == ExpectedLayers, "cascade skipped a layer");
            }
        }
        MountOptions options;
        for (bool incomplete : {false, true})
        {
            options.Protection = incomplete ? VolumeProtection::None : VolumeProtection::ReadOnly;
            shared_ptr<Volume> protectedVolume (new TestVolume (false,
                incomplete ? VolumeProtection::ReadOnly : VolumeProtection::HiddenVolumeReadOnly, incomplete));
            Layers = 0;
            try
            {
                core.MountVolumeNative (protectedVolume, options, "/test/aux");
                throw std::runtime_error ("protected volume selected native backend");
            }
            catch (NotApplicable &) { }
            Require (Layers == 0, "FUSE fallback created a native mapping");
        }

        // The FUSE image caller must propagate loop setup failure as well.
        options.Protection = VolumeProtection::ReadOnly;
        VolumeFilePath = "/test/aux/volume";
        LoopCalls = 0;
        LoopFailures = 256;
        ReadOnly = true;
        try
        {
            core.MountAuxVolumeImage ("/test/aux", options);
            throw std::runtime_error ("FUSE loop setup unexpectedly succeeded");
        }
        catch (LoopDeviceSetupFailed &) { }
        Require (LoopCalls == 256, "FUSE loop failure not exercised");
        std::cout << "PASS mapping arguments, cascades, effective protection, hidden/incomplete fallback, loop retries and failure\n";
    }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
