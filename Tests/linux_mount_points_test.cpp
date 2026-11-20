// Real path resolution and mount-directory lifecycle, without root or mounts.
#include "Core/Unix/Linux/CoreLinux.h"
#include "Platform/Directory.h"
#include <algorithm>
#include <cerrno>
#include <iostream>
#include <sys/stat.h>

using namespace VeraCrypt;

static string Root, AuxPath, MountedPath;
static unsigned OpenCalls, FuseCalls, MountCalls, ChownCalls;
static bool FailChown, FailMount, ExpectEarlyRejection;

static void Require (bool condition, const string &message)
{
    if (!condition) throw std::runtime_error (message);
}

extern "C" void WrapFuseMount (shared_ptr<Volume>, VolumeSlotNumber, const string &path)
{
    ++FuseCalls;
    AuxPath = path;
}

extern "C" string WrapExecute (const string &program, const list<string> &args,
    int, ProcessExecFunctor *, const Buffer *)
{
    Require (program == "umount" && vector<string> (args.begin(), args.end())
        == vector<string> {"--", AuxPath}, "unexpected external command");
    return "";
}

extern "C" int __wrap_chown (const char *path, uid_t, gid_t)
{
    Require (string (path).find (Root + "/") == 0, "chown escaped temporary directory");
    ++ChownCalls;
    if (!FailChown) return 0;
    errno = EACCES;
    return -1;
}

struct TestVolume : Volume
{
    TestVolume ()
    {
        Protection = VolumeProtection::None;
        VolumeFile.reset (new File);
        VolumeFile->Open (Root + "/volume", File::CreateWrite);
    }
};

struct TestCore : CoreLinux
{
    shared_ptr<Volume> Opened;
    string RejectCreated;
    TestCore () : Opened (new TestVolume) { }
    using CoreUnix::GetDefaultMountPointSlot;
    using CoreUnix::ValidateMountPoint;
    bool IsProtectedSystemDirectory (const DirectoryPath &path) const override
    {
        return (string (path) == RejectCreated && path.IsDirectory())
            || CoreUnix::IsProtectedSystemDirectory (path);
    }
    shared_ptr<Volume> OpenVolume (shared_ptr<VolumePath>, bool, shared_ptr<VolumePassword>, int,
        shared_ptr<Pkcs5Kdf>, shared_ptr<KeyfileList>, bool, VolumeProtection::Enum,
        shared_ptr<VolumePassword>, int, shared_ptr<Pkcs5Kdf>, shared_ptr<KeyfileList>,
        bool, VolumeType::Enum, bool, bool) const override
    {
        ++OpenCalls;
        // Stop a regressing validation check before it can create anything.
        Require (!ExpectEarlyRejection, "invalid mount point reached volume opening");
        return Opened;
    }
    bool IsVolumeMounted (const VolumePath &) const override { return false; }
    VolumeInfoList GetMountedVolumes (const VolumePath & = VolumePath()) const override { return VolumeInfoList(); }
    MountedFilesystemList GetMountedFilesystems (const DevicePath & = DevicePath(),
        const DirectoryPath & = DirectoryPath()) const override { return MountedFilesystemList(); }
    string GetTempDirectory () const override { return Root; }
    // The production locks, in a directory that the unprivileged test can create
    string GetMountLockDirectory () const override { return Root + "/locks"; }
    shared_ptr<VolumeInfo> GetMountedVolume (const VolumePath &) const override
    {
        shared_ptr<VolumeInfo> info (new VolumeInfo);
        info->MountPoint = MountedPath;
        info->AuxMountPoint = AuxPath;
        info->Protection = VolumeProtection::None;
        return info;
    }
    void MountVolumeNative (shared_ptr<Volume>, MountOptions &options, const DirectoryPath &) const override
    {
        ++MountCalls;
        if (FailMount || !options.MountPoint->IsDirectory())
            throw SystemException (SRC_POS, ENOENT);
        MountedPath = string (*options.MountPoint);
    }
    void DismountFilesystem (const DirectoryPath &, bool) const override { }
    void DismountNativeVolume (shared_ptr<VolumeInfo>) const override { }
    shared_ptr<VolumeInfo> DismountVolume (shared_ptr<VolumeInfo> info, bool force = false, bool sync = false) override
    {
        return CoreUnix::DismountVolume (info, force, sync);
    }
};

static MountOptions Options (const string &path)
{
    OpenCalls = FuseCalls = MountCalls = ChownCalls = 0;
    MountedPath.clear();
    AuxPath.clear();
    MountOptions options;
    options.Path.reset (new VolumePath (Root + "/volume"));
    options.MountPoint.reset (new DirectoryPath (path));
    options.SlotNumber = 2;
    return options;
}

template <class E> static void Blocked (TestCore &core, const string &path)
{
    MountOptions options = Options (path);
    bool blocked = false;
    ExpectEarlyRejection = true;
    try { core.MountVolume (options); }
    catch (E &) { blocked = true; }
    ExpectEarlyRejection = false;
    Require (blocked && OpenCalls == 0 && FuseCalls == 0 && ChownCalls == 0 && MountCalls == 0,
        "not rejected before side effects: " + path);
}

static void Mounted (TestCore &core, const string &path, bool managed, bool created)
{
    MountOptions options = Options (path);
    shared_ptr<VolumeInfo> info = core.MountVolume (options);
    Require (OpenCalls == 1 && FuseCalls == 1 && MountCalls == 1, "mount flow incomplete");
    Require (ChownCalls == (managed ? (created ? 2u : 1u) : 0u), "incorrect ownership handling");
    core.DismountVolume (info);
    Require (DirectoryPath (path).IsDirectory() == !managed, "incorrect directory cleanup");
    Require (!DirectoryPath (AuxPath).IsDirectory(), "auxiliary directory not removed");
}

int main (int argc, char **argv)
{
    try
    {
        Require (argc == 2, "expected temporary directory");
        Root = argv[1];
        Directory::Create (Root + "/media");
        const string prefix = Root + "/media/veracrypt";
        Require (setenv ("VERACRYPT_MOUNT_PREFIX", prefix.c_str(), 1) == 0, "set prefix");
        unsetenv ("SUDO_UID"); unsetenv ("SUDO_GID"); unsetenv ("DOAS_USER");
        const string first = prefix + "1";
        Directory::Create (first);
        Require (symlink ("/etc", (first + "/l").c_str()) == 0, "create protected alias");
        const string leaf = Root.substr (Root.find_last_of ('/') + 1);
        Require (!DirectoryPath ("/etc/" + leaf).IsDirectory(), "protected test name already exists");
        TestCore core;

        // The CLI preserves symlinks; favorites also preserve dot components.
        Blocked<MountPointBlocked> (core, first + "/l/" + leaf);
        string traversal = first;
        for (size_t i = 0; i < static_cast<size_t> (std::count (first.begin(), first.end(), '/')); ++i)
            traversal += "/..";
        Blocked<MountPointBlocked> (core, traversal + "/etc/" + leaf);
        Blocked<MountPointBlocked> (core, "/etc/" + leaf);
        Blocked<MountPointBlocked> (core, first + "/l/");
        Blocked<MountPointBlocked> (core, "/");
        core.SetAllowInsecureMount (true);
        Blocked<MountPointBlocked> (core, first + "/l/" + leaf);
        core.SetAllowInsecureMount (false);

        // PATH restrictions use the same resolved destination, even if missing.
        Directory::Create (Root + "/bin");
        Require (symlink ((Root + "/bin").c_str(), (first + "/p").c_str()) == 0, "create PATH alias");
        core.SetUserEnvPATH (Root + "/bin");
        Blocked<MountPointNotAllowed> (core, first + "/p/new");
        core.SetAllowInsecureMount (true);
        core.ValidateMountPoint (first + "/p/new");
        core.SetAllowInsecureMount (false);
        core.SetUserEnvPATH (first + "/p/new");
        Blocked<MountPointNotAllowed> (core, Root + "/bin/new");
        core.SetUserEnvPATH ("");

        // Failed resolution must not fall back to unchecked strings.
        Require (symlink ("missing", (prefix + "3").c_str()) == 0, "create dangling link");
        Require (symlink ("veracrypt4", (prefix + "4").c_str()) == 0, "create symlink loop");
        for (const string &path : {prefix + "3", prefix + "3/", prefix + "4", first + "/missing/child"})
            Blocked<SystemException> (core, path);
        Blocked<ParameterIncorrect> (core, first + "/missing/.");
        Blocked<ParameterIncorrect> (core, first + "/missing/..");
        if (geteuid() != 0)
        {
            Directory::Create (Root + "/inaccessible");
            Require (chmod ((Root + "/inaccessible").c_str(), 0000) == 0, "restrict parent");
            Blocked<SystemException> (core, Root + "/inaccessible/child");
            Require (chmod ((Root + "/inaccessible").c_str(), 0700) == 0, "restore parent");
        }

        for (VolumeSlotNumber slot : {1u, 2u, 64u})
        {
            const string path = prefix + StringConverter::ToSingle (slot);
            Require (core.GetDefaultMountPointSlot (path) == slot, "default name not recognized");
            Require (core.MountPointToSlotNumber (path + "/") == slot, "trailing slash changes slot");
        }
        for (const string &suffix : {"", "0", "01", "65", "-1", "+1", "4294967297",
                "99999999999999999999999999", "-backup", "-backup64", "1/photos", "1/../veracrypt2"})
            Require (core.GetDefaultMountPointSlot (prefix + suffix) == 0, "custom path treated as default");
        Require (core.MountPointToSlotNumber (prefix + "-backup64") == 1, "custom name selected trailing slot");

        Mounted (core, prefix + "2/", true, true);
        Directory::Create (prefix + "2");
        Mounted (core, prefix + "2", true, false);
        for (const string &path : {prefix + "-backup", first + "/photos", Root + "/custom mount"})
        {
            MountOptions options = Options (path);
            bool failed = false;
            try { core.MountVolume (options); }
            catch (SystemException &) { failed = true; }
            Require (failed && !DirectoryPath (path).IsDirectory() && ChownCalls == 0,
                "missing custom directory was automatically managed");
            Directory::Create (path);
            Mounted (core, path, false, false);
        }
        Require (symlink ((Root + "/custom mount").c_str(), (Root + "/custom alias").c_str()) == 0,
            "create custom alias");
        Mounted (core, Root + "/custom alias", false, false);

        // Every failure after mkdir must remove the newly created directory.
        for (unsigned failure = 0; failure < 3; ++failure)
        {
            FailChown = failure == 0;
            FailMount = failure == 1;
            core.RejectCreated = failure == 2 ? prefix + "2" : "";
            MountOptions options = Options (prefix + "2");
            bool failed = false;
            try { core.MountVolume (options); }
            catch (Exception &) { failed = true; }
            Require (failed && !DirectoryPath (prefix + "2").IsDirectory(), "failed mount left a created directory");
            if (failure == 2)
                Require (ChownCalls == 0 && MountCalls == 0, "post-creation validation occurred too late");
        }
        std::cout << "PASS: protected paths, PATH aliases, resolution errors, exact default names, custom mounts and failure cleanup\n";
    }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
