#!/usr/bin/env python3
"""Test production cleanup state transitions with an in-memory FUSE service.

--build-dir is the src directory of a matching macOS build. All mount, process
and discovery operations in this harness are mocked; it never operates on a
real mount, service, or device.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check_rollback(work, build_dir):
    source = (ROOT / "src/Driver/Fuse/FuseService.cpp").read_text()
    worker = source[source.index("\tclass FuseServiceShutdownContext"):source.index("\n\t// Hold the original parent")]
    worker = worker.replace("\tprivate:", "\tpublic:")  # Test access to Serve; Start is never called.
    prelude = r'''
#include "Platform/Platform.h"
#include "Platform/Unix/Pipe.h"
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
namespace VeraCrypt {
using FuseServiceClock=std::chrono::steady_clock;
static const uint64 VC_FUSE_SHUTDOWN_VERSION=3, VC_FUSE_SHUTDOWN_PROBE=0, VC_FUSE_SHUTDOWN_DISMOUNT=1, VC_FUSE_SHUTDOWN_FORCE=1;
static const char *VC_FUSE_SHUTDOWN_DIRECTORY_PREFIX="/unused-unit-path/";
static std::string FuseServiceShutdownDirectory;
static bool Mounted=true, Busy=true;
static int Attempts=0, Replies=0, Reply=-1, Polls=0, Finished=0;
static uint64 Command=VC_FUSE_SHUTDOWN_PROBE;
struct fuse {};
struct FuseService {
    static uid_t GetUserId(){return getuid();} static gid_t GetGroupId(){return getgid();}
    static uint64 GetSerialInstanceNumber(){return 42;} static unsigned GetSlotNumber(){return 7;}
};
struct SystemLog { static void WriteError(const std::string &){} static void WriteException(const std::exception &){} };
static void fuse_exit(fuse *){++Finished;}
static void fuse_service_unmount(fuse *){}
static bool fuse_service_find_mount(const char *,fsid_t &id){id.val[0]=101;id.val[1]=202;return Mounted;}
static bool fuse_service_same_mount(const fsid_t &a,const fsid_t &b){return a.val[0]==b.val[0] && a.val[1]==b.val[1];}
static sockaddr_un fuse_service_shutdown_address(const std::string &){return {};}
static void fuse_service_configure_socket(int){}
static bool fuse_service_socket_wait(int,short,int,int){return Polls++==0;}
static bool fuse_service_socket_transfer(int,void *data,size_t size,bool sending,int=-1,int=10000){
    if(!sending){
        if(size!=sizeof(uint64)*8)throw std::runtime_error("unexpected mock request");
        uint64 frame[8]={3,Command,static_cast<uint64>(getpid()),42,7,0,101,202};
        memcpy(data,frame,size);
    } else if(size==sizeof(int32)){++Replies;Reply=*static_cast<int32 *>(data);}
    return true;
}
static int FakeUnmount(const char *,int flags){
    ++Attempts;
    if(flags!=MNT_FORCE)throw std::runtime_error("provisional rollback lost force mode");
    if(Busy){errno=EBUSY;return -1;}Mounted=false;return 0;
}
static int FakePoll(struct pollfd *,nfds_t,int){return 1;}
static ssize_t FakeRecv(int,void *,size_t,int){return 0;}
static int FakeAccept(int,struct sockaddr *,socklen_t *){return open("/dev/null",O_RDWR);}
static int FakePeer(int,uid_t *uid,gid_t *gid){*uid=getuid();*gid=getgid();return 0;}
#define unmount FakeUnmount
#define poll FakePoll
#define recv FakeRecv
#define accept FakeAccept
#define getpeereid FakePeer
'''
    tests = r'''
static void Require(bool value,const char *message){if(!value)throw std::runtime_error(message);}
int Run(){
    for(uint64 command:{VC_FUSE_SHUTDOWN_PROBE,VC_FUSE_SHUTDOWN_DISMOUNT}){
        Mounted=Busy=true;Attempts=Replies=Polls=Finished=0;Reply=-1;Command=command;
        int startup=1000;
        FuseServiceShutdownContext worker(NULL,"/in-memory-unit-mount",startup);
        worker.StopPipe.reset(new Pipe);
        worker.StartupReported=true;
        worker.Serve();
        Require(worker.StartupAborted && Mounted && Finished==0,"busy rollback stopped FUSE");
        Require(Replies==1 && Reply==(command==VC_FUSE_SHUTDOWN_PROBE?0:EBUSY),"busy rollback starved endpoint");
        Require(Attempts==(command==VC_FUSE_SHUTDOWN_PROBE?1:2),"rollback request retry storm");
        Busy=false;worker.NextRollbackAttempt=FuseServiceClock::time_point();
        worker.Serve();
        Require(worker.Unmounted && !Mounted && Finished==1,"rollback did not resume after busy cleared");
    }
    std::cout<<"PASS: busy provisional rollback remains probeable, reports busy, and completes on retry\n";
    return 0;
}
}
int main(){try{return VeraCrypt::Run();}catch(std::exception &e){std::cerr<<e.what()<<'\n';return 1;}}
'''
    unit = work / "rollback.cpp"
    unit.write_text(prelude + worker + tests)
    command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX", "-I" + str(ROOT / "src"), str(unit), str(build_dir.resolve() / "Platform/Platform.a"), "-Wl,-dead_strip", "-o", str(work / "rollback")]
    subprocess.run(command, check=True)
    subprocess.run([str(work / "rollback")], check=True, timeout=10)


def check_dismount_reporting(work, build_dir):
    source = (ROOT / "src/Main/UserInterface.cpp").read_text()
    end = source.index("\tvoid UserInterface::DisplayVolumeProperties")
    start = source.index("\tvoid UserInterface::DismountVolumes")
    helper = source.find("\tstatic void ThrowUnconfirmedCleanups")
    method = source[helper if 0 <= helper < start else start:end]
    prelude = r"""
#include "Volume/VolumeInfo.h"
#include "Volume/VolumeException.h"
#include "Core/CoreException.h"
#include "Platform/ForEach.h"
#include "Platform/StringConverter.h"
#include <deque>
#include <iostream>
#include <map>
namespace VeraCrypt {
struct wxString : std::wstring {
    wxString () {}
    wxString (const std::wstring &text) : std::wstring (text) {}
    bool IsEmpty () const { return empty(); }
    std::wstring ToStdWstring () const { return *this; }
    wxString &operator+= (wchar_t c) { push_back (c); return *this; }
    wxString &operator+= (const std::wstring &text) { append (text); return *this; }
};
struct StringFormatter {
    StringFormatter (const std::wstring &format, const std::wstring &argument) : Text (format + L" " + argument) {}
    operator std::wstring () const { return Text; }
    std::wstring Text;
};
static struct { std::wstring operator[] (const char *key) const { return StringConverter::ToWide (std::string (key)); } } LangString;
enum Outcome { Unmounted, Busy, Unconfirmed, Failed };
static std::map <std::wstring, std::deque <Outcome> > Plan;
static bool ForceAnswer;
class UserInterface {
public:
    struct BusyScope { BusyScope (const UserInterface *) {} };
    void DismountVolumes (VolumeInfoList volumes, bool ignoreOpenFiles, bool interactive, bool emergencyCleanupRequested = false) const;
    shared_ptr <VolumeInfo> DismountVolumeThread (shared_ptr <VolumeInfo> volume, bool, bool = true) const {
        std::deque <Outcome> &steps = Plan[wstring (volume->Path)];
        Outcome outcome = steps.empty() ? Unmounted : steps.front();
        if (!steps.empty()) steps.pop_front();
        if (outcome == Busy) throw MountedVolumeInUse (SRC_POS);
        if (outcome == Unconfirmed) throw DismountServiceCleanupFailed (SRC_POS, L"service of " + wstring (volume->Path));
        if (outcome == Failed) throw ParameterIncorrect (SRC_POS);
        return volume;
    }
    bool AskYesNo (const std::wstring &, bool, bool) const { return ForceAnswer; }
    void ShowWarning (const std::wstring &) const {}
    void ShowInfo (const std::wstring &) const {}
    static wxString ExceptionToMessage (const exception &e) { return StringConverter::ToExceptionString (e); }
    struct { bool Verbose; } Preferences = { false };
};
"""
    tests = r"""
static void Require (bool condition, const char *message) { if (!condition) throw std::runtime_error (message); }
static VolumeInfoList Volumes () {
    VolumeInfoList volumes;
    for (int i = 0; i < 2; ++i) {
        shared_ptr <VolumeInfo> volume (new VolumeInfo);
        volume->Path = VolumePath (wstring (i == 0 ? L"A" : L"B"));
        volume->SerialInstanceNumber = i + 1;
        volume->HiddenVolumeProtectionTriggered = false;
        volumes.push_back (volume);
    }
    return volumes;
}
// Returns the details reported for unconfirmed cleanups, or the name of the other outcome.
static std::wstring Run (std::deque <Outcome> a, std::deque <Outcome> b, bool interactive, bool force = false) {
    UserInterface ui; Plan.clear(); Plan[L"A"] = a; Plan[L"B"] = b; ForceAnswer = force;
    try { ui.DismountVolumes (Volumes(), false, interactive); return L"<no error>"; }
    catch (DismountServiceCleanupFailed &e) { return e.GetSubject(); }
    catch (UserAbort &) { return L"<cancelled>"; }
    catch (MountedVolumeInUse &) { return L"<busy>"; }
    catch (ParameterIncorrect &) { return L"<failed>"; }
}
static bool Has (const std::wstring &text, const wchar_t *part) { return text.find (part) != std::wstring::npos; }
int Run () {
    std::wstring r = Run ({Unconfirmed}, {Unmounted}, false);
    Require (Has (r, L"service of A"), "unconfirmed cleanup lost when the other volume unmounts");
    r = Run ({Unconfirmed}, {Busy, Busy}, false);
    Require (Has (r, L"service of A") && Has (r, L"MountedVolumeInUse"), "unconfirmed cleanup lost when the other volume stays busy");
    r = Run ({Unconfirmed}, {Failed, Failed}, false);
    Require (Has (r, L"service of A") && Has (r, L"ParameterIncorrect"), "unconfirmed cleanup lost when the other volume fails");
    r = Run ({Unconfirmed}, {Busy}, true, false);
    Require (Has (r, L"service of A"), "unconfirmed cleanup lost when forced unmount is declined");
    r = Run ({Unconfirmed}, {Unconfirmed}, false);
    Require (Has (r, L"service of A") && Has (r, L"service of B"), "only one of two unconfirmed cleanups reported");
    Require (Run ({Unmounted}, {Busy, Busy}, false) == L"<busy>", "busy volume error changed without unconfirmed cleanup");
    Require (Run ({Unmounted}, {Busy}, true, false) == L"<cancelled>", "cancellation changed without unconfirmed cleanup");
    Require (Run ({Unmounted}, {Busy, Unmounted}, true, true) == L"<no error>", "forced second pass failed");
    std::cout << "PASS: multi-volume unmount reports every unconfirmed cleanup with other failures and cancellation\n";
    return 0;
}
}
int main () { try { return VeraCrypt::Run(); } catch (std::exception &e) { std::cerr << e.what() << '\n'; return 1; } }
"""
    unit = work / "dismount_reporting.cpp"
    unit.write_text(prelude + method + tests)
    command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX"]
    command += ["-I" + str(ROOT / p) for p in ("src", "src/Crypto", "src/Common", "src/Crypto/Argon2/include")]
    command += [str(unit)] + [str(build_dir.resolve() / name) for name in ("Volume/Volume.a", "Platform/Platform.a")]
    command += ["-Wl,-dead_strip", "-o", str(work / "dismount_reporting")]
    subprocess.run(command, check=True)
    subprocess.run([str(work / "dismount_reporting")], check=True, timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()
    source = (ROOT / "src/Core/Unix/MacOSX/CoreMacOSX.cpp").read_text()
    dismount = source[source.index("\tshared_ptr <VolumeInfo> CoreMacOSX::DismountVolume"):source.index("\tstatic void ClearDiskImageInfo")]
    # Reuse the fully initialized public metadata fixture from the IPC test.
    fixture = (ROOT / "Tests/macos_cleanup_state_test.cpp").read_text()
    fixture = fixture[fixture.index("\t\tshared_ptr <VolumeInfo> volume"):fixture.index("\n\t\tshared_ptr <MemoryStream> controlBefore")]
    prelude = r"""
#include "Volume/VolumeInfo.h"
#include "Core/CoreException.h"
#include "Platform/MemoryStream.h"
#include <iostream>
#include <unistd.h>
namespace VeraCrypt {
enum RequestMode { RequestOk, RequestBusy, RequestLostAfterUnmount };
static bool Mounted=true, FailWait=true, FailDiscovery=false, FailPreflight=false;
static RequestMode Request=RequestOk;
static int Preflights=0, Requests=0, Waits=0, Discoveries=0, Commands=0, CapturedReads=0;
static void FakeSync() {}
#define sync FakeSync
struct FuseService {
    struct DismountRequest { pid_t ProcessId; uint64 ProcessStartTime, SerialInstanceNumber; unsigned SlotNumber; bool IgnoreOpenFiles, LegacyService; std::string SocketDirectory, AuxMountPoint; int32 MountId[2]; };
    static DismountRequest PrepareDismount(const DirectoryPath &aux,uint64 serial,unsigned slot,bool force) {
        ++Preflights;
        if(!Mounted || FailPreflight)throw MountServiceUnavailable("mock preflight");
        DismountRequest request={}; request.ProcessId=1234; request.ProcessStartTime=987654321; request.SerialInstanceNumber=serial; request.SlotNumber=slot;
        request.AuxMountPoint=aux; request.IgnoreOpenFiles=force; request.MountId[0]=101; request.MountId[1]=202; return request;
    }
    static bool IsDismountMountPresent(const DismountRequest &) { return Mounted; }
    static pid_t RequestDismount(const DismountRequest &request) {
        ++Requests;
        if(Request==RequestBusy)throw MountedVolumeInUse("mock busy");
        Mounted=false;
        if(Request==RequestLostAfterUnmount)throw MountServiceUnavailable("mock request", L"service reply lost");
        return request.ProcessId;
    }
    static void WaitForDismount(pid_t pid,const DirectoryPath &,unsigned,int,uint64 startTime) {
        ++Waits; if(pid!=1234 || startTime!=987654321)throw std::runtime_error("wrong service identity");
        if(FailWait)throw DismountServiceCleanupFailed("mock timeout", L"pid=1234, auxiliary mount=/in-memory");
    }
    static void DismountLegacy(const DismountRequest &) { throw std::runtime_error("unexpected legacy path"); }
};
struct Process {
    static std::string Execute(const std::string &,const std::list<std::string> &) { ++Commands; throw std::runtime_error("unexpected disk command"); }
};
class CoreMacOSX {
public:
    shared_ptr<VolumeInfo> DismountVolume(shared_ptr<VolumeInfo>, bool=false, bool=false);
    void UpdateMountedVolumeInfo(shared_ptr<VolumeInfo> volume) {
        ++Discoveries; if(FailDiscovery)throw VolumeDiscoveryFailed("mock inventory");
        volume->VirtualDevice=DevicePath(); volume->MountPoint=DirectoryPath();
    }
    shared_ptr<VolumeInfo> ValidateMountedVolume(shared_ptr<VolumeInfo> volume) const { ++CapturedReads; return volume; }
};
"""
    tests = r"""
static void Require(bool condition,const char *message) { if(!condition)throw std::runtime_error(message); }
int Run() {
    auto volume=MakeVolume(); CoreMacOSX core;
    FailPreflight=true;
    try { core.DismountVolume(volume); throw std::runtime_error("preflight ignored"); }
    catch(MountServiceUnavailable &) {}
    Require(Discoveries==0 && Requests==0, "operation after failed preflight");
    FailPreflight=false; FailDiscovery=true;
    try { core.DismountVolume(volume); throw std::runtime_error("unknown inventory ignored"); }
    catch(VolumeDiscoveryFailed &) {}
    Require(Requests==0, "unmounted with unknown image ownership");
    FailDiscovery=false;
    try { core.DismountVolume(volume); throw std::runtime_error("cleanup reported as complete"); }
    catch(DismountServiceCleanupFailed &e) {
        Require(e.GetSubject().find(L"pid=1234, auxiliary mount=/in-memory")!=std::wstring::npos, "cleanup error lost service details");
    }
    Require(!Mounted && Requests==1 && Waits==1, "service exit was not awaited after SMB removal");
    Mounted=true; FailWait=false; Request=RequestLostAfterUnmount;
    try { core.DismountVolume(volume); throw std::runtime_error("lost request after SMB removal reported as complete"); }
    catch(DismountServiceCleanupFailed &e) {
        Require(e.GetSubject().find(L"service reply lost")!=std::wstring::npos, "cleanup error lost request details");
    }
    Mounted=true; Request=RequestBusy;
    try { core.DismountVolume(volume); throw std::runtime_error("busy auxiliary unmount reported as complete"); }
    catch(MountedVolumeInUse &) {}
    Require(Mounted, "busy auxiliary unmount changed the mount");
    Request=RequestOk; volume->Protection=VolumeProtection::HiddenVolumeReadOnly;
    core.DismountVolume(volume);
    Require(CapturedReads==1 && !Mounted && Commands==0, "hidden-protection refresh did not use captured volume");
    std::cout << "PASS: preflight/discovery failures stop teardown, unconfirmed exits keep details, busy SMB stays retryable, per-volume hidden-protection refresh\n";
    return 0;
}
}
int main() { try { return VeraCrypt::Run(); } catch(std::exception &e) { std::cerr<<e.what()<<'\n'; return 1; } }
"""
    with tempfile.TemporaryDirectory(prefix="vc-cleanup-unit-") as temporary:
        work = Path(temporary)
        unit = work / "cleanup.cpp"
        unit.write_text(prelude + dismount + "\nstatic shared_ptr<VolumeInfo> MakeVolume() {\n" + fixture + "\nreturn volume;\n}\n" + tests)
        command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX", "-DVC_MACOSX_FUSET"]
        command += ["-I" + str(ROOT / p) for p in ("src", "src/Crypto", "src/Common", "src/Crypto/Argon2/include")]
        command += [str(unit)] + [str(args.build_dir.resolve() / name) for name in ("Core/Core.a", "Volume/Volume.a", "Platform/Platform.a")]
        command += ["-Wl,-dead_strip", "-o", str(work / "cleanup")]
        subprocess.run(command, check=True)
        subprocess.run([str(work / "cleanup")], check=True, timeout=20)
        ipc_command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX"]
        ipc_command += ["-I" + str(ROOT / p) for p in ("src", "src/Crypto", "src/Common", "src/Crypto/Argon2/include")]
        ipc_command += [str(ROOT / "Tests/macos_cleanup_state_test.cpp")]
        # The test references no other symbol from the object that registers core
        # exception types for IPC, so the archive alone would not link it.
        ipc_command += [str(args.build_dir.resolve() / name) for name in ("Core/CoreException.o", "Core/Core.a", "Volume/Volume.a", "Platform/Platform.a")]
        ipc_command += ["-Wl,-dead_strip", "-o", str(work / "ipc")]
        subprocess.run(ipc_command, check=True)
        subprocess.run([str(work / "ipc")], check=True, timeout=20)
        check_rollback(work, args.build_dir)
        check_dismount_reporting(work, args.build_dir)


if __name__ == "__main__":
    main()
