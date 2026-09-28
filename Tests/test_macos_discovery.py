#!/usr/bin/env python3
"""Unit checks for macOS discovery; no mounted volumes or sudo needed.

Compiles the production plist helpers and batch-refresh methods with a fake
inventory provider, so tests can supply incomplete inventories safely. Optional
--platform-archive runs the real bounded process runner from a matching build.
"""
import argparse
from pathlib import Path
import plistlib
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-archive", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vc-discovery-unit-") as temporary:
        work = Path(temporary)
        image = work / ".veracrypt_aux_mnt-test" / "volume.dmg"
        image.parent.mkdir()
        image.touch()
        alias = work / "path-alias"
        alias.symlink_to(work, target_is_directory=True)
        exact = dict(**{"image-path": str(image.resolve()), "system-entities": [{"dev-entry": "/dev/disk42", "mount-point": "/Volumes/unit"}]})
        alias_image = dict(exact, **{"image-path": str(alias / image.relative_to(work))})
        unknown_alias = dict(exact, **{"image-path": str(work / "missing" / image.parent.name / image.name)})
        cases = {
            "exact": {"images": [exact]},
            "alias": {"images": [alias_image]},
            "absent": {"images": []},
            "unrelated": {"images": [{"image-path": "/offline/unrelated.dmg"}]},
            "exact_after_unknown": {"images": [unknown_alias, {}, exact]},
            "unknown_alias": {"images": [unknown_alias]},
            "unknown_record": {"images": [{}]},
            "bad_entities": {"images": [{"image-path": str(image.resolve())}]},
        }
        for name, contents in cases.items():
            (work / name).write_bytes(plistlib.dumps(contents))
        (work / "broken").write_text("invalid plist")

        source = (ROOT / "src/Core/Unix/MacOSX/CoreMacOSX.cpp").read_text()
        helpers = source[source.index("\tclass CFHolder"):source.index("\tstatic bool AuxiliaryControlFileHasVirtualDevice")]
        refresh = source[source.index("\tstatic void ClearDiskImageInfo"):source.index("\t// Strict /dev/diskN")]
        prelude = r'''
#include "Platform/Finally.h"
#include <CoreFoundation/CoreFoundation.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cstdlib>
#define throw_sys_sub_if(condition, subject) do { if (condition) throw std::runtime_error(subject); } while(false)
using DevicePath = std::string;
struct DirectoryPath : std::string {
    using std::string::string;
    DirectoryPath() {}
    DirectoryPath(const std::string &s) : std::string(s) {}
    bool IsEmpty() const { return empty(); }
};
struct ParameterIncorrect : std::runtime_error { ParameterIncorrect(const std::string &s) : std::runtime_error(s) {} };
struct VolumeDiscoveryFailed : std::runtime_error { VolumeDiscoveryFailed(const std::string &s, const std::wstring &) : std::runtime_error(s) {} };
struct StringConverter {
    static std::string Trim(std::string s) { size_t b=s.find_first_not_of(" \t\r\n"); if(b==std::string::npos)return ""; return s.substr(b,s.find_last_not_of(" \t\r\n")-b+1); }
    static std::wstring ToExceptionString(const std::exception &) { return L"failure"; }
};
static std::string Inventory;
static int Queries;
struct Process { static std::string ExecuteBounded(const std::string &, const std::list<std::string> &, int deadline) { if(deadline!=2000)throw std::runtime_error("discovery deadline"); ++Queries; return Inventory; } };
struct FuseService { static std::string GetVolumeImagePath() { return "/volume.dmg"; } };
struct SystemLog { static void WriteException(const std::exception &) {} };
#define foreach(declaration, collection) for (declaration : collection)
struct VolumeInfo {
    enum DiscoveryState { DiscoveryUnknown, ImageAttached, ImageAbsent, ControlUnavailable };
    DiscoveryState Discovery = DiscoveryUnknown;
    DirectoryPath AuxMountPoint, MountPoint;
    DevicePath VirtualDevice;
};
using VolumeInfoList = std::list<std::shared_ptr<VolumeInfo>>;
struct MountedFilesystem { DirectoryPath MountPoint; };
using MountedFilesystemList = std::list<std::shared_ptr<MountedFilesystem>>;
class CoreMacOSX {
public:
    void UpdateMountedVolumesInfo(VolumeInfoList &) const;
    void UpdateMountedVolumeInfo(std::shared_ptr<VolumeInfo>) const;
    void UpdateMountedVolumeInfo(std::shared_ptr<VolumeInfo>, const std::string &) const;
    MountedFilesystemList GetMountedFilesystems(const DevicePath &) const { return {}; }
};
'''
        # Production path types expose IsEmpty(); keep that interface in the mock.
        prelude = prelude.replace("using DevicePath = std::string;", "")
        prelude = prelude.replace("struct ParameterIncorrect", "using DevicePath = DirectoryPath;\nstruct ParameterIncorrect")
        tests = r'''
static void Require(bool condition, const char *message) { if(!condition)throw std::runtime_error(message); }
static std::string Read(const std::string &path) { std::ifstream f(path); return std::string(std::istreambuf_iterator<char>(f), {}); }
int main(int argc, char **argv) {
    try {
        std::string root=argv[1], image=argv[2];
        for (const auto &name : {"exact", "alias", "exact_after_unknown"}) {
            DevicePath device; DirectoryPath mount;
            Require(FindDiskImageInfoByImagePath(Read(root+"/"+name),image,device,mount), "positive match lost");
            Require(device=="/dev/disk42" && mount=="/Volumes/unit", "wrong mapping");
        }
        for (const auto &name : {"absent", "unrelated"}) {
            DevicePath device; DirectoryPath mount;
            Require(!FindDiskImageInfoByImagePath(Read(root+"/"+name),image,device,mount), "false match");
        }
        for (const auto &name : {"unknown_alias", "unknown_record", "bad_entities", "broken"}) {
            bool failed=false; DevicePath device; DirectoryPath mount;
            try { FindDiskImageInfoByImagePath(Read(root+"/"+name),image,device,mount); }
            catch(std::exception &) { failed=true; }
            Require(failed, "unknown inventory treated as absent");
        }
        VolumeInfoList volumes;
        for(int i=0;i<3;++i) { auto volume=std::make_shared<VolumeInfo>(); volume->AuxMountPoint=image.substr(0,image.rfind('/')); volumes.push_back(volume); }
        CoreMacOSX core;
        Queries=0; Inventory=Read(root+"/exact"); core.UpdateMountedVolumesInfo(volumes);
        Require(Queries==1, "more than one inventory per enumeration");
        for(auto volume:volumes)Require(volume->Discovery==VolumeInfo::ImageAttached, "attached status");
        Inventory=Read(root+"/broken"); core.UpdateMountedVolumesInfo(volumes);
        for(auto volume:volumes)Require(volume->Discovery==VolumeInfo::DiscoveryUnknown && volume->VirtualDevice.empty() && volume->MountPoint.empty(), "stale device survived failure");
        Inventory=Read(root+"/absent"); core.UpdateMountedVolumesInfo(volumes);
        for(auto volume:volumes)Require(volume->Discovery==VolumeInfo::ImageAbsent, "absent status");
        Inventory=Read(root+"/exact"); core.UpdateMountedVolumeInfo(volumes.front());
        Require(Queries==4 && volumes.front()->VirtualDevice=="/dev/disk42", "destructive lookup reused display snapshot");
        std::cout << "PASS: exact/alias matches, unrelated and incomplete inventories, batch query count, unknown/absent states, fresh lookup\n";
    } catch(std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
'''
        unit = work / "discovery.cpp"
        unit.write_text(prelude + helpers + refresh + tests)
        command = ["clang++", "-std=c++11", "-I" + str(ROOT / "src"), str(unit), "-framework", "CoreFoundation", "-o", str(work / "discovery")]
        subprocess.run(command, check=True)
        subprocess.run([str(work / "discovery"), str(work), str(image)], check=True, timeout=20)
        if args.platform_archive:
            command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX", "-I" + str(ROOT / "src"), str(ROOT / "Tests/macos_process_test.cpp"), str(args.platform_archive.resolve()), "-Wl,-dead_strip", "-o", str(work / "process")]
            subprocess.run(command, check=True)
            subprocess.run([str(work / "process")], check=True, timeout=20)
            command = ["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX", "-I" + str(ROOT / "src"), str(ROOT / "Tests/macos_volume_state_test.cpp"), str(args.platform_archive.resolve()), "-Wl,-dead_strip", "-o", str(work / "state")]
            subprocess.run(command, check=True)
            subprocess.run([str(work / "state")], check=True, timeout=20)


if __name__ == "__main__":
    main()
