#!/usr/bin/env python3
"""Test FUSE-T's production private-parent helpers using disposable directories.

Requires a matching macOS build, but no mounted volumes or FUSE service. Optional
--owner UID, when run as root, checks elevated access and real uid isolation
using a harmless sentinel file. No user accounts are created or modified.
"""
import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    begin = source.index("\t" + signature)
    return source[begin:source.index("\n\t}", begin) + 3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--owner", type=int, default=os.getuid())
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS is required")
    if args.owner != os.getuid() and os.geteuid() != 0:
        parser.error("--owner requires root when it differs from the current uid")
    owner = args.owner
    elevated = os.geteuid() == 0
    prefix = ".veracrypt_aux_root_" if elevated else ".veracrypt_aux_"
    other = 502 if owner != 502 else 503
    with tempfile.TemporaryDirectory(prefix="vc-aux-directory-", dir="/private/tmp") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        source = (ROOT / "src/Core/Unix/CoreUnix.cpp").read_text()
        helpers = function(source, "static string CreateFuseTAuxiliaryDirectory")
        helpers += function(source, "static bool IsOtherUsersFuseTAuxiliaryMount")
        service = (ROOT / "src/Driver/Fuse/FuseService.cpp").read_text()
        helpers += function(service, "void FuseService::RemoveAuxMountParent")
        begin = service.index("\tclass FuseServiceAuxDirectory")
        helpers += service[begin:service.index("\n\t};", begin) + 4]
        unit = work / "check.cpp"
        unit.write_text(r'''
#include "Core/CoreException.h"
#include "Core/Unix/MountedFilesystem.h"
#include "Platform/StringConverter.h"
#include <fcntl.h>
#include <membership.h>
#include <cstring>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
namespace VeraCrypt {
static bool IgnoreOwnership=false, FailAcl=false, Mounted=false;
static int TestStatfs(int fd, struct statfs *info) {
    int result=fstatfs(fd, info);
    if(result==0 && IgnoreOwnership)info->f_flags |= MNT_IGNORE_OWNERSHIP;
    return result;
}
static int TestSetAcl(int fd, acl_t acl, acl_type_t type) {
    if(FailAcl){errno=ENOTSUP;return -1;}
    return acl_set_fd_np(fd, acl, type);
}
static bool fuse_service_find_mount(const char *, fsid_t &) { return Mounted; }
struct FuseService { static void RemoveAuxMountParent(const string &, int=-1); };
#define fstatfs TestStatfs
#define acl_set_fd_np TestSetAcl
''' + helpers + r'''
}
using namespace VeraCrypt;
int main(int argc, char **argv) {
    try {
        const std::string command=argv[1];
        if(command=="create" || command=="noowners" || command=="acl-failure") {
            IgnoreOwnership=command=="noowners"; FailAcl=command=="acl-failure";
            std::cout << CreateFuseTAuxiliaryDirectory(argv[2], std::stoul(argv[3])) << '\n';
        } else if(command=="cleanup") {
            FuseService::RemoveAuxMountParent(argv[2]);
        } else if(command.find("service-")==0) {
            Mounted=command=="service-mounted";
            FuseServiceAuxDirectory directory(argv[2]);
            if(command=="service-removed" && rmdir(argv[2])!=0)throw std::runtime_error("fixture removal failed");
            if(command=="service-replaced-child" || command=="service-replaced-parent") {
                std::string path=argv[2];
                if(command=="service-replaced-parent")path=path.substr(0, path.find_last_of('/'));
                if(rename(path.c_str(), (path+".original").c_str())!=0 || mkdir(path.c_str(), 0700)!=0)
                    throw std::runtime_error("fixture replacement failed");
            }
        } else if(command=="filter") {
            MountedFilesystem mount;
            mount.MountPoint = argv[2]; mount.Owner = std::stoul(argv[3]); mount.Type = argv[4];
            std::cout << IsOtherUsersFuseTAuxiliaryMount(mount, std::stoul(argv[5]), std::stoul(argv[6])) << '\n';
        }
    } catch (std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
''')
        binary = work / "check"
        subprocess.run(["clang++", "-std=c++11", "-DTC_UNIX", "-DTC_MACOSX", "-I" + str(ROOT / "src"),
                        str(unit), str(args.build_dir / "Core/Core.a"),
                        str(args.build_dir / "Platform/Platform.a"), "-Wl,-dead_strip", "-o", str(binary)], check=True)

        def create(base, uid=owner, succeeds=True, command="create"):
            result = subprocess.run([str(binary), command, str(base), str(uid)], capture_output=True, text=True)
            assert (result.returncode == 0) == succeeds, result.stdout + result.stderr
            return Path(result.stdout.strip()) if succeeds else None

        def case(name):
            base = work / name
            base.mkdir(mode=0o755)
            return base

        base = case("normal")
        directory = create(base)
        info = directory.stat()
        assert info.st_uid == (0 if elevated else owner) and stat.S_IMODE(info.st_mode) == 0o700
        assert create(base) != directory
        sentinel = directory / "sentinel"
        sentinel.write_text("private directory regression fixture\n")
        if os.geteuid() == 0:
            os.chown(sentinel, owner, -1)
        sentinel.chmod(0o644)

        def foreign(path=directory, user=other, real=other, mount_owner=0, backend="smbfs"):
            result = subprocess.check_output([str(binary), "filter", str(path / ".veracrypt_aux_mnt-unit"),
                                              str(mount_owner), backend, str(user), str(real)], text=True)
            return result.strip() == "1"

        assert foreign() == elevated  # Only the elevated parent name identifies the user.
        assert not foreign(user=0, real=other)
        assert not foreign(user=owner, real=owner)
        assert not foreign(user=0, real=owner)
        assert not foreign(path=base)  # Legacy mounts in a shared temp directory.
        legacy = case("legacy-acl")
        legacy.chmod(0o700)
        subprocess.run(["chmod", "+a", "everyone allow search", str(legacy)], check=True)
        assert not foreign(path=legacy)  # ACL access is not reflected in owner/mode bits.
        assert not foreign(backend="macfuse")
        assert not foreign(mount_owner=owner if owner else other)
        assert foreign(path=work / f".veracrypt_aux_root_{owner}")
        assert not foreign(path=work / f".veracrypt_aux_root_{owner}", user=owner, real=owner)
        assert not foreign(path=work / ".veracrypt_aux_root_invalid-ABCDEFGHIJKL")

        for kind in ("symlink", "file", "directory"):
            base = case(kind)
            path = base / f"{prefix}{owner}"
            if kind == "symlink":
                path.symlink_to(directory, target_is_directory=True)
            elif kind == "file":
                path.write_text("unchanged")
            else:
                path.mkdir(mode=0o700)
            before = path.lstat()
            assert create(base) != path
            after = path.lstat()
            assert (before.st_ino, before.st_uid, before.st_mode) == (after.st_ino, after.st_uid, after.st_mode)
        assert sentinel.read_text() == "private directory regression fixture\n"

        base = case("inherited-acl")
        subprocess.run(["chmod", "+a", "everyone allow read,search,directory_inherit", str(base)], check=True)
        inherited = create(base)
        acl = subprocess.check_output(["ls", "-lde", str(inherited)], text=True)
        entries = re.findall(r"^\s*\d+: (.+)$", acl, re.M)
        assert len(entries) == (1 if elevated and owner else 0), acl
        if entries:
            assert entries[0].endswith(" allow list,search,readattr,readsecurity"), acl

        for failure in ("noowners", "acl-failure"):
            base = case(failure)
            create(base, succeeds=False, command=failure)
            assert not list(base.iterdir()), "Failed parent setup left a directory"

        base = case("concurrent")
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            paths = list(pool.map(lambda _: create(base), range(24)))
        assert len(set(paths)) == 24 and set(base.iterdir()) == set(paths)
        for parent in paths:
            child = parent / ".veracrypt_aux_mnt-unit"
            child.mkdir()
            subprocess.run([str(binary), "service-mounted", str(child)], check=True)
            assert child.exists() and parent.exists()
            subprocess.run([str(binary), "service-cleanup", str(child)], check=True)
            assert not child.exists() and not parent.exists()
        # An older client can remove the child before its service exits.
        parent = create(base)
        child = parent / ".veracrypt_aux_mnt-unit"
        child.mkdir()
        subprocess.run([str(binary), "service-removed", str(child)], check=True)
        assert not parent.exists()
        for target in ("child", "parent"):
            parent = create(base)
            child = parent / ".veracrypt_aux_mnt-unit"
            child.mkdir()
            subprocess.run([str(binary), "service-replaced-" + target, str(child)], check=True)
            assert parent.exists(), "Removed a replacement parent"
            if target == "child":
                assert child.exists(), "Removed a replacement child"
        # The fallback removes only empty parents in the per-mount format.
        parent = create(base)
        subprocess.run([str(binary), "cleanup", str(parent / ".veracrypt_aux_mnt-unit")], check=True)
        assert not parent.exists()
        for name in ("legacy-tmp", f"{prefix}{owner}", f"{prefix}{owner}-invalid"):
            parent = base / name
            parent.mkdir()
            child = parent / ".veracrypt_aux_mnt-unit"
            child.mkdir()
            subprocess.run([str(binary), "service-cleanup", str(child)], check=True)
            assert parent.exists() and not child.exists()
        print("PASS: unique parents, owner/mode, ACL normalization, setup rollback, discovery, legacy preservation, service cleanup")

        if os.geteuid() == 0 and owner != 0:
            for uid, allowed in ((owner, True), (other, False)):
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setgroups([])
                        os.setgid(20)
                        os.setuid(uid)
                        try:
                            with sentinel.open("rb") as stream:
                                stream.read(1)
                            assert allowed
                        except PermissionError:
                            assert not allowed
                        # Read/search access must not allow path replacement.
                        try:
                            (directory / "replacement").mkdir()
                            raise AssertionError("caller can modify the elevated parent")
                        except PermissionError:
                            pass
                        try:
                            directory.chmod(0o777)
                            raise AssertionError("caller can change the elevated parent's permissions")
                        except PermissionError:
                            pass
                        try:
                            directory.rename(directory.with_name("replacement-parent"))
                            raise AssertionError("caller can replace the elevated parent")
                        except PermissionError:
                            pass
                        # Discovery also works without entering the parent.
                        expected = "0" if allowed else "1"
                        output = subprocess.check_output([str(binary), "filter",
                            str(directory / ".veracrypt_aux_mnt-unit"),
                            "0", "smbfs", str(uid), str(uid)], text=True)
                        assert output.strip() == expected
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                _, status = os.waitpid(pid, 0)
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (uid, status)
            print("PASS: root owns elevated parent; caller has read/search only; unrelated uid gets EACCES; discovery scope")


if __name__ == "__main__":
    main()
