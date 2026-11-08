#!/usr/bin/env python3
"""Exercise production helper lookup and the Linux elevation restriction check.

Uses a fake filesystem to test trusted paths without changing system files.
The kernel check also runs with real NoNewPrivs in a separate process.
Pass --veracrypt to check the diagnostic in a built binary as an ordinary user.
"""
import argparse
import ctypes
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def between(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--veracrypt", type=Path)
    parser.add_argument("--probe-output", type=Path, help="save the tested resolver probe for filesystem integration checks")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("these tests require Linux")

    process = (ROOT / "src/Platform/Unix/Process.cpp").read_text()
    service = (ROOT / "src/Core/Unix/CoreService.cpp").read_text()
    lookup = between(process, "\tbool Process::IsExecutable", "\tstring Process::Execute (")
    guard_headers = between(service, "#ifdef TC_LINUX\n#include <sys/prctl.h>", '#include "Platform/FileStream.h"')
    guard = between(service, "\tstatic void CheckPrivilegeElevationAllowed", "\tstatic PrivilegeHelper FindPrivilegeHelper")
    prelude = r'''
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits.h>
#include <map>
#include <sstream>
#include <stdio.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/prctl.h>

#ifdef TEST_OLD_HEADERS
#undef PR_GET_NO_NEW_PRIVS
#endif

static void Require(bool value, const char *message) {
    if (!value) throw std::runtime_error(message);
}
using std::string;
using std::vector;
struct Entry {
    mode_t Mode;
    uid_t Owner;
    string Target, Contents;
    Entry(mode_t mode = 0, uid_t owner = 0, string target = "", string contents = "")
        : Mode(mode), Owner(owner), Target(target), Contents(contents) {}
};
static std::map<string, Entry> Files;
static std::vector<std::string> Probes;
static bool UseFilesystem;
static bool StoreReadOnly = true, StatvfsFails;
static string Normalize(const string &path) {
    std::istringstream input(path);
    vector<string> parts;
    string part, result;
    while (std::getline(input, part, '/')) {
        if (part.empty() || part == ".") continue;
        if (part == "..") { if (!parts.empty()) parts.pop_back(); }
        else parts.push_back(part);
    }
    for (const auto &component : parts) result += "/" + component;
    return result.empty() ? "/" : result;
}
static int FakeLstat(const char *path, struct stat *result) {
    if (UseFilesystem) return ::lstat(path, result);
    Probes.push_back(path);
    auto found = Files.find(Normalize(path));
    if (found == Files.end()) { errno = ENOENT; return -1; }
    *result = {};
    result->st_mode = found->second.Mode;
    result->st_uid = found->second.Owner;
    return 0;
}
static int FakeStat(const char *path, struct stat *result) {
    if (UseFilesystem) return ::stat(path, result);
    string current = path;
    for (int links = 0; links <= 40; ++links) {
        if (FakeLstat(current.c_str(), result) != 0) return -1;
        if (!S_ISLNK(result->st_mode)) return 0;
        string target = Files.at(Normalize(current)).Target;
        current = target[0] == '/' ? target : current.substr(0, current.rfind('/') + 1) + target;
    }
    errno = ELOOP;
    return -1;
}
static ssize_t FakeReadlink(const char *path, char *buffer, size_t size) {
    if (UseFilesystem) return ::readlink(path, buffer, size);
    auto found = Files.find(Normalize(path));
    if (found == Files.end() || !S_ISLNK(found->second.Mode)) { errno = EINVAL; return -1; }
    string target = found->second.Target;
    size_t count = target.size() < size ? target.size() : size;
    std::memcpy(buffer, target.data(), count);
    return count;
}
static FILE *FakeFopen(const char *path, const char *mode) {
    if (UseFilesystem) return ::fopen(path, mode);
    auto found = Files.find(Normalize(path));
    if (found == Files.end()) { errno = ENOENT; return nullptr; }
    FILE *file = tmpfile();
    Require(file != nullptr, "cannot create metadata fixture");
    const string &contents = found->second.Contents;
    Require(fwrite(contents.data(), 1, contents.size(), file) == contents.size(), "cannot write metadata fixture");
    rewind(file);
    return file;
}
static int FakeStatvfs(const char *path, struct statvfs *result) {
    if (UseFilesystem) return ::statvfs(path, result);
    if (StatvfsFails) { errno = EACCES; return -1; }
    *result = {};
    result->f_flag = StoreReadOnly ? ST_RDONLY : 0;
    return 0;
}
#define stat(path, result) FakeStat(path, result)
#define lstat(path, result) FakeLstat(path, result)
#define readlink(path, buffer, size) FakeReadlink(path, buffer, size)
#define fopen(path, mode) FakeFopen(path, mode)
#define statvfs(path, result) FakeStatvfs(path, result)
class Process {
public:
    static bool IsExecutable(const std::string &);
    static std::string FindSystemBinary(const char *, std::string &);
};

struct ElevationBlocked : std::runtime_error {
    explicit ElevationBlocked(const char *message) : std::runtime_error(message) {}
};
#define SRC_POS "test"
static int QueryResult, QueryError, QueryCount;
static bool UseKernel;
static int TestPrctl(int option, long a, long b, long c, long d) {
    Require(option == 39 && a == 0 && b == 0 && c == 0 && d == 0,
        "invalid PR_GET_NO_NEW_PRIVS query");
    ++QueryCount;
    if (UseKernel) return ::prctl(option, a, b, c, d);
    errno = QueryError;
    return QueryResult;
}
#define prctl(option, a, b, c, d) TestPrctl(option, a, b, c, d)
'''
    tests = r'''
#undef prctl
#undef stat
#undef lstat
#undef readlink
#undef fopen
#undef statvfs
static void ExpectPath(const char *name, const std::string &expected) {
    std::string error;
    Probes.clear();
    Require(Process::FindSystemBinary(name, error) == expected, "wrong helper selected");
    if (expected.empty())
        Require(errno == ENOENT && error.find("not found in system directories") != std::string::npos,
            "missing helper lost its diagnostic");
}
static void ExpectNoNixLookup() {
    ExpectPath("sudo", "/usr/bin/sudo");
    for (const auto &path : Probes)
        Require(path.find("/run/") != 0, "NixOS locations used without trusted NixOS metadata");
}
static void NixFixture() {
    Files.clear();
    StoreReadOnly = true;
    StatvfsFails = false;
    for (const char *path : {"/", "/etc", "/run", "/run/wrappers", "/run/wrappers/wrappers.test",
            "/nix", "/nix/store", "/nix/store/system", "/nix/store/profile", "/nix/store/profile/bin",
            "/nix/store/tools", "/nix/store/tools/bin"})
        Files[path] = Entry(S_IFDIR | 0755);
    Files["/etc/os-release"] = Entry(S_IFLNK | 0777, 0, "../nix/store/os-release");
    Files["/nix/store/os-release"] = Entry(S_IFREG | 0444, 0, "", "NAME=NixOS\nID=nixos\n");
    Files["/run/wrappers/bin"] = Entry(S_IFLNK | 0777, 0, "wrappers.test");
    Files["/run/current-system"] = Entry(S_IFLNK | 0777, 0, "/nix/store/system");
    Files["/nix/store/system/sw"] = Entry(S_IFLNK | 0777, 0, "../profile");
    for (const char *name : {"sudo", "true", "dmsetup", "mount", "umount", "losetup", "modprobe", "fsck", "mkfs.ext4"}) {
        Files[string("/nix/store/profile/bin/") + name] = Entry(S_IFLNK | 0777, 0, string("../../tools/bin/") + name);
        Files[string("/nix/store/tools/bin/") + name] = Entry(S_IFREG | 0555);
        Files[string("/usr/bin/") + name] = Entry(S_IFREG | 0755);
    }
    Files["/run/wrappers/wrappers.test/sudo"] = Entry(S_IFREG | 04511);
    Files["/run/wrappers/wrappers.test/doas"] = Entry(S_IFREG | 04511);
}
static bool IsBlocked() {
    try { CheckPrivilegeElevationAllowed(); }
    catch (const ElevationBlocked &) { return true; }
    return false;
}
int main(int argc, char **argv) {
    try {
#ifdef TC_LINUX
        if (argc == 3 && std::string(argv[1]) == "--resolve") {
            UseFilesystem = true;
            string error, path = Process::FindSystemBinary(argv[2], error);
            std::cout << (path.empty() ? error : path) << std::endl;
            return path.empty() ? 1 : 0;
        }
        if (argc == 3 && std::string(argv[1]) == "--trusted") {
            UseFilesystem = true;
            string path;
            struct stat info;
            if (!ResolveTrustedSystemPath(argv[2], path, info)) return 1;
            std::cout << path << std::endl;
            return 0;
        }
#endif
        if (argc == 2 && std::string(argv[1]) == "--kernel") {
#ifdef TC_LINUX
            UseKernel = true;
            int before = ::prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L);
            Require(before != -1, "kernel cannot query NoNewPrivs");
            Require(IsBlocked() == (before == 1), "wrong initial restriction state");
            Require(::prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) == 0,
                "cannot set NoNewPrivs in test process");
            Require(IsBlocked(), "real NoNewPrivs was not detected");
#endif
            return 0;
        }
        const mode_t executable = S_IFREG | 0755;
        setenv("PATH", "/tmp/untrusted:/home/test/.nix-profile/bin", 1);
        Files["/tmp/untrusted/sudo"] = executable;
        Files["/home/test/.nix-profile/bin/sudo"] = executable;
        ExpectPath("sudo", "");

        Files["/usr/bin/sudo"] = executable;
        ExpectPath("sudo", "/usr/bin/sudo");
        NixFixture();
#ifdef TC_LINUX
        ExpectPath("sudo", "/run/wrappers/bin/sudo");
        ExpectPath("doas", "/run/wrappers/bin/doas");
        for (const char *name : {"true", "dmsetup", "mount", "umount", "losetup", "modprobe", "fsck", "mkfs.ext4"}) {
            ExpectPath(name, string("/run/current-system/sw/bin/") + name);
        }
        for (mode_t mode : {S_IFREG | 0644, S_IFDIR | 0755, S_IFIFO | 0755}) {
            Files["/run/wrappers/wrappers.test/sudo"].Mode = mode;
            ExpectPath("sudo", "/run/current-system/sw/bin/sudo");
        }

        // Non-NixOS systems must ignore even existing, otherwise valid NixOS paths.
        for (const char *text : {"ID=ubuntu\n", "ID_LIKE=nixos\n", "# ID=nixos\n",
                "ID=nixos-extra\n", "ID=nixos\nID=ubuntu\n", "ID=\"nixos\" extra\n", ""}) {
            NixFixture();
            Files["/nix/store/os-release"].Contents = text;
            ExpectNoNixLookup();
        }
        for (const char *text : {"ID=nixos\n", "ID=\"nixos\"\n", "ID='nixos'\r\n"}) {
            NixFixture();
            Files["/nix/store/os-release"].Contents = text;
            ExpectPath("sudo", "/run/wrappers/bin/sudo");
        }
        NixFixture();
        Files.erase("/etc/os-release");
        ExpectNoNixLookup();
        NixFixture();
        Files["/etc/os-release"].Target = "/tmp/os-release";
        Files["/tmp"] = Entry(S_IFDIR | 01777);
        Files["/tmp/os-release"] = Entry(S_IFREG | 0444, 0, "", "ID=nixos\n");
        ExpectNoNixLookup();
        NixFixture();
        Files["/nix/store/os-release"].Contents = "ID=nixos\n" + string(65536, 'x');
        ExpectNoNixLookup();

        // Reject control by any non-root owner, or write access for group/other.
        for (const char *path : {"/", "/etc", "/etc/os-release", "/nix", "/nix/store", "/nix/store/os-release"}) {
            NixFixture();
            Files[path].Owner = 1000;
            ExpectNoNixLookup();
            if (S_ISLNK(Files[path].Mode)) continue;
            for (mode_t mode : {S_IWGRP, S_IWOTH}) {
                NixFixture();
                Files[path].Mode |= mode;
                ExpectNoNixLookup();
            }
        }
        for (const char *path : {"/run", "/run/wrappers", "/run/wrappers/bin",
                "/run/wrappers/wrappers.test", "/run/wrappers/wrappers.test/sudo"}) {
            NixFixture();
            Files.erase("/nix/store/profile/bin/sudo");
            Files[path].Owner = 1000;
            ExpectPath("sudo", "/usr/bin/sudo");
            if (S_ISLNK(Files[path].Mode)) continue;
            for (mode_t mode : {S_IWGRP, S_IWOTH}) {
                NixFixture();
                Files.erase("/nix/store/profile/bin/sudo");
                Files[path].Mode |= mode;
                ExpectPath("sudo", "/usr/bin/sudo");
            }
        }
        for (const char *path : {"/run/current-system", "/nix/store/system", "/nix/store/system/sw",
                "/nix/store/profile", "/nix/store/profile/bin", "/nix/store/profile/bin/true",
                "/nix/store/tools", "/nix/store/tools/bin", "/nix/store/tools/bin/true"}) {
            NixFixture();
            Files[path].Owner = 1000;
            ExpectPath("true", "/usr/bin/true");
            if (S_ISLNK(Files[path].Mode)) continue;
            for (mode_t mode : {S_IWGRP, S_IWOTH}) {
                NixFixture();
                Files[path].Mode |= mode;
                ExpectPath("true", "/usr/bin/true");
            }
        }
        // A root-owned link to a root-owned file still fails through a writable parent.
        for (const char *target : {"/tmp/helpers", "../../tmp/helpers", "/tmp/../nix/store/tools/bin"}) {
            NixFixture();
            Files.erase("/nix/store/profile/bin/sudo");
            Files["/tmp"] = Entry(S_IFDIR | 01777);
            Files["/tmp/helpers"] = Entry(S_IFDIR | 0755);
            Files["/tmp/helpers/sudo"] = Entry(executable);
            Files["/run/wrappers/bin"].Target = target;
            ExpectPath("sudo", "/usr/bin/sudo");
        }
        // Broken links and link cycles fail closed.
        for (const char *target : {"missing", "bin", "/run/wrappers/bin", ""}) {
            NixFixture();
            Files.erase("/nix/store/profile/bin/sudo");
            Files["/run/wrappers/bin"].Target = target;
            ExpectPath("sudo", "/usr/bin/sudo");
        }
        NixFixture();
        Files.erase("/run/wrappers");
        Files.erase("/run/current-system");
        ExpectPath("sudo", "/usr/bin/sudo");

        // The real NixOS store is sticky, group-writable, and mounted read-only.
        NixFixture();
        Files["/nix/store"].Mode = S_IFDIR | 01775;
        ExpectPath("sudo", "/run/wrappers/bin/sudo");
        ExpectPath("true", "/run/current-system/sw/bin/true");
        StoreReadOnly = false;
        ExpectNoNixLookup();
        StoreReadOnly = true;
        StatvfsFails = true;
        ExpectNoNixLookup();
        StatvfsFails = false;
        Files["/nix/store"].Mode = S_IFDIR | 01777;
        ExpectNoNixLookup();
        Files["/nix/store"].Mode = S_IFDIR | 0775;
        ExpectNoNixLookup();
        Files["/nix/store"].Mode = S_IFDIR | 01775;
        Files["/nix/store/tools/bin/true"].Mode |= S_IWGRP;
        ExpectPath("true", "/usr/bin/true");
        Files["/nix/store/tools/bin/true"].Mode = executable;
        Files["/nix/store/tools"].Mode |= S_IWGRP | S_ISVTX;
        ExpectPath("true", "/usr/bin/true");

        // Keep the invoked name when the checked target is a multicall binary.
        NixFixture();
        Files["/nix/store/tools/bin/coreutils"] = Entry(S_IFREG | 0555);
        Files["/nix/store/tools/bin/true"] = Entry(S_IFLNK | 0777, 0, "coreutils");
        ExpectPath("true", "/run/current-system/sw/bin/true");
#else
        ExpectNoNixLookup();
#endif
        Files["/opt/explicit/helper"] = executable;
        ExpectPath("/opt/explicit/helper", "/opt/explicit/helper");
        std::string error;
        Require(Process::FindSystemBinary(nullptr, error).empty() && errno == EINVAL,
            "null name handling changed");

        QueryResult = 0;
        Require(!IsBlocked(), "ordinary elevation blocked");
        QueryResult = 1;
#ifdef TC_LINUX
        Require(IsBlocked(), "NoNewPrivs did not block elevation");
#else
        Require(!IsBlocked() && QueryCount == 0, "Linux query used outside Linux");
#endif
        QueryResult = -1;
        QueryError = EINVAL;
        Require(!IsBlocked(), "unsupported query blocked older kernels");
        QueryError = EPERM;
        Require(!IsBlocked(), "failed query misreported as NoNewPrivs");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
'''
    with tempfile.TemporaryDirectory(prefix="vc-linux-helpers-") as directory:
        work = Path(directory)
        source = work / "helpers.cpp"
        source.write_text(prelude + guard_headers + lookup + guard + tests)
        compiler = shlex.split(os.environ.get("CXX", "c++"))
        for name, flags in [
            ("linux", ["-DTC_LINUX"]),
            ("old-headers", ["-DTC_LINUX", "-DTEST_OLD_HEADERS"]),
            ("other-unix", ["-DTC_MACOSX"]),
        ]:
            binary = work / name
            subprocess.run(compiler + ["-std=c++11", *flags, str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
            if name != "other-unix":
                subprocess.run([str(binary), "--kernel"], check=True)
            if name == "linux" and args.probe_output:
                shutil.copyfile(binary, args.probe_output)
                args.probe_output.chmod(0o755)
            print(f"PASS: {name} helper lookup and elevation checks", flush=True)

    if args.veracrypt:
        if os.geteuid() == 0:
            parser.error("--veracrypt must be tested as an ordinary user")
        binary = str(args.veracrypt.resolve())
        libc = ctypes.CDLL(None, use_errno=True)

        def restrict_privileges():
            if libc.prctl(38, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")

        command = [binary, "--text", "--non-interactive"]
        result = subprocess.run(command + ["--version"], preexec_fn=restrict_privileges,
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        result = subprocess.run(command + ["--mount", str(ROOT / "Tests/test.sha256.hc"),
                                "--password=test", "--pim=0", "--keyfiles=", "--protect-hidden=no",
                                "--filesystem=none", "--mount-options=ro"],
                                preexec_fn=restrict_privileges, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        entry = ET.parse(ROOT / "src/Common/Language.xml").find(".//entry[@key='LINUX_ELEVATION_BLOCKED']")
        message = entry.text.replace("\\n", "\n")
        assert result.returncode != 0 and message in output, output
        assert "Enter your user password" not in output, output
        print("PASS: built binary reports NoNewPrivs before authentication", flush=True)


if __name__ == "__main__":
    main()
