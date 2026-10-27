#!/usr/bin/env python3
"""Regression test for issue #1958, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_linux_fuse_service_memory.py [--veracrypt PATH]

Mounts a small volume through FUSE (nokernelcrypto) and checks that the
FUSE service, which holds the master keys, has locked memory and a core
file size limit of zero.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORD_A = "regression-test-password-a"
# A low PIM keeps the tests fast; it needs passwords of 20 characters or more.
COMMON = ["--pim=1", "--keyfiles="]
MOUNT = COMMON + ["--protect-hidden=no", "--mount-options=nokernelcrypto"]


class Checks:
    def __init__(self):
        self.failures = 0

    def check(self, desc, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + desc, flush=True)
        if not cond:
            self.failures += 1
            if detail:
                print("     " + detail.strip().replace("\n", "\n     "))


def text(result):
    return (result.stdout or b"").decode("utf-8", "replace")


class VeraCrypt:
    def __init__(self, path, work):
        self.path = path
        self.binary = os.path.realpath(path)
        self.work = work

    def run(self, args, stdin=None, timeout=300):
        return subprocess.run([self.path, "--text"] + args, input=stdin,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=self.work,
                              timeout=timeout)

    def create(self, path, size, password, filesystem, volume_type="normal"):
        return self.run(["--non-interactive", "--create", str(path),
                         "--size=" + size, "--volume-type=" + volume_type,
                         "--encryption=AES", "--hash=SHA-512",
                         "--filesystem=" + filesystem, "-p", password,
                         "--random-source=" + str(self.work / "random")]
                        + COMMON)

    def mount(self, volume, password, mount_point=None, extra=()):
        args = ["--non-interactive", "-p", password] + MOUNT + list(extra)
        args.append(str(volume))
        if mount_point:
            args.append(str(mount_point))
        return self.run(args)

    def dismount(self, target):
        return self.run(["--non-interactive", "-d", str(target)])

    def mounted_volumes(self):
        """Paths of the mounted volumes; raises if they cannot be listed."""
        r = self.run(["--list"])
        if r.returncode != 0:
            if "No volumes mounted" in text(r):
                return set()
            raise RuntimeError("veracrypt --list failed: " + text(r))
        return {line.split()[1] for line in text(r).splitlines()
                if len(line.split()) >= 4 and line.split()[0].endswith(":")}

    def dismount_volumes(self, volumes):
        """Dismounts only these volumes; returns whether none remains."""
        paths = {str(volume) for volume in volumes}
        for path in paths & self.mounted_volumes():
            self.dismount(path)
        return not paths & self.mounted_volumes()

    def service(self, volume):
        """PID of the FUSE service that has the volume file open."""
        volume = os.path.realpath(volume)
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                if os.readlink("/proc/%s/exe" % entry) != self.binary:
                    continue
                fds = ["/proc/%s/fd/%s" % (entry, fd)
                       for fd in os.listdir("/proc/%s/fd" % entry)]
                targets = {os.readlink(fd) for fd in fds}
            except OSError:
                continue
            if "/dev/fuse" in targets and volume in targets:
                return int(entry)
        return None


def process_status(pid, field):
    with open("/proc/%d/status" % pid) as status:
        for line in status:
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
    return ""


def core_limit(pid):
    with open("/proc/%d/limits" % pid) as limits:
        for line in limits:
            if line.startswith("Max core file size"):
                return line.split()[4:6]
    return []


def test_memory(vc, c, volume, mount_point):
    r = vc.mount(volume, PASSWORD_A, mount_point)
    c.check("#1958: mount", r.returncode == 0, text(r))
    pid = vc.service(volume)
    c.check("#1958: find the FUSE service", pid is not None)
    if pid:
        locked = process_status(pid, "VmLck")
        c.check("#1958: the FUSE service has locked memory",
                locked.split()[:1] != ["0"], "VmLck: " + locked)
        limit = core_limit(pid)
        c.check("#1958: the FUSE service cannot write a core file",
                limit == ["0", "0"], "core file size limit: %s" % limit)
    c.check("#1958: dismount", vc.dismount_volumes([volume]))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root: the test mounts volumes")

    work = Path(tempfile.mkdtemp(prefix="vc-regression-"))
    vc = VeraCrypt(args.veracrypt, work)
    c = Checks()
    mount_points = [work / name for name in ("a", "b")[:1]]
    for mount_point in mount_points:
        mount_point.mkdir()
    (work / "random").write_bytes(os.urandom(4096))
    try:
        volume = work / "a.hc"
        r = vc.create(volume, "10M", PASSWORD_A, "ext4")
        c.check("create %s" % volume.name, r.returncode == 0, text(r))
        if c.failures:
            sys.exit("Cannot create the test volume")
        test_memory(vc, c, volume, mount_points[0])
    finally:
        # Only the volume of this test: unrelated ones may be mounted
        if (not vc.dismount_volumes([work / "a.hc"])
                or any(os.path.ismount(m) for m in mount_points)):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
