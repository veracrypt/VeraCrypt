#!/usr/bin/env python3
"""Regression test for issue #1959, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_linux_emergency_dismount_remount.py [--veracrypt PATH]

Mounts a small volume and keeps a file on it open. After an emergency
dismount the volume stays in use, by the FUSE service (nokernelcrypto) or by
the deferred device-mapper device (kernel crypto), so mounting the volume
again must fail; it must work once the file is closed and the volume has
been released. Also checks that mounting a volume through another path
while it is mounted fails at once.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASSWORD_A = "regression-test-password-a"
# A low PIM keeps the tests fast; it needs passwords of 20 characters or more.
COMMON = ["--pim=1", "--keyfiles="]


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


def wait_for_exit(pid, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not os.path.exists("/proc/%d" % pid):
            return True
        time.sleep(0.5)
    return False


def mount_options(kernel_crypto):
    return COMMON + ["--protect-hidden=no"] + (
        [] if kernel_crypto else ["--mount-options=nokernelcrypto"])


def mount(vc, volume, mount_point, kernel_crypto=False):
    return vc.run(["--non-interactive", "-p", PASSWORD_A]
                  + mount_options(kernel_crypto)
                  + [str(volume), str(mount_point)])


def listed_device(vc, volume):
    for line in text(vc.run(["--list"])).splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == str(volume):
            return fields[2]
    return ""


def test_detached_service(vc, c, volume, mount_point, second_mount_point,
                          kernel_crypto):
    name = "#1959 (%s)" % ("kernel crypto" if kernel_crypto else "FUSE")
    r = mount(vc, volume, mount_point, kernel_crypto)
    c.check("%s: mount" % name, r.returncode == 0, text(r))
    device = listed_device(vc, volume)
    if kernel_crypto and not device.startswith("/dev/mapper/"):
        print("skip %s: kernel crypto not used (%s)" % (name, device))
        vc.dismount(mount_point)
        return
    pid = vc.service(volume)
    busy = open(mount_point / "busy", "w")
    try:
        r = vc.run(["--non-interactive", "-d", "--emergency-unmount",
                    str(mount_point)])
        c.check("%s: emergency dismount" % name, r.returncode == 0, text(r))
        if not kernel_crypto:
            c.check("%s: the old service is still running" % name,
                    pid is not None and os.path.exists("/proc/%d" % pid))
        r = mount(vc, volume, second_mount_point, kernel_crypto)
        c.check("%s: mounting again while the volume is in use fails" % name,
                r.returncode != 0 and "already mounted" in text(r), text(r))
        if r.returncode == 0:
            vc.dismount(second_mount_point)
    finally:
        busy.close()
    if not kernel_crypto:
        c.check("%s: the old service exits once the file is closed" % name,
                pid is None or wait_for_exit(pid, 30))
    end = time.monotonic() + 30
    while True:
        r = mount(vc, volume, second_mount_point, kernel_crypto)
        if r.returncode == 0 or time.monotonic() > end:
            break
        time.sleep(1)
    c.check("%s: mounting again after the volume is released works" % name,
            r.returncode == 0, text(r))
    vc.dismount(second_mount_point)


def test_other_path(vc, c, volume, mount_point, second_mount_point):
    alias = vc.work / "alias.hc"
    alias.symlink_to(volume)
    r = mount(vc, volume, mount_point)
    c.check("#1959: mount", r.returncode == 0, text(r))
    start = time.monotonic()
    r = mount(vc, alias, second_mount_point)
    elapsed = time.monotonic() - start
    c.check("#1959: mounting through another path fails at once (%.1f s)"
            % elapsed,
            r.returncode != 0 and "already mounted" in text(r)
            and elapsed < 5, text(r))
    c.check("#1959: dismount", vc.dismount_volumes([volume, alias]))


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
    mount_points = [work / name for name in ("a", "b")[:2]]
    for mount_point in mount_points:
        mount_point.mkdir()
    (work / "random").write_bytes(os.urandom(4096))
    volume = work / "a.hc"
    try:
        r = vc.create(volume, "10M", PASSWORD_A, "ext4")
        c.check("create %s" % volume.name, r.returncode == 0, text(r))
        if c.failures:
            sys.exit("Cannot create the test volume")
        for kernel_crypto in (False, True):
            test_detached_service(vc, c, volume, mount_points[0],
                                  mount_points[1], kernel_crypto)
        test_other_path(vc, c, volume, mount_points[0], mount_points[1])
    finally:
        # Only the volumes of this test: unrelated ones may be mounted
        if (not vc.dismount_volumes([volume, work / "alias.hc"])
                or any(os.path.ismount(m) for m in mount_points)):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
