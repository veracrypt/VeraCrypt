#!/usr/bin/env python3
"""Regression test for issue #1961, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_linux_protection_password_memory.py [--veracrypt PATH]

Mounts an outer volume with hidden volume protection through FUSE
(nokernelcrypto) and checks that the protection password is not in the
memory of the FUSE service, apart from the copy in its command line
([stack]).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORD_OUTER = "regression-outer-password-c"
PASSWORD_HIDDEN = "regression-hidden-password-d"
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


def memory_hits(pid, needle):
    """Occurrences of needle per mapping name in the memory of pid."""
    hits = {}
    with open("/proc/%d/maps" % pid) as maps, \
            open("/proc/%d/mem" % pid, "rb", 0) as mem:
        for line in maps:
            fields = line.split()
            if not fields[1].startswith("r") or "[vvar" in line:
                continue
            start, end = (int(x, 16) for x in fields[0].split("-"))
            name = fields[5] if len(fields) > 5 else "anonymous"
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except (OSError, ValueError, OverflowError):
                continue
            count = data.count(needle)
            if count:
                hits[name] = hits.get(name, 0) + count
    return hits


def test_protection_password(vc, c, work):
    volume = work / "hidden.hc"
    r = vc.create(volume, "10M", PASSWORD_OUTER, "none")
    c.check("#1961: create an outer volume", r.returncode == 0, text(r))
    r = vc.create(volume, "3M", PASSWORD_HIDDEN, "none", "hidden")
    c.check("#1961: create a hidden volume", r.returncode == 0, text(r))
    r = vc.run(["--non-interactive", "-p", PASSWORD_OUTER] + COMMON
               + ["--protect-hidden=yes",
                  "--protection-password=" + PASSWORD_HIDDEN,
                  "--protection-pim=1", "--protection-keyfiles=",
                  "--mount-options=nokernelcrypto", "--filesystem=none",
                  str(volume)])
    c.check("#1961: mount with hidden volume protection", r.returncode == 0,
            text(r))
    pid = vc.service(volume)
    c.check("#1961: find the FUSE service", pid is not None)
    if pid:
        hits = memory_hits(pid, PASSWORD_HIDDEN.encode())
        hits.pop("[stack]", None)
        c.check("#1961: the protection password is only in the command line",
                not hits, "found in %s" % hits)
    c.check("#1961: dismount", vc.dismount_volumes([volume]))


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
    (work / "random").write_bytes(os.urandom(4096))
    try:
        test_protection_password(vc, c, work)
    finally:
        # Only the volume of this test: unrelated ones may be mounted
        if not vc.dismount_volumes([work / "hidden.hc"]):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
