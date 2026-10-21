#!/usr/bin/env python3
"""Test the fstab helper mount.veracrypt against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_mount_helper.py [--helper /usr/sbin/mount.veracrypt]
      [--veracrypt /usr/bin/veracrypt]

The helper always runs /usr/bin/veracrypt; --veracrypt is only used here to
list and unmount. A copy of Tests/test.sha512.hc (password "test") is
mounted through the helper and through mount(8). Checked:

- password= mounts the volume;
- the helper itself rejects -N, unknown options, a missing -o or -t
  argument (also when another flag follows -t) and extra arguments; these
  run with -f, so veracrypt cannot be what refused them;
- -f checks the options and does not mount;
- the last of ro/rw sets both VeraCrypt's protection and the filesystem;
  repeated -o lists are joined and empty elements ignored.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "Tests" / "test.sha512.hc"
PASSWORD = "test"


class Checks:
    def __init__(self):
        self.failures = 0

    def check(self, desc, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + desc, flush=True)
        if not cond:
            self.failures += 1
            if detail:
                print("     " + detail.strip().replace("\n", "\n     "))


def run(cmd, timeout=600):
    return subprocess.run(cmd, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)


def text(r):
    return r.stdout.decode("utf-8", "replace")


def fs_mode(mountpoint):
    """ro or rw of the filesystem mounted on mountpoint, or None."""
    with open("/proc/self/mountinfo") as f:
        for line in f:
            fields = line.split()
            if fields[4] == str(mountpoint):
                return fields[5].split(",")[0]
    return None


def aux_mounts():
    with open("/proc/self/mountinfo", "rb") as f:
        return [l for l in f if b"veracrypt_aux_mnt" in l]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", default="/usr/sbin/mount.veracrypt")
    parser.add_argument("--veracrypt", default="/usr/bin/veracrypt")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("must run as root (mounting)")

    vc = args.veracrypt
    c = Checks()
    work = Path(tempfile.mkdtemp(prefix="vc-helper-"))
    mnt = work / "mnt"
    mnt.mkdir()
    volume = work / "test.hc"
    shutil.copyfile(FIXTURE, volume)

    def mounted():
        return run([vc, "--text", "--non-interactive", "--list",
                    str(volume)]).returncode == 0

    def unmount():
        if mounted():
            run([vc, "--text", "--non-interactive", "--unmount",
                 str(volume)])
        return not mounted()

    def helper(options=None, extra=()):
        cmd = ["sh", args.helper, str(volume), str(mnt), *extra]
        if options is not None:
            cmd += ["-o", options]
        return run(cmd)

    try:
        r = helper("password=" + PASSWORD)
        c.check("password= mounts", r.returncode == 0 and mounted(), text(r))
        c.check("volume content readable", mounted() and
                (mnt / "Dummy.txt").read_text() == "Dummy")
        unmount()

        # Rejected by the helper itself: with -f, veracrypt never runs.
        pw = "password=" + PASSWORD
        for desc, options, extra in (
                ("-N namespace", pw, ("-N", "1")),
                ("unknown option", pw, ("-x",)),
                ("missing -o argument", None, ("-o",)),
                ("missing -t argument at the end", pw, ("-t",)),
                ("missing -t argument before -f", pw, ("-t", "-f")),
                ("extra argument", pw, ("extra",))):
            cmd = ["sh", args.helper, str(volume), str(mnt), "-f"]
            if options is not None:
                cmd += ["-o", options]
            r = run(cmd + list(extra))
            c.check("%s rejected by the helper" % desc,
                    r.returncode != 0 and "mount.veracrypt:" in text(r)
                    and not mounted(), text(r))
            unmount()
        r = helper(pw, ("-f",))
        c.check("-f checks the options and does not mount",
                r.returncode == 0 and not mounted(), text(r))
        unmount()

        # ro/rw: the last one wins for VeraCrypt and the filesystem.
        for desc, options, extra, read_only in (
                ("ro", pw + ",ro", (), True),
                ("ro,rw", pw + ",ro,rw", (), False),
                ("rw,ro", pw + ",rw,ro", (), True),
                ("second -o ro", pw, ("-o", "ro"), True),
                ("empty elements", "," + pw + ",,ro,", (), True)):
            r = helper(options, extra)
            props = text(run([vc, "--text", "--non-interactive", "--list",
                              "--verbose", str(volume)]))
            vc_ro = re.search(r"read-only:\s*yes", props, re.I) is not None
            fs = fs_mode(mnt)
            c.check("%s: read-only %s for VeraCrypt and the filesystem"
                    % (desc, read_only),
                    r.returncode == 0 and vc_ro == read_only
                    and fs == ("ro" if read_only else "rw"),
                    text(r) + props + "fs=%s" % fs)
            unmount()

        # Through mount(8).
        r = run(["mount", "-t", "veracrypt", "-o", pw, str(volume),
                 str(mnt)])
        c.check("mount -t veracrypt mounts", r.returncode == 0 and mounted(),
                text(r))
        unmount()
        r = run(["mount", "-f", "-t", "veracrypt", "-o", pw, str(volume),
                 str(mnt)])
        c.check("mount -f -t veracrypt does not mount",
                r.returncode == 0 and not mounted(), text(r))
        unmount()
        c.check("no VeraCrypt FUSE mount left", not aux_mounts(),
                b"".join(aux_mounts()).decode("utf-8", "replace"))
    finally:
        unmount()
        if os.path.ismount(mnt) or aux_mounts():
            sys.exit("a test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
