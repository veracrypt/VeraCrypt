#!/usr/bin/env python3
"""Regression test for issue #1960, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_linux_parallel_mounts.py [--veracrypt PATH] [--rounds N]

Mounts two small volumes at the same time, repeatedly, and checks that both
mounts succeed and each volume appears in its own slot at its own mount
point:

- with --slot and a mount directory, through FUSE (nokernelcrypto);
- without --slot, with a mount directory, through FUSE;
- without --slot or a mount directory, so that each mount chooses a free
  slot and its default mount point, through FUSE and with kernel crypto
  (counted only if the volumes use device-mapper devices).

Also checks that occupying all names of the former auxiliary mount points
(.veracrypt_aux_mnt1 to 256, in a private TMPDIR) does not prevent
mounting. Only the volumes created by the test are dismounted; if that
fails, its files are kept.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORDS = {"a": "regression-test-password-a",
             "b": "regression-test-password-b"}
# The default PIM, so that opening a volume takes long enough for two mounts
# to overlap, as with ordinary volumes.
COMMON = ["--pim=0", "--keyfiles=", "--hash=sha512", "--protect-hidden=no"]
FUSE = ["--mount-options=nokernelcrypto"]


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
        self.work = work

    def command(self, args):
        return [self.path, "--text"] + args

    def run(self, args, env=None, timeout=300):
        return subprocess.run(self.command(args), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=self.work,
                              env=env, timeout=timeout)

    def mount_args(self, name, options, mount_point=None, slot=None):
        args = ["--non-interactive", "-p", PASSWORDS[name]] + COMMON + options
        if slot:
            args.append("--slot=%d" % slot)
        args.append(str(self.work / ("%s.hc" % name)))
        if mount_point:
            args.append(str(mount_point))
        return args

    def listed_volumes(self):
        """(slot, volume, device, mount point) of each mounted volume;
        raises if the volumes cannot be listed."""
        r = self.run(["--list"])
        if r.returncode != 0:
            if "No volumes mounted" in text(r):
                return []
            raise RuntimeError("veracrypt --list failed: " + text(r))
        volumes = []
        for line in text(r).splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0].endswith(":"):
                volumes.append((fields[0][:-1], fields[1], fields[2],
                                fields[-1]))
        return volumes

    def dismount_volumes(self, volumes):
        """Dismounts only these volumes; returns whether none remains."""
        paths = {str(volume) for volume in volumes}
        for _, path, _, _ in self.listed_volumes():
            if path in paths:
                self.run(["--non-interactive", "-d", path])
        return not any(path in paths for _, path, _, _ in
                       self.listed_volumes())


def parallel_rounds(vc, c, desc, rounds, requests, kernel_crypto=False):
    """Mounts both volumes at the same time, 'rounds' times. 'requests'
    gives the mount arguments of each volume."""
    volumes = [str(vc.work / ("%s.hc" % name)) for name in requests]
    failed = []
    fallback = False
    for _ in range(rounds):
        jobs = [subprocess.Popen(vc.command(args), stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=vc.work)
                for args in requests.values()]
        results = [(job.communicate(timeout=300)[0].decode(
            "utf-8", "replace"), job.returncode) for job in jobs]
        try:
            listed = vc.listed_volumes()
        except RuntimeError as e:
            failed.append(str(e))
            break
        ours = [entry for entry in listed if entry[1] in volumes]
        markers = []
        for _, path, _, mount_point in ours:
            try:
                markers.append((Path(path).stem, (Path(mount_point)
                                / "marker").read_text().strip()))
            except OSError:
                markers.append((Path(path).stem, None))
        if (any(code != 0 for _, code in results) or len(ours) != 2
                or len({slot for slot, _, _, _ in ours}) != 2
                or len({point for _, _, _, point in ours}) != 2
                or any(name != marker for name, marker in markers)):
            failed.append("mounted: %s, markers: %s\n%s" % (
                ours, markers, "\n".join(output for output, _ in results)))
        if kernel_crypto and not all(device.startswith("/dev/mapper/")
                                     for _, _, device, _ in ours):
            fallback = True
        # A mount left from this round must not supply the next one
        if not vc.dismount_volumes(volumes):
            failed.append("the volumes could not be dismounted")
            break
    if fallback and not failed:
        print("skip #1960: %s: kernel crypto was not used" % desc)
        return
    c.check("#1960: %s" % desc, not failed, "\n".join(failed[:3]))


def test_old_aux_names(vc, c):
    # All names that earlier versions tried, so that skipping a blocked one
    # does not help
    temporary = vc.work / "tmp"
    temporary.mkdir()
    for i in range(1, 257):
        old = temporary / (".veracrypt_aux_mnt%d" % i)
        old.mkdir()
        (old / "file").write_text("x")
        os.chown(old, 65534, 65534)
    env = dict(os.environ, TMPDIR=str(temporary))
    r = vc.run(vc.mount_args("a", FUSE, vc.work / "a"), env=env)
    c.check("#1960: mounting with all former auxiliary mount point names "
            "taken", r.returncode == 0, text(r))
    c.check("#1960: dismount", vc.dismount_volumes([vc.work / "a.hc"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    parser.add_argument("--rounds", type=int, default=10,
                        help="rounds of parallel mounts of each kind")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root: the test mounts volumes")

    work = Path(tempfile.mkdtemp(prefix="vc-regression-"))
    vc = VeraCrypt(args.veracrypt, work)
    c = Checks()
    mount_points = [work / name for name in ("a", "b")]
    for mount_point in mount_points:
        mount_point.mkdir()
    (work / "random").write_bytes(os.urandom(4096))
    volumes = [work / "a.hc", work / "b.hc"]
    try:
        for name in PASSWORDS:
            r = vc.run(["--non-interactive", "--create",
                        str(work / ("%s.hc" % name)), "--size=10M",
                        "--volume-type=normal", "--encryption=AES",
                        "--hash=SHA-512", "--filesystem=ext4", "-p",
                        PASSWORDS[name], "--pim=0", "--keyfiles=",
                        "--random-source=" + str(work / "random")])
            c.check("create %s.hc" % name, r.returncode == 0, text(r))
            r = vc.run(vc.mount_args(name, FUSE, mount_points[0]))
            if r.returncode == 0:
                (mount_points[0] / "marker").write_text(name)
            c.check("write the marker of %s.hc" % name,
                    r.returncode == 0 and vc.dismount_volumes(volumes),
                    text(r))
        if c.failures:
            sys.exit("Cannot create the test volumes")

        parallel_rounds(vc, c, "%d rounds with --slot" % args.rounds,
                        args.rounds,
                        {"a": vc.mount_args("a", FUSE, mount_points[0], 1),
                         "b": vc.mount_args("b", FUSE, mount_points[1], 2)})
        parallel_rounds(vc, c, "%d rounds without --slot, with mount "
                        "directories" % args.rounds, args.rounds,
                        {"a": vc.mount_args("a", FUSE, mount_points[0]),
                         "b": vc.mount_args("b", FUSE, mount_points[1])})
        parallel_rounds(vc, c, "%d rounds without --slot or mount directory "
                        "(FUSE)" % args.rounds, args.rounds,
                        {"a": vc.mount_args("a", FUSE),
                         "b": vc.mount_args("b", FUSE)})
        parallel_rounds(vc, c, "%d rounds without --slot or mount directory "
                        "(kernel crypto)" % args.rounds, args.rounds,
                        {"a": vc.mount_args("a", []),
                         "b": vc.mount_args("b", [])}, kernel_crypto=True)
        test_old_aux_names(vc, c)
    finally:
        # Only the volumes of this test: unrelated ones may be mounted
        if (not vc.dismount_volumes(volumes)
                or any(os.path.ismount(m) for m in mount_points)):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
