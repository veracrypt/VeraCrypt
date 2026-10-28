#!/usr/bin/env python3
"""Regression test for issue #1973, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_linux_mount_point_protection.py [--veracrypt PATH]

Mounts a volume containing a symbolic link to /etc at its default mount
point, and checks that another volume cannot be mounted on a new directory
under /etc through it:

- with a mount point that leads through the link (command line);
- with a favorite whose mount point contains "..".

Also checks that a directory that exists inside the mounted volume can
still be used as a mount point, and that a default mount point is created
for the user and removed after dismount.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

PASSWORD_A = "regression-test-password-a"
PASSWORD_B = "regression-test-password-b"
# A low PIM keeps the tests fast; it needs passwords of 20 characters or more.
COMMON = ["--pim=1", "--keyfiles=", "--protect-hidden=no"]


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


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root: the test mounts volumes")

    work = Path(tempfile.mkdtemp(prefix="vc-regression-"))
    config = work / "config" / "VeraCrypt"
    config.mkdir(parents=True)
    env = dict(os.environ, XDG_CONFIG_HOME=str(work / "config"))
    (work / "random").write_bytes(os.urandom(4096))
    targets = [Path("/etc") / ("vc-regression-" + uuid.uuid4().hex[:12])
               for _ in range(2)]
    c = Checks()

    def run(arguments):
        return subprocess.run([args.veracrypt, "--text"] + arguments,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=work, env=env,
                              timeout=300)

    def mounted():
        """Volume path and mount point of each mounted volume; raises if the
        volumes cannot be listed."""
        r = run(["--list"])
        if r.returncode != 0:
            if "No volumes mounted" in text(r):
                return {}
            raise RuntimeError("veracrypt --list failed: " + text(r))
        volumes = {}
        for line in text(r).splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0].endswith(":"):
                volumes[fields[1]] = fields[-1]
        return volumes

    def dismount(volumes):
        """Dismounts only these volumes, in the order given (a volume mounted
        inside another one first); returns whether none remains."""
        paths = [str(volume) for volume in volumes]
        for _ in paths:
            remaining = [path for path in paths if path in mounted()]
            if not remaining:
                return True
            for path in remaining:
                run(["--non-interactive", "-d", path])
        return not any(path in mounted() for path in paths)

    volume_a, volume_b = work / "a.hc", work / "b.hc"
    try:
        for volume, password in ((volume_a, PASSWORD_A),
                                 (volume_b, PASSWORD_B)):
            r = run(["--non-interactive", "--create", str(volume),
                     "--size=10M", "--volume-type=normal",
                     "--encryption=AES", "--hash=SHA-512",
                     "--filesystem=ext4", "-p", password, "--pim=1",
                     "--keyfiles=", "--random-source=" + str(work / "random")])
            c.check("create %s" % volume.name, r.returncode == 0, text(r))
        if c.failures:
            sys.exit("Cannot create the test volumes")

        r = run(["--non-interactive", "-p", PASSWORD_A] + COMMON
                + [str(volume_a)])
        mount_point = Path(mounted().get(str(volume_a), ""))
        c.check("mount a.hc at its default mount point",
                r.returncode == 0 and mount_point.is_dir(), text(r))
        if c.failures:
            sys.exit("Cannot mount the first test volume")
        (mount_point / "l").symlink_to("/etc")
        (mount_point / "existing").mkdir()

        r = run(["--non-interactive", "-p", PASSWORD_B] + COMMON
                + [str(volume_b), str(mount_point / "l" / targets[0].name)])
        c.check("#1973: a new mount point through a link to /etc is refused",
                r.returncode != 0 and not targets[0].exists(), text(r))
        c.check("dismount b.hc", dismount([volume_b]))

        (config / "Favorite Volumes.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<VeraCrypt>\n'
            '\t<favorites>\n\t\t<volume mountpoint="%s/../../etc/%s" '
            'slotnumber="5" readonly="0" system="0">%s</volume>\n'
            '\t</favorites>\n</VeraCrypt>\n'
            % (mount_point, targets[1].name, volume_b))
        r = run(["--non-interactive", "--auto-mount=favorites",
                 "-p", PASSWORD_B] + COMMON)
        c.check("#1973: a favorite mount point with \"..\" to /etc is refused",
                str(volume_b) not in mounted() and not targets[1].exists(),
                text(r))
        c.check("dismount b.hc", dismount([volume_b]))

        r = run(["--non-interactive", "-p", PASSWORD_B] + COMMON
                + [str(volume_b), str(mount_point / "existing")])
        c.check("#1973: an existing directory in a mounted volume can be used",
                r.returncode == 0
                and mounted().get(str(volume_b)) == str(
                    mount_point / "existing"), text(r))
        c.check("dismount both volumes", dismount([volume_b, volume_a]))

        r = run(["--non-interactive", "-p", PASSWORD_B] + COMMON
                + [str(volume_b)])
        default = Path(mounted().get(str(volume_b), ""))
        owner = int(os.environ.get("SUDO_UID", "0"))
        c.check("#1973: a default mount point is created for the user",
                r.returncode == 0 and default.is_dir()
                and os.stat(default).st_uid == owner, text(r))
        c.check("#1973: the default mount point is removed after dismount",
                dismount([volume_b]) and not default.exists())
    finally:
        # Only the volumes of this test: unrelated ones may be mounted
        if not dismount([volume_b, volume_a]):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        for target in targets:
            # Left by a version with the bug; removed only if empty
            if target.is_dir() and not os.path.ismount(target):
                os.rmdir(target)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
