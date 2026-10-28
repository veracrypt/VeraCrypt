#!/usr/bin/env python3
"""Regression test for issue #1969 on Linux, against the installed veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_password_cache_kdf.py [--veracrypt PATH]

Creates three volumes with a PIM of 100: A (SHA-512) and C (SHA-256) share
a password, B (SHA-512) has another one. With password caching enabled,
mounts them as favorites in one run, typing only the passwords of A and B,
with KDF autodetection. Checked:

- B is mounted after its password is typed, and the cached password of A
  that is tried on B first fails without trying Argon2: with that PIM,
  Argon2 uses 1 GiB and 82 passes, so the run would take much longer than
  mounting the volumes one by one;
- C is mounted with the cached password of A, without a prompt, although
  that password was cached with another KDF.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASSWORD_A = "regression-cache-password-a"
PASSWORD_B = "regression-cache-password-b"
PIM = "100"
# Argon2 with PIM 100 takes far longer than this on any machine that can run
# it, while the PBKDF2 attempts for the volumes here take a fraction of it.
MARGIN = 15


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
    c = Checks()

    def run(arguments, stdin=None):
        return subprocess.run([args.veracrypt, "--text"] + arguments,
                              input=stdin, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=work, env=env,
                              timeout=1800)

    def mounted():
        """Paths of the mounted volumes; raises if they cannot be listed."""
        r = run(["--list"])
        if r.returncode != 0:
            if "No volumes mounted" in text(r):
                return set()
            raise RuntimeError("veracrypt --list failed: " + text(r))
        return {line.split()[1] for line in text(r).splitlines()
                if len(line.split()) >= 4 and line.split()[0].endswith(":")}

    def dismount(paths):
        """Dismounts only these volumes; returns whether none remains."""
        paths = {str(path) for path in paths}
        for path in paths & mounted():
            run(["--non-interactive", "-d", path])
        return not paths & mounted()

    mount_options = ["--pim=" + PIM, "--keyfiles=", "--protect-hidden=no",
                     "--filesystem=none", "--mount-options=nokernelcrypto"]
    volumes = {name: work / ("%s.hc" % name) for name in ("a", "b", "c")}
    try:
        for name, password, hash in (("a", PASSWORD_A, "SHA-512"),
                                     ("b", PASSWORD_B, "SHA-512"),
                                     ("c", PASSWORD_A, "SHA-256")):
            r = run(["--non-interactive", "--create", str(volumes[name]),
                     "--size=2M", "--volume-type=normal", "--encryption=AES",
                     "--hash=" + hash, "--filesystem=none", "-p", password,
                     "--pim=" + PIM, "--keyfiles=",
                     "--random-source=" + str(work / "random")])
            c.check("create %s.hc" % name, r.returncode == 0, text(r))
        if c.failures:
            sys.exit("Cannot create the test volumes")

        start = time.monotonic()
        r = run(["--non-interactive", "-p", PASSWORD_A, str(volumes["a"])]
                + mount_options)
        single = time.monotonic() - start
        c.check("mount a.hc with KDF autodetection",
                r.returncode == 0 and dismount([volumes["a"]]), text(r))

        (config / "Configuration.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<VeraCrypt>\n'
            '\t<configuration>\n\t\t<config key="CachePasswords">1</config>\n'
            '\t</configuration>\n</VeraCrypt>\n')
        (config / "Favorite Volumes.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<VeraCrypt>\n'
            '\t<favorites>\n' + "".join(
                '\t\t<volume mountpoint="" slotnumber="%d" readonly="0" '
                'system="0">%s</volume>\n' % (slot, volumes[name])
                for slot, name in ((1, "a"), (2, "b"), (3, "c")))
            + '\t</favorites>\n</VeraCrypt>\n')

        start = time.monotonic()
        # --load-preferences enables the password cache of Configuration.xml
        r = run(["--load-preferences", "--auto-mount=favorites"]
                + mount_options,
                stdin=("%s\n%s\n" % (PASSWORD_A, PASSWORD_B)).encode())
        favorites = time.monotonic() - start
        listed = mounted()
        c.check("all three favorites are mounted",
                r.returncode == 0
                and all(str(volumes[name]) in listed for name in volumes),
                text(r) + "\n" + str(listed))
        c.check("c.hc (another KDF) is mounted from the cache, without a "
                "prompt",
                text(r).count("Enter password") == 2, text(r))
        c.check("cached passwords that do not match are not tried with "
                "Argon2 (%.1f s, one mount %.1f s)" % (favorites, single),
                favorites < 3 * single + MARGIN)
    finally:
        # Only the volumes of this test: unrelated ones may be mounted
        if not dismount(volumes.values()):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
