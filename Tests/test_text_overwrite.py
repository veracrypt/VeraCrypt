#!/usr/bin/env python3
"""Regression test for issue #1962, against the installed veracrypt.

Usage (after installing a package; root is not needed):
  python3 Tests/test_text_overwrite.py [--veracrypt PATH]

Checks that --create-keyfile refuses an existing keyfile without asking,
also in interactive mode, unless --force is given, and that
--backup-headers asks before replacing an existing file.
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


def test_overwrite(vc, c, work):
    keyfile = work / "keyfile"
    r = vc.run(["--non-interactive", "--create-keyfile", str(keyfile),
                "--random-source=" + str(work / "random")])
    c.check("#1962: create a keyfile", r.returncode == 0, text(r))
    original = keyfile.read_bytes() if keyfile.exists() else b""
    r = vc.run(["--non-interactive", "--create-keyfile", str(keyfile),
                "--random-source=" + str(work / "random")])
    c.check("#1962: --create-keyfile refuses an existing keyfile",
            r.returncode != 0 and "already exists" in text(r), text(r))
    r = vc.run(["--create-keyfile", str(keyfile),
                "--random-source=" + str(work / "random")], stdin=b"y\n")
    c.check("#1962: interactive --create-keyfile refuses without asking",
            r.returncode != 0 and "--force" in text(r)
            and "(y=Yes" not in text(r), text(r))
    c.check("#1962: the existing keyfile is unchanged",
            keyfile.read_bytes() == original)
    r = vc.run(["--non-interactive", "--force", "--create-keyfile",
                str(keyfile), "--random-source=" + str(work / "random")])
    c.check("#1962: --force replaces the keyfile",
            r.returncode == 0 and keyfile.read_bytes() != original, text(r))

    volume = work / "backup.hc"
    r = vc.create(volume, "2M", PASSWORD_A, "none")
    c.check("#1962: create a volume", r.returncode == 0, text(r))
    target = work / "existing"
    for answer, replaced in (("n", False), ("y", True)):
        target.write_text("keep")
        # password, PIM, keyfiles, hidden volume, confirmation, file name,
        # overwrite
        answers = "%s\n1\n\nn\ny\n%s\n%s\n" % (PASSWORD_A, target, answer)
        r = vc.run(["--random-source=" + str(work / "random"),
                    "--backup-headers", str(volume)],
                   stdin=answers.encode())
        c.check("#1962: --backup-headers asks before replacing a file "
                "(answer %s)" % answer,
                "already exists" in text(r)
                and (target.read_text(errors="replace") != "keep") == replaced,
                text(r))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="vc-regression-"))
    vc = VeraCrypt(args.veracrypt, work)
    c = Checks()
    (work / "random").write_bytes(os.urandom(4096))
    try:
        test_overwrite(vc, c, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
