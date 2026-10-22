#!/usr/bin/env python3
"""Test how veracrypt --stdin reads the password, against the installed
veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_stdin_password.py [--veracrypt /usr/bin/veracrypt]
      [--require-locales]

Mounts a copy of Tests/test.sha512.hc (password "test") and volumes created
here with --stdin. Checked:

- no input, an invalid byte, an incomplete character at the end of input
  and a line longer than a password can be fail with their own messages
  instead of becoming a shorter or empty password;
- oversized input is rejected even if the writer keeps the pipe open
  without sending a line feed;
- only the first line is used, a final line feed is optional, and a
  carriage return is part of the password;
- NUL bytes are part of the password: a volume created with "te\\0st"
  opens with exactly those bytes and not with "te" or "test";
- an empty line is an empty password (keyfiles only);
- commands that need no password still work with empty input;
- the password is decoded in the caller's locale: UTF-8 with the caller in
  C (veracrypt switches to en_US.UTF-8), ISO-8859-1 with the caller in
  en_US.ISO-8859-1. A missing locale is skipped, or fails with
  --require-locales.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "Tests" / "test.sha512.hc"
NONASCII = "pässwörd ünïcödé"


class Checks:
    def __init__(self):
        self.failures = 0

    def check(self, desc, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + desc, flush=True)
        if not cond:
            self.failures += 1
            if detail:
                print("     " + detail.strip().replace("\n", "\n     "))


def check_overflow_without_eof(vc, checks, work, env):
    path = work / "overflow.hc"
    read_fd, write_fd = os.pipe()
    try:
        # This fits in a Linux pipe and exceeds the reader's raw input cap.
        os.write(write_fd, b"x" * 4096)
        with subprocess.Popen(
                [vc, "--text", "--non-interactive", "--stdin", "--create",
                 str(path)], stdin=read_fd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env,
                start_new_session=True) as process:
            try:
                # Keep write_fd open: communicate must not supply EOF.
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                # Stop the core service too, since it inherits the output pipe.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                checks.check("oversized input is rejected without EOF", False,
                             "VeraCrypt waited for the writer to close")
            else:
                checks.check("oversized input is rejected without EOF",
                             process.returncode != 0
                             and b"The password from standard input is too long" in output
                             and not path.exists(),
                             output.decode("utf-8", "replace"))
    finally:
        os.close(read_fd)
        os.close(write_fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--veracrypt", default="/usr/bin/veracrypt")
    parser.add_argument("--require-locales", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("must run as root (mounting)")

    vc = args.veracrypt
    c = Checks()
    work = Path(tempfile.mkdtemp(prefix="vc-stdin-"))
    mnt = work / "mnt"
    mnt.mkdir()
    volume = work / "test.hc"
    shutil.copyfile(FIXTURE, volume)
    created = []
    utf8 = dict(os.environ, LC_ALL="C.UTF-8")

    def run(cmd, data=None, env=None, timeout=900):
        return subprocess.run(cmd, input=data if data is not None else b"",
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env,
                              timeout=timeout)

    def text(r):
        return r.stdout.decode("utf-8", "replace")

    def mounted(path):
        return run([vc, "--text", "--non-interactive", "--list",
                    str(path)]).returncode == 0

    def unmount(path):
        if mounted(path):
            run([vc, "--text", "--non-interactive", "--unmount", str(path)])

    def mount(path, data, env=None, target=None, extra=()):
        cmd = [vc, "--text", "--non-interactive", "--stdin", *extra, str(path)]
        cmd += [str(target)] if target else ["--filesystem=none"]
        r = run(cmd, data, env)
        ok = r.returncode == 0 and mounted(path)
        unmount(path)
        return ok, r

    def create(name, password_bytes, keyfiles=""):
        path = work / name
        r = run([vc, "--text", "--non-interactive", "--create", str(path),
                 "--size=1M", "--volume-type=normal", "--encryption=AES",
                 "--hash=sha512", "--filesystem=none", "--pim=0",
                 "--keyfiles=" + keyfiles, "--random-source=/dev/urandom",
                 "--stdin"], password_bytes + b"\n", utf8)
        created.append(path)
        return path, r

    def skip(reason):
        if args.require_locales:
            c.check(reason, False)
        else:
            print("skip " + reason)

    try:
        check_overflow_without_eof(vc, c, work, utf8)
        ok, r = mount(volume, b"test\n", target=mnt)
        c.check("the first line is the password", ok, text(r))
        for desc, data, want in (
                ("no input", b"", "Cannot read the password"),
                ("an invalid byte", b"p\xffss\n", "character encoding"),
                ("an incomplete character at the end", b"sample\xc3",
                 "character encoding"),
                ("a line longer than a password can be", b"x" * 5000 + b"\n",
                 "too long")):
            ok, r = mount(volume, data, utf8, mnt)
            c.check("%s fails with its own message" % desc,
                    not ok and want in text(r), text(r))
        for desc, data, expect in (
                ("only the first line is used", b"test\nsecond\n", True),
                ("a final line feed is optional", b"test", True),
                ("a carriage return is part of the password", b"test\r\n",
                 False)):
            ok, r = mount(volume, data, target=mnt)
            c.check(desc, ok == expect, text(r))

        nvol, r = create("nul.hc", b"te\0st")
        c.check("create a volume with a NUL byte in the password",
                r.returncode == 0, text(r))
        if r.returncode == 0:
            ok, r = mount(nvol, b"te\0st\n")
            c.check("NUL bytes are part of the password", ok, text(r))
            for wrong in (b"te", b"test"):
                ok, r = mount(nvol, wrong + b"\n")
                c.check("the NUL volume does not open with %r" % wrong,
                        not ok, text(r))

        keyfile = work / "keyfile"
        keyfile.write_bytes(os.urandom(64))
        kvol, r = create("keyfile.hc", b"", str(keyfile))
        c.check("create a keyfile-only volume (empty line)",
                r.returncode == 0, text(r))
        if r.returncode == 0:
            ok, r = mount(kvol, b"\n", extra=("--keyfiles=%s" % keyfile,))
            c.check("an empty line is an empty password", ok, text(r))

        r = run([vc, "--text", "--non-interactive", "--stdin", "--list"])
        c.check("--list with --stdin and no input still works",
                r.returncode in (0, 1) and "standard input" not in text(r),
                text(r))

        have = subprocess.run(["locale", "-a"], stdout=subprocess.PIPE,
                              text=True).stdout.lower().split()
        uvol, r = create("nonascii.hc", NONASCII.encode("utf-8"))
        c.check("create a volume with a non-ASCII password",
                r.returncode == 0, text(r))
        if r.returncode == 0:
            if "en_us.utf8" in have:
                ok, r = mount(uvol, NONASCII.encode("utf-8") + b"\n",
                              dict(os.environ, LC_ALL="C", LANG="C"))
                c.check("UTF-8 password with the caller in C", ok, text(r))
            else:
                skip("C caller: en_US.UTF-8 not installed")
            if "en_us.iso88591" in have or "en_us" in have:
                ok, r = mount(uvol, NONASCII.encode("latin-1") + b"\n",
                              dict(os.environ, LC_ALL="en_US.ISO-8859-1",
                                   LANG="en_US.ISO-8859-1"))
                c.check("ISO-8859-1 password with the caller in "
                        "en_US.ISO-8859-1", ok, text(r))
            else:
                skip("ISO-8859-1 caller: locale en_US not installed")
    finally:
        for path in [volume, *created]:
            unmount(path)
        if os.path.ismount(mnt):
            sys.exit("%s is still mounted; not removing %s" % (mnt, work))
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
