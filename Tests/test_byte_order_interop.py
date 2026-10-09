#!/usr/bin/env python3
"""Check that volume headers are compatible between little- and big-endian builds.

Usage:
  python3 Tests/test_byte_order_interop.py --binary-a /path/to/veracrypt \
      [--binary-b /path/to/other/veracrypt] [--skip-official] \
      [--fixture test.sha512.hc ...]

Each binary is a console (or GUI) veracrypt. A binary built for another CPU
can be run through qemu-user binfmt support. No root is needed: volumes are
created with --filesystem=none and only their passwords are changed, which
decrypts and re-encrypts the volume headers without mounting anything.

For every binary, the volumes in Tests/test.*.hc (created by little-endian
VeraCrypt, password "test") must open with the KDF named in the file name,
accept a new password, and then open with the new password (with KDF
autodetection for the first volume).

With two binaries, for every encryption algorithm and cascade (the PRFs are
used in turn, so every PRF is covered too), in both directions:

  - a volume created by one binary opens with the other,
  - after that password change, the first binary opens it again,
  - a wrong password is rejected without changing the volume's contents,
    and the volume still opens.

The KDF is passed with --hash, except in one case per direction, which
exercises KDF autodetection.

Build one binary on a little-endian and one on a big-endian CPU (or
cross-compile one) to check byte-order compatibility. Only the headers are
exercised here; the data-area XTS code is covered by the self-test vectors
(--test). Volumes are created in a temporary directory that is removed
afterwards. VeraCrypt runs with the C locale and an empty configuration
directory, so its messages are in English whatever the user's settings.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OFFICIAL_PASSWORD = "test"
PASSWORD = "abcdefghijklmnopqrstuvwxyz0123"
NEW_PASSWORD = "zyxwvutsrqponmlkjihgfedcba9876"
WRONG_PASSWORD = "wrongwrongwrongwrongwrongwrong"

ALGORITHMS = [
    "AES", "Serpent", "Twofish", "Camellia", "Kuznyechik",
    "AES-Twofish", "AES-Twofish-Serpent", "Camellia-Kuznyechik",
    "Camellia-Serpent", "Kuznyechik-AES", "Kuznyechik-Serpent-Camellia",
    "Kuznyechik-Twofish", "Serpent-AES", "Serpent-Twofish-AES",
    "Twofish-Serpent",
]
PRFS = ["sha512", "sha256", "blake2s", "whirlpool", "streebog", "argon2"]

COMMON = ["--text", "--non-interactive", "--keyfiles=",
          "--random-source=/dev/urandom"]


class StepFailed(Exception):
    pass


class Runner:
    def __init__(self, workdir, timeout):
        self.timeout = timeout
        # VeraCrypt takes its language from LANG and from the saved
        # preferences, so use the C locale and an empty config directory.
        config = workdir / "config"
        config.mkdir()
        self.env = os.environ.copy()
        self.env.update(LANG="C", LC_ALL="C", XDG_CONFIG_HOME=str(config))

    def run(self, binary, args):
        command = [binary] + COMMON + args
        try:
            return subprocess.run(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True,
                                  env=self.env, timeout=self.timeout,
                                  check=False)
        except subprocess.TimeoutExpired:
            raise StepFailed(f"timed out after {self.timeout} s: "
                             f"{' '.join(command)}")

    def step(self, name, binary, args):
        result = self.run(binary, args)
        if result.returncode != 0:
            raise StepFailed(f"{name}: exit {result.returncode}\n"
                             f"{result.stderr.strip() or result.stdout.strip()}")


def change_args(volume, kdf, old, pim, new, new_pim):
    args = ["--change", str(volume), f"--password={old}", f"--pim={pim}",
            f"--new-password={new}", f"--new-pim={new_pim}", "--new-keyfiles="]
    if kdf:
        args.append(f"--hash={kdf}")
    return args


def official_volumes(runner, binary, fixtures, workdir):
    failures = 0
    for i, source in enumerate(fixtures):
        kdf = source.name.split(".")[1]
        volume = workdir / source.name
        shutil.copyfile(source, volume)
        start = time.monotonic()
        try:
            # The fixtures use PIM 0; the new header uses PIM 1, so only
            # opening the original header costs a full key derivation.
            runner.step("open and change password", binary,
                        change_args(volume, kdf, OFFICIAL_PASSWORD, 0,
                                    PASSWORD, 1))
            # The command line has no way to only check a password without
            # mounting, so another password change verifies the new header.
            # The first volume is opened without --hash, which covers KDF
            # autodetection (cheap with PIM 1).
            runner.step("open with the new password", binary,
                        change_args(volume, kdf if i else None, PASSWORD, 1,
                                    NEW_PASSWORD, 1))
            print(f"ok   {binary}: {source.name} "
                  f"({time.monotonic() - start:.0f} s)", flush=True)
        except StepFailed as e:
            print(f"FAIL {binary}: {source.name} "
                  f"({time.monotonic() - start:.0f} s): {e}", flush=True)
            failures += 1
        volume.unlink()
    return failures


def interop_case(runner, maker, opener, algorithm, prf, kdf, volume):
    volume.unlink(missing_ok=True)
    runner.step(f"create by {maker}", maker,
                ["--create", str(volume), "--size=1M", "--volume-type=normal",
                 f"--encryption={algorithm}", f"--hash={prf}",
                 "--filesystem=none", f"--password={PASSWORD}", "--pim=1"])
    runner.step(f"open by {opener}", opener,
                change_args(volume, kdf, PASSWORD, 1, NEW_PASSWORD, 1))
    runner.step(f"reopen by {maker}", maker,
                change_args(volume, kdf, NEW_PASSWORD, 1, PASSWORD, 1))
    before_wrong_password = volume.read_bytes()
    result = runner.run(opener, change_args(volume, kdf, WRONG_PASSWORD, 1,
                                            NEW_PASSWORD, 1))
    if result.returncode != 1 or "Incorrect password" not in result.stderr:
        raise StepFailed(f"wrong password by {opener}: exit "
                         f"{result.returncode}\n{result.stderr.strip()}")
    # Check before another password change can repair a damaged header.
    if volume.read_bytes() != before_wrong_password:
        raise StepFailed(f"wrong password by {opener}: volume contents changed")
    runner.step(f"open by {opener} after a wrong password", opener,
                change_args(volume, kdf, PASSWORD, 1, NEW_PASSWORD, 1))


def interop(runner, maker, opener, workdir):
    failures = 0
    for i, algorithm in enumerate(ALGORITHMS):
        prf = PRFS[i % len(PRFS)]
        # One case leaves out --hash to exercise KDF autodetection. sha512
        # is tried first anyway, so use the second case (sha256).
        kdf = None if i == 1 else prf
        name = f"{algorithm}/{prf}{'' if kdf else ' (autodetect)'}"
        start = time.monotonic()
        try:
            interop_case(runner, maker, opener, algorithm, prf, kdf,
                         workdir / "interop.hc")
            print(f"ok   {name}: {maker} -> {opener} "
                  f"({time.monotonic() - start:.0f} s)", flush=True)
        except StepFailed as e:
            print(f"FAIL {name}: {maker} -> {opener} "
                  f"({time.monotonic() - start:.0f} s): {e}", flush=True)
            failures += 1
    return failures


def select_fixtures(names):
    available = sorted((ROOT / "Tests").glob("test.*.hc"))
    if not names:
        if not available:
            sys.exit(f"No Tests/test.*.hc volumes found in {ROOT / 'Tests'}")
        return available
    selected = []
    for name in names:
        path = ROOT / "Tests" / name
        if path not in available:
            sys.exit(f"Fixture not found: {path}")
        selected.append(path)
    return selected


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary-a", required=True, help="veracrypt binary")
    parser.add_argument("--binary-b",
                        help="second veracrypt binary (other byte order)")
    parser.add_argument("--skip-official", action="store_true",
                        help="do not open the Tests/test.*.hc volumes")
    parser.add_argument("--fixture", action="append", default=[],
                        metavar="NAME",
                        help="open only this volume from Tests/, given by "
                             "file name, e.g. test.sha512.hc (repeatable; "
                             "default: all)")
    parser.add_argument("--timeout", type=int, default=900,
                        help="seconds per veracrypt call (default: 900)")
    args = parser.parse_args()

    if args.skip_official and not args.binary_b:
        parser.error("--skip-official needs --binary-b, "
                     "otherwise there is nothing to test")
    if args.skip_official and args.fixture:
        parser.error("--fixture and --skip-official exclude each other")

    binaries = [str(Path(args.binary_a).resolve())]
    if args.binary_b:
        binaries.append(str(Path(args.binary_b).resolve()))
    fixtures = [] if args.skip_official else select_fixtures(args.fixture)

    failures = 0
    with tempfile.TemporaryDirectory(prefix="vc-byte-order-") as tmp:
        workdir = Path(tmp)
        runner = Runner(workdir, args.timeout)
        for binary in binaries:
            failures += official_volumes(runner, binary, fixtures, workdir)
        if len(binaries) == 2:
            failures += interop(runner, binaries[0], binaries[1], workdir)
            failures += interop(runner, binaries[1], binaries[0], workdir)

    if failures:
        sys.exit(f"Failed: {failures} check(s)")
    print("All checks passed", flush=True)


if __name__ == "__main__":
    main()
