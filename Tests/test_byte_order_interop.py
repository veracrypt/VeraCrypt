#!/usr/bin/env python3
"""Check that volume headers are compatible between little- and big-endian builds.

Usage:
  python3 Tests/test_byte_order_interop.py --binary-a /path/to/veracrypt \
      [--binary-b /path/to/other/veracrypt]

Each binary is a console (or GUI) veracrypt. A binary built for another CPU
can be run through qemu-user binfmt support. No root is needed: volumes are
created with --filesystem=none and only their passwords are changed, which
decrypts and re-encrypts the volume headers without mounting anything.

With one binary, the volumes in Tests/test.*.hc (created by little-endian
VeraCrypt, password "test") must open and accept a password change.

With two binaries, for every encryption algorithm and cascade (the PRFs are
used in turn, so every PRF is covered too), in both directions:

  - a volume created by one binary opens with the other,
  - after that password change, the first binary opens it again,
  - a wrong password is rejected as such, and the volume still opens.

Build one binary on a little-endian and one on a big-endian CPU (or
cross-compile one) to check byte-order compatibility. Only the headers are
exercised here; the data-area XTS code is covered by the self-test vectors
(--test). Volumes are created in a temporary directory that is removed
afterwards.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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


def run(binary, args, timeout):
    command = [binary] + COMMON + args
    try:
        return subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise StepFailed(f"timed out after {timeout} s: {' '.join(command)}")


def step(name, binary, args, timeout):
    result = run(binary, args, timeout)
    if result.returncode != 0:
        raise StepFailed(f"{name}: exit {result.returncode}\n"
                         f"{result.stderr.strip() or result.stdout.strip()}")


def change_args(volume, old, new, pim):
    return ["--change", str(volume), f"--password={old}", f"--pim={pim}",
            f"--new-password={new}", f"--new-pim={pim}", "--new-keyfiles="]


def official_volumes(binary, workdir, timeout):
    failures = 0
    for source in sorted((ROOT / "Tests").glob("test.*.hc")):
        volume = workdir / source.name
        shutil.copyfile(source, volume)
        try:
            step("open and change password", binary,
                 change_args(volume, "test", "test2", 0), timeout)
            print(f"ok   {binary}: {source.name}", flush=True)
        except StepFailed as e:
            print(f"FAIL {binary}: {source.name}: {e}", flush=True)
            failures += 1
        volume.unlink()
    return failures


def interop_case(maker, opener, algorithm, prf, volume, timeout):
    volume.unlink(missing_ok=True)
    step(f"create by {maker}", maker,
         ["--create", str(volume), "--size=1M", "--volume-type=normal",
          f"--encryption={algorithm}", f"--hash={prf}", "--filesystem=none",
          f"--password={PASSWORD}", "--pim=1"], timeout)
    step(f"open by {opener}", opener,
         change_args(volume, PASSWORD, NEW_PASSWORD, 1), timeout)
    step(f"reopen by {maker}", maker,
         change_args(volume, NEW_PASSWORD, PASSWORD, 1), timeout)
    result = run(opener, change_args(volume, WRONG_PASSWORD, NEW_PASSWORD, 1),
                 timeout)
    if result.returncode != 1 or "Incorrect password" not in result.stderr:
        raise StepFailed(f"wrong password by {opener}: exit "
                         f"{result.returncode}\n{result.stderr.strip()}")
    step(f"open by {opener} after a wrong password", opener,
         change_args(volume, PASSWORD, NEW_PASSWORD, 1), timeout)


def interop(maker, opener, workdir, timeout):
    failures = 0
    for i, algorithm in enumerate(ALGORITHMS):
        prf = PRFS[i % len(PRFS)]
        try:
            interop_case(maker, opener, algorithm, prf,
                         workdir / "interop.hc", timeout)
            print(f"ok   {algorithm}/{prf}: {maker} -> {opener}", flush=True)
        except StepFailed as e:
            print(f"FAIL {algorithm}/{prf}: {maker} -> {opener}: {e}",
                  flush=True)
            failures += 1
    return failures


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary-a", required=True, help="veracrypt binary")
    parser.add_argument("--binary-b",
                        help="second veracrypt binary (other byte order)")
    parser.add_argument("--skip-official", action="store_true",
                        help="do not open the Tests/test.*.hc volumes")
    parser.add_argument("--timeout", type=int, default=900,
                        help="seconds per veracrypt call (default: 900)")
    args = parser.parse_args()

    binaries = [str(Path(args.binary_a).resolve())]
    if args.binary_b:
        binaries.append(str(Path(args.binary_b).resolve()))

    failures = 0
    with tempfile.TemporaryDirectory(prefix="vc-byte-order-") as tmp:
        workdir = Path(tmp)
        if not args.skip_official:
            for binary in binaries:
                failures += official_volumes(binary, workdir, args.timeout)
        if len(binaries) == 2:
            failures += interop(binaries[0], binaries[1], workdir,
                                args.timeout)
            failures += interop(binaries[1], binaries[0], workdir,
                                args.timeout)

    if failures:
        sys.exit(f"Failed: {failures} check(s)")
    print("All checks passed", flush=True)


if __name__ == "__main__":
    main()
