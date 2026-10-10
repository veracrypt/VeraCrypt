#!/usr/bin/env python3
"""Read known data from the Tests/test.*.hc volumes without mounting.

Usage:
  python3 Tests/test_volume_read.py --build-dir src [--fixture test.sha512.hc ...]

Compiles Tests/volume_read_test.cpp against Volume/Volume.a and
Platform/Platform.a of a finished Linux build in --build-dir, then decrypts
the data area of each volume through Volume::ReadSectors (in one call, with
the encryption thread pool, and one sector at a time). The master keys and
data offsets decoded from a real header must recover the volume's
plaintext. For every volume, the decrypted data area must:

  - start with a FAT boot sector,
  - contain DUMMY.TXT with the content "Dummy" at the cluster given by the
    root directory,
  - match a known SHA-256 digest.

Unlike mounting the volumes, this needs no root, FUSE or installed package,
so it also runs on a cross build: set CXX (and NM) to the cross tools, e.g.
CXX=s390x-linux-gnu-g++ NM=s390x-linux-gnu-nm. The test program is then run
through qemu-user binfmt support, which needs the target's shared libraries
(e.g. libstdc++6:s390x from a multiarch install, as in the CI workflow).
"""

import argparse
import hashlib
import os
import shlex
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "test"
EXPECTED_FILE = ("DUMMY   TXT", b"Dummy")

# SHA-256 of the decrypted data area of each volume.
DIGESTS = {
    "test.blake2s.hc":
        "21cc4f2f8db13fadca82bebb2ad574184dcbb441d447a5dee7363ceac729e0c0",
    "test.sha256.hc":
        "2b15dbe4544a853ca15311dd1dc83162c6cc06c6c470d98ca427b26093a9fb41",
    "test.sha512.hc":
        "eef460d147e613d70df39a8e6e83b624fc1d258d8ae35875caf6579a05cba95b",
    "test.streebog.hc":
        "4c890502857a6360ed059c4d1dc736179fe29bffc9af72bfbff63bb691d34d82",
    "test.whirlpool.hc":
        "cb194e676678b7c40eead878df102eee0c93d453ca9d0a9e4eab7a3847edd1e0",
}


class CheckFailed(Exception):
    pass


def old_abi(archive):
    """Tell whether the archive was built with _GLIBCXX_USE_CXX11_ABI=0.

    src/Makefile selects the old ABI for WXSTATIC builds with GCC 5 or later;
    the test program must use the same one to link.
    """
    nm = shlex.split(os.environ.get("NM", "nm"))
    symbols = subprocess.run(nm + ["--defined-only", str(archive)],
                             stdout=subprocess.PIPE, text=True,
                             check=True).stdout
    return "cxx11" not in symbols


def build(build_dir, workdir):
    volume_lib = build_dir / "Volume" / "Volume.a"
    platform_lib = build_dir / "Platform" / "Platform.a"
    for lib in (volume_lib, platform_lib):
        if not lib.is_file():
            sys.exit(f"{lib} not found: build VeraCrypt in {build_dir} first")
    program = workdir / "volume_read_test"
    command = shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++11", "-O2", "-DTC_UNIX", "-DTC_LINUX", "-DARGON2_NO_THREADS",
        "-D_FILE_OFFSET_BITS=64",
        "-I" + str(build_dir), "-I" + str(build_dir / "Crypto"),
        "-I" + str(build_dir / "Crypto" / "Argon2" / "include"),
        "-I" + str(build_dir / "PKCS11"),
    ]
    if old_abi(volume_lib):
        command.append("-D_GLIBCXX_USE_CXX11_ABI=0")
    command += [str(ROOT / "Tests" / "volume_read_test.cpp"), str(volume_lib),
                str(platform_lib), "-pthread", "-ldl", "-o", str(program)]
    subprocess.run(command, check=True, timeout=300)
    return program


def find_file(data, name):
    """Return a small file (one cluster at most) from the root directory of a
    FAT12/16 image."""
    if data[510:512] != b"\x55\xaa":
        raise CheckFailed("no FAT boot sector signature")
    (sector_size, cluster_sectors, reserved_sectors, fat_count, root_entries,
     _, _, fat_sectors) = struct.unpack_from("<HBHBHHBH", data, 11)
    if sector_size not in (512, 1024, 2048, 4096) or not cluster_sectors \
            or not fat_count or not fat_sectors or not root_entries:
        raise CheckFailed("unexpected FAT boot sector")
    root = (reserved_sectors + fat_count * fat_sectors) * sector_size
    first_data = root + -(-root_entries * 32 // sector_size) * sector_size
    if first_data > len(data):
        raise CheckFailed("FAT root directory beyond the data area")
    for offset in range(root, root + root_entries * 32, 32):
        entry = data[offset:offset + 32]
        if entry[0] == 0:
            break
        # Skip volume labels, directories and long file name entries.
        if entry[:11].decode("latin-1") == name and not entry[11] & 0x18:
            cluster, size = struct.unpack_from("<HI", entry, 26)
            start = first_data + (cluster - 2) * cluster_sectors * sector_size
            if cluster < 2 or size > cluster_sectors * sector_size \
                    or start + size > len(data):
                raise CheckFailed(f"{name.strip()}: bad cluster {cluster} "
                                  f"or size {size}")
            return data[start:start + size]
    raise CheckFailed(f"{name.strip()} not found in the root directory")


def check_volume(program, fixture, workdir):
    kdf = fixture.name.split(".")[1]
    output = workdir / (fixture.name + ".plain")
    result = subprocess.run([str(program), str(fixture), PASSWORD, kdf,
                             str(output)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=900,
                            check=False)
    if result.returncode != 0:
        raise CheckFailed(f"exit {result.returncode}: "
                          f"{result.stderr.strip() or result.stdout.strip()}")
    data = output.read_bytes()
    output.unlink()
    name, content = EXPECTED_FILE
    found = find_file(data, name)
    if found != content:
        raise CheckFailed(f"{name.strip()} contains {found!r}, "
                          f"expected {content!r}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGESTS[fixture.name]:
        raise CheckFailed(f"data area SHA-256 {digest}, "
                          f"expected {DIGESTS[fixture.name]}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", type=Path, required=True,
                        help="VeraCrypt source directory of a finished build "
                             "(normally src)")
    parser.add_argument("--fixture", action="append", default=[],
                        metavar="NAME",
                        help="check only this volume from Tests/, given by "
                             "file name, e.g. test.sha512.hc (repeatable; "
                             "default: all)")
    args = parser.parse_args()

    names = args.fixture or sorted(DIGESTS)
    fixtures = []
    for name in names:
        path = ROOT / "Tests" / name
        if name not in DIGESTS or not path.is_file():
            sys.exit(f"Unknown or missing fixture: {path}")
        fixtures.append(path)

    failures = 0
    with tempfile.TemporaryDirectory(prefix="vc-volume-read-") as tmp:
        workdir = Path(tmp)
        program = build(args.build_dir.resolve(), workdir)
        for fixture in fixtures:
            try:
                info = check_volume(program, fixture, workdir)
                print(f"ok   {fixture.name}: {info}", flush=True)
            except (CheckFailed, subprocess.TimeoutExpired) as e:
                print(f"FAIL {fixture.name}: {e}", flush=True)
                failures += 1

    if failures:
        sys.exit(f"Failed: {failures} check(s)")
    print("All checks passed", flush=True)


if __name__ == "__main__":
    main()
