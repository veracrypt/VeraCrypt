#!/usr/bin/env python3
"""Test the production Linux mount commands without root or devices.

Run after a matching Linux build:
  python3 Tests/test_linux_mount_read_only.py --build-dir src

Links CoreLinux/CoreUnix from that build and intercepts external commands,
path type queries and auxiliary metadata using GNU ld --wrap. The native
tests stop before device I/O; real kernel access modes and cleanup require
the separate VM integration tests.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    parser.add_argument("--fuse-package", choices=("fuse", "fuse3"), default="fuse3")
    args = parser.parse_args()
    archives = [args.build_dir.resolve() / name for name in (
        "Core/Core.a", "Driver/Fuse/Driver.a", "Volume/Volume.a", "Platform/Platform.a")]
    symbols = subprocess.check_output(["nm", *map(str, archives)], text=True)
    wrappers = {
        "Process7ExecuteE": "WrapExecute",
        "Process16FindSystemBinaryE": "WrapFindBinary",
        "FilesystemPath7GetTypeE": "WrapGetType",
        "CoreUnix23ReadAuxiliaryVolumeInfoE": "WrapAuxInfo",
    }
    flags = []
    for fragment, wrapper in wrappers.items():
        matches = [line.split()[-1] for line in symbols.splitlines()
                   if " T " in line and fragment in line]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one definition for {fragment}: {matches}")
        symbol = matches[0]
        flags += [f"-Wl,--wrap={symbol}", f"-Wl,--defsym=__wrap_{symbol}={wrapper}"]
    with tempfile.TemporaryDirectory(prefix="vc-read-only-") as directory:
        work = Path(directory)
        binary = work / "mount-test"
        volume = work / "volume"
        volume.touch()
        command = shlex.split(os.environ.get("CXX", "c++")) + [
            "-std=c++11", "-DTC_UNIX", "-DTC_LINUX", "-D_FILE_OFFSET_BITS=64",
            "-I" + str(ROOT / "src"), "-I" + str(ROOT / "src/Core/Unix/Linux"),
            "-I" + str(ROOT / "src/Crypto"), "-I" + str(ROOT / "src/Crypto/Argon2/include"),
            str(ROOT / "Tests/linux_mount_read_only_test.cpp"), *flags,
            "-Wl,--start-group", *map(str, archives), "-Wl,--end-group",
            "-pthread", "-ldl", "-o", str(binary),
        ]
        command += shlex.split(subprocess.check_output(
            ["pkg-config", "--libs", args.fuse_package], text=True))
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary), str(volume)], check=True, timeout=30)


if __name__ == "__main__":
    main()
