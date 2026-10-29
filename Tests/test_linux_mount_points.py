#!/usr/bin/env python3
"""Check Unix mount-point validation and directory handling without root or mounts.

Links the production core from a matching Linux build. The fixture uses real
temporary directories and symlinks, substituting volume decoding, FUSE setup,
mount commands and chown. No system directories or devices are changed.
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
    parser.add_argument("--fuse-package", choices=("fuse", "fuse3"), default="fuse")
    args = parser.parse_args()
    archives = [args.build_dir.resolve() / name for name in (
        "Core/Core.a", "Driver/Fuse/Driver.a", "Volume/Volume.a", "Platform/Platform.a")]
    symbols = subprocess.check_output(["nm", *map(str, archives)], text=True)
    flags = ["-Wl,--wrap=chown"]
    for fragment, wrapper in (("FuseService5MountE", "WrapFuseMount"),
                              ("Process7ExecuteE", "WrapExecute")):
        matches = [line.split()[-1] for line in symbols.splitlines()
                   if " T " in line and fragment in line]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one definition for {fragment}: {matches}")
        symbol = matches[0]
        flags += [f"-Wl,--wrap={symbol}", f"-Wl,--defsym=__wrap_{symbol}={wrapper}"]
    with tempfile.TemporaryDirectory(prefix="vc-mount-points-") as directory:
        work = Path(directory).resolve()
        binary = work / "mount-points-test"
        command = shlex.split(os.environ.get("CXX", "c++")) + [
            "-std=c++11", "-DTC_UNIX", "-DTC_LINUX", "-D_FILE_OFFSET_BITS=64",
            "-I" + str(ROOT / "src"), "-I" + str(ROOT / "src/Core/Unix/Linux"),
            "-I" + str(ROOT / "src/Crypto"), "-I" + str(ROOT / "src/Crypto/Argon2/include"),
            str(ROOT / "Tests/linux_mount_points_test.cpp"), *flags,
            "-Wl,--start-group", *map(str, archives), "-Wl,--end-group",
            "-pthread", "-ldl", "-o", str(binary),
        ]
        if "cxx11" not in symbols:
            command.append("-D_GLIBCXX_USE_CXX11_ABI=0")
        command += shlex.split(subprocess.check_output(
            ["pkg-config", "--libs", args.fuse_package], text=True))
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary), str(work)], check=True, timeout=30)


if __name__ == "__main__":
    main()
