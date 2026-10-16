#!/usr/bin/env python3
"""Check concurrent fragment exceptions in the production Unix encryption pool.

Uses real pool, encryption-mode dispatch and platform synchronization code with
an event-controlled test cipher. Requires Linux, Python 3 and a C++11 compiler.
Run: python3 Tests/test_encryption_thread_pool_exceptions.py [--sanitize]
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def build_test(build, sanitize, test_source, extra_sources=(), extra_flags=()):
    build.mkdir(parents=True, exist_ok=True)
    sources = ["Volume/EncryptionThreadPool.cpp", "Volume/EncryptionMode.cpp"]
    sources += ["Platform/" + name + ".cpp" for name in (
        "Buffer", "Exception", "Memory", "Serializable", "Serializer", "SerializerFactory",
        "StringConverter", "Unix/Mutex", "Unix/SyncEvent", "Unix/SystemException",
        "Unix/SystemLog", "Unix/Thread")]
    sources += list(extra_sources)
    exe = build / Path(test_source).stem
    command = shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++11", "-O2", "-g", "-pthread", "-ffunction-sections", "-fdata-sections",
        "-Wl,--gc-sections", "-DTC_UNIX", "-DTC_LINUX", "-DARGON2_NO_THREADS",
        "-D_FILE_OFFSET_BITS=64", "-I" + str(ROOT / "src"),
        "-I" + str(ROOT / "src/Crypto"), "-I" + str(ROOT / "src/Crypto/Argon2/include")]
    if sanitize:
        command += ["-fsanitize=address", "-fno-omit-frame-pointer"]
    command += list(extra_flags)
    command += [str(ROOT / "Tests" / test_source)]
    command += [str(ROOT / "src" / source) for source in sources]
    command += ["-o", str(exe)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (build / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--sanitize", action="store_true", help="enable AddressSanitizer")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This build runner requires Linux")
    build = (args.build_dir or Path(tempfile.mkdtemp(prefix="vc-pool-exceptions-"))).resolve()
    exe = build_test(build, args.sanitize, "encryption_thread_pool_exception_test.cpp")
    result = subprocess.run([str(exe)], timeout=60)
    if result.returncode not in (0, 77):
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
