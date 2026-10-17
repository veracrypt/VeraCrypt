#!/usr/bin/env python3
"""Exercise Unix pool shutdown and restart with controlled worker/requester gates.

Uses the production pool, platform primitives, and KDF dispatch. Only the test
cipher/KDF, CPU count, thread-creation failures and event boundary gates are fake.
Run on Linux: python3 Tests/test_encryption_thread_pool_lifecycle.py [--sanitize]
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

from test_encryption_thread_pool_exceptions import build_test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This build runner requires Linux")
    build = (args.build_dir or Path(tempfile.mkdtemp(prefix="vc-pool-lifecycle-"))).resolve()
    symbols = ("sysconf", "pthread_create", "pthread_join",
               "_ZN9VeraCrypt9SyncEvent4WaitEv", "_ZN9VeraCrypt9SyncEvent6SignalEv")
    exe = build_test(build, args.sanitize, "encryption_thread_pool_lifecycle_test.cpp",
                     ("Volume/Pkcs5Kdf.cpp", "Volume/VolumePassword.cpp"),
                     ["-Wl,--wrap=" + symbol for symbol in symbols])
    for workers in (2, 8):
        subprocess.run([str(exe), str(workers)], check=True, timeout=90)


if __name__ == "__main__":
    main()
