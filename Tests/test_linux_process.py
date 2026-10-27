#!/usr/bin/env python3
"""Check Unix file inheritance and process execution without root or mounts.

Links the real Platform.a from a completed Linux build. Run with
--build-dir src, as for test_volume_read.py.
"""

import argparse
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = ("file", "descriptors", "forged", "output", "errors", "timeouts",
         "input", "closed-stdio", "fork", "background-output", "exit-deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    archive = args.build_dir.resolve() / "Platform/Platform.a"
    symbols = subprocess.check_output(
        shlex.split(os.environ.get("NM", "nm")) + ["--defined-only", str(archive)],
        text=True)
    with tempfile.TemporaryDirectory(prefix="vc-process-") as directory:
        work = Path(directory)
        binary = work / "process-test"
        command = shlex.split(os.environ.get("CXX", "c++")) + [
            "-std=c++11", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter", "-DTC_UNIX", "-DTC_LINUX",
            "-D_FILE_OFFSET_BITS=64", "-I" + str(ROOT / "src"),
            str(ROOT / "Tests/linux_process_test.cpp"), str(archive),
            "-pthread", "-ldl", "-o", str(binary),
        ]
        if "cxx11" not in symbols:
            command.append("-D_GLIBCXX_USE_CXX11_ABI=0")
        subprocess.run(command, check=True, timeout=120)
        failed = []
        for case in args.case or CASES:
            # Timeouts intentionally leave launched programs alive. Isolate
            # each case so cleanup also reaches descendants of fork callbacks.
            process = subprocess.Popen([str(binary), case, str(work)], start_new_session=True)
            try:
                if process.wait(timeout=20) != 0:
                    failed.append(case)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        if failed:
            raise SystemExit("Failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
