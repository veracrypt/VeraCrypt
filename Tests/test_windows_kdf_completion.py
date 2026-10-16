#!/usr/bin/env python3
"""Check Windows KDF request lifetimes without mounting volumes or loading a driver.

Run from an x64 MSVC developer environment:
    python Tests/test_windows_kdf_completion.py [--build-dir PATH]

The harness compiles the production thread pool with event-controlled KDF stubs.
Initialization and draining are extracted from ReadVolumeHeaderWithAbort, so the
caller and worker reference protocol are checked together. All request storage
is retained until pool shutdown joins the workers.
Startup checks fail each resource creation in turn and verify cleanup and restart.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def block(source, start):
    """Return a balanced source block, including its opening and closing braces."""
    first = source.index("{", start)
    depth = 1
    for end in range(first + 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return source[first:end + 1]
    raise RuntimeError("Unbalanced production source block")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    if os.name != "nt" or not shutil.which("cl.exe"):
        parser.error("An x64 MSVC developer environment on Windows is required")
    build = (args.build_dir or Path(tempfile.mkdtemp(prefix="vc-kdf-completion-"))).resolve()
    build.mkdir(parents=True, exist_ok=True)

    source = (ROOT / "src/Common/Volumes.c").read_text()
    start = source.index("int ReadVolumeHeaderWithAbort (")
    header = block(source, start)
    condition = "if ((selected_pkcs5_prf == 0) && (encryptionThreadCount > 1))"
    init_start = header.index(condition)
    init = block(header, init_start)
    drain_start = header.index(condition, header.index("\nret:"))
    drain = block(header, drain_start)
    # Keep the real reference release and wait; retain allocations for the test's
    # independent final join instead of executing production cleanup here.
    drain = drain[:drain.index("#if !defined(DEVICE_DRIVER)")] + "}\n"
    item_end = source.index("} KeyDerivationWorkItem;") + len("} KeyDerivationWorkItem;")
    item_start = source.rindex("typedef struct", 0, item_end)
    for filename, contents in (("kdf_init.inc", init), ("kdf_drain.inc", drain),
                               ("kdf_item.inc", source[item_start:item_end])):
        (build / filename).write_text(contents)

    exe = build / "windows_kdf_completion_test.exe"
    command = ["cl.exe", "/nologo", "/O2", "/W3", "/WX", "/MD",
               "/DUNICODE", "/D_UNICODE", f"/I{build}"]
    command += [f"/I{ROOT / 'src' / directory}"
                for directory in ("", "Common", "Crypto", "Crypto/Argon2/include")]
    command += [str(ROOT / "Tests/windows_kdf_completion_test.c"), f"/Fe:{exe}"]
    result = subprocess.run(command, cwd=build, capture_output=True, text=True)
    (build / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    for workers in (2, 8):
        subprocess.run([str(exe), str(workers)], cwd=build, check=True, timeout=90)
    subprocess.run([str(exe), "startup"], cwd=build, check=True, timeout=90)


if __name__ == "__main__":
    main()
