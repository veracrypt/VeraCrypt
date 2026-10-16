#!/usr/bin/env python3
"""Inject failures into the production Windows header setup/cleanup paths.

Extracts those paths verbatim; replaces only the intervening cryptographic search
with a chosen success/failure result. Tracks allocation, event and lock ownership.
Run in an x64 MSVC environment: python Tests/test_windows_header_cleanup.py
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from test_windows_kdf_completion import ROOT, block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    if os.name != "nt" or not shutil.which("cl.exe"):
        parser.error("An x64 MSVC developer environment on Windows is required")
    build = (args.build_dir or Path(tempfile.mkdtemp(prefix="vc-header-cleanup-"))).resolve()
    build.mkdir(parents=True, exist_ok=True)
    source = (ROOT / "src/Common/Volumes.c").read_text()
    start = source.index("int ReadVolumeHeaderWithAbort (")
    header = block(source, start)
    setup = header[:header.index("\tcrypto_loadkey (keyInfo,")]
    cleanup = header[header.index("\nerr:"):]
    signature = source[start:source.index("{", start)]
    (build / "header_cleanup.inc").write_text(signature + setup + """
    if (TestHeaderError) { status = ERR_PASSWORD_WRONG; goto err; }
    status = ERR_SUCCESS;
    goto ret;
""" + cleanup)
    item_end = source.index("} KeyDerivationWorkItem;") + len("} KeyDerivationWorkItem;")
    item_start = source.rindex("typedef struct", 0, item_end)
    (build / "kdf_item.inc").write_text(source[item_start:item_end])
    exe = build / "windows_header_cleanup_test.exe"
    command = ["cl.exe", "/nologo", "/O2", "/W3", "/WX", "/MD", "/wd4101",
               "/DUNICODE", "/D_UNICODE", f"/I{build}"]
    command += [f"/I{ROOT / 'src' / directory}"
                for directory in ("", "Common", "Crypto", "Crypto/Argon2/include")]
    command += [str(ROOT / "Tests/windows_header_cleanup_test.c"), f"/Fe:{exe}"]
    result = subprocess.run(command, cwd=build, capture_output=True, text=True)
    (build / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    subprocess.run([str(exe)], cwd=build, check=True, timeout=30)


if __name__ == "__main__":
    main()
