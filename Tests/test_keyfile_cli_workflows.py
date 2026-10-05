#!/usr/bin/env python3
# Copyright (c) 2026 AM Crypto. All rights reserved.
# Governed by the Apache License 2.0; see src/License.txt.

"""Exercise ordinary-keyfile CLI compatibility without mounting volumes.

Uses only private temporary files and the built executable. No token or provider
is required. Run after make test; --binary selects a GUI or console build.
"""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def run(command, *, transcript=None, success=True):
    result = subprocess.run(command, input=transcript, capture_output=True,
                            text=True, timeout=120, env=dict(os.environ, LANG="C", LC_ALL="C"))
    if (result.returncode == 0) != success:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=Path(__file__).resolve().parents[1] / "src/Main/veracrypt")
    parser.add_argument("--module", type=Path, help="Also check legacy stdin input with a loaded provider")
    args = parser.parse_args()
    base = [str(args.binary.resolve()), "--text"]
    if args.module:
        base += ["--token-lib=" + str(args.module.resolve())]
    password = "DisposableOrdinaryKeyfileWorkflowPassword"
    replacement = "ReplacementOrdinaryKeyfileWorkflowPassword"
    with tempfile.TemporaryDirectory(prefix="vc-keyfile-cli-") as temporary:
        work = Path(temporary)
        keyfile, volume = work / "ordinary-key", work / "volume.hc"
        keyfile.write_bytes(bytes(range(256)))
        create = base + ["--non-interactive", "--create", str(volume), "--size=2M",
                         "--encryption=AES", "--hash=sha512", "--filesystem=none",
                         "--volume-type=normal", f"--password={password}", "--pim=1",
                         "--random-source=/dev/urandom", f"--keyfiles={keyfile}"]
        run(create)

        # Established stdin transcript: current keyfiles, new password twice,
        # confirmation for the small PIM, then keep current keyfiles.
        transcript = f"{keyfile}\n\n{replacement}\n{replacement}\ny\ny\n"
        output = run(base + ["--change", str(volume), f"--password={password}", "--pim=1",
                            "--hash=sha512", "--new-pim=1", "--random-source=/dev/urandom"],
                     transcript=transcript)
        assert "Security token key descriptor" not in output

        # Authenticate with the resulting ordinary credentials, without a library.
        run(base + ["--non-interactive", "--change", str(volume), f"--password={replacement}",
                    "--pim=1", "--hash=sha512", f"--keyfiles={keyfile}",
                    f"--new-password={password}", "--new-pim=1", f"--new-keyfiles={keyfile}",
                    "--new-security-token-key=", "--random-source=/dev/urandom"])

        # Credential resolution errors occur before creation opens its destination.
        before = hashlib.sha256(volume.read_bytes()).digest()
        run(create + ["--security-token-key=invalid"], success=False)
        assert hashlib.sha256(volume.read_bytes()).digest() == before
        absent = work / "absent.hc"
        run([str(absent) if argument == str(volume) else argument for argument in create]
            + ["--security-token-key=invalid"], success=False)
        assert not absent.exists()

        # Recovery requires both explicit paths and a token selector.
        run(base + ["--non-interactive", "--export-decrypted-keyfile", str(keyfile)], success=False)
        assert keyfile.read_bytes() == bytes(range(256))
    print("PASS: redirected keyfile transcript, credential changes, creation preflight and export arguments")


if __name__ == "__main__":
    main()
