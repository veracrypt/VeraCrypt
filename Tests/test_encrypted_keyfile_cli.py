#!/usr/bin/env python3
"""Exercise encrypted keyfiles with an existing disposable software-token RSA key.

Requires a built VeraCrypt, pkcs11-tool and a PKCS #11 provider supporting RSA
OAEP SHA-256/MGF1-SHA256. No token objects are created, removed or modified.
Temporary volumes are never mounted. Inherit the provider's configuration, e.g.
SOFTHSM2_CONF. Released SoftHSM 2.6.1/2.7.0 lack these OAEP parameters; upstream
SoftHSM commit 9ad87341c94ffdf1364ecf27b715475e0d80b0dd was used for validation.

Example (use a disposable test PIN):
  python3 Tests/test_encrypted_keyfile_cli.py --module /path/libsofthsm2.so \
    --descriptor 'token-key:HEX_SERIAL:01:RSA PKCS#1 OAEP' \
    --pin 123456 --slot 123 --id 01 --pkcs11-tool /path/pkcs11-tool
"""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


def run(command, success=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != success:
        # Do not print command arguments, which contain the disposable PIN.
        raise AssertionError(result.stdout + result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "src/Main/veracrypt")
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--pin", required=True)
    parser.add_argument("--slot", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--pkcs11-tool", default="pkcs11-tool")
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    module = str(args.module.resolve())
    base = [binary, "--text", "--non-interactive"]
    token = [f"--token-lib={module}", f"--token-pin={args.pin}"]
    password = "DisposablePasswordForEncryptedKeyfileTest"
    with tempfile.TemporaryDirectory(prefix="vc-token-cli-") as directory:
        directory = Path(directory)
        blue1, blue2 = directory / "blue1", directory / "blue2"
        red2, volume = directory / "red2", directory / "volume.hc"
        for blue in (blue1, blue2):
            run(base + token + ["--create-keyfile", str(blue), f"--security-token-key={args.descriptor}"])
            assert blue.stat().st_mode & 0o777 == 0o600
        assert blue1.read_bytes() != blue2.read_bytes()

        # A separate implementation validates the ciphertext and OAEP parameters.
        run([args.pkcs11_tool, "--module", module, "--slot", args.slot,
             "--login", "--pin", args.pin, "--decrypt", "--id", args.id,
             "--mechanism", "RSA-PKCS-OAEP", "--hash-algorithm", "SHA256",
             "--mgf", "MGF1-SHA256", "--input-file", str(blue2), "--output-file", str(red2)])
        assert red2.stat().st_size + 66 == blue2.stat().st_size

        run(base + token + ["--create", str(volume), "--size=2M", "--encryption=AES",
             "--hash=sha512", "--filesystem=none", "--volume-type=normal",
             f"--password={password}", "--pim=1", "--random-source=/dev/urandom",
             f"--keyfiles={blue1}", f"--security-token-key={args.descriptor}"])
        change = base + ["--change", str(volume), f"--password={password}", "--pim=1",
                         "--hash=sha512", f"--new-password={password}", "--new-pim=1",
                         "--random-source=/dev/urandom"]

        # Invalid token selection must fail before modifying any volume bytes.
        before = hashlib.sha256(volume.read_bytes()).digest()
        run(change + token + [f"--keyfiles={blue1}", "--security-token-key=invalid",
                               "--new-keyfiles="], success=False)
        assert hashlib.sha256(volume.read_bytes()).digest() == before

        # Exercise both current and new selectors. The red recovery file must
        # then unlock the new credentials with ordinary keyfile processing.
        run(change + token + [f"--keyfiles={blue1}", f"--security-token-key={args.descriptor}",
                               f"--new-keyfiles={blue2}", f"--new-security-token-key={args.descriptor}"])
        run(change + [f"--keyfiles={red2}", "--new-keyfiles="])
        run(change + token + ["--keyfiles=", f"--new-keyfiles={blue1}",
                               f"--new-security-token-key={args.descriptor}"])
        run(change + token + [f"--keyfiles={blue1}", f"--security-token-key={args.descriptor}",
                               "--new-keyfiles="])
    print("PASS: OAEP interoperability, encrypted creation, credential changes, recovery and failure preservation")


if __name__ == "__main__":
    main()
