#!/usr/bin/env python3
"""Ordinary FUSE-T container and background GUI lifecycle; no sudo required.

Requires a logged-in macOS desktop and no other VeraCrypt processes or mounts.
Uses only a disposable container, isolated preferences, and a local app bundle.
No fault injection, device reassignment, or forced unmount is performed.
"""
import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    mounts = lambda: subprocess.check_output(["/sbin/mount"], text=True)
    if ".veracrypt_aux_mnt" in mounts():
        raise RuntimeError("Dismount existing VeraCrypt volumes before this isolated GUI test")
    processes = subprocess.check_output(["/bin/ps", "-axo", "comm="], text=True)
    if any(Path(line.strip()).name.lower() == "veracrypt" for line in processes.splitlines()):
        raise RuntimeError("Close other VeraCrypt processes before this isolated GUI test")

    root = Path(tempfile.mkdtemp(prefix="vc-gui-lifecycle-")).resolve()
    print("Artifacts:", root, flush=True)
    temporary = root / "tmp"
    mountpoint = root / "mount"
    config = root / "config" / "VeraCrypt"
    temporary.mkdir(mode=0o700)
    mountpoint.mkdir()
    config.mkdir(parents=True)
    prefs = dict(BackgroundTaskEnabled=1, CloseBackgroundTaskOnNoVolumes=1,
                 DismountOnInactivity=0, DismountOnLogOff=1, DismountOnPowerSaving=0,
                 MountFavoritesOnLogon=0, MountDevicesOnLogon=0,
                 OpenExplorerWindowAfterMount=0, SaveHistory=0)
    (config / "Configuration.xml").write_text("<VeraCrypt><configuration>" + "".join(
        f'<config key="{key}">{value}</config>' for key, value in prefs.items()
    ) + "</configuration></VeraCrypt>")
    env = dict(os.environ, TMPDIR=str(temporary) + "/", XDG_CONFIG_HOME=str(root / "config"))
    contents = root / "VeraCryptTest.app" / "Contents"
    executable = contents / "MacOS" / "VeraCrypt"
    executable.parent.mkdir(parents=True)
    shutil.copy2(binary, executable)
    (contents / "Info.plist").write_bytes(plistlib.dumps(dict(
        CFBundleExecutable="VeraCrypt", CFBundleName="VeraCrypt Lifecycle Test",
        CFBundleIdentifier=f"org.idrix.veracrypt.lifecycle-test.{os.getpid()}",
        CFBundlePackageType="APPL", NSHighResolutionCapable=True)))
    volume = root / "ordinary.hc"
    password = "Disposable-normal-lifecycle-only"
    gui = None
    active = None
    succeeded = False

    def vc(label, *options):
        result = subprocess.run([str(binary), "--text", "--non-interactive", *map(str, options)],
                                env=env, capture_output=True, text=True, timeout=90)
        (root / (label + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {root / (label + '.log')}")

    def mount(read_only=False):
        nonlocal active
        vc("mount", "--mount", volume, mountpoint, "--password=" + password,
           "--pim=1", "--keyfiles=", "--protect-hidden=no",
           *(["--mount-options=ro"] if read_only else []))
        identities = list(temporary.glob("**/.veracrypt_aux_mnt*/shutdown"))
        assert len(identities) == 1, "Expected one disposable FUSE-T service"
        aux = identities[0].parent
        active = (int(identities[0].read_text().split()[0]), aux,
                  Path((aux / "shutdown-socket").read_text().strip()))

    def confirm_closed():
        if active:
            pid, aux, endpoint = active
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("Disposable service still running")
            assert not aux.exists() and not aux.parent.exists() and not endpoint.exists(), "Cleanup paths remain"
        assert str(root) not in mounts(), "Disposable mount remains"
        handles = subprocess.run(["/usr/sbin/lsof", "-t", str(volume)], capture_output=True, text=True)
        assert handles.returncode == 1 and not handles.stdout.strip(), "Backing file still open"

    try:
        vc("create", "--create", volume, "--size=33554432", "--volume-type=normal",
           "--encryption=AES", "--hash=sha512", "--filesystem=FAT", "--password=" + password,
           "--pim=1", "--keyfiles=", "--random-source=/dev/urandom")
        mount()
        payload = bytes(range(256)) * 4096
        with (mountpoint / "payload.bin").open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        vc("unmount-write", "--unmount", volume)
        confirm_closed()
        mount(read_only=True)
        assert hashlib.sha256((mountpoint / "payload.bin").read_bytes()).digest() == hashlib.sha256(payload).digest()
        with (root / "gui.log").open("w") as log:
            gui = subprocess.Popen([str(executable), "--background-task"], env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        time.sleep(5)
        assert gui.poll() is None, "Background app exited with a mounted volume"
        vc("unmount-readonly", "--unmount", volume)
        assert gui.wait(timeout=20) == 0, "Background app did not exit cleanly"
        confirm_closed()
        succeeded = True
        print("PASS: payload integrity, initial background discovery, external-dismount refresh, automatic exit, service/file cleanup", flush=True)
    finally:
        if gui and gui.poll() is None:
            gui.terminate()
            gui.wait(timeout=10)
        if str(root) in mounts():
            vc("test-cleanup", "--unmount", volume)
        if succeeded and not args.keep_artifacts:
            confirm_closed()
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
