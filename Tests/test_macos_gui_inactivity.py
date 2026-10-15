#!/usr/bin/env python3
"""Inactivity auto-dismount in the background GUI; no sudo required.

Requires a logged-in macOS desktop and no other VeraCrypt processes or mounts.
Two disposable containers are mounted without a filesystem, so nothing else
reads or writes them. The GUI's automatic unmount of the first volume must not
restart the idle timer of the second. Takes about two minutes.
"""
import argparse
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

    root = Path(tempfile.mkdtemp(prefix="vc-gui-inactivity-")).resolve()
    print("Artifacts:", root, flush=True)
    temporary = root / "tmp"
    config = root / "config" / "VeraCrypt"
    temporary.mkdir(mode=0o700)
    config.mkdir(parents=True)
    prefs = dict(BackgroundTaskEnabled=1, CloseBackgroundTaskOnNoVolumes=1, DismountOnInactivity=1,
                 MaxVolumeIdleTime=1, ForceAutoDismount=1, DismountOnLogOff=0, WipeCacheOnAutoDismount=0,
                 MountFavoritesOnLogon=0, MountDevicesOnLogon=0, OpenExplorerWindowAfterMount=0, SaveHistory=0)
    (config / "Configuration.xml").write_text("<VeraCrypt><configuration>" + "".join(
        f'<config key="{key}">{value}</config>' for key, value in prefs.items()
    ) + "</configuration></VeraCrypt>")
    env = dict(os.environ, TMPDIR=str(temporary) + "/", XDG_CONFIG_HOME=str(root / "config"))
    contents = root / "VeraCryptTest.app" / "Contents"
    executable = contents / "MacOS" / "VeraCrypt"
    executable.parent.mkdir(parents=True)
    shutil.copy2(binary, executable)
    (contents / "Info.plist").write_bytes(plistlib.dumps(dict(
        CFBundleExecutable="VeraCrypt", CFBundleName="VeraCrypt Inactivity Test",
        CFBundleIdentifier=f"org.idrix.veracrypt.inactivity-test.{os.getpid()}",
        CFBundlePackageType="APPL", NSHighResolutionCapable=True)))
    password = "Disposable-inactivity-only"
    volumes = {name: root / f"{name}.hc" for name in ("first", "second")}
    gui = None
    succeeded = False

    def vc(label, *options):
        result = subprocess.run([str(binary), "--text", "--non-interactive", *map(str, options)],
                                env=env, capture_output=True, text=True, timeout=90)
        (root / (label + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {root / (label + '.log')}")

    def aux_mounts():
        return {line for line in mounts().splitlines() if str(temporary) in line and ".veracrypt_aux_mnt" in line}

    def mount(name):
        before = aux_mounts()
        vc("mount-" + name, "--mount", volumes[name], "--filesystem=none", "--password=" + password,
           "--pim=1", "--keyfiles=", "--protect-hidden=no")
        added = aux_mounts() - before
        assert len(added) == 1, "Expected one new auxiliary mount"
        return added.pop()

    try:
        for name, volume in volumes.items():
            vc("create-" + name, "--create", volume, "--size=33554432", "--volume-type=normal",
               "--encryption=AES", "--hash=sha512", "--filesystem=FAT", "--password=" + password,
               "--pim=1", "--keyfiles=", "--random-source=/dev/urandom")
        first = mount("first")
        with (root / "gui.log").open("w") as log:
            gui = subprocess.Popen([str(executable), "--background-task"], env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        start = time.monotonic()
        time.sleep(30)
        second = mount("second")
        second_mounted = time.monotonic()
        gone = {}
        while time.monotonic() - start < 150 and len(gone) < 2:
            current = aux_mounts()
            for name, line in (("first", first), ("second", second)):
                if name not in gone and line not in current:
                    gone[name] = time.monotonic()
            time.sleep(0.5)
        assert "first" in gone, "First idle volume was not unmounted automatically"
        assert "second" in gone, "Second idle volume was not unmounted automatically"
        idle = gone["second"] - second_mounted
        print(f"first unmounted after {gone['first'] - start:.0f} s; second after {idle:.0f} s idle", flush=True)
        # One minute limit plus discovery and timer granularity. A restarted
        # timer would add the time between the two mounts (about 30 s).
        assert idle < 80, "Automatic unmount of one volume restarted another volume's idle timer"
        assert gui.wait(timeout=20) == 0, "Background app did not exit cleanly"
        succeeded = True
        print("PASS: independent idle timers, automatic unmounts, automatic exit", flush=True)
    finally:
        if gui and gui.poll() is None:
            gui.terminate()
            gui.wait(timeout=10)
        for name, volume in volumes.items():
            if aux_mounts():
                subprocess.run([str(binary), "--text", "--non-interactive", "--unmount", str(volume)],
                               env=env, capture_output=True, text=True, timeout=90)
        if succeeded and not args.keep_artifacts:
            assert not aux_mounts(), "Disposable mount remains"
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
