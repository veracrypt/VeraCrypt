#!/usr/bin/env python3
"""Automatic GUI unmounts while a volume's service is slow; no sudo required.

Requires a logged-in macOS desktop, clang, an unsigned local build, and no other
VeraCrypt processes or mounts. Disposable containers are mounted without a
filesystem; fuset_startup_faults.c slows down only their own services.

1. A normal quit request (the quit Apple event also sent by logout) arrives while
   an automatic unmount is in progress. It must be honored afterwards, including
   unmount on quit for the remaining volume.
2. An automatic unmount cannot confirm that the service exited. The background
   application must keep a warning (shown on screen until the test ends) instead
   of exiting silently.
Takes about three minutes.
"""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
import tempfile
import time

QUIT_SOURCE = r"""
#import <AppKit/AppKit.h>
#include <stdlib.h>
int main (int argc, char **argv)
{
	@autoreleasepool {
		NSRunningApplication *app = argc > 1 ? [NSRunningApplication runningApplicationWithProcessIdentifier:atoi (argv[1])] : nil;
		return app && [app terminate] ? 0 : 1;
	}
}
"""


class Leg:
    def __init__(self, parent, name, prefs):
        self.parent, self.name = parent, name
        self.root = parent / name
        self.temporary = self.root / "tmp"
        config = self.root / "config" / "VeraCrypt"
        self.temporary.mkdir(parents=True, mode=0o700)
        config.mkdir(parents=True)
        defaults = dict(BackgroundTaskEnabled=1, DismountOnInactivity=1, MaxVolumeIdleTime=1, ForceAutoDismount=1,
                        WipeCacheOnAutoDismount=0, WipeCacheOnClose=0, MountFavoritesOnLogon=0,
                        MountDevicesOnLogon=0, OpenExplorerWindowAfterMount=0, SaveHistory=0)
        defaults.update(prefs)
        (config / "Configuration.xml").write_text("<VeraCrypt><configuration>" + "".join(
            f'<config key="{key}">{value}</config>' for key, value in defaults.items()
        ) + "</configuration></VeraCrypt>")
        self.env = dict(os.environ, TMPDIR=str(self.temporary) + "/", XDG_CONFIG_HOME=str(self.root / "config"))
        self.gui = None
        self.volumes = []

    def vc(self, binary, label, *options, extra=None):
        result = subprocess.run([str(binary), "--text", "--non-interactive", *map(str, options)],
                                env=dict(self.env, **(extra or {})), capture_output=True, text=True, timeout=90)
        (self.root / (label + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {self.root / (label + '.log')}")

    def aux_mounts(self):
        mounts = subprocess.check_output(["/sbin/mount"], text=True)
        return {line for line in mounts.splitlines() if str(self.temporary) in line and ".veracrypt_aux_mnt" in line}

    def mount(self, binary, name, password, faults=None):
        volume = self.root / (name + ".hc")
        self.vc(binary, "create-" + name, "--create", volume, "--size=33554432", "--volume-type=normal",
                "--encryption=AES", "--hash=sha512", "--filesystem=FAT", "--password=" + password,
                "--pim=1", "--keyfiles=", "--random-source=/dev/urandom")
        before = self.aux_mounts()
        self.vc(binary, "mount-" + name, "--mount", volume, "--filesystem=none", "--password=" + password,
                "--pim=1", "--keyfiles=", "--protect-hidden=no", extra=faults)
        added = self.aux_mounts() - before
        assert len(added) == 1, "Expected one new auxiliary mount"
        self.volumes.append(volume)
        return added.pop()

    def start_gui(self, bundle):
        with (self.root / "gui.log").open("w") as log:
            self.gui = subprocess.Popen([str(bundle), "--background-task"], env=self.env,
                                        stdout=log, stderr=log, start_new_session=True)
        return time.monotonic()

    def cleanup(self, binary):
        if self.gui and self.gui.poll() is None:
            self.gui.send_signal(signal.SIGTERM)
            try:
                self.gui.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.gui.kill()
                self.gui.wait(timeout=10)
        for volume in self.volumes:
            if self.aux_mounts():
                subprocess.run([str(binary), "--text", "--non-interactive", "--unmount", str(volume)],
                               env=self.env, capture_output=True, text=True, timeout=90)


def wait_for(condition, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.2)
    return condition()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if ".veracrypt_aux_mnt" in subprocess.check_output(["/sbin/mount"], text=True):
        raise RuntimeError("Dismount existing VeraCrypt volumes before this isolated GUI test")
    processes = subprocess.check_output(["/bin/ps", "-axo", "comm="], text=True)
    if any(Path(line.strip()).name.lower() == "veracrypt" for line in processes.splitlines()):
        raise RuntimeError("Close other VeraCrypt processes before this isolated GUI test")

    root = Path(tempfile.mkdtemp(prefix="vc-gui-teardown-")).resolve()
    print("Artifacts:", root, flush=True)
    contents = root / "VeraCryptTest.app" / "Contents"
    bundle = contents / "MacOS" / "VeraCrypt"
    bundle.parent.mkdir(parents=True)
    shutil.copy2(binary, bundle)
    (contents / "Info.plist").write_bytes(plistlib.dumps(dict(
        CFBundleExecutable="VeraCrypt", CFBundleName="VeraCrypt Teardown Test",
        CFBundleIdentifier=f"org.idrix.veracrypt.teardown-test.{os.getpid()}",
        CFBundlePackageType="APPL", NSHighResolutionCapable=True)))
    faults = root / "service-faults.dylib"
    subprocess.run(["/usr/bin/xcrun", "clang", "-dynamiclib", "-Wall", "-Wextra", "-O2",
                    str(Path(__file__).with_name("fuset_startup_faults.c")), "-o", str(faults)], check=True)
    quit_tool = root / "quit-application"
    subprocess.run(["/usr/bin/xcrun", "clang", "-x", "objective-c", "-fobjc-arc", "-framework", "AppKit",
                    "-", "-o", str(quit_tool)], input=QUIT_SOURCE, text=True, check=True)
    password = "Disposable-teardown-only"
    legs = []
    succeeded = False
    try:
        # 1. Quit request during an automatic unmount.
        leg = Leg(root, "quit", dict(CloseBackgroundTaskOnNoVolumes=0, DismountOnLogOff=1))
        legs.append(leg)
        marker = leg.root / "unmount-started"
        slow = leg.mount(binary, "slow", password, dict(
            DYLD_INSERT_LIBRARIES=str(faults), VC_FUSET_TEST_FAULT="unmount-delay", VC_FUSET_TEST_DELAY="8",
            VC_FUSET_TEST_ROOT=str(root), VC_FUSET_TEST_FAULT_MARKER=str(marker)))
        started = leg.start_gui(bundle)
        time.sleep(30)
        other = leg.mount(binary, "other", password)
        other_idle_deadline = time.monotonic() + 60
        assert wait_for(marker.exists, 120), "Automatic unmount did not start"
        subprocess.run([str(quit_tool), str(leg.gui.pid)], check=True)
        assert wait_for(lambda: leg.gui.poll() is not None, 40), "Quit request during an automatic unmount was not honored"
        exited = time.monotonic()
        assert leg.gui.returncode == 0, "Application did not exit cleanly after the quit request"
        remaining = leg.aux_mounts() & {slow, other}
        assert not remaining, "Volumes remained mounted after quit"
        assert exited < other_idle_deadline, "The remaining volume was not unmounted by the quit request"
        print(f"quit honored {exited - started:.0f} s after GUI start; both volumes unmounted", flush=True)

        # 2. Automatic unmount whose service exit cannot be confirmed.
        leg = Leg(root, "unconfirmed", dict(CloseBackgroundTaskOnNoVolumes=1, DismountOnLogOff=0))
        legs.append(leg)
        slow = leg.mount(binary, "slow", password, dict(
            DYLD_INSERT_LIBRARIES=str(faults), VC_FUSET_TEST_FAULT="cleanup-delay", VC_FUSET_TEST_DELAY="15",
            VC_FUSET_TEST_ROOT=str(root), VC_FUSET_TEST_FAULT_MARKER=str(leg.root / "cleanup-delayed")))
        service = int(next(leg.temporary.glob(".veracrypt_aux_mnt*/shutdown")).read_text().split()[0])
        leg.start_gui(bundle)
        assert wait_for(lambda: slow not in leg.aux_mounts(), 120), "Automatic unmount did not start"
        service_alive = lambda: subprocess.run(["/bin/kill", "-0", str(service)], capture_output=True).returncode == 0
        assert wait_for(lambda: not service_alive(), 40), "Delayed service did not exit"
        time.sleep(8)
        assert leg.gui.poll() is None, \
            f"Background application exited (status {leg.gui.returncode}) after an unconfirmed cleanup"
        print("unconfirmed cleanup kept the background application and its warning", flush=True)
        succeeded = True
        print("PASS: quit during automatic unmount, unmount on quit, unconfirmed cleanup warning", flush=True)
    finally:
        for leg in legs:
            leg.cleanup(binary)
        if succeeded and not args.keep_artifacts:
            assert not any(leg.aux_mounts() for leg in legs), "Disposable mount remains"
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
