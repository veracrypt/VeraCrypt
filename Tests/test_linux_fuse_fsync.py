#!/usr/bin/env python3
"""Check that Linux FUSE volumes forward fsync to the encrypted backing storage.

Usage:
  sudo python3 Tests/test_linux_fuse_fsync.py --binary /path/to/veracrypt

Requires root, util-linux, dmsetup and mkfs.ext4. Each check uses a disposable
volume on a sparse image behind a loop device and a device-mapper target: one
volume on the device itself and one file container in an ext4 filesystem on
it. Volumes are mounted with --mount-options=nokernelcrypto, so their data
goes through the FUSE volume image and the loop device attached to it.
For each volume, the test checks that:

  - fsync in the mounted filesystem flushes the backing device, also after
    an fsync of another file in the FUSE mount,
  - fsync reports EIO once the backing device fails. The device-mapper table
    is replaced without syncing, which simulates a power cut,
  - data synced before the cut is intact on the backing image, also when
    mounted read-only.

Mounts are made in a private mount namespace, so other processes cannot keep
them busy. Every unmount targets a test volume explicitly. Artifacts are kept
in a private temporary directory.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

CLONE_NEWNS = 0x00020000
TOOLS = ("blockdev", "dmsetup", "losetup", "mkfs.ext4", "mount", "umount")


class FsyncChecks:
    def __init__(self, args):
        self.binary = str(Path(args.binary).resolve())
        self.slot = args.slot
        self.root = Path(tempfile.mkdtemp(prefix="veracrypt-fsync-test-")).resolve()
        self.mountpoint = self.root / "mount"
        self.host = self.root / "host"
        self.mountpoint.mkdir()
        self.host.mkdir()
        self.password = "Disposable-FUSE-fsync-test-only"
        self.results = []
        self.failures = []
        self.volume = None
        self.host_mounted = False
        self.loop = None
        self.dm = None
        print("Artifacts:", self.root, flush=True)

    def record(self, entry):
        self.results.append(entry)
        (self.root / "results.json").write_text(json.dumps(self.results, indent=2))

    def run(self, label, args, expected=0):
        started = time.monotonic()
        result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        (self.root / (label + ".log")).write_text(output)
        self.record(dict(label=label, returncode=result.returncode,
                         seconds=round(time.monotonic() - started, 3), output=output))
        if expected is not None and result.returncode != expected:
            raise AssertionError(f"{label}: expected {expected}, got {result.returncode}: {output}")
        return result

    def vc(self, label, *args, expected=0):
        return self.run(label, [self.binary, "--text", "--non-interactive", *args], expected)

    def expect(self, label, passed, detail):
        self.record(dict(label=label, passed=passed, detail=detail))
        print("PASS" if passed else "FAIL", label + ":", detail, flush=True)
        if not passed:
            self.failures.append(label)

    def slot_volumes(self):
        result = self.vc("list", "--list", expected=None)
        return [line.split() for line in result.stdout.splitlines()
                if line.startswith(f"{self.slot}: ")]

    def mount(self, label, volume, *args, options="nokernelcrypto"):
        self.volume = volume
        self.vc(label, "--mount", volume, *args, f"--slot={self.slot}",
                "--mount-options=" + options, "--password=" + self.password,
                "--pim=1", "--keyfiles=", "--protect-hidden=no")
        listed = self.slot_volumes()
        if len(listed) != 1 or os.path.realpath(listed[0][1]) != os.path.realpath(volume):
            raise AssertionError(f"{volume} is not listed in slot {self.slot}: {listed}")
        # Only a loop device on the FUSE volume image uses the path under test.
        device = Path(listed[0][2])
        backing = Path("/sys/block", device.name, "loop", "backing_file")
        image = Path(backing.read_text().strip()) if backing.exists() else None
        if image is None or image.name != "volume" or not (image.parent / "control").exists():
            raise AssertionError(f"{device} is not attached to a FUSE volume image")
        return device, image.parent

    def unmount(self, label):
        if self.vc(label, "--unmount", self.volume, expected=None).returncode != 0:
            self.vc(label + "-force", "--force", "--unmount", self.volume)
        self.volume = None

    def mount_host(self, label, device):
        # Keep periodic journal commits from flushing the backing device.
        self.run(label, ["mount", "-o", "commit=600", device, self.host])
        self.host_mounted = True

    def cut_power(self, label, sectors):
        # Without lockfs, suspending syncs nothing above the target. Data that
        # has not reached the loop device is lost, as in a power cut.
        self.run(label + "-suspend", ["dmsetup", "suspend", "--nolockfs", self.dm])
        self.run(label + "-load", ["dmsetup", "load", self.dm, "--table", f"0 {sectors} error"])
        self.run(label + "-resume", ["dmsetup", "resume", self.dm])

    @staticmethod
    def flushes(device):
        # Completed flush requests (Documentation/block/stat.rst). Device-mapper
        # targets do not count them, so the loop device below is measured.
        fields = Path("/sys/block", Path(device).name, "stat").read_text().split()
        if len(fields) < 17:
            raise AssertionError("This kernel does not report flush statistics")
        return int(fields[15])

    @staticmethod
    def write_file(path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            try:
                os.fsync(fd)
            except OSError as e:
                return e.errno
            return 0
        finally:
            os.close(fd)

    def compare(self, synced):
        found = {}
        for name, digest in synced.items():
            try:
                data = (self.mountpoint / name).read_bytes()
                found[name] = "intact" if hashlib.sha256(data).hexdigest() == digest else "changed"
            except OSError as e:
                found[name] = errno.errorcode.get(e.errno, str(e.errno))
        return all(state == "intact" for state in found.values()), found

    def check(self, kind):
        image = self.root / (kind + ".img")
        with open(image, "wb") as f:
            f.truncate(128 << 20)
        self.loop = self.run(kind + "-losetup", ["losetup", "--find", "--show", image]).stdout.strip()
        sectors = int(self.run(kind + "-size", ["blockdev", "--getsz", self.loop]).stdout)
        self.dm = f"veracrypt-fsync-test-{os.getpid()}-{kind}"
        self.run(kind + "-dm", ["dmsetup", "create", self.dm, "--table", f"0 {sectors} linear {self.loop} 0"])
        if kind == "file":
            self.run(kind + "-host-mkfs", ["mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0",
                                           "/dev/mapper/" + self.dm])
            self.mount_host(kind + "-host-mount", "/dev/mapper/" + self.dm)
            volume = self.host / "test.hc"
        else:
            volume = Path("/dev/mapper", self.dm)

        self.vc(kind + "-create", "--create", volume, *(["--size=64M"] if kind == "file" else []),
                "--volume-type=normal", "--encryption=AES", "--hash=SHA-512", "--filesystem=none",
                "--password=" + self.password, "--pim=1", "--keyfiles=", "--random-source=/dev/urandom")
        device, _ = self.mount(kind + "-mount-raw", volume, "--filesystem=none")
        self.run(kind + "-mkfs", ["mkfs.ext4", "-q", "-F", "-b", "4096",
                                  "-E", "lazy_itable_init=0,lazy_journal_init=0", device])
        self.unmount(kind + "-unmount-raw")

        device, aux = self.mount(kind + "-mount", volume, self.mountpoint)
        # Linux FUSE stops forwarding fsync on the whole mount after any ENOSYS
        # reply, so sync another file first.
        fd = os.open(aux / "control", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

        synced = {}
        counts = []
        for i in range(3):
            name = f"synced{i}"
            data = os.urandom(1 << 20)
            before = self.flushes(device), self.flushes(self.loop)
            result = self.write_file(self.mountpoint / name, data)
            if result:
                raise AssertionError(f"fsync of {name} failed: {os.strerror(result)}")
            counts.append([self.flushes(device) - before[0], self.flushes(self.loop) - before[1]])
            synced[name] = hashlib.sha256(data).hexdigest()
        self.expect(kind + "-flush-forwarded", all(volume_flushes and backing_flushes
                                                   for volume_flushes, backing_flushes in counts),
                    f"flushes per fsync on the volume loop device and the backing device: {counts}")

        self.cut_power(kind + "-cut", sectors)
        result = self.write_file(self.mountpoint / "unsynced", os.urandom(1 << 20))
        self.expect(kind + "-sync-error-returned", result == errno.EIO,
                    "fsync after the backing device failed: "
                    + (errno.errorcode.get(result, str(result)) if result else "success"))
        self.unmount(kind + "-unmount-cut")

        # Inspect what reached the backing image before the cut.
        if kind == "file":
            self.run(kind + "-host-unmount-cut", ["umount", self.host])
            self.host_mounted = False
            self.mount_host(kind + "-host-mount-image", self.loop)
        else:
            volume = Path(self.loop)
        try:
            self.mount(kind + "-mount-image", volume, self.mountpoint)
        except AssertionError as e:
            self.expect(kind + "-synced-data-durable", False,
                        "volume did not mount after the cut: " + str(e).splitlines()[0])
            return
        self.expect(kind + "-synced-data-durable", *self.compare(synced))
        self.unmount(kind + "-unmount-image")
        self.mount(kind + "-mount-readonly", volume, self.mountpoint, options="ro,nokernelcrypto")
        self.expect(kind + "-readonly-mount", *self.compare(synced))
        self.unmount(kind + "-unmount-readonly")

    def cleanup(self, kind):
        if self.volume is not None:
            self.vc(kind + "-cleanup-unmount", "--force", "--unmount", self.volume, expected=None)
            self.volume = None
        if self.host_mounted:
            self.run(kind + "-cleanup-host", ["umount", self.host], expected=None)
            self.host_mounted = False
        if self.dm:
            if self.run(kind + "-cleanup-dm", ["dmsetup", "remove", "--retry", self.dm], expected=None).returncode:
                # Removed when its last user closes it.
                self.run(kind + "-cleanup-dm-deferred", ["dmsetup", "remove", "--deferred", self.dm], expected=None)
            self.dm = None
        if self.loop:
            self.run(kind + "-cleanup-loop", ["losetup", "--detach", self.loop], expected=None)
            self.loop = None
        (self.root / (kind + ".img")).unlink(missing_ok=True)


def isolate_mounts():
    # Mount namespaces created by other processes during the test would copy
    # its mounts and keep the backing devices busy after cleanup.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(CLONE_NEWNS) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "unshare: " + os.strerror(error))
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--slot", type=int, default=61, help="free slot for the test volumes (default: 61)")
    parser.add_argument("--backing", choices=("device", "file"), action="append",
                        help="backing storage to check (default: both)")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Run on Linux as root")
    missing = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing:
        parser.error("Missing tools: " + ", ".join(missing))
    isolate_mounts()
    checks = FsyncChecks(args)
    if checks.slot_volumes():
        parser.error(f"Slot {args.slot} is in use; choose a free one with --slot")
    for kind in args.backing or ("device", "file"):
        try:
            checks.check(kind)
        except Exception as e:
            traceback.print_exc()
            checks.expect(kind + "-completed", False, f"{type(e).__name__}: {e}")
        finally:
            checks.cleanup(kind)
    if checks.failures:
        sys.exit("Failed: " + ", ".join(checks.failures))
    print("All checks passed")


if __name__ == "__main__":
    main()
