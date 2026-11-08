#!/usr/bin/env python3
"""Check that Linux dismounts, and rollbacks of failed mounts, act only on the volume's own devices.

Usage:
  sudo python3 Tests/test_linux_loop_identity.py --binary /path/to/veracrypt

Requires root, util-linux, dmsetup and mkfs.ext4. Each check mounts a
disposable file container, with kernel cryptography (a device-mapper device
on a loop device attached to the container) and without it (a loop device
attached to the FUSE volume image), and checks that:

  - a dismount fails, and keeps the volume's devices, while its filesystem is
    still mounted elsewhere (a bind mount or a mount in another mount
    namespace),
  - while another process has the volume's loop device open, a dismount fails
    without kernel cryptography, as that device gives access to the decrypted
    volume, and succeeds with it, the kernel detaching that device, which
    gives access only to the container, once the process closes it,
  - after a dismount failed with its devices already released, and their
    names were reused by an unrelated loop device, filesystem and
    device-mapper device, the listing does not show these as the volume's
    and a retry releases the volume without touching them,
  - a device-mapper device without a UUID named after a cascade layer that
    the volume does not have, as left by a failed cascade mount of earlier
    versions, does not fail the dismount and is left alone,
  - emergency cleanup releases the volume's devices once their other users
    are gone,
  - a failed mount releases the devices it created, including the layers of a
    cascade created before its top layer, and leaves alone a device-mapper
    device of the same name that existed before, even one without a UUID, as
    created by earlier versions, that maps the container,
  - with kernel cryptography, the loop device is detached once the
    device-mapper devices are released, even when they are removed by other
    means,
  - dismounting a volume hosted on a loop device leaves that device attached.

With --legacy-binary, the path of an earlier version such as 1.26.29, it also
checks that volumes mounted by that version unmount and, as its
device-mapper devices have no UUID and are verified through the container,
that while the container is moved, a dismount fails, giving the cause,
without offering emergency cleanup, and keeps the volume's devices.

Mounts are made in a private mount namespace. Artifacts are kept in a private
temporary directory.
"""

import argparse
import ctypes
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
TOOLS = ("dmsetup", "losetup", "mkfs.ext4", "mount", "umount", "unshare")
AUX_PREFIX = ".veracrypt_aux_mnt"


def mounts():
    with open("/proc/self/mounts") as f:
        return [line.split()[1].replace("\\040", " ") for line in f]


def aux_mounts():
    return {m for m in mounts() if Path(m).name.startswith(AUX_PREFIX)}


def loop_backing(device):
    try:
        return Path("/sys/block", Path(device).name, "loop", "backing_file").read_text().strip()
    except OSError:
        return None


def loop_autoclear(device):
    try:
        return Path("/sys/block", Path(device).name, "loop", "autoclear").read_text().strip() == "1"
    except OSError:
        return None


def loop_devices():
    devices = {}
    for loop in Path("/sys/block").glob("loop*"):
        backing = loop_backing(loop.name)
        if backing:
            devices["/dev/" + loop.name] = backing
    return devices


def dm_devices():
    devices = {}
    for dm in Path("/sys/block").glob("dm-*"):
        try:
            devices[(dm / "dm" / "name").read_text().strip()] = (dm / "dm" / "uuid").read_text().strip()
        except OSError:
            pass
    return devices


def wait(condition, seconds=10):
    for _ in range(seconds * 2):
        if condition():
            return True
        time.sleep(0.5)
    return condition()


class LoopIdentityChecks:
    def __init__(self, args):
        self.binary = str(Path(args.binary).resolve())
        self.legacy_binary = str(Path(args.legacy_binary).resolve()) if args.legacy_binary else None
        self.slot = args.slot
        self.dm_name = f"veracrypt{self.slot}"
        self.root = Path(tempfile.mkdtemp(prefix="veracrypt-loop-identity-test-")).resolve()
        self.mountpoint = self.root / "mount"
        self.bind = self.root / "bind"
        self.other = self.root / "other"
        for d in (self.mountpoint, self.bind, self.other):
            d.mkdir()
        self.volume = self.root / "test.hc"
        self.cascade = self.root / "cascade.hc"
        self.other_image = self.root / "other.img"
        self.password = "Disposable-loop-identity-test-only"
        self.results = []
        self.failures = []
        self.processes = []
        self.mounted = None
        # Devices of volumes mounted before the test
        self.existing_aux = aux_mounts()
        self.existing_loops = set(self.volume_loops())
        print("Artifacts:", self.root, flush=True)

    def record(self, entry):
        self.results.append(entry)
        (self.root / "results.json").write_text(json.dumps(self.results, indent=2))

    def run(self, label, args, expected=0, stdin=None):
        started = time.monotonic()
        result = subprocess.run(list(map(str, args)), input=stdin, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        (self.root / (label + ".log")).write_text(output)
        self.record(dict(label=label, returncode=result.returncode,
                         seconds=round(time.monotonic() - started, 3), output=output))
        if expected is not None and result.returncode != expected:
            raise AssertionError(f"{label}: expected {expected}, got {result.returncode}: {output}")
        return result

    def vc(self, label, *args, expected=0, binary=None):
        return self.run(label, [binary or self.binary, "--text", "--non-interactive", *args], expected)

    def create(self, label, path, encryption):
        self.vc(label, "--create", path, "--size=16M", "--volume-type=normal", "--encryption=" + encryption,
                "--hash=SHA-512", "--filesystem=FAT", "--password=" + self.password, "--pim=1", "--keyfiles=",
                "--random-source=/dev/urandom")

    def expect(self, label, passed, detail):
        self.record(dict(label=label, passed=passed, detail=detail))
        print("PASS" if passed else "FAIL", label + ":", detail, flush=True)
        if not passed:
            self.failures.append(label)

    def listed(self):
        result = self.vc("list", "--list", expected=None)
        for line in result.stdout.splitlines():
            fields = line.split()
            if fields[:1] == [f"{self.slot}:"]:
                return dict(device=fields[2] if fields[2] != "-" else None,
                            mountpoint=fields[3] if len(fields) > 3 and fields[3] != "-" else None)
        return None

    def volume_loops(self):
        # Loop devices attached to a test container or to the volume image of an auxiliary mount, which is shown
        # as /volume once that mount is detached
        return [loop for loop, backing in loop_devices().items()
                if backing in (str(self.volume), str(self.cascade), "/volume")
                or Path(backing).parent.name.startswith(AUX_PREFIX)]

    def start(self, args, **kwargs):
        process = subprocess.Popen(list(map(str, args)), **kwargs)
        self.processes.append(process)
        time.sleep(0.5)
        return process

    def stop(self, process):
        process.kill()
        process.wait()
        self.processes.remove(process)
        time.sleep(0.5)

    def mount_args(self, path, kernel, *args):
        return ("--mount", path, self.mountpoint, f"--slot={self.slot}",
                "--mount-options=" + ("" if kernel else "nokernelcrypto"), "--password=" + self.password,
                "--pim=1", "--keyfiles=", "--protect-hidden=no", *args)

    def mount(self, label, kernel, binary=None):
        before = aux_mounts()
        self.vc(label, *self.mount_args(self.volume, kernel), binary=binary)
        self.mounted = self.volume
        listed = self.listed()
        device = listed and listed["device"]
        if not device or device.startswith("/dev/mapper/") != kernel:
            raise AssertionError(f"Unexpected device for the {'kernel' if kernel else 'FUSE'} mode: {listed}")
        aux = list(aux_mounts() - before)
        if len(aux) != 1:
            raise AssertionError(f"Auxiliary mount not found: {aux}")
        if kernel:
            loop = self.run(label + "-loop", ["losetup", "-j", self.volume]).stdout.split(":")[0]
        else:
            loop = device
        if not loop.startswith("/dev/loop"):
            raise AssertionError(f"Loop device not found: {loop}")
        return device, loop, aux[0]

    def mount_fails(self, label, kernel, *args, path=None):
        path = path or self.volume
        result = self.vc(label + "-mount", *self.mount_args(path, kernel, *args), expected=None)
        if result.returncode == 0:
            self.mounted = path
        output = result.stdout + result.stderr
        self.expect(label + "-mount-fails", result.returncode != 0, f"exit {result.returncode}: {output.strip()}")
        return output

    def dismount(self, label, expected):
        result = self.vc(label, "--unmount", self.volume, expected=None)
        self.expect(label + "-" + ("succeeds" if expected else "fails"), (result.returncode == 0) == expected,
                    f"exit {result.returncode}: {(result.stdout + result.stderr).strip()}")
        if result.returncode == 0:
            self.mounted = None
        return result.stdout + result.stderr

    def released(self, keep_loops=(), keep_dm=()):
        state = {}

        def done():
            state.update(listed=self.listed(), aux_mounted=sorted(aux_mounts() - self.existing_aux),
                         loops=sorted(set(self.volume_loops()) - self.existing_loops - set(keep_loops)),
                         dm=sorted(n for n in dm_devices() if n.startswith(self.dm_name) and n not in keep_dm))
            return not any(state.values())

        return (True, "volume and devices released") if wait(done) else (False, f"left: {state}")

    def check_busy(self, kind, kernel, hold):
        mode = "kernel" if kernel else "fuse"
        label = f"{mode}-{kind}"
        device, loop, aux = self.mount(label + "-mount", kernel)
        backing = loop_backing(loop)
        holder = hold(device, loop)
        if kernel and kind == "loop-open":
            # The loop device gives access only to the container: the kernel detaches it once the holder closes it
            self.dismount(label + "-dismount", True)
            self.expect(label + "-volume-released", self.listed() is None and self.dm_name not in dm_devices(),
                        f"listed: {self.listed()}, dm: {dm_devices().get(self.dm_name)}")
            self.expect(label + "-loop-autoclear", loop_backing(loop) == backing and loop_autoclear(loop) is True,
                        f"{loop}: {loop_backing(loop)}, autoclear {loop_autoclear(loop)}")
            holder()
        else:
            output = self.dismount(label + "-dismount", False)
            reason = "another process has the volume's loop device open" if kind == "loop-open" else "mounted elsewhere"
            self.expect(label + "-cause-reported", reason in output, output.strip())
            listed = self.listed()
            self.expect(label + "-still-listed", listed is not None, str(listed))
            # With kernel cryptography, the loop device is to be detached once device-mapper releases it
            kept = loop_backing(loop) == backing and loop_autoclear(loop) is kernel
            if kernel:
                kept = kept and dm_devices().get(self.dm_name, "").startswith("VERACRYPT-")
            self.expect(label + "-devices-kept", kept, f"{loop}: {loop_backing(loop)}, autoclear "
                        f"{loop_autoclear(loop)}, {self.dm_name}: {dm_devices().get(self.dm_name)}")
            holder()
            self.dismount(label + "-retry", True)
        self.expect(label + "-released", *self.released())

    def hold_bind(self, device, loop):
        self.run("bind", ["mount", "--bind", self.mountpoint, self.bind])
        return lambda: self.run("unbind", ["umount", self.bind])

    def hold_namespace(self, device, loop):
        process = self.start(["unshare", "-m", "--propagation", "private", "sleep", "600"])
        return lambda: self.stop(process)

    def hold_loop(self, device, loop):
        with open(loop, "rb") as f:
            process = self.start(["sleep", "600"], stdin=f)
        return lambda: self.stop(process)

    def check_reuse(self, kernel):
        label = ("kernel" if kernel else "fuse") + "-reuse"
        device, loop, aux = self.mount(label + "-mount", kernel)
        holder = self.start(["sleep", "600"], cwd=aux)
        self.dismount(label + "-dismount", False)
        self.expect(label + "-loop-released", wait(lambda: loop_backing(loop) is None), f"{loop}: {loop_backing(loop)}")

        # Unrelated objects take over the released names
        self.run(label + "-other-attach", ["losetup", loop, self.other_image])
        self.run(label + "-other-mount", ["mount", loop, self.other])
        foreign = f"FOREIGN-{os.getpid()}-{self.dm_name}"
        if kernel:
            self.run(label + "-other-dm", ["dmsetup", "create", self.dm_name, "--uuid", foreign,
                                           "--table", "0 2048 zero"])
        try:
            listed = self.listed()
            self.expect(label + "-listing", listed == dict(device=None, mountpoint=None), str(listed))
            self.dismount(label + "-retry-busy", False)
            self.stop(holder)
            self.dismount(label + "-retry", True)
            self.expect(label + "-other-mount-kept", str(self.other) in mounts(), f"{self.other} mounted")
            self.expect(label + "-other-loop-kept", loop_backing(loop) == str(self.other_image),
                        f"{loop}: {loop_backing(loop)}")
            if kernel:
                self.expect(label + "-other-dm-kept", dm_devices().get(self.dm_name) == foreign,
                            f"{self.dm_name}: {dm_devices().get(self.dm_name)}")
        finally:
            self.run(label + "-other-unmount", ["umount", self.other], expected=None)
            self.run(label + "-other-detach", ["losetup", "-d", loop], expected=None)
            if kernel:
                self.run(label + "-other-dm-remove", ["dmsetup", "remove", "--retry", self.dm_name], expected=None)
        self.expect(label + "-released", *self.released())

    def check_stale_layer(self, kernel):
        # The test volume uses a single cipher, so it has no layer named <name>_0
        label = ("kernel" if kernel else "fuse") + "-stale-layer"
        stale = self.dm_name + "_0"
        self.run(label + "-dm", ["dmsetup", "create", stale, "--table", "0 2048 zero"])
        try:
            self.mount(label + "-mount", kernel)
            self.dismount(label + "-dismount", True)
            self.expect(label + "-dm-kept", dm_devices().get(stale) == "", f"{stale}: {dm_devices().get(stale)}")
            self.expect(label + "-released", *self.released(keep_dm=[stale]))
        finally:
            self.run(label + "-dm-remove", ["dmsetup", "remove", "--retry", stale], expected=None)

    def check_emergency(self, kernel):
        label = ("kernel" if kernel else "fuse") + "-emergency"
        self.mount(label + "-mount", kernel)
        process = self.start(["unshare", "-m", "--propagation", "private", "sleep", "600"])
        result = self.run(label + "-dismount", [self.binary, "--text", "--unmount", self.volume],
                          expected=None, stdin="y\n")
        output = result.stdout + result.stderr
        self.expect(label + "-cause-reported", "mounted elsewhere" in output, output.strip())
        self.expect(label + "-done", result.returncode == 0 and self.listed() is None,
                    f"exit {result.returncode}, listed: {self.listed()}")
        if result.returncode == 0:
            self.mounted = None
        self.stop(process)
        self.expect(label + "-released", *self.released())

    def check_rollback(self, kernel):
        mode = "kernel" if kernel else "fuse"
        # Mounting the FAT filesystem as ext4 fails once the volume's devices are created
        label = mode + "-rollback"
        output = self.mount_fails(label, kernel, "--filesystem=ext4")
        device = "/dev/mapper/" + self.dm_name if kernel else "/dev/loop"
        self.expect(label + "-filesystem-mount-failed", device in output, output.strip())
        self.expect(label + "-released", *self.released())
        if not kernel:
            return

        # Creating the device-mapper device fails if one of the same name exists, here without a UUID, as created
        # by earlier versions, and mapping either something else or the container through another loop device
        for kind in ("other", "container"):
            label = f"kernel-rollback-existing-{kind}"
            loop = None
            try:
                if kind == "container":
                    loop = self.run(label + "-attach", ["losetup", "-f", "--show", "-r", self.volume]).stdout.strip()
                self.run(label + "-dm", ["dmsetup", "create", self.dm_name, "--table",
                                         f"0 2048 linear {loop} 0" if loop else "0 2048 zero"])
                self.mount_fails(label, kernel)
                self.expect(label + "-dm-kept", dm_devices().get(self.dm_name) == "",
                            f"{self.dm_name}: {dm_devices().get(self.dm_name)}")
                if loop:
                    self.expect(label + "-loop-kept", loop_backing(loop) == str(self.volume),
                                f"{loop}: {loop_backing(loop)}")
                self.expect(label + "-released", *self.released(keep_loops=[loop], keep_dm=[self.dm_name]))
            finally:
                self.run(label + "-dm-remove", ["dmsetup", "remove", "--retry", self.dm_name], expected=None)
                if loop:
                    self.run(label + "-detach", ["losetup", "-d", loop], expected=None)

    def check_cascade_rollback(self):
        # The top layer of a cascade cannot be created while a device of the same name exists, here without a
        # UUID: the layer <name>_0 created before it is removed, and that device is left alone
        label = "kernel-cascade-rollback"
        if not self.cascade.exists():
            self.create(label + "-create", self.cascade, "AES-Twofish")
        self.run(label + "-dm", ["dmsetup", "create", self.dm_name, "--table", "0 2048 zero"])
        try:
            output = self.mount_fails(label, True, path=self.cascade)
            self.expect(label + "-top-layer-failed", f"create ioctl on {self.dm_name} " in output, output.strip())
            self.expect(label + "-dm-kept", dm_devices().get(self.dm_name) == "",
                        f"{self.dm_name}: {dm_devices().get(self.dm_name)}")
            self.expect(label + "-released", *self.released(keep_dm=[self.dm_name]))
        finally:
            self.run(label + "-dm-remove", ["dmsetup", "remove", "--retry", self.dm_name], expected=None)

    def check_dm_removed(self):
        # The loop device is detached once device-mapper releases it, even when its devices are removed by other means
        label = "kernel-dm-removed"
        device, loop, aux = self.mount(label + "-mount", True)
        self.run(label + "-umount", ["umount", self.mountpoint])
        self.run(label + "-dm-remove", ["dmsetup", "remove", "--retry", self.dm_name])
        self.expect(label + "-loop-released", wait(lambda: loop_backing(loop) is None), f"{loop}: {loop_backing(loop)}")
        self.dismount(label + "-dismount", True)
        self.expect(label + "-released", *self.released())

    def check_legacy(self, kernel):
        # Device-mapper devices created by an earlier version have no UUID
        label = ("kernel" if kernel else "fuse") + "-legacy"
        self.mount(label + "-mount", kernel, self.legacy_binary)
        self.dismount(label + "-dismount", True)
        self.expect(label + "-released", *self.released())

    def check_legacy_moved(self):
        # A device-mapper device without a UUID is verified through the container
        label = "kernel-legacy-moved"
        device, loop, aux = self.mount(label + "-mount", True, self.legacy_binary)
        moved = self.root / "moved.hc"
        os.rename(self.volume, moved)
        try:
            output = self.dismount(label + "-dismount", False)
            self.expect(label + "-cause-reported", "could not verify that this device belongs to the volume" in output
                        and str(self.volume) in output, output.strip())
            # Emergency cleanup is not offered: it would release the auxiliary mount, hiding the volume, but not its
            # devices
            result = self.run(label + "-interactive", [self.binary, "--text", "--unmount", self.volume],
                              expected=None, stdin="y\n")
            self.expect(label + "-interactive-fails", result.returncode != 0,
                        f"exit {result.returncode}: {(result.stdout + result.stderr).strip()}")
            listed = self.listed()
            self.expect(label + "-still-listed", listed is not None, str(listed))
            mounted = str(self.mountpoint) in mounts()
            self.expect(label + "-devices-kept", mounted and dm_devices().get(self.dm_name) == ""
                        and loop_backing(loop) == str(moved), f"{self.mountpoint} mounted: {mounted}, "
                        f"{self.dm_name}: {dm_devices().get(self.dm_name)!r}, {loop}: {loop_backing(loop)}")
        finally:
            os.rename(moved, self.volume)
        self.dismount(label + "-retry", True)
        self.expect(label + "-released", *self.released())

    def check_device_hosted(self, kernel):
        label = ("kernel" if kernel else "fuse") + "-device-hosted"
        host = self.run(label + "-attach", ["losetup", "-f", "--show", self.volume]).stdout.strip()
        try:
            self.vc(label + "-mount", *self.mount_args(host, kernel))
            self.mounted = host
            result = self.vc(label + "-dismount", "--unmount", host, expected=None)
            if result.returncode == 0:
                self.mounted = None
            self.expect(label + "-dismount-succeeds", result.returncode == 0,
                        f"exit {result.returncode}: {(result.stdout + result.stderr).strip()}")
            self.expect(label + "-host-kept", loop_backing(host) == str(self.volume) and loop_autoclear(host) is False,
                        f"{host}: {loop_backing(host)}, autoclear {loop_autoclear(host)}")
            self.expect(label + "-released", *self.released(keep_loops=[host]))
        finally:
            if self.mounted:
                self.vc(label + "-cleanup-unmount", "--force", "--unmount", host, expected=None)
                self.mounted = None
            self.run(label + "-detach", ["losetup", "-d", host], expected=None)

    def cleanup(self):
        for process in list(self.processes):
            self.stop(process)
        for path in (self.bind, self.other):
            if str(path) in mounts():
                self.run("cleanup-umount", ["umount", path], expected=None)
        if self.mounted:
            self.vc("cleanup-unmount", "--force", "--unmount", self.mounted, expected=None)
            self.mounted = None
        # Release devices left by a failed check, so that the next ones are not affected
        for name in sorted(n for n in dm_devices() if n.startswith(self.dm_name)):
            self.run("cleanup-dm-remove", ["dmsetup", "remove", "--retry", name], expected=None)
        for loop in sorted(set(self.volume_loops()) - self.existing_loops):
            self.run("cleanup-detach", ["losetup", "-d", loop], expected=None)
        for aux in sorted(aux_mounts() - self.existing_aux):
            self.run("cleanup-aux-unmount", ["umount", aux], expected=None)


def isolate_mounts():
    # Mount namespaces created by other processes during the test would copy
    # its mounts and keep its devices busy.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(CLONE_NEWNS) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "unshare: " + os.strerror(error))
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--legacy-binary", help="earlier version, such as 1.26.29, whose mounts are also checked")
    parser.add_argument("--slot", type=int, default=62, help="free slot for the test volume (default: 62)")
    parser.add_argument("--mode", choices=("fuse", "kernel"), action="append",
                        help="mount mode to check (default: both)")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Run on Linux as root")
    missing = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing:
        parser.error("Missing tools: " + ", ".join(missing))
    isolate_mounts()
    checks = LoopIdentityChecks(args)
    if checks.listed():
        parser.error(f"Slot {args.slot} is in use; choose a free one with --slot")
    if any(name.startswith(checks.dm_name) for name in dm_devices()):
        parser.error(f"/dev/mapper/{checks.dm_name} exists; choose a free slot with --slot")

    checks.create("create", checks.volume, "AES")
    with open(checks.other_image, "wb") as f:
        f.truncate(16 << 20)
    checks.run("other-mkfs", ["mkfs.ext4", "-q", "-F", checks.other_image])

    for mode in args.mode or ("fuse", "kernel"):
        kernel = mode == "kernel"
        mode_checks = [("bind", lambda: checks.check_busy("bind", kernel, checks.hold_bind)),
                       ("namespace", lambda: checks.check_busy("namespace", kernel, checks.hold_namespace)),
                       ("loop-open", lambda: checks.check_busy("loop-open", kernel, checks.hold_loop)),
                       ("reuse", lambda: checks.check_reuse(kernel)),
                       ("stale-layer", lambda: checks.check_stale_layer(kernel)),
                       ("emergency", lambda: checks.check_emergency(kernel)),
                       ("rollback", lambda: checks.check_rollback(kernel)),
                       ("device-hosted", lambda: checks.check_device_hosted(kernel))]
        if kernel:
            mode_checks += [("cascade-rollback", checks.check_cascade_rollback),
                            ("dm-removed", checks.check_dm_removed)]
        if checks.legacy_binary:
            mode_checks.append(("legacy", lambda: checks.check_legacy(kernel)))
            if kernel:
                mode_checks.append(("legacy-moved", checks.check_legacy_moved))
        for name, check in mode_checks:
            try:
                check()
            except Exception as e:
                traceback.print_exc()
                checks.expect(f"{mode}-{name}-completed", False, f"{type(e).__name__}: {e}")
            finally:
                checks.cleanup()
    if checks.failures:
        sys.exit("Failed: " + ", ".join(checks.failures))
    print("All checks passed")


if __name__ == "__main__":
    main()
