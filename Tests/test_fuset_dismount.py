#!/usr/bin/env python3
"""Exercise macOS FUSE-T dismount using a disposable file container, without sudo.

Usage:
  python3 Tests/test_fuset_dismount.py --binary /path/to/patched/VeraCrypt

Optional compatibility checks use binaries built from these protocol generations:
  --released-binary /Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt
  --file-protocol-binary /path/to/d7bc65be/VeraCrypt

An unsigned/local build can also exercise startup rollback with --startup-faults
(requires clang and permits DYLD injection only in the disposable test clients).

Artifacts are retained in a private temporary directory. Every unmount targets
the test container explicitly. Existing volumes are never dismounted by the test.
The released-binary leg records legacy process remnants, then terminates only
the captured test processes after their filesystems have been unmounted.
"""

import argparse
import errno
import hashlib
import json
import os
import plistlib
import signal
import socket
import struct
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


class DismountChecks:
    def __init__(self, args):
        self.binary = str(Path(args.binary).resolve())
        self.released = str(Path(args.released_binary).resolve()) if args.released_binary else None
        self.file_protocol = str(Path(args.file_protocol_binary).resolve()) if args.file_protocol_binary else None
        self.startup_faults = getattr(args, "startup_faults", False)
        self.root = Path(tempfile.mkdtemp(prefix="veracrypt-dismount-test-")).resolve()
        self.volume = self.root / "test.hc"
        self.mountpoint = self.root / "mount"
        self.tmpdir = self.root / "tmp"
        self.mountpoint.mkdir()
        self.tmpdir.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.tmpdir) + "/")
        self.results = []
        self.active = None
        self.password = "Disposable-FUSE-T-test-only"
        self.payload = bytes(range(256)) * 32769
        self.digest = hashlib.sha256(self.payload).hexdigest()
        print("Artifacts:", self.root, flush=True)

    def record(self, entry):
        self.results.append(entry)
        (self.root / "results.json").write_text(json.dumps(self.results, indent=2))

    def run(self, label, args, expected=0):
        started = time.monotonic()
        result = subprocess.run(list(map(str, args)), env=self.env, capture_output=True,
                                text=True, timeout=90)
        output = result.stdout + result.stderr
        (self.root / (label + ".log")).write_text(output)
        self.record(dict(label=label, returncode=result.returncode,
                         seconds=round(time.monotonic() - started, 3), output=output))
        print(label, "exit", result.returncode, flush=True)
        if expected is not None and result.returncode != expected:
            raise AssertionError(f"{label}: expected {expected}, got {result.returncode}: {output}")
        return result

    def vc(self, label, *args, binary=None, expected=0):
        return self.run(label, [binary or self.binary, "--text", "--non-interactive", *args], expected)

    def mount(self, label, binary=None, options=()):
        binary = binary or self.binary
        # Retain the cleanup client even if mount fails after creating its service.
        self.active = dict(binary=binary)
        self.vc(label, "--mount", self.volume, self.mountpoint,
                "--password=" + self.password, "--pim=1", "--keyfiles=",
                "--protect-hidden=no", *options, binary=binary)
        auxiliaries = [p.parent for p in self.tmpdir.glob(".veracrypt_aux_mnt*/control")]
        if len(auxiliaries) != 1:
            raise AssertionError(f"Expected one test service, found {auxiliaries}")
        aux = auxiliaries[0]
        self.active.update(aux=aux)
        identity = aux / "shutdown"
        if identity.exists():
            pid, serial, slot = map(int, identity.read_text().split())
            self.active.update(pid=pid, serial=serial, slot=slot)
        endpoint = aux / "shutdown-socket"
        if endpoint.exists():
            self.active["endpoint"] = Path(endpoint.read_text().strip())
        self.active["holders"] = self.container_holders()

    def container_holders(self):
        result = subprocess.run(["/usr/sbin/lsof", "-t", str(self.volume)],
                                capture_output=True, text=True)
        if result.returncode not in (0, 1):
            raise AssertionError(result.stderr)
        return sorted(set(map(int, result.stdout.split())))

    def image(self, path):
        result = subprocess.run(["/usr/bin/hdiutil", "info", "-plist"],
                                capture_output=True, check=True)
        images = [image for image in plistlib.loads(result.stdout)["images"]
                  if Path(image["image-path"]).resolve() == path.resolve()]
        if len(images) > 1:
            raise AssertionError(images)
        return images[0] if images else None

    def device(self):
        image = self.image(self.active["aux"] / "volume.dmg")
        if not image:
            raise AssertionError("Test image is not attached")
        return next(entity["dev-entry"] for entity in image["system-entities"]
                    if "dev-entry" in entity)

    def cleanup_released_service(self):
        # The fallback restores unmounting; it cannot retrofit process teardown
        # into an already-running released service. Record this limitation and
        # clean only the captured test processes after all filesystems are gone.
        assert not self.mounted_paths()
        assert not self.image(self.active["aux"] / "volume.dmg")
        holders = self.container_holders()
        self.record(dict(label="released-service-remnants", holders=holders))
        assert set(holders) <= set(self.active["holders"])
        for pid in holders:
            process = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "uid=,args="],
                                     capture_output=True, text=True)
            if not process.stdout.strip():
                continue
            uid, command = process.stdout.strip().split(None, 1)
            assert int(uid) == os.getuid()
            assert self.released in command or ("go-nfsv4" in command and str(self.tmpdir) in command)
            os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        for pid in self.container_holders():
            assert pid in holders
            # Released signal handlers can also linger. All test filesystems
            # are unmounted; these exact processes still hold only our fixture.
            os.kill(pid, signal.SIGKILL)
        self.confirm_closed("released-service-fixture-cleanup")

    def mounted_paths(self):
        return [line for line in subprocess.check_output(["/sbin/mount"], text=True).splitlines()
                if str(self.tmpdir) + "/" in line or f" on {self.mountpoint} (" in line]

    def confirm_closed(self, label):
        deadline = time.monotonic() + 5
        while True:
            handles = subprocess.run(["/usr/sbin/lsof", "-nP", str(self.volume)],
                                     capture_output=True, text=True)
            if handles.returncode not in (0, 1):
                raise AssertionError(handles.stderr)
            processes = subprocess.check_output(["/bin/ps", "-axo", "pid=,args="], text=True)
            backend = [line for line in processes.splitlines()
                       if "go-nfsv4" in line and str(self.root) in line]
            services = [line for line in processes.splitlines() if str(self.volume) in line]
            inventory = plistlib.loads(subprocess.check_output(["/usr/bin/hdiutil", "info", "-plist"]))
            images = [entry for entry in inventory["images"]
                      if str(self.root) in entry.get("image-path", "")
                      and entry["image-path"].endswith("/volume.dmg")]
            alive = False
            if "pid" in self.active:
                try:
                    os.kill(self.active["pid"], 0)
                    alive = True
                except ProcessLookupError:
                    pass
            endpoint = self.active.get("endpoint")
            state = dict(label=label, mounts=self.mounted_paths(), handles=handles.stdout,
                         service_alive=alive, endpoint_exists=bool(endpoint and endpoint.exists()),
                         backend=backend, services=services, images=images)
            if not any(state[key] for key in ("mounts", "handles", "service_alive", "endpoint_exists", "backend", "services", "images")):
                self.record(state)
                self.active = None
                return
            if time.monotonic() >= deadline:
                self.record(state)
                raise AssertionError(state)
            time.sleep(0.1)

    def unmount(self, label, binary=None, force=False):
        options = ["--force"] if force else []
        self.vc(label, *options, "--unmount", self.volume, binary=binary)
        self.confirm_closed(label + "-closed")

    def assert_volume_unchanged(self, before):
        if self.mounted_paths() != before:
            raise AssertionError("A failed preflight changed the mount table")
        os.kill(self.active["pid"], 0)
        if hashlib.sha256((self.mountpoint / "payload.bin").read_bytes()).hexdigest() != self.digest:
            raise AssertionError("A failed preflight changed payload data")

    def expect_incompatible(self, label, force=False):
        before = self.mounted_paths()
        options = ["--force"] if force else []
        result = self.vc(label, *options, "--unmount", self.volume, expected=1)
        if "version of VeraCrypt that mounted it" not in result.stdout + result.stderr:
            raise AssertionError("Missing actionable compatibility message")
        self.assert_volume_unchanged(before)

    def check_device_reuse(self):
        decoy = self.root / "decoy.dmg"
        mountpoint = self.root / "decoy-mount"
        mountpoint.mkdir()
        self.run("decoy-create", ["/usr/bin/hdiutil", "create", "-size", "32m", "-fs", "HFS+",
                                  "-layout", "NONE", "-volname", "VC-disposable-decoy", decoy])
        for busy in (True, False):
            label = "busy-device-reuse" if busy else "external-eject-device-reuse"
            self.mount(label + "-mount")
            old_device = self.device()
            if busy:
                with (self.active["aux"] / "control").open("rb") as held:
                    held.read(1)
                    result = self.vc(label + "-refused", "--unmount", self.volume, expected=1)
                    # CLI errors are localized. Check the refusal and retained
                    # service instead of its internal C++ exception name.
                    os.kill(self.active["pid"], 0)
                    if not any(f" on {self.active['aux']} (" in line for line in self.mounted_paths()):
                        raise AssertionError("Busy unmount removed the auxiliary mount")
            else:
                self.run(label + "-detach", ["/usr/bin/hdiutil", "detach", old_device])
            try:
                self.run(label + "-decoy-attach", ["/usr/bin/hdiutil", "attach", decoy,
                                                   "-mountpoint", mountpoint, "-nobrowse"])
                attached = self.image(decoy)
                devices = [entity.get("dev-entry") for entity in attached["system-entities"]]
                if old_device not in devices:
                    raise AssertionError(f"Device reuse was not exercised: {old_device}, {devices}")
                listing = self.vc(label + "-list", "--list", "--verbose", self.volume).stdout
                if old_device in listing or str(mountpoint) in listing:
                    raise AssertionError("Listing retained a device now owned by another image")
                marker = mountpoint / "keep-mounted.txt"
                marker.write_text("This is a separate disposable disk image.\n")
                with marker.open("rb") as held:
                    self.unmount(label + "-retry", force=not busy)
                    if not self.image(decoy) or not held.read():
                        raise AssertionError("Retry detached the unrelated test image")
            finally:
                image = self.image(decoy)
                if image:
                    device = next(entity["dev-entry"] for entity in image["system-entities"]
                                  if "dev-entry" in entity)
                    self.run(label + "-decoy-cleanup", ["/usr/bin/hdiutil", "detach", device])

    def check_socket_errors(self):
        self.mount("socket-validation-mount")
        state = self.active
        mount_id = struct.unpack("=II", struct.pack("=Q", os.statvfs(state["aux"]).f_fsid))
        frame = [3, 0, state["pid"], state["serial"], state["slot"], 0, *mount_id]
        before = self.mounted_paths()
        for name, index, value, expected in (("version", 0, 999, errno.EPROTONOSUPPORT),
                                             ("identity", 3, state["serial"] + 1, errno.EINVAL),
                                             ("mount-instance", 6, mount_id[0] ^ 1, errno.ESTALE)):
            request = frame.copy()
            request[index] = value
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(str(state["endpoint"] / "socket"))
                client.sendall(struct.pack("=8Q", *request))
                result = struct.unpack("=i", client.recv(4))[0]
                if result != expected:
                    raise AssertionError((name, result, expected))
            self.assert_volume_unchanged(before)
            self.record(dict(label="socket-rejected-" + name, error=result))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(state["endpoint"] / "socket"))
            client.sendall(b"\x03")
            # A partial frame must expire without needing another request.
            if client.recv(1):
                raise AssertionError("Partial request did not expire")
        self.unmount("socket-validation-unmount")

    def check_path_aliases(self):
        alias = self.root / "tmp-alias"
        alias.symlink_to(self.tmpdir, target_is_directory=True)
        original_tmpdir = self.env["TMPDIR"]
        try:
            self.env["TMPDIR"] = str(alias) + "/"
            for force in (False, True):
                label = "alias-force" if force else "alias-normal"
                self.mount(label + "-mount")
                image = self.image(self.active["aux"] / "volume.dmg")
                if image["image-path"] != str(self.active["aux"] / "volume.dmg"):
                    raise AssertionError("New image was attached through a noncanonical path")
                device = self.device()
                listing = self.vc(label + "-list", "--list", "--verbose", self.volume).stdout
                if device not in listing or str(self.mountpoint) not in listing:
                    raise AssertionError("Aliased TMPDIR lost the device or mount directory")
                if force:
                    with (self.mountpoint / "alias-write.bin").open("wb", buffering=0) as output:
                        output.write(self.payload)
                        self.unmount(label + "-unmount", force=True)
                else:
                    self.unmount(label + "-unmount")
            self.mount("alias-integrity-remount", options=("--mount-options=ro",))
            if hashlib.sha256((self.mountpoint / "alias-write.bin").read_bytes()).hexdigest() != self.digest:
                raise AssertionError("Aliased forced dismount lost completed writes")
            self.unmount("alias-integrity-cleanup")

            if self.released:
                # A released service retains the alias in hdiutil's inventory.
                # New clients must resolve it even though new mounts are canonical.
                self.mount("released-alias-mount", binary=self.released)
                listing = self.vc("released-alias-list", "--list", "--verbose", self.volume).stdout
                if self.device() not in listing or str(self.mountpoint) not in listing:
                    raise AssertionError("Released service's image alias was not resolved")
                self.vc("released-alias-unmount", "--unmount", self.volume)
                self.cleanup_released_service()
        finally:
            self.env["TMPDIR"] = original_tmpdir

    def check_startup_rollback(self):
        library = self.root / "startup-faults.dylib"
        source = Path(__file__).with_name("fuset_startup_faults.c")
        self.run("build-startup-faults", ["/usr/bin/xcrun", "clang", "-dynamiclib", "-Wall", "-Wextra",
                                         "-O2", source, "-o", library])
        for fault in ("refused", "metadata", "control", "rollback-blocked"):
            label = "startup-" + fault
            socket_log = self.root / (label + "-socket.txt")
            fault_marker = self.root / (label + "-fault-reached")
            gate = self.root / (label + "-gate")
            if fault == "rollback-blocked":
                gate.touch()
            self.active = dict(binary=self.binary)
            fault_env = dict(DYLD_INSERT_LIBRARIES=str(library), VC_FUSET_TEST_FAULT=fault,
                             VC_FUSET_TEST_ROOT=str(self.root), VC_FUSET_TEST_SOCKET_LOG=str(socket_log),
                             VC_FUSET_TEST_UNMOUNT_GATE=str(gate), VC_FUSET_TEST_FAULT_MARKER=str(fault_marker))
            old_env = self.env
            self.env = dict(old_env, **fault_env)
            try:
                result = self.vc(label + "-mount", "--mount", self.volume, self.mountpoint,
                                 "--password=" + self.password, "--pim=1", "--keyfiles=",
                                 "--protect-hidden=no", expected=1)
                if not fault_marker.exists():
                    raise AssertionError("Fault injection was not reached; use an unsigned/local build")
                if socket_log.exists():
                    self.active["endpoint"] = Path(socket_log.read_text()).parent
                if fault == "rollback-blocked":
                    if "volume may still be accessible" not in result.stdout + result.stderr:
                        raise AssertionError("Failed rollback did not report the remaining partial mount")
                    if not self.container_holders():
                        raise AssertionError("Rollback failure was not exercised")
            finally:
                self.env = old_env
                gate.unlink(missing_ok=True)
            # Removing the gate also checks that a failed rollback is retried
            # by the service after the caller has already reported the failure.
            self.confirm_closed(label + "-rolled-back")
            self.mount(label + "-retry-mount")
            self.unmount(label + "-retry-unmount")

    def checks(self):
        self.vc("create", "--create", self.volume, "--size=67108864", "--volume-type=normal",
                "--encryption=AES", "--hash=sha512", "--filesystem=FAT",
                "--password=" + self.password, "--pim=1", "--keyfiles=",
                "--random-source=/dev/urandom")
        self.mount("normal-mount")
        with (self.mountpoint / "payload.bin").open("wb") as output:
            output.write(self.payload)
            output.flush()
            os.fsync(output.fileno())
        self.unmount("normal-unmount")

        self.mount("readonly-mount", options=("--mount-options=ro",))
        if hashlib.sha256((self.mountpoint / "payload.bin").read_bytes()).hexdigest() != self.digest:
            raise AssertionError("Payload failed verification after remount")
        self.unmount("readonly-unmount")

        self.mount("no-filesystem-mount", options=("--filesystem=none",))
        self.unmount("no-filesystem-unmount")

        self.mount("external-eject-mount")
        listing = self.vc("external-eject-properties", "--list", "--verbose", self.volume).stdout
        device = re.search(r"^Virtual Device: (.+)$", listing, re.M).group(1)
        self.run("external-eject", ["/usr/bin/hdiutil", "detach", device])
        self.unmount("external-eject-cleanup")

        self.mount("busy-mount")
        with (self.active["aux"] / "control").open("rb") as held:
            held.read(1)
            self.vc("busy-unmount-refused", "--unmount", self.volume, expected=1)
            os.kill(self.active["pid"], 0)
        self.unmount("busy-release-retry")

        self.mount("force-mount")
        with (self.active["aux"] / "control").open("rb") as held:
            held.read(1)
            self.unmount("force-unmount", force=True)

        for iteration in range(3):
            label = f"force-integrity-{iteration}"
            payload = bytes([iteration + 1]) * (16 * 1024 * 1024)
            self.mount(label + "-mount")
            with (self.mountpoint / "unsynced.bin").open("wb", buffering=0) as output:
                output.write(payload)
                self.unmount(label + "-unmount", force=True)
            self.mount(label + "-remount", options=("--mount-options=ro",))
            if (self.mountpoint / "unsynced.bin").read_bytes() != payload:
                raise AssertionError("Forced dismount did not preserve completed writes")
            self.unmount(label + "-verified")

        self.check_device_reuse()
        self.check_socket_errors()
        self.check_path_aliases()
        if self.startup_faults:
            self.check_startup_rollback()

        if self.released:
            for force in (False, True):
                label = "released-service-force" if force else "released-service-normal"
                self.mount(label + "-mount", binary=self.released)
                options = ["--force"] if force else []
                self.vc(label + "-unmount", *options, "--unmount", self.volume)
                self.cleanup_released_service()
            self.mount("released-client-mount")
            self.unmount("released-client-unmount", binary=self.released)

        if self.file_protocol:
            self.mount("file-client-mount")
            self.unmount("file-client-unmount", binary=self.file_protocol)
            self.mount("file-service-mount", binary=self.file_protocol)
            self.expect_incompatible("file-service-preflight")
            self.unmount("file-service-original-client-cleanup", binary=self.file_protocol)

        self.record(dict(result="passed", payload_sha256=self.digest))

    def cleanup(self):
        if self.active is not None:
            if not self.mounted_paths() and not self.container_holders():
                self.confirm_closed("failure-already-cleaned")
                return
            # Older services cannot understand the new force request; use their
            # original client for cleanup. Test file handles have been closed.
            original = self.active["binary"]
            if original == self.released:
                self.vc("failure-cleanup", "--unmount", self.volume, binary=original, expected=None)
                self.cleanup_released_service()
            else:
                self.unmount("failure-cleanup", binary=original, force=original == self.binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--released-binary")
    parser.add_argument("--file-protocol-binary")
    parser.add_argument("--startup-faults", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() == 0:
        parser.error("Run on macOS as an ordinary user with FUSE-T installed")
    checks = DismountChecks(args)
    try:
        checks.checks()
    finally:
        checks.cleanup()


if __name__ == "__main__":
    main()
