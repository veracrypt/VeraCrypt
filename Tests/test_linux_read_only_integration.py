#!/usr/bin/env python3
"""Verify Linux read-only device protection in a dedicated disposable VM.

Requires the same tools as test_linux_loop_identity.py, plus blockdev and
debugfs. Read-only cases reject raw writes and preserve the encrypted host's
SHA-256. Dirty ext4 cases must refuse journal recovery without changing the
host or leaking devices; an explicit noload mount is the positive control.
Run:
  python3 Tests/test_linux_read_only_integration.py --binary /usr/bin/veracrypt

To also test a virtual block device, attach a blank 16 MiB virtio disk with
serial=vc-readonly-test and pass --disposable-device /dev/vdb. That device is
overwritten with test containers. Never run this suite against user storage.
Use test_linux_mount_read_only.py for command/failure injection without root.
"""

import argparse
import errno
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import sys

from test_linux_loop_identity import (
    LoopIdentityChecks, TOOLS, aux_mounts, dm_devices, isolate_mounts, loop_devices,
)


def host_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_write_rejected(checks, label, device):
    # Establish readability separately, so a read error cannot be mistaken
    # for a rejected write. Reusing the sector avoids corrupting later checks
    # if read-only protection regresses.
    with open(device, "rb", buffering=0) as stream:
        sector = stream.read(512)
    if len(sector) != 512:
        raise AssertionError(f"Cannot read test sector from {device}")
    descriptor = None
    try:
        descriptor = os.open(device, os.O_RDWR)
        os.pwrite(descriptor, sector, 0)
    except OSError as error:
        checks.expect(label, error.errno in (errno.EROFS, errno.EPERM, errno.EACCES),
                      f"{device}: {error}")
    else:
        checks.expect(label, False, f"{device}: raw write accepted")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def check_setup_failure(checks, program, kernel):
    label = f"{program}-failure-{'native' if kernel else 'fuse'}"
    real = checks.root / (program + ".real")
    wrapper = checks.root / (program + ".sh")
    calls = checks.root / (label + ".args")
    count = checks.root / (label + ".count")
    target = shutil.which(program)
    shutil.copy2(target, real)
    count.write_text("0\n")
    script = "#!/bin/sh\n"
    script += f"printf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
    if program == "losetup":
        # Fail the requested read-only setup. Any weakened retry would
        # actually succeed, and is caught by both the status and argument checks.
        script += 'case "$1" in -r) exit 1;; esac\n'
    else:
        script += ('if [ "$1" = create ]; then\n'
                   f'  n=$(cat {shlex.quote(str(count))})\n'
                   '  n=$((n + 1))\n'
                   f'  echo "$n" > {shlex.quote(str(count))}\n'
                   '  [ "$n" != 2 ] || exit 1\nfi\n')
    script += f'exec {shlex.quote(str(real))} "$@"\n'
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    checks.run(label + "-inject", ["mount", "--bind", wrapper, target])
    try:
        path = checks.cascade if program == "dmsetup" else checks.volume
        result = checks.vc(label, "--mount", path, checks.mountpoint, f"--slot={checks.slot}",
                           "--password=" + checks.password, "--pim=1", "--keyfiles=",
                           "--protect-hidden=no", "--filesystem=none",
                           "--mount-options=ro" + ("" if kernel else ",nokernelcrypto"), expected=None)
        if result.returncode == 0:
            checks.mounted = path
        checks.expect(label + "-fails", result.returncode != 0, f"exit {result.returncode}")
        arguments = calls.read_text().splitlines()
        if program == "losetup":
            attachments = [line for line in arguments if line != "-f"]
            checks.expect(label + "-no-downgrade", len(attachments) == 256 and
                          all(line.startswith("-r -- ") for line in attachments),
                          f"{len(attachments)} attachment attempts, all must retain -r")
        else:
            creates = [line for line in arguments if line.startswith("create ")]
            checks.expect(label + "-partial-cascade", len(creates) == 2 and
                          all("--readonly" in line.split() for line in creates), str(creates))
        checks.expect(label + "-released", *checks.released())
    finally:
        checks.run(label + "-restore", ["umount", target])
        checks.cleanup()


def check(checks, path, kernel, readonly, filesystem, layers, effective_readonly=None):
    label = f"{path.name}-{'native' if kernel else 'fuse'}-{'ro' if readonly else 'rw'}-{'fs' if filesystem else 'none'}"
    expected_readonly = readonly if effective_readonly is None else effective_readonly
    if expected_readonly != readonly:
        label += "-access-fallback"
    before_digest = host_digest(path) if expected_readonly else None
    before_aux = aux_mounts()
    before_loops = loop_devices()
    options = ",".join((["ro"] if readonly else []) + ([] if kernel else ["nokernelcrypto"]))
    args = ["--mount", path, checks.mountpoint, f"--slot={checks.slot}",
            "--password=" + checks.password, "--pim=1", "--keyfiles=", "--protect-hidden=no",
            "--mount-options=" + options]
    if not filesystem:
        args += ["--filesystem=none"]
    try:
        checks.vc(label, *args)
        checks.mounted = path
        listed = checks.listed()
        device = listed and listed["device"]
        if not device or device.startswith("/dev/mapper/") != kernel:
            raise AssertionError(f"Wrong backend: {listed}")
        names = {name for name in dm_devices() if name == checks.dm_name or name.startswith(checks.dm_name + "_")}
        expected = {checks.dm_name} | {f"{checks.dm_name}_{i}" for i in range(layers - 1)} if kernel else set()
        checks.expect(label + "-layers", names == expected, str(sorted(names)))
        devices = ["/dev/mapper/" + name for name in sorted(names)] if kernel else [device]
        new_loops = set(loop_devices()) - set(before_loops)
        if kernel and str(path).startswith("/dev/"):
            checks.expect(label + "-no-loop", not new_loops, str(new_loops))
        else:
            checks.expect(label + "-loop", len(new_loops) == 1, str(new_loops))
        for index, dev in enumerate(sorted(set(devices) | new_loops)):
            mode = checks.run(f"{label}-mode-{index}", ["blockdev", "--getro", dev]).stdout.strip()
            checks.expect(f"{label}-protected-{index}", mode == str(int(expected_readonly)), f"{dev}: read-only={mode}")
            if expected_readonly:
                check_write_rejected(checks, f"{label}-write-rejected-{index}", dev)
        if filesystem:
            flags = next(line.split()[3].split(",") for line in Path("/proc/mounts").read_text().splitlines()
                         if line.split()[1] == str(checks.mountpoint))
            checks.expect(label + "-filesystem", ("ro" if expected_readonly else "rw") in flags, str(flags))
            if not expected_readonly:
                marker = checks.mountpoint / "writable-check"
                marker.write_text(label)
                checks.expect(label + "-write", marker.read_text() == label, "ordinary file write succeeded")
                marker.unlink()
        checks.vc(label + "-unmount", "--unmount", path)
        checks.mounted = None
        checks.expect(label + "-released", *checks.released())
        checks.expect(label + "-aux-released", aux_mounts() == before_aux, "auxiliary mount released")
        if expected_readonly:
            checks.expect(label + "-unchanged", host_digest(path) == before_digest,
                          "encrypted host SHA-256 unchanged")
    finally:
        checks.cleanup()


def check_journal_recovery(checks, path, kernel):
    label = f"{path.name}-{'native' if kernel else 'fuse'}-journal"
    args = ["--mount", path, checks.mountpoint, f"--slot={checks.slot}",
            "--password=" + checks.password, "--pim=1", "--keyfiles=", "--protect-hidden=no"]
    backend = "" if kernel else "nokernelcrypto"
    try:
        checks.vc(label + "-prepare", *args, "--filesystem=none", "--mount-options=" + backend)
        checks.mounted = path
        device = checks.listed()["device"]
        checks.run(label + "-mkfs", ["mkfs.ext4", "-q", "-F", device])
        checks.run(label + "-mark-dirty", ["debugfs", "-w", "-R", "feature needs_recovery", device])
        features = checks.run(label + "-features", ["debugfs", "-R", "feature", device]).stdout.split()
        if "needs_recovery" not in features:
            raise AssertionError(f"Journal fixture is not marked for recovery: {features}")
        checks.vc(label + "-prepare-unmount", "--unmount", path)
        checks.mounted = None
        before = host_digest(path)
        readonly = "--mount-options=ro" + ("," + backend if backend else "")
        result = checks.vc(label + "-mount", *args, "--filesystem=ext4", readonly, expected=None)
        if result.returncode == 0:
            checks.mounted = path
        checks.expect(label + "-recovery-refused", result.returncode != 0,
                      f"exit {result.returncode}: {result.stdout + result.stderr}")
        checks.expect(label + "-released", *checks.released())
        checks.cleanup()
        checks.expect(label + "-unchanged", host_digest(path) == before,
                      "failed read-only mount preserved encrypted host SHA-256")

        # The filesystem is mountable when journal recovery is explicitly
        # disabled. This is a test control, not an automatic recovery policy.
        checks.vc(label + "-noload", *args, "--filesystem=ext4", readonly, "--fs-options=noload")
        checks.mounted = path
        flags = next(line.split()[3].split(",") for line in Path("/proc/mounts").read_text().splitlines()
                     if line.split()[1] == str(checks.mountpoint))
        checks.expect(label + "-noload-readonly", "ro" in flags, str(flags))
        checks.vc(label + "-noload-unmount", "--unmount", path)
        checks.mounted = None
        checks.expect(label + "-noload-released", *checks.released())
        checks.expect(label + "-noload-unchanged", host_digest(path) == before,
                      "explicit noload mount preserved encrypted host SHA-256")
    finally:
        checks.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--disposable-device", type=Path)
    parser.add_argument("--slot", type=int, default=61)
    args = parser.parse_args()
    args.legacy_binary = None
    if os.geteuid() != 0:
        parser.error("Run as root in a dedicated disposable VM")
    missing = [tool for tool in (*TOOLS, "blockdev", "debugfs") if not shutil.which(tool)]
    if missing:
        parser.error("Missing tools: " + ", ".join(missing))
    if args.disposable_device:
        serial = Path("/sys/class/block", args.disposable_device.name, "serial")
        if not args.disposable_device.is_block_device() or serial.read_text().strip() != "vc-readonly-test":
            parser.error("The disposable device must have virtio serial vc-readonly-test")
    isolate_mounts()
    checks = LoopIdentityChecks(args)
    if checks.listed() or any(n.startswith(checks.dm_name) for n in dm_devices()):
        parser.error("Test slot is already in use")
    for path, cipher, layers in ((checks.volume, "AES", 1), (checks.cascade, "Serpent-Twofish-AES", 3)):
        checks.create("create-" + path.name, path, cipher)
        paths = [path]
        if args.disposable_device:
            checks.run("copy-" + path.name, ["dd", "if=" + str(path), "of=" + str(args.disposable_device), "bs=1M", "conv=fsync"])
            paths.append(args.disposable_device)
        for source in paths:
            for kernel in (True, False):
                for readonly in (True, False):
                    for filesystem in (False, True):
                        check(checks, source, kernel, readonly, filesystem, layers)
        # A read-only host mount makes the initial O_RDWR open fail with
        # EROFS. A block device's read-only flag alone need not reject open().
        checks.run("host-bind", ["mount", "--bind", path, path])
        try:
            checks.run("host-readonly", ["mount", "-o", "remount,bind,ro", path])
            for kernel in (True, False):
                check(checks, path, kernel, False, True, layers, effective_readonly=True)
        finally:
            checks.run("host-unbind", ["umount", path])
    for kernel in (True, False):
        check_setup_failure(checks, "losetup", kernel)
    check_setup_failure(checks, "dmsetup", True)
    for source in [checks.volume] + ([args.disposable_device] if args.disposable_device else []):
        for kernel in (True, False):
            check_journal_recovery(checks, source, kernel)
    if checks.failures:
        sys.exit("Failed: " + ", ".join(checks.failures))
    print("All read-only integration checks passed")


if __name__ == "__main__":
    main()
