#!/usr/bin/env python3
"""Verify Linux read-only device protection in a dedicated disposable VM.

Requires the same tools as test_linux_loop_identity.py, plus blockdev. Run:
  python3 Tests/test_linux_read_only_integration.py --binary /usr/bin/veracrypt

To also test a virtual block device, attach a blank 16 MiB virtio disk with
serial=vc-readonly-test and pass --disposable-device /dev/vdb. That device is
overwritten with test containers. Never run this suite against user storage.
Use test_linux_mount_read_only.py for command/failure injection without root.
"""

import argparse
import os
from pathlib import Path
import shutil
import shlex
import sys

from test_linux_loop_identity import (
    LoopIdentityChecks, TOOLS, aux_mounts, dm_devices, isolate_mounts, loop_devices,
)


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
    missing = [tool for tool in (*TOOLS, "blockdev") if not shutil.which(tool)]
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
    if checks.failures:
        sys.exit("Failed: " + ", ".join(checks.failures))
    print("All read-only integration checks passed")


if __name__ == "__main__":
    main()
