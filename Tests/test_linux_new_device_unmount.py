#!/usr/bin/env python3
"""Test for issue #1982, against the installed veracrypt GUI.

Usage (as root, with Xvfb and the dummy_hcd and g_zero kernel modules):
  python3 Tests/test_linux_new_device_unmount.py [--veracrypt PATH]
      [--connect-command COMMAND]

With --connect-command, COMMAND connects a new USB device (for example a
virtual machine's host hot-plugging one) instead of g_zero, and the kernel
modules are not needed.

Mounts a volume with kernel cryptography and a volume without kernel
cryptography, with a file open on each, then starts the GUI with "Unmount
all volumes when a new USB or Thunderbolt device is connected" enabled, and
checks that:

- a device that was connected when the GUI started does not unmount the
  volumes when the kernel reports it again;
- a new USB device unmounts both volumes, and their keys are gone at once:
  the open files fail with I/O errors (the FUSE service of the volume without
  kernel cryptography has exited), and the device-mapper devices of the
  other volume are removed or replaced with an error target.

The test is skipped if xvfb-run, or the kernel modules without
--connect-command, are not available.
"""

import argparse
import errno
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASSWORD = "regression-test-password-new-device"
# A low PIM keeps the tests fast; it needs passwords of 20 characters or more.
COMMON = ["--pim=1", "--keyfiles=", "--protect-hidden=no"]
NETLINK_KOBJECT_UEVENT = 15


class Checks:
    def __init__(self):
        self.failures = 0

    def check(self, desc, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + desc, flush=True)
        if not cond:
            self.failures += 1
            if detail:
                print("     " + detail.strip().replace("\n", "\n     "))


def text(result):
    return (result.stdout or b"").decode("utf-8", "replace")


def modprobe(*args):
    return subprocess.run(["modprobe"] + list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).returncode == 0


def uevent_socket_inodes():
    """Inodes of the netlink sockets listening to kernel uevents."""
    inodes = set()
    with open("/proc/net/netlink") as f:
        next(f)
        for line in f:
            fields = line.split()
            # sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
            if len(fields) >= 10 and int(fields[1]) == NETLINK_KOBJECT_UEVENT \
                    and int(fields[3], 16) & 1:
                inodes.add(fields[9])
    return inodes


def process_tree(root_pid):
    """The process and all its descendants."""
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as f:
                stat = f.read()
        except OSError:
            continue
        ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        children.setdefault(ppid, []).append(int(entry))
    pids, todo = [], [root_pid]
    while todo:
        pid = todo.pop()
        pids.append(pid)
        todo.extend(children.get(pid, []))
    return pids


def listens_to_uevents(root_pid):
    inodes = uevent_socket_inodes()
    for pid in process_tree(root_pid):
        try:
            for fd in os.listdir("/proc/%d/fd" % pid):
                link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
                match = re.match(r"socket:\[(\d+)\]", link)
                if match and match.group(1) in inodes:
                    return True
        except OSError:
            continue
    return False


def aux_mounts():
    with open("/proc/mounts") as f:
        return [line for line in f if ".veracrypt_aux_mnt" in line]


def fuse_holders(executable):
    """VeraCrypt processes that hold /dev/fuse open."""
    holders = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.readlink("/proc/%s/exe" % entry) != executable:
                continue
            for fd in os.listdir("/proc/%s/fd" % entry):
                if os.readlink("/proc/%s/fd/%s" % (entry, fd)) == "/dev/fuse":
                    holders.append(int(entry))
                    break
        except OSError:
            continue
    return holders


def wait_for(condition, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.5)
    return condition()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    parser.add_argument("--connect-command",
                        help="shell command connecting a new USB device")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root: the test mounts volumes and loads kernel modules")

    # The GUI destroys the keys of every mounted volume, not only of this test's
    if aux_mounts():
        sys.exit("Other VeraCrypt volumes are mounted: not running this test")

    if not shutil.which("xvfb-run"):
        print("SKIP: xvfb-run is not available")
        return
    if not args.connect_command and not modprobe("dummy_hcd"):
        print("SKIP: the dummy_hcd kernel module is not available")
        return

    work = Path(tempfile.mkdtemp(prefix="vc-new-device-"))
    config = work / "config" / "VeraCrypt"
    config.mkdir(parents=True)
    env = dict(os.environ, XDG_CONFIG_HOME=str(work / "config"))
    (work / "random").write_bytes(os.urandom(4096))
    (config / "Configuration.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<VeraCrypt>\n'
        '\t<configuration>\n'
        '\t\t<config key="DismountOnNewDevice">1</config>\n'
        '\t\t<config key="BackgroundTaskEnabled">0</config>\n'
        '\t</configuration>\n</VeraCrypt>\n')
    c = Checks()
    gui = None
    open_fds = {}

    def run(arguments):
        return subprocess.run([args.veracrypt, "--text"] + arguments,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=work, env=env,
                              timeout=300)

    def mounted():
        """Volume path and slot of each mounted volume; raises if the
        volumes cannot be listed."""
        r = run(["--list"])
        if r.returncode != 0:
            if "No volumes mounted" in text(r):
                return {}
            raise RuntimeError("veracrypt --list failed: " + text(r))
        volumes = {}
        for line in text(r).splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0].endswith(":"):
                volumes[fields[1]] = fields[0].rstrip(":")
        return volumes

    def dismount(volumes):
        """Dismounts only these volumes; returns whether none remains."""
        paths = [str(volume) for volume in volumes]
        for _ in range(3):
            remaining = [path for path in paths if path in mounted()]
            if not remaining:
                return True
            for path in remaining:
                run(["--non-interactive", "--force", "-d", path])
        return not any(path in mounted() for path in paths)

    def veracrypt_dm_tables():
        r = subprocess.run(["dmsetup", "table"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        return [line for line in text(r).splitlines()
                if line.startswith("veracrypt")]

    kernel, fuse = work / "kernel.hc", work / "fuse.hc"
    try:
        for volume in (kernel, fuse):
            r = run(["--non-interactive", "--create", str(volume),
                     "--size=10M", "--volume-type=normal",
                     "--encryption=AES", "--hash=SHA-512",
                     "--filesystem=fat", "-p", PASSWORD, "--pim=1",
                     "--keyfiles=", "--random-source=" + str(work / "random")])
            c.check("create %s" % volume.name, r.returncode == 0, text(r))
        if c.failures:
            sys.exit("Cannot create the test volumes")

        (work / "kernel").mkdir()
        (work / "fuse").mkdir()
        tables_before = veracrypt_dm_tables()
        r = run(["--non-interactive", "-p", PASSWORD] + COMMON
                + [str(kernel), str(work / "kernel")])
        c.check("mount kernel.hc with kernel cryptography", r.returncode == 0,
                text(r))
        r = run(["--non-interactive", "-p", PASSWORD] + COMMON
                + ["--mount-options=nokernelcrypto", str(fuse),
                   str(work / "fuse")])
        c.check("mount fuse.hc without kernel cryptography", r.returncode == 0,
                text(r))
        tables = [t for t in veracrypt_dm_tables() if t not in tables_before]
        c.check("kernel.hc has device-mapper devices", len(tables) > 0,
                "\n".join(veracrypt_dm_tables()))
        if c.failures:
            sys.exit("Cannot mount the test volumes")
        dm_names = [t.split(":")[0] for t in tables]

        for name in ("kernel", "fuse"):
            fd = os.open(str(work / name / "open.txt"),
                         os.O_RDWR | os.O_CREAT, 0o600)
            open_fds[name] = fd
            os.write(fd, b"data")
            os.fsync(fd)

        gui_log = open(str(work / "gui.log"), "wb")
        gui = subprocess.Popen(["xvfb-run", "-a", args.veracrypt],
                               cwd=work, env=env, stdout=gui_log,
                               stderr=subprocess.STDOUT,
                               start_new_session=True)
        listening = wait_for(lambda: listens_to_uevents(gui.pid), 180)
        detail = ""
        if not listening:
            detail = "GUI %s; output:\n%s" % (
                "running" if gui.poll() is None else "exited with %s" % gui.returncode,
                (work / "gui.log").read_text(errors="replace")[-3000:])
        c.check("the GUI listens to kernel device events", listening, detail)
        if c.failures:
            sys.exit("The GUI does not monitor devices")

        # Devices connected when the GUI started, reported again by the kernel
        for device in Path("/sys/bus/usb/devices").iterdir():
            if (device / "idVendor").exists():
                try:
                    (device / "uevent").write_text("add")
                except OSError:
                    pass
        time.sleep(5)
        volumes = mounted()
        c.check("a device connected before the GUI started does not unmount",
                str(kernel) in volumes and str(fuse) in volumes, str(volumes))

        if args.connect_command:
            c.check("connect a new device", subprocess.run(
                args.connect_command, shell=True).returncode == 0)
        else:
            # g_zero binds to the dummy UDC: a new device on the dummy host bus
            c.check("load g_zero", modprobe("g_zero"))
        c.check("#1982: a new USB device unmounts all volumes",
                wait_for(lambda: not ({str(kernel), str(fuse)}
                                      & set(mounted())), 60), str(mounted()))

        # The data must be read from the device, not from the page cache
        Path("/proc/sys/vm/drop_caches").write_text("3")
        for name, fd in open_fds.items():
            try:
                os.pread(fd, 4, 0)
                read_error = 0
            except OSError as e:
                read_error = e.errno
            c.check("#1982: the file open on %s.hc fails with an I/O error"
                    % name, read_error == errno.EIO, "errno %d" % read_error)

        left = [t for t in veracrypt_dm_tables()
                if t.split(":")[0] in dm_names]
        c.check("#1982: the device-mapper devices are removed or hold no key",
                all(" error" in t and " crypt " not in t for t in left),
                "\n".join(left))

        aux = aux_mounts()
        c.check("#1982: no auxiliary mount remains", not aux, "".join(aux))
        executable = os.path.realpath(shutil.which(args.veracrypt) or args.veracrypt)
        c.check("#1982: no FUSE service remains",
                wait_for(lambda: not fuse_holders(executable), 30),
                str(fuse_holders(executable)))
    finally:
        for fd in open_fds.values():
            os.close(fd)
        if gui is not None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(gui.pid, sig)
                    gui.wait(timeout=30)
                    break
                except (OSError, subprocess.TimeoutExpired):
                    continue
        if not args.connect_command:
            modprobe("-r", "g_zero")
        try:
            cleaned = dismount([fuse, kernel])
        except Exception as e:
            print("Cannot list the mounted volumes: %s" % e)
            cleaned = False
        if cleaned:
            if not args.connect_command:
                modprobe("-r", "dummy_hcd")
            shutil.rmtree(work, ignore_errors=True)
        else:
            # Reported after the original error, if any
            print("A test volume is still mounted; not removing %s" % work)
            c.failures += 1

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
