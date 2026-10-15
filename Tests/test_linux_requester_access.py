#!/usr/bin/env python3
"""Check that Linux mounts volume files that only the requesting user can open.

Usage:
  sudo python3 Tests/test_linux_requester_access.py --binary /path/to/veracrypt --user NAME [CHECK...]

Requires root, a C compiler, the libfuse3 development files and fusermount3.
NAME is an unprivileged account that may mount FUSE file systems. As NAME, the
test mounts Tests/linux_user_fuse_fixture.c without allow_other, so root is
denied, as with a GVfs share, and creates the containers without elevation.
VeraCrypt then runs as root with the SUDO_UID and SUDO_GID of NAME, as
'sudo veracrypt --text' does. The checks cover:

  - writable mounting through the FUSE volume image: the requester opens the
    file once, root does the I/O, one process holds the descriptor with
    close-on-exec, timestamps are restored once by the requester, and the data
    survives a remount; the warning is printed on stderr,
  - explicit read-only mounting, and the read-only fallback when the server
    denies writing or cannot open the file for writing in place,
  - missing, invalid, partial and root attribution keep the original error,
  - wrong passwords, special files, mount options, several mounts from one
    service, hidden volume protection,
  - a slow open() or timestamp change is waited for; the helper waiting in
    open() runs with the requester's IDs, groups and no capabilities, and
    holds only its socket besides /dev/null on descriptors 0-2.

Disposable volumes are used, and every unmount targets a test volume. The
artifacts are kept in a private temporary directory.
"""

import argparse
import hashlib
import os
import pwd
import re
import subprocess
import sys
import tempfile
import threading
import time

PASSWORD = "Disposable-requester-test-1"
HIDDEN_PASSWORD = "Disposable-requester-hidden-2"
WARNING = "opened the file with your user account's access rights"


class Checks:
    def __init__(self, args):
        self.binary = os.path.realpath(args.binary)
        self.user = pwd.getpwnam(args.user)
        self.slot = args.slot
        self.root = tempfile.mkdtemp(prefix="vc-requester-test-")
        os.chmod(self.root, 0o755)
        self.dirs = {}
        for name in ("backing", "control", "fuse", "home", "roothome", "volmnt"):
            path = os.path.join(self.root, name)
            os.mkdir(path)
            self.dirs[name] = path
        for name in ("backing", "control", "fuse", "home"):
            os.chown(self.dirs[name], self.user.pw_uid, self.user.pw_gid)
        self.failures = []
        self.mounted_volumes = []
        self.fuse_mounted = False
        print("Artifacts:", self.root, flush=True)

    # -- helpers ---------------------------------------------------------------
    def run(self, label, args, env=None, user=False, timeout=180, input=None):
        command = list(map(str, args))
        if user:
            command = ["runuser", "-u", self.user.pw_name, "--", "env", "HOME=" + self.dirs["home"]] + command
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, input=input)
        result.seconds = time.monotonic() - started
        with open(os.path.join(self.root, label + ".log"), "w") as log:
            log.write(" ".join(command) + "\n" + result.stdout + result.stderr + "\nrc=%d\n" % result.returncode)
        return result

    def env(self, attributed=True, **overrides):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": self.dirs["roothome"], "LANG": "C.UTF-8"}
        if attributed:
            env.update(SUDO_UID=str(self.user.pw_uid), SUDO_GID=str(self.user.pw_gid), SUDO_USER=self.user.pw_name)
        env.update(overrides)
        return {k: v for k, v in env.items() if v is not None}

    def vc(self, label, *args, env=None, timeout=180):
        return self.run(label, [self.binary, "--text", "--non-interactive", *args], env=env or self.env(), timeout=timeout)

    def expect(self, label, passed, detail=""):
        print(("PASS " if passed else "FAIL ") + label + (": " + detail if detail else ""), flush=True)
        if not passed:
            self.failures.append(label)
        return passed

    def path(self, name):
        return os.path.join(self.dirs["fuse"], name)

    def knob(self, name, enabled):
        path = os.path.join(self.dirs["control"], name)
        if enabled:
            open(path, "w").close()
        elif os.path.exists(path):
            os.unlink(path)

    def fixture_log(self):
        path = os.path.join(self.dirs["control"], "log")
        return open(path).read().splitlines() if os.path.exists(path) else []

    def clear_log(self):
        path = os.path.join(self.dirs["control"], "log")
        if os.path.exists(path):
            os.unlink(path)

    def backing_times(self, name):
        st = os.stat(os.path.join(self.dirs["backing"], name))
        return int(st.st_atime), int(st.st_mtime)

    def set_backing_times(self, name, atime, mtime):
        os.utime(os.path.join(self.dirs["backing"], name), (atime, mtime))

    def listed(self):
        result = self.vc("list", "--list", "--verbose")
        return result.stdout

    def mount(self, label, volume, *extra, env=None, expect_rc=0, timeout=180, password=PASSWORD):
        mountpoint = os.path.join(self.dirs["volmnt"], label)
        os.makedirs(mountpoint, exist_ok=True)
        result = self.vc(label, "--mount", volume, mountpoint, "--slot=%d" % self.slot, "--password=" + password,
                         "--pim=0", "--keyfiles=", *extra, env=env, timeout=timeout)
        if result.returncode == 0:
            self.mounted_volumes.append(volume)
        if expect_rc is not None:
            self.expect(label + " exit code", result.returncode == expect_rc,
                        "rc=%d %s" % (result.returncode, (result.stdout + result.stderr).strip()[-300:]))
        return result, mountpoint

    def unmount(self, label, volume, env=None, check=True):
        result = self.vc(label, "--unmount", volume, env=env)
        if check:
            self.expect(label + " exit code", result.returncode == 0, (result.stdout + result.stderr).strip()[-200:])
        elif result.returncode != 0:
            # Cleanup only: a volume left mounted keeps the fixture busy.
            result = self.vc(label + "-force", "--force", "--unmount", volume, env=env)
        if result.returncode == 0 and volume in self.mounted_volumes:
            self.mounted_volumes.remove(volume)
        return result

    def create(self, name, size="20M", extra=()):
        result = self.run("create-" + name, [self.binary, "--text", "--non-interactive", "--create", self.path(name),
                                             "--size=" + size, "--volume-type=normal", "--encryption=AES", "--hash=SHA-512",
                                             "--filesystem=FAT", "--password=" + PASSWORD, "--pim=0", "--keyfiles=",
                                             "--random-source=/dev/urandom", *extra], user=True)
        if result.returncode != 0:
            raise AssertionError("cannot create %s: %s" % (name, result.stdout + result.stderr))

    def leftover_processes(self):
        found = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                status = open("/proc/%s/status" % pid).read()
                name = status.split("Name:")[1].split()[0]
                state = status.split("State:")[1].split()[0]
                try:
                    exe = os.readlink("/proc/%s/exe" % pid)
                except OSError:
                    exe = ""
                if exe == self.binary or (state == "Z" and name.startswith("veracrypt")):
                    found.append((int(pid), name, state, exe))
            except (OSError, IndexError):
                pass
        return found

    def wait_no_processes(self, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not self.leftover_processes():
                return True
            time.sleep(0.2)
        return False

    # -- setup -----------------------------------------------------------------
    def setup(self):
        source = os.path.join(os.path.dirname(os.path.realpath(__file__)), "linux_user_fuse_fixture.c")
        self.fixture = os.path.join(self.root, "userfs")
        flags = subprocess.run(["pkg-config", "--cflags", "--libs", "fuse3"], capture_output=True, text=True, check=True).stdout.split()
        subprocess.run(["cc", "-O2", "-Wall", "-o", self.fixture, source, *flags], check=True)
        env_args = ["USERFS_BACKING=" + self.dirs["backing"], "USERFS_CONTROL=" + self.dirs["control"]]
        result = self.run("fixture-mount", ["env", *env_args, self.fixture, self.dirs["fuse"]], user=True)
        if result.returncode != 0:
            raise AssertionError("cannot mount fixture: " + result.stdout + result.stderr)
        self.fuse_mounted = True
        for _ in range(50):
            # Root cannot stat the mount point, so consult the mount table.
            if any(line.split()[4] == self.dirs["fuse"] for line in open("/proc/self/mountinfo")):
                break
            time.sleep(0.1)
        try:
            os.open(os.path.join(self.dirs["fuse"], "."), os.O_RDONLY)
            raise AssertionError("root can access the fixture; it must be user-only")
        except PermissionError:
            pass
        self.create("vol.hc")

    def cleanup(self):
        for volume in list(self.mounted_volumes):
            try:
                self.unmount("cleanup", volume, check=False)
            except Exception as e:
                print("cleanup:", e)
        self.expect("cleanup unmounted all volumes", not self.mounted_volumes, str(self.mounted_volumes))
        for knob in ("hang_open", "enotsup_rw", "eacces_rw", "hang_utimens"):
            self.knob(knob, False)
        if self.fuse_mounted:
            # The FUSE service of the last volume may still be closing its file.
            self.wait_no_processes()
            result = self.run("fixture-unmount", ["fusermount3", "-u", self.dirs["fuse"]], user=True)
            self.expect("fixture unmounted", result.returncode == 0, (result.stdout + result.stderr).strip())

    # -- checks ----------------------------------------------------------------
    def check_writable_mount(self):
        self.set_backing_times("vol.hc", 1500000000, 1500000100)
        self.clear_log()
        result, mountpoint = self.mount("rw", self.path("vol.hc"), "--protect-hidden=no")
        self.expect("rw warning on stderr", WARNING in result.stderr, result.stderr.strip()[:200])
        listing = self.listed()
        self.expect("rw listed writable", "Read-Only: No" in listing, listing.strip()[:300])
        self.expect("rw uses FUSE path", re.search(r"Virtual Device: /dev/loop\d+", listing) is not None)

        # Descriptor ownership and close-on-exec in the service processes.
        holders = self.descriptor_holders(self.path("vol.hc"))
        self.expect("rw descriptor held by one service with O_CLOEXEC",
                    len(holders) == 1 and all(cloexec for _, cloexec in holders), str(holders))

        data = os.urandom(3 * 1024 * 1024)
        with open(os.path.join(mountpoint, "data.bin"), "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        log = self.fixture_log()
        opens = [l for l in log if l.startswith("open ") and "/vol.hc" in l]
        self.expect("rw opened once by requester read/write",
                    len(opens) == 1 and "uid=%d" % self.user.pw_uid in opens[0] and int(opens[0].split("flags=")[1].split()[0], 8) & 3 == 2,
                    str(opens))
        self.expect("rw I/O performed by root", any(l.startswith("write uid=0") for l in log), str([l for l in log if l.startswith("write")]))
        self.unmount("rw-unmount", self.path("vol.hc"))
        time.sleep(0.5)
        times = self.backing_times("vol.hc")
        self.expect("rw timestamps restored", times == (1500000000, 1500000100), str(times))
        utimens = [l for l in self.fixture_log() if l.startswith("utimens ")]
        self.expect("rw timestamps restored once, by requester",
                    len(utimens) == 1 and "uid=%d" % self.user.pw_uid in utimens[0], str(utimens))
        self.expect("rw no leftover processes", self.wait_no_processes(), str(self.leftover_processes()))

        # Data must be intact on a fresh mount.
        result, mountpoint = self.mount("verify", self.path("vol.hc"), "--protect-hidden=no", "--mount-options=ro")
        try:
            with open(os.path.join(mountpoint, "data.bin"), "rb") as f:
                same = hashlib.sha256(f.read()).digest() == hashlib.sha256(data).digest()
        except OSError as e:
            same = False
        self.expect("data intact after remount", same)
        self.unmount("verify-unmount", self.path("vol.hc"))

    def descriptor_holders(self, path):
        holders = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                for fd in os.listdir("/proc/%s/fd" % pid):
                    try:
                        if os.readlink("/proc/%s/fd/%s" % (pid, fd)) == path:
                            flags = int(open("/proc/%s/fdinfo/%s" % (pid, fd)).read().split("flags:")[1].split()[0], 8)
                            holders.append((int(pid), bool(flags & 0o2000000)))
                    except OSError:
                        pass
            except OSError:
                pass
        return holders

    def check_read_only_modes(self):
        self.clear_log()
        result, _ = self.mount("ro-explicit", self.path("vol.hc"), "--protect-hidden=no", "--mount-options=ro")
        listing = self.listed()
        self.expect("explicit ro listed read-only", "Read-Only: Yes" in listing)
        opens = [l for l in self.fixture_log() if l.startswith("open ") and "/vol.hc" in l]
        self.expect("explicit ro opens read-only only", opens and all(int(l.split("flags=")[1].split()[0], 8) & 3 == 0 for l in opens), str(opens))
        self.unmount("ro-explicit-unmount", self.path("vol.hc"))

        for knob, label in (("eacces_rw", "server-denies-write"), ("enotsup_rw", "no-in-place-edit")):
            self.knob(knob, True)
            try:
                result, _ = self.mount(label, self.path("vol.hc"), "--protect-hidden=no")
                listing = self.listed()
                self.expect(label + " falls back to read-only", "Read-Only: Yes" in listing, listing.strip()[:200])
                self.unmount(label + "-unmount", self.path("vol.hc"))
            finally:
                self.knob(knob, False)

    def check_attribution(self):
        cases = [
            ("no-attribution", self.env(attributed=False)),
            ("root-attribution", self.env(SUDO_UID="0", SUDO_GID="0")),
            ("invalid-attribution", self.env(SUDO_UID="%dx" % self.user.pw_uid)),
            ("partial-attribution", self.env(SUDO_GID=None)),
            ("out-of-range-attribution", self.env(SUDO_UID="4294967295")),
        ]
        for label, env in cases:
            result, _ = self.mount(label, self.path("vol.hc"), "--protect-hidden=no", env=env, expect_rc=None)
            output = result.stdout + result.stderr
            self.expect(label + " keeps permission denied", result.returncode != 0 and "Permission denied" in output, output.strip()[-200:])
            if result.returncode == 0:
                self.unmount(label + "-unmount", self.path("vol.hc"))

    def check_wrong_password(self):
        self.set_backing_times("vol.hc", 1500000000, 1500000100)
        self.clear_log()
        mountpoint = os.path.join(self.dirs["volmnt"], "wrong")
        os.makedirs(mountpoint, exist_ok=True)
        result = self.vc("wrong-password", "--mount", self.path("vol.hc"), mountpoint, "--slot=%d" % self.slot,
                         "--password=wrong", "--pim=0", "--keyfiles=", "--protect-hidden=no")
        output = result.stdout + result.stderr
        self.expect("wrong password reported", result.returncode != 0 and "Incorrect password" in output, output.strip()[-200:])
        self.expect("wrong password timestamps", self.backing_times("vol.hc") == (1500000000, 1500000100))
        self.expect("wrong password no leftover processes", self.wait_no_processes(), str(self.leftover_processes()))

    def check_special_files(self):
        fifo = os.path.join(self.dirs["fuse"], "fifo.hc")
        self.run("mkfifo", ["mkfifo", fifo], user=True)
        result, _ = self.mount("fifo", fifo, "--protect-hidden=no", expect_rc=None, timeout=60)
        output = result.stdout + result.stderr
        self.expect("fifo rejected promptly", result.returncode != 0 and result.seconds < 30 and "Invalid argument" in output,
                    "%.1fs %s" % (result.seconds, output.strip()[-200:]))
        directory = os.path.join(self.dirs["fuse"], "dir.hc")
        self.run("mkdir", ["mkdir", directory], user=True)
        result, _ = self.mount("directory", directory, "--protect-hidden=no", "--mount-options=ro", expect_rc=None)
        output = result.stdout + result.stderr
        self.expect("directory rejected", result.returncode != 0 and "Is a directory" in output, output.strip()[-200:])

    def check_hidden_protection(self):
        result = self.run("create-hidden", [self.binary, "--text", "--non-interactive", "--create", self.path("vol.hc"),
                                            "--size=5M", "--volume-type=hidden", "--encryption=AES", "--hash=SHA-512",
                                            "--filesystem=FAT", "--password=" + HIDDEN_PASSWORD, "--pim=0", "--keyfiles=",
                                            "--random-source=/dev/urandom"], user=True)
        if not self.expect("hidden volume created by user", result.returncode == 0, (result.stdout + result.stderr).strip()[-200:]):
            return
        hidden_data = os.urandom(1024 * 1024)
        result, mountpoint = self.mount("hidden-write", self.path("vol.hc"), "--protect-hidden=no", password=HIDDEN_PASSWORD)
        if result.returncode != 0:
            return
        with open(os.path.join(mountpoint, "hidden.bin"), "wb") as f:
            f.write(hidden_data)
            f.flush()
            os.fsync(f.fileno())
        self.unmount("hidden-write-unmount", self.path("vol.hc"))

        result, mountpoint = self.mount("protected", self.path("vol.hc"), "--protect-hidden=yes",
                                        "--protection-password=" + HIDDEN_PASSWORD, "--protection-pim=0", "--protection-keyfiles=")
        if result.returncode != 0:
            return
        listing = self.listed()
        self.expect("outer mounted with hidden protection", "Hidden Volume Protected: Yes\n" in listing, listing.strip()[:300])
        # Fill the outer volume until a write reaches the hidden volume and is refused.
        try:
            with open(os.path.join(mountpoint, "fill.bin"), "wb") as f:
                for _ in range(40):
                    f.write(os.urandom(1024 * 1024))
                    f.flush()
                    os.fsync(f.fileno())
        except OSError:
            pass
        subprocess.run(["sync"])
        listing = self.listed()
        self.expect("outer writes refused by hidden protection", "Hidden Volume Protected: Yes (damage prevented!)" in listing,
                    listing.strip()[:300])
        self.unmount("protected-unmount", self.path("vol.hc"))

        result, mountpoint = self.mount("hidden-verify", self.path("vol.hc"), "--protect-hidden=no", "--mount-options=ro",
                                        password=HIDDEN_PASSWORD)
        if result.returncode != 0:
            return
        try:
            with open(os.path.join(mountpoint, "hidden.bin"), "rb") as f:
                same = f.read() == hidden_data
        except OSError:
            same = False
        self.expect("hidden volume data intact after protected writes", same)
        self.unmount("hidden-verify-unmount", self.path("vol.hc"))

    def waiting_helper(self, seconds=10):
        # Status fields and descriptors of the requester helper, found by its user.
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for pid in filter(str.isdigit, os.listdir("/proc")):
                try:
                    if os.readlink("/proc/%s/exe" % pid) != self.binary:
                        continue
                    status = dict(line.split(":", 1) for line in open("/proc/%s/status" % pid).read().splitlines())
                    if status["Uid"].split()[0] != str(self.user.pw_uid):
                        continue
                    fds = {int(fd): os.readlink("/proc/%s/fd/%s" % (pid, fd)) for fd in os.listdir("/proc/%s/fd" % pid)}
                    return {k: v.strip() for k, v in status.items()}, fds
                except (OSError, KeyError):
                    pass
            time.sleep(0.1)
        return None, None

    def check_slow_open(self):
        # VeraCrypt waits for the server to answer, here for 12 s.
        self.knob("hang_open", True)
        outcome = {}
        thread = threading.Thread(target=lambda: outcome.update(
            result=self.mount("slow-open", self.path("vol.hc"), "--protect-hidden=no", expect_rc=None, timeout=120)[0]))
        thread.start()
        try:
            status, fds = self.waiting_helper()
            uid, gid = str(self.user.pw_uid), str(self.user.pw_gid)
            groups = set(map(str, os.getgrouplist(self.user.pw_name, self.user.pw_gid)))
            self.expect("helper credentials", status is not None and status["Uid"].split() == [uid] * 4
                        and status["Gid"].split() == [gid] * 4 and set(status["Groups"].split()) == groups
                        and int(status["CapPrm"], 16) == 0 and int(status["CapEff"], 16) == 0 and status["Name"] == "veracrypt",
                        str(status and {k: status[k] for k in ("Name", "Uid", "Gid", "Groups", "CapPrm", "CapEff")}))
            self.expect("helper descriptors", fds is not None and all(fds.get(fd) == "/dev/null" for fd in (0, 1, 2))
                        and len(fds) == 4 and sum(target.startswith("socket:") for target in fds.values()) == 1, str(fds))
            time.sleep(12)
        finally:
            self.knob("hang_open", False)
            thread.join()
        result = outcome.get("result")
        self.expect("slow open succeeds", result is not None and result.returncode == 0 and result.seconds >= 12,
                    result and "rc=%d %.1fs %s" % (result.returncode, result.seconds, (result.stdout + result.stderr).strip()[-200:]))
        if result is not None and result.returncode == 0:
            self.unmount("slow-open-unmount", self.path("vol.hc"))
        self.expect("slow open no leftover processes", self.wait_no_processes(), str(self.leftover_processes()))

    def check_slow_timestamps(self):
        # Restoring the timestamps also waits for the server, then completes.
        self.mount("slow-utimens", self.path("vol.hc"), "--protect-hidden=no")
        self.clear_log()
        self.knob("hang_utimens", True)
        timer = threading.Timer(5, self.knob, ("hang_utimens", False))
        timer.start()
        try:
            self.unmount("slow-utimens-unmount", self.path("vol.hc"))
        finally:
            timer.join()
        self.expect("slow restoration no leftover processes", self.wait_no_processes(15), str(self.leftover_processes()))
        utimens = [l for l in self.fixture_log() if l.startswith("utimens ")]
        self.expect("slow restoration done once, by requester",
                    len(utimens) == 1 and "uid=%d" % self.user.pw_uid in utimens[0] and "result=0" in utimens[0], str(utimens))

    def check_mount_options(self):
        # Timestamp preservation disabled: no restoration helper.
        self.clear_log()
        self.mount("no-timestamps", self.path("vol.hc"), "--protect-hidden=no", "--mount-options=timestamp")
        self.unmount("no-timestamps-unmount", self.path("vol.hc"))
        utimens = [l for l in self.fixture_log() if l.startswith("utimens ")]
        self.expect("timestamp option skips restoration", not utimens, str(utimens))
        # Embedded backup header, read through the requester-backed descriptor.
        self.mount("backup-header", self.path("vol.hc"), "--protect-hidden=no", "--mount-options=headerbak,ro")
        self.expect("backup header mount listed", "Read-Only: Yes" in self.listed())
        self.unmount("backup-header-unmount", self.path("vol.hc"))

    def check_favorites(self):
        # Several mounts served by one core service process.
        self.create("vol2.hc")
        config = os.path.join(self.dirs["roothome"], ".config", "VeraCrypt")
        os.makedirs(config, exist_ok=True)
        entries = ""
        for index, name in enumerate(("vol.hc", "vol2.hc")):
            mountpoint = os.path.join(self.dirs["volmnt"], "fav%d" % index)
            os.makedirs(mountpoint, exist_ok=True)
            entries += '\t\t<volume mountpoint="%s" slotnumber="%d" readonly="0" system="0">%s</volume>\n' % (
                mountpoint, self.slot - 1 - index, self.path(name))
        with open(os.path.join(config, "Favorite Volumes.xml"), "w") as f:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n<VeraCrypt>\n\t<favorites>\n%s\t</favorites>\n</VeraCrypt>\n' % entries)
        result = self.vc("favorites", "--auto-mount=favorites", "--password=" + PASSWORD, "--pim=0", "--keyfiles=", "--protect-hidden=no")
        listing = self.listed()
        self.mounted_volumes += [self.path(name) for name in ("vol.hc", "vol2.hc") if "Volume: %s\n" % self.path(name) in listing]
        self.expect("favorites mounted by one service", result.returncode == 0 and result.stderr.count(WARNING) == 2
                    and listing.count("Read-Only: No") == 2, (result.stdout + result.stderr).strip()[-300:])
        for name in ("vol.hc", "vol2.hc"):
            self.unmount("favorite-unmount-" + name, self.path(name))
        os.unlink(os.path.join(config, "Favorite Volumes.xml"))
        self.expect("favorites no leftover processes", self.wait_no_processes(), str(self.leftover_processes()))

    def main(self, selected):
        try:
            self.setup()
            for name in selected:
                getattr(self, "check_" + name)()
        finally:
            self.cleanup()
        print("FAILURES:" if self.failures else "ALL PASSED", self.failures if self.failures else "", flush=True)
        return 1 if self.failures else 0


ALL = ["writable_mount", "read_only_modes", "attribution", "wrong_password", "special_files",
       "mount_options", "favorites", "slow_open", "slow_timestamps", "hidden_protection"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--user", required=True, help="unprivileged account that mounts the FUSE fixture")
    parser.add_argument("--slot", type=int, default=61)
    parser.add_argument("checks", nargs="*", default=ALL)
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root")
    sys.exit(Checks(args).main(args.checks))
