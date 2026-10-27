#!/usr/bin/env python3
"""Regression tests for issues #1958 to #1962, against the installed
veracrypt.

Usage (as root, after installing a package):
  python3 Tests/test_unix_security_regressions.py [--veracrypt PATH]
      [--rounds N]

Creates small volumes in a temporary directory and mounts them through FUSE
(nokernelcrypto), as in the reports. Checked:

- #1958: the FUSE service has locked memory and a core file size limit of
  zero;
- #1959: after an emergency dismount, while a file on the detached file
  system is still open, the volume cannot be mounted again; it can once the
  old service has exited;
- #1960: two volumes mounted at the same time each appear at their own
  mount point, and an existing /tmp/.veracrypt_aux_mnt1 does not prevent
  mounting;
- #1961: the hidden volume protection password is not in the memory of the
  FUSE service, apart from the copy in its command line ([stack]);
- #1962: --create-keyfile does not replace an existing keyfile in
  non-interactive mode unless --force is given, and --backup-headers asks
  before replacing an existing file.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASSWORD_A = "regression-test-password-a"
PASSWORD_B = "regression-test-password-b"
PASSWORD_OUTER = "regression-outer-password-c"
PASSWORD_HIDDEN = "regression-hidden-password-d"
# A low PIM keeps the tests fast; it needs passwords of 20 characters or more.
COMMON = ["--pim=1", "--keyfiles="]
MOUNT = COMMON + ["--protect-hidden=no", "--mount-options=nokernelcrypto"]


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


class VeraCrypt:
    def __init__(self, path, work):
        self.path = path
        self.binary = os.path.realpath(path)
        self.work = work

    def run(self, args, stdin=None, timeout=300):
        return subprocess.run([self.path, "--text"] + args, input=stdin,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, cwd=self.work,
                              timeout=timeout)

    def create(self, path, size, password, filesystem, volume_type="normal"):
        return self.run(["--non-interactive", "--create", str(path),
                         "--size=" + size, "--volume-type=" + volume_type,
                         "--encryption=AES", "--hash=SHA-512",
                         "--filesystem=" + filesystem, "-p", password,
                         "--random-source=" + str(self.work / "random")]
                        + COMMON)

    def mount(self, volume, password, mount_point=None, extra=()):
        args = ["--non-interactive", "-p", password] + MOUNT + list(extra)
        args.append(str(volume))
        if mount_point:
            args.append(str(mount_point))
        return self.run(args)

    def dismount(self, target=None):
        return self.run(["--non-interactive", "-d"]
                        + ([str(target)] if target else []))

    def service(self, volume):
        """PID of the FUSE service that has the volume file open."""
        volume = os.path.realpath(volume)
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                if os.readlink("/proc/%s/exe" % entry) != self.binary:
                    continue
                fds = ["/proc/%s/fd/%s" % (entry, fd)
                       for fd in os.listdir("/proc/%s/fd" % entry)]
                targets = {os.readlink(fd) for fd in fds}
            except OSError:
                continue
            if "/dev/fuse" in targets and volume in targets:
                return int(entry)
        return None


def process_status(pid, field):
    with open("/proc/%d/status" % pid) as status:
        for line in status:
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
    return ""


def core_limit(pid):
    with open("/proc/%d/limits" % pid) as limits:
        for line in limits:
            if line.startswith("Max core file size"):
                return line.split()[4:6]
    return []


def memory_hits(pid, needle):
    """Occurrences of needle per mapping name in the memory of pid."""
    hits = {}
    with open("/proc/%d/maps" % pid) as maps, \
            open("/proc/%d/mem" % pid, "rb", 0) as mem:
        for line in maps:
            fields = line.split()
            if not fields[1].startswith("r") or "[vvar" in line:
                continue
            start, end = (int(x, 16) for x in fields[0].split("-"))
            name = fields[5] if len(fields) > 5 else "anonymous"
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except (OSError, ValueError, OverflowError):
                continue
            count = data.count(needle)
            if count:
                hits[name] = hits.get(name, 0) + count
    return hits


def wait_for_exit(pid, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not os.path.exists("/proc/%d" % pid):
            return True
        time.sleep(0.5)
    return False


def test_memory(vc, c, volume, mount_point):
    r = vc.mount(volume, PASSWORD_A, mount_point)
    c.check("#1958: mount", r.returncode == 0, text(r))
    pid = vc.service(volume)
    c.check("#1958: find the FUSE service", pid is not None)
    if pid:
        locked = process_status(pid, "VmLck")
        c.check("#1958: the FUSE service has locked memory",
                locked.split()[:1] != ["0"], "VmLck: " + locked)
        limit = core_limit(pid)
        c.check("#1958: the FUSE service cannot write a core file",
                limit == ["0", "0"], "core file size limit: %s" % limit)
    vc.dismount(mount_point)


def test_detached_service(vc, c, volume, mount_point, second_mount_point):
    r = vc.mount(volume, PASSWORD_A, mount_point)
    c.check("#1959: mount", r.returncode == 0, text(r))
    pid = vc.service(volume)
    busy = open(mount_point / "busy", "w")
    try:
        r = vc.run(["--non-interactive", "-d", "--emergency-unmount",
                    str(mount_point)])
        c.check("#1959: emergency dismount", r.returncode == 0, text(r))
        c.check("#1959: the old service is still running",
                pid is not None and os.path.exists("/proc/%d" % pid))
        r = vc.mount(volume, PASSWORD_A, second_mount_point)
        c.check("#1959: mounting again while the old service runs fails",
                r.returncode != 0 and "already mounted" in text(r), text(r))
        if r.returncode == 0:
            vc.dismount(second_mount_point)
    finally:
        busy.close()
    c.check("#1959: the old service exits once the file is closed",
            pid is None or wait_for_exit(pid, 30))
    r = vc.mount(volume, PASSWORD_A, second_mount_point)
    c.check("#1959: mounting again after the old service exited works",
            r.returncode == 0, text(r))
    vc.dismount(second_mount_point)


def test_parallel_mounts(vc, c, volume_a, volume_b, mount_a, mount_b, rounds):
    failed = []
    for _ in range(rounds):
        jobs = [subprocess.Popen(
            [vc.path, "--text", "--non-interactive", "--slot=%d" % slot,
             "-p", password] + MOUNT + [str(volume), str(mount_point)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=vc.work)
            for slot, password, volume, mount_point in (
                (1, PASSWORD_A, volume_a, mount_a),
                (2, PASSWORD_B, volume_b, mount_b))]
        outputs = [job.communicate(timeout=300)[0] for job in jobs]
        for mount_point, marker, output in ((mount_a, "a", outputs[0]),
                                            (mount_b, "b", outputs[1])):
            try:
                found = (mount_point / "marker").read_text().strip()
            except OSError:
                found = None
            if found != marker:
                failed.append("%s holds %r: %s" % (
                    mount_point, found, output.decode("utf-8", "replace")))
        vc.dismount()
    c.check("#1960: %d rounds of two parallel mounts" % rounds, not failed,
            "\n".join(failed[:3]))

    foreign = Path("/tmp/.veracrypt_aux_mnt1")
    created = not foreign.exists()
    if created:
        foreign.mkdir(mode=0o755)
        (foreign / "file").write_text("x")
        os.chown(foreign, 65534, 65534)
    try:
        r = vc.mount(volume_a, PASSWORD_A, mount_a)
        c.check("#1960: an existing %s does not prevent mounting" % foreign,
                r.returncode == 0, text(r))
        vc.dismount(mount_a)
    finally:
        if created:
            shutil.rmtree(foreign, ignore_errors=True)


def test_protection_password(vc, c, work):
    volume = work / "hidden.hc"
    r = vc.create(volume, "10M", PASSWORD_OUTER, "none")
    c.check("#1961: create an outer volume", r.returncode == 0, text(r))
    r = vc.create(volume, "3M", PASSWORD_HIDDEN, "none", "hidden")
    c.check("#1961: create a hidden volume", r.returncode == 0, text(r))
    r = vc.run(["--non-interactive", "-p", PASSWORD_OUTER] + COMMON
               + ["--protect-hidden=yes",
                  "--protection-password=" + PASSWORD_HIDDEN,
                  "--protection-pim=1", "--protection-keyfiles=",
                  "--mount-options=nokernelcrypto", "--filesystem=none",
                  str(volume)])
    c.check("#1961: mount with hidden volume protection", r.returncode == 0,
            text(r))
    pid = vc.service(volume)
    c.check("#1961: find the FUSE service", pid is not None)
    if pid:
        hits = memory_hits(pid, PASSWORD_HIDDEN.encode())
        hits.pop("[stack]", None)
        c.check("#1961: the protection password is only in the command line",
                not hits, "found in %s" % hits)
    vc.dismount(volume)


def test_overwrite(vc, c, work):
    keyfile = work / "keyfile"
    r = vc.run(["--non-interactive", "--create-keyfile", str(keyfile),
                "--random-source=" + str(work / "random")])
    c.check("#1962: create a keyfile", r.returncode == 0, text(r))
    original = keyfile.read_bytes() if keyfile.exists() else b""
    r = vc.run(["--non-interactive", "--create-keyfile", str(keyfile),
                "--random-source=" + str(work / "random")])
    c.check("#1962: --create-keyfile refuses an existing keyfile",
            r.returncode != 0 and "already exists" in text(r), text(r))
    c.check("#1962: the existing keyfile is unchanged",
            keyfile.read_bytes() == original)
    r = vc.run(["--non-interactive", "--force", "--create-keyfile",
                str(keyfile), "--random-source=" + str(work / "random")])
    c.check("#1962: --force replaces the keyfile",
            r.returncode == 0 and keyfile.read_bytes() != original, text(r))

    volume = work / "backup.hc"
    r = vc.create(volume, "2M", PASSWORD_A, "none")
    c.check("#1962: create a volume", r.returncode == 0, text(r))
    target = work / "existing"
    for answer, replaced in (("n", False), ("y", True)):
        target.write_text("keep")
        # password, PIM, keyfiles, hidden volume, confirmation, file name,
        # overwrite
        answers = "%s\n1\n\nn\ny\n%s\n%s\n" % (PASSWORD_A, target, answer)
        r = vc.run(["--random-source=" + str(work / "random"),
                    "--backup-headers", str(volume)],
                   stdin=answers.encode())
        c.check("#1962: --backup-headers asks before replacing a file "
                "(answer %s)" % answer,
                "already exists" in text(r)
                and (target.read_text(errors="replace") != "keep") == replaced,
                text(r))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--veracrypt",
                        default=shutil.which("veracrypt") or "veracrypt")
    parser.add_argument("--rounds", type=int, default=20,
                        help="rounds of parallel mounts for #1960")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root: the tests mount volumes")

    work = Path(tempfile.mkdtemp(prefix="vc-regressions-"))
    vc = VeraCrypt(args.veracrypt, work)
    c = Checks()
    mount_points = [work / name for name in ("a", "b", "c")]
    for mount_point in mount_points:
        mount_point.mkdir()
    (work / "random").write_bytes(os.urandom(4096))
    try:
        volume_a, volume_b = work / "a.hc", work / "b.hc"
        for volume, password, marker in ((volume_a, PASSWORD_A, "a"),
                                         (volume_b, PASSWORD_B, "b")):
            r = vc.create(volume, "10M", password, "ext4")
            c.check("create %s" % volume.name, r.returncode == 0, text(r))
            r = vc.mount(volume, password, mount_points[0])
            if r.returncode == 0:
                (mount_points[0] / "marker").write_text(marker)
            vc.dismount(mount_points[0])
        if c.failures:
            sys.exit("Cannot create the test volumes")

        test_memory(vc, c, volume_a, mount_points[0])
        test_detached_service(vc, c, volume_a, mount_points[0],
                              mount_points[1])
        test_parallel_mounts(vc, c, volume_a, volume_b, mount_points[0],
                             mount_points[1], args.rounds)
        test_protection_password(vc, c, work)
        test_overwrite(vc, c, work)
    finally:
        vc.dismount()
        if any(os.path.ismount(m) for m in mount_points):
            sys.exit("A test volume is still mounted; not removing %s" % work)
        shutil.rmtree(work, ignore_errors=True)

    if c.failures:
        sys.exit("%d check(s) failed" % c.failures)
    print("All checks passed")


if __name__ == "__main__":
    main()
