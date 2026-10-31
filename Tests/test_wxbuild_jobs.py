#!/usr/bin/env python3
"""Check wxbuild job sharing and OpenWrt's serial fallback.

Run with python3 Tests/test_wxbuild_jobs.py [--make /path/to/gmake].
Requires Python 3 and GNU make on a POSIX host. No compiler, wxWidgets sources
or OpenWrt SDK are needed. The production wxbuild section and OpenWrt recipe
run in temporary fixtures with a small replacement for the wx library build.
"""

import argparse
import fcntl
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
OPENWRT_RECIPE = ROOT / "src/Build/Packaging/openwrt/package/utils/veracrypt/Makefile.in"
JOBS = 8


def wait_for(path):
    deadline = time.monotonic() + 10
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("Timed out waiting for " + str(path))
        time.sleep(0.01)


def worker(root, kind):
    if kind == "wait":
        wait_for(root / "sibling-ready")
        return

    with (root / "events").open("a") as events:
        fcntl.flock(events, fcntl.LOCK_EX)
        first = kind == "wx" and not (root / "wx-started").exists()
        if first:
            (root / "wx-started").touch()
        events.write("start " + kind + "\n")
    try:
        if kind == "sibling":
            (root / "sibling-ready").touch()
            # Occupy a parent slot until the first wx job finishes. The
            # remaining wx jobs must then be able to use that released slot.
            wait_for(root / "first-wx-finished")
        else:
            time.sleep(0.3 if first else 0.2)
    finally:
        with (root / "events").open("a") as events:
            fcntl.flock(events, fcntl.LOCK_EX)
            events.write("finish " + kind + "\n")
        if first:
            (root / "first-wx-finished").touch()


class WxBuildJobsTests(unittest.TestCase):
    make = "make"

    @classmethod
    def setUpClass(cls):
        executable = shutil.which(cls.make)
        if executable is None:
            raise RuntimeError("GNU make not found: " + cls.make)
        cls.make = str(Path(executable).resolve())
        version = subprocess.run([cls.make, "--version"], check=True,
                                 capture_output=True, text=True, timeout=10)
        if "GNU Make" not in version.stdout:
            raise RuntimeError("Use --make to select GNU make")

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vc-wx-jobs-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        source = (ROOT / "src/Makefile").read_text(encoding="utf-8")
        wx_section = source.split("#------ wxWidgets build ------", 1)[1]
        self.write("pkg/veracrypt/src/Makefile",
                   ".PHONY: all clean wxbuild\nall clean:\n\t@:\n" + wx_section)
        jobs = " ".join("job%d" % i for i in range(JOBS))
        self.write("pkg/wxWidgets/Makefile",
                   ".PHONY: all " + jobs + "\nall: " + jobs + "\n"
                   + jobs + ":\n\t@$(VC_TEST_WORKER) wx\n")
        configure = self.write("pkg/wxWidgets/configure",
                               '#!/bin/sh\nset -eu\ncp "$(dirname "$0")/Makefile" Makefile\n')
        configure.chmod(0o755)

        self.write("openwrt/rules.mk", "INCLUDE_DIR := $(TOPDIR)/include\n")
        # Model the job settings from OpenWrt include/package.mk. A package
        # that supports parallel builds still has empty PKG_JOBS when the
        # parent is serial.
        self.write("openwrt/include/package.mk", """
MAKE_J := $(if $(MAKE_JOBSERVER),$(MAKE_JOBSERVER) $(if $(filter 3.% 4.0 4.1,$(MAKE_VERSION)),-j))
PKG_JOBS ?= $(if $(PKG_BUILD_PARALLEL),$(MAKE_J),-j1)
override MAKEFLAGS=
define BuildPackage
.PHONY: all
all:
$(Build/Compile)
endef
""")

    def check_jobs(self, openwrt, serial=False):
        if openwrt:
            arguments = ["-f", str(OPENWRT_RECIPE),
                         "TOPDIR=" + str(self.root / "openwrt"),
                         "PKG_BUILD_DIR=" + str(self.root / "pkg")]
        else:
            arguments = ["-C", str(self.root / "pkg/veracrypt/src"), "wxbuild",
                         "WX_ROOT=" + str(self.root / "pkg/wxWidgets"),
                         "WX_BUILD_DIR=" + str(self.root / "pkg/wxBuildConsole")]
        siblings = "" if serial else "sibling "
        wait = "" if serial else "\t@$(VC_TEST_WORKER) wait\n"
        self.write("parent.mk",
                   "export MAKE_JOBSERVER=$(filter --jobserver%,$(MAKEFLAGS))\n"
                   ".PHONY: all wx sibling\nall: " + siblings + "wx\nwx:\n" + wait
                   + "\t+$(MAKE) " + " ".join(map(shlex.quote, arguments)) + "\n"
                   "sibling:\n\t@$(VC_TEST_WORKER) sibling\n")
        env = {k: v for k, v in os.environ.items() if k not in (
            "MAKE", "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "MAKEFILES",
            "GNUMAKEFLAGS", "MAKE_JOBSERVER", "PKG_JOBS", "WX_MAKE_JOBS", "WX_MAKE_OPTS")}
        env["VC_TEST_WORKER"] = " ".join(map(shlex.quote, [
            sys.executable, str(Path(__file__).resolve()), "--worker", str(self.root)]))
        command = [self.make, "-s", "-j1" if serial else "-j2", "-f", "parent.mk"]
        with subprocess.Popen(command, cwd=self.root, env=env, start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            try:
                output, _ = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
                self.fail("make timed out:\n" + output)
        self.assertEqual(process.returncode, 0, output)

        active = {"wx": 0, "sibling": 0}
        peak = wx_peak = started = 0
        for line in (self.root / "events").read_text(encoding="utf-8").splitlines():
            event, kind = line.split()
            active[kind] += 1 if event == "start" else -1
            started += event == "start" and kind == "wx"
            peak = max(peak, sum(active.values()))
            wx_peak = max(wx_peak, active["wx"])
        self.assertEqual(active, {"wx": 0, "sibling": 0}, output)
        self.assertEqual(started, JOBS, output)
        self.assertEqual(peak, 1 if serial else 2, "Combined job count:\n" + output)
        # A child that lost the jobserver and fell back to -j1 must fail too.
        self.assertEqual(wx_peak, 1 if serial else 2, "wx job count:\n" + output)

    def test_recursive_build_shares_parent_slots(self):
        self.check_jobs(openwrt=False)

    def test_openwrt_build_shares_parent_slots(self):
        self.check_jobs(openwrt=True)

    def test_openwrt_empty_pkg_jobs_stays_serial(self):
        self.check_jobs(openwrt=True, serial=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(Path(sys.argv[2]), sys.argv[3])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--make", default="make", help="GNU make executable")
        args, remaining = parser.parse_known_args()
        WxBuildJobsTests.make = args.make
        unittest.main(argv=[sys.argv[0]] + remaining, verbosity=2)
