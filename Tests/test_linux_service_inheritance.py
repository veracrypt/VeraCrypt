#!/usr/bin/env python3
"""Check that the UI's core-service pipes do not survive exec.

Run against a built GUI or console binary with --veracrypt. No root or mounted
volumes are needed. A temporary token module launches this script after the UI
has started its core service. The child compares its inherited pipes with the
UI's pipes through /proc. VeraCrypt then rejects the incomplete token module.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SUCCESS = "PASS: core-service pipes are closed on exec"
MODULE = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((constructor)) static void RunProbe(void)
{
    char parent[32];
    snprintf(parent, sizeof(parent), "%ld", (long)getpid());
    pid_t child = fork();
    if (child == -1)
        return;
    if (child == 0)
    {
        const char *python = getenv("VERACRYPT_FD_TEST_PYTHON");
        execl(python, python, getenv("VERACRYPT_FD_TEST_SCRIPT"),
              "--probe", parent, (char *)NULL);
        _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) == -1 && errno == EINTR) { }
}
'''


def pipes(pid):
    result = set()
    for path in Path(f"/proc/{pid}/fd").iterdir():
        if int(path.name) <= 2:
            continue
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target.startswith("pipe:["):
            result.add(target)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--veracrypt", type=Path, default=ROOT / "src/Main/veracrypt")
    parser.add_argument("--probe", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this test requires Linux /proc")

    if args.probe is not None:
        service_pipes = pipes(args.probe)
        if len(service_pipes) != 2:
            raise AssertionError(f"Expected two UI service pipes, found {service_pipes}")
        inherited = service_pipes & pipes(os.getpid())
        if inherited:
            raise AssertionError(f"Child inherited core-service pipes: {inherited}")
        print(SUCCESS)
        return

    with tempfile.TemporaryDirectory(prefix="vc-service-fds-") as directory:
        source = Path(directory) / "probe.c"
        module = Path(directory) / "probe.so"
        source.write_text(MODULE)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(compiler + ["-Wall", "-Wextra", "-shared", "-fPIC",
                                   str(source), "-o", str(module)], check=True)
        env = dict(os.environ, VERACRYPT_FD_TEST_PYTHON=sys.executable,
                   VERACRYPT_FD_TEST_SCRIPT=str(Path(__file__).resolve()))
        result = subprocess.run(
            [str(args.veracrypt.resolve()), "--text", "--non-interactive",
             "--list", "--token-lib=" + str(module)],
            env=env, capture_output=True, text=True, timeout=15)
        if result.returncode != 1 or SUCCESS not in result.stdout.splitlines():
            raise AssertionError(f"Service descriptor check failed (exit {result.returncode}):\n"
                                 + result.stdout + result.stderr)
    print(SUCCESS)


if __name__ == "__main__":
    main()
