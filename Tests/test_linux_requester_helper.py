#!/usr/bin/env python3
"""Check requester-helper self-exec and fail-closed startup using production code.

After a matching Linux build:
  sudo python3 Tests/test_linux_requester_helper.py --build-dir src --user NAME

Uses an ordinary disposable file, not encrypted volumes or secret material.
The harness links the matching Platform library and wraps execve/sendmsg only
in the test executable. It checks close_range, its older-kernel fallback, and
an AppImage-like dependency found only through LD_LIBRARY_PATH, and that the
helper refuses a socket whose peer is not root.
"""

import argparse
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <sys/resource.h>
#include <sys/syscall.h>
#ifdef TEST_NO_CLOSE_RANGE
#undef SYS_close_range
#endif
#include "Platform/Unix/RequesterAccess.cpp"
#include <stddef.h>
#include <stdio.h>
#include <sys/un.h>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace VeraCrypt;
static bool FreshHelper;
static int ExecError;
static bool ExitBeforeReady;
static int ParentOnlyMarker;
static const int InheritedFd = 70000;
#ifdef TEST_BUNDLED_LIBRARY
extern "C" int vc_requester_test_dependency ();
#endif

extern "C" int __real_execve (const char *, char *const [], char *const []);
extern "C" int __wrap_execve (const char *path, char *const argv[], char *const envp[])
{
    if (ExecError) { errno = ExecError; return -1; }
    if (ExitBeforeReady) _exit (127); // Simulate an early dynamic-loader exit.
    return __real_execve (path, argv, envp);
}

static bool OnDevNull (int fd)
{
    struct stat st, null;
    return fstat (fd, &st) == 0 && stat ("/dev/null", &null) == 0 && S_ISCHR (st.st_mode) && st.st_rdev == null.st_rdev;
}

extern "C" ssize_t __real_sendmsg (int, const struct msghdr *, int);
extern "C" ssize_t __wrap_sendmsg (int fd, const struct msghdr *message, int flags)
{
    // Only the credential-dropped helper sends replies. An ordinary fork cannot
    // pass this check: it retains the parent's marker and never re-enters main.
    if (geteuid() != 0 && (!FreshHelper || ParentOnlyMarker != 0
        || getenv ("VC_REQUESTER_TEST_ENV") || prctl (PR_GET_DUMPABLE, 0, 0, 0, 0) != 0
        || !OnDevNull (0) || !OnDevNull (1) || !OnDevNull (2)
        || fcntl (InheritedFd, F_GETFD) != -1 || errno != EBADF))
    {
        errno = EPERM;
        return -1;
    }
    return __real_sendmsg (fd, message, flags);
}

static void Require (bool condition, const char *message)
{
    if (!condition) throw std::runtime_error (message);
}

struct TestFile : File { using File::OpenAsRequester; };

// Only root may send requests. Here the requester listens on the socket, so the
// helper sees the requester as its peer and must exit without answering.
static void CheckNonRootPeer (uid_t userId, gid_t groupId)
{
    struct sockaddr_un address;
    memset (&address, 0, sizeof (address));
    address.sun_family = AF_UNIX;
    snprintf (address.sun_path + 1, sizeof (address.sun_path) - 1, "vc-requester-peer-%d", static_cast <int> (getpid()));
    socklen_t addressSize = offsetof (struct sockaddr_un, sun_path) + 1 + strlen (address.sun_path + 1);

    int ready[2];
    Require (pipe (ready) == 0, "pipe");
    pid_t listener = fork();
    Require (listener != -1, "fork listener");
    if (listener == 0)
    {
        close (ready[0]);
        int listening = -1;
        if (setgroups (1, &groupId) != 0 || setgid (groupId) != 0 || setuid (userId) != 0
            || (listening = socket (AF_UNIX, SOCK_SEQPACKET, 0)) == -1
            || bind (listening, reinterpret_cast <struct sockaddr *> (&address), addressSize) != 0
            || listen (listening, 1) != 0 || write (ready[1], "r", 1) != 1)
            _exit (2);
        int connection = accept (listening, nullptr, nullptr);
        char data;
        _exit (connection != -1 && recv (connection, &data, sizeof (data), 0) == 0 ? 0 : 1);
    }

    close (ready[1]);
    char data;
    bool listening = read (ready[0], &data, 1) == 1;
    close (ready[0]);
    int socketFd = listening ? socket (AF_UNIX, SOCK_SEQPACKET, 0) : -1;
    bool connected = socketFd != -1
        && connect (socketFd, reinterpret_cast <struct sockaddr *> (&address), addressSize) == 0;
    int serviceStatus = -1;
    if (connected)
    {
        pid_t service = fork();
        if (service == 0)
            _exit (File::RunRequesterHelperService (std::to_string (socketFd).c_str()));
        Require (service != -1 && waitpid (service, &serviceStatus, 0) == service, "run helper service");
    }
    else
        kill (listener, SIGKILL);
    if (socketFd != -1)
        close (socketFd);
    int listenerStatus;
    Require (waitpid (listener, &listenerStatus, 0) == listener, "wait for listener");
    Require (connected, "connect to the requester's socket");
    Require (WIFEXITED (serviceStatus) && WEXITSTATUS (serviceStatus) == 1, "helper service did not fail");
    Require (WIFEXITED (listenerStatus) && WEXITSTATUS (listenerStatus) == 0, "helper answered a non-root peer");
}

int main (int argc, char **argv)
{
    if (argc == 3 && strcmp (argv[1], TC_REQUESTER_HELPER_CMDLINE_OPTION) == 0)
    {
        FreshHelper = true;
        return File::RunRequesterHelperService (argv[2]);
    }
    try
    {
        Require (argc == 4 && geteuid() == 0, "expected root: UID GID FILE");
#ifdef TEST_BUNDLED_LIBRARY
        Require (vc_requester_test_dependency() == 1, "bundled library dependency");
#endif
        ParentOnlyMarker = 123;
        setenv ("VC_REQUESTER_TEST_ENV", "parent-only", 1);
        int file = open (argv[3], O_RDONLY | O_CLOEXEC);
        Require (file != -1, "open disposable file");
        struct rlimit originalLimit, limit;
        Require (getrlimit (RLIMIT_NOFILE, &originalLimit) == 0, "get fd limit");
        limit = originalLimit;
        if (limit.rlim_cur <= InheritedFd) limit.rlim_cur = InheritedFd + 1;
        Require (setrlimit (RLIMIT_NOFILE, &limit) == 0, "raise soft fd limit");
        Require (fcntl (file, F_DUPFD, InheritedFd) == InheritedFd, "create inherited high fd");
        Require (setrlimit (RLIMIT_NOFILE, &originalLimit) == 0, "restore soft fd limit");

        RequesterHelperRequest request;
        memset (&request, 0, sizeof (request));
        request.OpenFile = 1;
        strcpy (request.Path, argv[3]);
        request.Flags = O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
        request.UserId = static_cast <uid_t> (atoi (argv[1]));
        request.GroupId = static_cast <gid_t> (atoi (argv[2]));
        RequesterHelperReply reply;
        int descriptor;
        Require (RunRequesterHelperProcess (request, reply, descriptor) == 0
            && reply.Stage == RequesterHelperSucceeded && descriptor != -1, "fresh open helper");
        Require ((fcntl (descriptor, F_GETFD) & FD_CLOEXEC) != 0, "received fd is CLOEXEC");
        Require ((fcntl (descriptor, F_GETFL) & O_NONBLOCK) == 0, "received fd is blocking");
        std::cout << "PASS fresh open helper, minimal environment, descriptor cleanup, 0-2 on /dev/null\n";

        RequesterHelperRequest timesRequest;
        memset (&timesRequest, 0, sizeof (timesRequest));
        strcpy (timesRequest.Path, argv[3]);
        timesRequest.UserId = request.UserId;
        timesRequest.GroupId = request.GroupId;
        timesRequest.Times[0].tv_sec = 1500000000;
        timesRequest.Times[1].tv_sec = 1500000100;
        int unused;
        Require (RunRequesterHelperProcess (timesRequest, reply, unused) == 0
            && reply.Stage == RequesterHelperSucceeded && unused == -1, "fresh timestamp helper");
        struct stat st;
        Require (stat (argv[3], &st) == 0 && st.st_atime == timesRequest.Times[0].tv_sec
            && st.st_mtime == timesRequest.Times[1].tv_sec, "timestamps not restored through the path");
        std::cout << "PASS fresh timestamp helper\n";

        ExecError = EACCES;
        timesRequest.Times[0].tv_sec += 100;
        timesRequest.Times[1].tv_sec += 100;
        Require (RunRequesterHelperProcess (timesRequest, reply, unused) == EACCES
            && reply.Stage == RequesterHelperStartup && unused == -1,
            "failed exec must not run timestamp helper");
        Require (stat (argv[3], &st) == 0 && st.st_atime == 1500000000 && st.st_mtime == 1500000100,
            "failed exec changed timestamps");
        request.Flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
        Require (RunRequesterHelperProcess (request, reply, unused) == EACCES
            && reply.Stage == RequesterHelperStartup && unused == -1,
            "failed exec must not run opening helper");
        ExecError = ENOENT;
        Require (RunRequesterHelperProcess (request, reply, unused) == ENOENT
            && reply.Stage == RequesterHelperStartup && unused == -1, "exec errno lost");
        setenv ("SUDO_UID", argv[1], 1);
        setenv ("SUDO_GID", argv[2], 1);
        try
        {
            TestFile file;
            file.OpenAsRequester (FilePath (argv[3]), O_RDWR);
            throw std::runtime_error ("expected startup exception");
        }
        catch (const ExternalException &e)
        {
            string text = StringConverter::ToSingle (e.GetSubject());
            Require (text.find ("Cannot start VeraCrypt's requester-access process (/proc/self/exe)") != string::npos
                && text.find (strerror (ENOENT)) != string::npos, "startup diagnostic lost context or errno");
        }
        std::cout << "PASS exact startup errno, diagnostic, and no fork-only/read-only fallback\n";

        ExecError = 0;
        ExitBeforeReady = true;
        Require (RunRequesterHelperProcess (request, reply, unused) != 0
            && reply.Stage == RequesterHelperStartup && unused == -1, "early exit was not a startup failure");
        try
        {
            TestFile file;
            file.OpenAsRequester (FilePath (argv[3]), O_RDWR);
            throw std::runtime_error ("expected early-exit exception");
        }
        catch (const ExternalException &e)
        {
            Require (e.GetSubject().find (L"did not report readiness") != wstring::npos, "early-exit diagnostic");
        }
        ExitBeforeReady = false;
        std::cout << "PASS early exit reported as failure to become ready\n";

        request.Flags |= O_TRUNC;
        Require (RunRequesterHelperProcess (request, reply, unused) != 0 && unused == -1,
            "invalid request accepted");
        Require (fstat (descriptor, &st) == 0 && st.st_size != 0, "invalid request truncated file");
        request.Flags &= ~O_TRUNC;
        RequesterHelperRequest noPath = timesRequest;
        noPath.Path[0] = '\0';
        Require (RunRequesterHelperProcess (noPath, reply, unused) != 0 && unused == -1,
            "timestamp request without a path accepted");
        memset (request.Path, 'a', sizeof (request.Path));
        Require (RunRequesterHelperProcess (request, reply, unused) != 0 && unused == -1,
            "unterminated path accepted");
        strcpy (request.Path, argv[3]);
        request.UserId = 0;
        Require (RunRequesterHelperProcess (request, reply, unused) != 0 && unused == -1,
            "root requester accepted");
        std::cout << "PASS invalid requests rejected\n";

        CheckNonRootPeer (static_cast <uid_t> (atoi (argv[1])), static_cast <gid_t> (atoi (argv[2])));
        std::cout << "PASS request socket from a non-root peer refused\n";

        close (descriptor);
        close (InheritedFd);
        close (file);
        Require (waitpid (-1, nullptr, WNOHANG) == -1 && errno == ECHILD, "unreaped helper");
        return 0;
    }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    parser.add_argument("--user", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root")
    user = pwd.getpwnam(args.user)
    if user.pw_uid == 0:
        parser.error("--user must be unprivileged")
    library = args.build_dir.resolve() / "Platform" / "Platform.a"
    if not library.is_file():
        parser.error("build VeraCrypt first, or supply --build-dir")
    with tempfile.TemporaryDirectory(prefix="vc-requester-helper-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        source = root / "helper.cpp"
        source.write_text(HARNESS)
        target = root / "plain-file"
        target.write_text("Disposable helper test data\n")
        os.chown(target, user.pw_uid, user.pw_gid)
        compiler = shlex.split(os.environ.get("CXX", "c++"))
        bundled = root / "lib"
        bundled.mkdir()
        dependency = root / "dependency.cpp"
        dependency.write_text('extern "C" int vc_requester_test_dependency () { return 1; }\n')
        subprocess.run(compiler + ["-shared", "-fPIC", str(dependency), "-o",
                                   str(bundled / "libvc_requester_test.so")], check=True)
        for mode in ("close-range", "fd-fallback", "bundled-library"):
            binary = root / ("helper-" + mode)
            command = compiler + [
                "-std=c++11", "-O2", "-Wall", "-DTC_LINUX", "-D_FILE_OFFSET_BITS=64",
                "-I" + str(ROOT / "src"), str(source), str(library), "-pthread",
                "-Wl,--wrap=execve", "-Wl,--wrap=sendmsg", "-o", str(binary),
            ]
            env = os.environ.copy()
            if mode == "fd-fallback":
                command.append("-DTEST_NO_CLOSE_RANGE")
            if mode == "bundled-library":
                command += ["-DTEST_BUNDLED_LIBRARY", "-L" + str(bundled), "-lvc_requester_test"]
                env["LD_LIBRARY_PATH"] = str(bundled)
            subprocess.run(command, check=True)
            print("Testing", mode, flush=True)
            subprocess.run([str(binary), str(user.pw_uid), str(user.pw_gid), str(target)],
                           check=True, timeout=40, env=env)


if __name__ == "__main__":
    main()
