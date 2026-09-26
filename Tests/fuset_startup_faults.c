/* Scoped macOS fault injection for test_fuset_dismount.py --startup-faults.
 * Copyright (c) 2026 AM Crypto. Licensed under the Apache License 2.0.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int mode_is (const char *mode)
{
	const char *fault = getenv ("VC_FUSET_TEST_FAULT");
	return fault && strcmp (fault, mode) == 0;
}

static int fixture_path (const char *path, const char *suffix)
{
	const char *root = getenv ("VC_FUSET_TEST_ROOT");
	size_t size = strlen (path), suffix_size = strlen (suffix);
	return root && strncmp (path, root, strlen (root)) == 0
		&& path[strlen (root)] == '/' && size >= suffix_size
		&& strcmp (path + size - suffix_size, suffix) == 0;
}

static void mark_fault (void)
{
	const char *path = getenv ("VC_FUSET_TEST_FAULT_MARKER");
	if (path)
	{
		int fd = open (path, O_WRONLY | O_CREAT, 0600);
		if (fd != -1)
			close (fd);
	}
}

static int test_connect (int fd, const struct sockaddr *address, socklen_t length)
{
	static const char prefix[] = "/private/tmp/.veracrypt-shutdown-";
	if ((mode_is ("refused") || mode_is ("rollback-blocked")) && address->sa_family == AF_UNIX
		&& strncmp (((const struct sockaddr_un *) address)->sun_path, prefix, sizeof (prefix) - 1) == 0)
	{
		mark_fault();
		const char *log = getenv ("VC_FUSET_TEST_SOCKET_LOG");
		if (log)
		{
			int output = open (log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (output != -1)
			{
				const char *path = ((const struct sockaddr_un *) address)->sun_path;
				write (output, path, strlen (path));
				close (output);
			}
		}
		errno = ECONNREFUSED;
		return -1;
	}
	return connect (fd, address, length);
}

static int test_open (const char *path, int flags, ...)
{
	if (mode_is ("metadata") && fixture_path (path, "/shutdown-socket"))
	{
		mark_fault();
		errno = EIO;
		return -1;
	}
	if (flags & O_CREAT)
	{
		va_list args;
		va_start (args, flags);
		int mode = va_arg (args, int);
		va_end (args);
		return open (path, flags, mode);
	}
	return open (path, flags);
}

static int test_stat (const char *path, struct stat *value)
{
	if (mode_is ("control") && fixture_path (path, "/control"))
	{
		mark_fault();
		errno = ENOENT;
		return -1;
	}
	return stat (path, value);
}

static int test_unmount (const char *path, int flags)
{
	const char *gate = getenv ("VC_FUSET_TEST_UNMOUNT_GATE");
	if (mode_is ("rollback-blocked") && gate && fixture_path (path, "") && access (gate, F_OK) == 0)
	{
		mark_fault();
		errno = EBUSY;
		return -1;
	}
	return unmount (path, flags);
}

#define INTERPOSE(replacement, original) \
	__attribute__((used)) static const struct { const void *replace; const void *replacee; } \
	interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
		(const void *) replacement, (const void *) original }

INTERPOSE (test_connect, connect);
INTERPOSE (test_open, open);
INTERPOSE (test_stat, stat);
INTERPOSE (test_unmount, unmount);
