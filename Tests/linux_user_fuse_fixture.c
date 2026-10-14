/*
 * User-only FUSE passthrough fixture for Tests/test_linux_requester_access.py.
 *
 * Serves $USERFS_BACKING. Mounted by an unprivileged user without allow_other,
 * it denies root, like a GVfs share. Behavior knobs are files in $USERFS_CONTROL:
 *   hang_open     open() blocks while the file exists
 *   enotsup_rw    writable open() fails with ENOTSUP (no in-place editing)
 *   eacces_rw     writable open() fails with EACCES (the server denies writing)
 *   hang_utimens  utimens() blocks while the file exists
 * Operations are logged with the caller's uid to $USERFS_CONTROL/log.
 */
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

static const char *backing;
static const char *control;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void full (char *out, const char *path) { snprintf (out, PATH_MAX, "%s%s", backing, path); }

static int knob (const char *name)
{
	char p[PATH_MAX];
	snprintf (p, sizeof (p), "%s/%s", control, name);
	return access (p, F_OK) == 0;
}

static void wait_while (const char *name)
{
	while (knob (name))
		usleep (50000);
}

static void logop (const char *op, const char *path, int flags, int result)
{
	struct fuse_context *c = fuse_get_context ();
	char p[PATH_MAX];
	snprintf (p, sizeof (p), "%s/log", control);
	pthread_mutex_lock (&log_lock);
	FILE *f = fopen (p, "a");
	if (f)
	{
		fprintf (f, "%s uid=%u pid=%d flags=0%o result=%d %s\n", op, c ? c->uid : 0, c ? c->pid : 0, flags, result, path);
		fclose (f);
	}
	pthread_mutex_unlock (&log_lock);
}

static void *x_init (struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;
	cfg->attr_timeout = 0;
	cfg->entry_timeout = 0;
	cfg->negative_timeout = 0;
	return NULL;
}

static int x_getattr (const char *path, struct stat *st, struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	full (p, path);
	int r = fi ? fstat ((int) fi->fh, st) : lstat (p, st);
	return r == -1 ? -errno : 0;
}

static int x_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	(void) off; (void) fi; (void) flags;
	char p[PATH_MAX];
	full (p, path);
	DIR *d = opendir (p);
	if (!d)
		return -errno;
	struct dirent *e;
	while ((e = readdir (d)))
		filler (buf, e->d_name, NULL, 0, 0);
	closedir (d);
	return 0;
}

static int x_open (const char *path, struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	full (p, path);
	wait_while ("hang_open");
	int result = 0;
	if ((fi->flags & O_ACCMODE) != O_RDONLY && knob ("enotsup_rw"))
		result = -ENOTSUP;
	else if ((fi->flags & O_ACCMODE) != O_RDONLY && knob ("eacces_rw"))
		result = -EACCES;
	else
	{
		int fd = open (p, fi->flags & ~(O_CREAT | O_EXCL | O_NOCTTY));
		if (fd == -1)
			result = -errno;
		else
			fi->fh = fd;
	}
	logop ("open", path, fi->flags, result);
	return result;
}

static int x_create (const char *path, mode_t mode, struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	full (p, path);
	int fd = open (p, fi->flags, mode);
	logop ("create", path, fi->flags, fd == -1 ? -errno : 0);
	if (fd == -1)
		return -errno;
	fi->fh = fd;
	return 0;
}

static int x_read (const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	ssize_t r = pread ((int) fi->fh, buf, size, off);
	if (off == 0)
		logop ("read0", path, 0, (int) r);
	return r == -1 ? -errno : (int) r;
}

static int x_write (const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	ssize_t r = pwrite ((int) fi->fh, buf, size, off);
	static int logged_uid = -1;
	struct fuse_context *c = fuse_get_context ();
	if (c && (int) c->uid != logged_uid)
	{
		logged_uid = (int) c->uid;
		logop ("write", path, 0, (int) r);
	}
	return r == -1 ? -errno : (int) r;
}

static int x_flush (const char *path, struct fuse_file_info *fi)
{
	(void) fi;
	logop ("flush", path, 0, 0);
	return 0;
}

static int x_fsync (const char *path, int datasync, struct fuse_file_info *fi)
{
	(void) path;
	int r = datasync ? fdatasync ((int) fi->fh) : fsync ((int) fi->fh);
	return r == -1 ? -errno : 0;
}

static int x_release (const char *path, struct fuse_file_info *fi)
{
	close ((int) fi->fh);
	logop ("release", path, fi->flags, 0);
	return 0;
}

static int x_utimens (const char *path, const struct timespec tv[2], struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	full (p, path);
	wait_while ("hang_utimens");
	int r = fi ? futimens ((int) fi->fh, tv) : utimensat (AT_FDCWD, p, tv, AT_SYMLINK_NOFOLLOW);
	logop ("utimens", path, 0, r == -1 ? -errno : 0);
	return r == -1 ? -errno : 0;
}

static int x_truncate (const char *path, off_t size, struct fuse_file_info *fi)
{
	char p[PATH_MAX];
	full (p, path);
	int r = fi ? ftruncate ((int) fi->fh, size) : truncate (p, size);
	return r == -1 ? -errno : 0;
}

static int x_unlink (const char *path)
{
	char p[PATH_MAX];
	full (p, path);
	return unlink (p) == -1 ? -errno : 0;
}

static int x_mkfifo (const char *path, mode_t mode, dev_t dev)
{
	char p[PATH_MAX];
	full (p, path);
	(void) dev;
	if (!S_ISFIFO (mode))
		return -EPERM;
	return mkfifo (p, mode & 07777) == -1 ? -errno : 0;
}

static int x_mkdir (const char *path, mode_t mode)
{
	char p[PATH_MAX];
	full (p, path);
	return mkdir (p, mode) == -1 ? -errno : 0;
}

static int x_statfs (const char *path, struct statvfs *st)
{
	(void) path;
	return statvfs (backing, st) == -1 ? -errno : 0;
}

int main (int argc, char *argv[])
{
	backing = getenv ("USERFS_BACKING");
	control = getenv ("USERFS_CONTROL");
	if (!backing || !control)
	{
		fprintf (stderr, "USERFS_BACKING and USERFS_CONTROL are required\n");
		return 2;
	}

	static const struct fuse_operations ops = {
		.init = x_init, .getattr = x_getattr, .readdir = x_readdir, .open = x_open,
		.create = x_create, .read = x_read, .write = x_write, .flush = x_flush,
		.fsync = x_fsync, .release = x_release, .utimens = x_utimens,
		.truncate = x_truncate, .unlink = x_unlink, .mknod = x_mkfifo,
		.mkdir = x_mkdir, .statfs = x_statfs,
	};
	return fuse_main (argc, argv, &ops, NULL);
}
