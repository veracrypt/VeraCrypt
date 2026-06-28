/*
 * Copyright (c) 2026 VeraCrypt
 * Governed by the Apache License 2.0.
 *
 * Reproducible-build helper: a tiny libc-interposition shim that is
 * LD_PRELOAD'ed only around the "cpack -G RPM" step by the RPM packaging
 * wrappers. It pins the two RPM header fields that rpmbuild otherwise
 * stamps from the wall clock and the build host:
 *
 *   RPMTAG_BUILDTIME  <- SOURCE_DATE_EPOCH      (via time())
 *   RPMTAG_BUILDHOST  <- "reproducible"         (via gethostname()/uname())
 *
 * Modern rpm (>= 4.14 for buildtime, >= 4.18 for buildhost) handles these
 * through its own macros, which CMakeLists.txt already sets; on those
 * versions the shim merely produces the same values. The shim exists so
 * the same reproducibility holds on old rpm (CentOS/RHEL <= 7, rpm < 4.14)
 * that has no such macros, because it works at the libc level regardless of
 * rpm's age. Payload file mtimes/modes are handled separately and
 * version-independently by the install(SCRIPT) staging clamp.
 *
 * Safety notes:
 *  - Only time() is overridden for the clock; clock_gettime()/monotonic time
 *    are left untouched so nothing that waits on elapsed time can hang.
 *  - uname() is NOT faked wholesale: the real uname() is called first and
 *    only nodename is overwritten, so sysname/release/machine stay correct
 *    and rpm's architecture/platform detection is unaffected.
 *  - The shim must load cleanly; a load failure would make ld.so print to
 *    stderr, which rpm's check-buildroot brp script captures and treats as a
 *    fatal "buildroot leaked into files" error. The wrappers therefore only
 *    enable the shim after verifying it builds and loads without output.
 */

#define _GNU_SOURCE
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/utsname.h>

#ifndef VC_REPRO_BUILDHOST
#define VC_REPRO_BUILDHOST "reproducible"
#endif

static time_t vc_fixed_epoch(int *have_epoch)
{
	const char *e = getenv("SOURCE_DATE_EPOCH");
	if (e && *e) {
		*have_epoch = 1;
		return (time_t) strtoll(e, NULL, 10);
	}
	*have_epoch = 0;
	return (time_t) 0;
}

time_t time(time_t *t)
{
	int have_epoch;
	time_t v = vc_fixed_epoch(&have_epoch);

	/* Without SOURCE_DATE_EPOCH there is nothing to pin to, so defer to the
	 * real time() rather than stamping the epoch (1970): a no-op shim is far
	 * safer than a frozen 1970 clock for anything that runs under the
	 * preload. The wrappers always export SOURCE_DATE_EPOCH, so this path is
	 * only a defensive fallback. */
	if (!have_epoch) {
		static time_t (*real_time)(time_t *) = NULL;
		if (!real_time)
			real_time = (time_t (*)(time_t *)) dlsym(RTLD_NEXT, "time");
		if (real_time)
			return real_time(t);
	}

	if (t)
		*t = v;
	return v;
}

int gethostname(char *name, size_t len)
{
	if (name && len) {
		snprintf(name, len, "%s", VC_REPRO_BUILDHOST);
	}
	return 0;
}

int uname(struct utsname *buf)
{
	static int (*real_uname)(struct utsname *) = NULL;
	int rc;

	if (!real_uname)
		real_uname = (int (*)(struct utsname *)) dlsym(RTLD_NEXT, "uname");
	rc = real_uname ? real_uname(buf) : -1;
	if (rc == 0 && buf) {
		snprintf(buf->nodename, sizeof(buf->nodename), "%s", VC_REPRO_BUILDHOST);
	}
	return rc;
}
