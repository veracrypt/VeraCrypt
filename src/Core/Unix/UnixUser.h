/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_Unix_UnixUser
#define TC_HEADER_Core_Unix_UnixUser

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define TC_DOAS_CORE_SERVICE_ENV "VERACRYPT_DOAS_CORE_SERVICE"

namespace VeraCrypt
{
	static inline bool GetDoasUserIds (uid_t *uid, gid_t *gid)
	{
		if (getuid () != 0 || geteuid () != 0 || getenv ("SUDO_UID") || getenv ("SUDO_GID"))
			return false;

#ifndef TC_OPENBSD
		const char *trustedDoasService = getenv (TC_DOAS_CORE_SERVICE_ENV);
		if (!trustedDoasService || strcmp (trustedDoasService, "1") != 0)
			return false;
#endif

		const char *env = getenv ("DOAS_USER");
		if (!env || !env[0])
			return false;

		long bufferSize = 16384;
#ifdef _SC_GETPW_R_SIZE_MAX
		long sysconfBufferSize = sysconf (_SC_GETPW_R_SIZE_MAX);
		if (sysconfBufferSize > 0)
			bufferSize = sysconfBufferSize;
#endif

		struct passwd pw;
		struct passwd *pwResult = nullptr;
		std::vector <char> buffer (static_cast <size_t> (bufferSize));
		int status;

		while ((status = getpwnam_r (env, &pw, &buffer[0], buffer.size(), &pwResult)) == ERANGE)
		{
			if (buffer.size () > 1024 * 1024)
				return false;
			buffer.resize (buffer.size () * 2);
		}

		if (status != 0 || !pwResult)
			return false;

		if (uid)
			*uid = pw.pw_uid;
		if (gid)
			*gid = pw.pw_gid;

		return true;
	}
}

#endif // TC_HEADER_Core_Unix_UnixUser
