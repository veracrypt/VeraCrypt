/*
 VeraCrypt source code
 Copyright (c) 2026 AM Crypto

 This file is part of VeraCrypt and is governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

#ifndef TC_HEADER_Main_OpenBSDFormatterDevice
#define TC_HEADER_Main_OpenBSDFormatterDevice

#include "Main/Main.h"

#ifdef TC_OPENBSD
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "Core/Unix/CoreService.h"
#include "Core/Unix/UnixUser.h"
#include "Platform/Unix/Process.h"

namespace VeraCrypt
{
	inline bool IsOpenBSDVndDevicePath (const string &path, bool rawDevice)
	{
		const string prefix = rawDevice ? "/dev/rvnd" : "/dev/vnd";
		if (path.find (prefix) != 0)
			return false;

		size_t numberStart = prefix.size();
		size_t numberEnd = numberStart;
		while (numberEnd < path.size() && path[numberEnd] >= '0' && path[numberEnd] <= '9')
			++numberEnd;

		return numberEnd > numberStart
			&& numberEnd + 1 == path.size()
			&& path[numberEnd] == 'c';
	}

	inline DevicePath GetOpenBSDRawFormatterDevicePath (const DevicePath &path)
	{
		string pathStr = path;

		if (IsOpenBSDVndDevicePath (pathStr, true))
			return path;

		if (IsOpenBSDVndDevicePath (pathStr, false))
			return DevicePath (string ("/dev/r") + pathStr.substr (5));

		return path;
	}

	inline string GetOpenBSDFormatterName (const string &fsFormatter)
	{
		size_t namePos = fsFormatter.find_last_of ('/');
		return namePos == string::npos ? fsFormatter : fsFormatter.substr (namePos + 1);
	}

	inline bool IsOpenBSDFFSFormatter (const string &fsFormatter)
	{
		return GetOpenBSDFormatterName (fsFormatter) == "newfs";
	}

	inline bool GetOpenBSDFormatterEnvId (const char *name, uint64 &id)
	{
		const char *env = getenv (name);
		if (!env || !env[0])
			return false;

		char *endPtr = nullptr;
		errno = 0;
		unsigned long long value = strtoull (env, &endPtr, 10);
		if (errno != 0 || !endPtr || *endPtr != '\0')
			return false;

		id = static_cast <uint64> (value);
		return true;
	}

	inline uint64 GetOpenBSDFormatterOwnerUserId ()
	{
		uint64 id;
		if (GetOpenBSDFormatterEnvId ("SUDO_UID", id))
			return id;

		uid_t doasUid;
		if (GetDoasUserIds (&doasUid, nullptr))
			return static_cast <uint64> (doasUid);

		return static_cast <uint64> (getuid());
	}

	inline uint64 GetOpenBSDFormatterOwnerGroupId ()
	{
		uint64 id;
		if (GetOpenBSDFormatterEnvId ("SUDO_GID", id))
			return id;

		gid_t doasGid;
		if (GetDoasUserIds (nullptr, &doasGid))
			return static_cast <uint64> (doasGid);

		return static_cast <uint64> (getgid());
	}

	inline void ExecuteOpenBSDFilesystemFormatter (const string &fsFormatter, const list <string> &args)
	{
		if (IsOpenBSDFFSFormatter (fsFormatter))
		{
			if (args.empty())
				throw ParameterIncorrect (SRC_POS);

			CoreService::RequestExecuteOpenBSDFFSFormatter (DevicePath (args.back()), GetOpenBSDFormatterOwnerUserId(), GetOpenBSDFormatterOwnerGroupId());
			return;
		}

		Process::Execute (fsFormatter, args);
	}
}
#endif // TC_OPENBSD

#endif // TC_HEADER_Main_OpenBSDFormatterDevice
