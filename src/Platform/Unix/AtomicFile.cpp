/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Platform/AtomicFile.h"
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>

namespace VeraCrypt
{
	static void CheckDestination (const FilePath &destination)
	{
		struct stat info;
		if (lstat (string (destination).c_str(), &info) == 0)
		{
			if (!S_ISREG (info.st_mode))
				throw AtomicFileDestinationNotRegular (SRC_POS, destination);
		}
		else
			throw_sys_sub_if (errno != ENOENT, wstring (destination));
	}

	AtomicFile::AtomicFile (const FilePath &destination) : Destination (destination)
	{
		string name = destination;
		if (name.empty() || name.back() == '/')
			throw ParameterIncorrect (SRC_POS, destination);
		CheckDestination (destination);
		size_t separator = name.find_last_of ('/');
		string parent = separator == string::npos ? "." : name.substr (0, separator + 1);
		int flags = O_RDONLY;
#ifdef O_DIRECTORY
		flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
		flags |= O_CLOEXEC;
#endif
		int directoryHandle = open (parent.c_str(), flags);
		throw_sys_sub_if (directoryHandle == -1, wstring (destination));
		ParentDirectory.AssignSystemHandle (directoryHandle, false);
		ParentDirectory.SetCloseOnExec();

		name += ".tmp-XXXXXX";
		vector<char> temporaryName (name.begin(), name.end());
		temporaryName.push_back (0);
		int handle = mkstemp (temporaryName.data());
		throw_sys_sub_if (handle == -1, wstring (destination));
		try
		{
			Output.AssignSystemHandle (handle, false);
			TemporaryPath = temporaryName.data();
			Output.SetCloseOnExec();
		}
		catch (...)
		{
			if (Output.IsOpen()) Output.Close();
			else close (handle);
			unlink (temporaryName.data());
			throw;
		}
	}

	AtomicFile::~AtomicFile ()
	{
		try { if (Output.IsOpen()) Output.Close(); } catch (...) { }
		if (!TemporaryPath.empty()) unlink (TemporaryPath.c_str());
	}

	void AtomicFile::Commit ()
	{
		if (TemporaryPath.empty())
			throw NotInitialized (SRC_POS);
		CheckDestination (Destination);
		Output.Flush();
		Output.Close();
		throw_sys_sub_if (rename (TemporaryPath.c_str(), string (Destination).c_str()) != 0, wstring (Destination));
		TemporaryPath.clear();
		try { ParentDirectory.Flush(); }
		catch (const SystemException &e)
		{
			if (e.GetErrorCode() != EINVAL && e.GetErrorCode() != ENOTSUP)
				throw AtomicFilePublished (SRC_POS, Destination);
		}
	}
}
