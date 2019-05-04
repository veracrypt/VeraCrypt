/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "File.h"
#ifdef TC_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#endif

namespace VeraCrypt
{
	File::~File ()
	{
		try
		{
			if (FileIsOpen)
				Close();
		}
		catch (...) { }
	}

	void File::Copy (const FilePath &sourcePath, const FilePath &destinationPath, bool preserveTimestamps)
	{
		File source;
		source.Open (sourcePath);

		File destination;
		destination.Open (destinationPath, CreateWrite);

		SecureBuffer buffer (OptimalReadSize);
		uint64 len;

		while ((len = source.Read (buffer)) > 0)
		{
			destination.Write (buffer, static_cast <size_t> (len));
		}

		if (preserveTimestamps)
		{
			destination.Flush();
#ifndef TC_WINDOWS
			struct stat statData;
			throw_sys_sub_if (stat (string (sourcePath).c_str(), &statData) == -1, wstring (sourcePath));

			struct utimbuf u;
			u.actime = statData.st_atime;
			u.modtime = statData.st_mtime;
			throw_sys_sub_if (utime (string (destinationPath).c_str(), &u) == -1, wstring (destinationPath));
#endif
		}
	}

	FilePath File::GetPath () const
	{
		if_debug (ValidateState());
		return Path;
	}

	void File::ReadCompleteBuffer (const BufferPtr &buffer) const
	{
		size_t dataLeft = buffer.Size();
		size_t offset = 0;

		while (dataLeft > 0)
		{
			size_t dataRead = static_cast <size_t> (Read (buffer.GetRange (offset, dataLeft)));
			if (dataRead == 0)
				throw InsufficientData (SRC_POS);

			dataLeft -= dataRead;
			offset += dataRead;
		}
	}

	void File::ValidateState () const
	{
		if (!FileIsOpen)
			throw NotInitialized (SRC_POS);
	}
}
