/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/FilesystemPath.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include <stdio.h>
#include <sys/stat.h>

namespace VeraCrypt
{
	void FilesystemPath::Delete () const
	{
		throw_sys_sub_if (remove (string (*this).c_str()) == -1, Path);
	}

	UserId FilesystemPath::GetOwner () const
	{
		struct stat statData;
		throw_sys_if (stat (StringConverter::ToSingle (Path).c_str(), &statData) == -1);

		UserId owner;
		owner.SystemId = statData.st_uid;
		return owner;
	}

	FilesystemPathType::Enum FilesystemPath::GetType () const
	{
		// Strip trailing directory separator
		wstring path = Path;
		size_t pos = path.find_last_not_of (L'/');
		if (path.size() > 2 && pos != path.size() - 1)
			path = path.substr (0, pos + 1);

		struct stat statData;
		throw_sys_sub_if (stat (StringConverter::ToSingle (path).c_str(), &statData) != 0, Path);
		
		if (S_ISREG (statData.st_mode)) return FilesystemPathType::File;
		if (S_ISDIR (statData.st_mode)) return FilesystemPathType::Directory;
		if (S_ISCHR (statData.st_mode)) return FilesystemPathType::CharacterDevice;
		if (S_ISBLK (statData.st_mode)) return FilesystemPathType::BlockDevice;
		if (S_ISLNK (statData.st_mode)) return FilesystemPathType::SymbolickLink;

		return FilesystemPathType::Unknown;
	}

	FilesystemPath FilesystemPath::ToBaseName () const
	{
		wstring path = Path;
		size_t pos = path.find_last_of (L'/');

		if (pos == string::npos)
			return Path;

		return Path.substr (pos + 1);
	}

	FilesystemPath FilesystemPath::ToHostDriveOfPartition () const
	{
		DevicePath path;

#ifdef TC_LINUX

		path = StringConverter::StripTrailingNumber (StringConverter::ToSingle (Path));

#elif defined (TC_MACOSX)

		string pathStr = StringConverter::StripTrailingNumber (StringConverter::ToSingle (Path));
		path = pathStr.substr (0, pathStr.size() - 1);

#elif defined (TC_FREEBSD)

		string pathStr = StringConverter::ToSingle (Path);
		size_t p = pathStr.rfind ("s");
		if (p == string::npos)
			throw PartitionDeviceRequired (SRC_POS);
		path = pathStr.substr (0, p);

#elif defined (TC_SOLARIS)

		path = StringConverter::StripTrailingNumber (StringConverter::ToSingle (Path)) + "0";

#else
		throw NotImplemented (SRC_POS);
#endif
		if (!path.IsDevice())
			throw PartitionDeviceRequired (SRC_POS);

		return path;
	}
}
