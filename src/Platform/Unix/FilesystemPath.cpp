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

#include "Platform/FilesystemPath.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include <stdio.h>
#include <sys/stat.h>
#if !defined(__FreeBSD__) && !defined(__APPLE__)
#include <sys/sysmacros.h>
#endif

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

		// If simply removing trailing number didn't produce a valid drive name, try to use sysfs to get the right one
		if (!path.IsDevice()) {
			struct stat st;

			if(stat (StringConverter::ToSingle (Path).c_str (), &st) == 0) {
				const long maxPathLength = pathconf ("/", _PC_PATH_MAX);

				if(maxPathLength != -1) {
					string linkPathName ("/sys/dev/block/");
					linkPathName += StringConverter::ToSingle (major (st.st_rdev)) + string (":") + StringConverter::ToSingle (minor (st.st_rdev));

					vector<char> linkTargetPath(maxPathLength+1);

					if(readlink(linkPathName.c_str (), linkTargetPath.data(), linkTargetPath.size()) != -1) {
						const string targetPathStr (linkTargetPath.data());
						const size_t lastSlashPos = targetPathStr.find_last_of ('/');
						const size_t secondLastSlashPos = targetPathStr.find_last_of ('/', lastSlashPos-1);
						path = string ("/dev/") + targetPathStr.substr (secondLastSlashPos+1, lastSlashPos-secondLastSlashPos-1);
					}
				}
			}
		}

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
