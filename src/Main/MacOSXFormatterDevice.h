/*
 VeraCrypt source code
 Copyright (c) 2026 AM Crypto

 This file is part of VeraCrypt and is governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

#ifndef VC_HEADER_Main_MacOSXFormatterDevice
#define VC_HEADER_Main_MacOSXFormatterDevice

#include "Main/Main.h"

#ifdef TC_MACOSX
#include <unistd.h>
#include "Core/Unix/CoreService.h"
#include "Platform/Unix/Process.h"

namespace VeraCrypt
{
	inline bool IsMacOSXDiskDevicePath (const string &deviceIdentifier, const string &prefix)
	{
		return deviceIdentifier.find (prefix) == 0
			&& deviceIdentifier.size() > prefix.size()
			&& deviceIdentifier[prefix.size()] >= '0'
			&& deviceIdentifier[prefix.size()] <= '9';
	}

	inline string GetMacOSXRawDevicePath (const string &deviceIdentifier)
	{
		if (IsMacOSXDiskDevicePath (deviceIdentifier, "/dev/rdisk"))
			return deviceIdentifier;

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "/dev/disk"))
			return string ("/dev/rdisk") + deviceIdentifier.substr (9);

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "rdisk"))
			return string ("/dev/") + deviceIdentifier;

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "disk"))
			return string ("/dev/r") + deviceIdentifier;

		return deviceIdentifier;
	}

	inline string GetMacOSXBlockDevicePath (const string &deviceIdentifier)
	{
		if (IsMacOSXDiskDevicePath (deviceIdentifier, "/dev/disk"))
			return deviceIdentifier;

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "/dev/rdisk"))
			return string ("/dev/disk") + deviceIdentifier.substr (10);

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "disk"))
			return string ("/dev/") + deviceIdentifier;

		if (IsMacOSXDiskDevicePath (deviceIdentifier, "rdisk"))
			return string ("/dev/disk") + deviceIdentifier.substr (5);

		return deviceIdentifier;
	}

	inline bool IsSameMacOSXDevicePath (const string &firstDeviceIdentifier, const string &secondDeviceIdentifier)
	{
		return GetMacOSXRawDevicePath (firstDeviceIdentifier) == GetMacOSXRawDevicePath (secondDeviceIdentifier);
	}

	inline string GetMacOSXFormatterName (const string &fsFormatter)
	{
		size_t namePos = fsFormatter.find_last_of ('/');
		return namePos == string::npos ? fsFormatter : fsFormatter.substr (namePos + 1);
	}

	inline bool IsMacOSXAPFSFormatter (const string &fsFormatter)
	{
		return GetMacOSXFormatterName (fsFormatter) == "newfs_apfs";
	}

	inline bool IsMacOSXExFATFormatter (const string &fsFormatter)
	{
		return GetMacOSXFormatterName (fsFormatter) == "newfs_exfat";
	}

	inline bool UseElevatedMacOSXAPFSFormatter (const string &fsFormatter)
	{
		return IsMacOSXAPFSFormatter (fsFormatter) && !Core->HasAdminPrivileges();
	}

	inline void AddMacOSXAPFSFormatterUserArgs (list <string> &args)
	{
		stringstream uid;
		stringstream gid;

		// The APFS formatter may run elevated, so preserve the invoking user's ownership.
		uid << getuid();
		gid << getgid();

		args.push_back ("-U");
		args.push_back (uid.str());
		args.push_back ("-G");
		args.push_back (gid.str());
	}

	inline void AddMacOSXExFATFormatterArgs (list <string> &args)
	{
		// Match Disk Utility/Finder erase behavior by deriving a fresh exFAT layout.
		args.push_back ("-R");
	}

	struct MacOSXFormatterDeviceOwnerRestore
	{
		MacOSXFormatterDeviceOwnerRestore (const FilesystemPath &path, const UserId &owner)
			: Path (path), Owner (owner) { }

		FilesystemPath Path;
		UserId Owner;
	};

	typedef list <MacOSXFormatterDeviceOwnerRestore> MacOSXFormatterDeviceOwnerRestoreList;

	inline void AddUniqueMacOSXDevicePath (list <FilesystemPath> &paths, const string &path)
	{
		if (path.empty())
			return;

		foreach (const FilesystemPath &existingPath, paths)
		{
			if (string (existingPath) == path)
				return;
		}

		paths.push_back (FilesystemPath (path));
	}

	inline void PrepareMacOSXFormatterDevice (const DevicePath &devicePath, MacOSXFormatterDeviceOwnerRestoreList &changedDeviceOwners)
	{
		if (Core->HasAdminPrivileges())
			return;

		const string devicePathStr = devicePath;
		list <FilesystemPath> paths;
		// APFS formatters may resolve /dev/rdiskN back to /dev/diskN internally.
		AddUniqueMacOSXDevicePath (paths, devicePathStr);
		AddUniqueMacOSXDevicePath (paths, GetMacOSXRawDevicePath (devicePathStr));
		AddUniqueMacOSXDevicePath (paths, GetMacOSXBlockDevicePath (devicePathStr));

		foreach (const FilesystemPath &path, paths)
		{
			try
			{
				File file;
				file.Open (path, File::OpenReadWrite);
			}
			catch (...)
			{
				UserId origDeviceOwner = path.GetOwner();
				// Register before chown so service-side success followed by
				// an IPC failure can still be restored.
				changedDeviceOwners.push_back (MacOSXFormatterDeviceOwnerRestore (path, origDeviceOwner));
				Core->SetFileOwner (path, UserId (getuid()));
			}
		}
	}

	inline void RestoreMacOSXFormatterDeviceOwners (const MacOSXFormatterDeviceOwnerRestoreList &changedDeviceOwners)
	{
		foreach (const MacOSXFormatterDeviceOwnerRestore &restore, changedDeviceOwners)
		{
			try
			{
				Core->SetFileOwner (restore.Path, restore.Owner);
			}
			catch (...) { }
		}
	}

	inline void ExecuteMacOSXFilesystemFormatter (const string &fsFormatter, const list <string> &args)
	{
		if (UseElevatedMacOSXAPFSFormatter (fsFormatter))
		{
			if (args.empty())
				throw ParameterIncorrect (SRC_POS);

			CoreService::RequestExecuteMacOSXAPFSFormatter (DevicePath (args.back()), getuid(), getgid());
			return;
		}

		Process::Execute (IsMacOSXAPFSFormatter (fsFormatter) ? CoreService::GetMacOSXAPFSFormatterPath() : fsFormatter, args);
	}
}
#endif // TC_MACOSX

#endif // VC_HEADER_Main_MacOSXFormatterDevice
