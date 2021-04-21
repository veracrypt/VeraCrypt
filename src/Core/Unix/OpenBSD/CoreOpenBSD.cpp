/* $OpenBSD$ */
/*
 Based on FreeBSD/CoreFreeBSD.cpp

 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "CoreOpenBSD.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	CoreOpenBSD::CoreOpenBSD ()
	{
	}

	CoreOpenBSD::~CoreOpenBSD ()
	{
	}

	DevicePath CoreOpenBSD::AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const
	{
		list <string> args;

		if (readOnly)
		{
			throw;
		}

		// find an available vnd
		int freeVnd = -1;
		for (int vnd = 0; vnd <= 3; vnd++)
		{
			stringstream devPath;
			devPath << "/dev/vnd" << vnd << "c";

			if (FilesystemPath (devPath.str()).IsBlockDevice() || FilesystemPath (devPath.str()).IsCharacterDevice())
			{
				make_shared_auto (HostDevice, device);
				device->Path = devPath.str();
				try
				{
					GetDeviceSize (device->Path);
				}
				catch (...)
				{
					freeVnd = vnd;
					break;
				}
			}
		}

		if (freeVnd == -1)
			throw "couldn't find free vnd";

		args.push_back ("-c");

		stringstream freePath;
		freePath << "vnd" << freeVnd;
		args.push_back (freePath.str());

		args.push_back (filePath);

		Process::Execute ("vnconfig", args);

		return "/dev/" + freePath.str() + "c";
	}

	void CoreOpenBSD::DetachLoopDevice (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-u");
		args.push_back (devicePath);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("vnconfig", args);
				break;
			}
			catch (ExecutedProcessFailed&)
			{
				if (t > 5)
					throw;
				Thread::Sleep (200);
			}
		}
	}

	// not sure what this is used for
	HostDeviceList CoreOpenBSD::GetHostDevices (bool pathListOnly) const
	{
		throw;
	}

	MountedFilesystemList CoreOpenBSD::GetMountedFilesystems (const DevicePath &devicePath, const DirectoryPath &mountPoint) const
	{

		static Mutex mutex;
		ScopeLock sl (mutex);

		struct statfs *sysMountList;
		int count = getmntinfo (&sysMountList, MNT_NOWAIT);
		throw_sys_if (count == 0);

		MountedFilesystemList mountedFilesystems;

		for (int i = 0; i < count; i++)
		{
			make_shared_auto (MountedFilesystem, mf);

			if (sysMountList[i].f_mntfromname[0])
				mf->Device = DevicePath (sysMountList[i].f_mntfromname);
			else
				continue;

			if (sysMountList[i].f_mntonname[0])
				mf->MountPoint = DirectoryPath (sysMountList[i].f_mntonname);

			mf->Type = sysMountList[i].f_fstypename;

			if ((devicePath.IsEmpty() || devicePath == mf->Device) && (mountPoint.IsEmpty() || mountPoint == mf->MountPoint))
				mountedFilesystems.push_back (mf);
		}

		return mountedFilesystems;
	}

	void CoreOpenBSD::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
	{
		try
		{
			// Try to mount FAT by default as mount is unable to probe filesystem type on BSD
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType.empty() ? "msdos" : filesystemType, readOnly, systemMountOptions);
		}
		catch (ExecutedProcessFailed&)
		{
			if (!filesystemType.empty())
				throw;

			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions);
		}
	}

#ifdef TC_OPENBSD
	unique_ptr <CoreBase> Core (new CoreServiceProxy <CoreOpenBSD>);
	unique_ptr <CoreBase> CoreDirect (new CoreOpenBSD);
#endif
}
