/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include "CoreSolaris.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	CoreSolaris::CoreSolaris ()
	{
	}

	CoreSolaris::~CoreSolaris ()
	{
	}

	DevicePath CoreSolaris::AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const
	{
		list <string> args;
		args.push_back ("-a");
		args.push_back (filePath);

		return StringConverter::Trim (Process::Execute ("lofiadm", args));
	}

	void CoreSolaris::DetachLoopDevice (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-d");
		args.push_back (devicePath);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("lofiadm", args);
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

	HostDeviceList CoreSolaris::GetHostDevices (bool pathListOnly) const
	{
		HostDeviceList devices;

		foreach_ref (const FilePath &devPath, Directory::GetFilePaths ("/dev/rdsk", false))
		{
			string drivePath = devPath;
			if (drivePath.rfind ("p0") == drivePath.size() - 2)
			{
				make_shared_auto (HostDevice, device);
				device->Path = drivePath;

				try
				{
					device->Size = GetDeviceSize (device->Path);
				}
				catch (...)
				{
					device->Size = 0;
				}
				
				if (device->Size == 0)
					continue;

				device->MountPoint = GetDeviceMountPoint (device->Path);
				device->SystemNumber = 0;

				devices.push_back (device);

				for (int partNumber = 1; partNumber <= 32; partNumber++)
				{
					stringstream partPath;
					partPath << drivePath.substr (0, drivePath.size() - 1) << partNumber;

					if (FilesystemPath (partPath.str()).IsBlockDevice() || FilesystemPath (partPath.str()).IsCharacterDevice())
					{
						make_shared_auto (HostDevice, partition);
						partition->Path = partPath.str();

						try 
						{	        
							partition->Size = GetDeviceSize (partition->Path);
						}
						catch (...)
						{
							partition->Size = 0;
						}

						if (partition->Size == 0)
							continue;

						partition->MountPoint = GetDeviceMountPoint (partition->Path);
						partition->SystemNumber = 0;

						device->Partitions.push_back (partition);
					}
				}
			}
		}

		return devices;
	}

	MountedFilesystemList CoreSolaris::GetMountedFilesystems (const DevicePath &devicePath, const DirectoryPath &mountPoint) const
	{
		MountedFilesystemList mountedFilesystems;

		FILE *mtab = fopen ("/etc/mnttab", "r");
		throw_sys_sub_if (!mtab, "/etc/mnttab");
		finally_do_arg (FILE *, mtab, { fclose (finally_arg); });

		int getmntentResult;
		struct mnttab entry;
		while ((getmntentResult = getmntent (mtab, &entry)) == 0)
		{
			make_shared_auto (MountedFilesystem, mf);

			if (entry.mnt_special)
				mf->Device = DevicePath (entry.mnt_special);
			else
				continue;

			if (entry.mnt_mountp)
				mf->MountPoint = DirectoryPath (entry.mnt_mountp);

			if (entry.mnt_fstype)
				mf->Type = entry.mnt_fstype;

			if ((devicePath.IsEmpty() || devicePath == mf->Device) && (mountPoint.IsEmpty() || mountPoint == mf->MountPoint))
				mountedFilesystems.push_back (mf);
		}

		throw_sys_if (getmntentResult > 0);

		return mountedFilesystems;
	}

	void CoreSolaris::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
	{
		try
		{
			// Try to mount FAT by default as mount is unable to probe filesystem type on Solaris
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType.empty() ? "pcfs" : filesystemType, readOnly, systemMountOptions);
		}
		catch (ExecutedProcessFailed&)
		{
			if (!filesystemType.empty())
				throw;

			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions);
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreSolaris>);
	auto_ptr <CoreBase> CoreDirect (new CoreSolaris);
}
