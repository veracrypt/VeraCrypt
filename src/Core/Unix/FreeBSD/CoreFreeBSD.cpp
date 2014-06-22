/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "CoreFreeBSD.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	CoreFreeBSD::CoreFreeBSD ()
	{
	}

	CoreFreeBSD::~CoreFreeBSD ()
	{
	}

	DevicePath CoreFreeBSD::AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const
	{
		list <string> args;
		args.push_back ("-a");
		args.push_back ("-t");
		args.push_back ("vnode");

		if (readOnly)
		{
			args.push_back ("-o");
			args.push_back ("readonly");
		}

		args.push_back ("-f");
		args.push_back (filePath);

		string dev = StringConverter::Trim (Process::Execute ("mdconfig", args));

		if (dev.find ("/") == string::npos)
			dev = string ("/dev/") + dev;

		return dev;
	}

	void CoreFreeBSD::DetachLoopDevice (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-d");
		args.push_back ("-u");
		args.push_back (StringConverter::GetTrailingNumber (devicePath));

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("mdconfig", args);
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

	HostDeviceList CoreFreeBSD::GetHostDevices (bool pathListOnly) const
	{
		HostDeviceList devices;
#ifdef TC_MACOSX
		const string busType = "rdisk";
#else
		foreach (const string &busType, StringConverter::Split ("ad da"))
#endif
		{
			for (int devNumber = 0; devNumber < 64; devNumber++)
			{
				stringstream devPath;
				devPath << "/dev/" << busType << devNumber;

				if (FilesystemPath (devPath.str()).IsBlockDevice() || FilesystemPath (devPath.str()).IsCharacterDevice())
				{
					make_shared_auto (HostDevice, device);
					device->Path = devPath.str();
					if (!pathListOnly)
					{
						try
						{
							device->Size = GetDeviceSize (device->Path);
						}
						catch (...)
						{
							device->Size = 0;
						}
						device->MountPoint = GetDeviceMountPoint (device->Path);
						device->SystemNumber = 0;
					}
					devices.push_back (device);

					for (int partNumber = 1; partNumber < 32; partNumber++)
					{
#ifdef TC_MACOSX
						const string partLetter = "";
#else
						foreach (const string &partLetter, StringConverter::Split (",a,b,c,d,e,f,g,h", ",", true))
#endif
						{
							stringstream partPath;
							partPath << devPath.str() << "s" << partNumber << partLetter;

							if (FilesystemPath (partPath.str()).IsBlockDevice() || FilesystemPath (partPath.str()).IsCharacterDevice())
							{
								make_shared_auto (HostDevice, partition);
								partition->Path = partPath.str();
								if (!pathListOnly)
								{
									try 
									{	        
										partition->Size = GetDeviceSize (partition->Path);
									}
									catch (...)
									{
										partition->Size = 0;
									}
									partition->MountPoint = GetDeviceMountPoint (partition->Path);
									partition->SystemNumber = 0;
								}

								device->Partitions.push_back (partition);
							}
						}
					}
				}
			}
		}

		return devices;
	}

	MountedFilesystemList CoreFreeBSD::GetMountedFilesystems (const DevicePath &devicePath, const DirectoryPath &mountPoint) const
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

	void CoreFreeBSD::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
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

#ifdef TC_FREEBSD
	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreFreeBSD>);
	auto_ptr <CoreBase> CoreDirect (new CoreFreeBSD);
#endif
}
