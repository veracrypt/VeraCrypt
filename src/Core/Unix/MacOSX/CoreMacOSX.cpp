/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

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
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "CoreMacOSX.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	CoreMacOSX::CoreMacOSX ()
	{
	}

	CoreMacOSX::~CoreMacOSX ()
	{
	}

	shared_ptr <VolumeInfo> CoreMacOSX::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		if (!mountedVolume->VirtualDevice.IsEmpty() && mountedVolume->VirtualDevice.IsBlockDevice())
		{
			list <string> args;
			args.push_back ("detach");
			args.push_back (mountedVolume->VirtualDevice);

			if (ignoreOpenFiles)
				args.push_back ("-force");

			try
			{
				Process::Execute ("hdiutil", args);
			}
			catch (ExecutedProcessFailed &e)
			{
				if (!ignoreOpenFiles)
				{
					string err = e.GetErrorOutput();

					if (err.find ("couldn't unmount") != string::npos
						|| err.find ("busy") != string::npos
						|| err.find ("49153") != string::npos)
					{
						throw MountedVolumeInUse (SRC_POS);
					}
				}

				throw;
			}
		}

		if (syncVolumeInfo || mountedVolume->Protection == VolumeProtection::HiddenVolumeReadOnly)
		{
			sync();
			VolumeInfoList ml = GetMountedVolumes (mountedVolume->Path);

			if (ml.size() > 0)
				mountedVolume = ml.front();
		}

		list <string> args;
		args.push_back ("--");
		args.push_back (mountedVolume->AuxMountPoint);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("umount", args);
				break;
			}
			catch (ExecutedProcessFailed&)
			{
				if (t > 10)
					throw;
				Thread::Sleep (200);
			}
		}

		try
		{
			mountedVolume->AuxMountPoint.Delete();
		}
		catch (...)	{ }

		return mountedVolume;
	}

	void CoreMacOSX::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		list <string> args;
		args.push_back ("/Applications/Utilities/Disk Utility.app");
		Process::Execute ("open", args);
	}

	void CoreMacOSX::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
		// Check FUSE version
		char fuseVersionString[MAXHOSTNAMELEN + 1] = { 0 };
		size_t fuseVersionStringLength = MAXHOSTNAMELEN;
		int status;
		bool bIsOSXFuse = false;

		if ((status = sysctlbyname ("macfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
		{
			fuseVersionStringLength = MAXHOSTNAMELEN;
			if ((status = sysctlbyname ("osxfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
			{
				throw HigherFuseVersionRequired (SRC_POS);
			}
			else
			{
				// look for compatibility mode
				struct stat sb;
				if ((0 == stat("/usr/local/lib/libfuse.dylib", &sb)) && (0 == stat("/Library/Frameworks/MacFUSE.framework/MacFUSE", &sb)))
				{
					bIsOSXFuse = true;
				}
				else
					throw HigherFuseVersionRequired (SRC_POS);
			}
			
		}

		vector <string> fuseVersion = StringConverter::Split (string (fuseVersionString), ".");
		if (fuseVersion.size() < 2)
			throw HigherFuseVersionRequired (SRC_POS);

		uint32 fuseVersionMajor = StringConverter::ToUInt32 (fuseVersion[0]);
		uint32 fuseVersionMinor = StringConverter::ToUInt32 (fuseVersion[1]);

		if (bIsOSXFuse)
		{
			if (fuseVersionMajor < 2 || (fuseVersionMajor == 2 && fuseVersionMinor < 5))
				throw HigherFuseVersionRequired (SRC_POS);
		}
		else if (fuseVersionMajor < 1 || (fuseVersionMajor == 1 && fuseVersionMinor < 3))
			throw HigherFuseVersionRequired (SRC_POS);

		// Mount volume image
		string volImage = string (auxMountPoint) + FuseService::GetVolumeImagePath();

		list <string> args;
		args.push_back ("attach");
		args.push_back (volImage);
		args.push_back ("-plist");
		args.push_back ("-noautofsck");
		args.push_back ("-imagekey");
		args.push_back ("diskimage-class=CRawDiskImage");

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			args.push_back ("-mount");
			args.push_back ("required");

			// Let the system specify mount point except when the user specified a non-default one
			if (string (*options.MountPoint).find (GetDefaultMountPointPrefix()) != 0)
			{
				args.push_back ("-mountpoint");
				args.push_back (*options.MountPoint);
			}
		}
		else
			args.push_back ("-nomount");

		if (options.Protection == VolumeProtection::ReadOnly)
			args.push_back ("-readonly");

		string xml;
		
		while (true)
		{
			try
			{
				xml = Process::Execute ("hdiutil", args);
				break;
			}
			catch (ExecutedProcessFailed &e)
			{
				if (e.GetErrorOutput().find ("noautofsck") != string::npos)
				{
					args.remove ("-noautofsck");
					continue;
				}
				
				throw;
			}
		}

		size_t p = xml.find ("<key>dev-entry</key>");
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);

		p = xml.find ("<string>", p);
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);
		p += 8;

		size_t e = xml.find ("</string>", p);
		if (e == string::npos)
			throw ParameterIncorrect (SRC_POS);

		DevicePath virtualDev = StringConverter::Trim (xml.substr (p, e - p));

		try
		{
			FuseService::SendAuxDeviceInfo (auxMountPoint, virtualDev);
		}
		catch (...)
		{
			try
			{
				list <string> args;
				args.push_back ("detach");
				args.push_back (volImage);
				args.push_back ("-force");

				Process::Execute ("hdiutil", args);
			}
			catch (ExecutedProcessFailed&) { }
			throw;
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreMacOSX>);
	auto_ptr <CoreBase> CoreDirect (new CoreMacOSX);
}
