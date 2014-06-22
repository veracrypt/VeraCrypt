/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <fstream>
#include <iomanip>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "CoreLinux.h"
#include "Platform/SystemInfo.h"
#include "Platform/TextReader.h"
#include "Volume/EncryptionModeLRW.h"
#include "Volume/EncryptionModeXTS.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	CoreLinux::CoreLinux ()
	{
	}

	CoreLinux::~CoreLinux ()
	{
	}

	DevicePath CoreLinux::AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const
	{
		list <string> loopPaths;
		loopPaths.push_back ("/dev/loop");
		loopPaths.push_back ("/dev/loop/");
		loopPaths.push_back ("/dev/.static/dev/loop");

		for (int devIndex = 0; devIndex < 256; devIndex++)
		{
			string loopDev;
			foreach (const string &loopPath, loopPaths)
			{
				loopDev = loopPath + StringConverter::ToSingle (devIndex);
				if (FilesystemPath (loopDev).IsBlockDevice())
					break;
			}

			if (loopDev.empty())
				continue;

			list <string> args;

			list <string>::iterator readOnlyArg;
			if (readOnly)
			{
				args.push_back ("-r");
				readOnlyArg = --args.end();
			}

			args.push_back ("--");
			args.push_back (loopDev);
			args.push_back (filePath);

			try
			{
				Process::Execute ("losetup", args);
				return loopDev;
			}
			catch (ExecutedProcessFailed&)
			{
				if (readOnly)
				{
					try
					{
						args.erase (readOnlyArg);
						Process::Execute ("losetup", args);
						return loopDev;
					}
					catch (ExecutedProcessFailed&) { }
				}
			}
		}

		throw LoopDeviceSetupFailed (SRC_POS, wstring (filePath));
	}

	void CoreLinux::DetachLoopDevice (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-d");
		args.push_back (devicePath);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("losetup", args);
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

	void CoreLinux::DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const
	{
		string devPath = mountedVolume->VirtualDevice;

		if (devPath.find ("/dev/mapper/veracrypt") != 0)
			throw NotApplicable (SRC_POS);

		size_t devCount = 0;
		while (FilesystemPath (devPath).IsBlockDevice())
		{
			list <string> dmsetupArgs;
			dmsetupArgs.push_back ("remove");
			dmsetupArgs.push_back (StringConverter::Split (devPath, "/").back());

			for (int t = 0; true; t++)
			{
				try
				{
					Process::Execute ("dmsetup", dmsetupArgs);
					break;
				}
				catch (...)
				{
					if (t > 20)
						throw;

					Thread::Sleep (100);
				}
			}

			for (int t = 0; FilesystemPath (devPath).IsBlockDevice() && t < 20; t++)
			{
				Thread::Sleep (100);
			}

			devPath = string (mountedVolume->VirtualDevice) + "_" + StringConverter::ToSingle (devCount++);
		}
	}

	HostDeviceList CoreLinux::GetHostDevices (bool pathListOnly) const
	{
		HostDeviceList devices;
		TextReader tr ("/proc/partitions");

		string line;
		while (tr.ReadLine (line))
		{
			vector <string> fields = StringConverter::Split (line);
			
			if (fields.size() != 4
				|| fields[3].find ("loop") == 0	// skip loop devices
				|| fields[3].find ("cloop") == 0
				|| fields[3].find ("ram") == 0	// skip RAM devices
				|| fields[3].find ("dm-") == 0	// skip device mapper devices
				|| fields[2] == "1"				// skip extended partitions
				)
				continue;

			try
			{
				StringConverter::ToUInt32 (fields[0]);
			}
			catch (...)
			{
				continue;
			}

			try
			{
				make_shared_auto (HostDevice, hostDevice);

				hostDevice->Path = string (fields[3].find ("/dev/") == string::npos ? "/dev/" : "") + fields[3];

				if (!pathListOnly)
				{
					hostDevice->Size = StringConverter::ToUInt64 (fields[2]) * 1024;
					hostDevice->MountPoint = GetDeviceMountPoint (hostDevice->Path);
					hostDevice->SystemNumber = 0;
				}

				try
				{
					StringConverter::GetTrailingNumber (fields[3]);
					if (devices.size() > 0)
					{
						HostDevice &prevDev = **--devices.end();
						if (string (hostDevice->Path).find (prevDev.Path) == 0)
						{
							prevDev.Partitions.push_back (hostDevice);
							continue;
						}
					}
				}
				catch (...) { }

				devices.push_back (hostDevice);
				continue;
			}
			catch (...)
			{
				continue;
			}
		}

		return devices;
	}

	MountedFilesystemList CoreLinux::GetMountedFilesystems (const DevicePath &devicePath, const DirectoryPath &mountPoint) const
	{
		MountedFilesystemList mountedFilesystems;
		DevicePath realDevicePath = devicePath;

		if (!devicePath.IsEmpty())
		{
			char *resolvedPath = realpath (string (devicePath).c_str(), NULL);
			if (resolvedPath)
			{
				realDevicePath = resolvedPath;
				free (resolvedPath);
			}
		}

		FILE *mtab = fopen ("/etc/mtab", "r");

		if (!mtab)
			mtab = fopen ("/proc/mounts", "r");

		throw_sys_sub_if (!mtab, "/proc/mounts");
		finally_do_arg (FILE *, mtab, { fclose (finally_arg); });

		static Mutex mutex;
		ScopeLock sl (mutex);

		struct mntent *entry;
		while ((entry = getmntent (mtab)) != nullptr)
		{
			make_shared_auto (MountedFilesystem, mf);

			if (entry->mnt_fsname)
				mf->Device = DevicePath (entry->mnt_fsname);
			else
				continue;

			if (entry->mnt_dir)
				mf->MountPoint = DirectoryPath (entry->mnt_dir);

			if (entry->mnt_type)
				mf->Type = entry->mnt_type;

			if ((devicePath.IsEmpty() || devicePath == mf->Device || realDevicePath == mf->Device) && (mountPoint.IsEmpty() || mountPoint == mf->MountPoint))
				mountedFilesystems.push_back (mf);
		}

		return mountedFilesystems;
	}

	void CoreLinux::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
	{
		bool fsMounted = false;

		try
		{
			if (!FilesystemSupportsUnixPermissions (devicePath))
			{
				stringstream userMountOptions;
				userMountOptions << "uid=" << GetRealUserId() << ",gid=" << GetRealGroupId() << ",umask=077" << (!systemMountOptions.empty() ? "," : "");

				CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, userMountOptions.str() + systemMountOptions);
				fsMounted = true;
			}
		}
		catch (...) { }

		if (!fsMounted)
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions);
	}

	void CoreLinux::MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const
	{
		bool xts = (typeid (*volume->GetEncryptionMode()) == typeid (EncryptionModeXTS));
		bool lrw = (typeid (*volume->GetEncryptionMode()) == typeid (EncryptionModeLRW));

		if (options.NoKernelCrypto
			|| (!xts && (!lrw || volume->GetEncryptionAlgorithm()->GetCiphers().size() > 1 || volume->GetEncryptionAlgorithm()->GetMinBlockSize() != 16))
			|| volume->GetProtectionType() == VolumeProtection::HiddenVolumeReadOnly)
		{
			throw NotApplicable (SRC_POS);
		}

		if (!SystemInfo::IsVersionAtLeast (2, 6, xts ? 24 : 20))
			throw NotApplicable (SRC_POS);

		// Load device mapper kernel module
		list <string> execArgs;
		foreach (const string &dmModule, StringConverter::Split ("dm_mod dm-mod dm"))
		{
			execArgs.clear();
			execArgs.push_back (dmModule);

			try
			{
				Process::Execute ("modprobe", execArgs);
				break;
			}
			catch (...) { }
		}

		bool loopDevAttached = false;
		bool nativeDevCreated = false;
		bool filesystemMounted = false;

		// Attach volume to loopback device if required
		VolumePath volumePath = volume->GetPath();
		if (!volumePath.IsDevice())
		{
			volumePath = AttachFileToLoopDevice (volumePath, options.Protection == VolumeProtection::ReadOnly);
			loopDevAttached = true;
		}

		string nativeDevPath;

		try
		{
			// Create virtual device using device mapper
			size_t nativeDevCount = 0;
			size_t secondaryKeyOffset = volume->GetEncryptionMode()->GetKey().Size();
			size_t cipherCount = volume->GetEncryptionAlgorithm()->GetCiphers().size();

			foreach_reverse_ref (const Cipher &cipher, volume->GetEncryptionAlgorithm()->GetCiphers())
			{
				stringstream dmCreateArgs;
				dmCreateArgs << "0 " << volume->GetSize() / ENCRYPTION_DATA_UNIT_SIZE << " crypt ";

				// Mode
				dmCreateArgs << StringConverter::ToLower (StringConverter::ToSingle (cipher.GetName())) << (xts ? (SystemInfo::IsVersionAtLeast (2, 6, 33) ? "-xts-plain64 " : "-xts-plain ") : "-lrw-benbi ");

				size_t keyArgOffset = dmCreateArgs.str().size();
				dmCreateArgs << setw (cipher.GetKeySize() * (xts ? 4 : 2) + (xts ? 0 : 16 * 2)) << 0 << setw (0);

				// Sector and data unit offset
				uint64 startSector = volume->GetLayout()->GetDataOffset (volume->GetHostSize()) / ENCRYPTION_DATA_UNIT_SIZE;

				dmCreateArgs << ' ' << (xts ? startSector + volume->GetEncryptionMode()->GetSectorOffset() : 0) << ' ';
				if (nativeDevCount == 0)
					dmCreateArgs << string (volumePath) << ' ' << startSector;
				else
					dmCreateArgs << nativeDevPath << " 0";

				SecureBuffer dmCreateArgsBuf (dmCreateArgs.str().size());
				dmCreateArgsBuf.CopyFrom (ConstBufferPtr ((byte *) dmCreateArgs.str().c_str(), dmCreateArgs.str().size()));

				// Keys
				const SecureBuffer &cipherKey = cipher.GetKey();
				secondaryKeyOffset -= cipherKey.Size();
				ConstBufferPtr secondaryKey = volume->GetEncryptionMode()->GetKey().GetRange (xts ? secondaryKeyOffset : 0, xts ? cipherKey.Size() : 16);

				SecureBuffer hexStr (3);
				for (size_t i = 0; i < cipherKey.Size(); ++i)
				{
					sprintf ((char *) hexStr.Ptr(), "%02x", (int) cipherKey[i]);
					dmCreateArgsBuf.GetRange (keyArgOffset + i * 2, 2).CopyFrom (hexStr.GetRange (0, 2));

					if (lrw && i >= 16)
						continue;

					sprintf ((char *) hexStr.Ptr(), "%02x", (int) secondaryKey[i]);
					dmCreateArgsBuf.GetRange (keyArgOffset + cipherKey.Size() * 2 + i * 2, 2).CopyFrom (hexStr.GetRange (0, 2));
				}

				stringstream nativeDevName;
				nativeDevName << "veracrypt" << options.SlotNumber;
				
				if (nativeDevCount != cipherCount - 1)
					nativeDevName << "_" << cipherCount - nativeDevCount - 2;
				
				nativeDevPath = "/dev/mapper/" + nativeDevName.str();

				execArgs.clear();
				execArgs.push_back ("create");
				execArgs.push_back (nativeDevName.str());

				Process::Execute ("dmsetup", execArgs, -1, nullptr, &dmCreateArgsBuf);
				
				// Wait for the device to be created
				for (int t = 0; true; t++)
				{
					try
					{
						FilesystemPath (nativeDevPath).GetType();
						break;
					}
					catch (...)
					{
						if (t > 20)
							throw;

						Thread::Sleep (100);
					}
				}

				nativeDevCreated = true;
				++nativeDevCount;
			}

			// Test whether the device mapper is able to read and decrypt the last sector
			SecureBuffer lastSectorBuf (volume->GetSectorSize());
			uint64 lastSectorOffset = volume->GetSize() - volume->GetSectorSize();

			File nativeDev;
			nativeDev.Open (nativeDevPath);
			nativeDev.ReadAt (lastSectorBuf, lastSectorOffset);

			SecureBuffer lastSectorBuf2 (volume->GetSectorSize());
			volume->ReadSectors (lastSectorBuf2, lastSectorOffset);

			if (memcmp (lastSectorBuf.Ptr(), lastSectorBuf2.Ptr(), volume->GetSectorSize()) != 0)
				throw KernelCryptoServiceTestFailed (SRC_POS);

			// Mount filesystem
			if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
			{
				MountFilesystem (nativeDevPath, *options.MountPoint,
					StringConverter::ToSingle (options.FilesystemType),
					options.Protection == VolumeProtection::ReadOnly,
					StringConverter::ToSingle (options.FilesystemOptions));

				filesystemMounted = true;
			}

			FuseService::SendAuxDeviceInfo (auxMountPoint, nativeDevPath, volumePath);
		}
		catch (...)
		{
			try
			{
				if (filesystemMounted)
					DismountFilesystem (*options.MountPoint, true);
			}
			catch (...) { }

			try
			{
				if (nativeDevCreated)
				{
					make_shared_auto (VolumeInfo, vol);
					vol->VirtualDevice = nativeDevPath;
					DismountNativeVolume (vol);
				}
			}
			catch (...) { }

			try
			{
				if (loopDevAttached)
					DetachLoopDevice (volumePath);
			}
			catch (...) { }

			throw;
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreLinux>);
	auto_ptr <CoreBase> CoreDirect (new CoreLinux);
}
