/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include "CoreLinux.h"
#include "Platform/SystemInfo.h"
#include "Platform/TextReader.h"
#include "Volume/EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "Volume/EncryptionModeWolfCryptXTS.h"
#endif
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace VeraCrypt
{
	namespace
	{
		struct DeviceOwnership
		{
			enum Enum
			{
				Absent,
				Owned,
				Foreign
			};
		};

		struct LoopDetachResult
		{
			enum Enum
			{
				Released,
				Claimed,		// Exclusively claimed, e.g. by a mount of its filesystem
				OpenElsewhere
			};
		};

		// Backing file of a loop device
		struct LoopBacking
		{
			LoopBacking () : Device (0), Inode (0) { }
			LoopBacking (const struct stat &fileStat) : Device ((uint64) fileStat.st_dev), Inode ((uint64) fileStat.st_ino) { }

			bool IsBacking (const loop_info64 &info) const { return info.lo_device == Device && info.lo_inode == Inode; }
			bool IsFile (const struct stat &fileStat) const { return (uint64) fileStat.st_dev == Device && (uint64) fileStat.st_ino == Inode; }

			uint64 Device;
			uint64 Inode;
		};

		struct DeviceMapperDevice
		{
			DeviceMapperDevice () : Number (0), Legacy (false) { }

			string KernelName;
			string Name;
			dev_t Number;
			bool Legacy;
		};

		// Returns false if the attribute is gone, as when the device has been removed
		bool ReadSysfsAttribute (const string &path, string &value)
		{
			value.clear();

			int fd = open (path.c_str(), O_RDONLY | O_CLOEXEC);
			if (fd == -1)
			{
				if (errno == ENOENT || errno == ENOTDIR || errno == ENODEV || errno == ENXIO)
					return false;
				throw SystemException (SRC_POS, path);
			}
			finally_do_arg (int, fd, { close (finally_arg); });

			char buffer[4096];
			ssize_t size = read (fd, buffer, sizeof (buffer));
			if (size < 0)
			{
				if (errno == ENOENT || errno == ENODEV || errno == ENXIO)
					return false;
				throw SystemException (SRC_POS, path);
			}

			value.assign (buffer, size);
			size_t end = value.find ('\n');
			if (end != string::npos)
				value.erase (end);

			return true;
		}

		bool GetSysfsDeviceNumber (const string &sysfsDirectory, dev_t &deviceNumber)
		{
			string value;
			if (!ReadSysfsAttribute (sysfsDirectory + "/dev", value))
				return false;

			vector <string> fields = StringConverter::Split (value, ":");
			if (fields.size() != 2)
				throw ParameterIncorrect (SRC_POS);

			deviceNumber = makedev (StringConverter::ToUInt32 (fields[0]), StringConverter::ToUInt32 (fields[1]));
			return true;
		}

		bool GetSysfsSlaves (const string &kernelName, list <string> &slaves)
		{
			slaves.clear();

			const string path = "/sys/class/block/" + kernelName + "/slaves";
			DIR *dir = opendir (path.c_str());
			if (!dir)
			{
				throw_sys_sub_if (errno != ENOENT && errno != ENOTDIR, path);
				return false;
			}
			finally_do_arg (DIR *, dir, { closedir (finally_arg); });

			struct dirent *entry;
			while ((entry = readdir (dir)) != nullptr)
			{
				string name = entry->d_name;
				if (name != "." && name != "..")
					slaves.push_back (name);
			}

			return true;
		}

		// Returns false if the loop device is not bound
		bool GetLoopDeviceStatus (int fd, const string &devicePath, loop_info64 &info)
		{
			Memory::Zero (&info, sizeof (info));
			if (ioctl (fd, LOOP_GET_STATUS64, &info) == 0)
				return true;

			throw_sys_sub_if (errno != ENXIO, devicePath);
			return false;
		}

		bool IsLoopDevice (const struct stat &devStat)
		{
			return S_ISBLK (devStat.st_mode) && major (devStat.st_rdev) == LOOP_MAJOR;
		}

		bool IsLoopDeviceBackedBy (const string &devicePath, const LoopBacking &backing)
		{
			struct stat devStat;
			if (stat (devicePath.c_str(), &devStat) != 0)
			{
				throw_sys_sub_if (errno != ENOENT && errno != ENOTDIR, devicePath);
				return false;
			}

			if (!IsLoopDevice (devStat))
				return false;

			int fd = open (devicePath.c_str(), O_RDONLY | O_CLOEXEC);
			if (fd == -1)
			{
				if (errno == ENOENT || errno == ENXIO || errno == ENODEV)
					return false;

				throw_sys_sub_if ((errno != EACCES && errno != EPERM) || geteuid() == 0, devicePath);

				// Without access to the device, as when listing volumes unprivileged, compare the backing file path
				stringstream sysfsPath;
				sysfsPath << "/sys/dev/block/" << major (devStat.st_rdev) << ":" << minor (devStat.st_rdev) << "/loop/backing_file";

				string backingFile;
				struct stat backingStat;
				return ReadSysfsAttribute (sysfsPath.str(), backingFile)
					&& stat (backingFile.c_str(), &backingStat) == 0
					&& backing.IsFile (backingStat);
			}
			finally_do_arg (int, fd, { close (finally_arg); });

			struct stat fdStat;
			throw_sys_sub_if (fstat (fd, &fdStat) != 0, devicePath);

			loop_info64 info;
			return IsLoopDevice (fdStat) && GetLoopDeviceStatus (fd, devicePath, info) && backing.IsBacking (info);
		}

		// The descriptor keeps the device bound, so it cannot be released and reused in between
		LoopDetachResult::Enum TryDetachLoopDevice (int fd, const string &devicePath, const LoopBacking &backing, bool deferred)
		{
			loop_info64 info;
			if (!GetLoopDeviceStatus (fd, devicePath, info) || !backing.IsBacking (info))
				return LoopDetachResult::Released;

			if (ioctl (fd, LOOP_CLR_FD, 0) != 0)
			{
				if (errno == ENXIO)
					return LoopDetachResult::Released;

				// Kernels before 3.2 refuse to detach a device in use
				if (errno == EBUSY)
					return LoopDetachResult::OpenElsewhere;

				throw SystemException (SRC_POS, devicePath);
			}

			// With other openers, the kernel only marks the device for automatic detach at its last close
			if (deferred)
				return LoopDetachResult::Released;

			loop_info64 current;
			if (!GetLoopDeviceStatus (fd, devicePath, current) || !backing.IsBacking (current))
				return LoopDetachResult::Released;

			// Keep the device until the volume can be dismounted completely, changing only the flag set above
			if (!(info.lo_flags & LO_FLAGS_AUTOCLEAR))
			{
				current.lo_flags &= ~(uint32) LO_FLAGS_AUTOCLEAR;
				ioctl (fd, LOOP_SET_STATUS64, &current);
			}

			return LoopDetachResult::OpenElsewhere;
		}

		LoopDetachResult::Enum TryDetachLoopDevicePath (const string &devicePath, const string &backingFilePath, bool deferred)
		{
			struct stat devStat;
			if (stat (devicePath.c_str(), &devStat) != 0)
			{
				throw_sys_sub_if (errno != ENOENT && errno != ENOTDIR, devicePath);
				return LoopDetachResult::Released;
			}

			if (!IsLoopDevice (devStat))
				return LoopDetachResult::Released;

			// An exclusive open fails while the filesystem is mounted anywhere, including in other mount namespaces
			int fd = open (devicePath.c_str(), O_RDONLY | O_CLOEXEC | (deferred ? 0 : O_EXCL));
			if (fd == -1)
			{
				if (errno == ENOENT || errno == ENXIO || errno == ENODEV)
					return LoopDetachResult::Released;

				throw_sys_sub_if (errno != EBUSY || deferred, devicePath);

				struct stat backingStat;
				throw_sys_sub_if (stat (backingFilePath.c_str(), &backingStat) != 0, backingFilePath);

				return IsLoopDeviceBackedBy (devicePath, LoopBacking (backingStat)) ? LoopDetachResult::Claimed : LoopDetachResult::Released;
			}
			finally_do_arg (int, fd, { close (finally_arg); });

			struct stat fdStat;
			loop_info64 info;
			throw_sys_sub_if (fstat (fd, &fdStat) != 0, devicePath);

			if (!IsLoopDevice (fdStat) || !GetLoopDeviceStatus (fd, devicePath, info))
				return LoopDetachResult::Released;

			struct stat backingStat;
			throw_sys_sub_if (stat (backingFilePath.c_str(), &backingStat) != 0, backingFilePath);

			return TryDetachLoopDevice (fd, devicePath, LoopBacking (backingStat), deferred);
		}

		void ThrowLoopDeviceBusy (const string &devicePath, LoopDetachResult::Enum result)
		{
			string reason = (result == LoopDetachResult::Claimed)
				? "the volume's filesystem may still be mounted elsewhere (for example, a bind mount or a mount in another mount namespace)."
				: "another process has the volume's loop device open.";

			throw FilesystemDismountFailed (SRC_POS, "losetup", EBUSY, devicePath + ": device is busy: " + reason);
		}

		// Detaches the loop device if it is still bound to the backing file
		void DetachOwnedLoopDevice (const string &devicePath, const string &backingFilePath, bool deferred)
		{
			for (int t = 0; true; t++)
			{
				LoopDetachResult::Enum result = TryDetachLoopDevicePath (devicePath, backingFilePath, deferred);
				if (result == LoopDetachResult::Released)
					return;

				if (t > 5)
					ThrowLoopDeviceBusy (devicePath, result);

				Thread::Sleep (200);
			}
		}

		// Has the kernel detach a loop device held open by the caller at its last close, which, while device-mapper
		// holds it, comes once device-mapper releases it. Unlike LOOP_CLR_FD, which kernels before 3.2 refuse while
		// the device is in use, this works with other openers on every kernel since 2.6.25.
		bool SetLoopDeviceAutoClear (int fd)
		{
			loop_info64 info;
			Memory::Zero (&info, sizeof (info));
			if (ioctl (fd, LOOP_GET_STATUS64, &info) != 0)
				return false;

			if (info.lo_flags & LO_FLAGS_AUTOCLEAR)
				return true;

			info.lo_flags |= LO_FLAGS_AUTOCLEAR;
			return ioctl (fd, LOOP_SET_STATUS64, &info) == 0;
		}

		bool IsBlockDeviceClaimed (const string &devicePath, dev_t deviceNumber)
		{
			struct stat devStat;
			if (stat (devicePath.c_str(), &devStat) != 0 || !S_ISBLK (devStat.st_mode) || devStat.st_rdev != deviceNumber)
				return false;

			int fd = open (devicePath.c_str(), O_RDONLY | O_CLOEXEC | O_EXCL);
			if (fd == -1)
				return errno == EBUSY;

			close (fd);
			return false;
		}

		// Device-mapper devices are tagged with the serial instance number of their mount
		string GetDeviceMapperUuid (uint64 serialInstanceNumber, const string &name)
		{
			return "VERACRYPT-" + StringConverter::ToSingle (serialInstanceNumber) + "-" + name;
		}

		// Earlier versions created devices without a UUID: their dependencies must lead to the volume
		void VerifyLegacyDeviceMapperDevice (const VolumeInfo &volume, const string &name, const string &kernelName)
		{
			const string volumePath = volume.Path;
			struct stat volumeStat;
			const bool volumeFound = (stat (volumePath.c_str(), &volumeStat) == 0);
			throw_sys_sub_if (!volumeFound && errno != ENOENT && errno != ENOTDIR, volumePath);

			string current = kernelName;
			for (int depth = 0; volumeFound && depth < 8; depth++)
			{
				list <string> slaves;
				dev_t slaveNumber;
				if (!GetSysfsSlaves (current, slaves) || slaves.size() != 1
					|| !GetSysfsDeviceNumber ("/sys/class/block/" + slaves.front(), slaveNumber))
				{
					break;
				}

				const string &slave = slaves.front();

				if (S_ISBLK (volumeStat.st_mode) && volumeStat.st_rdev == slaveNumber)
					return;

				if (slave.find ("dm-") == 0)
				{
					current = slave;
					continue;
				}

				if (S_ISREG (volumeStat.st_mode) && major (slaveNumber) == LOOP_MAJOR)
				{
					const string loopPath = "/dev/" + slave;
					struct stat loopStat;

					if (stat (loopPath.c_str(), &loopStat) == 0 && S_ISBLK (loopStat.st_mode) && loopStat.st_rdev == slaveNumber
						&& IsLoopDeviceBackedBy (loopPath, LoopBacking (volumeStat)))
					{
						return;
					}
				}

				break;
			}

			// The device is left alone, and the dismount fails, until the volume is found where it was mounted from
			errno = EPERM;
			throw SystemException (SRC_POS, "/dev/mapper/" + name + ": could not verify that this device belongs to the volume. "
				"Devices created by earlier versions of VeraCrypt are verified through the path of their volume: if the volume "
				"has been moved, renamed or replaced, restore it to " + volumePath + " and try again.");
		}

		// Devices without a UUID, created by earlier versions, are included only if requested
		DeviceOwnership::Enum GetDeviceMapperOwnership (const VolumeInfo &volume, const string &name, bool includeLegacy, DeviceMapperDevice &device)
		{
			const string uuid = GetDeviceMapperUuid (volume.SerialInstanceNumber, name);
			bool nameFound = false;
			DeviceMapperDevice legacyDevice;

			DIR *sysBlock = opendir ("/sys/block");
			throw_sys_sub_if (!sysBlock, "/sys/block");
			finally_do_arg (DIR *, sysBlock, { closedir (finally_arg); });

			struct dirent *entry;
			while ((entry = readdir (sysBlock)) != nullptr)
			{
				const string kernelName = entry->d_name;
				if (kernelName.find ("dm-") != 0)
					continue;

				const string sysfsDirectory = "/sys/block/" + kernelName;
				string deviceUuid, deviceName;
				dev_t deviceNumber;

				if (!ReadSysfsAttribute (sysfsDirectory + "/dm/uuid", deviceUuid)
					|| !ReadSysfsAttribute (sysfsDirectory + "/dm/name", deviceName))
				{
					continue;
				}

				if (deviceUuid != uuid && (deviceName != name || !deviceUuid.empty() || !includeLegacy))
				{
					if (deviceName == name)
						nameFound = true;
					continue;
				}

				if (!GetSysfsDeviceNumber (sysfsDirectory, deviceNumber))
					continue;

				device.KernelName = kernelName;
				device.Name = deviceName;
				device.Number = deviceNumber;
				device.Legacy = deviceUuid.empty();

				if (!device.Legacy)
					return DeviceOwnership::Owned;

				nameFound = true;
				legacyDevice = device;
			}

			if (!legacyDevice.KernelName.empty())
			{
				VerifyLegacyDeviceMapperDevice (volume, name, legacyDevice.KernelName);
				device = legacyDevice;
				return DeviceOwnership::Owned;
			}

			return nameFound ? DeviceOwnership::Foreign : DeviceOwnership::Absent;
		}

		// Without kernel cryptography, the decrypted image <aux>/volume is attached to a loop device recorded as both devices
		bool IsAuxVolumeImageLoopDevice (const VolumeInfo &volume)
		{
			return !volume.LoopDevice.IsEmpty() && wstring (volume.LoopDevice) == wstring (volume.VirtualDevice);
		}

		string GetAuxVolumeImagePath (const VolumeInfo &volume)
		{
			return string (volume.AuxMountPoint) + FuseService::GetVolumeImagePath();
		}

		bool IsDeviceMapperDeviceOwned (const VolumeInfo &volume, const string &name, bool includeLegacy)
		{
			DeviceMapperDevice device;
			return GetDeviceMapperOwnership (volume, name, includeLegacy, device) == DeviceOwnership::Owned;
		}

		// Opens the loop device under a device-mapper device of the volume, or returns -1. The descriptor keeps
		// the loop device bound once device-mapper releases it, so that it cannot be reused in between.
		int OpenLoopDeviceUnder (const VolumeInfo &volume, const string &name)
		{
			DeviceMapperDevice device;
			if (GetDeviceMapperOwnership (volume, name, true, device) != DeviceOwnership::Owned)
				return -1;

			const string loopDevice = volume.LoopDevice;
			int fd = open (loopDevice.c_str(), O_RDONLY | O_CLOEXEC);
			if (fd == -1)
				return -1;

			bool pinned = false;
			finally_do_arg2 (int, fd, bool &, pinned, { if (!finally_arg2) close (finally_arg); });

			// Once open, it must be the device held by the device-mapper device, which must still be the same
			struct stat fdStat;
			list <string> slaves;
			dev_t slaveNumber;
			DeviceMapperDevice current;

			if (fstat (fd, &fdStat) != 0 || !IsLoopDevice (fdStat)
				|| !GetSysfsSlaves (device.KernelName, slaves) || slaves.size() != 1
				|| !GetSysfsDeviceNumber ("/sys/class/block/" + slaves.front(), slaveNumber) || slaveNumber != fdStat.st_rdev
				|| GetDeviceMapperOwnership (volume, name, true, current) != DeviceOwnership::Owned
				|| current.KernelName != device.KernelName || current.Number != device.Number)
			{
				return -1;
			}

			pinned = true;
			return fd;
		}

		void RemoveDeviceMapperDevice (const VolumeInfo &volume, const string &name, bool includeLegacy, bool deferred)
		{
			DeviceMapperDevice device;
			if (GetDeviceMapperOwnership (volume, name, includeLegacy, device) != DeviceOwnership::Owned)
				return;

			list <string> deviceArgs;
			if (device.Legacy)
			{
				deviceArgs.push_back (device.Name);
			}
			else
			{
				deviceArgs.push_back ("-u");
				deviceArgs.push_back (GetDeviceMapperUuid (volume.SerialInstanceNumber, name));
			}

			list <string> removeArgs;
			removeArgs.push_back ("remove");
			removeArgs.insert (removeArgs.end(), deviceArgs.begin(), deviceArgs.end());

			bool removeNow = !deferred;
			if (deferred)
			{
				list <string> args;
				args.push_back ("remove");
				args.push_back ("--retry");
				args.push_back ("--deferred");
				args.insert (args.end(), deviceArgs.begin(), deviceArgs.end());

				try
				{
					Process::Execute ("dmsetup", args);
				}
				catch (ExecutedProcessFailed&)
				{
					if (IsDeviceMapperDeviceOwned (volume, name, includeLegacy))
					{
						list <string> fallbackArgs;
						fallbackArgs.push_back ("remove");
						fallbackArgs.push_back ("--deferred");
						fallbackArgs.insert (fallbackArgs.end(), deviceArgs.begin(), deviceArgs.end());

						try
						{
							Process::Execute ("dmsetup", fallbackArgs);
						}
						catch (ExecutedProcessFailed&)
						{
							removeNow = true;
						}
					}
				}
			}

			if (removeNow)
			{
				for (int t = 0; true; t++)
				{
					try
					{
						Process::Execute ("dmsetup", removeArgs);
						break;
					}
					catch (ExecutedProcessFailed&)
					{
						if (!IsDeviceMapperDeviceOwned (volume, name, includeLegacy))
							break;

						if (t > 20)
						{
							const string devicePath = "/dev/mapper/" + device.Name;
							if (IsBlockDeviceClaimed (devicePath, device.Number))
							{
								throw FilesystemDismountFailed (SRC_POS, "dmsetup", EBUSY, devicePath
									+ ": device is busy: the volume's filesystem may still be mounted elsewhere (for example, a bind mount or a mount in another mount namespace).");
							}

							throw;
						}

						Thread::Sleep (100);
					}
				}
			}

			// Wait for the removal, unless it is deferred until the device is closed
			for (int t = 0; t < 20; t++)
			{
				dev_t deviceNumber;
				if (!GetSysfsDeviceNumber ("/sys/block/" + device.KernelName, deviceNumber) || deviceNumber != device.Number)
					break;

				Thread::Sleep (100);
			}
		}
	}

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

		// On Fedora 23,"losetup -f" must be called first to create a default loop device
		list <string> args;
		args.push_back ("-f");

		try
		{
			Process::Execute ("losetup", args);
		}
		catch (...) { }

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

	void CoreLinux::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		shared_ptr <VolumeInfo> volume = ResolveMountedVolume (mountedVolume);

		volume->VirtualDevice = GetOwnedVirtualDevice (*volume);
		if (volume->VirtualDevice.IsEmpty())
		{
			errno = ENXIO;
			throw SystemException (SRC_POS, wstring (volume->Path));
		}

		CoreUnix::CheckFilesystem (volume, repair);
	}

	shared_ptr <VolumeInfo> CoreLinux::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		return CoreUnix::DismountVolume (ResolveMountedVolume (mountedVolume), ignoreOpenFiles, syncVolumeInfo);
	}

	shared_ptr <VolumeInfo> CoreLinux::EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume)
	{
		return CoreUnix::EmergencyDismountVolume (ResolveMountedVolume (mountedVolume));
	}

	void CoreLinux::DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const
	{
		DismountNativeVolumeInternal (mountedVolume, false);
	}

	void CoreLinux::DismountNativeVolumeDeferred (shared_ptr <VolumeInfo> mountedVolume) const
	{
		DismountNativeVolumeInternal (mountedVolume, true);
	}

	// Releases only the objects that still belong to the volume, so that a retry after a partial dismount is safe
	void CoreLinux::DismountNativeVolumeInternal (shared_ptr <VolumeInfo> mountedVolume, bool deferred) const
	{
		const VolumeInfo &volume = *mountedVolume;

		if (IsAuxVolumeImageLoopDevice (volume))
		{
			DetachOwnedLoopDevice (volume.LoopDevice, GetAuxVolumeImagePath (volume), deferred);
			return;
		}

		const string virtualDevice = volume.VirtualDevice;
		const string mapperDirectory = "/dev/mapper/";

		if (virtualDevice.find (mapperDirectory + "veracrypt") != 0)
			throw NotApplicable (SRC_POS);

		// Top device first, then the volume's cascade layers <name>_0 ... <name>_<n-2>, any of which a partial dismount
		// may have removed. A device without a UUID named after a layer that the volume does not have, as left by a
		// failed cascade mount of an earlier version, cannot be verified and must not fail the dismount.
		const string name = virtualDevice.substr (mapperDirectory.size());
		list <string> names;
		names.push_back (name);

		size_t cipherCount = 0;
		size_t maxCipherCount = 1;
		foreach (shared_ptr <EncryptionAlgorithm> ea, EncryptionAlgorithm::GetAvailableAlgorithms())
		{
			if (ea->GetName() == volume.EncryptionAlgorithmName)
				cipherCount = ea->GetCiphers().size();

			if (ea->GetCiphers().size() > maxCipherCount)
				maxCipherCount = ea->GetCiphers().size();
		}

		// An unknown algorithm leaves all possible layers to check
		if (cipherCount == 0)
			cipherCount = maxCipherCount;

		for (size_t i = 0; i + 1 < cipherCount; i++)
			names.push_back (name + "_" + StringConverter::ToSingle ((uint32) i));

		// Device-hosted volumes have no loop device. Earlier versions recorded the host device instead.
		const bool fileHosted = !volume.LoopDevice.IsEmpty() && wstring (volume.LoopDevice) != wstring (volume.Path);

		// Hold the loop device under the volume's device-mapper devices and, while they still hold it, have the kernel
		// detach it at its last close, so that it cannot be released and reused in between. Another process holding
		// it open, which sees only the container's ciphertext, does not fail the dismount.
		int loopFd = -1;
		finally_do_arg (int *, &loopFd, { if (*finally_arg != -1) close (*finally_arg); });

		if (fileHosted)
		{
			for (list <string>::reverse_iterator i = names.rbegin(); i != names.rend() && loopFd == -1; ++i)
			{
				// Failing to hold the loop device must not keep the device-mapper devices, which hold the volume's keys.
				// One that cannot be verified makes the removal below fail.
				try
				{
					loopFd = OpenLoopDeviceUnder (volume, *i);
				}
				catch (...) { }
			}
		}

		// Already set at mount time, except by earlier versions
		if (loopFd != -1)
			SetLoopDeviceAutoClear (loopFd);

		foreach (const string &deviceName, names)
			RemoveDeviceMapperDevice (volume, deviceName, true, deferred);
	}

	// Returns the virtual device if it still belongs to the volume
	DevicePath CoreLinux::GetOwnedVirtualDevice (const VolumeInfo &volume) const
	{
		if (volume.VirtualDevice.IsEmpty())
			return DevicePath();

		if (IsAuxVolumeImageLoopDevice (volume))
		{
			const string imagePath = GetAuxVolumeImagePath (volume);
			struct stat imageStat;
			throw_sys_sub_if (stat (imagePath.c_str(), &imageStat) != 0, imagePath);

			return IsLoopDeviceBackedBy (volume.VirtualDevice, LoopBacking (imageStat)) ? volume.VirtualDevice : DevicePath();
		}

		const string virtualDevice = volume.VirtualDevice;
		const string mapperDirectory = "/dev/mapper/";

		DeviceMapperDevice device;
		if (virtualDevice.find (mapperDirectory + "veracrypt") == 0
			&& GetDeviceMapperOwnership (volume, virtualDevice.substr (mapperDirectory.size()), true, device) == DeviceOwnership::Owned)
		{
			return DevicePath (mapperDirectory + device.Name);
		}

		return DevicePath();
	}

	// The privileged service does not trust the volume information received from the client, which may be outdated
	shared_ptr <VolumeInfo> CoreLinux::ResolveMountedVolume (shared_ptr <VolumeInfo> mountedVolume) const
	{
		if (!mountedVolume || mountedVolume->AuxMountPoint.IsEmpty())
			throw ParameterIncorrect (SRC_POS);

		const DirectoryPath auxMountPoint = mountedVolume->AuxMountPoint;
		if (GetMountedFilesystems (DevicePath(), auxMountPoint).empty())
			throw MountServiceUnavailable (SRC_POS, wstring (auxMountPoint));

		shared_ptr <VolumeInfo> volume;
		try
		{
			volume = ReadAuxiliaryVolumeInfo (auxMountPoint);
		}
		catch (...)
		{
			throw MountServiceUnavailable (SRC_POS, wstring (auxMountPoint));
		}

		if (volume->SerialInstanceNumber != mountedVolume->SerialInstanceNumber
			|| volume->SlotNumber != mountedVolume->SlotNumber
			|| wstring (volume->Path) != wstring (mountedVolume->Path))
		{
			throw MountServiceUnavailable (SRC_POS, wstring (auxMountPoint));
		}

		// Unmount only a filesystem mounted from the volume's own virtual device
		volume->MountPoint = DirectoryPath();
		try
		{
			DevicePath virtualDevice = GetOwnedVirtualDevice (*volume);
			if (!virtualDevice.IsEmpty())
			{
				MountedFilesystemList mountedFilesystems = GetMountedFilesystems (virtualDevice);
				if (!mountedFilesystems.empty())
					volume->MountPoint = mountedFilesystems.front()->MountPoint;
			}
		}
		catch (...) { }

		return volume;
	}

	void CoreLinux::UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> mountedVolume) const
	{
		try
		{
			mountedVolume->VirtualDevice = GetOwnedVirtualDevice (*mountedVolume);
		}
		catch (...)
		{
			mountedVolume->VirtualDevice = DevicePath();
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

	void CoreLinux::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions, bool internalMountOnly) const
	{
		bool fsMounted = false;

		try
		{
			if (!FilesystemSupportsUnixPermissions (devicePath))
			{
				stringstream userMountOptions;
				userMountOptions << "uid=" << GetRealUserId() << ",gid=" << GetRealGroupId() << ",umask=077" << (!systemMountOptions.empty() ? "," : "");

				CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, userMountOptions.str() + systemMountOptions, internalMountOnly);
				fsMounted = true;
			}
		}
		catch (...) { }

		if (!fsMounted)
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions, internalMountOnly);
	}

	void CoreLinux::MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const
	{
		bool xts = (typeid (*volume->GetEncryptionMode()) == 
            #ifdef WOLFCRYPT_BACKEND
                        typeid (EncryptionModeWolfCryptXTS));
            #else
                        typeid (EncryptionModeXTS));
            #endif 
                bool algoNotSupported = (typeid (*volume->GetEncryptionAlgorithm()) == typeid (Kuznyechik))
			|| (typeid (*volume->GetEncryptionAlgorithm()) == typeid (CamelliaKuznyechik))
			|| (typeid (*volume->GetEncryptionAlgorithm()) == typeid (KuznyechikTwofish))
			|| (typeid (*volume->GetEncryptionAlgorithm()) == typeid (KuznyechikAES))
			|| (typeid (*volume->GetEncryptionAlgorithm()) == typeid (KuznyechikSerpentCamellia));

		if (options.NoKernelCrypto
			|| !xts
			|| algoNotSupported
			|| volume->IsEncryptionNotCompleted ()
			|| volume->GetProtectionType() == VolumeProtection::HiddenVolumeReadOnly)
		{
			throw NotApplicable (SRC_POS);
		}

		if (!SystemInfo::IsVersionAtLeast (2, 6, xts ? 24 : 20))
			throw NotApplicable (SRC_POS);

		// Without dmsetup, kernel crypto cannot be used: fall back to FUSE
		// instead of failing, as when nokernelcrypto was given.
		string dmsetupError;
		if (Process::FindSystemBinary ("dmsetup", dmsetupError).empty())
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
		bool filesystemMounted = false;

		// Tags the device-mapper devices of this mount
		const uint64 serialInstanceNumber = ReadAuxiliaryVolumeInfo (auxMountPoint)->SerialInstanceNumber;

		// Device-mapper devices whose creation was attempted, top layer first
		list <string> nativeDevNames;

		// Attach volume to loopback device if required. Through a descriptor held until the end of the mount, the loop
		// device is verified and marked for the kernel to detach it once neither that descriptor nor device-mapper
		// holds it: on failure, at dismount, and also if the device-mapper devices are removed by other means or this
		// process is killed. Another device bound to the same name is never affected.
		VolumePath volumePath = volume->GetPath();
		int loopFd = -1;
		finally_do_arg (int *, &loopFd, { if (*finally_arg != -1) close (*finally_arg); });

		if (!volumePath.IsDevice())
		{
			const string containerPath = volumePath;
			struct stat containerStat;
			throw_sys_sub_if (stat (containerPath.c_str(), &containerStat) != 0, containerPath);

			volumePath = AttachFileToLoopDevice (volumePath, options.Protection == VolumeProtection::ReadOnly);
			loopDevAttached = true;

			const string loopDevice = volumePath;
			loopFd = open (loopDevice.c_str(), O_RDONLY | O_CLOEXEC);

			bool verified = false;
			try
			{
				struct stat fdStat;
				loop_info64 info;
				verified = loopFd != -1 && fstat (loopFd, &fdStat) == 0 && IsLoopDevice (fdStat)
					&& GetLoopDeviceStatus (loopFd, loopDevice, info) && LoopBacking (containerStat).IsBacking (info)
					&& SetLoopDeviceAutoClear (loopFd);
			}
			catch (...) { }

			if (!verified)
			{
				// Detach the loop device only if it is still bound to the container
				try
				{
					TryDetachLoopDevicePath (loopDevice, containerPath, true);
				}
				catch (...) { }

				throw LoopDeviceSetupFailed (SRC_POS, wstring (volume->GetPath()));
			}
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
				dmCreateArgsBuf.CopyFrom (ConstBufferPtr ((uint8 *) dmCreateArgs.str().c_str(), dmCreateArgs.str().size()));

				// Keys
				const SecureBuffer &cipherKey = cipher.GetKey();
				secondaryKeyOffset -= cipherKey.Size();
				ConstBufferPtr secondaryKey = volume->GetEncryptionMode()->GetKey().GetRange (xts ? secondaryKeyOffset : 0, xts ? cipherKey.Size() : 16);

				SecureBuffer hexStr (3);
				for (size_t i = 0; i < cipherKey.Size(); ++i)
				{
					sprintf ((char *) hexStr.Ptr(), "%02x", (int) cipherKey[i]);
					dmCreateArgsBuf.GetRange (keyArgOffset + i * 2, 2).CopyFrom (hexStr.GetRange (0, 2));

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
				execArgs.push_back ("--uuid");
				execArgs.push_back (GetDeviceMapperUuid (serialInstanceNumber, nativeDevName.str()));
				execArgs.push_back (nativeDevName.str());

				nativeDevNames.push_front (nativeDevName.str());
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
				wstring filesystemType = options.FilesystemType;
				bool internalMountOnly = false;
				bool allowFilesystemTypeFallback = filesystemType.empty();

				ResolveNtfsKernelMountOptions (nativeDevPath, options.MountNtfsWithKernelDriver, filesystemType, internalMountOnly);
				allowFilesystemTypeFallback = allowFilesystemTypeFallback && filesystemType.empty() && !internalMountOnly;

				MountFilesystemWithFallback (nativeDevPath, *options.MountPoint,
					StringConverter::ToSingle (filesystemType),
					allowFilesystemTypeFallback,
					options.Protection == VolumeProtection::ReadOnly,
					StringConverter::ToSingle (options.FilesystemOptions),
					internalMountOnly);

				filesystemMounted = true;
			}

			// Dismounting detaches the recorded loop device, so record only one attached above
			if (loopDevAttached)
				FuseService::SendAuxDeviceInfo (auxMountPoint, nativeDevPath, volumePath);
			else
				FuseService::SendAuxDeviceInfo (auxMountPoint, nativeDevPath);
		}
		catch (...)
		{
			try
			{
				if (filesystemMounted)
					DismountFilesystem (*options.MountPoint, true);
			}
			catch (...) { }

			// Release only the objects created above. The kernel detaches the loop device once device-mapper releases it
			// and its descriptor is closed. Devices are removed by the UUID of this mount, so that one of the same name
			// that existed before is left alone.
			VolumeInfo createdVolume;
			createdVolume.SerialInstanceNumber = serialInstanceNumber;

			foreach (const string &name, nativeDevNames)
			{
				try
				{
					RemoveDeviceMapperDevice (createdVolume, name, false, false);
				}
				catch (...) { }
			}

			throw;
		}
	}

	unique_ptr <CoreBase> Core (new CoreServiceProxy <CoreLinux>);
	unique_ptr <CoreBase> CoreDirect (new CoreLinux);
}
