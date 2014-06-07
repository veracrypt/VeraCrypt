/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Core_CoreUnix
#define TC_HEADER_Core_CoreUnix

#include "System.h"
#include "Platform/Unix/Process.h"
#include "Core/CoreBase.h"
#include "Core/Unix/MountedFilesystem.h"

namespace TrueCrypt
{
	class CoreUnix : public CoreBase
	{
	public:
		CoreUnix ();
		virtual ~CoreUnix ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const; 
		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const;
		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false);
		virtual bool FilesystemSupportsLargeFiles (const FilePath &filePath) const;
		virtual DirectoryPath GetDeviceMountPoint (const DevicePath &devicePath) const;
		virtual uint32 GetDeviceSectorSize (const DevicePath &devicePath) const;
		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const;
		virtual int GetOSMajorVersion () const { throw NotApplicable (SRC_POS); }
		virtual int GetOSMinorVersion () const { throw NotApplicable (SRC_POS); }
		virtual VolumeInfoList GetMountedVolumes (const VolumePath &volumePath = VolumePath()) const;
		virtual bool IsDevicePresent (const DevicePath &device) const { throw NotApplicable (SRC_POS); }
		virtual bool IsInPortableMode () const { return false; }
		virtual bool IsMountPointAvailable (const DirectoryPath &mountPoint) const;
		virtual bool IsOSVersion (int major, int minor) const { throw NotApplicable (SRC_POS); }
		virtual bool IsOSVersionLower (int major, int minor) const { throw NotApplicable (SRC_POS); }
		virtual bool IsPasswordCacheEmpty () const { throw NotApplicable (SRC_POS); }
		virtual bool HasAdminPrivileges () const { return getuid() == 0 || geteuid() == 0; }
		virtual VolumeSlotNumber MountPointToSlotNumber (const DirectoryPath &mountPoint) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options);
		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const;
		virtual DirectoryPath SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const;
		virtual void WipePasswordCache () const { throw NotApplicable (SRC_POS); }

	protected:
		virtual DevicePath AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const { throw NotApplicable (SRC_POS); }
		virtual void DetachLoopDevice (const DevicePath &devicePath) const { throw NotApplicable (SRC_POS); }
		virtual void DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const { throw NotApplicable (SRC_POS); }
		virtual bool FilesystemSupportsUnixPermissions (const DevicePath &devicePath) const;
		virtual string GetDefaultMountPointPrefix () const;
		virtual string GetFuseMountDirPrefix () const { return ".veracrypt_aux_mnt"; }
		virtual MountedFilesystemList GetMountedFilesystems (const DevicePath &devicePath = DevicePath(), const DirectoryPath &mountPoint = DirectoryPath()) const = 0;
		virtual uid_t GetRealUserId () const;
		virtual gid_t GetRealGroupId () const;
		virtual string GetTempDirectory () const;
		virtual void MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const;
		virtual void MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const;
		virtual void MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const { throw NotApplicable (SRC_POS); }
		
	private:
		CoreUnix (const CoreUnix &);
		CoreUnix &operator= (const CoreUnix &);
	};
}

#endif // TC_HEADER_Core_CoreUnix
