/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_CoreLinux
#define TC_HEADER_Core_CoreLinux

#include "System.h"
#include "Core/Unix/CoreUnix.h"

namespace VeraCrypt
{
	class CoreLinux : public CoreUnix
	{
	public:
		CoreLinux ();
		virtual ~CoreLinux ();

		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const; 

	protected:
		virtual DevicePath AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const;
		virtual void DetachLoopDevice (const DevicePath &devicePath) const;
		virtual void DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const;
		virtual MountedFilesystemList GetMountedFilesystems (const DevicePath &devicePath = DevicePath(), const DirectoryPath &mountPoint = DirectoryPath()) const;
		virtual void MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const;
		virtual void MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const;

	private:
		CoreLinux (const CoreLinux &);
		CoreLinux &operator= (const CoreLinux &);
	};
}

#endif // TC_HEADER_Core_CoreLinux
