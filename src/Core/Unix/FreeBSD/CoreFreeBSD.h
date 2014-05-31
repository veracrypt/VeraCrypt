/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Core_CoreFreeBSD
#define TC_HEADER_Core_CoreFreeBSD

#include "System.h"
#include "Core/Unix/CoreUnix.h"

namespace TrueCrypt
{
	class CoreFreeBSD : public CoreUnix
	{
	public:
		CoreFreeBSD ();
		virtual ~CoreFreeBSD ();

		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const; 

	protected:
		virtual DevicePath AttachFileToLoopDevice (const FilePath &filePath, bool readOnly) const;
		virtual void DetachLoopDevice (const DevicePath &devicePath) const;
		virtual MountedFilesystemList GetMountedFilesystems (const DevicePath &devicePath = DevicePath(), const DirectoryPath &mountPoint = DirectoryPath()) const;
		virtual void MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const;

	private:
		CoreFreeBSD (const CoreFreeBSD &);
		CoreFreeBSD &operator= (const CoreFreeBSD &);
	};
}

#endif // TC_HEADER_Core_CoreFreeBSD
