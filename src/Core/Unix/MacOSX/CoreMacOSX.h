/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Core_CoreMacOSX
#define TC_HEADER_Core_CoreMacOSX

#include "System.h"
#include "Core/Unix/FreeBSD/CoreFreeBSD.h"

namespace VeraCrypt
{
	class CoreMacOSX : public CoreFreeBSD
	{
	public:
		CoreMacOSX ();
		virtual ~CoreMacOSX ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const;
		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false);
		virtual string GetDefaultMountPointPrefix () const { return "/Volumes/veracrypt"; }

	protected:
		virtual void MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const;

	private:
		CoreMacOSX (const CoreMacOSX &);
		CoreMacOSX &operator= (const CoreMacOSX &);
	};
}

#endif // TC_HEADER_Core_CoreMacOSX
