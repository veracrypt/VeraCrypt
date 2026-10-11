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

#ifndef TC_HEADER_Core_Unix_MountedFilesystem
#define TC_HEADER_Core_Unix_MountedFilesystem

#include "Platform/Platform.h"

namespace VeraCrypt
{
	struct MountedFilesystem
	{
	public:
#ifdef TC_MACOSX
		MountedFilesystem () : Owner (static_cast <uid_t> (-1)) { MountId[0] = MountId[1] = 0; }
		bool IsAuxiliaryMountCandidate (const string &prefix, uid_t userId, uid_t realUserId) const
		{
			const string name = MountPoint.ToBaseName();
			return name.compare (0, prefix.size(), prefix) == 0
				&& (Owner == userId || Owner == 0 || (userId == 0 && Owner == realUserId))
				&& (Type == "smbfs" || Type == "nfs" || Type == "macfuse" || Type == "osxfuse" || Type == "fusefs");
		}
		uid_t Owner;
		int32 MountId[2];
#endif
		DevicePath Device;
		DirectoryPath MountPoint;
		string Type;
	};

	typedef list < shared_ptr <MountedFilesystem> > MountedFilesystemList;
}

#endif // TC_HEADER_Core_Unix_MountedFilesystem
