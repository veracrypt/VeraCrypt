/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
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
		DevicePath Device;
		DirectoryPath MountPoint;
		string Type;
	};

	typedef list < shared_ptr <MountedFilesystem> > MountedFilesystemList;
}

#endif // TC_HEADER_Core_Unix_MountedFilesystem
