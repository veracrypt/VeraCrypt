/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Volume_VolumeExceptions
#define TC_HEADER_Volume_VolumeExceptions

#include "Platform/Platform.h"

namespace TrueCrypt
{
	struct VolumeException : public Exception
	{
	protected:
		VolumeException ();
		VolumeException (const string &message);
		VolumeException (const string &message, const wstring &subject);
	};

#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,VolumeException)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION (HigherVersionRequired); \
	TC_EXCEPTION (KeyfilePathEmpty); \
	TC_EXCEPTION (MissingVolumeData); \
	TC_EXCEPTION (MountedVolumeInUse); \
	TC_EXCEPTION (UnsupportedSectorSize); \
	TC_EXCEPTION (VolumeEncryptionNotCompleted); \
	TC_EXCEPTION (VolumeHostInUse); \
	TC_EXCEPTION (VolumeProtected); \
	TC_EXCEPTION (VolumeReadOnly);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION
}

#endif // TC_HEADER_Volume_VolumeExceptions
