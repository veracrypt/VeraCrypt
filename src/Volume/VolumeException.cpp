/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "VolumeException.h"
#include "Platform/SerializerFactory.h"

namespace TrueCrypt
{
	// Do not inline the constructors to ensure this module is not optimized away
	VolumeException::VolumeException ()
	{
	}

	VolumeException::VolumeException (const string &message) : Exception (message)
	{
	}
	
	VolumeException::VolumeException (const string &message, const wstring &subject) : Exception (message, subject)
	{
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (VolumeException);
}
