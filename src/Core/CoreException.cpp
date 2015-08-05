/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "CoreException.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	void ElevationFailed::Deserialize (shared_ptr <Stream> stream)
	{
		ExecutedProcessFailed::Deserialize (stream);
	}

	void ElevationFailed::Serialize (shared_ptr <Stream> stream) const
	{
		ExecutedProcessFailed::Serialize (stream);
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (CoreException);
}
