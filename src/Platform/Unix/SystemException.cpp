/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <errno.h>
#include <string.h>
#include "Platform/SerializerFactory.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace VeraCrypt
{
	SystemException::SystemException ()
		: ErrorCode (errno)
	{
	}

	SystemException::SystemException (const string &message)
		: Exception (message), ErrorCode (errno)
	{
	}

	SystemException::SystemException (const string &message, const string &subject)
		: Exception (message, StringConverter::ToWide (subject)), ErrorCode (errno)
	{
	}

	SystemException::SystemException (const string &message, const wstring &subject)
		: Exception (message, subject), ErrorCode (errno)
	{
	}
	
	void SystemException::Deserialize (shared_ptr <Stream> stream)
	{
		Exception::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("ErrorCode", ErrorCode);
	}

	bool SystemException::IsError () const
	{
		return ErrorCode != 0;
	}
	
	void SystemException::Serialize (shared_ptr <Stream> stream) const
	{
		Exception::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("ErrorCode", ErrorCode);
	}

	wstring SystemException::SystemText () const
	{
		return StringConverter::ToWide (strerror ((int) ErrorCode));
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (SystemException);
}
