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
