/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Exception.h"
#include "SerializerFactory.h"

namespace TrueCrypt
{
	void Exception::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		sr.Deserialize ("Message", Message);
		sr.Deserialize ("Subject", Subject);
	}

	void Exception::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("Message", Message);
		sr.Serialize ("Subject", Subject);
	}

	void ExecutedProcessFailed::Deserialize (shared_ptr <Stream> stream)
	{
		Exception::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("Command", Command);
		sr.Deserialize ("ExitCode", ExitCode);
		sr.Deserialize ("ErrorOutput", ErrorOutput);
	}

	void ExecutedProcessFailed::Serialize (shared_ptr <Stream> stream) const
	{
		Exception::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("Command", Command);
		sr.Serialize ("ExitCode", ExitCode);
		sr.Serialize ("ErrorOutput", ErrorOutput);
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (Exception);
}
