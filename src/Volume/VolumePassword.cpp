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

#include "VolumePassword.h"
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"

namespace VeraCrypt
{
	VolumePassword::VolumePassword () : PasswordSize (0)
	{
		AllocateBuffer ();
	}

	VolumePassword::~VolumePassword ()
	{
	}

	void VolumePassword::AllocateBuffer ()
	{
		if (!PasswordBuffer.IsAllocated ())
			PasswordBuffer.Allocate (MaxSize);
	}

	void VolumePassword::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		uint64 passwordSize;
		sr.Deserialize ("PasswordSize", passwordSize);
		PasswordSize = static_cast <size_t> (passwordSize);
		sr.Deserialize ("PasswordBuffer", BufferPtr (PasswordBuffer));

		Buffer wipeBuffer (128 * 1024);
		sr.Deserialize ("WipeData", wipeBuffer);
	}

	void VolumePassword::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("PasswordSize", static_cast <uint64> (PasswordSize));
		sr.Serialize ("PasswordBuffer", ConstBufferPtr (PasswordBuffer));

		// Wipe password from an eventual pipe buffer
		Buffer wipeBuffer (128 * 1024);
		wipeBuffer.Zero();
		sr.Serialize ("WipeData", ConstBufferPtr (wipeBuffer));
	}

	void VolumePassword::Set (const byte *password, size_t size)
	{
		AllocateBuffer ();

		if (size > MaxSize)
			throw PasswordTooLong (SRC_POS);

		PasswordBuffer.Erase ();
		if (size > 0)
			PasswordBuffer.CopyFrom (ConstBufferPtr (password, size));

		PasswordSize = size;
	}

	void VolumePassword::Set (const VolumePassword &password)
	{
		Set (password.DataPtr(), password.Size());
	}

	TC_SERIALIZER_FACTORY_ADD_CLASS (VolumePassword);

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (PasswordException);
}
