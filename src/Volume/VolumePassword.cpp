/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "VolumePassword.h"
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"

namespace VeraCrypt
{
	VolumePassword::VolumePassword () : PasswordSize (0), Unportable (false)
	{
		AllocateBuffer ();
	}

	VolumePassword::VolumePassword (const char *password, size_t size)
	{
		Set ((const byte *) password, size);
	}

	VolumePassword::VolumePassword (const byte *password, size_t size)
	{
		Set (password, size);
	}

	VolumePassword::VolumePassword (const wchar_t *password, size_t charCount)
	{
		Set (password, charCount);
	}

	VolumePassword::VolumePassword (const wstring &password)
	{
		Set (password.c_str(), password.size());
	}

	VolumePassword::~VolumePassword ()
	{
	}

	void VolumePassword::AllocateBuffer ()
	{
		if (!PasswordBuffer.IsAllocated ())
			PasswordBuffer.Allocate (MaxSize);
	}

	void VolumePassword::CheckPortability () const
	{
		if (Unportable || !IsPortable())
			throw UnportablePassword (SRC_POS);
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

	bool VolumePassword::IsPortable () const
	{
		for (size_t i = 0; i < PasswordSize; i++)
		{
			if (PasswordBuffer[i] >= 0x7f || PasswordBuffer[i] < 0x20)
				return false;
		}
		return true;
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
		
		PasswordBuffer.CopyFrom (ConstBufferPtr (password, size));
		PasswordSize = size;

		Unportable = !IsPortable();
	}
	
	void VolumePassword::Set (const wchar_t *password, size_t charCount)
	{
		if (charCount > MaxSize)
			throw PasswordTooLong (SRC_POS);

		union Conv
		{
			byte b[sizeof (wchar_t)];
			wchar_t c;
		};

		Conv conv;
		conv.c = L'A';
		
		int lsbPos = -1;
		for (size_t i = 0; i < sizeof (conv.b); ++i)
		{
			if (conv.b[i] == L'A')
			{
				lsbPos = i;
				break;
			}
		}

		if (lsbPos == -1)
			throw ParameterIncorrect (SRC_POS);

		bool unportable = false;
		byte passwordBuf[MaxSize];
		for (size_t i = 0; i < charCount; ++i)
		{
			conv.c = password[i];
			passwordBuf[i] = conv.b[lsbPos];
			for (int j = 0; j < (int) sizeof (wchar_t); ++j)
			{
				if (j != lsbPos && conv.b[j] != 0)
					unportable = true;
			}
		}
		
		Set (passwordBuf, charCount);
		
		if (unportable)
			Unportable = true;
	}

	void VolumePassword::Set (const ConstBufferPtr &password)
	{
		Set (password, password.Size());
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
