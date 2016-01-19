/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Encryption_Crc32
#define TC_HEADER_Encryption_Crc32

#include "Platform/Platform.h"
#include "Common/Crc.h"

namespace VeraCrypt
{
	class Crc32
	{
	public:
		Crc32 () : CrcValue (0xffffFFFF) { };
		virtual ~Crc32 () { };

		uint32 Get () const { return CrcValue ^ 0xffffFFFF; }

		uint32 Process (byte data)
		{
			return CrcValue = crc_32_tab[(byte) (CrcValue ^ data)] ^ (CrcValue >> 8);
		}

		static uint32 ProcessBuffer (const ConstBufferPtr &buffer)
		{
			return ::GetCrc32 (const_cast<byte *> (buffer.Get()), static_cast<int> (buffer.Size()));
		}

	protected:
		uint32 CrcValue;

	private:
		Crc32 (const Crc32 &);
		Crc32 &operator= (const Crc32 &);
	};
}

#endif // TC_HEADER_Encryption_Crc32
