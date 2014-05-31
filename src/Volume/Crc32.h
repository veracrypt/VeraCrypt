/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_Crc32
#define TC_HEADER_Encryption_Crc32

#include "Platform/Platform.h"
#include "Common/Crc.h"

namespace TrueCrypt
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
