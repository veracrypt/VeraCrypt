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

#ifndef TC_HEADER_Platform_MemoryStream
#define TC_HEADER_Platform_MemoryStream

#include "PlatformBase.h"
#include "Stream.h"

namespace VeraCrypt
{
	class MemoryStream : public Stream
	{
	public:
		MemoryStream () : ReadPosition (0) { }
		MemoryStream (const ConstBufferPtr &data);
		virtual ~MemoryStream () { }

		operator ConstBufferPtr () const { return ConstBufferPtr (&Data[0], Data.size()); }

		virtual uint64 Read (const BufferPtr &buffer);
		virtual void ReadCompleteBuffer (const BufferPtr &buffer);
		virtual void Write (const ConstBufferPtr &data);

	protected:
		vector <uint8> Data;
		size_t ReadPosition;
	};
}

#endif // TC_HEADER_Platform_MemoryStream
