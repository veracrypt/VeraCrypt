/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_MemoryStream
#define TC_HEADER_Platform_MemoryStream

#include "PlatformBase.h"
#include "Stream.h"

namespace TrueCrypt
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
		vector <byte> Data;
		size_t ReadPosition;
	};
}

#endif // TC_HEADER_Platform_MemoryStream
