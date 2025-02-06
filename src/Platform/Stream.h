/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_Stream
#define TC_HEADER_Platform_Stream

#include "PlatformBase.h"
#include "Buffer.h"

namespace VeraCrypt
{
	class Stream
	{
	public:
		virtual ~Stream () { }
		virtual uint64 Read (const BufferPtr &buffer) = 0;
		virtual void ReadCompleteBuffer (const BufferPtr &buffer) = 0;
		virtual void Write (const ConstBufferPtr &data) = 0;

	protected:
		Stream () { };

	private:
		Stream (const Stream &);
		Stream &operator= (const Stream &);
	};
}

#endif // TC_HEADER_Platform_Stream
