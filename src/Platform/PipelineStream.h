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

#ifndef TC_HEADER_Platform_PipelineStream
#define TC_HEADER_Platform_PipelineStream

#include "PlatformBase.h"
#include "Stream.h"

namespace VeraCrypt
{
	class PipelineStream : public Stream
	{
	public:
		PipelineStream () :  streams(), ReadPosition (0), CurrentStreamIdx(0) { }
		~PipelineStream () {  }

		void AddStream(shared_ptr<Stream> stream);

		uint64 Read (const BufferPtr &buffer);
		void ReadCompleteBuffer (const BufferPtr &buffer);
		void Write (const ConstBufferPtr &data);

	protected:
		vector <shared_ptr<Stream>> streams;
		size_t ReadPosition;
		size_t CurrentStreamIdx;
	};
}

#endif // TC_HEADER_Platform_PipelineStream
