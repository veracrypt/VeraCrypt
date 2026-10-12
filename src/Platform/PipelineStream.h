/*
 Copyright (c) 2024-2025 Anton Dubenchuk.
 Modifications and additions Copyright (c) 2026 AM Crypto.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_PipelineStream
#define TC_HEADER_Platform_PipelineStream

#include "PlatformBase.h"
#include "Stream.h"
#include <exception>

namespace VeraCrypt
{
	class PipelineStream : public Stream
	{
	public:
		PipelineStream () : CurrentStreamIdx (0) { }
		~PipelineStream () {  }

		void AddStream(shared_ptr<Stream> stream);

		uint64 Read (const BufferPtr &buffer);
		void ReadCompleteBuffer (const BufferPtr &buffer);
		void Write (const ConstBufferPtr &data);

	protected:
		vector <shared_ptr<Stream>> Streams;
		std::exception_ptr ReadFailure;
		size_t CurrentStreamIdx;
	};
}

#endif // TC_HEADER_Platform_PipelineStream
