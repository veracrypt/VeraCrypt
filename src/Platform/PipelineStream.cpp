/*
 Copyright (c) 2024-2025 Anton Dubenchuk.
 Modifications and additions Copyright (c) 2026 AM Crypto.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Exception.h"
#include "PipelineStream.h"

namespace VeraCrypt
{
	uint64 PipelineStream::Read (const BufferPtr &buffer)
	{
		if (ReadFailure)
			std::rethrow_exception (ReadFailure);
		// A zero-length read must not discard streams which still contain data.
		if (buffer.Size() == 0)
			return 0;

		try
		{
			while (CurrentStreamIdx < Streams.size())
			{
				uint64 readLength = Streams[CurrentStreamIdx]->Read (buffer);
				if (readLength > buffer.Size())
					throw ParameterIncorrect (SRC_POS);
				if (readLength != 0)
					return readLength;
				++CurrentStreamIdx;
			}
			return 0;
		}
		catch (...)
		{
			// A failed source may already have consumed bytes; never resume with a
			// silently truncated concatenation after a caller catches the error.
			ReadFailure = std::current_exception();
			throw;
		}
	}

	void PipelineStream::ReadCompleteBuffer (const BufferPtr &buffer)
	{
		size_t position = 0;
		while (position < buffer.Size())
		{
			uint64 readLength = Read (buffer.GetRange (position, buffer.Size() - position));
			if (readLength == 0)
				throw InsufficientData (SRC_POS);
			position += static_cast<size_t> (readLength);
		}
	}

	void PipelineStream::AddStream (shared_ptr<Stream> stream)
	{
		if (!stream || stream.get() == this)
			throw ParameterIncorrect (SRC_POS);
		Streams.push_back (stream);
	}

	void PipelineStream::Write (const ConstBufferPtr &)
	{
		throw NotApplicable (SRC_POS);
	}
}
