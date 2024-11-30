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

#include "Exception.h"
#include "PipelineStream.h"

using namespace std;

namespace VeraCrypt
{
	
	uint64 PipelineStream::Read (const BufferPtr &buffer)
	{
		if (streams.size() < 1 || CurrentStreamIdx >= streams.size()) {
			return 0;
		}

		auto s = streams.at(CurrentStreamIdx);
		
		size_t read = s->Read(buffer);
		if (read != 0) {
			return read;
		}

		bool hasMoreStreams = CurrentStreamIdx + 1 < streams.size();
		while (hasMoreStreams) {
			CurrentStreamIdx++;
			s = streams.at(CurrentStreamIdx);
			read = s->Read(buffer);
			if (read != 0) {
				return read;
			}
			hasMoreStreams = CurrentStreamIdx + 1 < streams.size();
		}
		
		return read;
	}

	void PipelineStream::ReadCompleteBuffer (const BufferPtr &buffer)
	{
		if (Read (buffer) != buffer.Size())
			throw InsufficientData (SRC_POS);
	}

	void PipelineStream::AddStream(shared_ptr<Stream> stream) {
		streams.push_back(stream);
	}

	void PipelineStream::Write (const ConstBufferPtr &data)
	{
		throw std::domain_error("write is not supported for pipeline stream");
	}
}
