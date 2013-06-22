/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Buffer.h"
#include "Exception.h"

namespace TrueCrypt
{
	Buffer::Buffer () : DataPtr (nullptr), DataSize (0)
	{
	}

	Buffer::Buffer (size_t size) : DataPtr (nullptr), DataSize (0)
	{
		Allocate (size);
	}

	Buffer::~Buffer ()
	{
		if (DataPtr != nullptr)
			Free ();
	}

	void Buffer::Allocate (size_t size)
	{
		if (size < 1)
			throw ParameterIncorrect (SRC_POS);

		if (DataPtr != nullptr)
		{
			if (DataSize == size)
				return;
			Free();
		}

		try
		{
			DataPtr = static_cast<byte *> (Memory::Allocate (size));
			DataSize = size;
		}
		catch (...)
		{
			DataPtr = nullptr;
			DataSize = 0;
			throw;
		}
	}

	void Buffer::CopyFrom (const ConstBufferPtr &bufferPtr)
	{
		if (!IsAllocated ())
			Allocate (bufferPtr.Size());
		else if (bufferPtr.Size() > DataSize)
			throw ParameterTooLarge (SRC_POS);

		Memory::Copy (DataPtr, bufferPtr.Get(), bufferPtr.Size());
	}

	void Buffer::Erase ()
	{
		if (DataSize > 0)
			Memory::Erase (DataPtr, DataSize);
	}

	void Buffer::Free ()
	{
		if (DataPtr == nullptr)
			throw NotInitialized (SRC_POS);

		Memory::Free (DataPtr);
		DataPtr = nullptr;
		DataSize = 0;
	}

	BufferPtr Buffer::GetRange (size_t offset, size_t size) const
	{
		if (offset + size > DataSize)
			throw ParameterIncorrect (SRC_POS);

		return BufferPtr (DataPtr + offset, size);
	}
	
	void Buffer::Zero ()
	{
		if (DataSize > 0)
			Memory::Zero (DataPtr, DataSize);
	}

	SecureBuffer::SecureBuffer (size_t size)
	{
		Allocate (size);
	}

	SecureBuffer::~SecureBuffer ()
	{
		if (DataPtr != nullptr && DataSize != 0)
			Free ();
	}

	void SecureBuffer::Allocate (size_t size)
	{
		Buffer::Allocate (size);
	}

	void SecureBuffer::Free ()
	{
		if (DataPtr == nullptr)
			throw NotInitialized (SRC_POS);

		Erase ();
		Buffer::Free ();
	}

	void BufferPtr::CopyFrom (const ConstBufferPtr &bufferPtr) const
	{
		if (bufferPtr.Size() > DataSize)
			throw ParameterTooLarge (SRC_POS);

		Memory::Copy (DataPtr, bufferPtr.Get(), bufferPtr.Size());
	}

	BufferPtr BufferPtr::GetRange (size_t offset, size_t size) const
	{
		if (offset + size > DataSize)
			throw ParameterIncorrect (SRC_POS);

		return BufferPtr (DataPtr + offset, size);
	}

	ConstBufferPtr ConstBufferPtr::GetRange (size_t offset, size_t size) const
	{
		if (offset + size > DataSize)
			throw ParameterIncorrect (SRC_POS);

		return ConstBufferPtr (DataPtr + offset, size);
	}
}
