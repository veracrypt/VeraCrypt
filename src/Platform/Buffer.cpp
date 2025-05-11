/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Buffer.h"
#include "Exception.h"

namespace VeraCrypt
{
	Buffer::Buffer () : DataPtr (nullptr), DataSize (0), DataAlignment (0)
	{
	}

	Buffer::Buffer (size_t size, size_t alignment) : DataPtr (nullptr), DataSize (0), DataAlignment (0)
	{
		Allocate (size, alignment);
	}

	Buffer::~Buffer ()
	{
		if (DataPtr != nullptr)
			Free ();
	}

	void Buffer::Allocate (size_t size, size_t alignment)
	{
		if (size < 1)
			throw ParameterIncorrect (SRC_POS);

		if (DataPtr != nullptr)
		{
			if ((DataSize == size) && (DataAlignment == alignment))
				return;
			Free();
		}

		try
		{
			DataPtr = static_cast<uint8 *> ((alignment > 0)? Memory::AllocateAligned (size, alignment) : Memory::Allocate (size));
			DataSize = size;
			DataAlignment = alignment;
		}
		catch (...)
		{
			DataPtr = nullptr;
			DataSize = 0;
			DataAlignment = 0;
			throw;
		}
	}

	void Buffer::CopyFrom (const ConstBufferPtr &bufferPtr, size_t alignment)
	{
		if (!IsAllocated () || ((bufferPtr.Size()) && (DataAlignment != alignment)))
		{
			if (IsAllocated ())
				Free ();

			if (bufferPtr.Size())
				Allocate (bufferPtr.Size(), alignment);
		}
		else if (bufferPtr.Size() > DataSize)
			throw ParameterTooLarge (SRC_POS);

		if (bufferPtr.Size())
			Memory::Copy (DataPtr, bufferPtr.Get(), bufferPtr.Size());
	}

	void Buffer::Erase ()
	{
		if (DataSize > 0)
			burn (DataPtr, DataSize);
	}

	void Buffer::Free ()
	{
		if (DataPtr == nullptr)
			throw NotInitialized (SRC_POS);

		if (DataAlignment > 0)
			Memory::FreeAligned (DataPtr);
		else
			Memory::Free (DataPtr);
		DataPtr = nullptr;
		DataSize = 0;
		DataAlignment = 0;
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

	SecureBuffer::SecureBuffer (size_t size, size_t alignment)
	{
		Allocate (size, alignment);
	}

	SecureBuffer::~SecureBuffer ()
	{
		if (DataPtr != nullptr && DataSize != 0)
			Free ();
	}

	void SecureBuffer::Allocate (size_t size, size_t alignment)
	{
		Buffer::Allocate (size, alignment);
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
