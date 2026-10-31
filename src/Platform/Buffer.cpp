/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Buffer.h"
#include "Exception.h"
#ifdef TC_UNIX
#include <set>
#include <sys/mman.h>
#include <unistd.h>
#include "ForEach.h"
#include "Mutex.h"
#endif

namespace VeraCrypt
{
#ifdef TC_UNIX
	// Secure buffers occupy whole pages of their own, which are locked in memory
	// and excluded from core dumps. Unlocking or including the pages again when a
	// buffer is freed cannot then affect another allocation.
	struct SecureBufferList
	{
		Mutex ListMutex;
		set <SecureBuffer *> Buffers;
	};

	static SecureBufferList &GetSecureBufferList ()
	{
		// Never destroyed: buffers may be freed after static destructors have run
		static SecureBufferList *list = new SecureBufferList;
		return *list;
	}

	static size_t GetPageSize ()
	{
		long pageSize = sysconf (_SC_PAGESIZE);
		return pageSize > 0 ? (size_t) pageSize : 4096;
	}

	static void ExcludeFromCoreDump (void *memory, size_t size, bool exclude)
	{
#if defined (MADV_DONTDUMP)
		madvise (memory, size, exclude ? MADV_DONTDUMP : MADV_DODUMP);
#elif defined (MADV_NOCORE)
		madvise (memory, size, exclude ? MADV_NOCORE : MADV_CORE);
#else
		(void) memory; (void) size; (void) exclude;
#endif
	}
#endif

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

	SecureBuffer::SecureBuffer (size_t size, size_t alignment) : AllocatedSize (0), Locked (false)
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
#ifdef TC_UNIX
		if (size < 1)
			throw ParameterIncorrect (SRC_POS);

		if (DataPtr != nullptr)
		{
			if ((DataSize == size) && (DataAlignment == alignment))
				return;
			Free();
		}

		const size_t pageSize = GetPageSize();
		if (size > ((size_t) -1) - pageSize)
			throw ParameterTooLarge (SRC_POS);

		const size_t allocatedSize = (size + pageSize - 1) / pageSize * pageSize;
		// Alignments are powers of two: the larger one satisfies both
		uint8 *memory = static_cast <uint8 *> (Memory::AllocateAligned (allocatedSize, alignment > pageSize ? alignment : pageSize));

		// Locking fails if RLIMIT_MEMLOCK is exceeded; the buffer is still usable
		Locked = mlock (memory, allocatedSize) == 0;
		ExcludeFromCoreDump (memory, allocatedSize, true);

		DataPtr = memory;
		DataSize = size;
		DataAlignment = alignment;
		AllocatedSize = allocatedSize;

		SecureBufferList &list = GetSecureBufferList();
		ScopeLock lock (list.ListMutex);
		list.Buffers.insert (this);
#else
		Buffer::Allocate (size, alignment);
#endif
	}

	void SecureBuffer::Free ()
	{
		if (DataPtr == nullptr)
			throw NotInitialized (SRC_POS);

#ifdef TC_UNIX
		{
			SecureBufferList &list = GetSecureBufferList();
			ScopeLock lock (list.ListMutex);
			list.Buffers.erase (this);
		}

		burn (DataPtr, AllocatedSize);
		ExcludeFromCoreDump (DataPtr, AllocatedSize, false);
		if (Locked)
			munlock (DataPtr, AllocatedSize);

		Memory::FreeAligned (DataPtr);
		DataPtr = nullptr;
		DataSize = 0;
		DataAlignment = 0;
		AllocatedSize = 0;
		Locked = false;
#else
		Erase ();
		Buffer::Free ();
#endif
	}

	void SecureBuffer::LockAllAfterFork ()
	{
#ifdef TC_UNIX
		SecureBufferList &list = GetSecureBufferList();
		ScopeLock lock (list.ListMutex);

		foreach (SecureBuffer *buffer, list.Buffers)
			buffer->Locked = mlock (buffer->DataPtr, buffer->AllocatedSize) == 0;
#endif
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
