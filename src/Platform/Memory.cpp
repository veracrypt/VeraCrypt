/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Common/Tcdefs.h"
#include "Memory.h"
#include "Exception.h"
#include <stdlib.h>

namespace VeraCrypt
{
	void *Memory::Allocate (std::size_t size)
	{
		if (size < 1)
			throw ParameterIncorrect (SRC_POS);

		void *bufPtr = malloc (size);
		if (!bufPtr)
			throw bad_alloc();

		return bufPtr;
	}
	
	void *Memory::AllocateAligned (std::size_t size, std::size_t alignment)
	{
		if (size < 1)
			throw ParameterIncorrect (SRC_POS);
#ifdef TC_WINDOWS
		void *bufPtr = _aligned_malloc (size, alignment);
#else
		void *bufPtr = NULL;
		if (0 != posix_memalign (&bufPtr, alignment, size))
			bufPtr = NULL;
#endif
		if (!bufPtr)
			throw bad_alloc();

		return bufPtr;
	}

	int Memory::Compare (const void *memory1, size_t size1, const void *memory2, size_t size2)
	{
		if (size1 > size2)
			return 1;
		else if (size1 < size2)
			return -1;

		return memcmp (memory1, memory2, size1);
	}

	void Memory::Copy (void *memoryDestination, const void *memorySource, size_t size)
	{
		assert (memoryDestination != nullptr && memorySource != nullptr);
		memcpy (memoryDestination, memorySource, size);
	}

	void Memory::Erase (void *memory, size_t size)
	{
		burn (memory, size);
	}

	void Memory::Zero (void *memory, size_t size)
	{
		memset (memory, 0, size);
	}

	void Memory::Free (void *memory)
	{
		assert (memory != nullptr);
		free (memory);
	}
	
	void Memory::FreeAligned (void *memory)
	{
		assert (memory != nullptr);
#ifdef TC_WINDOWS
		_aligned_free (memory);
#else
		free (memory);
#endif
	}
}
