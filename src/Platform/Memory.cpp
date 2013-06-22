/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Common/Tcdefs.h"
#include "Memory.h"
#include "Exception.h"

namespace TrueCrypt
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
}
