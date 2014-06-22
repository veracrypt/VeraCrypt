/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_WINDOWS
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#endif

#include "RandomNumberGenerator.h"
#include "Volume/Crc32.h"

namespace VeraCrypt
{
	void RandomNumberGenerator::AddSystemDataToPool (bool fast)
	{
		SecureBuffer buffer (PoolSize);

#ifdef TC_WINDOWS
#ifndef DEBUG
		throw NotImplemented (SRC_POS);
#endif
#else
		int urandom = open ("/dev/urandom", O_RDONLY);
		throw_sys_sub_if (urandom == -1, L"/dev/urandom");
		finally_do_arg (int, urandom, { close (finally_arg); });

		throw_sys_sub_if (read (urandom, buffer, buffer.Size()) == -1, L"/dev/urandom");
		AddToPool (buffer);

		if (!fast)
		{
			// Read all bytes available in /dev/random up to buffer size
			int random = open ("/dev/random", O_RDONLY | O_NONBLOCK);
			throw_sys_sub_if (random == -1, L"/dev/random");
			finally_do_arg (int, random, { close (finally_arg); });

			throw_sys_sub_if (read (random, buffer, buffer.Size()) == -1 && errno != EAGAIN, L"/dev/random");
			AddToPool (buffer);
		}
#endif
	}

	void RandomNumberGenerator::AddToPool (const ConstBufferPtr &data)
	{
		if (!Running)
			throw NotInitialized (SRC_POS);

		ScopeLock lock (AccessMutex);

		for (size_t i = 0; i < data.Size(); ++i)
		{
			Pool[WriteOffset++] += data[i];

			if (WriteOffset >= PoolSize)
				WriteOffset = 0;

			if (++BytesAddedSincePoolHashMix >= MaxBytesAddedBeforePoolHashMix)
				HashMixPool();
		}
	}

	void RandomNumberGenerator::GetData (const BufferPtr &buffer, bool fast)
	{
		if (!Running)
			throw NotInitialized (SRC_POS);

		if (buffer.Size() > PoolSize)
			throw ParameterIncorrect (SRC_POS);

		ScopeLock lock (AccessMutex);

		// Poll system for data
		AddSystemDataToPool (fast);
		HashMixPool();

		// Transfer bytes from pool to output buffer
		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			buffer[i] += Pool[ReadOffset++];

			if (ReadOffset >= PoolSize)
				ReadOffset = 0;
		}

		// Invert and mix the pool
		for (size_t i = 0; i < Pool.Size(); ++i)
		{
			Pool[i] = ~Pool[i];
		}

		AddSystemDataToPool (true);
		HashMixPool();

		// XOR the current pool content into the output buffer to prevent pool state leaks
		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			buffer[i] ^= Pool[ReadOffset++];

			if (ReadOffset >= PoolSize)
				ReadOffset = 0;
		}
	}

	shared_ptr <Hash> RandomNumberGenerator::GetHash ()
	{
		ScopeLock lock (AccessMutex);
		return PoolHash;
	}

	void RandomNumberGenerator::HashMixPool ()
	{
		BytesAddedSincePoolHashMix = 0;

		for (size_t poolPos = 0; poolPos < Pool.Size(); )
		{
			// Compute the message digest of the entire pool using the selected hash function
			SecureBuffer digest (PoolHash->GetDigestSize());
			PoolHash->ProcessData (Pool);
			PoolHash->GetDigest (digest);

			// Add the message digest to the pool
			for (size_t digestPos = 0; digestPos < digest.Size() && poolPos < Pool.Size(); ++digestPos)
			{
				Pool[poolPos++] += digest[digestPos];
			}
		}
	}

	void RandomNumberGenerator::SetHash (shared_ptr <Hash> hash)
	{
		ScopeLock lock (AccessMutex);
		PoolHash = hash;
	}

	void RandomNumberGenerator::Start ()
	{
		ScopeLock lock (AccessMutex);

		if (IsRunning())
			return;

		BytesAddedSincePoolHashMix = 0;
		ReadOffset = 0;
		WriteOffset = 0;
		Running = true;
		EnrichedByUser = false;

		Pool.Allocate (PoolSize);
		Test();

		if (!PoolHash)
		{
			// First hash algorithm is the default one
			PoolHash = Hash::GetAvailableAlgorithms().front();
		}

		AddSystemDataToPool (true);
	}

	void RandomNumberGenerator::Stop ()
	{		
		ScopeLock lock (AccessMutex);

		if (Pool.IsAllocated())
			Pool.Free ();

		PoolHash.reset();

		EnrichedByUser = false;
		Running = false;
	}

	void RandomNumberGenerator::Test ()
	{
		shared_ptr <Hash> origPoolHash = PoolHash;
		PoolHash.reset (new Ripemd160());

		Pool.Zero();
		Buffer buffer (1);
		for (size_t i = 0; i < PoolSize * 10; ++i)
		{
			buffer[0] = (byte) i;
			AddToPool (buffer);
		}

		if (Crc32::ProcessBuffer (Pool) != 0x2de46d17)
			throw TestFailed (SRC_POS);

		buffer.Allocate (PoolSize);
		buffer.CopyFrom (PeekPool());
		AddToPool (buffer);

		if (Crc32::ProcessBuffer (Pool) != 0xcb88e019)
			throw TestFailed (SRC_POS);

		PoolHash = origPoolHash;
	}

	Mutex RandomNumberGenerator::AccessMutex;
	size_t RandomNumberGenerator::BytesAddedSincePoolHashMix;
	bool RandomNumberGenerator::EnrichedByUser;
	SecureBuffer RandomNumberGenerator::Pool;
	shared_ptr <Hash> RandomNumberGenerator::PoolHash;
	size_t RandomNumberGenerator::ReadOffset;
	bool RandomNumberGenerator::Running = false;
	size_t RandomNumberGenerator::WriteOffset;
}
