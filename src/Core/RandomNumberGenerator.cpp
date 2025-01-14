/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_WINDOWS
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#ifndef ERESTART
#define ERESTART EINTR
#endif

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

			// ensure that we have read at least 32 bytes from /dev/random before allowing it to fail gracefully
			while (true)
			{
				int rndCount = read (random, buffer, buffer.Size());
				throw_sys_sub_if ((rndCount == -1) && errno != EAGAIN && errno != ERESTART && errno != EINTR, L"/dev/random");
				if (rndCount != -1) {
					// We count returned bytes until 32-bytes threshold reached
					if (DevRandomBytesCount < 32)
						DevRandomBytesCount += rndCount;
					break;
				}
				else if (DevRandomBytesCount >= 32) {
					// allow /dev/random to fail gracefully since we have enough bytes
					break;
				}
				else {
					// wait 250ms before querying /dev/random again
					::usleep (250 * 1000);
				}
			}
			
			AddToPool (buffer);
			
			/* use JitterEntropy library to get good quality random bytes based on CPU timing jitter */
			if (JitterRngCtx)
			{
				ssize_t rndLen = jent_read_entropy (JitterRngCtx, (char*) buffer.Ptr(), buffer.Size());
				if (rndLen > 0)
				{
					AddToPool (buffer);
				}
			}
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

	void RandomNumberGenerator::GetData (const BufferPtr &buffer, bool fast, bool allowAnyLength)
	{
		if (!Running)
			throw NotInitialized (SRC_POS);

		if (!allowAnyLength && (buffer.Size() > PoolSize))
			throw ParameterIncorrect (SRC_POS);

		ScopeLock lock (AccessMutex);
		size_t bufferLen = buffer.Size(), loopLen;
		uint8* pbBuffer = buffer.Get();
		
		// Initialize JitterEntropy RNG for this call
		if (0 == jent_entropy_init ())
		{
			JitterRngCtx = jent_entropy_collector_alloc (1, 0);
		}

		// Poll system for data
		AddSystemDataToPool (fast);
		HashMixPool();

		while (bufferLen > 0)
		{
			if (bufferLen > PoolSize)
			{
				loopLen = PoolSize;
				bufferLen -= PoolSize;
			}
			else
			{
				loopLen = bufferLen;
				bufferLen = 0;
			}

			// Transfer bytes from pool to output buffer
			for (size_t i = 0; i < loopLen; ++i)
			{
				pbBuffer[i] += Pool[ReadOffset++];

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
			for (size_t i = 0; i < loopLen; ++i)
			{
				pbBuffer[i] ^= Pool[ReadOffset++];

				if (ReadOffset >= PoolSize)
					ReadOffset = 0;
			}

			pbBuffer += loopLen;
		}
		
		if (JitterRngCtx)
		{
			jent_entropy_collector_free (JitterRngCtx);
			JitterRngCtx = NULL;
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
		size_t digestSize = PoolHash->GetDigestSize();
		size_t poolSize = Pool.Size();
		// pool size must be multiple of digest size
		// this is always the case with default pool size value (320 bytes)
		if (poolSize % digestSize)
			throw AssertionFailed (SRC_POS);

		for (size_t poolPos = 0; poolPos < poolSize; poolPos += digestSize)
		{
			// Compute the message digest of the entire pool using the selected hash function
			SecureBuffer digest (digestSize);
			PoolHash->Init();
			PoolHash->ProcessData (Pool);
			PoolHash->GetDigest (digest);

			/* XOR the resultant message digest to the pool at the poolIndex position. */
			/* this matches the documentation: https://veracrypt.fr/en/Random%20Number%20Generator.html */
			for (size_t digestIndex = 0; digestIndex < digestSize; digestIndex++)
			{
				Pool [poolPos + digestIndex] ^= digest [digestIndex];
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

		Pool.Allocate (PoolSize, 16);
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
		DevRandomBytesCount = 0;
	}

	void RandomNumberGenerator::Test ()
	{
		shared_ptr <Hash> origPoolHash = PoolHash;
	    #ifndef WOLFCRYPT_BACKEND
                PoolHash.reset (new Blake2s());
            #else
                PoolHash.reset (new Sha256());
            #endif

		Pool.Zero();
		Buffer buffer (1);
		for (size_t i = 0; i < PoolSize * 10; ++i)
		{
			buffer[0] = (uint8) i;
			AddToPool (buffer);
		}

	    #ifndef WOLFCRYPT_BACKEND
 		if (Crc32::ProcessBuffer (Pool) != 0x9c743238)
            #else
                if (Crc32::ProcessBuffer (Pool) != 0xac95ac1a)
            #endif
		        throw TestFailed (SRC_POS);

		buffer.Allocate (PoolSize);
		buffer.CopyFrom (PeekPool());
		AddToPool (buffer);

	    #ifndef WOLFCRYPT_BACKEND
                if (Crc32::ProcessBuffer (Pool) != 0xd2d09c8d)
            #else
                if (Crc32::ProcessBuffer (Pool) != 0xb79f3c12)
            #endif
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
	struct rand_data *RandomNumberGenerator::JitterRngCtx = NULL;
	int RandomNumberGenerator::DevRandomBytesCount = 0;
}
