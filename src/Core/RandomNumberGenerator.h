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

#ifndef TC_HEADER_Core_RandomNumberGenerator
#define TC_HEADER_Core_RandomNumberGenerator

#include "Platform/Platform.h"
#include "Volume/Hash.h"
#include "Common/Random.h"
#include "Crypto/jitterentropy.h"

namespace VeraCrypt
{
	class RandomNumberGenerator
	{
	public:
		static void AddToPool (const ConstBufferPtr &buffer);
		static void GetData (const BufferPtr &buffer, bool allowAnyLength = false) { GetData (buffer, false, allowAnyLength); }
		static void GetDataFast (const BufferPtr &buffer, bool allowAnyLength = false) { GetData (buffer, true, allowAnyLength); }
		static shared_ptr <Hash> GetHash ();
		static bool IsEnrichedByUser () { return EnrichedByUser; }
		static bool IsRunning () { return Running; }
		static ConstBufferPtr PeekPool () { return Pool; }
		static void SetEnrichedByUserStatus (bool enriched) { EnrichedByUser = enriched; }
		static void SetHash (shared_ptr <Hash> hash);
		static void Start ();
		static void Stop ();

		static const size_t PoolSize = RNG_POOL_SIZE;

	protected:
		static void AddSystemDataToPool (bool fast);
		static void GetData (const BufferPtr &buffer, bool fast, bool allowAnyLength);
		static void HashMixPool ();
		static void Test ();
		RandomNumberGenerator ();

		static const size_t MaxBytesAddedBeforePoolHashMix = RANDMIX_BYTE_INTERVAL;

		static Mutex AccessMutex;
		static size_t BytesAddedSincePoolHashMix;
		static bool EnrichedByUser;
		static SecureBuffer Pool;
		static shared_ptr <Hash> PoolHash;
		static size_t ReadOffset;
		static bool Running;
		static size_t WriteOffset;
		static struct rand_data *JitterRngCtx;
		static int DevRandomBytesCount;
	};
}

#endif // TC_HEADER_Core_RandomNumberGenerator
