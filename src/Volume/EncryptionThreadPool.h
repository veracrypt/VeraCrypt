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

#ifndef TC_HEADER_Volume_EncryptionThreadPool
#define TC_HEADER_Volume_EncryptionThreadPool

#include <atomic>
#include "Platform/Platform.h"
#include "EncryptionMode.h"

namespace VeraCrypt
{
	class Pkcs5Kdf;
	class VolumePassword;

	class EncryptionThreadPool
	{
	public:
		struct WorkType
		{
			enum Enum
			{
				EncryptDataUnits,
				DecryptDataUnits,
				DeriveKey
			};
		};

		struct KeyDerivationWorkItem;

		struct WorkItem
		{
			struct State
			{
				enum Enum
				{
					Free,
					Ready,
					Busy
				};
			};

			struct WorkItem *FirstFragment;
			unique_ptr <Exception> ItemException;
			std::atomic <bool> ExceptionCaptureFailed;
			SyncEvent ItemCompletedEvent;
			SharedVal <size_t> OutstandingFragmentCount;
			SharedVal <State::Enum> State;
			WorkType::Enum Type;

			union
			{
				struct
				{
					const EncryptionMode *Mode;
					uint8 *Data;
					uint64 StartUnitNo;
					uint64 UnitCount;
					size_t SectorSize;
				} Encryption;

				struct
				{
					long volatile *AbortFlag;
					SyncEvent *CompletionEvent;
					SyncEvent *NoOutstandingWorkItemEvent;
					SharedVal <size_t> *OutstandingWorkItemCount;
					const VolumePassword *Password;
					int Pim;
					const uint8 *Salt;
					size_t SaltSize;
					KeyDerivationWorkItem *WorkItem;
				} KeyDerivation;
			};
		};

		struct KeyDerivationWorkItem
		{
			KeyDerivationWorkItem (shared_ptr <Pkcs5Kdf> kdf, size_t derivedKeySize);
			~KeyDerivationWorkItem ();

			SharedVal <bool> Completed;
			SecureBuffer DerivedKey;
			unique_ptr <Exception> ItemException;
			bool ExceptionCaptureFailed;
			shared_ptr <Pkcs5Kdf> Kdf;
			bool Processed;
			int Result;
		};

		// Caller-owned references and pointers must remain valid until noOutstandingWorkItemEvent is signaled.
		// Derivation runs synchronously when the pool is unavailable or closing.
		static void BeginKeyDerivation (KeyDerivationWorkItem &keyDerivationWorkItem, const VolumePassword &password, int pim, const ConstBufferPtr &salt, SyncEvent &completionEvent, SyncEvent &noOutstandingWorkItemEvent, SharedVal <size_t> &outstandingWorkItemCount, long volatile *abortFlag);
		static void DoWork (WorkType::Enum type, const EncryptionMode *mode, uint8 *data, uint64 startUnitNo, uint64 unitCount, size_t sectorSize);
		static bool IsRunning () { return ThreadPoolRunning; }
		// Start and Stop must be serialized by the caller. Stop drains accepted pool users;
		// callers must still keep their objects alive for work running synchronously.
		static void Start ();
		static void Stop ();

	protected:
		static bool AcquirePoolReference ();
		static void ReleasePoolReference ();
		static void StopWorkers ();
		static void WorkThreadProc ();

		class PoolReference
		{
		public:
			explicit PoolReference (bool acquire = true) : Acquired (acquire && AcquirePoolReference()) { }
			~PoolReference () { if (Acquired) ReleasePoolReference(); }
			bool IsAcquired () const { return Acquired; }
		private:
			bool Acquired;
			PoolReference (const PoolReference &);
			PoolReference &operator= (const PoolReference &);
		};

		static const size_t MaxThreadCount = 32;
		static const size_t QueueSize = MaxThreadCount * 2;
		static const uint32 PoolClosing = 0x80000000U;
		static std::atomic <uint32> PoolReferences;
		static SyncEvent PoolDrainedEvent;

		static Mutex DequeueMutex;
		static volatile size_t DequeuePosition;
		static volatile size_t EnqueuePosition;
		static Mutex EnqueueMutex;
		// Fragments of one request share the first fragment's exception pointer.
		static Mutex FragmentExceptionMutex;
		// Orders KDF outstanding-count transitions against no-outstanding event updates.
		static Mutex KeyDerivationCompletionMutex;
		static list < shared_ptr <Thread> > RunningThreads;
		static std::atomic <bool> StopPending;
		static size_t ThreadCount;
		static std::atomic <bool> ThreadPoolRunning;
		static SyncEvent WorkItemCompletedEvent;
		static WorkItem WorkItemQueue[QueueSize];
		static SyncEvent WorkItemReadyEvent;
	};
}

#endif // TC_HEADER_Volume_EncryptionThreadPool
