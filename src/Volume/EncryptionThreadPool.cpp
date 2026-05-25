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

#ifdef TC_UNIX
#	include <unistd.h>
#endif

#ifdef TC_MACOSX
#	include <sys/types.h>
#	include <sys/sysctl.h>
#endif

#include "Platform/SyncEvent.h"
#include "Platform/SystemLog.h"
#include "Common/Crypto.h"
#include "EncryptionThreadPool.h"
#include "Pkcs5Kdf.h"

namespace VeraCrypt
{
	EncryptionThreadPool::KeyDerivationWorkItem::KeyDerivationWorkItem (shared_ptr <Pkcs5Kdf> kdf, size_t derivedKeySize)
		: Completed (false), DerivedKey (derivedKeySize), Kdf (kdf), Processed (false), Result (0)
	{
	}

	EncryptionThreadPool::KeyDerivationWorkItem::~KeyDerivationWorkItem ()
	{
	}

	void EncryptionThreadPool::BeginKeyDerivation (KeyDerivationWorkItem &keyDerivationWorkItem, const VolumePassword &password, int pim, const ConstBufferPtr &salt, SyncEvent &completionEvent, SyncEvent &noOutstandingWorkItemEvent, SharedVal <size_t> &outstandingWorkItemCount, long volatile *abortFlag)
	{
		if (!ThreadPoolRunning)
			throw NotInitialized (SRC_POS);

		ScopeLock lock (EnqueueMutex);

		WorkItem *workItem = &WorkItemQueue[EnqueuePosition++];

		if (EnqueuePosition >= QueueSize)
			EnqueuePosition = 0;

		while (workItem->State != WorkItem::State::Free)
		{
			WorkItemCompletedEvent.Wait();
		}

		keyDerivationWorkItem.Completed.Set (false);
		keyDerivationWorkItem.ItemException.reset();
		keyDerivationWorkItem.Processed = false;
		keyDerivationWorkItem.Result = 0;

		workItem->Type = WorkType::DeriveKey;
		workItem->KeyDerivation.AbortFlag = abortFlag;
		workItem->KeyDerivation.CompletionEvent = &completionEvent;
		workItem->KeyDerivation.NoOutstandingWorkItemEvent = &noOutstandingWorkItemEvent;
		workItem->KeyDerivation.OutstandingWorkItemCount = &outstandingWorkItemCount;
		workItem->KeyDerivation.Password = &password;
		workItem->KeyDerivation.Pim = pim;
		workItem->KeyDerivation.Salt = salt.Get();
		workItem->KeyDerivation.SaltSize = salt.Size();
		workItem->KeyDerivation.WorkItem = &keyDerivationWorkItem;

		{
			ScopeLock outstandingWorkItemLock (KeyDerivationCompletionMutex);
			if (outstandingWorkItemCount.Increment() == 1)
				noOutstandingWorkItemEvent.Reset();
		}

		workItem->State.Set (WorkItem::State::Ready);
		WorkItemReadyEvent.Signal();
	}

	void EncryptionThreadPool::DoWork (WorkType::Enum type, const EncryptionMode *encryptionMode, uint8 *data, uint64 startUnitNo, uint64 unitCount, size_t sectorSize)
	{
		size_t fragmentCount;
		size_t unitsPerFragment;
		size_t remainder;

		uint8 *fragmentData;
		uint64 fragmentStartUnitNo;

		WorkItem *workItem;
		WorkItem *firstFragmentWorkItem;

		if (unitCount == 0)
			return;

		if (!ThreadPoolRunning || unitCount == 1)
		{
			switch (type)
			{
			case WorkType::DecryptDataUnits:
				encryptionMode->DecryptSectorsCurrentThread (data, startUnitNo, unitCount, sectorSize);
				break;

			case WorkType::EncryptDataUnits:
				encryptionMode->EncryptSectorsCurrentThread (data, startUnitNo, unitCount, sectorSize);
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			return;
		}

		if (unitCount <= ThreadCount)
		{
			fragmentCount = (size_t) unitCount;
			unitsPerFragment = 1;
			remainder = 0;
		}
		else
		{
			fragmentCount = ThreadCount;
			unitsPerFragment = (size_t) unitCount / ThreadCount;
			remainder = (size_t) unitCount % ThreadCount;

			if (remainder > 0)
				++unitsPerFragment;
		}

		fragmentData = data;
		fragmentStartUnitNo = startUnitNo;

		{
			ScopeLock lock (EnqueueMutex);
			firstFragmentWorkItem = &WorkItemQueue[EnqueuePosition];

			while (firstFragmentWorkItem->State != WorkItem::State::Free)
			{
				WorkItemCompletedEvent.Wait();
			}

			firstFragmentWorkItem->OutstandingFragmentCount.Set (fragmentCount);
			firstFragmentWorkItem->ItemException.reset();

			while (fragmentCount-- > 0)
			{
				workItem = &WorkItemQueue[EnqueuePosition++];

				if (EnqueuePosition >= QueueSize)
					EnqueuePosition = 0;

				while (workItem->State != WorkItem::State::Free)
				{
					WorkItemCompletedEvent.Wait();
				}

				workItem->Type = type;
				workItem->FirstFragment = firstFragmentWorkItem;

				workItem->Encryption.Mode = encryptionMode;
				workItem->Encryption.Data = fragmentData;
				workItem->Encryption.UnitCount = unitsPerFragment;
				workItem->Encryption.StartUnitNo = fragmentStartUnitNo;
				workItem->Encryption.SectorSize = sectorSize;

				fragmentData += unitsPerFragment * sectorSize;
				fragmentStartUnitNo += unitsPerFragment;

				if (remainder > 0 && --remainder == 0)
					--unitsPerFragment;

				workItem->State.Set (WorkItem::State::Ready);
				WorkItemReadyEvent.Signal();
			}
		}

		firstFragmentWorkItem->ItemCompletedEvent.Wait();

		unique_ptr <Exception> itemException;
		if (firstFragmentWorkItem->ItemException.get())
			itemException = move_ptr(firstFragmentWorkItem->ItemException);

		firstFragmentWorkItem->State.Set (WorkItem::State::Free);
		WorkItemCompletedEvent.Signal();

		if (itemException.get())
			itemException->Throw();
	}

	void EncryptionThreadPool::Start ()
	{
		if (ThreadPoolRunning)
			return;

		size_t cpuCount;

#ifdef TC_WINDOWS

		SYSTEM_INFO sysInfo;
		GetSystemInfo (&sysInfo);
		cpuCount = sysInfo.dwNumberOfProcessors;

#elif defined (_SC_NPROCESSORS_ONLN)

		cpuCount = (size_t) sysconf (_SC_NPROCESSORS_ONLN);
		if (cpuCount == (size_t) -1)
			cpuCount = 1;

#elif defined (TC_MACOSX)

		int cpuCountSys;
		int mib[2] = { CTL_HW, HW_NCPU };

		size_t len = sizeof (cpuCountSys);
		if (sysctl (mib, 2, &cpuCountSys, &len, nullptr, 0) == -1)
			cpuCountSys = 1;

		cpuCount = (size_t) cpuCountSys;

#else
#	error Cannot determine CPU count
#endif

		if (cpuCount < 2)
			return;

		if (cpuCount > MaxThreadCount)
			cpuCount = MaxThreadCount;

		StopPending = false;
		DequeuePosition = 0;
		EnqueuePosition = 0;

		for (size_t i = 0; i < sizeof (WorkItemQueue) / sizeof (WorkItemQueue[0]); ++i)
		{
			WorkItemQueue[i].State.Set (WorkItem::State::Free);
		}

		try
		{
			for (ThreadCount = 0; ThreadCount < cpuCount; ++ThreadCount)
			{
				struct ThreadFunctor : public Functor
				{
					virtual void operator() ()
					{
						WorkThreadProc();
					}
				};

				make_shared_auto (Thread, thread);
				thread->Start (new ThreadFunctor ());
				RunningThreads.push_back (thread);
			}
		}
		catch (...)
		{
			try
			{
				ThreadPoolRunning = true;
				Stop();
			} catch (...) { }

			throw;
		}

		ThreadPoolRunning = true;
	}

	void EncryptionThreadPool::Stop ()
	{
		if (!ThreadPoolRunning)
			return;

		StopPending = true;
		WorkItemReadyEvent.Signal();

		foreach_ref (const Thread &thread, RunningThreads)
		{
			thread.Join();
		}

		ThreadCount = 0;
		ThreadPoolRunning = false;
	}

	void EncryptionThreadPool::WorkThreadProc ()
	{
		try
		{
			WorkItem *workItem;

			while (!StopPending)
			{
				{
					ScopeLock lock (DequeueMutex);

					workItem = &WorkItemQueue[DequeuePosition++];

					if (DequeuePosition >= QueueSize)
						DequeuePosition = 0;

					while (!StopPending && workItem->State != WorkItem::State::Ready)
					{
						WorkItemReadyEvent.Wait();
					}

					workItem->State.Set (WorkItem::State::Busy);
				}

				if (StopPending)
					break;

				try
				{
					switch (workItem->Type)
					{
					case WorkType::DecryptDataUnits:
						workItem->Encryption.Mode->DecryptSectorsCurrentThread (workItem->Encryption.Data, workItem->Encryption.StartUnitNo, workItem->Encryption.UnitCount, workItem->Encryption.SectorSize);
						break;

					case WorkType::EncryptDataUnits:
						workItem->Encryption.Mode->EncryptSectorsCurrentThread (workItem->Encryption.Data, workItem->Encryption.StartUnitNo, workItem->Encryption.UnitCount, workItem->Encryption.SectorSize);
						break;

					case WorkType::DeriveKey:
						{
							KeyDerivationWorkItem *keyDerivationWorkItem = workItem->KeyDerivation.WorkItem;
							if (workItem->KeyDerivation.AbortFlag && *workItem->KeyDerivation.AbortFlag)
								keyDerivationWorkItem->Result = ERR_USER_ABORT;
							else
								keyDerivationWorkItem->Result = keyDerivationWorkItem->Kdf->DeriveKey (keyDerivationWorkItem->DerivedKey, *workItem->KeyDerivation.Password, workItem->KeyDerivation.Pim, ConstBufferPtr (workItem->KeyDerivation.Salt, workItem->KeyDerivation.SaltSize), workItem->KeyDerivation.AbortFlag);
						}
						break;

					default:
						throw ParameterIncorrect (SRC_POS);
					}
				}
				catch (Exception &e)
				{
					if (workItem->Type == WorkType::DeriveKey)
						workItem->KeyDerivation.WorkItem->ItemException.reset (e.CloneNew());
					else
						workItem->FirstFragment->ItemException.reset (e.CloneNew());
				}
				catch (exception &e)
				{
					if (workItem->Type == WorkType::DeriveKey)
						workItem->KeyDerivation.WorkItem->ItemException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
					else
						workItem->FirstFragment->ItemException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
				}
				catch (...)
				{
					if (workItem->Type == WorkType::DeriveKey)
						workItem->KeyDerivation.WorkItem->ItemException.reset (new UnknownException (SRC_POS));
					else
						workItem->FirstFragment->ItemException.reset (new UnknownException (SRC_POS));
				}

				if (workItem->Type == WorkType::DeriveKey)
				{
					workItem->KeyDerivation.WorkItem->Completed.Set (true);
					workItem->KeyDerivation.CompletionEvent->Signal();
					{
						ScopeLock outstandingWorkItemLock (KeyDerivationCompletionMutex);
						if (workItem->KeyDerivation.OutstandingWorkItemCount->Decrement() == 0)
							workItem->KeyDerivation.NoOutstandingWorkItemEvent->Signal();
					}
					workItem->State.Set (WorkItem::State::Free);
					WorkItemCompletedEvent.Signal();
					continue;
				}

				if (workItem != workItem->FirstFragment)
				{
					workItem->State.Set (WorkItem::State::Free);
					WorkItemCompletedEvent.Signal();
				}

				if (workItem->FirstFragment->OutstandingFragmentCount.Decrement() == 0)
					workItem->FirstFragment->ItemCompletedEvent.Signal();
			}
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}
	}

	volatile bool EncryptionThreadPool::ThreadPoolRunning = false;
	volatile bool EncryptionThreadPool::StopPending = false;

	size_t EncryptionThreadPool::ThreadCount;

	EncryptionThreadPool::WorkItem EncryptionThreadPool::WorkItemQueue[QueueSize];

	volatile size_t EncryptionThreadPool::EnqueuePosition;
	volatile size_t EncryptionThreadPool::DequeuePosition;

	Mutex EncryptionThreadPool::EnqueueMutex;
	Mutex EncryptionThreadPool::DequeueMutex;
	Mutex EncryptionThreadPool::KeyDerivationCompletionMutex;

	SyncEvent EncryptionThreadPool::WorkItemReadyEvent;
	SyncEvent EncryptionThreadPool::WorkItemCompletedEvent;

	list < shared_ptr <Thread> > EncryptionThreadPool::RunningThreads;
}
