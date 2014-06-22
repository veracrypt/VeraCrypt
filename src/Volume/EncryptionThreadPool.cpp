/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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

namespace VeraCrypt
{
	void EncryptionThreadPool::DoWork (WorkType::Enum type, const EncryptionMode *encryptionMode, byte *data, uint64 startUnitNo, uint64 unitCount, size_t sectorSize)
	{
		size_t fragmentCount;
		size_t unitsPerFragment;
		size_t remainder;

		byte *fragmentData;
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

				fragmentData += unitsPerFragment * ENCRYPTION_DATA_UNIT_SIZE;
				fragmentStartUnitNo += unitsPerFragment;

				if (remainder > 0 && --remainder == 0)
					--unitsPerFragment;

				workItem->State.Set (WorkItem::State::Ready);
				WorkItemReadyEvent.Signal();
			}
		}

		firstFragmentWorkItem->ItemCompletedEvent.Wait();
		
		auto_ptr <Exception> itemException;
		if (firstFragmentWorkItem->ItemException.get())
			itemException = firstFragmentWorkItem->ItemException;

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

					default:
						throw ParameterIncorrect (SRC_POS);
					}
				}
				catch (Exception &e)
				{
					workItem->FirstFragment->ItemException.reset (e.CloneNew());
				}
				catch (exception &e)
				{
					workItem->FirstFragment->ItemException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
				}
				catch (...)
				{
					workItem->FirstFragment->ItemException.reset (new UnknownException (SRC_POS));
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

	SyncEvent EncryptionThreadPool::WorkItemReadyEvent;
	SyncEvent EncryptionThreadPool::WorkItemCompletedEvent;

	list < shared_ptr <Thread> > EncryptionThreadPool::RunningThreads;
}
