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

#include "TCdefs.h"
#include "Apidrvr.h"
#include "Ntdriver.h"
#include "DriveFilter.h"
#include "EncryptedIoQueue.h"
#include "EncryptionThreadPool.h"
#include "Volumes.h"
#include <IntSafe.h>

// Returns STATUS_SUCCESS on success and sets *outVa.
// On failure, returns STATUS_INVALID_USER_BUFFER or STATUS_INSUFFICIENT_RESOURCES
// and leaves *outVa as NULL. If *outTempMdl not NULL, the caller must unlock/free it at completion.
__drv_maxIRQL(APC_LEVEL) static NTSTATUS
	MapIrpDataBuffer(
		_In_ PIRP irp,
		_In_ BOOL isWriteIRP, // TRUE for IRP_MJ_WRITE (we READ from caller buffer)
		_In_ ULONG length,
		_Outptr_result_bytebuffer_(length) PUCHAR *outVa,
		_Outptr_result_maybenull_ PMDL *outTempMdl)
{
	ULONG mapFlags = HighPagePriority | MdlMappingNoExecute;
	PUCHAR va = NULL;

	ASSERT(outVa && outTempMdl);
	*outVa = NULL;
	*outTempMdl = NULL;

	ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	if (length == 0)
		return STATUS_INVALID_PARAMETER;

	// If this is a WRITE IRP we only read from caller’s buffer: ask for a no-write mapping.
	if (isWriteIRP)
		mapFlags |= MdlMappingNoWrite;

	// --- Direct I/O ---
	if (irp->MdlAddress)
	{
		if (MmGetMdlByteCount(irp->MdlAddress) < length)
			return STATUS_INVALID_USER_BUFFER; // caller asked for more than mapped

		va = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, mapFlags);
		if (!va)
			return STATUS_INSUFFICIENT_RESOURCES; // low PTEs, etc.

		*outVa = va;
		return STATUS_SUCCESS;
	}

	// --- Buffered I/O ---
	if (irp->AssociatedIrp.SystemBuffer)
	{
		*outVa = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
		return STATUS_SUCCESS;
	}

	// --- Neither I/O ---
	if (!irp->UserBuffer)
		return STATUS_INVALID_USER_BUFFER;

	PMDL mdl = IoAllocateMdl(irp->UserBuffer, length, FALSE, FALSE, NULL);
	if (!mdl)
		return STATUS_INSUFFICIENT_RESOURCES;

	__try
	{
		// For WRITE IRPs we read from user => IoReadAccess.
		// For READ IRPs we write to user => IoWriteAccess.
		MmProbeAndLockPages(mdl, irp->RequestorMode, isWriteIRP ? IoReadAccess : IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(mdl);
		return STATUS_INVALID_USER_BUFFER; // bad pointer/range/rights
	}

	va = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, mapFlags);
	if (!va)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*outTempMdl = mdl;
	*outVa = va;
	return STATUS_SUCCESS;
}

static void AcquireBufferPoolMutex (EncryptedIoQueue *queue)
{
	NTSTATUS status;

	status = KeWaitForMutexObject (&queue->BufferPoolMutex, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS (status))
		TC_BUG_CHECK (status);
}


static void ReleaseBufferPoolMutex (EncryptedIoQueue *queue)
{
	KeReleaseMutex (&queue->BufferPoolMutex, FALSE);
}


static void *GetPoolBuffer (EncryptedIoQueue *queue, ULONG requestedSize)
{
	EncryptedIoQueueBuffer *buffer;
	void *bufferAddress = NULL;
	BOOL requestedSizePresentInPool = FALSE;

	while (TRUE)
	{
		AcquireBufferPoolMutex (queue);

		for (buffer = queue->FirstPoolBuffer; ; buffer = buffer->NextBuffer)
		{
			if (buffer && buffer->Size == requestedSize)
			{
				requestedSizePresentInPool = TRUE;

				if (!buffer->InUse)
				{
					// Reuse a free buffer
					buffer->InUse = TRUE;
					bufferAddress = buffer->Address;
					break;
				}
			}

			if (!buffer || !buffer->NextBuffer)
			{
				EncryptedIoQueueBuffer *newBuffer;

				if (requestedSizePresentInPool && !queue->StartPending)
					break;

				// Allocate a new buffer
				newBuffer = TCalloc (sizeof (EncryptedIoQueueBuffer));
				if (!newBuffer)
				{
					bufferAddress = NULL;
					break;
				}

				bufferAddress = TCalloc (requestedSize);
				if (bufferAddress)
				{
					newBuffer->NextBuffer = NULL;
					newBuffer->Address = bufferAddress;
					newBuffer->Size = requestedSize;
					newBuffer->InUse = TRUE;

					if (!buffer)
						queue->FirstPoolBuffer = newBuffer;
					else
						buffer->NextBuffer = newBuffer;
				}
				else
					TCfree (newBuffer);

				break;
			}
		}

		ReleaseBufferPoolMutex (queue);

		if (bufferAddress || !requestedSizePresentInPool || queue->StartPending)
			break;

		KeWaitForSingleObject (&queue->PoolBufferFreeEvent, Executive, KernelMode, FALSE, NULL);
	}

	return bufferAddress;
}


static void ReleasePoolBuffer (EncryptedIoQueue *queue, void *address)
{
	EncryptedIoQueueBuffer *buffer;
	AcquireBufferPoolMutex (queue);

	for (buffer = queue->FirstPoolBuffer; buffer != NULL; buffer = buffer->NextBuffer)
	{
		if (buffer->Address == address)
		{
			ASSERT (buffer->InUse);

			buffer->InUse = FALSE;
			break;
		}
	}

	ReleaseBufferPoolMutex (queue);
	KeSetEvent (&queue->PoolBufferFreeEvent, IO_DISK_INCREMENT, FALSE);
}


static void FreePoolBuffers (EncryptedIoQueue *queue)
{
	EncryptedIoQueueBuffer *buffer;
	AcquireBufferPoolMutex (queue);

	for (buffer = queue->FirstPoolBuffer; buffer != NULL; )
	{
		EncryptedIoQueueBuffer *nextBuffer = buffer->NextBuffer;

		ASSERT (!buffer->InUse || queue->StartPending);

		TCfree (buffer->Address);
		TCfree (buffer);

		buffer = nextBuffer;
	}

	queue->FirstPoolBuffer = NULL;
	ReleaseBufferPoolMutex (queue);
}


static void DecrementOutstandingIoCount (EncryptedIoQueue *queue)
{
	if (InterlockedDecrement (&queue->OutstandingIoCount) == 0 && (queue->SuspendPending || queue->StopPending))
		KeSetEvent (&queue->NoOutstandingIoEvent, IO_DISK_INCREMENT, FALSE);
}


static void OnItemCompleted (EncryptedIoQueueItem *item, BOOL freeItem)
{
	if (item->TempUserMdl) {
		MmUnlockPages(item->TempUserMdl);
		IoFreeMdl(item->TempUserMdl);
		item->TempUserMdl = NULL;
	}

	DecrementOutstandingIoCount (item->Queue);
	IoReleaseRemoveLock (&item->Queue->RemoveLock, item->OriginalIrp);

	if (NT_SUCCESS (item->Status))
	{
		if (item->Write)
			item->Queue->TotalBytesWritten += item->OriginalLength;
		else
			item->Queue->TotalBytesRead += item->OriginalLength;
	}

	if (freeItem)
		ReleasePoolBuffer (item->Queue, item);
}

static void AcquireFragmentBuffer (EncryptedIoQueue *queue, uint8 *buffer)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if (buffer == queue->FragmentBufferA)
	{
		status = KeWaitForSingleObject (&queue->FragmentBufferAFreeEvent, Executive, KernelMode, FALSE, NULL);
	}
	else if (buffer == queue->FragmentBufferB)
	{
		status = KeWaitForSingleObject (&queue->FragmentBufferBFreeEvent, Executive, KernelMode, FALSE, NULL);
	}

	if (!NT_SUCCESS (status))
		TC_BUG_CHECK (status);
}


static void ReleaseFragmentBuffer (EncryptedIoQueue *queue, uint8 *buffer)
{
	if (buffer == queue->FragmentBufferA)
	{
		KeSetEvent (&queue->FragmentBufferAFreeEvent, IO_DISK_INCREMENT, FALSE);
	}
	else if (buffer == queue->FragmentBufferB)
	{
		KeSetEvent (&queue->FragmentBufferBFreeEvent, IO_DISK_INCREMENT, FALSE);
	}
	else
	{
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);
	}
}

BOOL
UpdateBuffer(
	uint8* buffer,
	uint8* secRegion,
	SIZE_T     secRegionSize,
	uint64     bufferDiskOffset,
	uint32     bufferLength,
	BOOL       doUpdate
)
{
	uint64       intersectStart;
	uint32       intersectLength;
	uint32       i;
	DCS_DISK_ENTRY_LIST *DeList = NULL;
	BOOL         updated = FALSE;

	if (secRegion == NULL)
		return FALSE;

	// Check if secRegion is large enough to hold the DCS_DISK_ENTRY_LIST structure 
	// starting at offset 512
	if (secRegionSize < (512 + sizeof(DCS_DISK_ENTRY_LIST)))
		return FALSE;

	DeList = (DCS_DISK_ENTRY_LIST*)(secRegion + 512);

	// Ensure Count doesn't exceed the fixed array size
	if (DeList->Count > 15)
		return FALSE;

	for (i = 0; i < DeList->Count; ++i) {
		if (DeList->DE[i].Type == DE_Sectors) {
			uint64 sectorStart = DeList->DE[i].Sectors.Start;
			uint64 sectorLength = DeList->DE[i].Sectors.Length;
			uint64 sectorOffset = DeList->DE[i].Sectors.Offset;

			// Check that sectorOffset and sectorLength are valid within secRegion (guard against overflow)
			ULONGLONG regionBoundEnd; // sectorOffset + sectorLength
			if (sectorOffset > (uint64)secRegionSize ||
				sectorLength == 0 ||
				FAILED(ULongLongAdd(sectorOffset, sectorLength, &regionBoundEnd)) ||
				regionBoundEnd > (ULONGLONG)secRegionSize)
			{
				// Invalid entry - skip
				continue;
			}

			// Safely compute inclusive end = start + length - 1
			ULONGLONG secEnd, tmp;
			if (FAILED(ULongLongAdd(sectorStart, sectorLength, &tmp)) || tmp == 0)
				continue; // invalid descriptor (overflow or zero)
			secEnd = tmp - 1;

			GetIntersection(
				bufferDiskOffset, bufferLength,
				sectorStart, secEnd,
				&intersectStart, &intersectLength
			);

			if (intersectLength != 0) {
				uint64 bufferPos = intersectStart - bufferDiskOffset;
				uint64 regionPos = sectorOffset + (intersectStart - sectorStart);

				// Check buffer boundaries using safe add
				ULONGLONG bufEndCheck;
				if (FAILED(ULongLongAdd(bufferPos, (ULONGLONG)intersectLength, &bufEndCheck)) ||
					bufEndCheck > (ULONGLONG)bufferLength)
					continue; // Intersection out of buffer range

				// Check secRegion boundaries using safe add
				ULONGLONG regEndCheck;
				if (FAILED(ULongLongAdd(regionPos, (ULONGLONG)intersectLength, &regEndCheck)) ||
					regEndCheck > (ULONGLONG)secRegionSize)
					continue; // Intersection out of secRegion range

				updated = TRUE;
				if (doUpdate && buffer != NULL) {
					memcpy(
						buffer + bufferPos,
						secRegion + regionPos,
						intersectLength
					);
				}
				else {
					// If no update is needed but intersection found
					return TRUE;
				}
			}
		}
	}
	return updated;
}

static VOID CompleteIrpWorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
	PCOMPLETE_IRP_WORK_ITEM workItem = (PCOMPLETE_IRP_WORK_ITEM)Context;
	EncryptedIoQueueItem *item = (EncryptedIoQueueItem *)workItem->Item;
	EncryptedIoQueue *queue = (EncryptedIoQueue *)workItem->Queue;
	KIRQL oldIrql;
	UNREFERENCED_PARAMETER(DeviceObject);

	__try
	{
		if (item)
		{
			// Normal path: completion associated with an EncryptedIoQueueItem
			item->Status = workItem->Status;
			OnItemCompleted(item, FALSE); // Do not free item here; it will be freed below
			TCCompleteDiskIrp(workItem->Irp, workItem->Status, workItem->Information);
		}
		else
		{
			// Raw completion: release lock/counters if requested and finish the IRP
			if (workItem->ReleaseLockAndCounters && queue)
			{
				DecrementOutstandingIoCount(queue);
				IoReleaseRemoveLock(&queue->RemoveLock, workItem->Irp);
			}
			TCCompleteDiskIrp(workItem->Irp, workItem->Status, workItem->Information);
		}
	}
	__finally
	{
		// If no active work items remain, signal the event
		if (InterlockedDecrement(&queue->ActiveWorkItems) == 0)
		{
			KeSetEvent(&queue->NoActiveWorkItemsEvent, IO_DISK_INCREMENT, FALSE);
		}

		// Return the work item to the free list
		KeAcquireSpinLock(&queue->WorkItemLock, &oldIrql);
		InsertTailList(&queue->FreeWorkItemsList, &workItem->ListEntry);
		KeReleaseSpinLock(&queue->WorkItemLock, oldIrql);

		// Release the semaphore to signal that a work item is available
		KeReleaseSemaphore(&queue->WorkItemSemaphore, IO_DISK_INCREMENT, 1, FALSE);

		// Free the queue item if any
		if (item)
		{
			ReleasePoolBuffer(queue, item);
		}
	}
}

// Queues completion of the original IRP via pre-allocated work-item (from an EncryptedIoQueueItem)
static VOID QueueIrpCompletionFromItem(EncryptedIoQueue *queue,
									   EncryptedIoQueueItem *item,
									   NTSTATUS status)
{
	// Must be PASSIVE_LEVEL. We rely on the preallocated pool only.
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	// Block until a work item is available (no inline completion, no alloc).
	for (;;)
	{
		NTSTATUS ws = KeWaitForSingleObject(&queue->WorkItemSemaphore,
											Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(ws))
			break;
		// Non-alertable wait: an error here is unexpected
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&queue->WorkItemLock, &oldIrql);
	ASSERT(!IsListEmpty(&queue->FreeWorkItemsList));
	PLIST_ENTRY freeEntry = RemoveHeadList(&queue->FreeWorkItemsList);
	KeReleaseSpinLock(&queue->WorkItemLock, oldIrql);

	PCOMPLETE_IRP_WORK_ITEM wi = CONTAINING_RECORD(freeEntry, COMPLETE_IRP_WORK_ITEM, ListEntry);

	KeResetEvent(&queue->NoActiveWorkItemsEvent);
	InterlockedIncrement(&queue->ActiveWorkItems);

	wi->Irp = item->OriginalIrp;
	wi->Status = status;
	wi->Information = NT_SUCCESS(status) ? item->OriginalLength : 0;
	wi->Item = item;
	wi->Queue = queue;
	wi->ReleaseLockAndCounters = FALSE;

	IoQueueWorkItem(wi->WorkItem, CompleteIrpWorkItemRoutine, CriticalWorkQueue, wi);
}

// Queues completion of a raw IRP not bound to EncryptedIoQueueItem (early error/cancel paths)
static VOID QueueRawIrpCompletion(EncryptedIoQueue *queue,
								  PIRP irp, NTSTATUS status, ULONG_PTR info)
{
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	for (;;)
	{
		NTSTATUS ws = KeWaitForSingleObject(&queue->WorkItemSemaphore,
											Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(ws))
			break;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&queue->WorkItemLock, &oldIrql);
	ASSERT(!IsListEmpty(&queue->FreeWorkItemsList));
	PLIST_ENTRY freeEntry = RemoveHeadList(&queue->FreeWorkItemsList);
	KeReleaseSpinLock(&queue->WorkItemLock, oldIrql);

	PCOMPLETE_IRP_WORK_ITEM wi = CONTAINING_RECORD(freeEntry, COMPLETE_IRP_WORK_ITEM, ListEntry);

	KeResetEvent(&queue->NoActiveWorkItemsEvent);
	InterlockedIncrement(&queue->ActiveWorkItems);

	wi->Irp = irp;
	wi->Status = status;
	wi->Information = info;
	wi->Item = NULL; // raw path: helper will release lock/counters
	wi->Queue = queue;
	wi->ReleaseLockAndCounters = TRUE;

	IoQueueWorkItem(wi->WorkItem, CompleteIrpWorkItemRoutine, CriticalWorkQueue, wi);
}

// Handles the completion of the original IRP.
static VOID HandleCompleteOriginalIrp(EncryptedIoQueue *queue, EncryptedIoRequest *request)
{
	QueueIrpCompletionFromItem(queue,
							   request->Item,
							   request->Item->Status);
}

static VOID CompletionThreadProc(PVOID threadArg)
{
	EncryptedIoQueue* queue = (EncryptedIoQueue*)threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoRequest* request;
	UINT64_STRUCT dataUnit;

	if (IsEncryptionThreadPoolRunning())
		KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS(KeWaitForSingleObject(&queue->CompletionThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList(&queue->CompletionThreadQueue, &queue->CompletionThreadQueueLock)))
		{
			request = CONTAINING_RECORD(listEntry, EncryptedIoRequest, CompletionListEntry);

			if (request->EncryptedLength > 0 && NT_SUCCESS(request->Item->Status))
			{
				ASSERT(request->EncryptedOffset + request->EncryptedLength <= request->Offset.QuadPart + request->Length);
				dataUnit.Value = (request->Offset.QuadPart + request->EncryptedOffset) / ENCRYPTION_DATA_UNIT_SIZE;

				if (queue->CryptoInfo->bPartitionInInactiveSysEncScope)
					dataUnit.Value += queue->CryptoInfo->FirstDataUnitNo.Value;
				else if (queue->RemapEncryptedArea)
					dataUnit.Value += queue->RemappedAreaDataUnitOffset;

				DecryptDataUnits(request->Data + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
			}
//			Dump("Read sector %lld count %d\n", request->Offset.QuadPart >> 9, request->Length >> 9);
			// Update subst sectors
			if((queue->SecRegionData != NULL) && (queue->SecRegionSize > 512)) {
				UpdateBuffer(request->Data, queue->SecRegionData, queue->SecRegionSize, request->Offset.QuadPart, request->Length, TRUE);
			}

			if (request->CompleteOriginalIrp)
			{
				HandleCompleteOriginalIrp(queue, request);
			}

			ReleasePoolBuffer(queue, request);
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}


static NTSTATUS TCCachedRead (EncryptedIoQueue *queue, IO_STATUS_BLOCK *ioStatus, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	queue->LastReadOffset = offset;
	queue->LastReadLength = length;

	if (queue->ReadAheadBufferValid && queue->ReadAheadOffset.QuadPart == offset.QuadPart && queue->ReadAheadLength >= length)
	{
		memcpy (buffer, queue->ReadAheadBuffer, length);

		if (!queue->IsFilterDevice)
		{
			ioStatus->Information = length;
			ioStatus->Status = STATUS_SUCCESS;
		}

		return STATUS_SUCCESS;
	}

	if (queue->IsFilterDevice)
		return TCReadDevice (queue->LowerDeviceObject, buffer, offset, length);

	return ZwReadFile (queue->HostFileHandle, NULL, NULL, NULL, ioStatus, buffer, length, &offset, NULL);
}


static VOID IoThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoRequest *request;

	KeSetPriorityThread (KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	if (!queue->IsFilterDevice && queue->SecurityClientContext)
	{
#ifdef DEBUG
		NTSTATUS status =
#endif
		SeImpersonateClientEx (queue->SecurityClientContext, NULL);
		ASSERT (NT_SUCCESS (status));
	}

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->IoThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		if (queue->ThreadExitRequested)
			break;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->IoThreadQueue, &queue->IoThreadQueueLock)))
		{
			InterlockedDecrement (&queue->IoThreadPendingRequestCount);
			request = CONTAINING_RECORD (listEntry, EncryptedIoRequest, ListEntry);

#ifdef TC_TRACE_IO_QUEUE
			Dump ("%c   %I64d [%I64d] roff=%I64d rlen=%d\n", request->Item->Write ? 'W' : 'R', request->Item->OriginalIrpOffset.QuadPart, GetElapsedTime (&queue->LastPerformanceCounter), request->Offset.QuadPart, request->Length);
#endif

			// Perform IO request if no preceding request of the item failed
			if (NT_SUCCESS (request->Item->Status))
			{
				if (queue->ThreadBlockReadWrite)
					request->Item->Status = STATUS_DEVICE_BUSY;
				else if (queue->IsFilterDevice)
				{
					if (queue->RemapEncryptedArea && request->EncryptedLength > 0)
					{
						if (request->EncryptedLength != request->Length)
						{
							// Up to three subfragments may be required to handle a partially remapped fragment
							int subFragment;
							uint8 *subFragmentData = request->Data;

							for (subFragment = 0 ; subFragment < 3; ++subFragment)
							{
								LARGE_INTEGER subFragmentOffset;
								ULONG subFragmentLength = 0;
								subFragmentOffset.QuadPart = request->Offset.QuadPart;

								switch (subFragment)
								{
								case 0:
									subFragmentLength = (ULONG) request->EncryptedOffset;
									break;

								case 1:
									subFragmentOffset.QuadPart += request->EncryptedOffset + queue->RemappedAreaOffset;
									subFragmentLength = request->EncryptedLength;
									break;

								case 2:
									subFragmentOffset.QuadPart += request->EncryptedOffset + request->EncryptedLength;
									subFragmentLength = (ULONG) (request->Length - (request->EncryptedOffset + request->EncryptedLength));
									break;
								}

								if (subFragmentLength > 0)
								{
									if (request->Item->Write)
										request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, subFragmentData, subFragmentOffset, subFragmentLength);
									else
										request->Item->Status = TCCachedRead (queue, NULL, subFragmentData, subFragmentOffset, subFragmentLength);

									subFragmentData += subFragmentLength;
								}
							}
						}
						else
						{
							// Remap the fragment
							LARGE_INTEGER remappedOffset;
							remappedOffset.QuadPart = request->Offset.QuadPart + queue->RemappedAreaOffset;

							if (request->Item->Write)
								request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, request->Data, remappedOffset, request->Length);
							else
								request->Item->Status = TCCachedRead (queue, NULL, request->Data, remappedOffset, request->Length);
						}
					}
					else
					{
						if (request->Item->Write)
							request->Item->Status = TCWriteDevice (queue->LowerDeviceObject, request->Data, request->Offset, request->Length);
						else
							request->Item->Status = TCCachedRead (queue, NULL, request->Data, request->Offset, request->Length);
					}
				}
				else
				{
					IO_STATUS_BLOCK ioStatus;

					if (request->Item->Write)
						request->Item->Status = ZwWriteFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, request->Data, request->Length, &request->Offset, NULL);
					else
						request->Item->Status = TCCachedRead (queue, &ioStatus, request->Data, request->Offset, request->Length);

					if (NT_SUCCESS (request->Item->Status) && ioStatus.Information != request->Length)
						request->Item->Status = STATUS_END_OF_FILE;
				}
			}

			if (request->Item->Write)
			{
				queue->ReadAheadBufferValid = FALSE;

				ReleaseFragmentBuffer (queue, request->Data);

				if (request->CompleteOriginalIrp)
				{
					HandleCompleteOriginalIrp(queue, request);
				}

				ReleasePoolBuffer (queue, request);
			}
			else
			{
				BOOL readAhead = FALSE;

				if (NT_SUCCESS (request->Item->Status))
					memcpy (request->OrigDataBufferFragment, request->Data, request->Length);

				ReleaseFragmentBuffer (queue, request->Data);
				request->Data = request->OrigDataBufferFragment;

				if (request->CompleteOriginalIrp
					&& queue->LastReadLength > 0
					&& NT_SUCCESS (request->Item->Status)
					&& InterlockedExchangeAdd (&queue->IoThreadPendingRequestCount, 0) == 0)
				{
					readAhead = TRUE;
					InterlockedIncrement (&queue->OutstandingIoCount);
				}

				ExInterlockedInsertTailList (&queue->CompletionThreadQueue, &request->CompletionListEntry, &queue->CompletionThreadQueueLock);
				KeSetEvent (&queue->CompletionThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);

				if (readAhead)
				{
					queue->ReadAheadBufferValid = FALSE;
					queue->ReadAheadOffset.QuadPart = queue->LastReadOffset.QuadPart + queue->LastReadLength;
					queue->ReadAheadLength = queue->LastReadLength;

					if (queue->ReadAheadOffset.QuadPart + queue->ReadAheadLength <= queue->MaxReadAheadOffset.QuadPart)
					{
#ifdef TC_TRACE_IO_QUEUE
						Dump ("A   %I64d [%I64d] roff=%I64d rlen=%d\n", request->Item->OriginalIrpOffset.QuadPart, GetElapsedTime (&queue->LastPerformanceCounter), queue->ReadAheadOffset, queue->ReadAheadLength);
#endif
						if (queue->IsFilterDevice)
						{
							queue->ReadAheadBufferValid = NT_SUCCESS (TCReadDevice (queue->LowerDeviceObject, queue->ReadAheadBuffer, queue->ReadAheadOffset, queue->ReadAheadLength));
						}
						else
						{
							IO_STATUS_BLOCK ioStatus;
							queue->ReadAheadBufferValid = NT_SUCCESS (ZwReadFile (queue->HostFileHandle, NULL, NULL, NULL, &ioStatus, queue->ReadAheadBuffer, queue->ReadAheadLength, &queue->ReadAheadOffset, NULL));
							queue->ReadAheadLength = (ULONG) ioStatus.Information;
						}
					}

					DecrementOutstandingIoCount (queue);
				}
			}
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


static VOID MainThreadProc (PVOID threadArg)
{
	EncryptedIoQueue *queue = (EncryptedIoQueue *) threadArg;
	PLIST_ENTRY listEntry;
	EncryptedIoQueueItem *item;

	LARGE_INTEGER fragmentOffset;
	ULONG dataRemaining;
	PUCHAR activeFragmentBuffer = queue->FragmentBufferA;
	PUCHAR dataBuffer;
	EncryptedIoRequest *request;
	uint64 intersectStart;
	uint32 intersectLength;
	ULONGLONG addResult;
	HRESULT hResult;

	if (IsEncryptionThreadPoolRunning())
		KeSetPriorityThread (KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	while (!queue->ThreadExitRequested)
	{
		if (!NT_SUCCESS (KeWaitForSingleObject (&queue->MainThreadQueueNotEmptyEvent, Executive, KernelMode, FALSE, NULL)))
			continue;

		while ((listEntry = ExInterlockedRemoveHeadList (&queue->MainThreadQueue, &queue->MainThreadQueueLock)))
		{
			PIRP irp = CONTAINING_RECORD (listEntry, IRP, Tail.Overlay.ListEntry);
			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (irp);
			KIRQL irql;
			BOOLEAN cancelled;

			if (queue->Suspended)
				KeWaitForSingleObject (&queue->QueueResumedEvent, Executive, KernelMode, FALSE, NULL);

			item = GetPoolBuffer (queue, sizeof (EncryptedIoQueueItem));
			if (!item)
			{
				// Defer completion to work item to avoid re-entrant completion on our thread
				QueueRawIrpCompletion(queue, irp, STATUS_INSUFFICIENT_RESOURCES, 0);

				continue;
			}

			item->Queue = queue;
			item->OriginalIrp = irp;
			item->TempUserMdl = NULL;
			item->Status = STATUS_SUCCESS;

			IoAcquireCancelSpinLock(&irql);
			(PDRIVER_CANCEL)IoSetCancelRoutine(irp, NULL);
			cancelled = irp->Cancel ? TRUE : FALSE;
			IoReleaseCancelSpinLock(irql);
			if (cancelled)
			{
				// Defer cancellation completion
				QueueIrpCompletionFromItem(queue, item, STATUS_CANCELLED);
				continue;
			}

			switch (irpSp->MajorFunction)
			{
			case IRP_MJ_READ:
				item->Write = FALSE;
				item->OriginalOffset = irpSp->Parameters.Read.ByteOffset;
				item->OriginalLength = irpSp->Parameters.Read.Length;
				break;

			case IRP_MJ_WRITE:
				item->Write = TRUE;
				item->OriginalOffset = irpSp->Parameters.Write.ByteOffset;
				item->OriginalLength = irpSp->Parameters.Write.Length;
				break;

			default:
				// Defer completion for invalid parameter
				QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
				continue;
			}

#ifdef TC_TRACE_IO_QUEUE
			item->OriginalIrpOffset = item->OriginalOffset;
#endif

			// Handle misaligned read operations to work around a bug in Windows System Assessment Tool which does not follow FILE_FLAG_NO_BUFFERING requirements when benchmarking disk devices
			if (queue->IsFilterDevice
				&& !item->Write
				&& item->OriginalLength > 0
				&& (item->OriginalLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) == 0
				&& (item->OriginalOffset.QuadPart & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
			{
				uint8 *buffer;
				ULONG alignedLength;
				LARGE_INTEGER alignedOffset;
				hResult = ULongAdd(item->OriginalLength, ENCRYPTION_DATA_UNIT_SIZE, &alignedLength);
				if (hResult != S_OK)
				{
					// Defer completion for invalid parameter
					QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
					continue;
				}

				alignedOffset.QuadPart = item->OriginalOffset.QuadPart & ~((LONGLONG) ENCRYPTION_DATA_UNIT_SIZE - 1);

				buffer = TCalloc (alignedLength);
				if (!buffer)
				{
					QueueIrpCompletionFromItem (queue, item, STATUS_INSUFFICIENT_RESOURCES);
					continue;
				}

				item->Status = TCReadDevice (queue->LowerDeviceObject, buffer, alignedOffset, alignedLength);

				if (NT_SUCCESS (item->Status))
				{
					UINT64_STRUCT dataUnit;

					dataBuffer = NULL;
					NTSTATUS mapStatus = MapIrpDataBuffer(
						irp,
						FALSE,
						item->OriginalLength,
						&dataBuffer,
						&item->TempUserMdl);
					if (!NT_SUCCESS(mapStatus))
					{
						TCfree (buffer);
						// Defer completion on mapping failure
						QueueIrpCompletionFromItem(queue, item, mapStatus);
						continue;
					}

					if (queue->EncryptedAreaStart != -1 && queue->EncryptedAreaEnd != -1)
					{
						GetIntersection (alignedOffset.QuadPart, alignedLength, queue->EncryptedAreaStart, queue->EncryptedAreaEnd, &intersectStart, &intersectLength);
						if (intersectLength > 0)
						{
							dataUnit.Value = intersectStart / ENCRYPTION_DATA_UNIT_SIZE;
							DecryptDataUnits (buffer + (intersectStart - alignedOffset.QuadPart), &dataUnit, intersectLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
						}
					}
					// Update subst sectors
 					if((queue->SecRegionData != NULL) && (queue->SecRegionSize > 512)) {
 						UpdateBuffer(buffer, queue->SecRegionData, queue->SecRegionSize, alignedOffset.QuadPart, alignedLength, TRUE);
 					}

					memcpy (dataBuffer, buffer + (item->OriginalOffset.LowPart & (ENCRYPTION_DATA_UNIT_SIZE - 1)), item->OriginalLength);
				}

				TCfree (buffer);
				// Defer completion of misaligned read workaround
				QueueIrpCompletionFromItem(queue, item, item->Status);
				continue;
			}

			// Validate offset and length
			if (item->OriginalLength == 0
				|| (item->OriginalLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0
				|| (item->OriginalOffset.QuadPart & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0
				|| (	!queue->IsFilterDevice &&
						(	(S_OK != ULongLongAdd(item->OriginalOffset.QuadPart, item->OriginalLength, &addResult))
							||	(addResult > (ULONGLONG) queue->VirtualDeviceLength)
						)
					)
				)
			{
				// Defer completion for invalid parameter
				QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
				continue;
			}

#ifdef TC_TRACE_IO_QUEUE
			Dump ("Q  %I64d [%I64d] %c len=%d\n", item->OriginalOffset.QuadPart, GetElapsedTime (&queue->LastPerformanceCounter), item->Write ? 'W' : 'R', item->OriginalLength);
#endif

			if (!queue->IsFilterDevice)
			{
				// Adjust the offset for host file or device
				if (queue->CryptoInfo->hiddenVolume)
					hResult = ULongLongAdd(item->OriginalOffset.QuadPart, queue->CryptoInfo->hiddenVolumeOffset, &addResult);
				else
					hResult = ULongLongAdd(item->OriginalOffset.QuadPart, queue->CryptoInfo->volDataAreaOffset, &addResult);

				if (hResult != S_OK)
				{
					// Defer completion for invalid parameter
					QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
					continue;
				}
				else
					item->OriginalOffset.QuadPart = addResult;

				// Hidden volume protection
				if (item->Write && queue->CryptoInfo->bProtectHiddenVolume)
				{
					// If there has already been a write operation denied in order to protect the
					// hidden volume (since the volume mount time)
					if (queue->CryptoInfo->bHiddenVolProtectionAction)
					{
						// Do not allow writing to this volume anymore. This is to fake a complete volume
						// or system failure (otherwise certain kinds of inconsistency within the file
						// system could indicate that this volume has used hidden volume protection).
						QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
						continue;
					}

					// Verify that no byte is going to be written to the hidden volume area
					if (RegionsOverlap ((unsigned __int64) item->OriginalOffset.QuadPart,
						(unsigned __int64) item->OriginalOffset.QuadPart + item->OriginalLength - 1,
						queue->CryptoInfo->hiddenVolumeOffset,
						(unsigned __int64) queue->CryptoInfo->hiddenVolumeOffset + queue->CryptoInfo->hiddenVolumeProtectedSize - 1))
					{
						Dump ("Hidden volume protection triggered: write %I64d-%I64d (protected %I64d-%I64d)\n", item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, queue->CryptoInfo->hiddenVolumeOffset, queue->CryptoInfo->hiddenVolumeOffset + queue->CryptoInfo->hiddenVolumeProtectedSize - 1);
						queue->CryptoInfo->bHiddenVolProtectionAction = TRUE;

						// Deny this write operation to prevent the hidden volume from being overwritten
						QueueIrpCompletionFromItem(queue, item, STATUS_INVALID_PARAMETER);
						continue;
					}
				}
			}
			else if (item->Write
				&& RegionsOverlap (item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET + TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE - 1))
			{
				// Prevent inappropriately designed software from damaging important data that may be out of sync with the backup on the Rescue Disk (such as the end of the encrypted area).
				Dump ("Preventing write to the system encryption key data area\n");
				QueueIrpCompletionFromItem(queue, item, STATUS_MEDIA_WRITE_PROTECTED);
				continue;
			}
			else if (item->Write && IsHiddenSystemRunning()
				&& (RegionsOverlap (item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, TC_SECTOR_SIZE_BIOS, TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS - 1)
				 || RegionsOverlap (item->OriginalOffset.QuadPart, item->OriginalOffset.QuadPart + item->OriginalLength - 1, GetBootDriveLength(), _I64_MAX)))
			{
				Dump ("Preventing write to boot loader or host protected area\n");
				QueueIrpCompletionFromItem(queue, item, STATUS_MEDIA_WRITE_PROTECTED);
				continue;
			} 
			else if (item->Write
				&& (queue->SecRegionData != NULL) && (queue->SecRegionSize > 512)
				&& UpdateBuffer (NULL, queue->SecRegionData, queue->SecRegionSize, item->OriginalOffset.QuadPart, item->OriginalLength, FALSE))
			{
				// Prevent inappropriately designed software from damaging important data
				Dump ("Preventing write to the system GPT area\n");
				QueueIrpCompletionFromItem(queue, item, STATUS_MEDIA_WRITE_PROTECTED);
				continue;
			}
			
			dataBuffer = NULL;
			NTSTATUS mapStatus = MapIrpDataBuffer(
				irp,
				item->Write,
				item->OriginalLength,
				&dataBuffer,
				&item->TempUserMdl);
			if (!NT_SUCCESS(mapStatus))
			{
				QueueIrpCompletionFromItem (queue, item, mapStatus);
				continue;
			}

			// Divide data block to fragments to enable efficient overlapping of encryption and IO operations

			dataRemaining = item->OriginalLength;
			fragmentOffset = item->OriginalOffset;

			while (dataRemaining > 0)
			{
				ULONG queueFragmentSize = queue->FragmentSize;
				BOOL isLastFragment = dataRemaining <= queueFragmentSize;

				ULONG dataFragmentLength = isLastFragment ? dataRemaining : queueFragmentSize;
				activeFragmentBuffer = (activeFragmentBuffer == queue->FragmentBufferA ? queue->FragmentBufferB : queue->FragmentBufferA);

				InterlockedIncrement (&queue->IoThreadPendingRequestCount);

				// Create IO request
				request = GetPoolBuffer (queue, sizeof (EncryptedIoRequest));
				if (!request)
				{
					InterlockedDecrement(&queue->IoThreadPendingRequestCount);
					QueueIrpCompletionFromItem (queue, item, STATUS_INSUFFICIENT_RESOURCES);
					break;
				}
				request->Item = item;
				request->CompleteOriginalIrp = isLastFragment;
				request->Offset = fragmentOffset;
				request->Data = activeFragmentBuffer;
				request->OrigDataBufferFragment = dataBuffer;
				request->Length = dataFragmentLength;

				if (queue->IsFilterDevice || queue->bSupportPartialEncryption)
				{
					if (queue->EncryptedAreaStart == -1 || queue->EncryptedAreaEnd == -1)
					{
						request->EncryptedLength = 0;
					}
					else
					{
						// Get intersection of data fragment with encrypted area
						GetIntersection (fragmentOffset.QuadPart, dataFragmentLength, queue->EncryptedAreaStart, queue->EncryptedAreaEnd, &intersectStart, &intersectLength);

						request->EncryptedOffset = intersectStart - fragmentOffset.QuadPart;
						request->EncryptedLength = intersectLength;
					}
				}
				else
				{
					request->EncryptedOffset = 0;
					request->EncryptedLength = dataFragmentLength;
				}

				AcquireFragmentBuffer (queue, activeFragmentBuffer);

				if (item->Write)
				{
					// Encrypt data
					memcpy (activeFragmentBuffer, dataBuffer, dataFragmentLength);

					if (request->EncryptedLength > 0)
					{
						UINT64_STRUCT dataUnit;
						ASSERT (request->EncryptedOffset + request->EncryptedLength <= request->Offset.QuadPart + request->Length);

						dataUnit.Value = (request->Offset.QuadPart + request->EncryptedOffset) / ENCRYPTION_DATA_UNIT_SIZE;

						if (queue->CryptoInfo->bPartitionInInactiveSysEncScope)
							dataUnit.Value += queue->CryptoInfo->FirstDataUnitNo.Value;
						else if (queue->RemapEncryptedArea)
							dataUnit.Value += queue->RemappedAreaDataUnitOffset;

						EncryptDataUnits (activeFragmentBuffer + request->EncryptedOffset, &dataUnit, request->EncryptedLength / ENCRYPTION_DATA_UNIT_SIZE, queue->CryptoInfo);
					}
				}

				// Queue IO request
				ExInterlockedInsertTailList (&queue->IoThreadQueue, &request->ListEntry, &queue->IoThreadQueueLock);
				KeSetEvent (&queue->IoThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);

				if (isLastFragment)
					break;

				dataRemaining -= queueFragmentSize;
				dataBuffer += queueFragmentSize;
				fragmentOffset.QuadPart += queueFragmentSize;
			}
		}
	}

	PsTerminateSystemThread (STATUS_SUCCESS);
}


NTSTATUS EncryptedIoQueueAddIrp (EncryptedIoQueue *queue, PIRP irp)
{
	NTSTATUS status;

	InterlockedIncrement (&queue->OutstandingIoCount);
	if (queue->StopPending)
	{
		Dump ("STATUS_DEVICE_NOT_READY  out=%d\n", queue->OutstandingIoCount);
		status = STATUS_DEVICE_NOT_READY;
		goto err;
	}

	status = IoAcquireRemoveLock (&queue->RemoveLock, irp);
	if (!NT_SUCCESS (status))
		goto err;

#ifdef TC_TRACE_IO_QUEUE
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (irp);
		Dump ("* %I64d [%I64d] %c len=%d out=%d\n", irpSp->MajorFunction == IRP_MJ_WRITE ? irpSp->Parameters.Write.ByteOffset : irpSp->Parameters.Read.ByteOffset, GetElapsedTime (&queue->LastPerformanceCounter), irpSp->MajorFunction == IRP_MJ_WRITE ? 'W' : 'R', irpSp->MajorFunction == IRP_MJ_WRITE ? irpSp->Parameters.Write.Length : irpSp->Parameters.Read.Length, queue->OutstandingIoCount);
	}
#endif

	IoMarkIrpPending (irp);

	ExInterlockedInsertTailList (&queue->MainThreadQueue, &irp->Tail.Overlay.ListEntry, &queue->MainThreadQueueLock);
	KeSetEvent (&queue->MainThreadQueueNotEmptyEvent, IO_DISK_INCREMENT, FALSE);

	return STATUS_PENDING;

err:
	DecrementOutstandingIoCount (queue);
	return status;
}


NTSTATUS EncryptedIoQueueHoldWhenIdle (EncryptedIoQueue *queue, int64 timeout)
{
	NTSTATUS status;
	ASSERT (!queue->Suspended);

	queue->SuspendPending = TRUE;

	while (TRUE)
	{
		while (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
		{
			LARGE_INTEGER waitTimeout;

			waitTimeout.QuadPart = timeout * -10000;
			status = KeWaitForSingleObject (&queue->NoOutstandingIoEvent, Executive, KernelMode, FALSE, timeout != 0 ? &waitTimeout : NULL);

			if (status == STATUS_TIMEOUT)
				status = STATUS_UNSUCCESSFUL;

			if (!NT_SUCCESS (status))
			{
				queue->SuspendPending = FALSE;
				return status;
			}

			TCSleep (1);
			if (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
			{
				queue->SuspendPending = FALSE;
				return STATUS_UNSUCCESSFUL;
			}
		}

		KeClearEvent (&queue->QueueResumedEvent);
		queue->Suspended = TRUE;

		if (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) == 0)
			break;

		queue->Suspended = FALSE;
		KeSetEvent (&queue->QueueResumedEvent, IO_DISK_INCREMENT, FALSE);
	}

	queue->ReadAheadBufferValid = FALSE;

	queue->SuspendPending = FALSE;
	return STATUS_SUCCESS;
}


BOOL EncryptedIoQueueIsSuspended (EncryptedIoQueue *queue)
{
	return queue->Suspended;
}


BOOL EncryptedIoQueueIsRunning (EncryptedIoQueue *queue)
{
	return !queue->StopPending;
}


NTSTATUS EncryptedIoQueueResumeFromHold (EncryptedIoQueue *queue)
{
	ASSERT (queue->Suspended);

	queue->Suspended = FALSE;
	KeSetEvent (&queue->QueueResumedEvent, IO_DISK_INCREMENT, FALSE);

	return STATUS_SUCCESS;
}


NTSTATUS EncryptedIoQueueStart (EncryptedIoQueue *queue)
{
	NTSTATUS status;
	EncryptedIoQueueBuffer *buffer;
	int i, j, preallocatedIoRequestCount, preallocatedItemCount, fragmentSize;

	preallocatedIoRequestCount = EncryptionIoRequestCount;
	preallocatedItemCount = EncryptionItemCount;
	fragmentSize = EncryptionFragmentSize;

	queue->StartPending = TRUE;
	queue->ThreadExitRequested = FALSE;

	queue->OutstandingIoCount = 0;
	queue->IoThreadPendingRequestCount = 0;

	queue->FirstPoolBuffer = NULL;
	KeInitializeMutex (&queue->BufferPoolMutex, 0);

	KeInitializeEvent (&queue->NoOutstandingIoEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&queue->PoolBufferFreeEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent (&queue->QueueResumedEvent, SynchronizationEvent, FALSE);

retry_fragmentAllocate:
	queue->FragmentBufferA = TCalloc (fragmentSize);
	if (!queue->FragmentBufferA)
	{
		if (fragmentSize > TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE)
		{
			fragmentSize = TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
			goto retry_fragmentAllocate;
		}
		else
			goto noMemory;
	}

	queue->FragmentBufferB = TCalloc (fragmentSize);
	if (!queue->FragmentBufferB)
	{
		if (fragmentSize > TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE)
		{
			fragmentSize = TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
			TCfree (queue->FragmentBufferA);
			queue->FragmentBufferA = NULL;
			goto retry_fragmentAllocate;
		}
		else
			goto noMemory;
	}

	queue->ReadAheadBufferValid = FALSE;
	queue->ReadAheadBuffer = TCalloc (fragmentSize);
	if (!queue->ReadAheadBuffer)
	{
		if (fragmentSize > TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE)
		{
			fragmentSize = TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE;
			TCfree (queue->FragmentBufferA);
			TCfree (queue->FragmentBufferB);
			queue->FragmentBufferA = NULL;
			queue->FragmentBufferB = NULL;
			goto retry_fragmentAllocate;
		}
		else
			goto noMemory;
	}

	queue->FragmentSize = fragmentSize;

	KeInitializeEvent (&queue->FragmentBufferAFreeEvent, SynchronizationEvent, TRUE);
	KeInitializeEvent (&queue->FragmentBufferBFreeEvent, SynchronizationEvent, TRUE);

retry_preallocated:
	// Preallocate buffers
	for (i = 0; i < preallocatedIoRequestCount; ++i)
	{
		if (i < preallocatedItemCount && !GetPoolBuffer (queue, sizeof (EncryptedIoQueueItem)))
		{
			if (preallocatedItemCount > TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT)
			{
				preallocatedItemCount = TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT;
				preallocatedIoRequestCount = TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT;
				FreePoolBuffers (queue);
				goto retry_preallocated;
			}
			else
				goto noMemory;
		}

		if (!GetPoolBuffer (queue, sizeof (EncryptedIoRequest)))
		{
			if (preallocatedIoRequestCount > TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT)
			{
				preallocatedItemCount = TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT;
				preallocatedIoRequestCount = TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT;
				FreePoolBuffers (queue);
				goto retry_preallocated;
			}
			else
				goto noMemory;
		}
	}

	for (buffer = queue->FirstPoolBuffer; buffer != NULL; buffer = buffer->NextBuffer)
	{
		buffer->InUse = FALSE;
	}

	// Initialize the free work item list
	InitializeListHead(&queue->FreeWorkItemsList);
	KeInitializeSemaphore(&queue->WorkItemSemaphore, EncryptionMaxWorkItems, EncryptionMaxWorkItems);
	KeInitializeSpinLock(&queue->WorkItemLock);

	queue->MaxWorkItems = EncryptionMaxWorkItems;
	queue->WorkItemPool = (PCOMPLETE_IRP_WORK_ITEM)TCalloc(sizeof(COMPLETE_IRP_WORK_ITEM) * queue->MaxWorkItems);
	if (!queue->WorkItemPool)
	{
		goto noMemory;
	}

	// Initialize the work item pool
	for (j = 0; j < (int) queue->MaxWorkItems; ++j)
	{
		queue->WorkItemPool[j].WorkItem = NULL;
	}

	// Allocate work items
	for (i = 0; i < (int) queue->MaxWorkItems; ++i)
	{
		queue->WorkItemPool[i].WorkItem = IoAllocateWorkItem(queue->DeviceObject);
		if (!queue->WorkItemPool[i].WorkItem)
		{
			goto noMemory;
		}

		// Insert the work item into the free list
		ExInterlockedInsertTailList(&queue->FreeWorkItemsList, &queue->WorkItemPool[i].ListEntry, &queue->WorkItemLock);
	}

	queue->ActiveWorkItems = 0;
	KeInitializeEvent(&queue->NoActiveWorkItemsEvent, NotificationEvent, FALSE);

	// Main thread
	InitializeListHead (&queue->MainThreadQueue);
	KeInitializeSpinLock (&queue->MainThreadQueueLock);
	KeInitializeEvent (&queue->MainThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThread (MainThreadProc, queue, &queue->MainThread);
	if (!NT_SUCCESS (status))
		goto err;

	// IO thread
	InitializeListHead (&queue->IoThreadQueue);
	KeInitializeSpinLock (&queue->IoThreadQueueLock);
	KeInitializeEvent (&queue->IoThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThread (IoThreadProc, queue, &queue->IoThread);
	if (!NT_SUCCESS (status))
	{
		queue->ThreadExitRequested = TRUE;
		TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
		goto err;
	}

	// Completion thread
	InitializeListHead (&queue->CompletionThreadQueue);
	KeInitializeSpinLock (&queue->CompletionThreadQueueLock);
	KeInitializeEvent (&queue->CompletionThreadQueueNotEmptyEvent, SynchronizationEvent, FALSE);

	status = TCStartThread (CompletionThreadProc, queue, &queue->CompletionThread);
	if (!NT_SUCCESS (status))
	{
		queue->ThreadExitRequested = TRUE;
		TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
		TCStopThread (queue->IoThread, &queue->IoThreadQueueNotEmptyEvent);
		goto err;
	}

#ifdef TC_TRACE_IO_QUEUE
	GetElapsedTimeInit (&queue->LastPerformanceCounter);
#endif

	queue->StopPending = FALSE;
	queue->StartPending = FALSE;

	Dump ("Queue started\n");
	return STATUS_SUCCESS;

noMemory:
	status = STATUS_INSUFFICIENT_RESOURCES;

err:
    if (queue->WorkItemPool)
	{
        for (i = 0; i < (int) queue->MaxWorkItems; ++i)
		{
            if (queue->WorkItemPool[i].WorkItem)
			{
                IoFreeWorkItem(queue->WorkItemPool[i].WorkItem);
                queue->WorkItemPool[i].WorkItem = NULL;
            }
        }
        TCfree(queue->WorkItemPool);
        queue->WorkItemPool = NULL;
    }
	if (queue->FragmentBufferA)
		TCfree (queue->FragmentBufferA);
	if (queue->FragmentBufferB)
		TCfree (queue->FragmentBufferB);
	if (queue->ReadAheadBuffer)
		TCfree (queue->ReadAheadBuffer);

	FreePoolBuffers (queue);

	queue->StartPending = FALSE;
	return status;
}


NTSTATUS EncryptedIoQueueStop (EncryptedIoQueue *queue)
{
	ASSERT (!queue->StopPending);
	queue->StopPending = TRUE;

	while (InterlockedExchangeAdd (&queue->OutstandingIoCount, 0) > 0)
	{
		KeWaitForSingleObject (&queue->NoOutstandingIoEvent, Executive, KernelMode, FALSE, NULL);
	}

	Dump ("Queue stopping  out=%d\n", queue->OutstandingIoCount);

	queue->ThreadExitRequested = TRUE;

	TCStopThread (queue->MainThread, &queue->MainThreadQueueNotEmptyEvent);
	TCStopThread (queue->IoThread, &queue->IoThreadQueueNotEmptyEvent);
	TCStopThread (queue->CompletionThread, &queue->CompletionThreadQueueNotEmptyEvent);

	// Wait for active work items to complete
	KeResetEvent(&queue->NoActiveWorkItemsEvent);
	Dump("Queue stopping  active work items=%d\n", queue->ActiveWorkItems);
	while (InterlockedCompareExchange(&queue->ActiveWorkItems, 0, 0) > 0)
	{
		KeWaitForSingleObject(&queue->NoActiveWorkItemsEvent, Executive, KernelMode, FALSE, NULL);
		// reset the event again in case multiple work items are completing
		KeResetEvent(&queue->NoActiveWorkItemsEvent);
	}

	// Free pre-allocated work items
	for (ULONG i = 0; i < queue->MaxWorkItems; ++i)
	{
		if (queue->WorkItemPool[i].WorkItem)
		{
			IoFreeWorkItem(queue->WorkItemPool[i].WorkItem);
			queue->WorkItemPool[i].WorkItem = NULL;
		}
	}
	TCfree(queue->WorkItemPool);

	TCfree (queue->FragmentBufferA);
	TCfree (queue->FragmentBufferB);
	TCfree (queue->ReadAheadBuffer);

	FreePoolBuffers (queue);

	Dump ("Queue stopped  out=%d\n", queue->OutstandingIoCount);
	return STATUS_SUCCESS;
}
