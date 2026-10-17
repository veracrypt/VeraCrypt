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

#ifndef TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE
#define TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE

#include "TCdefs.h"
#include "Apidrvr.h"

#if 0
#	define TC_TRACE_IO_QUEUE
#endif

#define TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE (256 * 1024)

#define TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT 8
#define TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT 16
#define TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_MAX_COUNT 8192

#define VC_MAX_WORK_ITEMS 1024 
#define VC_MOUNTED_VOLUME_FAST_IO_MAX_REQUEST_SIZE (1024U * 1024U)
#define VC_MOUNTED_VOLUME_FAST_IO_MAX_SEGMENT_SIZE VC_MOUNTED_VOLUME_FAST_IO_MAX_REQUEST_SIZE
#define VC_DIRECT_HOST_IO_THREAD_COUNT 8

typedef struct EncryptedIoQueueBufferStruct
{
	struct EncryptedIoQueueBufferStruct *NextBuffer;

	void *Address;
	ULONG Size;
	BOOL InUse;

} EncryptedIoQueueBuffer;

typedef struct _COMPLETE_IRP_WORK_ITEM
{
	PIO_WORKITEM WorkItem;
	PIRP Irp;
	NTSTATUS Status;
	ULONG_PTR Information;
	void* Item;
	LIST_ENTRY ListEntry; // For managing free work items
} COMPLETE_IRP_WORK_ITEM, * PCOMPLETE_IRP_WORK_ITEM;

typedef struct _VC_DIRECT_HOST_IO_TASK VC_DIRECT_HOST_IO_TASK;
typedef void (*VC_DIRECT_HOST_IO_TASK_ROUTINE) (VC_DIRECT_HOST_IO_TASK *task);

struct _VC_DIRECT_HOST_IO_TASK
{
	LIST_ENTRY ListEntry;
	VC_DIRECT_HOST_IO_TASK_ROUTINE Routine;
	PIRP IrpToMarkPending;
};

typedef struct
{
	PDEVICE_OBJECT DeviceObject;

	KMUTEX BufferPoolMutex;
	EncryptedIoQueueBuffer *FirstPoolBuffer;

	CRYPTO_INFO *CryptoInfo;

	// File-handle-based IO
	HANDLE HostFileHandle;
	PDEVICE_OBJECT HostDeviceObject;
	PFILE_OBJECT HostFileObject;
	ULONG HostDeviceIoMaxSize;
	ULONG DirectHostIoMaxRequestSize;
	ULONG HostAlignmentMask;
	uint32 HostBytesPerSector;
	BOOL DirectHostWriteConfigured;
	volatile LONG DirectHostReadEnabled;
	volatile LONG DirectHostWriteEnabled;
	KSPIN_LOCK DirectHostReadLock;
	KEVENT NoDirectHostReadsEvent;
	volatile LONG DirectHostReadsInFlight;
	KSPIN_LOCK DirectHostWriteLock;
	KEVENT NoDirectHostWritesEvent;
	KEVENT DirectHostWriteRangeChangedEvent;
	KSEMAPHORE DirectHostWriteSlots;
	LIST_ENTRY DirectHostWriteRanges;
	volatile LONG DirectHostWritesInFlight;
	volatile LONG PendingWriteBarrierCount;
	PKTHREAD DirectHostIoThreads[VC_DIRECT_HOST_IO_THREAD_COUNT];
	ULONG DirectHostIoThreadCount;
	LIST_ENTRY DirectHostIoQueue;
	KSPIN_LOCK DirectHostIoQueueLock;
	KSEMAPHORE DirectHostIoQueueSemaphore;
	volatile LONG DirectHostIoExitRequested;
	BOOL bSupportPartialEncryption;
	int64 VirtualDeviceLength;
	SECURITY_CLIENT_CONTEXT *SecurityClientContext;

	// Filter device
	BOOL IsFilterDevice;
	PDEVICE_OBJECT LowerDeviceObject;
	int64 EncryptedAreaStart;
	volatile int64 EncryptedAreaEnd;
	volatile BOOL EncryptedAreaEndUpdatePending;
	BOOL RemapEncryptedArea;
	int64 RemappedAreaOffset;
	int64 RemappedAreaDataUnitOffset;
	IO_REMOVE_LOCK RemoveLock;

	// Main tread
	PKTHREAD MainThread;
	LIST_ENTRY MainThreadQueue;
	KSPIN_LOCK MainThreadQueueLock;
	KEVENT MainThreadQueueNotEmptyEvent;

	// IO thread
	PKTHREAD IoThread;
	LIST_ENTRY IoThreadQueue;
	KSPIN_LOCK IoThreadQueueLock;
	KEVENT IoThreadQueueNotEmptyEvent;

	// Completion thread
	PKTHREAD CompletionThread;
	LIST_ENTRY CompletionThreadQueue;
	KSPIN_LOCK CompletionThreadQueueLock;
	KEVENT CompletionThreadQueueNotEmptyEvent;

	// Fragment buffers
	uint8 *FragmentBufferA;
	uint8 *FragmentBufferB;
	KEVENT FragmentBufferAFreeEvent;
	KEVENT FragmentBufferBFreeEvent;

	// Read-ahead buffer
	BOOL ReadAheadBufferValid;
	LARGE_INTEGER LastReadOffset;
	ULONG LastReadLength;
	LARGE_INTEGER ReadAheadOffset;
	ULONG ReadAheadLength;
	uint8 *ReadAheadBuffer;
	LARGE_INTEGER MaxReadAheadOffset;

	volatile LONG OutstandingIoCount;
	KEVENT NoOutstandingIoEvent;
	volatile LONG IoThreadPendingRequestCount;
	volatile LONG LegacyIoRequestsInFlight;
	KEVENT NoLegacyIoRequestsEvent;

	KEVENT PoolBufferFreeEvent;

	__int64 TotalBytesRead;
	__int64 TotalBytesWritten;

	volatile BOOL StartPending;
	volatile BOOL ThreadExitRequested;

	volatile BOOL Suspended;
	volatile BOOL SuspendPending;
	volatile BOOL StopPending;

	KEVENT QueueResumedEvent;

#ifdef TC_TRACE_IO_QUEUE
	LARGE_INTEGER LastPerformanceCounter;
#endif

 	uint8*  SecRegionData;
 	SIZE_T SecRegionSize;

	volatile BOOL ThreadBlockReadWrite;

	int FragmentSize;

	// Pre-allocated work items
	PCOMPLETE_IRP_WORK_ITEM WorkItemPool;
	ULONG MaxWorkItems;
	LIST_ENTRY FreeWorkItemsList;
	KSEMAPHORE WorkItemSemaphore;
	KSPIN_LOCK WorkItemLock;

	volatile LONG ActiveWorkItems;
	KEVENT NoActiveWorkItemsEvent;
}  EncryptedIoQueue;


typedef struct
{
	EncryptedIoQueue *Queue;
	PIRP OriginalIrp;
	BOOL Write;
	BOOL Flush;
	ULONG OriginalLength;
	LARGE_INTEGER OriginalOffset;
	NTSTATUS Status;
	PMDL TempUserMdl; // NULL if none. Used in MapIrpDataBuffer logic
	BOOL WriteBarrierTracked;

#ifdef TC_TRACE_IO_QUEUE
	LARGE_INTEGER OriginalIrpOffset;
#endif

} EncryptedIoQueueItem;


typedef struct
{
	EncryptedIoQueueItem *Item;

	BOOL CompleteOriginalIrp;
	LARGE_INTEGER Offset;
	ULONG Length;
	int64 EncryptedOffset;
	ULONG EncryptedLength;
	uint8 *Data;
	uint8 *OrigDataBufferFragment;

	LIST_ENTRY ListEntry;
	LIST_ENTRY CompletionListEntry;
} EncryptedIoRequest;


NTSTATUS EncryptedIoQueueAddIrp (EncryptedIoQueue *queue, PIRP irp);
BOOL EncryptedIoQueueIsRunning (EncryptedIoQueue *queue);
BOOL EncryptedIoQueueIsSuspended (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueResumeFromHold (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueStart (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueStop (EncryptedIoQueue *queue);
NTSTATUS EncryptedIoQueueHoldWhenIdle (EncryptedIoQueue *queue, int64 timeout);
NTSTATUS EncryptedIoQueueBeginDirectRead (EncryptedIoQueue *queue, PIRP irp);
NTSTATUS EncryptedIoQueueAdmitDirectRead (EncryptedIoQueue *queue);
void EncryptedIoQueueCancelDirectRead (EncryptedIoQueue *queue, PIRP irp);
void EncryptedIoQueueAbortDirectRead (EncryptedIoQueue *queue, PIRP irp);
void EncryptedIoQueueCompleteDirectRead (EncryptedIoQueue *queue, PIRP irp, ULONG length, NTSTATUS status, ULONG_PTR information);
BOOL EncryptedIoQueueSubmitDirectIoTask (EncryptedIoQueue *queue, VC_DIRECT_HOST_IO_TASK *task);


#endif // TC_HEADER_DRIVER_ENCRYPTED_IO_QUEUE
