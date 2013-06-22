/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2011 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_NTDRIVER
#define TC_HEADER_NTDRIVER

#include "Common.h"
#include "EncryptedIoQueue.h"

/* This structure is used to start new threads */
typedef struct _THREAD_BLOCK_
{
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS ntCreateStatus;
	WCHAR wszMountVolume[TC_MAX_PATH + 8];
	MOUNT_STRUCT *mount;
} THREAD_BLOCK, *PTHREAD_BLOCK;


/* This structure is allocated for non-root devices! WARNING: bRootDevice
   must be the first member of the structure! */
typedef struct EXTENSION
{
	BOOL bRootDevice;	/* Is this the root device ? which the user-mode apps talk to */
	BOOL IsVolumeDevice;
	BOOL IsDriveFilterDevice;
	BOOL IsVolumeFilterDevice;

	int UniqueVolumeId;
	int nDosDriveNo;	/* Drive number this extension is mounted against */

	BOOL bShuttingDown;			/* Is the driver shutting down ? */
	BOOL bThreadShouldQuit;		/* Instruct per device worker thread to quit */
	PETHREAD peThread;			/* Thread handle */
	KEVENT keCreateEvent;		/* Device creation event */
	KSPIN_LOCK ListSpinLock;	/* IRP spinlock */
	LIST_ENTRY ListEntry;		/* IRP listentry */
	KSEMAPHORE RequestSemaphore;	/* IRP list request  Semaphore */

	HANDLE hDeviceFile;			/* Device handle for this device */
	PFILE_OBJECT pfoDeviceFile;	/* Device fileobject for this device */
	PDEVICE_OBJECT pFsdDevice;	/* lower level device handle */

	CRYPTO_INFO *cryptoInfo;	/* Cryptographic and other information for this device */

	__int64	HostLength;
	__int64 DiskLength;			/* The length of the disk referred to by this device */  
	__int64 NumberOfCylinders;		/* Partition info */
	ULONG TracksPerCylinder;	/* Partition info */
	ULONG SectorsPerTrack;		/* Partition info */
	ULONG BytesPerSector;		/* Partition info */
	UCHAR PartitionType;		/* Partition info */
	
	uint32 HostBytesPerSector;

	KEVENT keVolumeEvent;		/* Event structure used when setting up a device */

	EncryptedIoQueue Queue;

	BOOL bReadOnly;				/* Is this device read-only ? */
	BOOL bRemovable;			/* Is this device removable media ? */
	BOOL PartitionInInactiveSysEncScope;
	BOOL bRawDevice;			/* Is this a raw-partition or raw-floppy device ? */
	BOOL bMountManager;			/* Mount manager knows about volume */
	BOOL SystemFavorite;

	WCHAR wszVolume[TC_MAX_PATH];	/*  DONT change this size without also changing MOUNT_LIST_STRUCT! */

	LARGE_INTEGER fileCreationTime;
	LARGE_INTEGER fileLastAccessTime;
	LARGE_INTEGER fileLastWriteTime;
	LARGE_INTEGER fileLastChangeTime;
	BOOL bTimeStampValid;

	PSID UserSid;
	BOOL SecurityClientContextValid;
	SECURITY_CLIENT_CONTEXT SecurityClientContext;

} EXTENSION, *PEXTENSION;


typedef enum
{
	ValidateInput,
	ValidateOutput,
	ValidateInputOutput
} ValidateIOBufferSizeType;


extern PDRIVER_OBJECT TCDriverObject;
extern PDEVICE_OBJECT RootDeviceObject;
extern BOOL DriverShuttingDown;
extern ULONG OsMajorVersion;
extern ULONG OsMinorVersion;
extern BOOL VolumeClassFilterRegistered;
extern BOOL CacheBootPassword;

/* Helper macro returning x seconds in units of 100 nanoseconds */
#define WAIT_SECONDS(x) ((x)*10000000)

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS DriverAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo);
void DumpMemory (void *memory, int size);
BOOL IsAccessibleByUser (PUNICODE_STRING objectFileName, BOOL readOnly);
NTSTATUS ProcessMainDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS ProcessVolumeDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp);
NTSTATUS SendDeviceIoControlRequest (PDEVICE_OBJECT deviceObject, ULONG ioControlCode, void *inputBuffer, int inputBufferSize, void *outputBuffer, int outputBufferSize);
NTSTATUS TCDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TCCreateRootDeviceObject (PDRIVER_OBJECT DriverObject);
NTSTATUS TCCreateDeviceObject (PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT * ppDeviceObject, MOUNT_STRUCT * mount);
NTSTATUS TCReadDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);
NTSTATUS TCWriteDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);
NTSTATUS TCStartThread (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread);
NTSTATUS TCStartThreadInProcess (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread, PEPROCESS process);
NTSTATUS TCStartVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount);
void TCStopThread (PKTHREAD kThread, PKEVENT wakeUpEvent);
void TCStopVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID VolumeThreadProc (PVOID Context);
void TCSleep (int milliSeconds);
void TCGetNTNameFromNumber (LPWSTR ntname, int nDriveNo);
void TCGetDosNameFromNumber (LPWSTR dosname, int nDriveNo);
LPWSTR TCTranslateCode (ULONG ulCode);
void TCDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension);
VOID TCUnloadDriver (PDRIVER_OBJECT DriverObject);
void OnShutdownPending ();
NTSTATUS TCDeviceIoControl (PWSTR deviceName, ULONG IoControlCode, void *InputBuffer, ULONG InputBufferSize, void *OutputBuffer, ULONG OutputBufferSize);
NTSTATUS TCOpenFsVolume (PEXTENSION Extension, PHANDLE volumeHandle, PFILE_OBJECT * fileObject);
void TCCloseFsVolume (HANDLE volumeHandle, PFILE_OBJECT fileObject);
NTSTATUS TCFsctlCall (PFILE_OBJECT fileObject, LONG IoControlCode, void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize);
NTSTATUS CreateDriveLink (int nDosDriveNo);
NTSTATUS RemoveDriveLink (int nDosDriveNo);
NTSTATUS MountManagerMount (MOUNT_STRUCT *mount);
NTSTATUS MountManagerUnmount (int nDosDriveNo);
NTSTATUS MountDevice (PDEVICE_OBJECT deviceObject, MOUNT_STRUCT *mount);
NTSTATUS UnmountDevice (UNMOUNT_STRUCT *unmountRequest, PDEVICE_OBJECT deviceObject, BOOL ignoreOpenFiles);
NTSTATUS UnmountAllDevices (UNMOUNT_STRUCT *unmountRequest, BOOL ignoreOpenFiles);
NTSTATUS SymbolicLinkToTarget (PWSTR symlinkName, PWSTR targetName, USHORT maxTargetNameLength);
BOOL RootDeviceControlMutexAcquireNoWait ();
void RootDeviceControlMutexRelease ();
BOOL RegionsOverlap (unsigned __int64 start1, unsigned __int64 end1, unsigned __int64 start2, unsigned __int64 end2);
void GetIntersection (uint64 start1, uint32 length1, uint64 start2, uint64 end2, uint64 *intersectStart, uint32 *intersectLength);
NTSTATUS TCCompleteIrp (PIRP irp, NTSTATUS status, ULONG_PTR information);
NTSTATUS TCCompleteDiskIrp (PIRP irp, NTSTATUS status, ULONG_PTR information);
NTSTATUS ProbeRealDriveSize (PDEVICE_OBJECT driveDeviceObject, LARGE_INTEGER *driveSize);
BOOL UserCanAccessDriveDevice ();
size_t GetCpuCount ();
void EnsureNullTerminatedString (wchar_t *str, size_t maxSizeInBytes);
void *AllocateMemoryWithTimeout (size_t size, int retryDelay, int timeout);
BOOL IsDriveLetterAvailable (int nDosDriveNo);
NTSTATUS TCReadRegistryKey (PUNICODE_STRING keyPath, wchar_t *keyValueName, PKEY_VALUE_PARTIAL_INFORMATION *keyData);
NTSTATUS TCWriteRegistryKey (PUNICODE_STRING keyPath, wchar_t *keyValueName, ULONG keyValueType, void *valueData, ULONG valueSize);
BOOL IsVolumeClassFilterRegistered ();
NTSTATUS ReadRegistryConfigFlags (BOOL driverEntry);
NTSTATUS WriteRegistryConfigFlags (uint32 flags);
BOOL ValidateIOBufferSize (PIRP irp, size_t requiredBufferSize, ValidateIOBufferSizeType type);
NTSTATUS GetDeviceSectorSize (PDEVICE_OBJECT deviceObject, ULONG *bytesPerSector);
NTSTATUS ZeroUnreadableSectors (PDEVICE_OBJECT deviceObject, LARGE_INTEGER startOffset, ULONG size, uint64 *zeroedSectorCount);
NTSTATUS ReadDeviceSkipUnreadableSectors (PDEVICE_OBJECT deviceObject, byte *buffer, LARGE_INTEGER startOffset, ULONG size, uint64 *badSectorCount);
BOOL IsVolumeAccessibleByCurrentUser (PEXTENSION volumeDeviceExtension);
void GetElapsedTimeInit (LARGE_INTEGER *lastPerfCounter);
int64 GetElapsedTime (LARGE_INTEGER *lastPerfCounter);
BOOL IsOSAtLeast (OSVersionEnum reqMinOS);

#define TC_BUG_CHECK(status) KeBugCheckEx (SECURITY_SYSTEM, __LINE__, (ULONG_PTR) status, 0, 'TC')

#endif // TC_HEADER_NTDRIVER
