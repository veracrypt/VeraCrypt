/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "TCdefs.h"
#include <ntddk.h>
#include "Crypto.h"
#include "Fat.h"
#include "Tests.h"
#include "cpu.h"
#include "Crc.h"

#include "Apidrvr.h"
#include "Boot/Windows/BootDefs.h"
#include "EncryptedIoQueue.h"
#include "EncryptionThreadPool.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "DriveFilter.h"
#include "DumpFilter.h"
#include "Cache.h"
#include "Volumes.h"
#include "VolumeFilter.h"

#include <tchar.h>
#include <initguid.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddvol.h>

#include <Ntstrsafe.h>
#include <Intsafe.h>

#ifndef IOCTL_DISK_GET_CLUSTER_INFO
#define IOCTL_DISK_GET_CLUSTER_INFO				CTL_CODE(IOCTL_DISK_BASE, 0x0085, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef IOCTL_DISK_ARE_VOLUMES_READY
#define IOCTL_DISK_ARE_VOLUMES_READY			CTL_CODE(IOCTL_DISK_BASE, 0x0087, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif

#ifndef FT_BALANCED_READ_MODE
#define FTTYPE  ((ULONG)'f') 
#define FT_BALANCED_READ_MODE						CTL_CODE(FTTYPE, 6, METHOD_NEITHER,  FILE_ANY_ACCESS) 
#endif

#ifndef IOCTL_VOLUME_QUERY_ALLOCATION_HINT
#define IOCTL_VOLUME_QUERY_ALLOCATION_HINT      CTL_CODE(IOCTL_VOLUME_BASE, 20, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#endif

#ifndef IOCTL_DISK_IS_CLUSTERED
#define IOCTL_DISK_IS_CLUSTERED             CTL_CODE(IOCTL_DISK_BASE, 0x003e, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef IOCTL_VOLUME_POST_ONLINE
#define IOCTL_VOLUME_POST_ONLINE                CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_VOLUME_IS_DYNAMIC
#define IOCTL_VOLUME_IS_DYNAMIC                 CTL_CODE(IOCTL_VOLUME_BASE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Init section, which is thrown away as soon as DriverEntry returns */
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(INIT,TCCreateRootDeviceObject)

/* We need to silence 'type cast' warning in order to use MmGetSystemRoutineAddress.
 * MmGetSystemRoutineAddress() should have been declare FARPROC instead of PVOID.
 */
#pragma warning(disable:4055)

PDRIVER_OBJECT TCDriverObject;
PDEVICE_OBJECT RootDeviceObject = NULL;
static KMUTEX RootDeviceControlMutex;
BOOL DriverShuttingDown = FALSE;
BOOL SelfTestsPassed;
int LastUniqueVolumeId;
ULONG OsMajorVersion = 0;
ULONG OsMinorVersion;
BOOL DriverUnloadDisabled = FALSE;
BOOL PortableMode = FALSE;
BOOL VolumeClassFilterRegistered = FALSE;
BOOL CacheBootPassword = FALSE;
BOOL CacheBootPim = FALSE;
BOOL NonAdminSystemFavoritesAccessDisabled = FALSE;
static size_t EncryptionThreadPoolFreeCpuCountLimit = 0;
static BOOL SystemFavoriteVolumeDirty = FALSE;
static BOOL PagingFileCreationPrevented = FALSE;
static BOOL EnableExtendedIoctlSupport = FALSE;
static KeSaveExtendedProcessorStateFn KeSaveExtendedProcessorStatePtr = NULL;
static KeRestoreExtendedProcessorStateFn KeRestoreExtendedProcessorStatePtr = NULL;

POOL_TYPE ExDefaultNonPagedPoolType = NonPagedPool;
ULONG ExDefaultMdlProtection = 0;

PDEVICE_OBJECT VirtualVolumeDeviceObjects[MAX_MOUNTED_VOLUME_DRIVE_NUMBER + 1];


NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	PKEY_VALUE_PARTIAL_INFORMATION startKeyValue;
	LONG version;
	int i;

	Dump ("DriverEntry " TC_APP_NAME " " VERSION_STRING "\n");

	DetectX86Features ();

	PsGetVersion (&OsMajorVersion, &OsMinorVersion, NULL, NULL);

	Dump ("OsMajorVersion=%d OsMinorVersion=%d\n", OsMajorVersion, OsMinorVersion);

	// NX pool support is available starting from Windows 8
	if ((OsMajorVersion > 6) || (OsMajorVersion == 6 && OsMinorVersion >= 2))
	{
		ExDefaultNonPagedPoolType = (POOL_TYPE) NonPagedPoolNx;
		ExDefaultMdlProtection = MdlMappingNoExecute;
	}

	// KeSaveExtendedProcessorState/KeRestoreExtendedProcessorState are available starting from Windows 7
	if ((OsMajorVersion > 6) || (OsMajorVersion == 6 && OsMinorVersion >= 1))
	{
		UNICODE_STRING saveFuncName, restoreFuncName;
		RtlInitUnicodeString(&saveFuncName, L"KeSaveExtendedProcessorState");
		RtlInitUnicodeString(&restoreFuncName, L"KeRestoreExtendedProcessorState");
		KeSaveExtendedProcessorStatePtr = (KeSaveExtendedProcessorStateFn) MmGetSystemRoutineAddress(&saveFuncName);
		KeRestoreExtendedProcessorStatePtr = (KeRestoreExtendedProcessorStateFn) MmGetSystemRoutineAddress(&restoreFuncName);
	}

	// Load dump filter if the main driver is already loaded
	if (NT_SUCCESS (TCDeviceIoControl (NT_ROOT_PREFIX, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &version, sizeof (version))))
		return DumpFilterEntry ((PFILTER_EXTENSION) DriverObject, (PFILTER_INITIALIZATION_DATA) RegistryPath);

	TCDriverObject = DriverObject;
	memset (VirtualVolumeDeviceObjects, 0, sizeof (VirtualVolumeDeviceObjects));

	ReadRegistryConfigFlags (TRUE);
	EncryptionThreadPoolStart (EncryptionThreadPoolFreeCpuCountLimit);
	SelfTestsPassed = AutoTestAlgorithms();

	// Enable device class filters and load boot arguments if the driver is set to start at system boot

	if (NT_SUCCESS (TCReadRegistryKey (RegistryPath, L"Start", &startKeyValue)))
	{
		if (startKeyValue->Type == REG_DWORD && *((uint32 *) startKeyValue->Data) == SERVICE_BOOT_START)
		{
			if (!SelfTestsPassed)
			{
				// in case of system encryption, if self-tests fail, disable all extended CPU
				// features and try again in order to workaround faulty configurations
				DisableCPUExtendedFeatures ();
				SelfTestsPassed = AutoTestAlgorithms();

				// BUG CHECK if the self-tests still fail
				if (!SelfTestsPassed)
					TC_BUG_CHECK (STATUS_INVALID_PARAMETER);
			}

			LoadBootArguments();
			VolumeClassFilterRegistered = IsVolumeClassFilterRegistered();

			DriverObject->DriverExtension->AddDevice = DriverAddDevice;
		}

		TCfree (startKeyValue);
	}

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		DriverObject->MajorFunction[i] = TCDispatchQueueIRP;
	}

	DriverObject->DriverUnload = TCUnloadDriver;
	return TCCreateRootDeviceObject (DriverObject);
}


NTSTATUS DriverAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo)
{
#if defined(DEBUG) || defined (DEBUG_TRACE)
	char nameInfoBuffer[128];
	POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION) nameInfoBuffer;
	ULONG nameInfoSize;
	Dump ("AddDevice pdo=%p type=%x name=%ws\n", pdo, pdo->DeviceType, NT_SUCCESS (ObQueryNameString (pdo, nameInfo, sizeof (nameInfoBuffer), &nameInfoSize)) ? nameInfo->Name.Buffer : L"?");
#endif

	if (VolumeClassFilterRegistered && BootArgsValid && BootArgs.HiddenSystemPartitionStart != 0)
	{
		PWSTR interfaceLinks = NULL;
		if (NT_SUCCESS (IoGetDeviceInterfaces (&GUID_DEVINTERFACE_VOLUME, pdo, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &interfaceLinks)) && interfaceLinks)
		{
			if (interfaceLinks[0] != UNICODE_NULL)
			{
				Dump ("Volume pdo=%p interface=%ws\n", pdo, interfaceLinks);
				ExFreePool (interfaceLinks);

				return VolumeFilterAddDevice (driverObject, pdo);
			}

			ExFreePool (interfaceLinks);
		}
	}

	return DriveFilterAddDevice (driverObject, pdo);
}


// Dumps a memory region to debug output
void DumpMemory (void *mem, int size)
{
	unsigned char str[20];
	unsigned char *m = mem;
	int i,j;

	for (j = 0; j < size / 8; j++)
	{
		memset (str,0,sizeof str);
		for (i = 0; i < 8; i++)
		{
			if (m[i] > ' ' && m[i] <= '~')
				str[i]=m[i];
			else
				str[i]='.';
		}

		Dump ("0x%08p  %02x %02x %02x %02x %02x %02x %02x %02x  %s\n",
			m, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], str);

		m+=8;
	}
}

BOOL IsAllZeroes (unsigned char* pbData, DWORD dwDataLen)
{
	while (dwDataLen--)
	{
		if (*pbData)
			return FALSE;
		pbData++;
	}
	return TRUE;
}

BOOL ValidateIOBufferSize (PIRP irp, size_t requiredBufferSize, ValidateIOBufferSizeType type)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (irp);
	BOOL input = (type == ValidateInput || type == ValidateInputOutput);
	BOOL output = (type == ValidateOutput || type == ValidateInputOutput);

	if ((input && irpSp->Parameters.DeviceIoControl.InputBufferLength < requiredBufferSize)
		|| (output && irpSp->Parameters.DeviceIoControl.OutputBufferLength < requiredBufferSize))
	{
		Dump ("STATUS_BUFFER_TOO_SMALL ioctl=0x%x,%d in=%d out=%d reqsize=%d insize=%d outsize=%d\n", (int) (irpSp->Parameters.DeviceIoControl.IoControlCode >> 16), (int) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x1FFF) >> 2), input, output, requiredBufferSize, irpSp->Parameters.DeviceIoControl.InputBufferLength, irpSp->Parameters.DeviceIoControl.OutputBufferLength);

		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
		return FALSE;
	}

	if (!input && output)
		memset (irp->AssociatedIrp.SystemBuffer, 0, irpSp->Parameters.DeviceIoControl.OutputBufferLength);

	return TRUE;
}


PDEVICE_OBJECT GetVirtualVolumeDeviceObject (int driveNumber)
{
	if (driveNumber < MIN_MOUNTED_VOLUME_DRIVE_NUMBER || driveNumber > MAX_MOUNTED_VOLUME_DRIVE_NUMBER)
		return NULL;

	return VirtualVolumeDeviceObjects[driveNumber];
}


/* TCDispatchQueueIRP queues any IRP's so that they can be processed later
   by the thread -- or in some cases handles them immediately! */
NTSTATUS TCDispatchQueueIRP (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PEXTENSION Extension = (PEXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS ntStatus;

#if defined(_DEBUG) || defined (_DEBUG_TRACE)
	if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL && (Extension->bRootDevice || Extension->IsVolumeDevice))
	{
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case TC_IOCTL_GET_MOUNTED_VOLUMES:
		case TC_IOCTL_GET_PASSWORD_CACHE_STATUS:
		case TC_IOCTL_GET_PORTABLE_MODE_STATUS:
		case TC_IOCTL_SET_PORTABLE_MODE_STATUS:
		case TC_IOCTL_OPEN_TEST:
		case TC_IOCTL_GET_RESOLVED_SYMLINK:
		case TC_IOCTL_GET_DEVICE_REFCOUNT:
		case TC_IOCTL_GET_DRIVE_PARTITION_INFO:
		case TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES:
		case TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS:
		case TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS:
		case TC_IOCTL_GET_WARNING_FLAGS:
		case TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING:
		case IOCTL_DISK_CHECK_VERIFY:
			break;

		default:
			Dump ("%ls (0x%x %d)\n",
				TCTranslateCode (irpSp->Parameters.DeviceIoControl.IoControlCode),
				(int) (irpSp->Parameters.DeviceIoControl.IoControlCode >> 16),
				(int) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x1FFF) >> 2));
		}
	}
#endif

	if (!Extension->bRootDevice)
	{
		// Drive filter IRP
		if (Extension->IsDriveFilterDevice)
			return DriveFilterDispatchIrp (DeviceObject, Irp);

		// Volume filter IRP
		if (Extension->IsVolumeFilterDevice)
			return VolumeFilterDispatchIrp (DeviceObject, Irp);
	}

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_CLOSE:
	case IRP_MJ_CREATE:
	case IRP_MJ_CLEANUP:
		return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);

	case IRP_MJ_SHUTDOWN:
		if (Extension->bRootDevice)
		{
			Dump ("Driver shutting down\n");
			DriverShuttingDown = TRUE;

			if (EncryptionSetupThread)
				while (SendDeviceIoControlRequest (RootDeviceObject, TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP, NULL, 0, NULL, 0) == STATUS_INSUFFICIENT_RESOURCES);

			if (DecoySystemWipeThread)
				while (SendDeviceIoControlRequest (RootDeviceObject, TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE, NULL, 0, NULL, 0) == STATUS_INSUFFICIENT_RESOURCES);

			OnShutdownPending();
		}

		return COMPLETE_IRP (DeviceObject, Irp, STATUS_SUCCESS, 0);

	case IRP_MJ_FLUSH_BUFFERS:
	case IRP_MJ_READ:
	case IRP_MJ_WRITE:
	case IRP_MJ_DEVICE_CONTROL:

		if (Extension->bRootDevice)
		{
			if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
			{
				NTSTATUS status = KeWaitForMutexObject (&RootDeviceControlMutex, Executive, KernelMode, FALSE, NULL);
				if (!NT_SUCCESS (status))
					return status;

				status = ProcessMainDeviceControlIrp (DeviceObject, Extension, Irp);

				KeReleaseMutex (&RootDeviceControlMutex, FALSE);
				return status;
			}
			break;
		}

		if (Extension->bShuttingDown)
		{
			Dump ("Device %d shutting down: STATUS_DELETE_PENDING\n", Extension->nDosDriveNo);
			return TCCompleteDiskIrp (Irp, STATUS_DELETE_PENDING, 0);
		}

		if (Extension->bRemovable
			&& (DeviceObject->Flags & DO_VERIFY_VOLUME)
			&& !(irpSp->Flags & SL_OVERRIDE_VERIFY_VOLUME)
			&& irpSp->MajorFunction != IRP_MJ_FLUSH_BUFFERS)
		{
			Dump ("Removable device %d has DO_VERIFY_VOLUME flag: STATUS_DEVICE_NOT_READY\n", Extension->nDosDriveNo);
			return TCCompleteDiskIrp (Irp, STATUS_DEVICE_NOT_READY, 0);
		}

		switch (irpSp->MajorFunction)
		{
		case IRP_MJ_READ:
		case IRP_MJ_WRITE:
			ntStatus = EncryptedIoQueueAddIrp (&Extension->Queue, Irp);

			if (ntStatus != STATUS_PENDING)
				TCCompleteDiskIrp (Irp, ntStatus, 0);

			return ntStatus;

		case IRP_MJ_DEVICE_CONTROL:
			ntStatus = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
			if (!NT_SUCCESS (ntStatus))
				return TCCompleteIrp (Irp, ntStatus, 0);

			IoMarkIrpPending (Irp);

			ExInterlockedInsertTailList (&Extension->ListEntry, &Irp->Tail.Overlay.ListEntry, &Extension->ListSpinLock);
			KeReleaseSemaphore (&Extension->RequestSemaphore, IO_DISK_INCREMENT, 1, FALSE);

			return STATUS_PENDING;

		case IRP_MJ_FLUSH_BUFFERS:
			return TCCompleteDiskIrp (Irp, STATUS_SUCCESS, 0);
		}

		break;

	case IRP_MJ_PNP:
		if (!Extension->bRootDevice
			&& Extension->IsVolumeDevice
			&& irpSp->MinorFunction == IRP_MN_DEVICE_USAGE_NOTIFICATION
			&& irpSp->Parameters.UsageNotification.Type == DeviceUsageTypePaging
			&& irpSp->Parameters.UsageNotification.InPath)
		{
			PagingFileCreationPrevented = TRUE;
			return TCCompleteIrp (Irp, STATUS_UNSUCCESSFUL, 0);
		}
		break;
	}

	return TCCompleteIrp (Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

NTSTATUS TCCreateRootDeviceObject (PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING Win32NameString, ntUnicodeString;
	WCHAR dosname[32], ntname[32];
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS ntStatus;
	BOOL *bRootExtension;

	Dump ("TCCreateRootDeviceObject BEGIN\n");
	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

	RtlStringCbCopyW (dosname, sizeof(dosname),(LPWSTR) DOS_ROOT_PREFIX);
	RtlStringCbCopyW (ntname, sizeof(ntname),(LPWSTR) NT_ROOT_PREFIX);
	RtlInitUnicodeString (&ntUnicodeString, ntname);
	RtlInitUnicodeString (&Win32NameString, dosname);

	Dump ("Creating root device nt=%ls dos=%ls\n", ntname, dosname);

	ntStatus = IoCreateDevice (
					  DriverObject,
					  sizeof (BOOL),
					  &ntUnicodeString,
					  FILE_DEVICE_UNKNOWN,
					  FILE_DEVICE_SECURE_OPEN,
					  FALSE,
					  &DeviceObject);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateRootDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		return ntStatus;/* Failed to create DeviceObject */
	}

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;

	/* Setup the device extension */
	bRootExtension = (BOOL *) DeviceObject->DeviceExtension;
	*bRootExtension = TRUE;

	KeInitializeMutex (&RootDeviceControlMutex, 0);

	ntStatus = IoCreateSymbolicLink (&Win32NameString, &ntUnicodeString);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateRootDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		IoDeleteDevice (DeviceObject);
		return ntStatus;
	}

	IoRegisterShutdownNotification (DeviceObject);
	RootDeviceObject = DeviceObject;

	Dump ("TCCreateRootDeviceObject STATUS_SUCCESS END\n");
	return STATUS_SUCCESS;
}

NTSTATUS TCCreateDeviceObject (PDRIVER_OBJECT DriverObject,
		       PDEVICE_OBJECT * ppDeviceObject,
		       MOUNT_STRUCT * mount)
{
	UNICODE_STRING ntUnicodeString;
	WCHAR ntname[32];
	PEXTENSION Extension;
	NTSTATUS ntStatus;
	ULONG devChars = 0;
#if defined (DEBUG) || defined (DEBUG_TRACE)
	WCHAR dosname[32];
#endif

	Dump ("TCCreateDeviceObject BEGIN\n");
	ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

	TCGetNTNameFromNumber (ntname, sizeof(ntname),mount->nDosDriveNo);
	RtlInitUnicodeString (&ntUnicodeString, ntname);
#if defined (DEBUG) || defined (DEBUG_TRACE)
	TCGetDosNameFromNumber (dosname, sizeof(dosname),mount->nDosDriveNo, DeviceNamespaceDefault);
#endif

	devChars = FILE_DEVICE_SECURE_OPEN;
	devChars |= mount->bMountReadOnly ? FILE_READ_ONLY_DEVICE : 0;
	devChars |= mount->bMountRemovable ? FILE_REMOVABLE_MEDIA : 0;

#if defined (DEBUG) || defined (DEBUG_TRACE)
	Dump ("Creating device nt=%ls dos=%ls\n", ntname, dosname);
#endif

	ntStatus = IoCreateDevice (
					  DriverObject,			/* Our Driver Object */
					  sizeof (EXTENSION),	/* Size of state information */
					  &ntUnicodeString,		/* Device name "\Device\Name" */
					  FILE_DEVICE_DISK,		/* Device type */
					  devChars,				/* Device characteristics */
					  FALSE,				/* Exclusive device */
					  ppDeviceObject);		/* Returned ptr to Device Object */

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("TCCreateDeviceObject NTSTATUS = 0x%08x END\n", ntStatus);
		return ntStatus;/* Failed to create DeviceObject */
	}
	/* Initialize device object and extension. */

	(*ppDeviceObject)->Flags |= DO_DIRECT_IO;
	(*ppDeviceObject)->StackSize += 6;		// Reduce occurrence of NO_MORE_IRP_STACK_LOCATIONS bug check caused by buggy drivers

	/* Setup the device extension */
	Extension = (PEXTENSION) (*ppDeviceObject)->DeviceExtension;
	memset (Extension, 0, sizeof (EXTENSION));

	Extension->IsVolumeDevice = TRUE;
	Extension->nDosDriveNo = mount->nDosDriveNo;
	Extension->bRemovable = mount->bMountRemovable;
	Extension->PartitionInInactiveSysEncScope = mount->bPartitionInInactiveSysEncScope;
	Extension->SystemFavorite = mount->SystemFavorite;

	KeInitializeEvent (&Extension->keCreateEvent, SynchronizationEvent, FALSE);
	KeInitializeSemaphore (&Extension->RequestSemaphore, 0L, MAXLONG);
	KeInitializeSpinLock (&Extension->ListSpinLock);
	InitializeListHead (&Extension->ListEntry);
	IoInitializeRemoveLock (&Extension->Queue.RemoveLock, 'LRCV', 0, 0);

	VirtualVolumeDeviceObjects[mount->nDosDriveNo] = *ppDeviceObject;

	Dump ("TCCreateDeviceObject STATUS_SUCCESS END\n");

	return STATUS_SUCCESS;
}


BOOL RootDeviceControlMutexAcquireNoWait ()
{
	NTSTATUS status;
	LARGE_INTEGER timeout;
	timeout.QuadPart = 0;

	status = KeWaitForMutexObject (&RootDeviceControlMutex, Executive, KernelMode, FALSE, &timeout);
	return NT_SUCCESS (status) && status != STATUS_TIMEOUT;
}


void RootDeviceControlMutexRelease ()
{
	KeReleaseMutex (&RootDeviceControlMutex, FALSE);
}

/*
IOCTL_STORAGE_GET_DEVICE_NUMBER 0x002D1080 
IOCTL_STORAGE_GET_HOTPLUG_INFO 0x002D0C14
IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400
*/

NTSTATUS ProcessVolumeDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_MOUNTDEV_QUERY_DEVICE_NAME)\n");
		if (!ValidateIOBufferSize (Irp, sizeof (MOUNTDEV_NAME), ValidateOutput))
		{
			Irp->IoStatus.Information = sizeof (MOUNTDEV_NAME);
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
		}
		else
		{
			ULONG outLength;
			UNICODE_STRING ntUnicodeString;
			WCHAR ntName[256];
			PMOUNTDEV_NAME outputBuffer = (PMOUNTDEV_NAME) Irp->AssociatedIrp.SystemBuffer;

			TCGetNTNameFromNumber (ntName, sizeof(ntName),Extension->nDosDriveNo);
			RtlInitUnicodeString (&ntUnicodeString, ntName);

			outputBuffer->NameLength = ntUnicodeString.Length;
			outLength = ntUnicodeString.Length + sizeof(USHORT);

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_NAME);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;

				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("name = %ls\n",ntName);
		}
		break;

	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_MOUNTDEV_QUERY_UNIQUE_ID)\n");
		if (!ValidateIOBufferSize (Irp, sizeof (MOUNTDEV_UNIQUE_ID), ValidateOutput))
		{
			Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
		}
		else
		{
			ULONG outLength;
			UCHAR volId[128], tmp[] = { 0,0 };
			PMOUNTDEV_UNIQUE_ID outputBuffer = (PMOUNTDEV_UNIQUE_ID) Irp->AssociatedIrp.SystemBuffer;

			RtlStringCbCopyA (volId, sizeof(volId),TC_UNIQUE_ID_PREFIX);
			tmp[0] = 'A' + (UCHAR) Extension->nDosDriveNo;
			RtlStringCbCatA (volId, sizeof(volId),tmp);

			outputBuffer->UniqueIdLength = (USHORT) strlen (volId);
			outLength = (ULONG) (strlen (volId) + sizeof (USHORT));

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->UniqueId, volId, strlen (volId));

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("id = %s\n",volId);
		}
		break;

	case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME)\n");
		{
			ULONG outLength;
			UNICODE_STRING ntUnicodeString;
			WCHAR ntName[256];
			PMOUNTDEV_SUGGESTED_LINK_NAME outputBuffer = (PMOUNTDEV_SUGGESTED_LINK_NAME) Irp->AssociatedIrp.SystemBuffer;

			if (!ValidateIOBufferSize (Irp, sizeof (MOUNTDEV_SUGGESTED_LINK_NAME), ValidateOutput))
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				Irp->IoStatus.Information = 0;
				break;
			}

			TCGetDosNameFromNumber (ntName, sizeof(ntName),Extension->nDosDriveNo, DeviceNamespaceDefault);
			RtlInitUnicodeString (&ntUnicodeString, ntName);

			outLength = FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME,Name) + ntUnicodeString.Length;

			outputBuffer->UseOnlyIfThereAreNoOtherLinks = FALSE;
			outputBuffer->NameLength = ntUnicodeString.Length;

			if(irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
			{
				Irp->IoStatus.Information = sizeof (MOUNTDEV_SUGGESTED_LINK_NAME);
				Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = outLength;

			Dump ("link = %ls\n",ntName);
		}
		break;

	case IOCTL_DISK_GET_MEDIA_TYPES:
	case IOCTL_STORAGE_GET_MEDIA_TYPES:
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_DRIVE_GEOMETRY)\n");
		/* Return the drive geometry for the disk.  Note that we
		   return values which were made up to suit the disk size.  */
		if (ValidateIOBufferSize (Irp, sizeof (DISK_GEOMETRY), ValidateOutput))
		{
			PDISK_GEOMETRY outputBuffer = (PDISK_GEOMETRY)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->MediaType = Extension->bRemovable ? RemovableMedia : FixedMedia;
			outputBuffer->Cylinders.QuadPart = Extension->NumberOfCylinders;
			outputBuffer->TracksPerCylinder = Extension->TracksPerCylinder;
			outputBuffer->SectorsPerTrack = Extension->SectorsPerTrack;
			outputBuffer->BytesPerSector = Extension->BytesPerSector;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (DISK_GEOMETRY);
		}
		break;

	case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			/* Return the drive geometry for the disk and its size.*/
			if (ValidateIOBufferSize (Irp, sizeof (DISK_GEOMETRY_EX), ValidateOutput))
			{
				PDISK_GEOMETRY_EX outputBuffer = (PDISK_GEOMETRY_EX)
				Irp->AssociatedIrp.SystemBuffer;

				outputBuffer->Geometry.MediaType = Extension->bRemovable ? RemovableMedia : FixedMedia;
				outputBuffer->Geometry.Cylinders.QuadPart = Extension->NumberOfCylinders;
				outputBuffer->Geometry.TracksPerCylinder = Extension->TracksPerCylinder;
				outputBuffer->Geometry.SectorsPerTrack = Extension->SectorsPerTrack;
				outputBuffer->Geometry.BytesPerSector = Extension->BytesPerSector;
				outputBuffer->DiskSize.QuadPart = Extension->DiskLength;
				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (DISK_GEOMETRY_EX);
			}
		}
		break;

	case IOCTL_STORAGE_QUERY_PROPERTY:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_STORAGE_QUERY_PROPERTY)\n");		
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (STORAGE_PROPERTY_QUERY), ValidateInput))
			{
				PSTORAGE_PROPERTY_QUERY pStoragePropQuery = (PSTORAGE_PROPERTY_QUERY) Irp->AssociatedIrp.SystemBuffer;
				STORAGE_QUERY_TYPE type = pStoragePropQuery->QueryType;

				Dump ("IOCTL_STORAGE_QUERY_PROPERTY - PropertyId = %d, type = %d\n", pStoragePropQuery->PropertyId, type);

				/* return error if an unsupported type is encountered */
				Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

				if (	(pStoragePropQuery->PropertyId == StorageAccessAlignmentProperty)
					||	(pStoragePropQuery->PropertyId == StorageDeviceProperty)
					||	(pStoragePropQuery->PropertyId == StorageAdapterProperty)
					||	(pStoragePropQuery->PropertyId == StorageDeviceSeekPenaltyProperty)
					||	(pStoragePropQuery->PropertyId == StorageDeviceTrimProperty)
					)
				{
					if (type == PropertyExistsQuery)
					{
						Irp->IoStatus.Status = STATUS_SUCCESS;
						Irp->IoStatus.Information = 0;
					}
					else if (type == PropertyStandardQuery)
					{
						switch (pStoragePropQuery->PropertyId)
						{
							case StorageDeviceProperty:
								{
									/* Add 0x00 for NULL terminating string used as ProductId, ProductRevision, SerialNumber, VendorId */
									ULONG descriptorSize = sizeof (STORAGE_DEVICE_DESCRIPTOR) + 1;
									if (ValidateIOBufferSize (Irp, descriptorSize, ValidateOutput))
									{
										PSTORAGE_DEVICE_DESCRIPTOR outputBuffer = (PSTORAGE_DEVICE_DESCRIPTOR) Irp->AssociatedIrp.SystemBuffer;

										outputBuffer->Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->Size = descriptorSize;
										outputBuffer->DeviceType = FILE_DEVICE_DISK;
										outputBuffer->RemovableMedia = Extension->bRemovable? TRUE : FALSE;
										outputBuffer->ProductIdOffset = sizeof (STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->SerialNumberOffset = sizeof (STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->ProductRevisionOffset = sizeof (STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->VendorIdOffset = sizeof (STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->BusType = BusTypeVirtual;
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = descriptorSize;
									}
									else if (irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof (STORAGE_DESCRIPTOR_HEADER))
									{
										PSTORAGE_DESCRIPTOR_HEADER outputBuffer = (PSTORAGE_DESCRIPTOR_HEADER) Irp->AssociatedIrp.SystemBuffer;
										outputBuffer->Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
										outputBuffer->Size = descriptorSize;
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_DESCRIPTOR_HEADER);
									}
								}
								break;
							case StorageAdapterProperty:
								{
									ULONG descriptorSize = sizeof (STORAGE_ADAPTER_DESCRIPTOR);
									if (ValidateIOBufferSize (Irp, descriptorSize, ValidateOutput))
									{
										PSTORAGE_ADAPTER_DESCRIPTOR outputBuffer = (PSTORAGE_ADAPTER_DESCRIPTOR) Irp->AssociatedIrp.SystemBuffer;

										outputBuffer->Version = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
										outputBuffer->Size = descriptorSize;
										outputBuffer->MaximumTransferLength = Extension->HostMaximumTransferLength;
										outputBuffer->MaximumPhysicalPages = Extension->HostMaximumPhysicalPages;
										outputBuffer->AlignmentMask = Extension->HostAlignmentMask;
										outputBuffer->BusType = BusTypeVirtual;
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = descriptorSize;
									}
									else if (irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof (STORAGE_DESCRIPTOR_HEADER))
									{
										PSTORAGE_DESCRIPTOR_HEADER outputBuffer = (PSTORAGE_DESCRIPTOR_HEADER) Irp->AssociatedIrp.SystemBuffer;
										outputBuffer->Version = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
										outputBuffer->Size = descriptorSize;
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_DESCRIPTOR_HEADER);
									}
								}
								break;
							case StorageAccessAlignmentProperty:
								{
									if (ValidateIOBufferSize (Irp, sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR), ValidateOutput))
									{
										PSTORAGE_ACCESS_ALIGNMENT_DESCRIPTOR outputBuffer = (PSTORAGE_ACCESS_ALIGNMENT_DESCRIPTOR) Irp->AssociatedIrp.SystemBuffer;

										outputBuffer->Version = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
										outputBuffer->Size = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
										outputBuffer->BytesPerLogicalSector = Extension->BytesPerSector;
										outputBuffer->BytesPerPhysicalSector = Extension->HostBytesPerPhysicalSector;										
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
									}
									else if (irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof (STORAGE_DESCRIPTOR_HEADER))
									{
										PSTORAGE_DESCRIPTOR_HEADER outputBuffer = (PSTORAGE_DESCRIPTOR_HEADER) Irp->AssociatedIrp.SystemBuffer;
										outputBuffer->Version = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
										outputBuffer->Size = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_DESCRIPTOR_HEADER);
									}
								}
								break;
							case StorageDeviceSeekPenaltyProperty:
								{
									if (ValidateIOBufferSize (Irp, sizeof (DEVICE_SEEK_PENALTY_DESCRIPTOR), ValidateOutput))
									{
										PDEVICE_SEEK_PENALTY_DESCRIPTOR outputBuffer = (PDEVICE_SEEK_PENALTY_DESCRIPTOR) Irp->AssociatedIrp.SystemBuffer;

										outputBuffer->Version = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
										outputBuffer->Size = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
										outputBuffer->IncursSeekPenalty = TRUE; //TODO: in case of SSD drive, we should probably return FALSE
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (DEVICE_SEEK_PENALTY_DESCRIPTOR);
									}
									else if (irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof (STORAGE_DESCRIPTOR_HEADER))
									{
										PSTORAGE_DESCRIPTOR_HEADER outputBuffer = (PSTORAGE_DESCRIPTOR_HEADER) Irp->AssociatedIrp.SystemBuffer;
										outputBuffer->Version = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
										outputBuffer->Size = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_DESCRIPTOR_HEADER);
									}
								}
								break;
							case StorageDeviceTrimProperty:
								{
									if (ValidateIOBufferSize (Irp, sizeof (DEVICE_TRIM_DESCRIPTOR), ValidateOutput))
									{
										PDEVICE_TRIM_DESCRIPTOR outputBuffer = (PDEVICE_TRIM_DESCRIPTOR) Irp->AssociatedIrp.SystemBuffer;

										outputBuffer->Version = sizeof(DEVICE_TRIM_DESCRIPTOR);
										outputBuffer->Size = sizeof(DEVICE_TRIM_DESCRIPTOR);
										outputBuffer->TrimEnabled = FALSE; /* TODO: implement Trim support for SSD drives */
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (DEVICE_TRIM_DESCRIPTOR);
									}
									else if (irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof (STORAGE_DESCRIPTOR_HEADER))
									{
										PSTORAGE_DESCRIPTOR_HEADER outputBuffer = (PSTORAGE_DESCRIPTOR_HEADER) Irp->AssociatedIrp.SystemBuffer;
										outputBuffer->Version = sizeof(DEVICE_TRIM_DESCRIPTOR);
										outputBuffer->Size = sizeof(DEVICE_TRIM_DESCRIPTOR);
										Irp->IoStatus.Status = STATUS_SUCCESS;
										Irp->IoStatus.Information = sizeof (STORAGE_DESCRIPTOR_HEADER);
									}
								}
								break;
						}
					}
				}
			}
		}

		break;

	case IOCTL_DISK_GET_PARTITION_INFO:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_PARTITION_INFO)\n");
		if (ValidateIOBufferSize (Irp, sizeof (PARTITION_INFORMATION), ValidateOutput))
		{
			PPARTITION_INFORMATION outputBuffer = (PPARTITION_INFORMATION)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->PartitionType = Extension->PartitionType;
			outputBuffer->BootIndicator = FALSE;
			outputBuffer->RecognizedPartition = TRUE;
			outputBuffer->RewritePartition = FALSE;
			outputBuffer->StartingOffset.QuadPart = Extension->BytesPerSector;
			outputBuffer->PartitionLength.QuadPart= Extension->DiskLength;
			outputBuffer->PartitionNumber = 1;
			outputBuffer->HiddenSectors = 0;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (PARTITION_INFORMATION);
		}
		break;

	case IOCTL_DISK_GET_PARTITION_INFO_EX:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_PARTITION_INFO_EX)\n");
		if (ValidateIOBufferSize (Irp, sizeof (PARTITION_INFORMATION_EX), ValidateOutput))
		{
			PPARTITION_INFORMATION_EX outputBuffer = (PPARTITION_INFORMATION_EX) Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->PartitionStyle = PARTITION_STYLE_MBR;
			outputBuffer->RewritePartition = FALSE;
			outputBuffer->StartingOffset.QuadPart = Extension->BytesPerSector;
			outputBuffer->PartitionLength.QuadPart= Extension->DiskLength;
			outputBuffer->PartitionNumber = 1;
			outputBuffer->Mbr.PartitionType = Extension->PartitionType;
			outputBuffer->Mbr.BootIndicator = FALSE;
			outputBuffer->Mbr.RecognizedPartition = TRUE;
			outputBuffer->Mbr.HiddenSectors = 0;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (PARTITION_INFORMATION_EX);
		}
		break;

	case IOCTL_DISK_GET_DRIVE_LAYOUT:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_DRIVE_LAYOUT)\n");
		if (ValidateIOBufferSize (Irp, sizeof (DRIVE_LAYOUT_INFORMATION), ValidateOutput))
		{
			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
			BOOL bFullBuffer = (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= (sizeof (DRIVE_LAYOUT_INFORMATION) + 3*sizeof(PARTITION_INFORMATION)))? TRUE : FALSE;
			PDRIVE_LAYOUT_INFORMATION outputBuffer = (PDRIVE_LAYOUT_INFORMATION)
			Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->PartitionCount = bFullBuffer? 4 : 1;
			outputBuffer->Signature = GetCrc32((unsigned char*) &(Extension->UniqueVolumeId), 4);

			outputBuffer->PartitionEntry->PartitionType = Extension->PartitionType;
			outputBuffer->PartitionEntry->BootIndicator = FALSE;
			outputBuffer->PartitionEntry->RecognizedPartition = TRUE;
			outputBuffer->PartitionEntry->RewritePartition = FALSE;
			outputBuffer->PartitionEntry->StartingOffset.QuadPart = Extension->BytesPerSector;
			outputBuffer->PartitionEntry->PartitionLength.QuadPart = Extension->DiskLength;
			outputBuffer->PartitionEntry->PartitionNumber = 1;
			outputBuffer->PartitionEntry->HiddenSectors = 0;			

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (DRIVE_LAYOUT_INFORMATION);
			if (bFullBuffer)
			{
				Irp->IoStatus.Information += 3*sizeof(PARTITION_INFORMATION);
				memset (((BYTE*) Irp->AssociatedIrp.SystemBuffer) + sizeof (DRIVE_LAYOUT_INFORMATION), 0, 3*sizeof(PARTITION_INFORMATION));
			}				
		}
		break;

	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_DRIVE_LAYOUT_EX)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (DRIVE_LAYOUT_INFORMATION_EX), ValidateOutput))
			{
				PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
				BOOL bFullBuffer = (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= (sizeof (DRIVE_LAYOUT_INFORMATION_EX) + 3*sizeof(PARTITION_INFORMATION_EX)))? TRUE : FALSE;
				PDRIVE_LAYOUT_INFORMATION_EX outputBuffer = (PDRIVE_LAYOUT_INFORMATION_EX)
				Irp->AssociatedIrp.SystemBuffer;

				outputBuffer->PartitionCount = bFullBuffer? 4 : 1;
				outputBuffer->PartitionStyle = PARTITION_STYLE_MBR;
				outputBuffer->Mbr.Signature = GetCrc32((unsigned char*) &(Extension->UniqueVolumeId), 4);

				outputBuffer->PartitionEntry->PartitionStyle = PARTITION_STYLE_MBR;
				outputBuffer->PartitionEntry->Mbr.BootIndicator = FALSE;
				outputBuffer->PartitionEntry->Mbr.RecognizedPartition = TRUE;
				outputBuffer->PartitionEntry->RewritePartition = FALSE;
				outputBuffer->PartitionEntry->StartingOffset.QuadPart = Extension->BytesPerSector;
				outputBuffer->PartitionEntry->PartitionLength.QuadPart = Extension->DiskLength;
				outputBuffer->PartitionEntry->PartitionNumber = 1;
				outputBuffer->PartitionEntry->Mbr.HiddenSectors = 0;
				outputBuffer->PartitionEntry->Mbr.PartitionType = Extension->PartitionType;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (DRIVE_LAYOUT_INFORMATION_EX);
				if (bFullBuffer)
				{
					Irp->IoStatus.Information += 3*sizeof(PARTITION_INFORMATION_EX);
					memset (((BYTE*) Irp->AssociatedIrp.SystemBuffer) + sizeof (DRIVE_LAYOUT_INFORMATION_EX), 0, 3*sizeof(PARTITION_INFORMATION_EX));
				}
			}
		}
		break;

	case IOCTL_DISK_GET_LENGTH_INFO:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_GET_LENGTH_INFO)\n");
		if (!ValidateIOBufferSize (Irp, sizeof (GET_LENGTH_INFORMATION), ValidateOutput))
		{
			Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
			Irp->IoStatus.Information = sizeof (GET_LENGTH_INFORMATION);
		}
		else
		{
			PGET_LENGTH_INFORMATION outputBuffer = (PGET_LENGTH_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

			outputBuffer->Length.QuadPart = Extension->DiskLength;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (GET_LENGTH_INFORMATION);
		}
		break;

	case IOCTL_DISK_VERIFY:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_VERIFY)\n");
		if (ValidateIOBufferSize (Irp, sizeof (VERIFY_INFORMATION), ValidateInput))
		{
			HRESULT hResult;
			ULONGLONG ullStartingOffset, ullNewOffset, ullEndOffset;
			PVERIFY_INFORMATION pVerifyInformation;
			pVerifyInformation = (PVERIFY_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

			ullStartingOffset = (ULONGLONG) pVerifyInformation->StartingOffset.QuadPart;
			hResult = ULongLongAdd(ullStartingOffset,
				(ULONGLONG) Extension->cryptoInfo->hiddenVolume ? Extension->cryptoInfo->hiddenVolumeOffset : Extension->cryptoInfo->volDataAreaOffset,
				&ullNewOffset);
			if (hResult != S_OK)
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			else if (S_OK != ULongLongAdd(ullStartingOffset, (ULONGLONG) pVerifyInformation->Length, &ullEndOffset))
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			else if (ullEndOffset > (ULONGLONG) Extension->DiskLength)
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			else
			{
				IO_STATUS_BLOCK ioStatus;
				PVOID buffer = TCalloc (max (pVerifyInformation->Length, PAGE_SIZE));

				if (!buffer)
				{
					Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				}
				else
				{
					LARGE_INTEGER offset = pVerifyInformation->StartingOffset;
					offset.QuadPart = ullNewOffset;

					Irp->IoStatus.Status = ZwReadFile (Extension->hDeviceFile, NULL, NULL, NULL, &ioStatus, buffer, pVerifyInformation->Length, &offset, NULL);
					TCfree (buffer);

					if (NT_SUCCESS (Irp->IoStatus.Status) && ioStatus.Information != pVerifyInformation->Length)
						Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				}
			}

			Irp->IoStatus.Information = 0;
		}
		break;

	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY2:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_STORAGE_CHECK_VERIFY)\n");
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof (ULONG))
			{
				*((ULONG *) Irp->AssociatedIrp.SystemBuffer) = 0;
				Irp->IoStatus.Information = sizeof (ULONG);
			}
		}
		break;

	case IOCTL_DISK_IS_WRITABLE:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_IS_WRITABLE)\n");
		{
			if (Extension->bReadOnly)
				Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			else
				Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;

		}
		break;

	case IOCTL_VOLUME_ONLINE:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_VOLUME_ONLINE)\n");
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

	case IOCTL_VOLUME_POST_ONLINE:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_VOLUME_POST_ONLINE)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;
		}
		break;

	case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS)\n");
		// Vista's filesystem defragmenter fails if IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS does not succeed.
		if (!(OsMajorVersion == 6 && OsMinorVersion == 0))
		{
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
		}
		else if (ValidateIOBufferSize (Irp, sizeof (VOLUME_DISK_EXTENTS), ValidateOutput))
		{
			VOLUME_DISK_EXTENTS *extents = (VOLUME_DISK_EXTENTS *) Irp->AssociatedIrp.SystemBuffer;

			// No extent data can be returned as this is not a physical drive.
			memset (extents, 0, sizeof (*extents));
			extents->NumberOfDiskExtents = 0;

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (*extents);
		}
		break;

	case IOCTL_STORAGE_READ_CAPACITY:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_STORAGE_READ_CAPACITY)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (STORAGE_READ_CAPACITY), ValidateOutput))
			{
				STORAGE_READ_CAPACITY *capacity = (STORAGE_READ_CAPACITY *) Irp->AssociatedIrp.SystemBuffer;

				capacity->Version = sizeof (STORAGE_READ_CAPACITY);
				capacity->Size = sizeof (STORAGE_READ_CAPACITY);
				capacity->BlockLength = Extension->BytesPerSector;
				capacity->NumberOfBlocks.QuadPart = Extension->DiskLength / Extension->BytesPerSector;
				capacity->DiskLength.QuadPart = Extension->DiskLength;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (STORAGE_READ_CAPACITY);
			}
		}
		break;

	/*case IOCTL_STORAGE_GET_DEVICE_NUMBER:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_STORAGE_GET_DEVICE_NUMBER)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (STORAGE_DEVICE_NUMBER), ValidateOutput))
			{
				STORAGE_DEVICE_NUMBER *storage = (STORAGE_DEVICE_NUMBER *) Irp->AssociatedIrp.SystemBuffer;

				storage->DeviceType = FILE_DEVICE_DISK;
				storage->DeviceNumber = (ULONG) -1;
				storage->PartitionNumber = 1;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (STORAGE_DEVICE_NUMBER);
			}
		}
		break;*/

	case IOCTL_STORAGE_GET_HOTPLUG_INFO:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_STORAGE_GET_HOTPLUG_INFO)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (STORAGE_HOTPLUG_INFO), ValidateOutput))
			{
				STORAGE_HOTPLUG_INFO *info = (STORAGE_HOTPLUG_INFO *) Irp->AssociatedIrp.SystemBuffer;

				info->Size = sizeof (STORAGE_HOTPLUG_INFO);
				info->MediaRemovable = Extension->bRemovable? TRUE : FALSE;
				info->MediaHotplug = FALSE;
				info->DeviceHotplug = FALSE;
				info->WriteCacheEnableOverride = FALSE;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (STORAGE_HOTPLUG_INFO);
			}
		}
		break;

	case IOCTL_VOLUME_IS_DYNAMIC:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_VOLUME_IS_DYNAMIC)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (BOOLEAN), ValidateOutput))
			{
				BOOLEAN *pbDynamic = (BOOLEAN*) Irp->AssociatedIrp.SystemBuffer;

				*pbDynamic = FALSE;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (BOOLEAN);
			}
		}
		break;

	case IOCTL_DISK_IS_CLUSTERED:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_DISK_IS_CLUSTERED)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (BOOLEAN), ValidateOutput))
			{
				BOOLEAN *pbIsClustered = (BOOLEAN*) Irp->AssociatedIrp.SystemBuffer;

				*pbIsClustered = FALSE;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (BOOLEAN);
			}
		}
		break;

	case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
		Dump ("ProcessVolumeDeviceControlIrp (IOCTL_VOLUME_GET_GPT_ATTRIBUTES)\n");
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			if (ValidateIOBufferSize (Irp, sizeof (VOLUME_GET_GPT_ATTRIBUTES_INFORMATION), ValidateOutput))
			{
				VOLUME_GET_GPT_ATTRIBUTES_INFORMATION *pGptAttr = (VOLUME_GET_GPT_ATTRIBUTES_INFORMATION*) Irp->AssociatedIrp.SystemBuffer;

				pGptAttr->GptAttributes = 0; // we are MBR not GPT

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);
			}
		}
		break;

	case IOCTL_UNKNOWN_WINDOWS10_EFS_ACCESS:
		// This undocumented IOCTL is sent when handling EFS data
		// We must return success otherwise EFS operations fail
		Dump ("ProcessVolumeDeviceControlIrp (unknown IOCTL 0x%.8X, OutputBufferLength = %d). Returning fake success\n", irpSp->Parameters.DeviceIoControl.IoControlCode, (int) irpSp->Parameters.DeviceIoControl.OutputBufferLength);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		break;

	case IOCTL_DISK_GET_CLUSTER_INFO:
		Dump ("ProcessVolumeDeviceControlIrp: returning STATUS_NOT_SUPPORTED for %ls\n", TCTranslateCode (irpSp->Parameters.DeviceIoControl.IoControlCode));
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		if (EnableExtendedIoctlSupport)
		{
			Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			Irp->IoStatus.Information = 0;
		}
		break;
	
	case IOCTL_STORAGE_CHECK_PRIORITY_HINT_SUPPORT:
	case IOCTL_DISK_MEDIA_REMOVAL:
	case IOCTL_VOLUME_QUERY_ALLOCATION_HINT:
	case FT_BALANCED_READ_MODE:
	case IOCTL_STORAGE_GET_DEVICE_NUMBER:
		Dump ("ProcessVolumeDeviceControlIrp: returning STATUS_INVALID_DEVICE_REQUEST for %ls\n", TCTranslateCode (irpSp->Parameters.DeviceIoControl.IoControlCode));
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;		
		break;
	default:
		Dump ("ProcessVolumeDeviceControlIrp (unknown code 0x%.8X)\n", irpSp->Parameters.DeviceIoControl.IoControlCode);
		return TCCompleteIrp (Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}

#if defined(DEBUG) || defined (DEBG_TRACE)
	if (!NT_SUCCESS (Irp->IoStatus.Status))
	{
		Dump ("IOCTL error 0x%08x (0x%x %d)\n",
			Irp->IoStatus.Status,
			(int) (irpSp->Parameters.DeviceIoControl.IoControlCode >> 16),
			(int) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x1FFF) >> 2));
	}
#endif

	return TCCompleteDiskIrp (Irp, Irp->IoStatus.Status, Irp->IoStatus.Information);
}


NTSTATUS ProcessMainDeviceControlIrp (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS ntStatus;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case TC_IOCTL_GET_DRIVER_VERSION:
	case TC_IOCTL_LEGACY_GET_DRIVER_VERSION:
		if (ValidateIOBufferSize (Irp, sizeof (LONG), ValidateOutput))
		{
			LONG tmp = VERSION_NUM;
			memcpy (Irp->AssociatedIrp.SystemBuffer, &tmp, 4);
			Irp->IoStatus.Information = sizeof (LONG);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_GET_DEVICE_REFCOUNT:
		if (ValidateIOBufferSize (Irp, sizeof (int), ValidateOutput))
		{
			*(int *) Irp->AssociatedIrp.SystemBuffer = DeviceObject->ReferenceCount;
			Irp->IoStatus.Information = sizeof (int);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED:
		if (ValidateIOBufferSize (Irp, sizeof (int), ValidateOutput))
		{
			LONG deviceObjectCount = 0;

			*(int *) Irp->AssociatedIrp.SystemBuffer = DriverUnloadDisabled;

			if (IoEnumerateDeviceObjectList (TCDriverObject, NULL, 0, &deviceObjectCount) == STATUS_BUFFER_TOO_SMALL && deviceObjectCount > 1)
				*(int *) Irp->AssociatedIrp.SystemBuffer = TRUE;

			Irp->IoStatus.Information = sizeof (int);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_IS_ANY_VOLUME_MOUNTED:
		if (ValidateIOBufferSize (Irp, sizeof (int), ValidateOutput))
		{
			int drive;
			*(int *) Irp->AssociatedIrp.SystemBuffer = 0;

			for (drive = MIN_MOUNTED_VOLUME_DRIVE_NUMBER; drive <= MAX_MOUNTED_VOLUME_DRIVE_NUMBER; ++drive)
			{
				if (GetVirtualVolumeDeviceObject (drive))
				{
					*(int *) Irp->AssociatedIrp.SystemBuffer = 1;
					break;
				}
			}

			if (IsBootDriveMounted())
				*(int *) Irp->AssociatedIrp.SystemBuffer = 1;

			Irp->IoStatus.Information = sizeof (int);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_OPEN_TEST:
		{
			OPEN_TEST_STRUCT *opentest = (OPEN_TEST_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			OBJECT_ATTRIBUTES ObjectAttributes;
			HANDLE NtFileHandle;
			UNICODE_STRING FullFileName;
			IO_STATUS_BLOCK IoStatus;
			LARGE_INTEGER offset;
			ACCESS_MASK access = FILE_READ_ATTRIBUTES;

			if (!ValidateIOBufferSize (Irp, sizeof (OPEN_TEST_STRUCT), ValidateInputOutput))
				break;

			EnsureNullTerminatedString (opentest->wszFileName, sizeof (opentest->wszFileName));
			RtlInitUnicodeString (&FullFileName, opentest->wszFileName);

			InitializeObjectAttributes (&ObjectAttributes, &FullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

			if (opentest->bDetectTCBootLoader || opentest->DetectFilesystem || opentest->bComputeVolumeIDs)
				access |= FILE_READ_DATA;

			ntStatus = ZwCreateFile (&NtFileHandle,
						 SYNCHRONIZE | access, &ObjectAttributes, &IoStatus, NULL,
						 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

			if (NT_SUCCESS (ntStatus))
			{
				opentest->TCBootLoaderDetected = FALSE;
				opentest->FilesystemDetected = FALSE;
				memset (opentest->VolumeIDComputed, 0, sizeof (opentest->VolumeIDComputed));
				memset (opentest->volumeIDs, 0, sizeof (opentest->volumeIDs));

				if (opentest->bDetectTCBootLoader || opentest->DetectFilesystem || opentest->bComputeVolumeIDs)
				{
					byte *readBuffer = TCalloc (TC_MAX_VOLUME_SECTOR_SIZE);
					if (!readBuffer)
					{
						ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					}
					else
					{
						if (opentest->bDetectTCBootLoader || opentest->DetectFilesystem)
						{
							// Determine if the first sector contains a portion of the VeraCrypt Boot Loader

							offset.QuadPart = 0;

							ntStatus = ZwReadFile (NtFileHandle,
								NULL,
								NULL,
								NULL,
								&IoStatus,
								readBuffer,
								TC_MAX_VOLUME_SECTOR_SIZE,
								&offset,
								NULL);

							if (NT_SUCCESS (ntStatus))
							{
								size_t i;

								if (opentest->bDetectTCBootLoader && IoStatus.Information >= TC_SECTOR_SIZE_BIOS)
								{
									// Search for the string "VeraCrypt"
									for (i = 0; i < TC_SECTOR_SIZE_BIOS - strlen (TC_APP_NAME); ++i)
									{
										if (memcmp (readBuffer + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
										{
											opentest->TCBootLoaderDetected = TRUE;
											break;
										}
									}
								}

								if (opentest->DetectFilesystem && IoStatus.Information >= sizeof (int64))
								{
									switch (BE64 (*(uint64 *) readBuffer))
									{
									case 0xEB52904E54465320ULL: // NTFS
									case 0xEB3C904D53444F53ULL: // FAT16/FAT32
									case 0xEB58904D53444F53ULL: // FAT32
									case 0xEB76904558464154ULL: // exFAT
									case 0x0000005265465300ULL: // ReFS
									case 0xEB58906D6B66732EULL: // FAT32 mkfs.fat
									case 0xEB58906D6B646F73ULL: // FAT32 mkfs.vfat/mkdosfs
									case 0xEB3C906D6B66732EULL: // FAT16/FAT12 mkfs.fat
									case 0xEB3C906D6B646F73ULL: // FAT16/FAT12 mkfs.vfat/mkdosfs
										opentest->FilesystemDetected = TRUE;
										break;
									case 0x0000000000000000ULL:
										// all 512 bytes are zeroes => unencrypted filesystem like Microsoft reserved partition
										if (IsAllZeroes (readBuffer + 8, TC_VOLUME_HEADER_EFFECTIVE_SIZE - 8))
											opentest->FilesystemDetected = TRUE;
										break;
									}
								}
							}
						}

						if (opentest->bComputeVolumeIDs && (!opentest->DetectFilesystem || !opentest->FilesystemDetected))
						{
							int volumeType;
							// Go through all volume types (e.g., normal, hidden)
							for (volumeType = TC_VOLUME_TYPE_NORMAL;
								volumeType < TC_VOLUME_TYPE_COUNT;
								volumeType++)
							{
								/* Read the volume header */
								switch (volumeType)
								{
								case TC_VOLUME_TYPE_NORMAL:
									offset.QuadPart = TC_VOLUME_HEADER_OFFSET;
									break;

								case TC_VOLUME_TYPE_HIDDEN:

									offset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;
									break;
								}

								ntStatus = ZwReadFile (NtFileHandle,
								NULL,
								NULL,
								NULL,
								&IoStatus,
								readBuffer,
								TC_MAX_VOLUME_SECTOR_SIZE,
								&offset,
								NULL);

								if (NT_SUCCESS (ntStatus))
								{
									/* compute the ID of this volume: SHA-256 of the effective header */
									sha256 (opentest->volumeIDs[volumeType], readBuffer, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
									opentest->VolumeIDComputed[volumeType] = TRUE;
								}
							}
						}

						TCfree (readBuffer);
					}
				}

				ZwClose (NtFileHandle);
				Dump ("Open test on file %ls success.\n", opentest->wszFileName);
			}
			else
			{
#if 0
				Dump ("Open test on file %ls failed NTSTATUS 0x%08x\n", opentest->wszFileName, ntStatus);
#endif
			}

			Irp->IoStatus.Information = NT_SUCCESS (ntStatus) ? sizeof (OPEN_TEST_STRUCT) : 0;
			Irp->IoStatus.Status = ntStatus;
		}
		break;

	case TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG:
		{
			GetSystemDriveConfigurationRequest *request = (GetSystemDriveConfigurationRequest *) Irp->AssociatedIrp.SystemBuffer;
			OBJECT_ATTRIBUTES ObjectAttributes;
			HANDLE NtFileHandle;
			UNICODE_STRING FullFileName;
			IO_STATUS_BLOCK IoStatus;
			LARGE_INTEGER offset;
			byte readBuffer [TC_SECTOR_SIZE_BIOS];

			if (!ValidateIOBufferSize (Irp, sizeof (GetSystemDriveConfigurationRequest), ValidateInputOutput))
				break;

			EnsureNullTerminatedString (request->DevicePath, sizeof (request->DevicePath));
			RtlInitUnicodeString (&FullFileName, request->DevicePath);

			InitializeObjectAttributes (&ObjectAttributes, &FullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

			ntStatus = ZwCreateFile (&NtFileHandle,
				SYNCHRONIZE | GENERIC_READ, &ObjectAttributes, &IoStatus, NULL,
				FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_RANDOM_ACCESS, NULL, 0);

			if (NT_SUCCESS (ntStatus))
			{
				// Determine if the first sector contains a portion of the VeraCrypt Boot Loader
				offset.QuadPart = 0;	// MBR

				ntStatus = ZwReadFile (NtFileHandle,
					NULL,
					NULL,
					NULL,
					&IoStatus,
					readBuffer,
					sizeof(readBuffer),
					&offset,
					NULL);

				if (NT_SUCCESS (ntStatus))
				{
					size_t i;

					// Check for dynamic drive
					request->DriveIsDynamic = FALSE;

					if (readBuffer[510] == 0x55 && readBuffer[511] == 0xaa)
					{
						int i;
						for (i = 0; i < 4; ++i)
						{
							if (readBuffer[446 + i * 16 + 4] == PARTITION_LDM)
							{
								request->DriveIsDynamic = TRUE;
								break;
							}
						}
					}

					request->BootLoaderVersion = 0;
					request->Configuration = 0;
					request->UserConfiguration = 0;
					request->CustomUserMessage[0] = 0;

					// Search for the string "VeraCrypt"
					for (i = 0; i < sizeof (readBuffer) - strlen (TC_APP_NAME); ++i)
					{
						if (memcmp (readBuffer + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
						{
							request->BootLoaderVersion = BE16 (*(uint16 *) (readBuffer + TC_BOOT_SECTOR_VERSION_OFFSET));
							request->Configuration = readBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET];

							if (request->BootLoaderVersion != 0 && request->BootLoaderVersion <= VERSION_NUM)
							{
								request->UserConfiguration = readBuffer[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
								memcpy (request->CustomUserMessage, readBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
							}
							break;
						}
					}

					Irp->IoStatus.Status = STATUS_SUCCESS;
					Irp->IoStatus.Information = sizeof (*request);
				}
				else
				{
					Irp->IoStatus.Status = ntStatus;
					Irp->IoStatus.Information = 0;
				}

				ZwClose (NtFileHandle);

			}
			else
			{
				Irp->IoStatus.Status = ntStatus;
				Irp->IoStatus.Information = 0;
			}
		}
		break;

	case TC_IOCTL_WIPE_PASSWORD_CACHE:
		WipeCache ();

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_PASSWORD_CACHE_STATUS:
		Irp->IoStatus.Status = cacheEmpty ? STATUS_PIPE_EMPTY : STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_SET_PORTABLE_MODE_STATUS:
		if (!UserCanAccessDriveDevice())
		{
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			Irp->IoStatus.Information = 0;
		}
		else
		{
			PortableMode = TRUE;
			Dump ("Setting portable mode\n");
		}
		break;

	case TC_IOCTL_GET_PORTABLE_MODE_STATUS:
		Irp->IoStatus.Status = PortableMode ? STATUS_SUCCESS : STATUS_PIPE_EMPTY;
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_MOUNTED_VOLUMES:

		if (ValidateIOBufferSize (Irp, sizeof (MOUNT_LIST_STRUCT), ValidateOutput))
		{
			MOUNT_LIST_STRUCT *list = (MOUNT_LIST_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice;
			int drive;

			list->ulMountedDrives = 0;

			for (drive = MIN_MOUNTED_VOLUME_DRIVE_NUMBER; drive <= MAX_MOUNTED_VOLUME_DRIVE_NUMBER; ++drive)
			{
				PEXTENSION ListExtension;

				ListDevice = GetVirtualVolumeDeviceObject (drive);
				if (!ListDevice)
					continue;

				ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (IsVolumeAccessibleByCurrentUser (ListExtension))
				{
					list->ulMountedDrives |= (1 << ListExtension->nDosDriveNo);
					RtlStringCbCopyW (list->wszVolume[ListExtension->nDosDriveNo], sizeof(list->wszVolume[ListExtension->nDosDriveNo]),ListExtension->wszVolume);
					RtlStringCbCopyW (list->wszLabel[ListExtension->nDosDriveNo], sizeof(list->wszLabel[ListExtension->nDosDriveNo]),ListExtension->wszLabel);
					memcpy (list->volumeID[ListExtension->nDosDriveNo], ListExtension->volumeID, VOLUME_ID_SIZE);
					list->diskLength[ListExtension->nDosDriveNo] = ListExtension->DiskLength;
					list->ea[ListExtension->nDosDriveNo] = ListExtension->cryptoInfo->ea;
					if (ListExtension->cryptoInfo->hiddenVolume)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_HIDDEN;	// Hidden volume
					else if (ListExtension->cryptoInfo->bHiddenVolProtectionAction)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED;	// Normal/outer volume (hidden volume protected AND write already prevented)
					else if (ListExtension->cryptoInfo->bProtectHiddenVolume)
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_OUTER;	// Normal/outer volume (hidden volume protected)
					else
						list->volumeType[ListExtension->nDosDriveNo] = PROP_VOL_TYPE_NORMAL;	// Normal volume
					list->truecryptMode[ListExtension->nDosDriveNo] = ListExtension->cryptoInfo->bTrueCryptMode;
				}
			}

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof (MOUNT_LIST_STRUCT);
		}
		break;

	case TC_IOCTL_LEGACY_GET_MOUNTED_VOLUMES:
		if (ValidateIOBufferSize (Irp, sizeof (uint32), ValidateOutput))
		{
			// Prevent the user from downgrading to versions lower than 5.0 by faking mounted volumes.
			// The user could render the system unbootable by downgrading when boot encryption
			// is active or being set up.

			memset (Irp->AssociatedIrp.SystemBuffer, 0, irpSp->Parameters.DeviceIoControl.OutputBufferLength);
			*(uint32 *) Irp->AssociatedIrp.SystemBuffer = 0xffffFFFF;

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
		}
		break;

	case TC_IOCTL_GET_VOLUME_PROPERTIES:
		if (ValidateIOBufferSize (Irp, sizeof (VOLUME_PROPERTIES_STRUCT), ValidateInputOutput))
		{
			VOLUME_PROPERTIES_STRUCT *prop = (VOLUME_PROPERTIES_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice = GetVirtualVolumeDeviceObject (prop->driveNo);

			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;

			if (ListDevice)
			{
				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
				if (IsVolumeAccessibleByCurrentUser (ListExtension))
				{
					prop->uniqueId = ListExtension->UniqueVolumeId;
					RtlStringCbCopyW (prop->wszVolume, sizeof(prop->wszVolume),ListExtension->wszVolume);
					RtlStringCbCopyW (prop->wszLabel, sizeof(prop->wszLabel),ListExtension->wszLabel);
					memcpy (prop->volumeID, ListExtension->volumeID, VOLUME_ID_SIZE);
					prop->bDriverSetLabel = ListExtension->bDriverSetLabel;
					prop->diskLength = ListExtension->DiskLength;
					prop->ea = ListExtension->cryptoInfo->ea;
					prop->mode = ListExtension->cryptoInfo->mode;
					prop->pkcs5 = ListExtension->cryptoInfo->pkcs5;
					prop->pkcs5Iterations = ListExtension->cryptoInfo->noIterations;
					prop->volumePim = ListExtension->cryptoInfo->volumePim;
#if 0
					prop->volumeCreationTime = ListExtension->cryptoInfo->volume_creation_time;
					prop->headerCreationTime = ListExtension->cryptoInfo->header_creation_time;
#endif
					prop->volumeHeaderFlags = ListExtension->cryptoInfo->HeaderFlags;
					prop->readOnly = ListExtension->bReadOnly;
					prop->removable = ListExtension->bRemovable;
					prop->partitionInInactiveSysEncScope = ListExtension->PartitionInInactiveSysEncScope;
					prop->hiddenVolume = ListExtension->cryptoInfo->hiddenVolume;

					if (ListExtension->cryptoInfo->bProtectHiddenVolume)
						prop->hiddenVolProtection = ListExtension->cryptoInfo->bHiddenVolProtectionAction ? HIDVOL_PROT_STATUS_ACTION_TAKEN : HIDVOL_PROT_STATUS_ACTIVE;
					else
						prop->hiddenVolProtection = HIDVOL_PROT_STATUS_NONE;

					prop->totalBytesRead = ListExtension->Queue.TotalBytesRead;
					prop->totalBytesWritten = ListExtension->Queue.TotalBytesWritten;

					prop->volFormatVersion = ListExtension->cryptoInfo->LegacyVolume ? TC_VOLUME_FORMAT_VERSION_PRE_6_0 : TC_VOLUME_FORMAT_VERSION;

					Irp->IoStatus.Status = STATUS_SUCCESS;
					Irp->IoStatus.Information = sizeof (VOLUME_PROPERTIES_STRUCT);
				}
			}
		}
		break;

	case TC_IOCTL_GET_RESOLVED_SYMLINK:
		if (ValidateIOBufferSize (Irp, sizeof (RESOLVE_SYMLINK_STRUCT), ValidateInputOutput))
		{
			RESOLVE_SYMLINK_STRUCT *resolve = (RESOLVE_SYMLINK_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			{
				NTSTATUS ntStatus;

				EnsureNullTerminatedString (resolve->symLinkName, sizeof (resolve->symLinkName));

				ntStatus = SymbolicLinkToTarget (resolve->symLinkName,
					resolve->targetName,
					sizeof (resolve->targetName));

				Irp->IoStatus.Information = sizeof (RESOLVE_SYMLINK_STRUCT);
				Irp->IoStatus.Status = ntStatus;
			}
		}
		break;

	case TC_IOCTL_GET_DRIVE_PARTITION_INFO:
		if (ValidateIOBufferSize (Irp, sizeof (DISK_PARTITION_INFO_STRUCT), ValidateInputOutput))
		{
			DISK_PARTITION_INFO_STRUCT *info = (DISK_PARTITION_INFO_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			{
				PARTITION_INFORMATION_EX pi;
				NTSTATUS ntStatus;

				EnsureNullTerminatedString (info->deviceName, sizeof (info->deviceName));

				ntStatus = TCDeviceIoControl (info->deviceName, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &pi, sizeof (pi));
				if (NT_SUCCESS(ntStatus))
				{
					memset (&info->partInfo, 0, sizeof (info->partInfo));

					info->partInfo.PartitionLength = pi.PartitionLength;
					info->partInfo.PartitionNumber = pi.PartitionNumber;
					info->partInfo.StartingOffset = pi.StartingOffset;

					if (pi.PartitionStyle == PARTITION_STYLE_MBR)
					{
						info->partInfo.PartitionType = pi.Mbr.PartitionType;
						info->partInfo.BootIndicator = pi.Mbr.BootIndicator;
					}

					info->IsGPT = pi.PartitionStyle == PARTITION_STYLE_GPT;
				}
				else
				{
					// Windows 2000 does not support IOCTL_DISK_GET_PARTITION_INFO_EX
					ntStatus = TCDeviceIoControl (info->deviceName, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &info->partInfo, sizeof (info->partInfo));
					info->IsGPT = FALSE;
				}

				if (!NT_SUCCESS (ntStatus))
				{
					GET_LENGTH_INFORMATION lengthInfo;
					ntStatus = TCDeviceIoControl (info->deviceName, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &lengthInfo, sizeof (lengthInfo));

					if (NT_SUCCESS (ntStatus))
					{
						memset (&info->partInfo, 0, sizeof (info->partInfo));
						info->partInfo.PartitionLength = lengthInfo.Length;
					}
				}

				info->IsDynamic = FALSE;

				if (NT_SUCCESS (ntStatus) && OsMajorVersion >= 6)
				{
#					define IOCTL_VOLUME_IS_DYNAMIC CTL_CODE(IOCTL_VOLUME_BASE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
					if (!NT_SUCCESS (TCDeviceIoControl (info->deviceName, IOCTL_VOLUME_IS_DYNAMIC, NULL, 0, &info->IsDynamic, sizeof (info->IsDynamic))))
						info->IsDynamic = FALSE;
				}

				Irp->IoStatus.Information = sizeof (DISK_PARTITION_INFO_STRUCT);
				Irp->IoStatus.Status = ntStatus;
			}
		}
		break;

	case TC_IOCTL_GET_DRIVE_GEOMETRY:
		if (ValidateIOBufferSize (Irp, sizeof (DISK_GEOMETRY_STRUCT), ValidateInputOutput))
		{
			DISK_GEOMETRY_STRUCT *g = (DISK_GEOMETRY_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			{
				NTSTATUS ntStatus;

				EnsureNullTerminatedString (g->deviceName, sizeof (g->deviceName));
				Dump ("Calling IOCTL_DISK_GET_DRIVE_GEOMETRY on %ls\n", g->deviceName);

				ntStatus = TCDeviceIoControl (g->deviceName,
					IOCTL_DISK_GET_DRIVE_GEOMETRY,
					NULL, 0, &g->diskGeometry, sizeof (g->diskGeometry));

				Irp->IoStatus.Information = sizeof (DISK_GEOMETRY_STRUCT);
				Irp->IoStatus.Status = ntStatus;
			}
		}
		break;

	case VC_IOCTL_GET_DRIVE_GEOMETRY_EX:
		if (ValidateIOBufferSize (Irp, sizeof (DISK_GEOMETRY_EX_STRUCT), ValidateInputOutput))
		{
			DISK_GEOMETRY_EX_STRUCT *g = (DISK_GEOMETRY_EX_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			{
				NTSTATUS ntStatus;
				DISK_GEOMETRY_EX geo = {0};

				EnsureNullTerminatedString (g->deviceName, sizeof (g->deviceName));
				Dump ("Calling IOCTL_DISK_GET_DRIVE_GEOMETRY_EX on %ls\n", g->deviceName);

				ntStatus = TCDeviceIoControl (g->deviceName,
					IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
					NULL, 0, &geo, sizeof (geo));

				if (NT_SUCCESS(ntStatus))
				{
					memcpy (&g->diskGeometry, &geo.Geometry, sizeof (DISK_GEOMETRY));
					g->DiskSize.QuadPart = geo.DiskSize.QuadPart;
				}

				Irp->IoStatus.Information = sizeof (DISK_GEOMETRY_EX_STRUCT);
				Irp->IoStatus.Status = ntStatus;
			}
		}
		break;

	case TC_IOCTL_PROBE_REAL_DRIVE_SIZE:
		if (ValidateIOBufferSize (Irp, sizeof (ProbeRealDriveSizeRequest), ValidateInputOutput))
		{
			ProbeRealDriveSizeRequest *request = (ProbeRealDriveSizeRequest *) Irp->AssociatedIrp.SystemBuffer;
			NTSTATUS status;
			UNICODE_STRING name;
			PFILE_OBJECT fileObject;
			PDEVICE_OBJECT deviceObject;

			EnsureNullTerminatedString (request->DeviceName, sizeof (request->DeviceName));

			RtlInitUnicodeString (&name, request->DeviceName);
			status = IoGetDeviceObjectPointer (&name, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject);
			if (!NT_SUCCESS (status))
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = status;
				break;
			}

			status = ProbeRealDriveSize (deviceObject, &request->RealDriveSize);
			ObDereferenceObject (fileObject);

			if (status == STATUS_TIMEOUT)
			{
				request->TimeOut = TRUE;
				Irp->IoStatus.Information = sizeof (ProbeRealDriveSizeRequest);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else if (!NT_SUCCESS (status))
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = status;
			}
			else
			{
				request->TimeOut = FALSE;
				Irp->IoStatus.Information = sizeof (ProbeRealDriveSizeRequest);
				Irp->IoStatus.Status = status;
			}
		}
		break;

	case TC_IOCTL_MOUNT_VOLUME:
		if (ValidateIOBufferSize (Irp, sizeof (MOUNT_STRUCT), ValidateInputOutput))
		{
			MOUNT_STRUCT *mount = (MOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;

			if (mount->VolumePassword.Length > MAX_PASSWORD || mount->ProtectedHidVolPassword.Length > MAX_PASSWORD
				||	mount->pkcs5_prf < 0 || mount->pkcs5_prf > LAST_PRF_ID
				||	mount->VolumePim < -1 || mount->VolumePim == INT_MAX
				|| mount->ProtectedHidVolPkcs5Prf < 0 || mount->ProtectedHidVolPkcs5Prf > LAST_PRF_ID
				|| (mount->bTrueCryptMode != FALSE && mount->bTrueCryptMode != TRUE)
				)
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				Irp->IoStatus.Information = 0;
				break;
			}

			EnsureNullTerminatedString (mount->wszVolume, sizeof (mount->wszVolume));
			EnsureNullTerminatedString (mount->wszLabel, sizeof (mount->wszLabel));

			Irp->IoStatus.Information = sizeof (MOUNT_STRUCT);
			Irp->IoStatus.Status = MountDevice (DeviceObject, mount);

			burn (&mount->VolumePassword, sizeof (mount->VolumePassword));
			burn (&mount->ProtectedHidVolPassword, sizeof (mount->ProtectedHidVolPassword));
			burn (&mount->pkcs5_prf, sizeof (mount->pkcs5_prf));
			burn (&mount->VolumePim, sizeof (mount->VolumePim));
			burn (&mount->bTrueCryptMode, sizeof (mount->bTrueCryptMode));
			burn (&mount->ProtectedHidVolPkcs5Prf, sizeof (mount->ProtectedHidVolPkcs5Prf));
			burn (&mount->ProtectedHidVolPim, sizeof (mount->ProtectedHidVolPim));
		}
		break;

	case TC_IOCTL_DISMOUNT_VOLUME:
		if (ValidateIOBufferSize (Irp, sizeof (UNMOUNT_STRUCT), ValidateInputOutput))
		{
			UNMOUNT_STRUCT *unmount = (UNMOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;
			PDEVICE_OBJECT ListDevice = GetVirtualVolumeDeviceObject (unmount->nDosDriveNo);

			unmount->nReturnCode = ERR_DRIVE_NOT_FOUND;

			if (ListDevice)
			{
				PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;

				if (IsVolumeAccessibleByCurrentUser (ListExtension))
					unmount->nReturnCode = UnmountDevice (unmount, ListDevice, unmount->ignoreOpenFiles);
			}

			Irp->IoStatus.Information = sizeof (UNMOUNT_STRUCT);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_DISMOUNT_ALL_VOLUMES:
		if (ValidateIOBufferSize (Irp, sizeof (UNMOUNT_STRUCT), ValidateInputOutput))
		{
			UNMOUNT_STRUCT *unmount = (UNMOUNT_STRUCT *) Irp->AssociatedIrp.SystemBuffer;

			unmount->nReturnCode = UnmountAllDevices (unmount, unmount->ignoreOpenFiles);

			Irp->IoStatus.Information = sizeof (UNMOUNT_STRUCT);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_BOOT_ENCRYPTION_SETUP:
		Irp->IoStatus.Status = StartBootEncryptionSetup (DeviceObject, Irp, irpSp);
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP:
		Irp->IoStatus.Status = AbortBootEncryptionSetup();
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS:
		GetBootEncryptionStatus (Irp, irpSp);
		break;

	case TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT:
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = GetSetupResult();
		break;

	case TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES:
		GetBootDriveVolumeProperties (Irp, irpSp);
		break;

	case TC_IOCTL_GET_BOOT_LOADER_VERSION:
		GetBootLoaderVersion (Irp, irpSp);
		break;

	case TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER:
		ReopenBootVolumeHeader (Irp, irpSp);
		break;

	case VC_IOCTL_GET_BOOT_LOADER_FINGERPRINT:
		GetBootLoaderFingerprint (Irp, irpSp);
		break;

	case TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME:
		GetBootEncryptionAlgorithmName (Irp, irpSp);
		break;

	case TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING:
		if (ValidateIOBufferSize (Irp, sizeof (int), ValidateOutput))
		{
			*(int *) Irp->AssociatedIrp.SystemBuffer = IsHiddenSystemRunning() ? 1 : 0;
			Irp->IoStatus.Information = sizeof (int);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_START_DECOY_SYSTEM_WIPE:
		Irp->IoStatus.Status = StartDecoySystemWipe (DeviceObject, Irp, irpSp);
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE:
		Irp->IoStatus.Status = AbortDecoySystemWipe();
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT:
		Irp->IoStatus.Status = GetDecoySystemWipeResult();
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS:
		GetDecoySystemWipeStatus (Irp, irpSp);
		break;

	case TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR:
		Irp->IoStatus.Status = WriteBootDriveSector (Irp, irpSp);
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_WARNING_FLAGS:
		if (ValidateIOBufferSize (Irp, sizeof (GetWarningFlagsRequest), ValidateOutput))
		{
			GetWarningFlagsRequest *flags = (GetWarningFlagsRequest *) Irp->AssociatedIrp.SystemBuffer;

			flags->PagingFileCreationPrevented = PagingFileCreationPrevented;
			PagingFileCreationPrevented = FALSE;
			flags->SystemFavoriteVolumeDirty = SystemFavoriteVolumeDirty;
			SystemFavoriteVolumeDirty = FALSE;

			Irp->IoStatus.Information = sizeof (GetWarningFlagsRequest);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	case TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY:
		if (UserCanAccessDriveDevice())
		{
			SystemFavoriteVolumeDirty = TRUE;
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;

		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_REREAD_DRIVER_CONFIG:
		Irp->IoStatus.Status = ReadRegistryConfigFlags (FALSE);
		Irp->IoStatus.Information = 0;
		break;

	case TC_IOCTL_GET_SYSTEM_DRIVE_DUMP_CONFIG:
		if (	(ValidateIOBufferSize (Irp, sizeof (GetSystemDriveDumpConfigRequest), ValidateOutput))
			&&	(Irp->RequestorMode == KernelMode)
			)
		{
			GetSystemDriveDumpConfigRequest *request = (GetSystemDriveDumpConfigRequest *) Irp->AssociatedIrp.SystemBuffer;

			request->BootDriveFilterExtension = GetBootDriveFilterExtension();
			if (IsBootDriveMounted() && request->BootDriveFilterExtension)
			{
				request->HwEncryptionEnabled = IsHwEncryptionEnabled();
				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof (*request);
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				Irp->IoStatus.Information = 0;
			}
		}
		break;

	default:
		return TCCompleteIrp (Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}


#if defined(DEBUG) || defined(DEBUG_TRACE)
	if (!NT_SUCCESS (Irp->IoStatus.Status))
	{
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case TC_IOCTL_GET_MOUNTED_VOLUMES:
		case TC_IOCTL_GET_PASSWORD_CACHE_STATUS:
		case TC_IOCTL_GET_PORTABLE_MODE_STATUS:
		case TC_IOCTL_SET_PORTABLE_MODE_STATUS:
		case TC_IOCTL_OPEN_TEST:
		case TC_IOCTL_GET_RESOLVED_SYMLINK:
		case TC_IOCTL_GET_DRIVE_PARTITION_INFO:
		case TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES:
		case TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS:
		case TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING:
			break;

		default:
			Dump ("IOCTL error 0x%08x\n", Irp->IoStatus.Status);
		}
	}
#endif

	return TCCompleteIrp (Irp, Irp->IoStatus.Status, Irp->IoStatus.Information);
}


NTSTATUS TCStartThread (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread)
{
	return TCStartThreadInProcess (threadProc, threadArg, kThread, NULL);
}


NTSTATUS TCStartThreadInProcess (PKSTART_ROUTINE threadProc, PVOID threadArg, PKTHREAD *kThread, PEPROCESS process)
{
	NTSTATUS status;
	HANDLE threadHandle;
	HANDLE processHandle = NULL;
	OBJECT_ATTRIBUTES threadObjAttributes;

	if (process)
	{
		status = ObOpenObjectByPointer (process, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &processHandle);
		if (!NT_SUCCESS (status))
			return status;
	}

	InitializeObjectAttributes (&threadObjAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = PsCreateSystemThread (&threadHandle, THREAD_ALL_ACCESS, &threadObjAttributes, processHandle, NULL, threadProc, threadArg);
	if (!NT_SUCCESS (status))
		return status;

	status = ObReferenceObjectByHandle (threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID *) kThread, NULL);
	if (!NT_SUCCESS (status))
	{
		ZwClose (threadHandle);
		*kThread = NULL;
		return status;
	}

	if (processHandle)
		ZwClose (processHandle);

	ZwClose (threadHandle);
	return STATUS_SUCCESS;
}


void TCStopThread (PKTHREAD kThread, PKEVENT wakeUpEvent)
{
	if (wakeUpEvent)
		KeSetEvent (wakeUpEvent, 0, FALSE);

	KeWaitForSingleObject (kThread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject (kThread);
}


NTSTATUS TCStartVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension, MOUNT_STRUCT * mount)
{
	PTHREAD_BLOCK pThreadBlock = TCalloc (sizeof (THREAD_BLOCK));
	HANDLE hThread;
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES threadObjAttributes;
	SECURITY_QUALITY_OF_SERVICE qos;

	Dump ("Starting thread...\n");

	if (pThreadBlock == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
		pThreadBlock->DeviceObject = DeviceObject;
		pThreadBlock->mount = mount;
	}

	qos.Length = sizeof (qos);
	qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
	qos.EffectiveOnly = TRUE;
	qos.ImpersonationLevel = SecurityImpersonation;

	ntStatus = SeCreateClientSecurity (PsGetCurrentThread(), &qos, FALSE, &Extension->SecurityClientContext);
	if (!NT_SUCCESS (ntStatus))
		goto ret;

	Extension->SecurityClientContextValid = TRUE;

	Extension->bThreadShouldQuit = FALSE;

	InitializeObjectAttributes (&threadObjAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = PsCreateSystemThread (&hThread,
					 THREAD_ALL_ACCESS,
					 &threadObjAttributes,
					 NULL,
					 NULL,
					 VolumeThreadProc,
					 pThreadBlock);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("PsCreateSystemThread Failed END\n");
		goto ret;
	}

	ntStatus = ObReferenceObjectByHandle (hThread,
				   THREAD_ALL_ACCESS,
				   NULL,
				   KernelMode,
				   &Extension->peThread,
				   NULL);

	ZwClose (hThread);

	if (!NT_SUCCESS (ntStatus))
		goto ret;

	Dump ("Waiting for thread to initialize...\n");

	KeWaitForSingleObject (&Extension->keCreateEvent,
			       Executive,
			       KernelMode,
			       FALSE,
			       NULL);

	Dump ("Waiting completed! Thread returns 0x%08x\n", pThreadBlock->ntCreateStatus);
	ntStatus = pThreadBlock->ntCreateStatus;

ret:
	TCfree (pThreadBlock);
	return ntStatus;
}

void TCStopVolumeThread (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	NTSTATUS ntStatus;

	UNREFERENCED_PARAMETER (DeviceObject);	/* Remove compiler warning */

	Dump ("Signalling thread to quit...\n");

	Extension->bThreadShouldQuit = TRUE;

	KeReleaseSemaphore (&Extension->RequestSemaphore,
			    0,
			    1,
			    TRUE);

	ntStatus = KeWaitForSingleObject (Extension->peThread,
					  Executive,
					  KernelMode,
					  FALSE,
					  NULL);

	ASSERT (NT_SUCCESS (ntStatus));

	ObDereferenceObject (Extension->peThread);
	Extension->peThread = NULL;

	Dump ("Thread exited\n");
}


// Suspend current thread for a number of milliseconds
void TCSleep (int milliSeconds)
{
	PKTIMER timer = (PKTIMER) TCalloc (sizeof (KTIMER));
	LARGE_INTEGER duetime;

	if (!timer)
		return;

	duetime.QuadPart = (__int64) milliSeconds * -10000;
	KeInitializeTimerEx(timer, NotificationTimer);
	KeSetTimerEx(timer, duetime, 0, NULL);

	KeWaitForSingleObject (timer, Executive, KernelMode, FALSE, NULL);

	TCfree (timer);
}

BOOL IsDeviceName(wchar_t wszVolume[TC_MAX_PATH])
{
	if	(	(wszVolume[0] == '\\')
		&&	(wszVolume[1] == 'D' || wszVolume[1] == 'd')
		&&	(wszVolume[2] == 'E' || wszVolume[2] == 'e')
		&&	(wszVolume[3] == 'V' || wszVolume[3] == 'v')
		&&	(wszVolume[4] == 'I' || wszVolume[4] == 'i')
		&&	(wszVolume[5] == 'C' || wszVolume[5] == 'c')
		&&	(wszVolume[6] == 'E' || wszVolume[6] == 'e')
		)
	{
		return TRUE;
	}
	else
		return FALSE;
}

/* VolumeThreadProc does all the work of processing IRP's, and dispatching them
   to either the ReadWrite function or the DeviceControl function */
VOID VolumeThreadProc (PVOID Context)
{
	PTHREAD_BLOCK pThreadBlock = (PTHREAD_BLOCK) Context;
	PDEVICE_OBJECT DeviceObject = pThreadBlock->DeviceObject;
	PEXTENSION Extension = (PEXTENSION) DeviceObject->DeviceExtension;
	BOOL bDevice;

	/* Set thread priority to lowest realtime level. */
	KeSetPriorityThread (KeGetCurrentThread (), LOW_REALTIME_PRIORITY);

	Dump ("Mount THREAD OPENING VOLUME BEGIN\n");

	if ( !IsDeviceName (pThreadBlock->mount->wszVolume))
	{
		RtlStringCbCopyW (pThreadBlock->wszMountVolume, sizeof(pThreadBlock->wszMountVolume),WIDE ("\\??\\"));
		RtlStringCbCatW (pThreadBlock->wszMountVolume, sizeof(pThreadBlock->wszMountVolume),pThreadBlock->mount->wszVolume);
		bDevice = FALSE;
	}
	else
	{
		pThreadBlock->wszMountVolume[0] = 0;
		RtlStringCbCatW (pThreadBlock->wszMountVolume, sizeof(pThreadBlock->wszMountVolume),pThreadBlock->mount->wszVolume);
		bDevice = TRUE;
	}

	Dump ("Mount THREAD request for File %ls DriveNumber %d Device = %d\n",
	      pThreadBlock->wszMountVolume, pThreadBlock->mount->nDosDriveNo, bDevice);

	pThreadBlock->ntCreateStatus = TCOpenVolume (DeviceObject,
		Extension,
		pThreadBlock->mount,
		pThreadBlock->wszMountVolume,
		bDevice);

	if (!NT_SUCCESS (pThreadBlock->ntCreateStatus) || pThreadBlock->mount->nReturnCode != 0)
	{
		KeSetEvent (&Extension->keCreateEvent, 0, FALSE);
		PsTerminateSystemThread (STATUS_SUCCESS);
	}

	// Start IO queue
	Extension->Queue.IsFilterDevice = FALSE;
	Extension->Queue.DeviceObject = DeviceObject;
	Extension->Queue.CryptoInfo = Extension->cryptoInfo;
	Extension->Queue.HostFileHandle = Extension->hDeviceFile;
	Extension->Queue.VirtualDeviceLength = Extension->DiskLength;
	Extension->Queue.MaxReadAheadOffset.QuadPart = Extension->HostLength;

	if (Extension->SecurityClientContextValid)
		Extension->Queue.SecurityClientContext = &Extension->SecurityClientContext;
	else
		Extension->Queue.SecurityClientContext = NULL;

	pThreadBlock->ntCreateStatus = EncryptedIoQueueStart (&Extension->Queue);

	if (!NT_SUCCESS (pThreadBlock->ntCreateStatus))
	{
		TCCloseVolume (DeviceObject, Extension);

		pThreadBlock->mount->nReturnCode = ERR_OS_ERROR;
		KeSetEvent (&Extension->keCreateEvent, 0, FALSE);
		PsTerminateSystemThread (STATUS_SUCCESS);
	}

	KeSetEvent (&Extension->keCreateEvent, 0, FALSE);
	/* From this point on pThreadBlock cannot be used as it will have been released! */
	pThreadBlock = NULL;

	for (;;)
	{
		/* Wait for a request from the dispatch routines. */
		KeWaitForSingleObject ((PVOID) & Extension->RequestSemaphore, Executive, KernelMode, FALSE, NULL);

		for (;;)
		{
			PIO_STACK_LOCATION irpSp;
			PLIST_ENTRY request;
			PIRP irp;

			request = ExInterlockedRemoveHeadList (&Extension->ListEntry, &Extension->ListSpinLock);
			if (request == NULL)
				break;

			irp = CONTAINING_RECORD (request, IRP, Tail.Overlay.ListEntry);
			irpSp = IoGetCurrentIrpStackLocation (irp);

			ASSERT (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);

			ProcessVolumeDeviceControlIrp (DeviceObject, Extension, irp);
			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, irp);
		}

		if (Extension->bThreadShouldQuit)
		{
			Dump ("Closing volume\n");
			EncryptedIoQueueStop (&Extension->Queue);

			TCCloseVolume (DeviceObject, Extension);
			PsTerminateSystemThread (STATUS_SUCCESS);
		}
	}
}

void TCGetNTNameFromNumber (LPWSTR ntname, int cbNtName, int nDriveNo)
{
	WCHAR tmp[2] =
	{0, 0};
	int j = nDriveNo + (WCHAR) 'A';

	tmp[0] = (short) j;
	RtlStringCbCopyW (ntname, cbNtName,(LPWSTR) NT_MOUNT_PREFIX);
	RtlStringCbCatW (ntname, cbNtName, tmp);
}

void TCGetDosNameFromNumber (LPWSTR dosname,int cbDosName, int nDriveNo, DeviceNamespaceType namespaceType)
{
	WCHAR tmp[3] =
	{0, ':', 0};
	int j = nDriveNo + (WCHAR) 'A';

	tmp[0] = (short) j;

	if (DeviceNamespaceGlobal == namespaceType)
	{
		RtlStringCbCopyW (dosname, cbDosName, (LPWSTR) DOS_MOUNT_PREFIX_GLOBAL);
	}
	else
	{
		RtlStringCbCopyW (dosname, cbDosName, (LPWSTR) DOS_MOUNT_PREFIX_DEFAULT);
	}

	RtlStringCbCatW (dosname, cbDosName, tmp);
}

#if defined(_DEBUG) || defined (_DEBUG_TRACE)
LPWSTR TCTranslateCode (ULONG ulCode)
{
	switch (ulCode)
	{
#define TC_CASE_RET_NAME(CODE) case CODE : return L###CODE

		TC_CASE_RET_NAME (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);
		TC_CASE_RET_NAME (TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE);
		TC_CASE_RET_NAME (TC_IOCTL_BOOT_ENCRYPTION_SETUP);
		TC_CASE_RET_NAME (TC_IOCTL_DISMOUNT_ALL_VOLUMES);
		TC_CASE_RET_NAME (TC_IOCTL_DISMOUNT_VOLUME);
		TC_CASE_RET_NAME (TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES);
		TC_CASE_RET_NAME (TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME);
		TC_CASE_RET_NAME (TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT);
		TC_CASE_RET_NAME (TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS);
		TC_CASE_RET_NAME (TC_IOCTL_GET_BOOT_LOADER_VERSION);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DEVICE_REFCOUNT);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DRIVE_GEOMETRY);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DRIVE_PARTITION_INFO);
		TC_CASE_RET_NAME (TC_IOCTL_GET_DRIVER_VERSION);
		TC_CASE_RET_NAME (TC_IOCTL_GET_MOUNTED_VOLUMES);
		TC_CASE_RET_NAME (TC_IOCTL_GET_PASSWORD_CACHE_STATUS);
		TC_CASE_RET_NAME (TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG);
		TC_CASE_RET_NAME (TC_IOCTL_GET_PORTABLE_MODE_STATUS);
		TC_CASE_RET_NAME (TC_IOCTL_SET_PORTABLE_MODE_STATUS);
		TC_CASE_RET_NAME (TC_IOCTL_GET_RESOLVED_SYMLINK);
		TC_CASE_RET_NAME (TC_IOCTL_GET_SYSTEM_DRIVE_DUMP_CONFIG);
		TC_CASE_RET_NAME (TC_IOCTL_GET_VOLUME_PROPERTIES);
		TC_CASE_RET_NAME (TC_IOCTL_GET_WARNING_FLAGS);
		TC_CASE_RET_NAME (TC_IOCTL_DISK_IS_WRITABLE);
		TC_CASE_RET_NAME (TC_IOCTL_IS_ANY_VOLUME_MOUNTED);
		TC_CASE_RET_NAME (TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED);
		TC_CASE_RET_NAME (TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING);
		TC_CASE_RET_NAME (TC_IOCTL_MOUNT_VOLUME);
		TC_CASE_RET_NAME (TC_IOCTL_OPEN_TEST);
		TC_CASE_RET_NAME (TC_IOCTL_PROBE_REAL_DRIVE_SIZE);
		TC_CASE_RET_NAME (TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER);
		TC_CASE_RET_NAME (TC_IOCTL_REREAD_DRIVER_CONFIG);
		TC_CASE_RET_NAME (TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY);
		TC_CASE_RET_NAME (TC_IOCTL_START_DECOY_SYSTEM_WIPE);
		TC_CASE_RET_NAME (TC_IOCTL_WIPE_PASSWORD_CACHE);
		TC_CASE_RET_NAME (TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR);
		TC_CASE_RET_NAME (VC_IOCTL_GET_DRIVE_GEOMETRY_EX);

		TC_CASE_RET_NAME (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS);

#undef TC_CASE_RET_NAME
	}

	if (ulCode ==			 IOCTL_DISK_GET_DRIVE_GEOMETRY)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_GEOMETRY");
	else if (ulCode ==		 IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_DEVICE_NAME)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME");
	else if (ulCode ==		 IOCTL_MOUNTDEV_QUERY_UNIQUE_ID)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID");
	else if (ulCode ==		 IOCTL_VOLUME_ONLINE)
		return (LPWSTR) _T ("IOCTL_VOLUME_ONLINE");
	else if (ulCode ==		 IOCTL_MOUNTDEV_LINK_CREATED)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_LINK_CREATED");
	else if (ulCode ==		 IOCTL_MOUNTDEV_LINK_DELETED)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_LINK_DELETED");
	else if (ulCode ==		 IOCTL_MOUNTMGR_QUERY_POINTS)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_QUERY_POINTS");
	else if (ulCode ==		 IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED");
	else if (ulCode ==		 IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED)
		return (LPWSTR) _T ("IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED");
	else if (ulCode ==		 IOCTL_DISK_GET_LENGTH_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_GET_LENGTH_INFO");
	else if (ulCode ==		 IOCTL_STORAGE_GET_DEVICE_NUMBER)
		return (LPWSTR) _T ("IOCTL_STORAGE_GET_DEVICE_NUMBER");
	else if (ulCode ==		 IOCTL_DISK_GET_PARTITION_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_GET_PARTITION_INFO");
	else if (ulCode ==		 IOCTL_DISK_GET_PARTITION_INFO_EX)
		return (LPWSTR) _T ("IOCTL_DISK_GET_PARTITION_INFO_EX");
	else if (ulCode ==		 IOCTL_DISK_SET_PARTITION_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_SET_PARTITION_INFO");
	else if (ulCode ==		 IOCTL_DISK_GET_DRIVE_LAYOUT)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_LAYOUT");
	else if (ulCode ==		 IOCTL_DISK_GET_DRIVE_LAYOUT_EX)
		return (LPWSTR) _T ("IOCTL_DISK_GET_DRIVE_LAYOUT_EX");
	else if (ulCode ==		 IOCTL_DISK_SET_DRIVE_LAYOUT_EX)
		return (LPWSTR) _T ("IOCTL_DISK_SET_DRIVE_LAYOUT_EX");
	else if (ulCode ==		 IOCTL_DISK_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_VERIFY");
	else if (ulCode == IOCTL_DISK_FORMAT_TRACKS)
		return (LPWSTR) _T ("IOCTL_DISK_FORMAT_TRACKS");
	else if (ulCode == IOCTL_DISK_REASSIGN_BLOCKS)
		return (LPWSTR) _T ("IOCTL_DISK_REASSIGN_BLOCKS");
	else if (ulCode == IOCTL_DISK_PERFORMANCE)
		return (LPWSTR) _T ("IOCTL_DISK_PERFORMANCE");
	else if (ulCode == IOCTL_DISK_IS_WRITABLE)
		return (LPWSTR) _T ("IOCTL_DISK_IS_WRITABLE");
	else if (ulCode == IOCTL_DISK_LOGGING)
		return (LPWSTR) _T ("IOCTL_DISK_LOGGING");
	else if (ulCode == IOCTL_DISK_FORMAT_TRACKS_EX)
		return (LPWSTR) _T ("IOCTL_DISK_FORMAT_TRACKS_EX");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_STRUCTURE)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_STRUCTURE");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_DATA)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_DATA");
	else if (ulCode == IOCTL_DISK_HISTOGRAM_RESET)
		return (LPWSTR) _T ("IOCTL_DISK_HISTOGRAM_RESET");
	else if (ulCode == IOCTL_DISK_REQUEST_STRUCTURE)
		return (LPWSTR) _T ("IOCTL_DISK_REQUEST_STRUCTURE");
	else if (ulCode == IOCTL_DISK_REQUEST_DATA)
		return (LPWSTR) _T ("IOCTL_DISK_REQUEST_DATA");
	else if (ulCode == IOCTL_DISK_CONTROLLER_NUMBER)
		return (LPWSTR) _T ("IOCTL_DISK_CONTROLLER_NUMBER");
	else if (ulCode == SMART_GET_VERSION)
		return (LPWSTR) _T ("SMART_GET_VERSION");
	else if (ulCode == SMART_SEND_DRIVE_COMMAND)
		return (LPWSTR) _T ("SMART_SEND_DRIVE_COMMAND");
	else if (ulCode == SMART_RCV_DRIVE_DATA)
		return (LPWSTR) _T ("SMART_RCV_DRIVE_DATA");
	else if (ulCode == IOCTL_DISK_INTERNAL_SET_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_INTERNAL_SET_VERIFY");
	else if (ulCode == IOCTL_DISK_INTERNAL_CLEAR_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_INTERNAL_CLEAR_VERIFY");
	else if (ulCode == IOCTL_DISK_CHECK_VERIFY)
		return (LPWSTR) _T ("IOCTL_DISK_CHECK_VERIFY");
	else if (ulCode == IOCTL_DISK_MEDIA_REMOVAL)
		return (LPWSTR) _T ("IOCTL_DISK_MEDIA_REMOVAL");
	else if (ulCode == IOCTL_DISK_EJECT_MEDIA)
		return (LPWSTR) _T ("IOCTL_DISK_EJECT_MEDIA");
	else if (ulCode == IOCTL_DISK_LOAD_MEDIA)
		return (LPWSTR) _T ("IOCTL_DISK_LOAD_MEDIA");
	else if (ulCode == IOCTL_DISK_RESERVE)
		return (LPWSTR) _T ("IOCTL_DISK_RESERVE");
	else if (ulCode == IOCTL_DISK_RELEASE)
		return (LPWSTR) _T ("IOCTL_DISK_RELEASE");
	else if (ulCode == IOCTL_DISK_FIND_NEW_DEVICES)
		return (LPWSTR) _T ("IOCTL_DISK_FIND_NEW_DEVICES");
	else if (ulCode == IOCTL_DISK_GET_MEDIA_TYPES)
		return (LPWSTR) _T ("IOCTL_DISK_GET_MEDIA_TYPES");
	else if (ulCode == IOCTL_DISK_IS_CLUSTERED)
		return (LPWSTR) _T ("IOCTL_DISK_IS_CLUSTERED");	
	else if (ulCode == IOCTL_STORAGE_GET_MEDIA_TYPES)
		return (LPWSTR) _T ("IOCTL_STORAGE_GET_MEDIA_TYPES");
	else if (ulCode == IOCTL_STORAGE_GET_HOTPLUG_INFO)
		return (LPWSTR) _T ("IOCTL_STORAGE_GET_HOTPLUG_INFO");
	else if (ulCode == IOCTL_STORAGE_SET_HOTPLUG_INFO)
		return (LPWSTR) _T ("IOCTL_STORAGE_SET_HOTPLUG_INFO");
	else if (ulCode == IOCTL_STORAGE_QUERY_PROPERTY)
		return (LPWSTR) _T ("IOCTL_STORAGE_QUERY_PROPERTY");
	else if (ulCode == IOCTL_VOLUME_GET_GPT_ATTRIBUTES)
		return (LPWSTR) _T ("IOCTL_VOLUME_GET_GPT_ATTRIBUTES");	
	else if (ulCode == FT_BALANCED_READ_MODE)
		return (LPWSTR) _T ("FT_BALANCED_READ_MODE");
	else if (ulCode == IOCTL_VOLUME_QUERY_ALLOCATION_HINT)
		return (LPWSTR) _T ("IOCTL_VOLUME_QUERY_ALLOCATION_HINT");
	else if (ulCode == IOCTL_DISK_GET_CLUSTER_INFO)
		return (LPWSTR) _T ("IOCTL_DISK_GET_CLUSTER_INFO");
	else if (ulCode == IOCTL_DISK_ARE_VOLUMES_READY)
		return (LPWSTR) _T ("IOCTL_DISK_ARE_VOLUMES_READY");			
	else if (ulCode == IOCTL_VOLUME_IS_DYNAMIC)
		return (LPWSTR) _T ("IOCTL_VOLUME_IS_DYNAMIC");
	else if (ulCode == IOCTL_MOUNTDEV_QUERY_STABLE_GUID)
		return (LPWSTR) _T ("IOCTL_MOUNTDEV_QUERY_STABLE_GUID");
	else if (ulCode == IOCTL_VOLUME_POST_ONLINE)
		return (LPWSTR) _T ("IOCTL_VOLUME_POST_ONLINE");
	else if (ulCode == IOCTL_STORAGE_CHECK_PRIORITY_HINT_SUPPORT)
		return (LPWSTR) _T ("IOCTL_STORAGE_CHECK_PRIORITY_HINT_SUPPORT");
	else if (ulCode == IRP_MJ_READ)
		return (LPWSTR) _T ("IRP_MJ_READ");
	else if (ulCode == IRP_MJ_WRITE)
		return (LPWSTR) _T ("IRP_MJ_WRITE");
	else if (ulCode == IRP_MJ_CREATE)
		return (LPWSTR) _T ("IRP_MJ_CREATE");
	else if (ulCode == IRP_MJ_CLOSE)
		return (LPWSTR) _T ("IRP_MJ_CLOSE");
	else if (ulCode == IRP_MJ_CLEANUP)
		return (LPWSTR) _T ("IRP_MJ_CLEANUP");
	else if (ulCode == IRP_MJ_FLUSH_BUFFERS)
		return (LPWSTR) _T ("IRP_MJ_FLUSH_BUFFERS");
	else if (ulCode == IRP_MJ_SHUTDOWN)
		return (LPWSTR) _T ("IRP_MJ_SHUTDOWN");
	else if (ulCode == IRP_MJ_DEVICE_CONTROL)
		return (LPWSTR) _T ("IRP_MJ_DEVICE_CONTROL");
	else
	{
		return (LPWSTR) _T ("IOCTL");
	}
}

#endif

void TCDeleteDeviceObject (PDEVICE_OBJECT DeviceObject, PEXTENSION Extension)
{
	UNICODE_STRING Win32NameString;
	NTSTATUS ntStatus;

	Dump ("TCDeleteDeviceObject BEGIN\n");

	if (Extension->bRootDevice)
	{
		RtlInitUnicodeString (&Win32NameString, (LPWSTR) DOS_ROOT_PREFIX);
		ntStatus = IoDeleteSymbolicLink (&Win32NameString);
		if (!NT_SUCCESS (ntStatus))
			Dump ("IoDeleteSymbolicLink failed ntStatus = 0x%08x\n", ntStatus);

		RootDeviceObject = NULL;
	}
	else
	{
		if (Extension->peThread != NULL)
			TCStopVolumeThread (DeviceObject, Extension);

		if (Extension->UserSid)
			TCfree (Extension->UserSid);

		if (Extension->SecurityClientContextValid)
		{
			if (OsMajorVersion == 5 && OsMinorVersion == 0)
			{
				ObDereferenceObject (Extension->SecurityClientContext.ClientToken);
			}
			else
			{
				// Windows 2000 does not support PsDereferenceImpersonationToken() used by SeDeleteClientSecurity().
				// TODO: Use only SeDeleteClientSecurity() once support for Windows 2000 is dropped.

				VOID (*PsDereferenceImpersonationTokenD) (PACCESS_TOKEN ImpersonationToken);
				UNICODE_STRING name;
				RtlInitUnicodeString (&name, L"PsDereferenceImpersonationToken");

				PsDereferenceImpersonationTokenD = MmGetSystemRoutineAddress (&name);
				if (!PsDereferenceImpersonationTokenD)
					TC_BUG_CHECK (STATUS_NOT_IMPLEMENTED);

#				define PsDereferencePrimaryToken
#				define PsDereferenceImpersonationToken PsDereferenceImpersonationTokenD

				SeDeleteClientSecurity (&Extension->SecurityClientContext);

#				undef PsDereferencePrimaryToken
#				undef PsDereferenceImpersonationToken
			}
		}

		VirtualVolumeDeviceObjects[Extension->nDosDriveNo] = NULL;
	}

	IoDeleteDevice (DeviceObject);

	Dump ("TCDeleteDeviceObject END\n");
}


VOID TCUnloadDriver (PDRIVER_OBJECT DriverObject)
{
	Dump ("TCUnloadDriver BEGIN\n");

	OnShutdownPending();

	if (IsBootDriveMounted())
		TC_BUG_CHECK (STATUS_INVALID_DEVICE_STATE);

	EncryptionThreadPoolStop();
	TCDeleteDeviceObject (RootDeviceObject, (PEXTENSION) RootDeviceObject->DeviceExtension);

	Dump ("TCUnloadDriver END\n");
}


void OnShutdownPending ()
{
	UNMOUNT_STRUCT unmount;
	memset (&unmount, 0, sizeof (unmount));
	unmount.ignoreOpenFiles = TRUE;

	while (SendDeviceIoControlRequest (RootDeviceObject, TC_IOCTL_DISMOUNT_ALL_VOLUMES, &unmount, sizeof (unmount), &unmount, sizeof (unmount)) == STATUS_INSUFFICIENT_RESOURCES || unmount.HiddenVolumeProtectionTriggered)
		unmount.HiddenVolumeProtectionTriggered = FALSE;

	while (SendDeviceIoControlRequest (RootDeviceObject, TC_IOCTL_WIPE_PASSWORD_CACHE, NULL, 0, NULL, 0) == STATUS_INSUFFICIENT_RESOURCES);
}


NTSTATUS TCDeviceIoControl (PWSTR deviceName, ULONG IoControlCode, void *InputBuffer, ULONG InputBufferSize, void *OutputBuffer, ULONG OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	PFILE_OBJECT fileObject;
	PDEVICE_OBJECT deviceObject;
	KEVENT event;
	UNICODE_STRING name;

	RtlInitUnicodeString(&name, deviceName);
	ntStatus = IoGetDeviceObjectPointer (&name, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject);

	if (!NT_SUCCESS (ntStatus))
		return ntStatus;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     deviceObject,
					     InputBuffer, InputBufferSize,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &event,
					     &ioStatusBlock);

	if (irp == NULL)
	{
		Dump ("IRP allocation failed\n");
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	IoGetNextIrpStackLocation (irp)->FileObject = fileObject;

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, Executive, KernelMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

ret:
	ObDereferenceObject (fileObject);
	return ntStatus;
}


typedef struct
{
	PDEVICE_OBJECT deviceObject; ULONG ioControlCode; void *inputBuffer; int inputBufferSize; void *outputBuffer; int outputBufferSize;
	NTSTATUS Status;
	KEVENT WorkItemCompletedEvent;
} SendDeviceIoControlRequestWorkItemArgs;


static VOID SendDeviceIoControlRequestWorkItemRoutine (PDEVICE_OBJECT rootDeviceObject, SendDeviceIoControlRequestWorkItemArgs *arg)
{
	arg->Status = SendDeviceIoControlRequest (arg->deviceObject, arg->ioControlCode, arg->inputBuffer, arg->inputBufferSize, arg->outputBuffer, arg->outputBufferSize);
	KeSetEvent (&arg->WorkItemCompletedEvent, IO_NO_INCREMENT, FALSE);
}


NTSTATUS SendDeviceIoControlRequest (PDEVICE_OBJECT deviceObject, ULONG ioControlCode, void *inputBuffer, int inputBufferSize, void *outputBuffer, int outputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS status;
	PIRP irp;
	KEVENT event;

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		SendDeviceIoControlRequestWorkItemArgs args;

		PIO_WORKITEM workItem = IoAllocateWorkItem (RootDeviceObject);
		if (!workItem)
			return STATUS_INSUFFICIENT_RESOURCES;

		args.deviceObject = deviceObject;
		args.ioControlCode = ioControlCode;
		args.inputBuffer = inputBuffer;
		args.inputBufferSize = inputBufferSize;
		args.outputBuffer = outputBuffer;
		args.outputBufferSize = outputBufferSize;

		KeInitializeEvent (&args.WorkItemCompletedEvent, SynchronizationEvent, FALSE);
		IoQueueWorkItem (workItem, SendDeviceIoControlRequestWorkItemRoutine, DelayedWorkQueue, &args);

		KeWaitForSingleObject (&args.WorkItemCompletedEvent, Executive, KernelMode, FALSE, NULL);
		IoFreeWorkItem (workItem);

		return args.Status;
	}

	KeInitializeEvent (&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (ioControlCode, deviceObject, inputBuffer, inputBufferSize,
		outputBuffer, outputBufferSize, FALSE, &event, &ioStatusBlock);

	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	ObReferenceObject (deviceObject);

	status = IoCallDriver (deviceObject, irp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatusBlock.Status;
	}

	ObDereferenceObject (deviceObject);
	return status;
}


NTSTATUS ProbeRealDriveSize (PDEVICE_OBJECT driveDeviceObject, LARGE_INTEGER *driveSize)
{
	NTSTATUS status;
	LARGE_INTEGER sysLength;
	LARGE_INTEGER offset;
	byte *sectorBuffer;
	ULONGLONG startTime;

	if (!UserCanAccessDriveDevice())
		return STATUS_ACCESS_DENIED;

	sectorBuffer = TCalloc (TC_SECTOR_SIZE_BIOS);
	if (!sectorBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	status = SendDeviceIoControlRequest (driveDeviceObject, IOCTL_DISK_GET_LENGTH_INFO,
		NULL, 0, &sysLength, sizeof (sysLength));

	if (!NT_SUCCESS (status))
	{
		Dump ("Failed to get drive size - error %x\n", status);
		TCfree (sectorBuffer);
		return status;
	}

	startTime = KeQueryInterruptTime ();
	for (offset.QuadPart = sysLength.QuadPart; ; offset.QuadPart += TC_SECTOR_SIZE_BIOS)
	{
		status = TCReadDevice (driveDeviceObject, sectorBuffer, offset, TC_SECTOR_SIZE_BIOS);

		if (NT_SUCCESS (status))
			status = TCWriteDevice (driveDeviceObject, sectorBuffer, offset, TC_SECTOR_SIZE_BIOS);

		if (!NT_SUCCESS (status))
		{
			driveSize->QuadPart = offset.QuadPart;
			Dump ("Real drive size = %I64d bytes (%I64d hidden)\n", driveSize->QuadPart, driveSize->QuadPart - sysLength.QuadPart);
			TCfree (sectorBuffer);
			return STATUS_SUCCESS;
		}

		if (KeQueryInterruptTime() - startTime > 3ULL * 60 * 1000 * 1000 * 10)
		{
			// Abort if probing for more than 3 minutes
			driveSize->QuadPart = sysLength.QuadPart;
			TCfree (sectorBuffer);
			return STATUS_TIMEOUT;
		}
	}
}


NTSTATUS TCOpenFsVolume (PEXTENSION Extension, PHANDLE volumeHandle, PFILE_OBJECT * fileObject)
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fullFileName;
	IO_STATUS_BLOCK ioStatus;
	WCHAR volumeName[TC_MAX_PATH];

	TCGetNTNameFromNumber (volumeName, sizeof(volumeName),Extension->nDosDriveNo);
	RtlInitUnicodeString (&fullFileName, volumeName);
	InitializeObjectAttributes (&objectAttributes, &fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = ZwCreateFile (volumeHandle,
		SYNCHRONIZE | GENERIC_READ,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	Dump ("Volume %ls open NTSTATUS 0x%08x\n", volumeName, ntStatus);

	if (!NT_SUCCESS (ntStatus))
		return ntStatus;

	ntStatus = ObReferenceObjectByHandle (*volumeHandle,
		FILE_READ_DATA,
		NULL,
		KernelMode,
		fileObject,
		NULL);

	if (!NT_SUCCESS (ntStatus))
		ZwClose (*volumeHandle);

	return ntStatus;
}


void TCCloseFsVolume (HANDLE volumeHandle, PFILE_OBJECT fileObject)
{
	ObDereferenceObject (fileObject);
	ZwClose (volumeHandle);
}


static NTSTATUS TCReadWriteDevice (BOOL write, PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock;
	PIRP irp;
	KEVENT completionEvent;

	ASSERT (KeGetCurrentIrql() <= APC_LEVEL);

	KeInitializeEvent (&completionEvent, NotificationEvent, FALSE);
	irp = IoBuildSynchronousFsdRequest (write ? IRP_MJ_WRITE : IRP_MJ_READ, deviceObject, buffer, length, &offset, &completionEvent, &ioStatusBlock);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	ObReferenceObject (deviceObject);
	status = IoCallDriver (deviceObject, irp);

	if (status == STATUS_PENDING)
	{
		status = KeWaitForSingleObject (&completionEvent, Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS (status))
			status = ioStatusBlock.Status;
	}

	ObDereferenceObject (deviceObject);
	return status;
}


NTSTATUS TCReadDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	return TCReadWriteDevice (FALSE, deviceObject, buffer, offset, length);
}


NTSTATUS TCWriteDevice (PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	return TCReadWriteDevice (TRUE, deviceObject, buffer, offset, length);
}


NTSTATUS TCFsctlCall (PFILE_OBJECT fileObject, LONG IoControlCode,
	void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	KEVENT event;
	PIO_STACK_LOCATION stack;
	PDEVICE_OBJECT deviceObject = IoGetRelatedDeviceObject (fileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
					     deviceObject,
					     InputBuffer, InputBufferSize,
					     OutputBuffer, OutputBufferSize,
					     FALSE,
					     &event,
					     &ioStatusBlock);

	if (irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	stack = IoGetNextIrpStackLocation(irp);

	stack->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
	stack->MinorFunction = IRP_MN_USER_FS_REQUEST;
	stack->FileObject = fileObject;

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, Executive, KernelMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

	return ntStatus;
}


NTSTATUS CreateDriveLink (int nDosDriveNo)
{
	WCHAR dev[128], link[128];
	UNICODE_STRING deviceName, symLink;
	NTSTATUS ntStatus;

	TCGetNTNameFromNumber (dev, sizeof(dev),nDosDriveNo);
	TCGetDosNameFromNumber (link, sizeof(link),nDosDriveNo, DeviceNamespaceDefault);

	RtlInitUnicodeString (&deviceName, dev);
	RtlInitUnicodeString (&symLink, link);

	ntStatus = IoCreateSymbolicLink (&symLink, &deviceName);
	Dump ("IoCreateSymbolicLink returned %X\n", ntStatus);
	return ntStatus;
}


NTSTATUS RemoveDriveLink (int nDosDriveNo)
{
	WCHAR link[256];
	UNICODE_STRING symLink;
	NTSTATUS ntStatus;

	TCGetDosNameFromNumber (link, sizeof(link),nDosDriveNo, DeviceNamespaceDefault);
	RtlInitUnicodeString (&symLink, link);

	ntStatus = IoDeleteSymbolicLink (&symLink);
	Dump ("IoDeleteSymbolicLink returned %X\n", ntStatus);
	return ntStatus;
}


NTSTATUS MountManagerMount (MOUNT_STRUCT *mount)
{
	NTSTATUS ntStatus;
	WCHAR arrVolume[256];
	char buf[200];
	PMOUNTMGR_TARGET_NAME in = (PMOUNTMGR_TARGET_NAME) buf;
	PMOUNTMGR_CREATE_POINT_INPUT point = (PMOUNTMGR_CREATE_POINT_INPUT) buf;

	TCGetNTNameFromNumber (arrVolume, sizeof(arrVolume),mount->nDosDriveNo);
	in->DeviceNameLength = (USHORT) wcslen (arrVolume) * 2;
	RtlStringCbCopyW(in->DeviceName, sizeof(buf) - sizeof(in->DeviceNameLength),arrVolume);

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
		in, (ULONG) (sizeof (in->DeviceNameLength) + wcslen (arrVolume) * 2), 0, 0);

	memset (buf, 0, sizeof buf);
	TCGetDosNameFromNumber ((PWSTR) &point[1], sizeof(buf) - sizeof(MOUNTMGR_CREATE_POINT_INPUT),mount->nDosDriveNo, DeviceNamespaceDefault);

	point->SymbolicLinkNameOffset = sizeof (MOUNTMGR_CREATE_POINT_INPUT);
	point->SymbolicLinkNameLength = (USHORT) wcslen ((PWSTR) &point[1]) * 2;

	point->DeviceNameOffset = point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength;
	TCGetNTNameFromNumber ((PWSTR) (buf + point->DeviceNameOffset), sizeof(buf) - point->DeviceNameOffset,mount->nDosDriveNo);
	point->DeviceNameLength = (USHORT) wcslen ((PWSTR) (buf + point->DeviceNameOffset)) * 2;

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_CREATE_POINT, point,
			point->DeviceNameOffset + point->DeviceNameLength, 0, 0);

	return ntStatus;
}


NTSTATUS MountManagerUnmount (int nDosDriveNo)
{
	NTSTATUS ntStatus;
	char buf[256], out[300];
	PMOUNTMGR_MOUNT_POINT in = (PMOUNTMGR_MOUNT_POINT) buf;

	memset (buf, 0, sizeof buf);

	TCGetDosNameFromNumber ((PWSTR) &in[1], sizeof(buf) - sizeof(MOUNTMGR_MOUNT_POINT),nDosDriveNo, DeviceNamespaceDefault);

	// Only symbolic link can be deleted with IOCTL_MOUNTMGR_DELETE_POINTS. If any other entry is specified, the mount manager will ignore subsequent IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION for the same volume ID.
	in->SymbolicLinkNameOffset = sizeof (MOUNTMGR_MOUNT_POINT);
	in->SymbolicLinkNameLength = (USHORT) wcslen ((PWCHAR) &in[1]) * 2;

	ntStatus = TCDeviceIoControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_DELETE_POINTS,
		in, sizeof(MOUNTMGR_MOUNT_POINT) + in->SymbolicLinkNameLength, out, sizeof out);

	Dump ("IOCTL_MOUNTMGR_DELETE_POINTS returned 0x%08x\n", ntStatus);

	return ntStatus;
}


NTSTATUS MountDevice (PDEVICE_OBJECT DeviceObject, MOUNT_STRUCT *mount)
{
	PDEVICE_OBJECT NewDeviceObject;
	NTSTATUS ntStatus;

	// Make sure the user is asking for a reasonable nDosDriveNo
	if (mount->nDosDriveNo >= 0 && mount->nDosDriveNo <= 25
		&& IsDriveLetterAvailable (mount->nDosDriveNo, DeviceNamespaceDefault) // drive letter must not exist both locally and globally
		&& IsDriveLetterAvailable (mount->nDosDriveNo, DeviceNamespaceGlobal)
		)
	{
		Dump ("Mount request looks valid\n");
	}
	else
	{
		Dump ("WARNING: MOUNT DRIVE LETTER INVALID\n");
		mount->nReturnCode = ERR_DRIVE_NOT_FOUND;
		return ERR_DRIVE_NOT_FOUND;
	}

	if (!SelfTestsPassed)
	{
		Dump ("Failure of built-in automatic self-tests! Mounting not allowed.\n");
		mount->nReturnCode = ERR_SELF_TESTS_FAILED;
		return ERR_SELF_TESTS_FAILED;
	}

	ntStatus = TCCreateDeviceObject (DeviceObject->DriverObject, &NewDeviceObject, mount);

	if (!NT_SUCCESS (ntStatus))
	{
		Dump ("Mount CREATE DEVICE ERROR, ntStatus = 0x%08x\n", ntStatus);
		return ntStatus;
	}
	else
	{
		PEXTENSION NewExtension = (PEXTENSION) NewDeviceObject->DeviceExtension;
		SECURITY_SUBJECT_CONTEXT subContext;
		PACCESS_TOKEN accessToken;

		SeCaptureSubjectContext (&subContext);
		SeLockSubjectContext(&subContext);
		if (subContext.ClientToken && subContext.ImpersonationLevel >= SecurityImpersonation)
			accessToken = subContext.ClientToken;
		else
			accessToken = subContext.PrimaryToken;

		if (!accessToken)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
		}
		else
		{
			PTOKEN_USER tokenUser;

			ntStatus = SeQueryInformationToken (accessToken, TokenUser, &tokenUser);
			if (NT_SUCCESS (ntStatus))
			{
				ULONG sidLength = RtlLengthSid (tokenUser->User.Sid);

				NewExtension->UserSid = TCalloc (sidLength);
				if (!NewExtension->UserSid)
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				else
					ntStatus = RtlCopySid (sidLength, NewExtension->UserSid, tokenUser->User.Sid);

				ExFreePool (tokenUser);		// Documented in newer versions of WDK
			}
		}

		SeUnlockSubjectContext(&subContext);
		SeReleaseSubjectContext (&subContext);

		if (NT_SUCCESS (ntStatus))
			ntStatus = TCStartVolumeThread (NewDeviceObject, NewExtension, mount);

		if (!NT_SUCCESS (ntStatus))
		{
			Dump ("Mount FAILURE NT ERROR, ntStatus = 0x%08x\n", ntStatus);
			TCDeleteDeviceObject (NewDeviceObject, NewExtension);
			return ntStatus;
		}
		else
		{
			if (mount->nReturnCode == 0)
			{
				HANDLE volumeHandle;
				PFILE_OBJECT volumeFileObject;
				ULONG labelLen = (ULONG) wcslen (mount->wszLabel);
				BOOL bIsNTFS = FALSE;
				ULONG labelMaxLen, labelEffectiveLen;

				Dump ("Mount SUCCESS TC code = 0x%08x READ-ONLY = %d\n", mount->nReturnCode, NewExtension->bReadOnly);

				if (NewExtension->bReadOnly)
					NewDeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;

				NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

				NewExtension->UniqueVolumeId = LastUniqueVolumeId++;

				// check again that the drive letter is available globally and locally
				if (	!IsDriveLetterAvailable (mount->nDosDriveNo, DeviceNamespaceDefault)
					|| !IsDriveLetterAvailable (mount->nDosDriveNo, DeviceNamespaceGlobal)
					)
				{
						TCDeleteDeviceObject (NewDeviceObject, NewExtension);
						mount->nReturnCode = ERR_DRIVE_NOT_FOUND;
						return ERR_DRIVE_NOT_FOUND;
				}

				if (mount->bMountManager)
					MountManagerMount (mount);

				NewExtension->bMountManager = mount->bMountManager;

				// We create symbolic link even if mount manager is notified of
				// arriving volume as it apparently sometimes fails to create the link
				CreateDriveLink (mount->nDosDriveNo);

				mount->FilesystemDirty = FALSE;

				if (NT_SUCCESS (TCOpenFsVolume (NewExtension, &volumeHandle, &volumeFileObject)))
				{
					__try
					{
						ULONG fsStatus;

						if (NT_SUCCESS (TCFsctlCall (volumeFileObject, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &fsStatus, sizeof (fsStatus)))
							&& (fsStatus & VOLUME_IS_DIRTY))
						{
							mount->FilesystemDirty = TRUE;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						mount->FilesystemDirty = TRUE;
					}

					// detect if the filesystem is NTFS or FAT
					__try
					{
						NTFS_VOLUME_DATA_BUFFER ntfsData;
						if (NT_SUCCESS (TCFsctlCall (volumeFileObject, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntfsData, sizeof (ntfsData))))
						{
							bIsNTFS = TRUE;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						bIsNTFS = FALSE;
					}

					NewExtension->bIsNTFS = bIsNTFS;
					mount->bIsNTFS = bIsNTFS;

					if (labelLen > 0)
					{
						if (bIsNTFS)
							labelMaxLen = 32; // NTFS maximum label length
						else
							labelMaxLen = 11; // FAT maximum label length

						// calculate label effective length
						labelEffectiveLen = labelLen > labelMaxLen? labelMaxLen : labelLen;

						// correct the label in the device
						memset (&NewExtension->wszLabel[labelEffectiveLen], 0, 33 - labelEffectiveLen);
						memcpy (mount->wszLabel, NewExtension->wszLabel, 33);

						// set the volume label
						__try
						{
							IO_STATUS_BLOCK ioblock;
							ULONG labelInfoSize = sizeof(FILE_FS_LABEL_INFORMATION) + (labelEffectiveLen * sizeof(WCHAR));
							FILE_FS_LABEL_INFORMATION* labelInfo = (FILE_FS_LABEL_INFORMATION*) TCalloc (labelInfoSize);
							labelInfo->VolumeLabelLength = labelEffectiveLen * sizeof(WCHAR);
							memcpy (labelInfo->VolumeLabel, mount->wszLabel, labelInfo->VolumeLabelLength);

							if (STATUS_SUCCESS == ZwSetVolumeInformationFile (volumeHandle, &ioblock, labelInfo, labelInfoSize, FileFsLabelInformation))
							{
								mount->bDriverSetLabel = TRUE;
								NewExtension->bDriverSetLabel = TRUE;
							}

							TCfree(labelInfo);
						}
						__except (EXCEPTION_EXECUTE_HANDLER)
						{

						}
					}

					TCCloseFsVolume (volumeHandle, volumeFileObject);
				}
			}
			else
			{
				Dump ("Mount FAILURE TC code = 0x%08x\n", mount->nReturnCode);
				TCDeleteDeviceObject (NewDeviceObject, NewExtension);
			}

			return STATUS_SUCCESS;
		}
	}
}

NTSTATUS UnmountDevice (UNMOUNT_STRUCT *unmountRequest, PDEVICE_OBJECT deviceObject, BOOL ignoreOpenFiles)
{
	PEXTENSION extension = deviceObject->DeviceExtension;
	NTSTATUS ntStatus;
	HANDLE volumeHandle;
	PFILE_OBJECT volumeFileObject;

	Dump ("UnmountDevice %d\n", extension->nDosDriveNo);

	ntStatus = TCOpenFsVolume (extension, &volumeHandle, &volumeFileObject);

	if (NT_SUCCESS (ntStatus))
	{
		int dismountRetry;

		// Dismounting a writable NTFS filesystem prevents the driver from being unloaded on Windows 7
		if (IsOSAtLeast (WIN_7) && !extension->bReadOnly)
		{
			NTFS_VOLUME_DATA_BUFFER ntfsData;

			if (NT_SUCCESS (TCFsctlCall (volumeFileObject, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntfsData, sizeof (ntfsData))))
				DriverUnloadDisabled = TRUE;
		}

		// Lock volume
		ntStatus = TCFsctlCall (volumeFileObject, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);
		Dump ("FSCTL_LOCK_VOLUME returned %X\n", ntStatus);

		if (!NT_SUCCESS (ntStatus) && !ignoreOpenFiles)
		{
			TCCloseFsVolume (volumeHandle, volumeFileObject);
			return ERR_FILES_OPEN;
		}

		// Dismount volume
		for (dismountRetry = 0; dismountRetry < 200; ++dismountRetry)
		{
			ntStatus = TCFsctlCall (volumeFileObject, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);
			Dump ("FSCTL_DISMOUNT_VOLUME returned %X\n", ntStatus);

			if (NT_SUCCESS (ntStatus) || ntStatus == STATUS_VOLUME_DISMOUNTED)
				break;

			if (!ignoreOpenFiles)
			{
				TCCloseFsVolume (volumeHandle, volumeFileObject);
				return ERR_FILES_OPEN;
			}

			TCSleep (100);
		}
	}
	else
	{
		// Volume cannot be opened => force dismount if allowed
		if (!ignoreOpenFiles)
			return ERR_FILES_OPEN;
		else
			volumeHandle = NULL;
	}

	if (extension->bMountManager)
		MountManagerUnmount (extension->nDosDriveNo);

	// We always remove symbolic link as mount manager might fail to do so
	RemoveDriveLink (extension->nDosDriveNo);

	extension->bShuttingDown = TRUE;

	ntStatus = IoAcquireRemoveLock (&extension->Queue.RemoveLock, NULL);
	ASSERT (NT_SUCCESS (ntStatus));
	IoReleaseRemoveLockAndWait (&extension->Queue.RemoveLock, NULL);

	if (volumeHandle != NULL)
		TCCloseFsVolume (volumeHandle, volumeFileObject);

	if (unmountRequest)
	{
		PCRYPTO_INFO cryptoInfo = ((PEXTENSION) deviceObject->DeviceExtension)->cryptoInfo;
		unmountRequest->HiddenVolumeProtectionTriggered = (cryptoInfo->bProtectHiddenVolume && cryptoInfo->bHiddenVolProtectionAction);
	}

	TCDeleteDeviceObject (deviceObject, (PEXTENSION) deviceObject->DeviceExtension);
	return 0;
}


static PDEVICE_OBJECT FindVolumeWithHighestUniqueId (int maxUniqueId)
{
	PDEVICE_OBJECT highestIdDevice = NULL;
	int highestId = -1;
	int drive;

	for (drive = MIN_MOUNTED_VOLUME_DRIVE_NUMBER; drive <= MAX_MOUNTED_VOLUME_DRIVE_NUMBER; ++drive)
	{
		PDEVICE_OBJECT device = GetVirtualVolumeDeviceObject (drive);
		if (device)
		{
			PEXTENSION extension = (PEXTENSION) device->DeviceExtension;
			if (extension->UniqueVolumeId > highestId && extension->UniqueVolumeId <= maxUniqueId)
			{
				highestId = extension->UniqueVolumeId;
				highestIdDevice = device;
			}
		}
	}

	return highestIdDevice;
}


NTSTATUS UnmountAllDevices (UNMOUNT_STRUCT *unmountRequest, BOOL ignoreOpenFiles)
{
	NTSTATUS status = 0;
	PDEVICE_OBJECT ListDevice;
	int maxUniqueId = LastUniqueVolumeId;

	Dump ("Unmounting all volumes\n");

	if (unmountRequest)
		unmountRequest->HiddenVolumeProtectionTriggered = FALSE;

	// Dismount volumes in the reverse order they were mounted to properly dismount nested volumes
	while ((ListDevice = FindVolumeWithHighestUniqueId (maxUniqueId)) != NULL)
	{
		PEXTENSION ListExtension = (PEXTENSION) ListDevice->DeviceExtension;
		maxUniqueId = ListExtension->UniqueVolumeId - 1;

		if (IsVolumeAccessibleByCurrentUser (ListExtension))
		{
			NTSTATUS ntStatus;

			if (unmountRequest)
				unmountRequest->nDosDriveNo = ListExtension->nDosDriveNo;

			ntStatus = UnmountDevice (unmountRequest, ListDevice, ignoreOpenFiles);
			status = ntStatus == 0 ? status : ntStatus;

			if (unmountRequest && unmountRequest->HiddenVolumeProtectionTriggered)
				break;
		}
	}

	return status;
}

// Resolves symbolic link name to its target name
NTSTATUS SymbolicLinkToTarget (PWSTR symlinkName, PWSTR targetName, USHORT maxTargetNameLength)
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fullFileName;
	HANDLE handle;

	RtlInitUnicodeString (&fullFileName, symlinkName);
	InitializeObjectAttributes (&objectAttributes, &fullFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = ZwOpenSymbolicLinkObject (&handle, GENERIC_READ, &objectAttributes);

	if (NT_SUCCESS (ntStatus))
	{
		UNICODE_STRING target;
		target.Buffer = targetName;
		target.Length = 0;
		target.MaximumLength = maxTargetNameLength;
		memset (targetName, 0, maxTargetNameLength);

		ntStatus = ZwQuerySymbolicLinkObject (handle, &target, NULL);

		ZwClose (handle);
	}

	return ntStatus;
}


// Checks if two regions overlap (borders are parts of regions)
BOOL RegionsOverlap (unsigned __int64 start1, unsigned __int64 end1, unsigned __int64 start2, unsigned __int64 end2)
{
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}


void GetIntersection (uint64 start1, uint32 length1, uint64 start2, uint64 end2, uint64 *intersectStart, uint32 *intersectLength)
{
	uint64 end1 = start1 + length1 - 1;
	uint64 intersectEnd = (end1 <= end2) ? end1 : end2;

	*intersectStart = (start1 >= start2) ? start1 : start2;
	*intersectLength = (uint32) ((*intersectStart > intersectEnd) ? 0 : intersectEnd + 1 - *intersectStart);

	if (*intersectLength == 0)
		*intersectStart = start1;
}


BOOL IsAccessibleByUser (PUNICODE_STRING objectFileName, BOOL readOnly)
{
	OBJECT_ATTRIBUTES fileObjAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE fileHandle;
	NTSTATUS status;

	ASSERT (!IoIsSystemThread (PsGetCurrentThread()));

	InitializeObjectAttributes (&fileObjAttributes, objectFileName, OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile (&fileHandle,
		readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		&fileObjAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (NT_SUCCESS (status))
	{
		ZwClose (fileHandle);
		return TRUE;
	}

	return FALSE;
}


BOOL UserCanAccessDriveDevice ()
{
	UNICODE_STRING name;
	RtlInitUnicodeString (&name, L"\\Device\\MountPointManager");

	return IsAccessibleByUser (&name, FALSE);
}

BOOL IsDriveLetterAvailable (int nDosDriveNo, DeviceNamespaceType namespaceType)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING objectName;
	WCHAR link[128];
	HANDLE handle;
	NTSTATUS ntStatus;

	TCGetDosNameFromNumber (link, sizeof(link),nDosDriveNo, namespaceType);
	RtlInitUnicodeString (&objectName, link);
	InitializeObjectAttributes (&objectAttributes, &objectName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (NT_SUCCESS (ntStatus = ZwOpenSymbolicLinkObject (&handle, GENERIC_READ, &objectAttributes)))
	{
		ZwClose (handle);
		return FALSE;
	}

	return (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND)? TRUE : FALSE;
}


NTSTATUS TCCompleteIrp (PIRP irp, NTSTATUS status, ULONG_PTR information)
{
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = information;
	IoCompleteRequest (irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS TCCompleteDiskIrp (PIRP irp, NTSTATUS status, ULONG_PTR information)
{
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = information;
	IoCompleteRequest (irp, NT_SUCCESS (status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	return status;
}


size_t GetCpuCount ()
{
	KAFFINITY activeCpuMap = KeQueryActiveProcessors();
	size_t mapSize = sizeof (activeCpuMap) * 8;
	size_t cpuCount = 0;

	while (mapSize--)
	{
		if (activeCpuMap & 1)
			++cpuCount;

		activeCpuMap >>= 1;
	}

	if (cpuCount == 0)
		return 1;

	return cpuCount;
}


void EnsureNullTerminatedString (wchar_t *str, size_t maxSizeInBytes)
{
	ASSERT ((maxSizeInBytes & 1) == 0);
	str[maxSizeInBytes / sizeof (wchar_t) - 1] = 0;
}


void *AllocateMemoryWithTimeout (size_t size, int retryDelay, int timeout)
{
	LARGE_INTEGER waitInterval;
	waitInterval.QuadPart = retryDelay * -10000;

	ASSERT (KeGetCurrentIrql() <= APC_LEVEL);
	ASSERT (retryDelay > 0 && retryDelay <= timeout);

	while (TRUE)
	{
		void *memory = TCalloc (size);
		if (memory)
			return memory;

		timeout -= retryDelay;
		if (timeout <= 0)
			break;

		KeDelayExecutionThread (KernelMode, FALSE, &waitInterval);
	}

	return NULL;
}


NTSTATUS TCReadRegistryKey (PUNICODE_STRING keyPath, wchar_t *keyValueName, PKEY_VALUE_PARTIAL_INFORMATION *keyData)
{
	OBJECT_ATTRIBUTES regObjAttribs;
	HANDLE regKeyHandle;
	NTSTATUS status;
	UNICODE_STRING valName;
	ULONG size = 0;
	ULONG resultSize;

	InitializeObjectAttributes (&regObjAttribs, keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey (&regKeyHandle, KEY_READ, &regObjAttribs);
	if (!NT_SUCCESS (status))
		return status;

	RtlInitUnicodeString (&valName, keyValueName);
	status = ZwQueryValueKey (regKeyHandle, &valName, KeyValuePartialInformation, NULL, 0, &size);

	if (!NT_SUCCESS (status) && status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL)
	{
		ZwClose (regKeyHandle);
		return status;
	}

	if (size == 0)
	{
		ZwClose (regKeyHandle);
		return STATUS_NO_DATA_DETECTED;
	}

	*keyData = (PKEY_VALUE_PARTIAL_INFORMATION) TCalloc (size);
	if (!*keyData)
	{
		ZwClose (regKeyHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryValueKey (regKeyHandle, &valName, KeyValuePartialInformation, *keyData, size, &resultSize);

	ZwClose (regKeyHandle);
	return status;
}


NTSTATUS TCWriteRegistryKey (PUNICODE_STRING keyPath, wchar_t *keyValueName, ULONG keyValueType, void *valueData, ULONG valueSize)
{
	OBJECT_ATTRIBUTES regObjAttribs;
	HANDLE regKeyHandle;
	NTSTATUS status;
	UNICODE_STRING valName;

	InitializeObjectAttributes (&regObjAttribs, keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey (&regKeyHandle, KEY_READ | KEY_WRITE, &regObjAttribs);
	if (!NT_SUCCESS (status))
		return status;

	RtlInitUnicodeString (&valName, keyValueName);

	status = ZwSetValueKey (regKeyHandle, &valName, 0, keyValueType, valueData, valueSize);

	ZwClose (regKeyHandle);
	return status;
}


BOOL IsVolumeClassFilterRegistered ()
{
	UNICODE_STRING name;
	NTSTATUS status;
	BOOL registered = FALSE;

	PKEY_VALUE_PARTIAL_INFORMATION data;

	RtlInitUnicodeString (&name, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
	status = TCReadRegistryKey (&name, L"UpperFilters", &data);

	if (NT_SUCCESS (status))
	{
		if (data->Type == REG_MULTI_SZ && data->DataLength >= 9 * sizeof (wchar_t))
		{
			// Search for the string "veracrypt"
			ULONG i;
			for (i = 0; i <= data->DataLength - 9 * sizeof (wchar_t); ++i)
			{
				if (memcmp (data->Data + i, L"veracrypt", 9 * sizeof (wchar_t)) == 0)
				{
					Dump ("Volume class filter active\n");
					registered = TRUE;
					break;
				}
			}
		}

		TCfree (data);
	}

	return registered;
}


NTSTATUS ReadRegistryConfigFlags (BOOL driverEntry)
{
	PKEY_VALUE_PARTIAL_INFORMATION data;
	UNICODE_STRING name;
	NTSTATUS status;
	uint32 flags = 0;

	RtlInitUnicodeString (&name, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\veracrypt");
	status = TCReadRegistryKey (&name, TC_DRIVER_CONFIG_REG_VALUE_NAME, &data);

	if (NT_SUCCESS (status))
	{
		if (data->Type == REG_DWORD)
		{
			flags = *(uint32 *) data->Data;
			Dump ("Configuration flags = 0x%x\n", flags);

			if (driverEntry)
			{
				if (flags & (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD | TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES))
					CacheBootPassword = TRUE;

				if (flags & TC_DRIVER_CONFIG_DISABLE_NONADMIN_SYS_FAVORITES_ACCESS)
					NonAdminSystemFavoritesAccessDisabled = TRUE;

				if (flags & TC_DRIVER_CONFIG_CACHE_BOOT_PIM)
					CacheBootPim = TRUE;
			}

			EnableHwEncryption ((flags & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION) ? FALSE : TRUE);

			EnableExtendedIoctlSupport = (flags & TC_DRIVER_CONFIG_ENABLE_EXTENDED_IOCTL)? TRUE : FALSE;
		}
		else
			status = STATUS_INVALID_PARAMETER;

		TCfree (data);
	}

	if (driverEntry && NT_SUCCESS (TCReadRegistryKey (&name, TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, &data)))
	{
		if (data->Type == REG_DWORD)
			EncryptionThreadPoolFreeCpuCountLimit = *(uint32 *) data->Data;

		TCfree (data);
	}

	return status;
}


NTSTATUS WriteRegistryConfigFlags (uint32 flags)
{
	UNICODE_STRING name;
	RtlInitUnicodeString (&name, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\veracrypt");

	return TCWriteRegistryKey (&name, TC_DRIVER_CONFIG_REG_VALUE_NAME, REG_DWORD, &flags, sizeof (flags));
}


NTSTATUS GetDeviceSectorSize (PDEVICE_OBJECT deviceObject, ULONG *bytesPerSector)
{
	NTSTATUS status;
	DISK_GEOMETRY_EX geometry;

	status = SendDeviceIoControlRequest (deviceObject, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geometry, sizeof (geometry));

	if (!NT_SUCCESS (status))
		return status;

	*bytesPerSector = geometry.Geometry.BytesPerSector;
	return STATUS_SUCCESS;
}


NTSTATUS ZeroUnreadableSectors (PDEVICE_OBJECT deviceObject, LARGE_INTEGER startOffset, ULONG size, uint64 *zeroedSectorCount)
{
	NTSTATUS status;
	ULONG sectorSize;
	ULONG sectorCount;
	byte *sectorBuffer = NULL;

	*zeroedSectorCount = 0;

	status = GetDeviceSectorSize (deviceObject, &sectorSize);
	if (!NT_SUCCESS (status))
		return status;

	sectorBuffer = TCalloc (sectorSize);
	if (!sectorBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	for (sectorCount = size / sectorSize; sectorCount > 0; --sectorCount, startOffset.QuadPart += sectorSize)
	{
		status = TCReadDevice (deviceObject, sectorBuffer, startOffset, sectorSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("Zeroing sector at %I64d\n", startOffset.QuadPart);
			memset (sectorBuffer, 0, sectorSize);

			status = TCWriteDevice (deviceObject, sectorBuffer, startOffset, sectorSize);
			if (!NT_SUCCESS (status))
				goto err;

			++(*zeroedSectorCount);
		}
	}

	status = STATUS_SUCCESS;

err:
	if (sectorBuffer)
		TCfree (sectorBuffer);

	return status;
}


NTSTATUS ReadDeviceSkipUnreadableSectors (PDEVICE_OBJECT deviceObject, byte *buffer, LARGE_INTEGER startOffset, ULONG size, uint64 *badSectorCount)
{
	NTSTATUS status;
	ULONG sectorSize;
	ULONG sectorCount;

	*badSectorCount = 0;

	status = GetDeviceSectorSize (deviceObject, &sectorSize);
	if (!NT_SUCCESS (status))
		return status;

	for (sectorCount = size / sectorSize; sectorCount > 0; --sectorCount, startOffset.QuadPart += sectorSize, buffer += sectorSize)
	{
		status = TCReadDevice (deviceObject, buffer, startOffset, sectorSize);
		if (!NT_SUCCESS (status))
		{
			Dump ("Skipping bad sector at %I64d\n", startOffset.QuadPart);
			memset (buffer, 0, sectorSize);
			++(*badSectorCount);
		}
	}

	return STATUS_SUCCESS;
}


BOOL IsVolumeAccessibleByCurrentUser (PEXTENSION volumeDeviceExtension)
{
	SECURITY_SUBJECT_CONTEXT subContext;
	PACCESS_TOKEN accessToken;
	PTOKEN_USER tokenUser;
	BOOL result = FALSE;

	if (IoIsSystemThread (PsGetCurrentThread())
		|| UserCanAccessDriveDevice()
		|| !volumeDeviceExtension->UserSid
		|| (volumeDeviceExtension->SystemFavorite && !NonAdminSystemFavoritesAccessDisabled))
	{
		return TRUE;
	}

	SeCaptureSubjectContext (&subContext);
	SeLockSubjectContext(&subContext);
	if (subContext.ClientToken && subContext.ImpersonationLevel >= SecurityImpersonation)
		accessToken = subContext.ClientToken;
	else
		accessToken = subContext.PrimaryToken;

	if (!accessToken)
		goto ret;

	if (SeTokenIsAdmin (accessToken))
	{
		result = TRUE;
		goto ret;
	}

	if (!NT_SUCCESS (SeQueryInformationToken (accessToken, TokenUser, &tokenUser)))
		goto ret;

	result = RtlEqualSid (volumeDeviceExtension->UserSid, tokenUser->User.Sid);
	ExFreePool (tokenUser);		// Documented in newer versions of WDK

ret:
	SeUnlockSubjectContext(&subContext);
	SeReleaseSubjectContext (&subContext);
	return result;
}


void GetElapsedTimeInit (LARGE_INTEGER *lastPerfCounter)
{
	*lastPerfCounter = KeQueryPerformanceCounter (NULL);
}


// Returns elapsed time in microseconds since last call
int64 GetElapsedTime (LARGE_INTEGER *lastPerfCounter)
{
	LARGE_INTEGER freq;
	LARGE_INTEGER counter = KeQueryPerformanceCounter (&freq);

	int64 elapsed = (counter.QuadPart - lastPerfCounter->QuadPart) * 1000000LL / freq.QuadPart;
	*lastPerfCounter = counter;

	return elapsed;
}


BOOL IsOSAtLeast (OSVersionEnum reqMinOS)
{
	/* When updating this function, update IsOSVersionAtLeast() in Dlgcode.c too. */

	ULONG major = 0, minor = 0;

	ASSERT (OsMajorVersion != 0);

	switch (reqMinOS)
	{
	case WIN_2000:			major = 5; minor = 0; break;
	case WIN_XP:			major = 5; minor = 1; break;
	case WIN_SERVER_2003:	major = 5; minor = 2; break;
	case WIN_VISTA:			major = 6; minor = 0; break;
	case WIN_7:				major = 6; minor = 1; break;
	case WIN_8:				major = 6; minor = 2; break;
	case WIN_8_1:			major = 6; minor = 3; break;
	case WIN_10:			major = 10; minor = 0; break;

	default:
		TC_THROW_FATAL_EXCEPTION;
		break;
	}

	return ((OsMajorVersion << 16 | OsMinorVersion << 8)
		>= (major << 16 | minor << 8));
}

NTSTATUS NTAPI KeSaveExtendedProcessorState (
    __in ULONG64 Mask,
    PXSTATE_SAVE XStateSave
    )
{
	if (KeSaveExtendedProcessorStatePtr)
	{
		return (KeSaveExtendedProcessorStatePtr) (Mask, XStateSave);
	}
	else
	{
		return STATUS_SUCCESS;
	}
}

VOID NTAPI KeRestoreExtendedProcessorState (
	PXSTATE_SAVE XStateSave
	)
{
	if (KeRestoreExtendedProcessorStatePtr)
	{
		(KeRestoreExtendedProcessorStatePtr) (XStateSave);
	}
}