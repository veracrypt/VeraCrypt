/*
 Copyright (c) 2008-2011 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "TCdefs.h"
#include "Ntdriver.h"
#include "Ntvol.h"
#include "DriveFilter.h"
#include "VolumeFilter.h"

typedef DriveFilterExtension VolumeFilterExtension;

// Number of times the filter driver answered that an unencrypted volume
// is read-only (or mounted an outer/normal TrueCrypt volume as read only)
uint32 HiddenSysLeakProtectionCount = 0;


NTSTATUS VolumeFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo)
{
	VolumeFilterExtension *Extension;
	NTSTATUS status;
	PDEVICE_OBJECT filterDeviceObject = NULL;
	PDEVICE_OBJECT attachedDeviceObject;

	Dump ("VolumeFilterAddDevice pdo=%p\n", pdo);

	attachedDeviceObject = IoGetAttachedDeviceReference (pdo);
	status = IoCreateDevice (driverObject, sizeof (VolumeFilterExtension), NULL, attachedDeviceObject->DeviceType, 0, FALSE, &filterDeviceObject);

	ObDereferenceObject (attachedDeviceObject);

	if (!NT_SUCCESS (status))
	{
		filterDeviceObject = NULL;
		goto err;
	}

	Extension = (VolumeFilterExtension *) filterDeviceObject->DeviceExtension;
	memset (Extension, 0, sizeof (VolumeFilterExtension));

	Extension->LowerDeviceObject = IoAttachDeviceToDeviceStack (filterDeviceObject, pdo);  // IoAttachDeviceToDeviceStackSafe() is not required in AddDevice routine and is also unavailable on Windows 2000 SP4
	if (!Extension->LowerDeviceObject)
	{
		status = STATUS_DEVICE_REMOVED;
		goto err;
	}
	
	Extension->IsVolumeFilterDevice = TRUE;
	Extension->DeviceObject = filterDeviceObject;
	Extension->Pdo = pdo;

	IoInitializeRemoveLock (&Extension->Queue.RemoveLock, 'LRCT', 0, 0);

	filterDeviceObject->Flags |= Extension->LowerDeviceObject->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);
	filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;

err:
	if (filterDeviceObject)
	{
		if (Extension->LowerDeviceObject)
			IoDetachDevice (Extension->LowerDeviceObject);

		IoDeleteDevice (filterDeviceObject);
	}

	return status;
}


static NTSTATUS PassIrp (PDEVICE_OBJECT deviceObject, PIRP irp)
{
	IoSkipCurrentIrpStackLocation (irp);
	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS PassFilteredIrp (PDEVICE_OBJECT deviceObject, PIRP irp, PIO_COMPLETION_ROUTINE completionRoutine, PVOID completionRoutineArg)
{
	IoCopyCurrentIrpStackLocationToNext (irp);

	if (completionRoutine)
		IoSetCompletionRoutine (irp, completionRoutine, completionRoutineArg, TRUE, TRUE, TRUE);

	return IoCallDriver (deviceObject, irp);
}


static NTSTATUS OnDeviceUsageNotificationCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, VolumeFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (!(Extension->LowerDeviceObject->Flags & DO_POWER_PAGABLE))
		filterDeviceObject->Flags &= ~DO_POWER_PAGABLE;

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static NTSTATUS OnStartDeviceCompleted (PDEVICE_OBJECT filterDeviceObject, PIRP Irp, VolumeFilterExtension *Extension)
{
	if (Irp->PendingReturned)
		IoMarkIrpPending (Irp);

	if (Extension->LowerDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
		filterDeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return STATUS_CONTINUE_COMPLETION;
}


static NTSTATUS DispatchControl (PDEVICE_OBJECT DeviceObject, PIRP Irp, VolumeFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	if (IsHiddenSystemRunning())
	{
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_DISK_IS_WRITABLE:
			{
				// All volumes except the system volume must be read-only

				DriveFilterExtension *bootDriveExtension = GetBootDriveFilterExtension();
				STORAGE_DEVICE_NUMBER storageDeviceNumber;

				if (!bootDriveExtension->SystemStorageDeviceNumberValid)
					TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

				status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &storageDeviceNumber, sizeof (storageDeviceNumber));

				if (NT_SUCCESS (status) && bootDriveExtension->SystemStorageDeviceNumber == storageDeviceNumber.DeviceNumber)
				{
					PARTITION_INFORMATION_EX partition;
					status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partition, sizeof (partition));

					if (NT_SUCCESS (status) && partition.StartingOffset.QuadPart == bootDriveExtension->ConfiguredEncryptedAreaStart)
					{
						IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
						return TCCompleteDiskIrp (Irp, STATUS_SUCCESS, 0);
					}
				}

				IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);

				++HiddenSysLeakProtectionCount;
				return TCCompleteDiskIrp (Irp, STATUS_MEDIA_WRITE_PROTECTED, 0);
			}

		case TC_IOCTL_DISK_IS_WRITABLE:
			Dump ("TC_IOCTL_DISK_IS_WRITABLE pdo=%p\n", Extension->Pdo);

			if (!ProbingHostDeviceForWrite)
				break;

			// Probe the real state of the device as the user is mounting a TrueCrypt volume.

			// Volume filter may be attached to a merged drive+volume PDO. First test if TC_IOCTL_DISK_IS_WRITABLE works for the underlying device.
			status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, TC_IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0);

			if (NT_SUCCESS (status) || status == STATUS_MEDIA_WRITE_PROTECTED)
			{
				IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
				return TCCompleteDiskIrp (Irp, status, 0);
			}

			status = SendDeviceIoControlRequest (Extension->LowerDeviceObject, IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0);

			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
			return TCCompleteDiskIrp (Irp, status, 0);

		case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:

			// Filter IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES to enable potential future use of hidden systems on drives that use the trim operation but not wear-leveling (if any appear in future). The documentation forbids users to create hidden volumes/systems on drives that use wear-leveling and consequently also on drives that use trim (as trim is used only by drives that use wear-leveling, as of 2010).

			IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
			return TCCompleteDiskIrp (Irp, STATUS_SUCCESS, 0);
		}
	}

	status = PassIrp (Extension->LowerDeviceObject, Irp);
	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}


static NTSTATUS DispatchPnp (PDEVICE_OBJECT DeviceObject, PIRP Irp, VolumeFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	switch (irpSp->MinorFunction)
	{
	case IRP_MN_START_DEVICE:
		Dump ("IRP_MN_START_DEVICE volume pdo=%p\n", Extension->Pdo);
		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnStartDeviceCompleted, Extension);

	case IRP_MN_DEVICE_USAGE_NOTIFICATION:
		{
			PDEVICE_OBJECT attachedDevice = IoGetAttachedDeviceReference (DeviceObject);

			if (attachedDevice == DeviceObject || (attachedDevice->Flags & DO_POWER_PAGABLE))
				DeviceObject->Flags |= DO_POWER_PAGABLE;

			ObDereferenceObject (attachedDevice);
		}

		return PassFilteredIrp (Extension->LowerDeviceObject, Irp, OnDeviceUsageNotificationCompleted, Extension);


	case IRP_MN_REMOVE_DEVICE:
		Dump ("IRP_MN_REMOVE_DEVICE volume pdo=%p\n", Extension->Pdo);

		IoReleaseRemoveLockAndWait (&Extension->Queue.RemoveLock, Irp);
		status = PassIrp (Extension->LowerDeviceObject, Irp);

		IoDetachDevice (Extension->LowerDeviceObject);

		IoDeleteDevice (DeviceObject);
		return status;

	default:
		status = PassIrp (Extension->LowerDeviceObject, Irp);
		IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	}

	return status;
}


static NTSTATUS DispatchPower (PDEVICE_OBJECT DeviceObject, PIRP Irp, VolumeFilterExtension *Extension, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;
	PoStartNextPowerIrp (Irp);

	status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
	if (!NT_SUCCESS (status))
		return TCCompleteIrp (Irp, status, 0);

	IoSkipCurrentIrpStackLocation (Irp);
	status = PoCallDriver (Extension->LowerDeviceObject, Irp);

	IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
	return status;
}


NTSTATUS VolumeFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	VolumeFilterExtension *Extension = (VolumeFilterExtension *) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation (Irp);
	NTSTATUS status;

	ASSERT (!Extension->bRootDevice && Extension->IsVolumeFilterDevice);

	switch (irpSp->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:
		return DispatchControl (DeviceObject, Irp, Extension, irpSp);

	case IRP_MJ_PNP:
		return DispatchPnp (DeviceObject, Irp, Extension, irpSp);

	case IRP_MJ_POWER:
		return DispatchPower (DeviceObject, Irp, Extension, irpSp);

	default:
		status = IoAcquireRemoveLock (&Extension->Queue.RemoveLock, Irp);
		if (!NT_SUCCESS (status))
			return TCCompleteIrp (Irp, status, 0);

		status = PassIrp (Extension->LowerDeviceObject, Irp);

		IoReleaseRemoveLock (&Extension->Queue.RemoveLock, Irp);
		return status;
	}
}
