/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "DumpFilter.h"
#include "DriveFilter.h"
#include "Ntdriver.h"
#include "Tests.h"

static DriveFilterExtension *BootDriveFilterExtension = NULL;
static LARGE_INTEGER DumpPartitionOffset;
static byte *WriteFilterBuffer = NULL;
static SIZE_T WriteFilterBufferSize;


NTSTATUS DumpFilterEntry (PFILTER_EXTENSION filterExtension, PFILTER_INITIALIZATION_DATA filterInitData)
{
	GetSystemDriveDumpConfigRequest dumpConfig;
	PHYSICAL_ADDRESS highestAcceptableWriteBufferAddr;
	STORAGE_DEVICE_NUMBER storageDeviceNumber;
	PARTITION_INFORMATION partitionInfo;
	LONG version;
	NTSTATUS status;

	Dump ("DumpFilterEntry type=%d\n", filterExtension->DumpType);

	filterInitData->MajorVersion = DUMP_FILTER_MAJOR_VERSION;
	filterInitData->MinorVersion = DUMP_FILTER_MINOR_VERSION;
	filterInitData->Flags |= DUMP_FILTER_CRITICAL;

	// Check driver version of the main device
	status = TCDeviceIoControl (NT_ROOT_PREFIX, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &version, sizeof (version));
	if (!NT_SUCCESS (status))
		goto err;

	if (version != VERSION_NUM)
	{
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	// Get dump configuration from the main device
	status = TCDeviceIoControl (NT_ROOT_PREFIX, TC_IOCTL_GET_SYSTEM_DRIVE_DUMP_CONFIG, NULL, 0, &dumpConfig, sizeof (dumpConfig));
	if (!NT_SUCCESS (status))
		goto err;

	BootDriveFilterExtension = dumpConfig.BootDriveFilterExtension;

	if (BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
	{
		status = STATUS_CRC_ERROR;
		goto err;
	}

	// KeSaveFloatingPointState() may generate a bug check during crash dump
#if !defined (_WIN64)
	if (filterExtension->DumpType == DumpTypeCrashdump)
		dumpConfig.HwEncryptionEnabled = FALSE;
#endif

	EnableHwEncryption (dumpConfig.HwEncryptionEnabled);

	if (!AutoTestAlgorithms())
	{
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	// Check dump volume is located on the system drive
	status = SendDeviceIoControlRequest (filterExtension->DeviceObject, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &storageDeviceNumber, sizeof (storageDeviceNumber));
	if (!NT_SUCCESS (status))
		goto err;

	if (!BootDriveFilterExtension->SystemStorageDeviceNumberValid)
	{
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	if (storageDeviceNumber.DeviceNumber != BootDriveFilterExtension->SystemStorageDeviceNumber)
	{
		status = STATUS_ACCESS_DENIED;
		goto err;
	}

	// Check dump volume is located within the scope of system encryption
	status = SendDeviceIoControlRequest (filterExtension->DeviceObject, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &partitionInfo, sizeof (partitionInfo));
	if (!NT_SUCCESS (status))
		goto err;

	DumpPartitionOffset = partitionInfo.StartingOffset;

	if (DumpPartitionOffset.QuadPart < BootDriveFilterExtension->ConfiguredEncryptedAreaStart
		|| DumpPartitionOffset.QuadPart > BootDriveFilterExtension->ConfiguredEncryptedAreaEnd)
	{
		status = STATUS_ACCESS_DENIED;
		goto err;
	}

	// Allocate buffer for encryption
	if (filterInitData->MaxPagesPerWrite == 0)
	{
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	WriteFilterBufferSize = filterInitData->MaxPagesPerWrite * PAGE_SIZE;

#ifdef _WIN64
	highestAcceptableWriteBufferAddr.QuadPart = 0x7FFffffFFFFLL;
#else
	highestAcceptableWriteBufferAddr.QuadPart = 0xffffFFFFLL;
#endif

	WriteFilterBuffer = MmAllocateContiguousMemory (WriteFilterBufferSize, highestAcceptableWriteBufferAddr);
	if (!WriteFilterBuffer)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto err;
	}

	filterInitData->DumpStart = DumpFilterStart;
	filterInitData->DumpWrite = DumpFilterWrite;
	filterInitData->DumpFinish = DumpFilterFinish;
	filterInitData->DumpUnload = DumpFilterUnload;

	Dump ("Dump filter loaded type=%d\n", filterExtension->DumpType);
	return STATUS_SUCCESS;

err:
	Dump ("DumpFilterEntry error %x\n", status);
	return status;
}


static NTSTATUS DumpFilterStart (PFILTER_EXTENSION filterExtension)
{
	Dump ("DumpFilterStart type=%d\n", filterExtension->DumpType);

	if (BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
		TC_BUG_CHECK (STATUS_CRC_ERROR);

	return BootDriveFilterExtension->DriveMounted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


static NTSTATUS DumpFilterWrite (PFILTER_EXTENSION filterExtension, PLARGE_INTEGER diskWriteOffset, PMDL writeMdl)
{
	ULONG dataLength = MmGetMdlByteCount (writeMdl);
	uint64 offset = DumpPartitionOffset.QuadPart + diskWriteOffset->QuadPart;
	uint64 intersectStart;
	uint32 intersectLength;
	PVOID writeBuffer;
	CSHORT origMdlFlags;

	if (BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
		TC_BUG_CHECK (STATUS_CRC_ERROR);

	if (BootDriveFilterExtension->Queue.EncryptedAreaEndUpdatePending)	// Hibernation should always abort the setup thread
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if (BootDriveFilterExtension->Queue.EncryptedAreaStart == -1 || BootDriveFilterExtension->Queue.EncryptedAreaEnd == -1)
		return STATUS_SUCCESS;

	if (dataLength > WriteFilterBufferSize)
		TC_BUG_CHECK (STATUS_BUFFER_OVERFLOW);	// Bug check is required as returning an error does not prevent data from being written to disk

	if ((dataLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if ((offset & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	writeBuffer = MmGetSystemAddressForMdlSafe (writeMdl, HighPagePriority);
	if (!writeBuffer)
		TC_BUG_CHECK (STATUS_INSUFFICIENT_RESOURCES);

	memcpy (WriteFilterBuffer, writeBuffer, dataLength);

	GetIntersection (offset,
		dataLength,
		BootDriveFilterExtension->Queue.EncryptedAreaStart,
		BootDriveFilterExtension->Queue.EncryptedAreaEnd,
		&intersectStart,
		&intersectLength);

	if (intersectLength > 0)
	{
		UINT64_STRUCT dataUnit;
		dataUnit.Value = intersectStart / ENCRYPTION_DATA_UNIT_SIZE;

		if (BootDriveFilterExtension->Queue.RemapEncryptedArea)
		{
			diskWriteOffset->QuadPart += BootDriveFilterExtension->Queue.RemappedAreaOffset;
			dataUnit.Value += BootDriveFilterExtension->Queue.RemappedAreaDataUnitOffset;
		}

		EncryptDataUnitsCurrentThread (WriteFilterBuffer + (intersectStart - offset),
			&dataUnit,
			intersectLength / ENCRYPTION_DATA_UNIT_SIZE,
			BootDriveFilterExtension->Queue.CryptoInfo);
	}

	origMdlFlags = writeMdl->MdlFlags;

	MmInitializeMdl (writeMdl, WriteFilterBuffer, dataLength);
	MmBuildMdlForNonPagedPool (writeMdl);

	// Instead of using MmGetSystemAddressForMdlSafe(), some buggy custom storage drivers may directly test MDL_MAPPED_TO_SYSTEM_VA flag,
	// disregarding the fact that other MDL flags may be set by the system or a dump filter (e.g. MDL_SOURCE_IS_NONPAGED_POOL flag only).
	// Therefore, to work around this issue, the original flags will be restored even if they do not match the new MDL.
	// MS BitLocker also uses this hack/workaround (it should be safe to use until the MDL structure is changed).

	writeMdl->MdlFlags = origMdlFlags;

	return STATUS_SUCCESS;
}


static NTSTATUS DumpFilterFinish (PFILTER_EXTENSION filterExtension)
{
	Dump ("DumpFilterFinish type=%d\n", filterExtension->DumpType);

	return STATUS_SUCCESS;
}


static NTSTATUS DumpFilterUnload (PFILTER_EXTENSION filterExtension)
{
	Dump ("DumpFilterUnload type=%d\n", filterExtension->DumpType);

	if (WriteFilterBuffer)
	{
		memset (WriteFilterBuffer, 0, WriteFilterBufferSize);
		MmFreeContiguousMemory (WriteFilterBuffer);
		WriteFilterBuffer = NULL;
	}

	return STATUS_SUCCESS;
}
