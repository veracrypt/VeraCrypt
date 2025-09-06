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

#include "DumpFilter.h"
#include "DriveFilter.h"
#include "Ntdriver.h"
#include "Tests.h"
#include "cpu.h"

typedef struct _DumpFilterContext
{
	DriveFilterExtension* BootDriveFilterExtension;
	LARGE_INTEGER DumpPartitionOffset;
	uint8* WriteFilterBuffer;
	SIZE_T WriteFilterBufferSize;
	PMDL WriteFilterBufferMdl;
} DumpFilterContext;

// In crash/hibernate paths, execution can be at HIGH_LEVEL and many memory manager
// DDIs are illegal (documented as IRQL <= DISPATCH_LEVEL). The dump stack expects
// a filter to be mostly passive: supply physical pages and avoid mapping/locking.
// We therefore pre-build an MDL for a private nonpaged scratch buffer at init time
// and, at write time we ONLY swap PFNs into the caller's MDL. We do not call:
//   - MmInitializeMdl
//   - MmBuildMdlForNonPagedPool
//   - MmGetSystemAddressForMdlSafe
//

static void Cleanup(DumpFilterContext* dumpContext)
{
	if (!dumpContext)
		return;

	if (dumpContext->WriteFilterBufferMdl)
	{
		IoFreeMdl(dumpContext->WriteFilterBufferMdl);
	}

	if (dumpContext->WriteFilterBuffer)
	{
		RtlSecureZeroMemory(dumpContext->WriteFilterBuffer, dumpContext->WriteFilterBufferSize);
		MmFreeContiguousMemory(dumpContext->WriteFilterBuffer);
	}

	RtlSecureZeroMemory(dumpContext, sizeof(DumpFilterContext));
	TCfree(dumpContext);
}

NTSTATUS DumpFilterEntry (PFILTER_EXTENSION filterExtension, PFILTER_INITIALIZATION_DATA filterInitData)
{
	GetSystemDriveDumpConfigRequest dumpConfig;
	PHYSICAL_ADDRESS lowestAcceptableWriteBufferAddr;
	PHYSICAL_ADDRESS highestAcceptableWriteBufferAddr;
	PHYSICAL_ADDRESS highestAcceptableBoundaryWriteBufferAddr;
	STORAGE_DEVICE_NUMBER storageDeviceNumber;
	PARTITION_INFORMATION partitionInfo;
	LONG version;
	NTSTATUS status;

	Dump ("DumpFilterEntry type=%d\n", filterExtension->DumpType);

	filterInitData->MajorVersion = DUMP_FILTER_MAJOR_VERSION;
	filterInitData->MinorVersion = DUMP_FILTER_MINOR_VERSION;
	filterInitData->Flags |= DUMP_FILTER_CRITICAL;

	DumpFilterContext* dumpContext = TCalloc ( sizeof (DumpFilterContext));
	
	if (!dumpContext)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto err;
	}
	
	memset (dumpContext, 0, sizeof (DumpFilterContext));

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

	dumpContext->BootDriveFilterExtension = dumpConfig.BootDriveFilterExtension;

	if (dumpContext->BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
	{
		status = STATUS_CRC_ERROR;
		goto err;
	}


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

	if (!dumpContext->BootDriveFilterExtension->SystemStorageDeviceNumberValid)
	{
		status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	if (storageDeviceNumber.DeviceNumber != dumpContext->BootDriveFilterExtension->SystemStorageDeviceNumber)
	{
		status = STATUS_ACCESS_DENIED;
		goto err;
	}

	// Check dump volume is located within the scope of system encryption
	status = SendDeviceIoControlRequest (filterExtension->DeviceObject, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &partitionInfo, sizeof (partitionInfo));
	if (!NT_SUCCESS (status))
	{
		PARTITION_INFORMATION_EX partitionInfoEx;
		status = SendDeviceIoControlRequest (filterExtension->DeviceObject, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partitionInfoEx, sizeof (partitionInfoEx));
		if (!NT_SUCCESS (status))
		{
			goto err;
		}

		// we only need starting offset
		partitionInfo.StartingOffset = partitionInfoEx.StartingOffset;
	}

	dumpContext->DumpPartitionOffset = partitionInfo.StartingOffset;

	if (dumpContext->DumpPartitionOffset.QuadPart < dumpContext->BootDriveFilterExtension->ConfiguredEncryptedAreaStart
		|| dumpContext->DumpPartitionOffset.QuadPart > dumpContext->BootDriveFilterExtension->ConfiguredEncryptedAreaEnd)
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

	dumpContext->WriteFilterBufferSize = ((SIZE_T)filterInitData->MaxPagesPerWrite) * PAGE_SIZE;

	lowestAcceptableWriteBufferAddr.QuadPart = 0;
	//
	// Historical behavior: allocate below 0x7FFFFFFFFFF (old driver cap).
	// Some storage stacks in dump context behaved better with lower PFNs.
	// Try conservative cap first, then fall back to no cap if needed.
	highestAcceptableWriteBufferAddr.QuadPart = 0x7FFFFFFFFFFLL;
	highestAcceptableBoundaryWriteBufferAddr.QuadPart = 0;

	// Allocate resident scratch buffer as READ/WRITE only and contiguous.
	dumpContext->WriteFilterBuffer = MmAllocateContiguousNodeMemory(
		dumpContext->WriteFilterBufferSize,
		lowestAcceptableWriteBufferAddr,
		highestAcceptableWriteBufferAddr,
		highestAcceptableBoundaryWriteBufferAddr,
		PAGE_READWRITE,
		MM_ANY_NODE_OK);

	if (!dumpContext->WriteFilterBuffer)
	{
		// Fallback: lift the cap if the conservative allocation failed.
		highestAcceptableWriteBufferAddr.QuadPart = (LONGLONG)-1; // QWORD_MAX
		dumpContext->WriteFilterBuffer = MmAllocateContiguousNodeMemory(
			dumpContext->WriteFilterBufferSize,
			lowestAcceptableWriteBufferAddr,
			highestAcceptableWriteBufferAddr,
			highestAcceptableBoundaryWriteBufferAddr,
			PAGE_READWRITE,
			MM_ANY_NODE_OK);
	}
	if (!dumpContext->WriteFilterBuffer)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto err;
	}

	dumpContext->WriteFilterBufferMdl = IoAllocateMdl (dumpContext->WriteFilterBuffer, (ULONG)dumpContext->WriteFilterBufferSize, FALSE, FALSE, NULL);
	
	if (!dumpContext->WriteFilterBufferMdl)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto err;
	}

	MmBuildMdlForNonPagedPool (dumpContext->WriteFilterBufferMdl);

	filterInitData->DumpStart = DumpFilterStart;
	filterInitData->DumpWrite = DumpFilterWrite;
	filterInitData->DumpFinish = DumpFilterFinish;
	filterInitData->DumpUnload = DumpFilterUnload;
	filterInitData->DumpData = dumpContext;

	Dump ("Dump filter loaded type=%d\n", filterExtension->DumpType);
	return STATUS_SUCCESS;

err:
	Dump ("DumpFilterEntry error %x\n", status);
	Cleanup (dumpContext);
	return status;
}


static NTSTATUS DumpFilterStart (PFILTER_EXTENSION filterExtension)
{
	Dump ("DumpFilterStart type=%d\n", filterExtension->DumpType);

	DumpFilterContext* dumpContext = filterExtension->DumpData;

	if (dumpContext->BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
		TC_BUG_CHECK (STATUS_CRC_ERROR);

	return dumpContext->BootDriveFilterExtension->DriveMounted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


static NTSTATUS DumpFilterWrite (PFILTER_EXTENSION filterExtension, PLARGE_INTEGER diskWriteOffset, PMDL writeMdl)
{
	DumpFilterContext* dumpContext = filterExtension->DumpData;
	ULONG dataLength = MmGetMdlByteCount (writeMdl);
	uint64 offset = dumpContext->DumpPartitionOffset.QuadPart + diskWriteOffset->QuadPart;
	uint64 intersectStart;
	uint32 intersectLength;
	PVOID writeBuffer;

	if (dumpContext->BootDriveFilterExtension->MagicNumber != TC_BOOT_DRIVE_FILTER_EXTENSION_MAGIC_NUMBER)
		TC_BUG_CHECK (STATUS_CRC_ERROR);

	if (dumpContext->BootDriveFilterExtension->Queue.EncryptedAreaEndUpdatePending)	// Hibernation should always abort the setup thread
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if (dumpContext->BootDriveFilterExtension->Queue.EncryptedAreaStart == -1 || dumpContext->BootDriveFilterExtension->Queue.EncryptedAreaEnd == -1)
		return STATUS_SUCCESS;

	if (dataLength > dumpContext->WriteFilterBufferSize)
		TC_BUG_CHECK (STATUS_BUFFER_OVERFLOW);	// Bug check is required as returning an error does not prevent data from being written to disk

	if ((dataLength & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	if ((offset & (ENCRYPTION_DATA_UNIT_SIZE - 1)) != 0)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	// Require either a valid mapping or a nonpaged system VA we can read at HIGH_LEVEL.
	if ((writeMdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) == 0)
		TC_BUG_CHECK(STATUS_INVALID_PARAMETER);

	writeBuffer = MmGetMdlVirtualAddress (writeMdl);
	if (!writeBuffer)
		TC_BUG_CHECK (STATUS_INVALID_PARAMETER);

	memcpy (dumpContext->WriteFilterBuffer, writeBuffer, dataLength);

	GetIntersection (offset,
		dataLength,
		dumpContext->BootDriveFilterExtension->Queue.EncryptedAreaStart,
		dumpContext->BootDriveFilterExtension->Queue.EncryptedAreaEnd,
		&intersectStart,
		&intersectLength);

	if (intersectLength > 0)
	{
		UINT64_STRUCT dataUnit;
		dataUnit.Value = intersectStart / ENCRYPTION_DATA_UNIT_SIZE;

		if (dumpContext->BootDriveFilterExtension->Queue.RemapEncryptedArea)
		{
			diskWriteOffset->QuadPart += dumpContext->BootDriveFilterExtension->Queue.RemappedAreaOffset;
			dataUnit.Value += dumpContext->BootDriveFilterExtension->Queue.RemappedAreaDataUnitOffset;
		}

		EncryptDataUnitsCurrentThreadEx (dumpContext->WriteFilterBuffer + (intersectStart - offset),
			&dataUnit,
			intersectLength / ENCRYPTION_DATA_UNIT_SIZE,
			dumpContext->BootDriveFilterExtension->Queue.CryptoInfo);
	}

	//
	// Intercept the write: data is now encrypted in our scratch buffer.
	// We re-point the caller's MDL to our pages by copying PFNs from our
	// pre-built MDL. We cannot call MmBuildMdlForNonPagedPool here
	// (forbidden at HIGH_LEVEL).

	// Get pointers to the Page Frame Number (PFN) arrays for both MDLs.
	PPFN_NUMBER dstPfnArray = MmGetMdlPfnArray(writeMdl);
	PPFN_NUMBER srcPfnArray = MmGetMdlPfnArray(dumpContext->WriteFilterBufferMdl);

	// Number of PFNs required to describe the DESTINATION MDL’s span.
	// Using the dest MDL avoids subtle off-by-one/unaligned cases.
	ULONG dstPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
		MmGetMdlVirtualAddress(writeMdl),
		MmGetMdlByteCount(writeMdl));

	// Total PFN capacity available in our SCRATCH MDL.
	ULONG srcCapacityPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
		MmGetMdlVirtualAddress(dumpContext->WriteFilterBufferMdl),
		MmGetMdlByteCount(dumpContext->WriteFilterBufferMdl));

	// Sanity: scratch must be large enough to back this I/O.
	if (dstPages > srcCapacityPages)
		TC_BUG_CHECK(STATUS_BUFFER_TOO_SMALL);

	// Copy exactly the PFNs required by the destination MDL’s span.
	RtlCopyMemory(dstPfnArray, srcPfnArray, dstPages * sizeof(PFN_NUMBER));

	//
	// Retarget MDL header fields to match the PFNs we just supplied.
	// NOTE: We intentionally don't modify MdlFlags.
	// This preserves the historical quirk where fields describe a
	// nonpaged/system VA while flags may not advertise a mapping.
	// Several lower stacks have relied on this behavior for years.
	//
	writeMdl->StartVa        = dumpContext->WriteFilterBufferMdl->StartVa;
	writeMdl->ByteOffset     = dumpContext->WriteFilterBufferMdl->ByteOffset;
	writeMdl->MappedSystemVa = dumpContext->WriteFilterBufferMdl->MappedSystemVa;

	return STATUS_SUCCESS;
}


static NTSTATUS DumpFilterFinish (PFILTER_EXTENSION filterExtension)
{
	UNREFERENCED_PARAMETER(filterExtension);
	Dump ("DumpFilterFinish type=%d\n", filterExtension->DumpType);

	return STATUS_SUCCESS;
}


static NTSTATUS DumpFilterUnload (PFILTER_EXTENSION filterExtension)
{
	Dump ("DumpFilterUnload type=%d\n", filterExtension->DumpType);

	DumpFilterContext* dumpContext = filterExtension->DumpData;
	
	// Defensive: in normal flow DumpData is set. We tolerate NULL to be safe.
	if (dumpContext) {
		Cleanup (dumpContext);
		filterExtension->DumpData = NULL;
	}

	return STATUS_SUCCESS;
}
