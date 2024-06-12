/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Crypto.h"
#include "Platform.h"
#include "BootConfig.h"
#include "BootDebug.h"
#include "BootDefs.h"
#include "BootDiskIo.h"
#include "BootEncryptedIo.h"


BiosResult ReadEncryptedSectors (uint16 destSegment, uint16 destOffset, uint8 drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result;
	bool decrypt = true;

	if (BootCryptoInfo->hiddenVolume)
	{
		if (ReadWritePartiallyCoversEncryptedArea (sector, sectorCount))
			return BiosResultInvalidFunction;

		if (sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
		{
			// Remap the request to the hidden volume
			sector -= EncryptedVirtualPartition.StartSector;
			sector += HiddenVolumeStartSector;
		}
		else
			decrypt = false;
	}

	result = ReadSectors (destSegment, destOffset, drive, sector, sectorCount);

	if (result != BiosResultSuccess || !decrypt)
		return result;

	if (BootCryptoInfo->hiddenVolume)
	{
		// Convert sector number to data unit number of the hidden volume
		sector -= HiddenVolumeStartSector;
		sector += PimValueOrHiddenVolumeStartUnitNo;
	}

	if (drive == EncryptedVirtualPartition.Drive)
	{
		while (sectorCount-- > 0)
		{
			if (BootCryptoInfo->hiddenVolume
				|| (sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector))
			{
				AcquireSectorBuffer();
				CopyMemory (destSegment, destOffset, SectorBuffer, TC_LB_SIZE);

				DecryptDataUnits (SectorBuffer, &sector, 1, BootCryptoInfo);

				CopyMemory (SectorBuffer, destSegment, destOffset, TC_LB_SIZE);
				ReleaseSectorBuffer();
			}

			++sector;
			destOffset += TC_LB_SIZE;
		}
	}

	return result;
}


BiosResult WriteEncryptedSectors (uint16 sourceSegment, uint16 sourceOffset, uint8 drive, uint64 sector, uint16 sectorCount)
{
	BiosResult result = BiosResultSuccess;
	AcquireSectorBuffer();
	uint64 dataUnitNo;
	uint64 writeOffset;

	dataUnitNo = sector;
	writeOffset.HighPart = 0;
	writeOffset.LowPart = 0;

	if (BootCryptoInfo->hiddenVolume)
	{
		if (ReadWritePartiallyCoversEncryptedArea (sector, sectorCount))
			return BiosResultInvalidFunction;

		// Remap the request to the hidden volume
		writeOffset = HiddenVolumeStartSector;
		writeOffset -= EncryptedVirtualPartition.StartSector;
		dataUnitNo -= EncryptedVirtualPartition.StartSector;
		dataUnitNo += PimValueOrHiddenVolumeStartUnitNo;
	}

	while (sectorCount-- > 0)
	{
		CopyMemory (sourceSegment, sourceOffset, SectorBuffer, TC_LB_SIZE);

		if (drive == EncryptedVirtualPartition.Drive && sector >= EncryptedVirtualPartition.StartSector && sector <= EncryptedVirtualPartition.EndSector)
		{
			EncryptDataUnits (SectorBuffer, &dataUnitNo, 1, BootCryptoInfo);
		}

		result = ReadWriteSectors (true, SectorBuffer, drive, sector + writeOffset, 1, true);
		if (BiosResultTimeout == result)
		{
			if (BiosResultSuccess == ReadWriteSectors (false, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, sector + writeOffset, 8, false))
			{
				CopyMemory (SectorBuffer, TC_BOOT_LOADER_BUFFER_SEGMENT,0, TC_LB_SIZE);
				result = ReadWriteSectors (true, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, sector + writeOffset, 8, true);
			}
		}

		if (result != BiosResultSuccess)
		{
			sector += writeOffset;
			PrintDiskError (result, true, drive, &sector);
			break;
		}

		++sector;
		++dataUnitNo;
		sourceOffset += TC_LB_SIZE;
	}

	ReleaseSectorBuffer();
	return result;
}


static bool ReadWritePartiallyCoversEncryptedArea (const uint64 &sector, uint16 sectorCount)
{
	uint64 readWriteEnd = sector + --sectorCount;

	return ((sector < EncryptedVirtualPartition.StartSector && readWriteEnd >= EncryptedVirtualPartition.StartSector)
		|| (sector >= EncryptedVirtualPartition.StartSector && readWriteEnd > EncryptedVirtualPartition.EndSector));
}
