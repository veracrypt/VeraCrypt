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

#include "BootConfig.h"

byte BootSectorFlags;

byte BootLoaderDrive;
byte BootDrive;
bool BootDriveGeometryValid = false;
bool PreventNormalSystemBoot = false;
bool PreventBootMenu = false;
char CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
uint32 OuterVolumeBackupHeaderCrc;

bool BootStarted = false;

DriveGeometry BootDriveGeometry;

CRYPTO_INFO *BootCryptoInfo;
Partition EncryptedVirtualPartition;

Partition ActivePartition;
Partition PartitionFollowingActive;
bool ExtraBootPartitionPresent = false;
uint64 PimValueOrHiddenVolumeStartUnitNo; // reuse this variable for stored PIM value to reduce memory usage
uint64 HiddenVolumeStartSector;

#ifndef TC_WINDOWS_BOOT_RESCUE_DISK_MODE

void ReadBootSectorUserConfiguration ()
{
	byte userConfig;

	AcquireSectorBuffer();

	if (ReadWriteMBR (false, BootLoaderDrive, true) != BiosResultSuccess)
		goto ret;

	userConfig = SectorBuffer[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];

#ifdef TC_WINDOWS_BOOT_AES
	EnableHwEncryption (!(userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_HW_ENCRYPTION));
#endif

	PreventBootMenu = (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_ESC);

	memcpy (CustomUserMessage, SectorBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
	CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH] = 0;

	if (userConfig & TC_BOOT_USER_CFG_FLAG_SILENT_MODE)
	{
		if (CustomUserMessage[0])
		{
			InitVideoMode();
			Print (CustomUserMessage);
		}

		DisableScreenOutput();
	}

	if (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM)
	{
		PimValueOrHiddenVolumeStartUnitNo.LowPart = 0;
		memcpy (&PimValueOrHiddenVolumeStartUnitNo.LowPart, SectorBuffer + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, TC_BOOT_SECTOR_PIM_VALUE_SIZE);
	}
	else
		PimValueOrHiddenVolumeStartUnitNo.LowPart = -1;

	OuterVolumeBackupHeaderCrc = *(uint32 *) (SectorBuffer + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET);

ret:
	ReleaseSectorBuffer();
}


BiosResult UpdateBootSectorConfiguration (byte drive)
{
	uint64 mbrSector;
	mbrSector.HighPart = 0;
	mbrSector.LowPart = 0;

	AcquireSectorBuffer();
/*
	BiosResult result = ReadWriteMBR (false, drive);
	if (result != BiosResultSuccess)
		goto ret;

	SectorBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET] = BootSectorFlags;
	result = ReadWriteMBR (true, drive);
*/

	BiosResult result = ReadWriteSectors (false, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, mbrSector, 8, false);
	if (result != BiosResultSuccess)
		goto ret;

	CopyMemory (TC_BOOT_LOADER_BUFFER_SEGMENT, 0, SectorBuffer, TC_LB_SIZE);
	SectorBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET] = BootSectorFlags;
	CopyMemory (SectorBuffer, TC_BOOT_LOADER_BUFFER_SEGMENT,0, TC_LB_SIZE);

	result = ReadWriteSectors (true, TC_BOOT_LOADER_BUFFER_SEGMENT, 0, drive, mbrSector, 8, false);

ret:
	ReleaseSectorBuffer();
	return result;
}

#endif // !TC_WINDOWS_BOOT_RESCUE_DISK_MODE
