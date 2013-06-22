/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Boot_BootCommon
#define TC_HEADER_Boot_BootCommon

#include "Common/Password.h"
#include "BootDefs.h"

// The user will be advised to upgrade the rescue disk if upgrading from the following or any previous version
#define TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION 0x060a

#define TC_BOOT_LOADER_AREA_SIZE (TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)

#define TC_BOOT_VOLUME_HEADER_SECTOR (TC_BOOT_LOADER_AREA_SECTOR_COUNT - 1)
#define TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET (TC_BOOT_VOLUME_HEADER_SECTOR * TC_SECTOR_SIZE_BIOS)

#define TC_CD_BOOTSECTOR_OFFSET 0xd000
#define TC_CD_BOOT_LOADER_SECTOR 26

#define TC_ORIG_BOOT_LOADER_BACKUP_SECTOR TC_BOOT_LOADER_AREA_SECTOR_COUNT
#define TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET (TC_ORIG_BOOT_LOADER_BACKUP_SECTOR * TC_SECTOR_SIZE_BIOS)

#define TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR (TC_ORIG_BOOT_LOADER_BACKUP_SECTOR + TC_BOOT_LOADER_AREA_SECTOR_COUNT)
#define TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR_OFFSET (TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR * TC_SECTOR_SIZE_BIOS)

#define TC_MBR_SECTOR 0
#define TC_MAX_MBR_BOOT_CODE_SIZE 440

#define TC_MAX_EXTRA_BOOT_PARTITION_SIZE (512UL * 1024UL * 1024UL)


#pragma pack (1)

typedef struct
{
	byte Flags;
} BootSectorConfiguration;


// Modifying this value can introduce incompatibility with previous versions
#define TC_BOOT_LOADER_ARGS_OFFSET 0x10

typedef struct
{
	// Modifying this structure can introduce incompatibility with previous versions
	char Signature[8];
	uint16 BootLoaderVersion;
	uint16 CryptoInfoOffset;
	uint16 CryptoInfoLength;
	uint32 HeaderSaltCrc32;
	Password BootPassword;
	uint64 HiddenSystemPartitionStart;
	uint64 DecoySystemPartitionStart;
	uint32 Flags;
	uint32 BootDriveSignature;

	uint32 BootArgumentsCrc32;

} BootArguments;

// Modifying these values can introduce incompatibility with previous versions
#define TC_BOOT_ARGS_FLAG_EXTRA_BOOT_PARTITION				0x1

#pragma pack ()

// Boot arguments signature should not be defined as a static string
// Modifying these values can introduce incompatibility with previous versions
#define TC_SET_BOOT_ARGUMENTS_SIGNATURE(SG) do { SG[0]  = 'T';   SG[1]  = 'R';   SG[2]  = 'U';   SG[3]  = 'E';   SG[4]  = 0x11;   SG[5]  = 0x23;   SG[6]  = 0x45;   SG[7]  = 0x66; } while (FALSE)
#define TC_IS_BOOT_ARGUMENTS_SIGNATURE(SG)      (SG[0] == 'T' && SG[1] == 'R' && SG[2] == 'U' && SG[3] == 'E' && SG[4] == 0x11 && SG[5] == 0x23 && SG[6] == 0x45 && SG[7] == 0x66)


#endif // TC_HEADER_Boot_BootCommon
