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

#ifndef TC_HEADER_Boot_BootCommon
#define TC_HEADER_Boot_BootCommon

#include "Common/Password.h"
#include "BootDefs.h"

// The user will be advised to upgrade the rescue disk if upgrading from the following or any previous version
#define TC_RESCUE_DISK_UPGRADE_NOTICE_MAX_VERSION 0x0121

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

#if defined(_MSC_VER) && !defined(TC_WINDOWS_BOOT)

#define DCS_DISK_ENTRY_LIST_HEADER_SIGN      SIGNATURE_64 ('D','C','S','D','E','L','S','T')

#ifndef CSTATIC_ASSERT
#define CSTATIC_ASSERT(b, name) typedef int StaticAssertFailed##name[b ? 1 : -1];
#endif

#define DE_IDX_CRYPTOHEADER  0
#define DE_IDX_LIST          1
#define DE_IDX_DISKID        2
#define DE_IDX_MAINGPTHDR    3
#define DE_IDX_MAINGPTENTRYS 4
#define DE_IDX_ALTGPTHDR     5
#define DE_IDX_ALTGPTENTRYS  6
#define DE_IDX_EXEC          7
#define DE_IDX_PWDCACHE      8
#define DE_IDX_RND           9
#define DE_IDX_TOTAL         10
CSTATIC_ASSERT(DE_IDX_TOTAL <= 15, DE_IDX_TOTAL_too_big);

enum DcsDiskEntryTypes {
	DE_Unused = 0,
	DE_Sectors,
	DE_List,
	DE_DISKID,
	DE_ExecParams,
	DE_PwdCache,
	DE_Rnd
};

#pragma pack(1)
typedef struct _SECREGION_BOOT_PARAMS {
	uint64               Ptr;
	uint32               Size;
	uint32               Crc;
} SECREGION_BOOT_PARAMS;

typedef struct {
	uint32  Data1;
	uint16  Data2;
	uint16  Data3;
	byte    Data4[8];
} DCS_GUID;

// DE types
typedef struct _DCS_DISK_ENTRY_SECTORS {
	uint32      Type;
	uint32      Offset; // Offset in memory
	uint64      Reserved;
	uint64      Start;  // Start on disk (byte)
	uint64      Length; // length on disk (byte)
} DCS_DISK_ENTRY_SECTORS;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_SECTORS) ==	32, Wrong_size_DCS_DISK_ENTRY_SECTORS);

typedef struct _DCS_DISK_ENTRY_PARAMS {
	uint32      Type;
	uint32      Offset;
	uint64      Reserved[2];
	uint64      Length;           // size of data
} DCS_DISK_ENTRY_PARAMS;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_PARAMS) == 32, Wrong_size_DCS_DISK_ENTRY_PARAMS);

typedef struct _DCS_DISK_ENTRY_DISKID {
	uint32      Type;
	uint32      MbrID;
	uint64      ReservedDiskId;
	DCS_GUID    GptID;
} DCS_DISK_ENTRY_DISKID;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_DISKID) == 32, Wrong_size_DCS_DISK_ENTRY_DISKID);

#pragma warning(disable:4201)
typedef struct _DCS_DISK_ENTRY {
	union {
		struct {
			uint32      Type;
			uint32      Offset;
			byte        reserved[16];
			uint64      Length;           // size of structure at Offset
		};
		DCS_DISK_ENTRY_SECTORS Sectors;
		DCS_DISK_ENTRY_DISKID  DiskId;
		DCS_DISK_ENTRY_PARAMS  Prm;
	};
} DCS_DISK_ENTRY;
#pragma warning(default:4201)
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY) == 32, Wrong_size_DCS_DISK_ENTRY);

// Static compile time checks field offsets
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(t, f) ((UINTN)(&((t*)0)->f))
#endif
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_DISKID,  Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Length) == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Length), Wrong_Length_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Length) == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Length), Wrong_Length_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Offset) == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Offset), Wrong_Offset_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Offset) == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Offset), Wrong_Offset_offset);

// DE type specific data 
// DE List
typedef struct _DCS_DISK_ENTRY_LIST {
	//	EFI_TABLE_HEADER
	uint64  Signature;
	uint32  Revision;
	uint32  HeaderSize;	//< The size, in bytes, of the entire table including the EFI_TABLE_HEADER.
	uint32  CRC32;       //< The 32-bit CRC for the entire table. This value is computed by setting this field to 0, and computing the 32-bit CRC for HeaderSize bytes.
	uint32  Reserved; 	//< Reserved field that must be set to 0.
								//
	uint32  Count;
	uint32  DataSize;
	//
	DCS_DISK_ENTRY  DE[15];
} DCS_DISK_ENTRY_LIST;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_LIST) == 512, Wrong_size_DCS_DISK_ENTRY_LIST);

typedef struct _DCS_DEP_EXEC {
	DCS_GUID     ExecPartGuid;
	uint16       ExecCmd[248];
} DCS_DEP_EXEC;
CSTATIC_ASSERT(sizeof(DCS_DEP_EXEC) == 512, Wrong_size_DCS_DEP_EXEC);

#define DCS_DEP_PWD_CACHE_SIGN      SIGNATURE_64 ('P','W','D','C','A','C','H','E')
typedef struct _DCS_DEP_PWD_CACHE {
	uint64       Sign;
	uint32       CRC;
	uint32       Count;
	Password     Pwd[4];
	int32        Pim[4];
	byte         pad[512 - 8 - 4 - 4 - (sizeof(Password) + 4) * 4];
} DCS_DEP_PWD_CACHE;
CSTATIC_ASSERT(sizeof(DCS_DEP_PWD_CACHE) == 512, Wrong_size_DCS_DEP_PWD_CACHE);
#pragma pack()

#endif // #if !defined(TC_WINDOWS_BOOT)

#endif // TC_HEADER_Boot_BootCommon
