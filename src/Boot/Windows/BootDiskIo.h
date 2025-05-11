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

#ifndef TC_HEADER_Boot_BootDiskIo
#define TC_HEADER_Boot_BootDiskIo

#include "Bios.h"
#include "BootDebug.h"
#include "BootDefs.h"

#define TC_MAX_BIOS_DISK_IO_RETRIES 5

enum
{
	BiosResultEccCorrected = 0x11
};

#pragma pack(1)

struct PartitionEntryMBR
{
	uint8 BootIndicator;

	uint8 StartHead;
	uint8 StartCylSector;
	uint8 StartCylinder;

	uint8 Type;

	uint8 EndHead;
	uint8 EndSector;
	uint8 EndCylinder;

	uint32 StartLBA;
	uint32 SectorCountLBA;
};

struct MBR
{
	uint8 Code[446];
	PartitionEntryMBR Partitions[4];
	uint16 Signature;
};

struct BiosLbaPacket
{
	uint8 Size;
	uint8 Reserved;
	uint16 SectorCount;
	uint32 Buffer;
	uint64 Sector;
};

#pragma pack()


struct ChsAddress
{
	uint16 Cylinder;
	uint8 Head;
	uint8 Sector;
};

struct Partition
{
	uint8 Number;
	uint8 Drive;
	bool Active;
	uint64 EndSector;
	bool Primary;
	uint64 SectorCount;
	uint64 StartSector;
	uint8 Type;
};

struct DriveGeometry
{
	uint16 Cylinders;
	uint8 Heads;
	uint8 Sectors;
};


#ifdef TC_BOOT_DEBUG_ENABLED
void AcquireSectorBuffer ();
void ReleaseSectorBuffer ();
#else
#	define AcquireSectorBuffer()
#	define ReleaseSectorBuffer()
#endif

void ChsToLba (const DriveGeometry &geometry, const ChsAddress &chs, uint64 &lba);
bool GetActivePartition (uint8 drive);
BiosResult GetDriveGeometry (uint8 drive, DriveGeometry &geometry, bool silent = false);
BiosResult GetDrivePartitions (uint8 drive, Partition *partitionArray, size_t partitionArrayCapacity, size_t &partitionCount, bool activeOnly = false, Partition *findPartitionFollowingThis = nullptr, bool silent = false);
bool IsLbaSupported (uint8 drive);
void LbaToChs (const DriveGeometry &geometry, const uint64 &lba, ChsAddress &chs);
void Print (const ChsAddress &chs);
void PrintDiskError (BiosResult error, bool write, uint8 drive, const uint64 *sector, const ChsAddress *chs = nullptr);
void PrintSectorCountInMB (const uint64 &sectorCount);
BiosResult ReadWriteMBR (bool write, uint8 drive, bool silent = false);
BiosResult ReadSectors (uint16 bufferSegment, uint16 bufferOffset, uint8 drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult ReadSectors (uint8 *buffer, uint8 drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult ReadSectors (uint8 *buffer, uint8 drive, const ChsAddress &chs, uint8 sectorCount, bool silent = false);
BiosResult ReadWriteSectors (bool write, uint16 bufferSegment, uint16 bufferOffset, uint8 drive, const uint64 &sector, uint16 sectorCount, bool silent);
BiosResult ReadWriteSectors (bool write, uint8 *buffer, uint8 drive, const uint64 &sector, uint16 sectorCount, bool silent);
BiosResult WriteSectors (uint8 *buffer, uint8 drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult WriteSectors (uint8 *buffer, uint8 drive, const ChsAddress &chs, uint8 sectorCount, bool silent = false);

extern uint8 SectorBuffer[TC_LB_SIZE];

#endif // TC_HEADER_Boot_BootDiskIo
