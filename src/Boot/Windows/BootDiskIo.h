/*
 Copyright (c) 2008-2011 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
	byte BootIndicator;

	byte StartHead;
	byte StartCylSector;
	byte StartCylinder;

	byte Type;

	byte EndHead;
	byte EndSector;
	byte EndCylinder;

	uint32 StartLBA;
	uint32 SectorCountLBA;
};

struct MBR
{
	byte Code[446];
	PartitionEntryMBR Partitions[4];
	uint16 Signature;
};

struct BiosLbaPacket
{
	byte Size;
	byte Reserved;
	uint16 SectorCount;
	uint32 Buffer;
	uint64 Sector;
};

#pragma pack()


struct ChsAddress
{
	uint16 Cylinder;
	byte Head;
	byte Sector;
};

struct Partition
{
	byte Number;
	byte Drive;
	bool Active;
	uint64 EndSector;
	bool Primary;
	uint64 SectorCount;
	uint64 StartSector;
	byte Type;
};

struct DriveGeometry
{
	uint16 Cylinders;
	byte Heads;
	byte Sectors;
};


#ifdef TC_BOOT_DEBUG_ENABLED
void AcquireSectorBuffer ();
void ReleaseSectorBuffer ();
#else
#	define AcquireSectorBuffer()
#	define ReleaseSectorBuffer()
#endif

void ChsToLba (const DriveGeometry &geometry, const ChsAddress &chs, uint64 &lba);
bool GetActivePartition (byte drive);
BiosResult GetDriveGeometry (byte drive, DriveGeometry &geometry, bool silent = false);
BiosResult GetDrivePartitions (byte drive, Partition *partitionArray, size_t partitionArrayCapacity, size_t &partitionCount, bool activeOnly = false, Partition *findPartitionFollowingThis = nullptr, bool silent = false);
bool IsLbaSupported (byte drive);
void LbaToChs (const DriveGeometry &geometry, const uint64 &lba, ChsAddress &chs);
void Print (const ChsAddress &chs);
void PrintDiskError (BiosResult error, bool write, byte drive, const uint64 *sector, const ChsAddress *chs = nullptr);
void PrintSectorCountInMB (const uint64 &sectorCount);
BiosResult ReadWriteMBR (bool write, byte drive, bool silent = false);
BiosResult ReadSectors (uint16 bufferSegment, uint16 bufferOffset, byte drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult ReadSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult ReadSectors (byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent = false);
BiosResult ReadWriteSectors (bool write, uint16 bufferSegment, uint16 bufferOffset, byte drive, const uint64 &sector, uint16 sectorCount, bool silent);
BiosResult WriteSectors (byte *buffer, byte drive, const uint64 &sector, uint16 sectorCount, bool silent = false);
BiosResult WriteSectors (byte *buffer, byte drive, const ChsAddress &chs, byte sectorCount, bool silent = false);

extern byte SectorBuffer[TC_LB_SIZE];

#endif // TC_HEADER_Boot_BootDiskIo
