/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Common/Tcdefs.h"
#include "Platform/Platform.h"
#include "Volume/VolumeHeader.h"
#include "FatFormatter.h"
#include "RandomNumberGenerator.h"

namespace TrueCrypt
{
	struct fatparams
	{
		char volume_name[11];
		uint32 num_sectors;	/* total number of sectors */
		uint32 cluster_count;	/* number of clusters */
		uint32 size_root_dir;	/* size of the root directory in bytes */
		uint32 size_fat;		/* size of FAT */
		uint32 fats;
		uint32 media;
		uint32 cluster_size;
		uint32 fat_length;
		uint16 dir_entries;
		uint16 sector_size;
		uint32 hidden;
		uint16 reserved;
		uint16 sectors;
		uint32 total_sect;

		uint16 heads;
		uint16 secs_track;

	};

	static void GetFatParams (fatparams * ft)
	{
		uint64 volumeSize = (uint64) ft->num_sectors * ft->sector_size;
		unsigned int fatsecs;

		if(ft->cluster_size == 0)	// 'Default' cluster size
		{
			uint32 clusterSize;

			// Determine optimal cluster size to minimize FAT size (mounting delay), maximize number of files, keep 4 KB alignment, etc.
			if (volumeSize >= 2 * BYTES_PER_TB)
				clusterSize = 256 * BYTES_PER_KB;
			else if (volumeSize >= 512 * BYTES_PER_GB)
				clusterSize = 128 * BYTES_PER_KB;
			else if (volumeSize >= 128 * BYTES_PER_GB)
				clusterSize = 64 * BYTES_PER_KB;
			else if (volumeSize >= 64 * BYTES_PER_GB)
				clusterSize = 32 * BYTES_PER_KB;
			else if (volumeSize >= 32 * BYTES_PER_GB)
				clusterSize = 16 * BYTES_PER_KB;
			else if (volumeSize >= 16 * BYTES_PER_GB)
				clusterSize = 8 * BYTES_PER_KB;
			else if (volumeSize >= 512 * BYTES_PER_MB)
				clusterSize = 4 * BYTES_PER_KB;
			else if (volumeSize >= 256 * BYTES_PER_MB)
				clusterSize = 2 * BYTES_PER_KB;
			else if (volumeSize >= 1 * BYTES_PER_MB)
				clusterSize = 1 * BYTES_PER_KB;
			else
				clusterSize = 512;

			ft->cluster_size = clusterSize / ft->sector_size;

			if (ft->cluster_size == 0)
				ft->cluster_size = 1;

			if (ft->cluster_size * ft->sector_size > TC_MAX_FAT_CLUSTER_SIZE)
				ft->cluster_size = TC_MAX_FAT_CLUSTER_SIZE / ft->sector_size;

			if (ft->cluster_size > 128)
				ft->cluster_size = 128;
		}

		if (volumeSize <= TC_MAX_FAT_CLUSTER_SIZE * 4)
			ft->cluster_size = 1;

		// Geometry always set to SECTORS/1/1
		ft->secs_track = 1; 
		ft->heads = 1; 

		ft->dir_entries = 512;
		ft->fats = 2;
		ft->media = 0xf8;
		ft->hidden = 0;

		ft->size_root_dir = ft->dir_entries * 32;

		// FAT12
		ft->size_fat = 12;
		ft->reserved = 2;
		fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
		ft->cluster_count = (int) (((int64) fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
		ft->fat_length = (((ft->cluster_count * 3 + 1) >> 1) + ft->sector_size - 1) / ft->sector_size;

		if (ft->cluster_count >= 4085) // FAT16
		{
			ft->size_fat = 16;
			ft->reserved = 2;
			fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
			ft->cluster_count = (int) (((int64) fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
			ft->fat_length = (ft->cluster_count * 2 + ft->sector_size - 1) / ft->sector_size;
		}

		if(ft->cluster_count >= 65525) // FAT32
		{
			ft->size_fat = 32;
			ft->reserved = 32 - 1;

			do
			{
				ft->reserved++;

				fatsecs = ft->num_sectors - ft->reserved;
				ft->size_root_dir = ft->cluster_size * ft->sector_size;
				ft->cluster_count = (int) (((int64) fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
				ft->fat_length = (ft->cluster_count * 4 + ft->sector_size - 1) / ft->sector_size;

				// Align data area on TC_MAX_VOLUME_SECTOR_SIZE

			} while (ft->sector_size == TC_SECTOR_SIZE_LEGACY
				&& (ft->reserved * ft->sector_size + ft->fat_length * ft->fats * ft->sector_size) % TC_MAX_VOLUME_SECTOR_SIZE != 0);
		}

		ft->cluster_count -= ft->fat_length * ft->fats / ft->cluster_size;

		if (ft->num_sectors >= 65536 || ft->size_fat == 32)
		{
			ft->sectors = 0;
			ft->total_sect = ft->num_sectors;
		}
		else
		{
			ft->sectors = (uint16) ft->num_sectors;
			ft->total_sect = 0;
		}
	}

	static void PutBoot (fatparams * ft, byte *boot, uint32 volumeId)
	{
		int cnt = 0;

		boot[cnt++] = 0xeb;	/* boot jump */
		boot[cnt++] = 0x3c;
		boot[cnt++] = 0x90;
		memcpy (boot + cnt, "MSDOS5.0", 8); /* system id */
		cnt += 8;
		*(int16 *)(boot + cnt) = Endian::Little (ft->sector_size);	/* bytes per sector */
		cnt += 2;
		boot[cnt++] = (int8) ft->cluster_size;			/* sectors per cluster */
		*(int16 *)(boot + cnt) = Endian::Little (ft->reserved);		/* reserved sectors */
		cnt += 2;
		boot[cnt++] = (int8) ft->fats;					/* 2 fats */

		if(ft->size_fat == 32)
		{
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x00;
		}
		else
		{
			*(int16 *)(boot + cnt) = Endian::Little (ft->dir_entries);	/* 512 root entries */
			cnt += 2;
		}

		*(int16 *)(boot + cnt) = Endian::Little (ft->sectors);		/* # sectors */
		cnt += 2;
		boot[cnt++] = (int8) ft->media;					/* media byte */

		if(ft->size_fat == 32)	
		{
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x00;
		}
		else 
		{ 
			*(uint16 *)(boot + cnt) = Endian::Little ((uint16) ft->fat_length);	/* fat size */
			cnt += 2;
		}

		*(int16 *)(boot + cnt) = Endian::Little (ft->secs_track);	/* # sectors per track */
		cnt += 2;
		*(int16 *)(boot + cnt) = Endian::Little (ft->heads);			/* # heads */
		cnt += 2;
		*(int32 *)(boot + cnt) = Endian::Little (ft->hidden);		/* # hidden sectors */
		cnt += 4;
		*(int32 *)(boot + cnt) = Endian::Little (ft->total_sect);	/* # huge sectors */
		cnt += 4;

		if(ft->size_fat == 32)
		{
			*(int32 *)(boot + cnt) = Endian::Little (ft->fat_length); cnt += 4;	/* fat size 32 */
			boot[cnt++] = 0x00;	/* ExtFlags */
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x00;	/* FSVer */
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x02;	/* RootClus */
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x01;	/* FSInfo */
			boot[cnt++] = 0x00;
			boot[cnt++] = 0x06;	/* BkBootSec */
			boot[cnt++] = 0x00;
			memset(boot+cnt, 0, 12); cnt+=12;	/* Reserved */
		}

		boot[cnt++] = 0x00;	/* drive number */   // FIXED 80 > 00
		boot[cnt++] = 0x00;	/* reserved */
		boot[cnt++] = 0x29;	/* boot sig */

		*(int32 *)(boot + cnt) = volumeId;
		cnt += 4;

		memcpy (boot + cnt, ft->volume_name, 11);	/* vol title */
		cnt += 11;

		switch(ft->size_fat) /* filesystem type */
		{
		case 12: memcpy (boot + cnt, "FAT12   ", 8); break;
		case 16: memcpy (boot + cnt, "FAT16   ", 8); break;
		case 32: memcpy (boot + cnt, "FAT32   ", 8); break;
		}
		cnt += 8;

		memset (boot + cnt, 0, ft->size_fat==32 ? 420:448);	/* boot code */
		cnt += ft->size_fat==32 ? 420:448;
		boot[cnt++] = 0x55;
		boot[cnt++] = 0xaa;	/* boot sig */
	}


	/* FAT32 FSInfo */
	static void PutFSInfo (byte *sector, fatparams *ft)
	{
		memset (sector, 0, ft->sector_size);
		sector[3] = 0x41; /* LeadSig */
		sector[2] = 0x61; 
		sector[1] = 0x52; 
		sector[0] = 0x52; 
		sector[484+3] = 0x61; /* StrucSig */
		sector[484+2] = 0x41; 
		sector[484+1] = 0x72; 
		sector[484+0] = 0x72; 

		// Free cluster count
		*(uint32 *)(sector + 488) = Endian::Little (ft->cluster_count - ft->size_root_dir / ft->sector_size / ft->cluster_size);

		// Next free cluster
		*(uint32 *)(sector + 492) = Endian::Little ((uint32) 2);

		sector[508+3] = 0xaa; /* TrailSig */
		sector[508+2] = 0x55;
		sector[508+1] = 0x00;
		sector[508+0] = 0x00;
	}

	void FatFormatter::Format (WriteSectorCallback &writeSector, uint64 deviceSize, uint32 clusterSize, uint32 sectorSize)
	{
		fatparams fatParams;

#if TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#error TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#endif
		fatParams.sector_size = (uint16) sectorSize;

		if (deviceSize / fatParams.sector_size > 0xffffFFFF)
			throw ParameterIncorrect (SRC_POS);

		fatParams.num_sectors = (uint32) (deviceSize / fatParams.sector_size);
		fatParams.cluster_size = clusterSize / fatParams.sector_size;
		memcpy (fatParams.volume_name, "NO NAME    ", 11);
		GetFatParams (&fatParams); 
		fatparams *ft = &fatParams;

		SecureBuffer sector (ft->sector_size);
		uint32 sectorNumber = 0;

		/* Write the data area */

		sector.Zero();

		uint32 volumeId;
		RandomNumberGenerator::GetDataFast (BufferPtr ((byte *) &volumeId, sizeof (volumeId)));

		PutBoot (ft, (byte *) sector, volumeId);
		writeSector (sector); ++sectorNumber;

		/* fat32 boot area */
		if (ft->size_fat == 32)				
		{
			/* fsinfo */
			PutFSInfo((byte *) sector, ft);
			writeSector (sector); ++sectorNumber;

			/* reserved */
			while (sectorNumber < 6)
			{
				sector.Zero();
				sector[508+3] = 0xaa; /* TrailSig */
				sector[508+2] = 0x55;
				writeSector (sector); ++sectorNumber;
			}

			/* bootsector backup */
			sector.Zero();
			PutBoot (ft, (byte *) sector, volumeId);
			writeSector (sector); ++sectorNumber;

			PutFSInfo((byte *) sector, ft);
			writeSector (sector); ++sectorNumber;
		}

		/* reserved */
		while (sectorNumber < (uint32)ft->reserved)
		{
			sector.Zero();
			writeSector (sector); ++sectorNumber;
		}

		/* write fat */
		for (uint32 x = 1; x <= ft->fats; x++)
		{
			for (uint32 n = 0; n < ft->fat_length; n++)
			{
				sector.Zero();

				if (n == 0)
				{
					byte fat_sig[12];
					if (ft->size_fat == 32)
					{
						fat_sig[0] = (byte) ft->media;
						fat_sig[1] = fat_sig[2] = 0xff;
						fat_sig[3] = 0x0f;
						fat_sig[4] = fat_sig[5] = fat_sig[6] = 0xff;
						fat_sig[7] = 0x0f;
						fat_sig[8] = fat_sig[9] = fat_sig[10] = 0xff;
						fat_sig[11] = 0x0f;
						memcpy (sector, fat_sig, 12);
					}				
					else if (ft->size_fat == 16)
					{
						fat_sig[0] = (byte) ft->media;
						fat_sig[1] = 0xff;
						fat_sig[2] = 0xff;
						fat_sig[3] = 0xff;
						memcpy (sector, fat_sig, 4);
					}
					else if (ft->size_fat == 12)
					{
						fat_sig[0] = (byte) ft->media;
						fat_sig[1] = 0xff;
						fat_sig[2] = 0xff;
						fat_sig[3] = 0x00;
						memcpy (sector, fat_sig, 4);
					}
				}

				if (!writeSector (sector))
					return;
			}
		}

		/* write rootdir */
		for (uint32 x = 0; x < ft->size_root_dir / ft->sector_size; x++)
		{
			sector.Zero();
			if (!writeSector (sector))
				return;
		}
	}
}
