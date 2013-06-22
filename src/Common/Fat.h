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

typedef struct fatparams_t
{
	char volume_name[11];
	byte volume_id[4];
	unsigned int num_sectors;	/* total number of sectors */
	int cluster_count;	/* number of clusters */
	int size_root_dir;	/* size of the root directory in bytes */
	int size_fat;		/* size of FAT */
	int fats;
	int media;
	int cluster_size;
	int fat_length;
	uint16 dir_entries;
	uint16 sector_size;
	int hidden;
	__int16 reserved;
	uint16 sectors;
	unsigned int total_sect;

	uint16 heads;
	uint16 secs_track;

} fatparams;


struct msdos_boot_sector
{
	unsigned char boot_jump[3];	/* Boot strap short or near jump */
	char system_id[8];	/* Name - can be used to special case
				   partition manager volumes */
	unsigned char sector_size[2];	/* bytes per logical sector */
	unsigned char cluster_size;	/* sectors/cluster */
	unsigned short reserved;/* reserved sectors */
	unsigned char fats;	/* number of FATs */
	unsigned char dir_entries[2];	/* root directory entries */
	unsigned char sectors[2];	/* number of sectors */
	unsigned char media;	/* media code  */
	unsigned short fat_length;	/* sectors/FAT */
	unsigned short secs_track;	/* sectors per track */
	unsigned short heads;	/* number of heads */
	unsigned __int32 hidden;	/* hidden sectors */
	unsigned __int32 total_sect;	/* number of sectors (if sectors == 0) */
	unsigned char drive_number;	/* BIOS drive number */
	unsigned char RESERVED;	/* Unused */
	unsigned char ext_boot_sign;	/* 0x29 if fields below exist (DOS 3.3+) */
	unsigned char volume_id[4];	/* Volume ID number */
	char volume_label[11];	/* Volume label */
	char fs_type[8];	/* Typically FAT12, FAT16, or FAT32 */
	unsigned char boot_code[448];	/* Boot code (or message) */
	unsigned short boot_sign;	/* 0xAA55 */
};


void GetFatParams ( fatparams *ft );
void PutBoot ( fatparams *ft , unsigned char *boot );
int FormatFat (unsigned __int64 startSector, fatparams * ft, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);
