/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#pragma once

#include "Tcdefs.h"
#include "Boot/Windows/BootDefs.h"
#include "Common.h"
#include "Crypto.h"
#include "Volumes.h"
#include "Wipe.h"

#ifdef _WIN32

/* WARNING: Modifying the following values or their meanings can introduce incompatibility with previous versions. */

#define TC_IOCTL(CODE) (CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800 + (CODE), METHOD_BUFFERED, FILE_ANY_ACCESS))

// IOCTL interface to \\device\veracrypt

// Gets version of driver
// OUT struct - LONG
#define TC_IOCTL_GET_DRIVER_VERSION						TC_IOCTL (1)

// Gets boot loader version
// OUT struct - int16
#define TC_IOCTL_GET_BOOT_LOADER_VERSION				TC_IOCTL (2)

// Mount volume to \\Device\VeraCryptVolume"X"
// IN OUT - MOUNT_STRUCT
#define TC_IOCTL_MOUNT_VOLUME							TC_IOCTL (3)

// Dismount volume
// IN OUT - UNMOUNT_STRUCT
#define TC_IOCTL_DISMOUNT_VOLUME						TC_IOCTL (4)

// Dismount all volumes
// IN OUT - UNMOUNT_STRUCT
#define TC_IOCTL_DISMOUNT_ALL_VOLUMES					TC_IOCTL (5)

// Get list of all mounted volumes
// IN OUT - MOUNT_LIST_STRUCT (only 26 volumes possible)
#define TC_IOCTL_GET_MOUNTED_VOLUMES					TC_IOCTL (6)

// Get properties of the volume selected by driveNo
// In OUT - VOLUME_PROPERTIES_STRUCT
#define TC_IOCTL_GET_VOLUME_PROPERTIES					TC_IOCTL (7)

// Get reference count to main device object
// OUT - int
#define TC_IOCTL_GET_DEVICE_REFCOUNT					TC_IOCTL (8)

// Is it possible to unload driver 
// It check file system cache of mounted drives via unmount IOCTL.
// OUT - int
#define TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED				TC_IOCTL (9)

// Is there any mounted device
// OUT - int
#define TC_IOCTL_IS_ANY_VOLUME_MOUNTED					TC_IOCTL (10)

// Check password cache
// Result in IOCTL result TRUE if there is chached passwords
#define TC_IOCTL_GET_PASSWORD_CACHE_STATUS				TC_IOCTL (11)

// Clean password cache
#define TC_IOCTL_WIPE_PASSWORD_CACHE					TC_IOCTL (12)

// Check file/drive container
// IN OUT - OPEN_TEST_STRUCT
#define TC_IOCTL_OPEN_TEST								TC_IOCTL (13)

// result of IOCTL_DISK_GET_PARTITION_INFO
// IN OUT - DISK_PARTITION_INFO_STRUCT
// TODO: need IOCTL_DISK_GET_PARTITION_INFO_EX to support GPT
#define TC_IOCTL_GET_DRIVE_PARTITION_INFO				TC_IOCTL (14)

// result IOCTL_DISK_GET_DRIVE_GEOMETRY
// IN OUT - DISK_GEOMETRY_STRUCT
#define TC_IOCTL_GET_DRIVE_GEOMETRY						TC_IOCTL (15)

// result IOCTL_DISK_GET_LENGTH_INFO
// IN OUT - ProbeRealDriveSizeRequest
#define TC_IOCTL_PROBE_REAL_DRIVE_SIZE					TC_IOCTL (16)

// result of ZwQuerySymbolicLinkObject
// IN OUT RESOLVE_SYMLINK_STRUCT
#define TC_IOCTL_GET_RESOLVED_SYMLINK					TC_IOCTL (17)

#define TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS				TC_IOCTL (18)
#define TC_IOCTL_BOOT_ENCRYPTION_SETUP					TC_IOCTL (19)
#define TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP			TC_IOCTL (20)
#define TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT		TC_IOCTL (21)
#define TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES		TC_IOCTL (22)
#define TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER				TC_IOCTL (23)
#define TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME		TC_IOCTL (24)
#define TC_IOCTL_GET_PORTABLE_MODE_STATUS				TC_IOCTL (25)
#define TC_IOCTL_SET_PORTABLE_MODE_STATUS				TC_IOCTL (26)
#define TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING				TC_IOCTL (27)
#define TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG				TC_IOCTL (28)
#define TC_IOCTL_DISK_IS_WRITABLE						TC_IOCTL (29)
#define TC_IOCTL_START_DECOY_SYSTEM_WIPE				TC_IOCTL (30)
#define TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE				TC_IOCTL (31)
#define TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS			TC_IOCTL (32)
#define TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT			TC_IOCTL (33)
#define TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR				TC_IOCTL (34)
#define TC_IOCTL_GET_WARNING_FLAGS						TC_IOCTL (35)
#define TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY		TC_IOCTL (36)
#define TC_IOCTL_REREAD_DRIVER_CONFIG					TC_IOCTL (37)
#define TC_IOCTL_GET_SYSTEM_DRIVE_DUMP_CONFIG			TC_IOCTL (38)
#define VC_IOCTL_GET_BOOT_LOADER_FINGERPRINT			TC_IOCTL (39)
// result IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
// IN OUT - DISK_GEOMETRY_EX_STRUCT
#define VC_IOCTL_GET_DRIVE_GEOMETRY_EX					TC_IOCTL (40)

#define VC_IOCTL_EMERGENCY_CLEAR_ALL_KEYS				TC_IOCTL (41)

#define VC_IOCTL_IS_RAM_ENCRYPTION_ENABLED				TC_IOCTL (42)

#define VC_IOCTL_ENCRYPTION_QUEUE_PARAMS				TC_IOCTL (43)

// Undocumented IOCTL sent by Windows 10 when handling EFS data on volumes
#define IOCTL_UNKNOWN_WINDOWS10_EFS_ACCESS				0x455610D8

/* Start of driver interface structures, the size of these structures may
   change between versions; so make sure you first send DRIVER_VERSION to
   check that it's the correct device driver */

#pragma pack (push)
#pragma pack(1)

typedef struct
{
	int nReturnCode;					/* Return code back from driver */
	BOOL FilesystemDirty;
	BOOL VolumeMountedReadOnlyAfterAccessDenied;
	BOOL VolumeMountedReadOnlyAfterDeviceWriteProtected;

	wchar_t wszVolume[TC_MAX_PATH];		/* Volume to be mounted */
	Password VolumePassword;			/* User password */
	BOOL bCache;						/* Cache passwords in driver */
	int nDosDriveNo;					/* Drive number to mount */
	uint32 BytesPerSector;
	BOOL bMountReadOnly;				/* Mount volume in read-only mode */
	BOOL bMountRemovable;				/* Mount volume as removable media */
	BOOL bExclusiveAccess;				/* Open host file/device in exclusive access mode */
	BOOL bMountManager;					/* Announce volume to mount manager */
	BOOL bPreserveTimestamp;			/* Preserve file container timestamp */
	BOOL bPartitionInInactiveSysEncScope;		/* If TRUE, we are to attempt to mount a partition located on an encrypted system drive without pre-boot authentication. */
	int nPartitionInInactiveSysEncScopeDriveNo;	/* If bPartitionInInactiveSysEncScope is TRUE, this contains the drive number of the system drive on which the partition is located. */
	BOOL SystemFavorite;
	// Hidden volume protection
	BOOL bProtectHiddenVolume;			/* TRUE if the user wants the hidden volume within this volume to be protected against being overwritten (damaged) */
	Password ProtectedHidVolPassword;	/* Password to the hidden volume to be protected against overwriting */
	BOOL UseBackupHeader;
	BOOL RecoveryMode;
	int pkcs5_prf;
	int ProtectedHidVolPkcs5Prf;
	BOOL VolumeMountedReadOnlyAfterPartialSysEnc;
	uint32 BytesPerPhysicalSector;
	int VolumePim;
	int ProtectedHidVolPim;
	wchar_t wszLabel[33]; // maximum label length is 32 for NTFS and 11 for FAT32
	BOOL bIsNTFS; // output only
	BOOL bDriverSetLabel;
	BOOL bCachePim;
	ULONG MaximumTransferLength;
	ULONG MaximumPhysicalPages;
	ULONG AlignmentMask;
	BOOL VolumeMasterKeyVulnerable;
} MOUNT_STRUCT;

typedef struct
{
	int nDosDriveNo;	/* Drive letter to unmount */
	BOOL ignoreOpenFiles;
	BOOL HiddenVolumeProtectionTriggered;
	int nReturnCode;	/* Return code back from driver */
} UNMOUNT_STRUCT;

typedef struct
{
	unsigned __int32 ulMountedDrives;	/* Bitfield of all mounted drive letters */
	wchar_t wszVolume[26][TC_MAX_PATH];	/* Volume names of mounted volumes */
	wchar_t wszLabel[26][33];	/* Labels of mounted volumes */
	wchar_t volumeID[26][VOLUME_ID_SIZE];	/* IDs of mounted volumes */
	unsigned __int64 diskLength[26];
	int ea[26];
	int volumeType[26];	/* Volume type (e.g. PROP_VOL_TYPE_OUTER, PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED, etc.) */
	BOOL reserved[26]; /* needed to keep the same size for the structure so that installer of new version can communicate with installed old version */
} MOUNT_LIST_STRUCT;

typedef struct
{
	int driveNo;
	int uniqueId;
	wchar_t wszVolume[TC_MAX_PATH];
	unsigned __int64 diskLength;
	int ea;
	int mode;
	int pkcs5;
	int pkcs5Iterations;
	BOOL hiddenVolume;
	BOOL readOnly;
	BOOL removable;
	BOOL partitionInInactiveSysEncScope;
	uint32 volumeHeaderFlags;
	unsigned __int64 totalBytesRead;
	unsigned __int64 totalBytesWritten;
	int hiddenVolProtection;	/* Hidden volume protection status (e.g. HIDVOL_PROT_STATUS_NONE, HIDVOL_PROT_STATUS_ACTIVE, etc.) */
	int volFormatVersion;
	int volumePim;
	wchar_t wszLabel[33];
	BOOL bDriverSetLabel;
	unsigned char volumeID[VOLUME_ID_SIZE];
	BOOL mountDisabled;
} VOLUME_PROPERTIES_STRUCT;

typedef struct
{
	WCHAR symLinkName[TC_MAX_PATH];
	WCHAR targetName[TC_MAX_PATH];
} RESOLVE_SYMLINK_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	PARTITION_INFORMATION partInfo;
	BOOL IsGPT;
	BOOL IsDynamic;
}
DISK_PARTITION_INFO_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	DISK_GEOMETRY diskGeometry;
}
DISK_GEOMETRY_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	DISK_GEOMETRY diskGeometry;
	LARGE_INTEGER DiskSize;
}
DISK_GEOMETRY_EX_STRUCT;

typedef struct
{
	WCHAR DeviceName[TC_MAX_PATH];
	LARGE_INTEGER RealDriveSize;
	BOOL TimeOut;
} ProbeRealDriveSizeRequest;

typedef struct
{
	wchar_t wszFileName[TC_MAX_PATH];		// Volume to be "open tested"
	BOOL bDetectTCBootLoader;			// Whether the driver is to determine if the first sector contains a portion of the TrueCrypt Boot Loader
	BOOL TCBootLoaderDetected;
	BOOL DetectFilesystem;
	BOOL FilesystemDetected;
	BOOL bComputeVolumeIDs;
	unsigned char volumeIDs[TC_VOLUME_TYPE_COUNT][VOLUME_ID_SIZE];
	BOOL VolumeIDComputed[TC_VOLUME_TYPE_COUNT];
} OPEN_TEST_STRUCT;


typedef enum
{
	SetupNone = 0,
	SetupEncryption,
	SetupDecryption
} BootEncryptionSetupMode;


typedef struct
{
	// New fields must be added at the end of the structure to maintain compatibility with previous versions
	BOOL DeviceFilterActive;

	uint16 BootLoaderVersion;

	BOOL DriveMounted;
	BOOL VolumeHeaderPresent;
	BOOL DriveEncrypted;

	LARGE_INTEGER BootDriveLength;

	int64 ConfiguredEncryptedAreaStart;
	int64 ConfiguredEncryptedAreaEnd;
	int64 EncryptedAreaStart;
	int64 EncryptedAreaEnd;

	uint32 VolumeHeaderSaltCrc32;

	BOOL SetupInProgress;
	BootEncryptionSetupMode SetupMode;
	BOOL TransformWaitingForIdle;

	uint32 HibernationPreventionCount;

	BOOL HiddenSystem;
	int64 HiddenSystemPartitionStart;

	// Number of times the filter driver answered that an unencrypted volume
	// is read-only (or mounted an outer/normal TrueCrypt volume as read only)
	uint32 HiddenSysLeakProtectionCount;

	BOOL MasterKeyVulnerable;

} BootEncryptionStatus;


typedef struct
{
	BootEncryptionSetupMode SetupMode;
	WipeAlgorithmId WipeAlgorithm;
	BOOL ZeroUnreadableSectors;
	BOOL DiscardUnreadableEncryptedSectors;
} BootEncryptionSetupRequest;


typedef struct
{
	Password VolumePassword;
	int pkcs5_prf;
	int pim;
} ReopenBootVolumeHeaderRequest;


typedef struct
{
	char BootEncryptionAlgorithmName[256];
	char BootPrfAlgorithmName[256];
} GetBootEncryptionAlgorithmNameRequest;

typedef struct
{
	uint8 Fingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE];
} BootLoaderFingerprintRequest;

typedef struct
{
	wchar_t DevicePath[TC_MAX_PATH];
	uint8 Configuration;
	BOOL DriveIsDynamic;
	uint16 BootLoaderVersion;
	uint8 UserConfiguration;
	char CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
} GetSystemDriveConfigurationRequest;

typedef struct
{
	WipeAlgorithmId WipeAlgorithm;
	CRYPTOPP_ALIGN_DATA(16) uint8 WipeKey[MASTER_KEYDATA_SIZE];
} WipeDecoySystemRequest;

typedef struct
{
	BOOL WipeInProgress;
	WipeAlgorithmId WipeAlgorithm;
	int64 WipedAreaEnd;
} DecoySystemWipeStatus;

typedef struct
{
	LARGE_INTEGER Offset;
	uint8 Data[TC_SECTOR_SIZE_BIOS];
} WriteBootDriveSectorRequest;

typedef struct
{
	BOOL PagingFileCreationPrevented;
	BOOL SystemFavoriteVolumeDirty;
} GetWarningFlagsRequest;

typedef struct
{
	struct _DriveFilterExtension *BootDriveFilterExtension;
	BOOL HwEncryptionEnabled;
} GetSystemDriveDumpConfigRequest;

typedef struct
{
	int EncryptionIoRequestCount;
	int EncryptionItemCount;
	int EncryptionFragmentSize;
} EncryptionQueueParameters;

#pragma pack (pop)

#define DRIVER_STR WIDE

#define TC_UNIQUE_ID_PREFIX "VeraCryptVolume"
#define TC_MOUNT_PREFIX L"\\Device\\VeraCryptVolume"

#define NT_MOUNT_PREFIX DRIVER_STR("\\Device\\VeraCryptVolume")
#define NT_ROOT_PREFIX DRIVER_STR("\\Device\\VeraCrypt")
#define DOS_MOUNT_PREFIX_DEFAULT DRIVER_STR("\\DosDevices\\")
#define DOS_MOUNT_PREFIX_GLOBAL DRIVER_STR("\\GLOBAL??\\") // Use Global MS-DOS device names for sanity checks on drive letters
#define DOS_ROOT_PREFIX DRIVER_STR("\\DosDevices\\VeraCrypt")
#define WIN32_ROOT_PREFIX DRIVER_STR("\\\\.\\VeraCrypt")

#define TC_DRIVER_CONFIG_REG_VALUE_NAME DRIVER_STR("VeraCryptConfig")
#define TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME DRIVER_STR("VeraCryptEncryptionFreeCpuCount")

#define VC_ENCRYPTION_IO_REQUEST_COUNT DRIVER_STR("VeraCryptEncryptionIoRequestCount")
#define VC_ENCRYPTION_ITEM_COUNT DRIVER_STR("VeraCryptEncryptionItemCount")
#define VC_ENCRYPTION_FRAGMENT_SIZE DRIVER_STR("VeraCryptEncryptionFragmentSize")

#define VC_ERASE_KEYS_SHUTDOWN DRIVER_STR("VeraCryptEraseKeysShutdown")

#define VC_ENABLE_MEMORY_PROTECTION DRIVER_STR("VeraCryptEnableMemoryProtection")

// WARNING: Modifying the following values can introduce incompatibility with previous versions.
#define TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD						0x1
#define TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES		0x2
#define TC_DRIVER_CONFIG_DISABLE_NONADMIN_SYS_FAVORITES_ACCESS		0x4
#define TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION				0x8
#define TC_DRIVER_CONFIG_ENABLE_EXTENDED_IOCTL						0x10
#define TC_DRIVER_CONFIG_DISABLE_EVIL_MAID_ATTACK_DETECTION			0x20
#define TC_DRIVER_CONFIG_CACHE_BOOT_PIM								0x40
#define VC_DRIVER_CONFIG_ALLOW_NONSYS_TRIM							0x80
#define VC_DRIVER_CONFIG_BLOCK_SYS_TRIM								0x100
#define VC_DRIVER_CONFIG_ALLOW_WINDOWS_DEFRAG						0x200
#define VC_DRIVER_CONFIG_CLEAR_KEYS_ON_NEW_DEVICE_INSERTION			0x400
#define VC_DRIVER_CONFIG_ENABLE_CPU_RNG								0x800
#define VC_DRIVER_CONFIG_ENABLE_RAM_ENCRYPTION						0x1000

#endif		/* _WIN32 */
