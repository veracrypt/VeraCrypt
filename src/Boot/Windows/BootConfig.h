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

#ifndef TC_HEADER_Boot_BootConfig
#define TC_HEADER_Boot_BootConfig

#include "Crypto.h"
#include "Platform.h"
#include "BootDiskIo.h"

extern uint8 BootSectorFlags;

extern uint8 BootLoaderDrive;
extern uint8 BootDrive;
extern bool BootDriveGeometryValid;
extern DriveGeometry BootDriveGeometry;
extern bool PreventNormalSystemBoot;
extern bool PreventBootMenu;
extern char CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH + 1];
extern uint32 OuterVolumeBackupHeaderCrc;

extern bool BootStarted;

extern CRYPTO_INFO *BootCryptoInfo;
extern Partition EncryptedVirtualPartition;

extern Partition ActivePartition;
extern Partition PartitionFollowingActive;
extern bool ExtraBootPartitionPresent;
extern uint64 PimValueOrHiddenVolumeStartUnitNo; // reuse this variable for stored PIM value to reduce memory usage
extern uint64 HiddenVolumeStartSector;


void ReadBootSectorUserConfiguration ();
BiosResult UpdateBootSectorConfiguration (uint8 drive);

#endif // TC_HEADER_Boot_BootConfig
