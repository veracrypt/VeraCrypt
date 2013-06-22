/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Boot_BootEncryptionIo
#define TC_HEADER_Boot_BootEncryptionIo

#include "Platform.h"

BiosResult ReadEncryptedSectors (uint16 destSegment, uint16 destOffset, byte drive, uint64 sector, uint16 sectorCount);
BiosResult WriteEncryptedSectors (uint16 sourceSegment, uint16 sourceOffset, byte drive, uint64 sector, uint16 sectorCount);
static bool ReadWritePartiallyCoversEncryptedArea (const uint64 &sector, uint16 sectorCount);

#endif // TC_HEADER_Boot_BootEncryptionIo
