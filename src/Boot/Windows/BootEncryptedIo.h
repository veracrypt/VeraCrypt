/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Boot_BootEncryptionIo
#define TC_HEADER_Boot_BootEncryptionIo

#include "Platform.h"

BiosResult ReadEncryptedSectors (uint16 destSegment, uint16 destOffset, byte drive, uint64 sector, uint16 sectorCount);
BiosResult WriteEncryptedSectors (uint16 sourceSegment, uint16 sourceOffset, byte drive, uint64 sector, uint16 sectorCount);
static bool ReadWritePartiallyCoversEncryptedArea (const uint64 &sector, uint16 sectorCount);

#endif // TC_HEADER_Boot_BootEncryptionIo
