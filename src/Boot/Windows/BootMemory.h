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

#include "Platform.h"
#include "Bios.h"

#pragma pack(1)

struct BiosMemoryMapEntry
{
	uint64 BaseAddress;
	uint64 Length;
	uint32 Type;
};

#pragma pack()

bool GetFirstBiosMemoryMapEntry (BiosMemoryMapEntry &entry);
bool GetNextBiosMemoryMapEntry (BiosMemoryMapEntry &entry);
