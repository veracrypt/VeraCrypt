/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Common.h"

#ifndef CACHE_SIZE
/* WARNING: Changing this value might not be safe (some items may be hard coded for 4)! Inspection necessary. */
#define CACHE_SIZE 4	
#endif

extern int cacheEmpty;

void AddPasswordToCache (Password *password);
int ReadVolumeHeaderWCache (BOOL bBoot, BOOL bCache, char *header, Password *password, PCRYPTO_INFO *retInfo);
void WipeCache (void);
