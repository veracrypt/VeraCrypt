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

#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DATA_POOL_CAPACITY 1000000

void AddDictionaryEntry (char *key, int intKey, void *value);
void *GetDictionaryValue (const char *key);
void *GetDictionaryValueByInt (int intKey);
void *AddPoolData (void *data, size_t dataSize);
void ClearDictionaryPool ();

#ifdef __cplusplus
}
#endif

#endif
