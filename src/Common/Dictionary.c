/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "../Common/Dictionary.h"
#include <windows.h>
#include <map>
#include <string>

using namespace std;

static map <string, void *> StringKeyMap;
static map <int, void *> IntKeyMap;

static void *DataPool = NULL;
static size_t DataPoolSize = 0;


void AddDictionaryEntry (char *key, int intKey, void *value)
{
	try
	{
		if (key)
			StringKeyMap[key] = value;

		if (intKey != 0)
			IntKeyMap[intKey] = value;
	}
	catch (exception&) {}
}


void *GetDictionaryValue (const char *key)
{
	map <string, void *>::const_iterator i = StringKeyMap.find (key);

	if (i == StringKeyMap.end())
		return NULL;

	return i->second;
}


void *GetDictionaryValueByInt (int intKey)
{
	map <int, void *>::const_iterator i = IntKeyMap.find (intKey);

	if (i == IntKeyMap.end())
		return NULL;

	return i->second;
}


void *AddPoolData (void *data, size_t dataSize)
{
	if (DataPoolSize + dataSize > DATA_POOL_CAPACITY) return NULL;

	if (DataPool == NULL)
	{
		DataPool = malloc (DATA_POOL_CAPACITY);
		if (DataPool == NULL) return NULL;
	}

	memcpy ((BYTE *)DataPool + DataPoolSize, data, dataSize);

	// Ensure 32-bit alignment for next entries
	dataSize = (dataSize + 3) & (~(size_t)3);

	DataPoolSize += dataSize;
	return (BYTE *)DataPool + DataPoolSize - dataSize;
}


void ClearDictionaryPool ()
{
	DataPoolSize = 0;
	StringKeyMap.clear();
	IntKeyMap.clear();
}