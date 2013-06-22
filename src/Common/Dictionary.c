/*
 Copyright (c) 2005-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
	if (key)
		StringKeyMap[key] = value;

	if (intKey != 0)
		IntKeyMap[intKey] = value;
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