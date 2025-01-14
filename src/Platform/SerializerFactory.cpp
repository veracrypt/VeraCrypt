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

#include <stdexcept>
#include "SerializerFactory.h"

namespace VeraCrypt
{
	void SerializerFactory::Deinitialize ()
	{
		if (--UseCount == 0)
		{
			delete NameToTypeMap;
			delete TypeToNameMap;
		}
	}

	string SerializerFactory::GetName (const type_info &typeInfo)
	{
		string typeName = StringConverter::GetTypeName (typeInfo);
		if (TypeToNameMap->find (typeName) == TypeToNameMap->end())
			throw std::runtime_error (SRC_POS);

		return (*TypeToNameMap)[typeName];
	}

	Serializable *SerializerFactory::GetNewSerializable (const string &typeName)
	{
		if (NameToTypeMap->find (typeName) == NameToTypeMap->end())
			throw std::runtime_error (SRC_POS);

		return (*NameToTypeMap)[typeName].GetNewPtr();
	}

	void SerializerFactory::Initialize ()
	{
		if (UseCount == 0)
		{
			NameToTypeMap = new map <string, SerializerFactory::MapEntry>;
			TypeToNameMap = new map <string, string>;
		}

		++UseCount;
	}

	map <string, SerializerFactory::MapEntry> *SerializerFactory::NameToTypeMap;
	map <string, string> *SerializerFactory::TypeToNameMap;
	int SerializerFactory::UseCount;
}
