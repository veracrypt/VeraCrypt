/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <algorithm>
#include "Exception.h"
#include "ForEach.h"
#include "Memory.h"
#include "Serializer.h"

namespace VeraCrypt
{
	SerializationScope::SerializationScope (shared_ptr <Stream> stream) : DataStream (stream)
	{
		if (!DataStream || DataStream->SerializationDepth >= Serializer::MaxNestingDepth)
			throw ParameterIncorrect (SRC_POS);
		++DataStream->SerializationDepth;
	}

	SerializationScope::~SerializationScope ()
	{
		--DataStream->SerializationDepth;
	}

	Serializer::Serializer (shared_ptr <Stream> stream) : DataStream (stream)
	{
		if (!DataStream)
			throw ParameterIncorrect (SRC_POS);
	}

	template <typename T>
	T Serializer::Deserialize ()
	{
		uint64 size;
		DataStream->ReadCompleteBuffer (BufferPtr ((uint8 *) &size, sizeof (size)));

		if (Endian::Big (size) != sizeof (T))
			throw ParameterIncorrect (SRC_POS);

		T data;
		DataStream->ReadCompleteBuffer (BufferPtr ((uint8 *) &data, sizeof (data)));

		return Endian::Big (data);
	}

	void Serializer::Deserialize (const string &name, bool &data)
	{
		ValidateName (name);
		data = Deserialize <uint8> () == 1;
	}

	void Serializer::Deserialize (const string &name, uint8 &data)
	{
		ValidateName (name);
		data = Deserialize <uint8> ();
	}

	void Serializer::Deserialize (const string &name, int32 &data)
	{
		ValidateName (name);
		data = (int32) Deserialize <uint32> ();
	}

	void Serializer::Deserialize (const string &name, int64 &data)
	{
		ValidateName (name);
		data = (int64) Deserialize <uint64> ();
	}

	void Serializer::Deserialize (const string &name, uint32 &data)
	{
		ValidateName (name);
		data = Deserialize <uint32> ();
	}

	void Serializer::Deserialize (const string &name, uint64 &data)
	{
		ValidateName (name);
		data = Deserialize <uint64> ();
	}

	void Serializer::Deserialize (const string &name, string &data)
	{
		ValidateName (name);
		data = DeserializeString ();
	}

	void Serializer::Deserialize (const string &name, wstring &data)
	{
		ValidateName (name);
		data = DeserializeWString ();
	}

	void Serializer::Deserialize (const string &name, const BufferPtr &data)
	{
		ValidateName (name);

		uint64 size = Deserialize <uint64> ();
		if (data.Size() != size)
			throw ParameterIncorrect (SRC_POS);

		DataStream->ReadCompleteBuffer (data);
	}

	bool Serializer::DeserializeBool (const string &name)
	{
		bool data;
		Deserialize (name, data);
		return data;
	}

	int32 Serializer::DeserializeInt32 (const string &name)
	{
		ValidateName (name);
		return Deserialize <uint32> ();
	}

	int64 Serializer::DeserializeInt64 (const string &name)
	{
		ValidateName (name);
		return Deserialize <uint64> ();
	}

	uint32 Serializer::DeserializeUInt32 (const string &name)
	{
		ValidateName (name);
		return Deserialize <uint32> ();
	}

	uint64 Serializer::DeserializeUInt64 (const string &name)
	{
		ValidateName (name);
		return Deserialize <uint64> ();
	}

	string Serializer::DeserializeString ()
	{
		uint64 size = Deserialize <uint64> ();
		if (size == 0 || size > MaxStringSize)
			throw ParameterIncorrect (SRC_POS);

		vector <char> data ((size_t) size);
		DataStream->ReadCompleteBuffer (BufferPtr ((uint8 *) &data[0], (size_t) size));
		if (data.back() != 0 || find (data.begin(), data.end() - 1, '\0') != data.end() - 1)
			throw ParameterIncorrect (SRC_POS);

		return string (&data[0], data.size() - 1);
	}

	string Serializer::DeserializeString (const string &name)
	{
		ValidateName (name);
		return DeserializeString ();
	}

	list <string> Serializer::DeserializeStringList (const string &name)
	{
		ValidateName (name);
		list <string> deserializedList;
		uint64 listSize = Deserialize <uint64> ();
		ValidateCollectionSize (listSize);

		for (uint64 i = 0; i < listSize; i++)
			deserializedList.push_back (DeserializeString ());

		return deserializedList;
	}

	wstring Serializer::DeserializeWString ()
	{
		uint64 size = Deserialize <uint64> ();
		if (size == 0 || size > MaxStringSize || size % sizeof (wchar_t) != 0)
			throw ParameterIncorrect (SRC_POS);

		vector <wchar_t> data ((size_t) size / sizeof (wchar_t));
		DataStream->ReadCompleteBuffer (BufferPtr ((uint8 *) &data[0], (size_t) size));
		if (data.back() != 0 || find (data.begin(), data.end() - 1, L'\0') != data.end() - 1)
			throw ParameterIncorrect (SRC_POS);

		return wstring (&data[0], data.size() - 1);
	}

	list <wstring> Serializer::DeserializeWStringList (const string &name)
	{
		ValidateName (name);
		list <wstring> deserializedList;
		uint64 listSize = Deserialize <uint64> ();
		ValidateCollectionSize (listSize);

		for (uint64 i = 0; i < listSize; i++)
			deserializedList.push_back (DeserializeWString ());

		return deserializedList;
	}

	wstring Serializer::DeserializeWString (const string &name)
	{
		ValidateName (name);
		return DeserializeWString ();
	}

	void Serializer::ValidateCollectionSize (uint64 size)
	{
		if (size > MaxCollectionSize)
			throw ParameterIncorrect (SRC_POS);
	}

	template <typename T>
	void Serializer::Serialize (T data)
	{
		uint64 size = Endian::Big (uint64 (sizeof (data)));
		DataStream->Write (ConstBufferPtr ((uint8 *) &size, sizeof (size)));

		data = Endian::Big (data);
		DataStream->Write (ConstBufferPtr ((uint8 *) &data, sizeof (data)));
	}

	void Serializer::Serialize (const string &name, bool data)
	{
		SerializeString (name);
		uint8 d = data ? 1 : 0;
		Serialize (d);
	}

	void Serializer::Serialize (const string &name, uint8 data)
	{
		SerializeString (name);
		Serialize (data);
	}

	void Serializer::Serialize (const string &name, const char *data)
	{
		Serialize (name, string (data));
	}

	void Serializer::Serialize (const string &name, int32 data)
	{
		SerializeString (name);
		Serialize ((uint32) data);
	}

	void Serializer::Serialize (const string &name, int64 data)
	{
		SerializeString (name);
		Serialize ((uint64) data);
	}

	void Serializer::Serialize (const string &name, uint32 data)
	{
		SerializeString (name);
		Serialize (data);
	}

	void Serializer::Serialize (const string &name, uint64 data)
	{
		SerializeString (name);
		Serialize (data);
	}

	void Serializer::Serialize (const string &name, const string &data)
	{
		SerializeString (name);
		SerializeString (data);
	}

	void Serializer::Serialize (const string &name, const wchar_t *data)
	{
		Serialize (name, wstring (data));
	}

	void Serializer::Serialize (const string &name, const wstring &data)
	{
		SerializeString (name);
		SerializeWString (data);
	}

	void Serializer::Serialize (const string &name, const list <string> &stringList)
	{
		ValidateCollectionSize (stringList.size());
		SerializeString (name);

		uint64 listSize = stringList.size();
		Serialize (listSize);

		foreach (const string &item, stringList)
			SerializeString (item);
	}

	void Serializer::Serialize (const string &name, const list <wstring> &stringList)
	{
		ValidateCollectionSize (stringList.size());
		SerializeString (name);

		uint64 listSize = stringList.size();
		Serialize (listSize);

		foreach (const wstring &item, stringList)
			SerializeWString (item);
	}

	void Serializer::Serialize (const string &name, const ConstBufferPtr &data)
	{
		SerializeString (name);

		uint64 size = data.Size();
		Serialize (size);

		DataStream->Write (data);
	}

	void Serializer::SerializeString (const string &data)
	{
		// Embedded NULs would be interpreted differently by C-string consumers.
		if (data.size() >= MaxStringSize || data.find ('\0') != string::npos)
			throw ParameterIncorrect (SRC_POS);

		Serialize ((uint64) data.size() + 1);
		DataStream->Write (ConstBufferPtr ((const uint8 *) data.c_str(), data.size() + 1));
	}

	void Serializer::SerializeWString (const wstring &data)
	{
		if (data.size() >= MaxStringSize / sizeof (wchar_t) || data.find (L'\0') != wstring::npos)
			throw ParameterIncorrect (SRC_POS);

		uint64 size = ((uint64) data.size() + 1) * sizeof (wchar_t);
		Serialize (size);
		DataStream->Write (ConstBufferPtr ((const uint8 *) data.c_str(), (size_t) size));
	}

	void Serializer::ValidateName (const string &name)
	{
		string dName = DeserializeString();
		if (dName != name)
		{
			throw ParameterIncorrect (SRC_POS);
		}
	}
}
