/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Exception.h"
#include "ForEach.h"
#include "Memory.h"
#include "Serializer.h"

namespace TrueCrypt
{
	template <typename T>
	T Serializer::Deserialize ()
	{
		uint64 size;
		DataStream->ReadCompleteBuffer (BufferPtr ((byte *) &size, sizeof (size)));
		
		if (Endian::Big (size) != sizeof (T))
			throw ParameterIncorrect (SRC_POS);

		T data;
		DataStream->ReadCompleteBuffer (BufferPtr ((byte *) &data, sizeof (data)));

		return Endian::Big (data);
	}

	void Serializer::Deserialize (const string &name, bool &data)
	{
		ValidateName (name);
		data = Deserialize <byte> () == 1;
	}

	void Serializer::Deserialize (const string &name, byte &data)
	{
		ValidateName (name);
		data = Deserialize <byte> ();
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

		vector <char> data ((size_t) size);
		DataStream->ReadCompleteBuffer (BufferPtr ((byte *) &data[0], (size_t) size));

		return string (&data[0]);
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

		for (size_t i = 0; i < listSize; i++)
			deserializedList.push_back (DeserializeString ());

		return deserializedList;
	}

	wstring Serializer::DeserializeWString ()
	{
		uint64 size = Deserialize <uint64> ();

		vector <wchar_t> data ((size_t) size / sizeof (wchar_t));
		DataStream->ReadCompleteBuffer (BufferPtr ((byte *) &data[0], (size_t) size));

		return wstring (&data[0]);
	}

	list <wstring> Serializer::DeserializeWStringList (const string &name)
	{
		ValidateName (name);
		list <wstring> deserializedList;
		uint64 listSize = Deserialize <uint64> ();

		for (size_t i = 0; i < listSize; i++)
			deserializedList.push_back (DeserializeWString ());

		return deserializedList;
	}

	wstring Serializer::DeserializeWString (const string &name)
	{
		ValidateName (name);
		return DeserializeWString ();
	}

	template <typename T>
	void Serializer::Serialize (T data)
	{
		uint64 size = Endian::Big (uint64 (sizeof (data)));
		DataStream->Write (ConstBufferPtr ((byte *) &size, sizeof (size)));

		data = Endian::Big (data);
		DataStream->Write (ConstBufferPtr ((byte *) &data, sizeof (data)));
	}

	void Serializer::Serialize (const string &name, bool data)
	{
		SerializeString (name);
		byte d = data ? 1 : 0;
		Serialize (d);
	}

	void Serializer::Serialize (const string &name, byte data)
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
		SerializeString (name);
		
		uint64 listSize = stringList.size();
		Serialize (listSize);

		foreach (const string &item, stringList)
			SerializeString (item);
	}

	void Serializer::Serialize (const string &name, const list <wstring> &stringList)
	{
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
		Serialize ((uint64) data.size() + 1);
		DataStream->Write (ConstBufferPtr ((byte *) (data.data() ? data.data() : data.c_str()), data.size() + 1));
	}

	void Serializer::SerializeWString (const wstring &data)
	{
		uint64 size = (data.size() + 1) * sizeof (wchar_t);
		Serialize (size);
		DataStream->Write (ConstBufferPtr ((byte *) (data.data() ? data.data() : data.c_str()), (size_t) size));
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
