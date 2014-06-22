/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Serializer
#define TC_HEADER_Platform_Serializer

#include "PlatformBase.h"
#include "Buffer.h"
#include "SharedPtr.h"
#include "Stream.h"

namespace VeraCrypt
{
	class Serializer
	{
	public:
		Serializer (shared_ptr <Stream> stream) : DataStream (stream) { }
		virtual ~Serializer () { }

		void Deserialize (const string &name, bool &data);
		void Deserialize (const string &name, byte &data);
		void Deserialize (const string &name, int32 &data);
		void Deserialize (const string &name, int64 &data);
		void Deserialize (const string &name, uint32 &data);
		void Deserialize (const string &name, uint64 &data);
		void Deserialize (const string &name, string &data);
		void Deserialize (const string &name, wstring &data);
		void Deserialize (const string &name, const BufferPtr &data);
		bool DeserializeBool (const string &name);
		int32 DeserializeInt32 (const string &name);
		int64 DeserializeInt64 (const string &name);
		uint32 DeserializeUInt32 (const string &name);
		uint64 DeserializeUInt64 (const string &name);
		string DeserializeString (const string &name);
		list <string> DeserializeStringList (const string &name);
		wstring DeserializeWString (const string &name);
		list <wstring> DeserializeWStringList (const string &name);
		void Serialize (const string &name, bool data);
		void Serialize (const string &name, byte data);
		void Serialize (const string &name, const char *data);
		void Serialize (const string &name, int32 data);
		void Serialize (const string &name, int64 data);
		void Serialize (const string &name, uint32 data);
		void Serialize (const string &name, uint64 data);
		void Serialize (const string &name, const string &data);
		void Serialize (const string &name, const wstring &data);
		void Serialize (const string &name, const wchar_t *data);
		void Serialize (const string &name, const list <string> &stringList);
		void Serialize (const string &name, const list <wstring> &stringList);
		void Serialize (const string &name, const ConstBufferPtr &data);

	protected:
		template <typename T> T Deserialize ();
		string DeserializeString ();
		wstring DeserializeWString ();
		template <typename T> void Serialize (T data);
		void SerializeString (const string &data);
		void SerializeWString (const wstring &data);
		void ValidateName (const string &name);

		shared_ptr <Stream> DataStream;

	private:
		Serializer (const Serializer &);
		Serializer &operator= (const Serializer &);
	};
}

#endif // TC_HEADER_Platform_Serializer
