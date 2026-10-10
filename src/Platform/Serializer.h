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

#ifndef TC_HEADER_Platform_Serializer
#define TC_HEADER_Platform_Serializer

#include "PlatformBase.h"
#include "Buffer.h"
#include "SharedPtr.h"
#include "Stream.h"

namespace VeraCrypt
{
	// An object or object-list operation retains this scope across all its fields.
	// Sibling operations and separate streams have independent nesting limits.
	class SerializationScope
	{
	public:
		explicit SerializationScope (shared_ptr <Stream> stream);
		~SerializationScope ();

	private:
		shared_ptr <Stream> DataStream;
		SerializationScope (const SerializationScope &);
		SerializationScope &operator= (const SerializationScope &);
	};

	class Serializer
	{
	public:
		Serializer (shared_ptr <Stream> stream);
		virtual ~Serializer () { }

		// Wire sizes include the terminating NUL. The same limits apply in both directions.
		static const uint64 MaxCollectionSize = 65536;
		static const uint64 MaxStringSize = 1024 * 1024;
		static const unsigned int MaxNestingDepth = 64;

		void Deserialize (const string &name, bool &data);
		void Deserialize (const string &name, uint8 &data);
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
		static void ValidateCollectionSize (uint64 size);
		void Serialize (const string &name, bool data);
		void Serialize (const string &name, uint8 data);
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
