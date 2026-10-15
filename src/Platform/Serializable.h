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

#ifndef TC_HEADER_Platform_Serializable
#define TC_HEADER_Platform_Serializable

#include <stdexcept>
#include "PlatformBase.h"
#include "ForEach.h"
#include "Serializer.h"
#include "SerializerFactory.h"

namespace VeraCrypt
{
	class Serializable
	{
	public:
		virtual ~Serializable () { }

		// Non-virtual entry points enforce nesting limits for every object. Derived
		// classes implement only the field operations below; Serialize owns the header.
		void Deserialize (shared_ptr <Stream> stream);
		static string DeserializeHeader (shared_ptr <Stream> stream);
		typedef bool (*TypeValidator) (const Serializable &object);
		static Serializable *DeserializeNew (shared_ptr <Stream> stream, TypeValidator isExpectedType = nullptr);

		template <class T>
		static bool IsType (const Serializable &object)
		{
			return dynamic_cast <const T *> (&object) != nullptr;
		}

		template <class T>
		static shared_ptr <T> DeserializeNew (shared_ptr <Stream> stream)
		{
			return shared_ptr <T> (dynamic_cast <T *> (DeserializeNew (stream, &IsType <T>)));
		}

		template <class T>
		static void DeserializeList (shared_ptr <Stream> stream, list < shared_ptr <T> > &dataList)
		{
			SerializationScope scope (stream);
			if (DeserializeHeader (stream) != string ("list<") + SerializerFactory::GetName (typeid (T)) + ">")
				throw std::runtime_error (SRC_POS);

			Serializer sr (stream);
			uint64 listSize;
			sr.Deserialize ("ListSize", listSize);
			Serializer::ValidateCollectionSize (listSize);

			list < shared_ptr <T> > deserializedList;
			for (uint64 i = 0; i < listSize; i++)
				deserializedList.push_back (DeserializeNew <T> (stream));
			dataList.splice (dataList.end(), deserializedList);
		}

		void Serialize (shared_ptr <Stream> stream) const;

		template <class T>
		static void SerializeList (shared_ptr <Stream> stream, const list < shared_ptr <T> > &dataList)
		{
			Serializer::ValidateCollectionSize (dataList.size());
			SerializationScope scope (stream);
			Serializer sr (stream);
			SerializeHeader (sr, string ("list<") + SerializerFactory::GetName (typeid (T)) + ">");

			sr.Serialize ("ListSize", (uint64) dataList.size());
			foreach_ref (const T &item, dataList)
				item.Serialize (stream);
		}

		static void SerializeHeader (Serializer &serializer, const string &name);

	protected:
		Serializable () { }
		// Call base-class field operations here, never their public entry points.
		virtual void DeserializeData (shared_ptr <Stream> stream) = 0;
		virtual void SerializeData (shared_ptr <Stream> stream) const { }
	};
}

#define TC_SERIALIZABLE(TYPE) \
	static Serializable *GetNewSerializable () { return new TYPE(); } \
protected: \
	virtual void DeserializeData (shared_ptr <Stream> stream); \
	virtual void SerializeData (shared_ptr <Stream> stream) const; \
public:

#endif // TC_HEADER_Platform_Serializable
