/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Serializable
#define TC_HEADER_Platform_Serializable

#include <stdexcept>
#include "PlatformBase.h"
#include "ForEach.h"
#include "Serializer.h"
#include "SerializerFactory.h"

namespace TrueCrypt
{
	class Serializable
	{
	public:
		virtual ~Serializable () { }

		virtual void Deserialize (shared_ptr <Stream> stream) = 0;
		static string DeserializeHeader (shared_ptr <Stream> stream);
		static Serializable *DeserializeNew (shared_ptr <Stream> stream);
		
		template <class T> 
		static shared_ptr <T> DeserializeNew (shared_ptr <Stream> stream)
		{
			shared_ptr <T> p (dynamic_cast <T *> (DeserializeNew (stream)));
			if (!p)
				throw std::runtime_error (SRC_POS);
			return p;
		}

		template <class T> 
		static void DeserializeList (shared_ptr <Stream> stream, list < shared_ptr <T> > &dataList)
		{
			if (DeserializeHeader (stream) != string ("list<") + SerializerFactory::GetName (typeid (T)) + ">")
				throw std::runtime_error (SRC_POS);

			Serializer sr (stream);
			uint64 listSize;
			sr.Deserialize ("ListSize", listSize);

			for (size_t i = 0; i < listSize; i++)
			{
				shared_ptr <T> p (dynamic_cast <T *> (DeserializeNew (stream)));
				if (!p)
					throw std::runtime_error (SRC_POS);
				dataList.push_back (p);
			}
		}

		virtual void Serialize (shared_ptr <Stream> stream) const;

		template <class T>
		static void SerializeList (shared_ptr <Stream> stream, const list < shared_ptr <T> > &dataList)
		{
			Serializer sr (stream);
			SerializeHeader (sr, string ("list<") + SerializerFactory::GetName (typeid (T)) + ">");

			sr.Serialize ("ListSize", (uint64) dataList.size());
			foreach_ref (const T &item, dataList)
				item.Serialize (stream);
		}

		static void SerializeHeader (Serializer &serializer, const string &name);

	protected:
		Serializable () { }
	};
}

#define TC_SERIALIZABLE(TYPE) \
	static Serializable *GetNewSerializable () { return new TYPE(); } \
	virtual void Deserialize (shared_ptr <Stream> stream); \
	virtual void Serialize (shared_ptr <Stream> stream) const

#endif // TC_HEADER_Platform_Serializable
