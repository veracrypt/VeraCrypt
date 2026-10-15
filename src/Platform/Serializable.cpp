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

#include "Exception.h"
#include "Serializable.h"
#include "SerializerFactory.h"

namespace VeraCrypt
{
	void Serializable::Deserialize (shared_ptr <Stream> stream)
	{
		SerializationScope scope (stream);
		DeserializeData (stream);
	}

	string Serializable::DeserializeHeader (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		return sr.DeserializeString ("SerializableName");
	}

	Serializable *Serializable::DeserializeNew (shared_ptr <Stream> stream, TypeValidator isExpectedType)
	{
		string name = Serializable::DeserializeHeader (stream);
		unique_ptr <Serializable> serializable (SerializerFactory::GetNewSerializable (name));
		// Allow legitimate subtypes, but never run an unexpected object's parser.
		if (isExpectedType && !isExpectedType (*serializable))
			throw ParameterIncorrect (SRC_POS);
		serializable->Deserialize (stream);

		return serializable.release();
	}

	void Serializable::Serialize (shared_ptr <Stream> stream) const
	{
		SerializationScope scope (stream);
		Serializer sr (stream);
		Serializable::SerializeHeader (sr, SerializerFactory::GetName (typeid (*this)));
		SerializeData (stream);
	}

	void Serializable::SerializeHeader (Serializer &serializer, const string &name)
	{
		serializer.Serialize ("SerializableName", name);
	}
}
