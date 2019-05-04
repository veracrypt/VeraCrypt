/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Serializable.h"
#include "SerializerFactory.h"

namespace VeraCrypt
{
	string Serializable::DeserializeHeader (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		return sr.DeserializeString ("SerializableName");
	}

	Serializable *Serializable::DeserializeNew (shared_ptr <Stream> stream)
	{
		string name = Serializable::DeserializeHeader (stream);
		Serializable *serializable = SerializerFactory::GetNewSerializable (name);
		serializable->Deserialize (stream);

		return serializable;
	}

	void Serializable::Serialize (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		Serializable::SerializeHeader (sr, SerializerFactory::GetName (typeid (*this)));
	}

	void Serializable::SerializeHeader (Serializer &serializer, const string &name)
	{
		serializer.Serialize ("SerializableName", name);
	}
}
