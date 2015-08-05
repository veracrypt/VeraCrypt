/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "HostDevice.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	void HostDevice::Deserialize (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		MountPoint = sr.DeserializeWString ("MountPoint");
		sr.Deserialize ("Name", Name);
		Path = sr.DeserializeWString ("Path");
		sr.Deserialize ("Removable", Removable);
		sr.Deserialize ("Size", Size);
		sr.Deserialize ("SystemNumber", SystemNumber);

		uint32 partitionCount;
		sr.Deserialize ("Partitions", partitionCount);
		for (uint32 i = 0; i < partitionCount; i++)
			Partitions.push_back (Serializable::DeserializeNew <HostDevice> (stream));
	}

	void HostDevice::Serialize (shared_ptr <Stream> stream) const
	{
		Serializable::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("MountPoint", wstring (MountPoint));
		sr.Serialize ("Name", Name);
		sr.Serialize ("Path", wstring (Path));
		sr.Serialize ("Removable", Removable);
		sr.Serialize ("Size", Size);
		sr.Serialize ("SystemNumber", SystemNumber);
		
		sr.Serialize ("Partitions", (uint32) Partitions.size());
		foreach_ref (const HostDevice &partition, Partitions)
			partition.Serialize (stream);
	}

	TC_SERIALIZER_FACTORY_ADD_CLASS (HostDevice);
}
