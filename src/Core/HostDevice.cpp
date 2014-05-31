/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "HostDevice.h"
#include "Platform/SerializerFactory.h"

namespace TrueCrypt
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
