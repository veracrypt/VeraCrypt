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

#include "CoreServiceResponse.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	// ElevatedServiceStartedResponse
	void ElevatedServiceStartedResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void ElevatedServiceStartedResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}

	// CheckFilesystemResponse
	void CheckFilesystemResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void CheckFilesystemResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}

	// DismountFilesystemResponse
	void DismountFilesystemResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void DismountFilesystemResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}

	// DismountVolumeResponse
	void DismountVolumeResponse::DeserializeData (shared_ptr <Stream> stream)
	{
		DismountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
	}

	void DismountVolumeResponse::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		DismountedVolumeInfo->Serialize (stream);
	}

	// GetDeviceSectorSizeResponse
	void GetDeviceSectorSizeResponse::DeserializeData (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		sr.Deserialize ("Size", Size);
	}

	void GetDeviceSectorSizeResponse::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		sr.Serialize ("Size", Size);
	}

	// GetDeviceSizeResponse
	void GetDeviceSizeResponse::DeserializeData (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		sr.Deserialize ("Size", Size);
	}

	void GetDeviceSizeResponse::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		sr.Serialize ("Size", Size);
	}

	// GetHostDevicesResponse
	void GetHostDevicesResponse::DeserializeData (shared_ptr <Stream> stream)
	{
		Serializable::DeserializeList (stream, HostDevices);
	}

	void GetHostDevicesResponse::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializable::SerializeList (stream, HostDevices);
	}

#ifdef TC_MACOSX
	// ExecuteMacOSXAPFSFormatterResponse
	void ExecuteMacOSXAPFSFormatterResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void ExecuteMacOSXAPFSFormatterResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}
#endif

#ifdef TC_OPENBSD
	// ExecuteOpenBSDFFSFormatterResponse
	void ExecuteOpenBSDFFSFormatterResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void ExecuteOpenBSDFFSFormatterResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}
#endif

	// MountVolumeResponse
	void MountVolumeResponse::DeserializeData (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
	}

	void MountVolumeResponse::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		MountedVolumeInfo->Serialize (stream);
	}

	// SetFileOwnerResponse
	void SetFileOwnerResponse::DeserializeData (shared_ptr <Stream> stream)
	{
	}

	void SetFileOwnerResponse::SerializeData (shared_ptr <Stream> stream) const
	{
	}

	TC_SERIALIZER_FACTORY_ADD_CLASS (ElevatedServiceStartedResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (CheckFilesystemResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (DismountFilesystemResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (DismountVolumeResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetDeviceSectorSizeResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetDeviceSizeResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetHostDevicesResponse);
#ifdef TC_MACOSX
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExecuteMacOSXAPFSFormatterResponse);
#endif
#ifdef TC_OPENBSD
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExecuteOpenBSDFFSFormatterResponse);
#endif
	TC_SERIALIZER_FACTORY_ADD_CLASS (MountVolumeResponse);
	TC_SERIALIZER_FACTORY_ADD_CLASS (SetFileOwnerResponse);
}
