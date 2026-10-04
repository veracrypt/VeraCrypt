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

#include <errno.h>
#include "CoreServiceRequest.h"
#include "Platform/SerializerFactory.h"

namespace VeraCrypt
{
	void CoreServiceRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		Serializer sr (stream);
		sr.Deserialize ("AdminPassword", AdminPassword);
		ApplicationExecutablePath = sr.DeserializeWString ("ApplicationExecutablePath");
		sr.Deserialize ("ElevateUserPrivileges", ElevateUserPrivileges);
		sr.Deserialize ("FastElevation", FastElevation);
		sr.Deserialize ("UserEnvPATH", UserEnvPATH);
		sr.Deserialize ("UseDummySudoPassword", UseDummySudoPassword);
		sr.Deserialize ("AllowInsecureMount", AllowInsecureMount);
	}

	void CoreServiceRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		Serializer sr (stream);
		sr.Serialize ("AdminPassword", AdminPassword);
		sr.Serialize ("ApplicationExecutablePath", wstring (ApplicationExecutablePath));
		sr.Serialize ("ElevateUserPrivileges", ElevateUserPrivileges);
		sr.Serialize ("FastElevation", FastElevation);
		sr.Serialize ("UserEnvPATH", UserEnvPATH);
		sr.Serialize ("UseDummySudoPassword", UseDummySudoPassword);
		sr.Serialize ("AllowInsecureMount", AllowInsecureMount);
	}

	// CheckFilesystemRequest
	void CheckFilesystemRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
		sr.Deserialize ("Repair", Repair);
	}

	bool CheckFilesystemRequest::RequiresElevation () const
	{
#ifdef TC_MACOSX
		return false;
#endif
		return !Core->HasAdminPrivileges();
	}

	void CheckFilesystemRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		MountedVolumeInfo->Serialize (stream);
		sr.Serialize ("Repair", Repair);
	}

	// DismountFilesystemRequest
	void DismountFilesystemRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		sr.Deserialize ("Force", Force);
		MountPoint = sr.DeserializeWString ("MountPoint");
	}

	bool DismountFilesystemRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void DismountFilesystemRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("Force", Force);
		sr.Serialize ("MountPoint", wstring (MountPoint));
	}

	// DismountVolumeRequest
	void DismountVolumeRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		sr.Deserialize ("IgnoreOpenFiles", IgnoreOpenFiles);
		sr.Deserialize ("SyncVolumeInfo", SyncVolumeInfo);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
	}

	bool DismountVolumeRequest::RequiresElevation () const
	{
#ifdef TC_MACOSX
		if (MountedVolumeInfo->Path.IsDevice())
		{
			try
			{
				File file;
				file.Open (MountedVolumeInfo->Path, File::OpenReadWrite);
			}
			catch (...)
			{
				return true;
			}
		}

		return false;
#endif
		return !Core->HasAdminPrivileges();
	}

	void DismountVolumeRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("IgnoreOpenFiles", IgnoreOpenFiles);
		sr.Serialize ("SyncVolumeInfo", SyncVolumeInfo);
		MountedVolumeInfo->Serialize (stream);
	}

#ifdef TC_LINUX
	// EmergencyDismountVolumeRequest
	void EmergencyDismountVolumeRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		MountedVolumeInfo = Serializable::DeserializeNew <VolumeInfo> (stream);
	}

	bool EmergencyDismountVolumeRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void EmergencyDismountVolumeRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		MountedVolumeInfo->Serialize (stream);
	}
#endif

	// GetDeviceSectorSizeRequest
	void GetDeviceSectorSizeRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		Path = sr.DeserializeWString ("Path");
	}

	bool GetDeviceSectorSizeRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void GetDeviceSectorSizeRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("Path", wstring (Path));
	}

	// GetDeviceSizeRequest
	void GetDeviceSizeRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		Path = sr.DeserializeWString ("Path");
	}

	bool GetDeviceSizeRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void GetDeviceSizeRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("Path", wstring (Path));
	}

	// GetHostDevicesRequest
	void GetHostDevicesRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		sr.Deserialize ("PathListOnly", PathListOnly);
	}

	bool GetHostDevicesRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void GetHostDevicesRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("PathListOnly", PathListOnly);
	}

	// ExitRequest
	void ExitRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
	}

	void ExitRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
	}

#ifdef TC_MACOSX
	// ExecuteMacOSXAPFSFormatterRequest
	void ExecuteMacOSXAPFSFormatterRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		Device = sr.DeserializeWString ("Device");
		sr.Deserialize ("OwnerGroupId", OwnerGroupId);
		sr.Deserialize ("OwnerUserId", OwnerUserId);
	}

	bool ExecuteMacOSXAPFSFormatterRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void ExecuteMacOSXAPFSFormatterRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("Device", wstring (Device));
		sr.Serialize ("OwnerGroupId", OwnerGroupId);
		sr.Serialize ("OwnerUserId", OwnerUserId);
	}
#endif

#ifdef TC_OPENBSD
	// ExecuteOpenBSDFFSFormatterRequest
	void ExecuteOpenBSDFFSFormatterRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		Device = sr.DeserializeWString ("Device");
		sr.Deserialize ("OwnerGroupId", OwnerGroupId);
		sr.Deserialize ("OwnerUserId", OwnerUserId);
	}

	bool ExecuteOpenBSDFFSFormatterRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void ExecuteOpenBSDFFSFormatterRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		sr.Serialize ("Device", wstring (Device));
		sr.Serialize ("OwnerGroupId", OwnerGroupId);
		sr.Serialize ("OwnerUserId", OwnerUserId);
	}
#endif

	// MountVolumeRequest
	void MountVolumeRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);
		DeserializedOptions = Serializable::DeserializeNew <MountOptions> (stream);
		Options = DeserializedOptions.get();
	}

	bool MountVolumeRequest::RequiresElevation () const
	{
#ifdef TC_MACOSX
		if (Options->Path->IsDevice())
		{
			try
			{
				File file;
				file.Open (*Options->Path, File::OpenReadWrite);
			}
			catch (...)
			{
				return true;
			}
		}

		return false;
#endif
		return !Core->HasAdminPrivileges();
	}

	void MountVolumeRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);
		Options->Serialize (stream);
	}

	// SetFileOwnerRequest
	void SetFileOwnerRequest::DeserializeData (shared_ptr <Stream> stream)
	{
		CoreServiceRequest::DeserializeData (stream);
		Serializer sr (stream);

		uint64 owner;
		sr.Deserialize ("Owner", owner);
		Owner.SystemId = static_cast <uid_t> (owner);

		Path = sr.DeserializeWString ("Path");
	}

	bool SetFileOwnerRequest::RequiresElevation () const
	{
		return !Core->HasAdminPrivileges();
	}

	void SetFileOwnerRequest::SerializeData (shared_ptr <Stream> stream) const
	{
		CoreServiceRequest::SerializeData (stream);
		Serializer sr (stream);

		uint64 owner = Owner.SystemId;
		sr.Serialize ("Owner", owner);

		sr.Serialize ("Path", wstring (Path));
	}


	TC_SERIALIZER_FACTORY_ADD_CLASS (CoreServiceRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (CheckFilesystemRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (DismountFilesystemRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (DismountVolumeRequest);
#ifdef TC_LINUX
	TC_SERIALIZER_FACTORY_ADD_CLASS (EmergencyDismountVolumeRequest);
#endif
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExitRequest);
#ifdef TC_MACOSX
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExecuteMacOSXAPFSFormatterRequest);
#endif
#ifdef TC_OPENBSD
	TC_SERIALIZER_FACTORY_ADD_CLASS (ExecuteOpenBSDFFSFormatterRequest);
#endif
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetDeviceSectorSizeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetDeviceSizeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (GetHostDevicesRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (MountVolumeRequest);
	TC_SERIALIZER_FACTORY_ADD_CLASS (SetFileOwnerRequest);
}
