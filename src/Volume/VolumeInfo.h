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

#ifndef TC_HEADER_Volume_VolumeInfo
#define TC_HEADER_Volume_VolumeInfo

#include "Platform/Platform.h"
#include "Platform/Serializable.h"
#include "Volume/Volume.h"
#include "Volume/VolumeSlot.h"

namespace VeraCrypt
{
	class VolumeInfo;
	typedef list < shared_ptr <VolumeInfo> > VolumeInfoList;

	class VolumeInfo : public Serializable
	{
	public:
		VolumeInfo () { }
		virtual ~VolumeInfo () { }

		TC_SERIALIZABLE (VolumeInfo);
		static bool FirstVolumeMountedAfterSecond (shared_ptr <VolumeInfo> first, shared_ptr <VolumeInfo> second);
		void Set (const Volume &volume);

		// Modifying this structure can introduce incompatibility with previous versions
		DirectoryPath AuxMountPoint;
		uint32 EncryptionAlgorithmBlockSize;
		uint32 EncryptionAlgorithmKeySize;
		uint32 EncryptionAlgorithmMinBlockSize;
		wstring EncryptionAlgorithmName;
		wstring EncryptionModeName;
		VolumeTime HeaderCreationTime;
		bool HiddenVolumeProtectionTriggered;
		DevicePath LoopDevice;
		uint32 MinRequiredProgramVersion;
		DirectoryPath MountPoint;
		VolumePath Path;
		uint32 Pkcs5IterationCount;
		wstring Pkcs5PrfName;
		uint32 ProgramVersion;
		VolumeProtection::Enum Protection;
		uint64 SerialInstanceNumber;
		uint64 Size;
		VolumeSlotNumber SlotNumber;
		bool SystemEncryption;
		uint64 TopWriteOffset;
		uint64 TotalDataRead;
		uint64 TotalDataWritten;
		VolumeType::Enum Type;
		DevicePath VirtualDevice;
		VolumeTime VolumeCreationTime;
		int Pim;
		bool MasterKeyVulnerable;
	private:
		VolumeInfo (const VolumeInfo &);
		VolumeInfo &operator= (const VolumeInfo &);
	};
}

#endif // TC_HEADER_Volume_VolumeInfo
