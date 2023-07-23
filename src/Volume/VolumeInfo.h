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
		uint32 EncryptionAlgorithmBlockSize = 0;
		uint32 EncryptionAlgorithmKeySize = 0;
		uint32 EncryptionAlgorithmMinBlockSize = 0;
		wstring EncryptionAlgorithmName;
		wstring EncryptionModeName;
		VolumeTime HeaderCreationTime;
		bool HiddenVolumeProtectionTriggered = false;
		DevicePath LoopDevice;
		uint32 MinRequiredProgramVersion = 0;
		DirectoryPath MountPoint;
		VolumePath Path;
		uint32 Pkcs5IterationCount = 0;
		wstring Pkcs5PrfName;
		uint32 ProgramVersion = 0;
		VolumeProtection::Enum Protection;
		uint64 SerialInstanceNumber = 0;
		uint64 Size = 0;
		VolumeSlotNumber SlotNumber;
		bool SystemEncryption = false;
		uint64 TopWriteOffset = 0;
		uint64 TotalDataRead = 0;
		uint64 TotalDataWritten = 0;
		VolumeType::Enum Type = VolumeType::Unknown;
		DevicePath VirtualDevice;
		VolumeTime VolumeCreationTime;
		bool TrueCryptMode = false;
		int Pim = 0;

	private:
		VolumeInfo (const VolumeInfo &);
		VolumeInfo &operator= (const VolumeInfo &);
	};
}

#endif // TC_HEADER_Volume_VolumeInfo
