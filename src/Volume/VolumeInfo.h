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

	// Unreadable candidates are not VolumeInfo objects: their slot and identity
	// are unknown. Callers may act on verified volumes without claiming that an
	// incomplete inventory proves absence (or that every volume was unmounted).
	struct VolumeDiscoveryResult
	{
		VolumeInfoList Volumes;
		list <DirectoryPath> UnresolvedMounts;
		bool IsComplete () const { return UnresolvedMounts.empty(); }
	};

	class VolumeInfo : public Serializable
	{
	public:
		VolumeInfo () : Discovery (DiscoveryUnknown) { }
		virtual ~VolumeInfo () { }

		TC_SERIALIZABLE (VolumeInfo);
		static bool FirstVolumeMountedAfterSecond (shared_ptr <VolumeInfo> first, shared_ptr <VolumeInfo> second);
		void Set (const Volume &volume);
		shared_ptr <VolumeInfo> Clone () const { return shared_ptr <VolumeInfo> (new VolumeInfo (*this)); }

		// Local discovery hints only. Never serialized into the legacy control
		// file or used as authority for a destructive operation. A GUI-retained
		// entry whose control metadata is now unreadable has no current counters.
		enum DiscoveryState { DiscoveryUnknown, ImageAttached, ImageAbsent, ControlUnavailable };
		DiscoveryState Discovery;

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
		VolumeInfo (const VolumeInfo &) = default;
		VolumeInfo &operator= (const VolumeInfo &);
	};
}

#endif // TC_HEADER_Volume_VolumeInfo
