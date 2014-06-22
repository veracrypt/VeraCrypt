/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Volume_Volume
#define TC_HEADER_Volume_Volume

#include "Platform/Platform.h"
#include "Platform/StringConverter.h"
#include "EncryptionAlgorithm.h"
#include "EncryptionMode.h"
#include "Keyfile.h"
#include "VolumePassword.h"
#include "VolumeException.h"
#include "VolumeLayout.h"

namespace VeraCrypt
{
	class VolumePath
	{
	public:
		VolumePath () { }
		VolumePath (const wstring &path) { Data = path; }
		VolumePath (const FilesystemPath &path) { Data = path; }

		bool operator== (const VolumePath &other) const { return Data == other.Data; }
		bool operator!= (const VolumePath &other) const { return Data != other.Data; }
		operator FilesystemPath () const { return FilesystemPath (Data); }
		operator string () const { return StringConverter::ToSingle (Data); }
		operator wstring () const { return Data; }

		bool IsDevice () const { return FilesystemPath (Data).IsBlockDevice() || FilesystemPath (Data).IsCharacterDevice(); }
		bool IsEmpty () const { return Data.empty(); }

	protected:
		wstring Data;
	};

	typedef list <VolumePath> VolumePathList;

	struct VolumeHostType
	{
		enum Enum
		{
			Unknown,
			File,
			Device
		};
	};

	struct VolumeProtection
	{
		enum Enum
		{
			None,
			ReadOnly,
			HiddenVolumeReadOnly
		};
	};

	class Volume
	{
	public:
		Volume ();
		virtual ~Volume ();

		void Close ();
		shared_ptr <EncryptionAlgorithm> GetEncryptionAlgorithm () const;
		shared_ptr <EncryptionMode> GetEncryptionMode () const;
		shared_ptr <File> GetFile () const { return VolumeFile; }
		shared_ptr <VolumeHeader> GetHeader () const { return Header; }
		uint64 GetHeaderCreationTime () const { return Header->GetHeaderCreationTime(); }
		uint64 GetHostSize () const { return VolumeHostSize; }
		shared_ptr <VolumeLayout> GetLayout () const { return Layout; }
		VolumePath GetPath () const { return VolumeFile->GetPath(); }
		VolumeProtection::Enum GetProtectionType () const { return Protection; }
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf () const { return Header->GetPkcs5Kdf(); }
		uint32 GetSaltSize () const { return Header->GetSaltSize(); }
		size_t GetSectorSize () const { return SectorSize; }
		uint64 GetSize () const { return VolumeDataSize; }
		uint64 GetTopWriteOffset () const { return TopWriteOffset; }
		uint64 GetTotalDataRead () const { return TotalDataRead; }
		uint64 GetTotalDataWritten () const { return TotalDataWritten; }
		VolumeType::Enum GetType () const { return Type; }
		uint64 GetVolumeCreationTime () const { return Header->GetVolumeCreationTime(); }
		bool IsHiddenVolumeProtectionTriggered () const { return HiddenVolumeProtectionTriggered; }
		bool IsInSystemEncryptionScope () const { return SystemEncryption; }
		void Open (const VolumePath &volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, VolumeProtection::Enum protection = VolumeProtection::None, shared_ptr <VolumePassword> protectionPassword = shared_ptr <VolumePassword> (), shared_ptr <KeyfileList> protectionKeyfiles = shared_ptr <KeyfileList> (), bool sharedAccessAllowed = false, VolumeType::Enum volumeType = VolumeType::Unknown, bool useBackupHeaders = false, bool partitionInSystemEncryptionScope = false);
		void Open (shared_ptr <File> volumeFile, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, VolumeProtection::Enum protection = VolumeProtection::None, shared_ptr <VolumePassword> protectionPassword = shared_ptr <VolumePassword> (), shared_ptr <KeyfileList> protectionKeyfiles = shared_ptr <KeyfileList> (), VolumeType::Enum volumeType = VolumeType::Unknown, bool useBackupHeaders = false, bool partitionInSystemEncryptionScope = false);
		void ReadSectors (const BufferPtr &buffer, uint64 byteOffset);
		void ReEncryptHeader (bool backupHeader, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf);
		void WriteSectors (const ConstBufferPtr &buffer, uint64 byteOffset);

	protected:
		void CheckProtectedRange (uint64 writeHostOffset, uint64 writeLength);
		void ValidateState () const;

		shared_ptr <EncryptionAlgorithm> EA;
		shared_ptr <VolumeHeader> Header;
		bool HiddenVolumeProtectionTriggered;
		shared_ptr <VolumeLayout> Layout;
		uint64 ProtectedRangeStart;
		uint64 ProtectedRangeEnd;
		VolumeProtection::Enum Protection;
		size_t SectorSize;
		bool SystemEncryption;
		VolumeType::Enum Type;
		shared_ptr <File> VolumeFile;
		uint64 VolumeHostSize;
		uint64 VolumeDataOffset; 
		uint64 VolumeDataSize;
		uint64 TopWriteOffset;
		uint64 TotalDataRead;
		uint64 TotalDataWritten;

	private:
		Volume (const Volume &);
		Volume &operator= (const Volume &);
	};
}

#endif // TC_HEADER_Volume_Volume
