/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Volume_VolumeCreator
#define TC_HEADER_Volume_VolumeCreator

#include "Platform/Platform.h"
#include "Volume/Volume.h"
#include "RandomNumberGenerator.h"

namespace VeraCrypt
{
	
	struct VolumeCreationOptions
	{
		VolumePath Path;
		VolumeType::Enum Type;
		uint64 Size;
		shared_ptr <VolumePassword> Password;
		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <Pkcs5Kdf> VolumeHeaderKdf;
		shared_ptr <EncryptionAlgorithm> EA;
		bool Quick;

		struct FilesystemType
		{
			enum Enum
			{
				Unknown = 0,
				None,
				FAT,
				NTFS,
				Ext2,
				Ext3,
				Ext4,
				MacOsExt,
				UFS
			};

			static Enum GetPlatformNative ()
			{
#ifdef TC_WINDOWS
				return VolumeCreationOptions::FilesystemType::NTFS;
#elif defined (TC_LINUX)
				return VolumeCreationOptions::FilesystemType::Ext3;
#elif defined (TC_MACOSX)
				return VolumeCreationOptions::FilesystemType::MacOsExt;
#elif defined (TC_FREEBSD) || defined (TC_SOLARIS)
				return VolumeCreationOptions::FilesystemType::UFS;
#else
				return VolumeCreationOptions::FilesystemType::FAT;
#endif
			}
		};

		FilesystemType::Enum Filesystem;
		uint32 FilesystemClusterSize;
		uint32 SectorSize;
	};

	class VolumeCreator
	{
	public:

		struct ProgressInfo
		{
			bool CreationInProgress;
			uint64 TotalSize;
			uint64 SizeDone;
		};

		struct KeyInfo
		{
			ConstBufferPtr HeaderKey;
			ConstBufferPtr MasterKey;
		};

		VolumeCreator ();
		virtual ~VolumeCreator ();

		void Abort ();
		void CheckResult ();
		void CreateVolume (shared_ptr <VolumeCreationOptions> options);
		KeyInfo GetKeyInfo () const;
		ProgressInfo GetProgressInfo ();

	protected:
		void CreationThread ();

		volatile bool AbortRequested;
		volatile bool CreationInProgress;
		uint64 DataStart;
		uint64 HostSize;
		shared_ptr <VolumeCreationOptions> Options;
		shared_ptr <Exception> ThreadException;
		uint64 VolumeSize;

		shared_ptr <VolumeLayout> Layout;
		shared_ptr <File> VolumeFile;
		SharedVal <uint64> SizeDone;
		uint64 WriteOffset;
		ProgressInfo mProgressInfo;

		SecureBuffer HeaderKey;
		shared_ptr <VolumePassword> PasswordKey;
		SecureBuffer MasterKey;

	private:
		VolumeCreator (const VolumeCreator &);
		VolumeCreator &operator= (const VolumeCreator &);
	};
}

#endif // TC_HEADER_Volume_VolumeCreator
