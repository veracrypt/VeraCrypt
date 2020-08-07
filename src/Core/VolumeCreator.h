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

#ifndef TC_HEADER_Volume_VolumeCreator
#define TC_HEADER_Volume_VolumeCreator

#include "Platform/Platform.h"
#include "Volume/Volume.h"
#include "RandomNumberGenerator.h"
#if defined (TC_LINUX)
#include "Platform/Unix/Process.h"
#include <errno.h>
#endif

#define VC_MIN_BTRFS_VOLUME_SIZE 114294784ULL

namespace VeraCrypt
{

	struct VolumeCreationOptions
	{
		VolumePath Path;
		VolumeType::Enum Type;
		uint64 Size;
		shared_ptr <VolumePassword> Password;
		int Pim;
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
				exFAT,
				NTFS,
				Ext2,
				Ext3,
				Ext4,
				Btrfs,
				MacOsExt,
				APFS,
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

			static const char* GetFsFormatter (VolumeCreationOptions::FilesystemType::Enum fsType)
			{
				switch (fsType)
				{
	#if defined (TC_LINUX)
				case VolumeCreationOptions::FilesystemType::Ext2:		return "mkfs.ext2";
				case VolumeCreationOptions::FilesystemType::Ext3:		return "mkfs.ext3";
				case VolumeCreationOptions::FilesystemType::Ext4:		return "mkfs.ext4";
				case VolumeCreationOptions::FilesystemType::NTFS:		return "mkfs.ntfs";
				case VolumeCreationOptions::FilesystemType::exFAT:		return "mkfs.exfat";
				case VolumeCreationOptions::FilesystemType::Btrfs:		return "mkfs.btrfs";
	#elif defined (TC_MACOSX)
				case VolumeCreationOptions::FilesystemType::MacOsExt:	return "newfs_hfs";
				case VolumeCreationOptions::FilesystemType::exFAT:		return "newfs_exfat";
				case VolumeCreationOptions::FilesystemType::APFS:		return "newfs_apfs";
	#elif defined (TC_FREEBSD) || defined (TC_SOLARIS)
				case VolumeCreationOptions::FilesystemType::UFS:		return "newfs" ;
	#endif
				default: return NULL;
				}
			}

			static bool IsFsFormatterPresent (VolumeCreationOptions::FilesystemType::Enum fsType)
			{
				bool bRet = false;
				const char* fsFormatter = GetFsFormatter (fsType);
				if (fsFormatter)
				{
#if defined (TC_LINUX)
					try
					{
						list <string> args;

						args.push_back ("-V");
						Process::Execute (fsFormatter, args);

						bRet = true;
					}
					catch (ExecutedProcessFailed& epe)
					{
						// only permission error is accepted in case of failure of the command
						if (epe.GetExitCode () == EPERM || epe.GetExitCode () == EACCES)
							bRet = true;
					}
					catch (SystemException& se)
					{
						// if a permission error occured, then we consider that the command exists
						if (se.GetErrorCode () == EPERM || se.GetErrorCode () == EACCES)
							bRet = true;
					}
					catch (exception &e)
					{
					}
#else
					bRet = true;
#endif
				}

				return bRet;
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
