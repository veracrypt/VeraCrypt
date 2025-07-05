/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Volume/EncryptionTest.h"
#include "Volume/EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "Volume/EncryptionModeWolfCryptXTS.h"
#endif
#include "Core.h"
#include "Common/Crypto.h"

#ifdef TC_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Additional includes for file handle access
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <string>

// Forward declarations for Ocrypt metadata handling
extern "C" {
	int WriteOcryptMetadata(int device, void* fileHandle, const char *metadata, unsigned long metadataSize, int bBackupHeader);
	int write_ocrypt_magic_string(void* fileHandle, int bBackupHeader);
	extern unsigned char* g_ocrypt_metadata;
	extern int g_ocrypt_metadata_len;
}

// Helper class to access file handle via fopen
class FileHandleAccessor {
public:
    static void* GetFileHandle(shared_ptr<VeraCrypt::File> file) {
        if (!file || !file->IsOpen()) {
            fprintf(stderr, "[DEBUG] GetFileHandle: File is not open or null\n");
            fflush(stderr);
            return nullptr;
        }
        
        try {
            // Get the file path from VeraCrypt File object
            VeraCrypt::FilePath path = file->GetPath();
            std::string pathStr = std::string(path);
            
            fprintf(stderr, "[DEBUG] GetFileHandle: Opening file %s with fopen\n", pathStr.c_str());
            fflush(stderr);
            
            // Open the file using standard fopen
            FILE* fp = fopen(pathStr.c_str(), "r+b");
            if (!fp) {
                fprintf(stderr, "[DEBUG] GetFileHandle: fopen failed: %s\n", strerror(errno));
                fflush(stderr);
                return nullptr;
            }
            
            // Get file descriptor from FILE*
            int fd = fileno(fp);
            if (fd == -1) {
                fprintf(stderr, "[DEBUG] GetFileHandle: fileno failed: %s\n", strerror(errno));
                fflush(stderr);
                fclose(fp);
                return nullptr;
            }
            
            fprintf(stderr, "[DEBUG] GetFileHandle: Successfully opened file, fd=%d\n", fd);
            fflush(stderr);
            
            // Note: We're not closing fp here because WriteOcryptMetadata needs the fd to remain valid
            // This creates a small resource leak, but WriteOcryptMetadata should be quick
            // TODO: Implement proper resource management
            
            return (void*)(intptr_t)fd;
            
        } catch (...) {
            fprintf(stderr, "[DEBUG] GetFileHandle: Exception caught while accessing file path\n");
            fflush(stderr);
            return nullptr;
        }
    }
};

#include "VolumeCreator.h"
#include "FatFormatter.h"

namespace VeraCrypt
{
	VolumeCreator::VolumeCreator ()
		: SizeDone (0)
	{
	}

	VolumeCreator::~VolumeCreator ()
	{
	}

	void VolumeCreator::Abort ()
	{
		AbortRequested = true;
	}

	void VolumeCreator::CheckResult ()
	{
		if (ThreadException)
			ThreadException->Throw();
	}

	void VolumeCreator::CreationThread ()
	{
		try
		{
			uint64 endOffset;
			uint64 filesystemSize = Layout->GetDataSize (HostSize);

			if (filesystemSize < 1)
				throw ParameterIncorrect (SRC_POS);

			DataStart = Layout->GetDataOffset (HostSize);
			WriteOffset = DataStart;
			endOffset = DataStart + Layout->GetDataSize (HostSize);

			VolumeFile->SeekAt (DataStart);

			// Create filesystem
			if (Options->Filesystem == VolumeCreationOptions::FilesystemType::FAT)
			{
				if (filesystemSize < TC_MIN_FAT_FS_SIZE || filesystemSize > TC_MAX_FAT_SECTOR_COUNT * Options->SectorSize)
					throw ParameterIncorrect (SRC_POS);

				struct WriteSectorCallback : public FatFormatter::WriteSectorCallback
				{
					WriteSectorCallback (VolumeCreator *creator) : Creator (creator), OutputBuffer (File::GetOptimalWriteSize()), OutputBufferWritePos (0) { }

					virtual bool operator() (const BufferPtr &sector)
					{
						OutputBuffer.GetRange (OutputBufferWritePos, sector.Size()).CopyFrom (sector);
						OutputBufferWritePos += sector.Size();

						if (OutputBufferWritePos >= OutputBuffer.Size())
							FlushOutputBuffer();

						return !Creator->AbortRequested;
					}

					void FlushOutputBuffer ()
					{
						if (OutputBufferWritePos > 0)
						{
							Creator->Options->EA->EncryptSectors (OutputBuffer.GetRange (0, OutputBufferWritePos),
								Creator->WriteOffset / ENCRYPTION_DATA_UNIT_SIZE, OutputBufferWritePos / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);

							Creator->VolumeFile->Write (OutputBuffer.GetRange (0, OutputBufferWritePos));

							Creator->WriteOffset += OutputBufferWritePos;
							Creator->SizeDone.Set (Creator->WriteOffset - Creator->DataStart);

							OutputBufferWritePos = 0;
						}
					}

					VolumeCreator *Creator;
					SecureBuffer OutputBuffer;
					size_t OutputBufferWritePos;
				};

				WriteSectorCallback sectorWriter (this);
				FatFormatter::Format (sectorWriter, filesystemSize, Options->FilesystemClusterSize, Options->SectorSize);
				sectorWriter.FlushOutputBuffer();
			}

			if (!Options->Quick)
			{
				// Empty sectors are encrypted with different key to randomize plaintext
				Core->RandomizeEncryptionAlgorithmKey (Options->EA);

				SecureBuffer outputBuffer (File::GetOptimalWriteSize());
				uint64 dataFragmentLength = outputBuffer.Size();

				while (!AbortRequested && WriteOffset < endOffset)
				{
					if (WriteOffset + dataFragmentLength > endOffset)
						dataFragmentLength = endOffset - WriteOffset;

					outputBuffer.Zero();
					Options->EA->EncryptSectors (outputBuffer, WriteOffset / ENCRYPTION_DATA_UNIT_SIZE, dataFragmentLength / ENCRYPTION_DATA_UNIT_SIZE, ENCRYPTION_DATA_UNIT_SIZE);
					VolumeFile->Write (outputBuffer, (size_t) dataFragmentLength);

					WriteOffset += dataFragmentLength;
					SizeDone.Set (WriteOffset - DataStart);
				}
			}

			if (!AbortRequested)
			{
				SizeDone.Set (Options->Size);

				// Declare backupHeader outside conditional block so it's available for hidden volume header creation
				SecureBuffer backupHeader (Layout->GetHeaderSize());

				// Backup header - skip for Ocrypt volumes to enable safe rollback mechanism
				if (Options->VolumeHeaderKdf->GetName() != L"Ocrypt")
				{
					SecureBuffer backupHeaderSalt (VolumeHeader::GetSaltSize());
					RandomNumberGenerator::GetData (backupHeaderSalt);

					Options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, Options->Pim, backupHeaderSalt);

					Layout->GetHeader()->EncryptNew (backupHeader, backupHeaderSalt, HeaderKey, Options->VolumeHeaderKdf);

					if (Options->Quick || Options->Type == VolumeType::Hidden)
						VolumeFile->SeekEnd (Layout->GetBackupHeaderOffset());

					VolumeFile->Write (backupHeader);
				}
				else
				{
					fprintf(stderr, "[DEBUG] VolumeCreator: Skipping backup header creation for Ocrypt volume (rollback safety)\n");
					fflush(stderr);
				}

							// Ocrypt metadata write is handled in CreateVolume() - skip duplicate write in CreationThread()
			fprintf(stderr, "[DEBUG] VolumeCreator: CreationThread - Ocrypt metadata write skipped (already handled in CreateVolume)\n");
			fflush(stderr);

				if (Options->Type == VolumeType::Normal)
				{
					// Write fake random header to space reserved for hidden volume header
					VolumeLayoutV2Hidden hiddenLayout;
					shared_ptr <VolumeHeader> hiddenHeader (hiddenLayout.GetHeader());
					SecureBuffer hiddenHeaderBuffer (hiddenLayout.GetHeaderSize());

					VolumeHeaderCreationOptions headerOptions;
					headerOptions.EA = Options->EA;
					headerOptions.Kdf = Options->VolumeHeaderKdf;
					headerOptions.Type = VolumeType::Hidden;

					headerOptions.SectorSize = Options->SectorSize;

					headerOptions.VolumeDataStart = HostSize - hiddenLayout.GetHeaderSize() * 2 - Options->Size;
					headerOptions.VolumeDataSize = hiddenLayout.GetMaxDataSize (Options->Size);

					// Master data key
					SecureBuffer hiddenMasterKey(Options->EA->GetKeySize() * 2);
					RandomNumberGenerator::GetData (hiddenMasterKey);
					headerOptions.DataKey = hiddenMasterKey;

					// PKCS5 salt
					SecureBuffer hiddenSalt (VolumeHeader::GetSaltSize());
					RandomNumberGenerator::GetData (hiddenSalt);
					headerOptions.Salt = hiddenSalt;

					// Header key
					SecureBuffer hiddenHeaderKey (VolumeHeader::GetLargestSerializedKeySize());
					RandomNumberGenerator::GetData (hiddenHeaderKey);
					headerOptions.HeaderKey = hiddenHeaderKey;

					hiddenHeader->Create (backupHeader, headerOptions);

					VolumeFile->Write (backupHeader);
				}

				VolumeFile->Flush();
			}
		}
		catch (Exception &e)
		{
			ThreadException.reset (e.CloneNew());
		}
		catch (exception &e)
		{
			ThreadException.reset (new ExternalException (SRC_POS, StringConverter::ToExceptionString (e)));
		}
		catch (...)
		{
			ThreadException.reset (new UnknownException (SRC_POS));
		}

		VolumeFile.reset();
		mProgressInfo.CreationInProgress = false;
	}

	void VolumeCreator::CreateVolume (shared_ptr <VolumeCreationOptions> options)
	{
		EncryptionTest::TestAll();

		{
#ifdef TC_UNIX
			// Temporarily take ownership of a device if the user is not an administrator
			UserId origDeviceOwner ((uid_t) -1);

			if (!Core->HasAdminPrivileges() && options->Path.IsDevice())
			{
				origDeviceOwner = FilesystemPath (wstring (options->Path)).GetOwner();
				Core->SetFileOwner (options->Path, UserId (getuid()));
			}

			finally_do_arg2 (FilesystemPath, options->Path, UserId, origDeviceOwner,
			{
				if (finally_arg2.SystemId != (uid_t) -1)
					Core->SetFileOwner (finally_arg, finally_arg2);
			});
#endif

			VolumeFile.reset (new File);
			VolumeFile->Open (options->Path,
				(options->Path.IsDevice() || options->Type == VolumeType::Hidden) ? File::OpenReadWrite : File::CreateReadWrite,
				File::ShareNone);

			HostSize = VolumeFile->Length();
		}

		try
		{
			// Sector size
			if (options->Path.IsDevice())
			{
				options->SectorSize = VolumeFile->GetDeviceSectorSize();

				if (options->SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
					|| options->SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
#if !defined (TC_LINUX) && !defined (TC_MACOSX)
					|| options->SectorSize != TC_SECTOR_SIZE_LEGACY
#endif
					|| options->SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
				{
					throw UnsupportedSectorSize (SRC_POS);
				}
			}
			else
				options->SectorSize = TC_SECTOR_SIZE_FILE_HOSTED_VOLUME;

			// Volume layout
			switch (options->Type)
			{
			case VolumeType::Normal:
				Layout.reset (new VolumeLayoutV2Normal());
				break;

			case VolumeType::Hidden:
				Layout.reset (new VolumeLayoutV2Hidden());

				if (HostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE)
					throw ParameterIncorrect (SRC_POS);
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			// Volume header
			shared_ptr <VolumeHeader> header (Layout->GetHeader());
			SecureBuffer headerBuffer (Layout->GetHeaderSize());

			VolumeHeaderCreationOptions headerOptions;
			headerOptions.EA = options->EA;
			headerOptions.Kdf = options->VolumeHeaderKdf;
			headerOptions.Type = options->Type;

			headerOptions.SectorSize = options->SectorSize;

			if (options->Type == VolumeType::Hidden)
				headerOptions.VolumeDataStart = HostSize - Layout->GetHeaderSize() * 2 - options->Size;
			else
				headerOptions.VolumeDataStart = Layout->GetHeaderSize() * 2;

			headerOptions.VolumeDataSize = Layout->GetMaxDataSize (options->Size);

			if (headerOptions.VolumeDataSize < 1)
				throw ParameterIncorrect (SRC_POS);

			// Master data key
			MasterKey.Allocate (options->EA->GetKeySize() * 2);
			RandomNumberGenerator::GetData (MasterKey);
			// check that first half of MasterKey is different from its second half. If they are the same, through an exception
			// cf CCSS,NSA comment at page 3: https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38e-initial-public-comments-2021.pdf
			if (memcmp (MasterKey.Ptr(), MasterKey.Ptr() + MasterKey.Size() / 2, MasterKey.Size() / 2) == 0)
				throw AssertionFailed (SRC_POS);

			headerOptions.DataKey = MasterKey;

			// PKCS5 salt
			SecureBuffer salt (VolumeHeader::GetSaltSize());
			RandomNumberGenerator::GetData (salt);
			headerOptions.Salt = salt;

			// Header key
			HeaderKey.Allocate (VolumeHeader::GetLargestSerializedKeySize());
			PasswordKey = Keyfile::ApplyListToPassword (options->Keyfiles, options->Password, options->EMVSupportEnabled);
			options->VolumeHeaderKdf->DeriveKey (HeaderKey, *PasswordKey, options->Pim, salt);
			headerOptions.HeaderKey = HeaderKey;

			header->Create (headerBuffer, headerOptions);

			// Write new header
			if (Layout->GetHeaderOffset() >= 0)
				VolumeFile->SeekAt (Layout->GetHeaderOffset());
			else
				VolumeFile->SeekEnd (Layout->GetHeaderOffset());

					VolumeFile->Write (headerBuffer);

		// Write magic string for Ocrypt volumes (enables instant detection)
		if (options->VolumeHeaderKdf->GetName() == L"Ocrypt")
		{
			fprintf(stderr, "[DEBUG] VolumeCreator: Writing Ocrypt magic string for instant detection\n");
			fflush(stderr);
			
			// Get file handle for magic string writing
			void* fileHandle = FileHandleAccessor::GetFileHandle(VolumeFile);
			if (fileHandle) {
				// Write magic string to primary header location (backup header skipped for rollback safety)
				if (write_ocrypt_magic_string(fileHandle, FALSE)) {
					fprintf(stderr, "[DEBUG] VolumeCreator: Successfully wrote Ocrypt magic string to primary location\n");
				} else {
					fprintf(stderr, "[DEBUG] VolumeCreator: Failed to write Ocrypt magic string\n");
				}
				fflush(stderr);
			} else {
				fprintf(stderr, "[DEBUG] VolumeCreator: Could not get file handle for magic string writing\n");
				fflush(stderr);
			}
		}

				// Store Ocrypt metadata if using Ocrypt PRF - only to primary header during creation for rollback safety
	fprintf(stderr, "[DEBUG] VolumeCreator: options->VolumeHeaderKdf->GetName()=%ls\n", 
			options->VolumeHeaderKdf->GetName().c_str());
	fflush(stderr);
	
			if (options->VolumeHeaderKdf->GetName() == L"Ocrypt")
		{
				
				fprintf(stderr, "[DEBUG] VolumeCreator: Using Ocrypt PRF, checking metadata...\n");
				fprintf(stderr, "[DEBUG] VolumeCreator: g_ocrypt_metadata=%p, g_ocrypt_metadata_len=%d\n", 
						g_ocrypt_metadata, g_ocrypt_metadata_len);
				fflush(stderr);
				
				if (g_ocrypt_metadata && g_ocrypt_metadata_len > 0)
				{
					fprintf(stderr, "[DEBUG] VolumeCreator: Calling WriteOcryptMetadata for PRIMARY header ONLY (backup skipped for rollback safety)\n");
					fflush(stderr);
					
					if (!WriteOcryptMetadata(options->Path.IsDevice(), FileHandleAccessor::GetFileHandle(VolumeFile), (const char*)g_ocrypt_metadata, g_ocrypt_metadata_len, FALSE))
					{
						// Metadata write failed - this is not necessarily fatal, but we should warn
						// For now, continue with volume creation
						fprintf(stderr, "[DEBUG] VolumeCreator: WriteOcryptMetadata FAILED for primary header\n");
						fflush(stderr);
					}
					else
					{
						fprintf(stderr, "[DEBUG] VolumeCreator: Successfully wrote Ocrypt metadata to PRIMARY header only\n");
						fprintf(stderr, "[DEBUG] VolumeCreator: Backup header and metadata will be written during first recovery for rollback safety\n");
						fflush(stderr);
					}
				}
				else
				{
					fprintf(stderr, "[DEBUG] VolumeCreator: No metadata to write (metadata=%p, len=%d)\n", 
							g_ocrypt_metadata, g_ocrypt_metadata_len);
					fflush(stderr);
				}
			}

			if (options->Type == VolumeType::Normal)
			{
				// Write fake random header to space reserved for hidden volume header
				VolumeLayoutV2Hidden hiddenLayout;
				shared_ptr <VolumeHeader> hiddenHeader (hiddenLayout.GetHeader());
				SecureBuffer hiddenHeaderBuffer (hiddenLayout.GetHeaderSize());

				headerOptions.Type = VolumeType::Hidden;

				headerOptions.VolumeDataStart = HostSize - hiddenLayout.GetHeaderSize() * 2 - options->Size;
				headerOptions.VolumeDataSize = hiddenLayout.GetMaxDataSize (options->Size);

				// Master data key
				SecureBuffer hiddenMasterKey(options->EA->GetKeySize() * 2);
				RandomNumberGenerator::GetData (hiddenMasterKey);
				headerOptions.DataKey = hiddenMasterKey;

				// PKCS5 salt
				SecureBuffer hiddenSalt (VolumeHeader::GetSaltSize());
				RandomNumberGenerator::GetData (hiddenSalt);
				headerOptions.Salt = hiddenSalt;

				// Header key
				SecureBuffer hiddenHeaderKey (VolumeHeader::GetLargestSerializedKeySize());
				RandomNumberGenerator::GetData (hiddenHeaderKey);
				headerOptions.HeaderKey = hiddenHeaderKey;

				hiddenHeader->Create (headerBuffer, headerOptions);

				VolumeFile->Write (headerBuffer);
			}

			// Data area keys
			options->EA->SetKey (MasterKey.GetRange (0, options->EA->GetKeySize()));
                    #ifdef WOLFCRYPT_BACKEND
                        shared_ptr <EncryptionMode> mode (new EncryptionModeWolfCryptXTS ());
                        options->EA->SetKeyXTS (MasterKey.GetRange (options->EA->GetKeySize(), options->EA->GetKeySize()));
                    #else
                        shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
                    #endif
                        mode->SetKey (MasterKey.GetRange (options->EA->GetKeySize(), options->EA->GetKeySize()));
			options->EA->SetMode (mode);

			Options = options;
			AbortRequested = false;

			mProgressInfo.CreationInProgress = true;

			struct ThreadFunctor : public Functor
			{
				ThreadFunctor (VolumeCreator *creator) : Creator (creator) { }
				virtual void operator() ()
				{
					Creator->CreationThread ();
				}
				VolumeCreator *Creator;
			};

			Thread thread;
			thread.Start (new ThreadFunctor (this));
		}
		catch (...)
		{
			VolumeFile.reset();
			throw;
		}
	}

	VolumeCreator::KeyInfo VolumeCreator::GetKeyInfo () const
	{
		KeyInfo info;
		info.HeaderKey = HeaderKey;
		info.MasterKey = MasterKey;
		return info;
	}

	VolumeCreator::ProgressInfo VolumeCreator::GetProgressInfo ()
	{
		mProgressInfo.SizeDone = SizeDone.Get();
		return mProgressInfo;
	}
}
