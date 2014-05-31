/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_CommandInterface
#define TC_HEADER_Main_CommandInterface

#include "System.h"
#include "Main.h"
#include "Volume/VolumeInfo.h"
#include "Core/MountOptions.h"
#include "Core/VolumeCreator.h"
#include "UserPreferences.h"
#include "UserInterfaceType.h"

namespace TrueCrypt
{
	struct CommandId
	{
		enum Enum
		{
			None,
			AutoMountDevices,
			AutoMountDevicesFavorites,
			AutoMountFavorites,
			BackupHeaders,
			ChangePassword,
			CreateKeyfile,
			CreateVolume,
			DeleteSecurityTokenKeyfiles,
			DismountVolumes,
			DisplayVersion,
			DisplayVolumeProperties,
			ExportSecurityTokenKeyfile,
			Help,
			ImportSecurityTokenKeyfiles,
			ListSecurityTokenKeyfiles,
			ListVolumes,
			MountVolume,
			RestoreHeaders,
			SavePreferences,
			Test
		};
	};

	struct CommandLineInterface
	{
	public:
		CommandLineInterface (wxCmdLineParser &parser, UserInterfaceType::Enum interfaceType);
		virtual ~CommandLineInterface ();


		CommandId::Enum ArgCommand;
		bool ArgDisplayPassword;
		shared_ptr <EncryptionAlgorithm> ArgEncryptionAlgorithm;
		shared_ptr <FilePath> ArgFilePath;
		VolumeCreationOptions::FilesystemType::Enum ArgFilesystem;
		bool ArgForce;
		shared_ptr <Hash> ArgHash;
		shared_ptr <KeyfileList> ArgKeyfiles;
		MountOptions ArgMountOptions;
		shared_ptr <DirectoryPath> ArgMountPoint;
		shared_ptr <KeyfileList> ArgNewKeyfiles;
		shared_ptr <VolumePassword> ArgNewPassword;
		bool ArgNoHiddenVolumeProtection;
		shared_ptr <VolumePassword> ArgPassword;
		bool ArgQuick;
		FilesystemPath ArgRandomSourcePath;
		uint64 ArgSize;
		shared_ptr <VolumePath> ArgVolumePath;
		VolumeInfoList ArgVolumes;
		VolumeType::Enum ArgVolumeType;

		bool StartBackgroundTask;
		UserPreferences Preferences;

	protected:
		void CheckCommandSingle () const;
		shared_ptr <KeyfileList> ToKeyfileList (const wxString &arg) const;
		VolumeInfoList GetMountedVolumes (const wxString &filter) const;

	private:
		CommandLineInterface (const CommandLineInterface &);
		CommandLineInterface &operator= (const CommandLineInterface &);
	};

	extern auto_ptr <CommandLineInterface> CmdLine;
}

#endif // TC_HEADER_Main_CommandInterface
