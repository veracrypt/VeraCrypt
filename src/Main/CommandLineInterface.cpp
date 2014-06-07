/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include <wx/cmdline.h>
#include <wx/tokenzr.h>
#include "Core/Core.h"
#include "Application.h"
#include "CommandLineInterface.h"
#include "LanguageStrings.h"
#include "UserInterfaceException.h"

namespace TrueCrypt
{
	CommandLineInterface::CommandLineInterface (wxCmdLineParser &parser, UserInterfaceType::Enum interfaceType) :
		ArgCommand (CommandId::None),
		ArgFilesystem (VolumeCreationOptions::FilesystemType::Unknown),
		ArgNoHiddenVolumeProtection (false),
		ArgSize (0),
		ArgVolumeType (VolumeType::Unknown),
		StartBackgroundTask (false)
	{
		parser.SetSwitchChars (L"-");

		parser.AddOption (L"",  L"auto-mount",			_("Auto mount device-hosted/favorite volumes"));
		parser.AddSwitch (L"",  L"backup-headers",		_("Backup volume headers"));
		parser.AddSwitch (L"",  L"background-task",		_("Start Background Task"));
#ifdef TC_WINDOWS
		parser.AddSwitch (L"",  L"cache",				_("Cache passwords and keyfiles"));
#endif
		parser.AddSwitch (L"C", L"change",				_("Change password or keyfiles"));
		parser.AddSwitch (L"c", L"create",				_("Create new volume"));
		parser.AddSwitch (L"",	L"create-keyfile",		_("Create new keyfile"));
		parser.AddSwitch (L"",	L"delete-token-keyfiles", _("Delete security token keyfiles"));
		parser.AddSwitch (L"d", L"dismount",			_("Dismount volume"));
		parser.AddSwitch (L"",	L"display-password",	_("Display password while typing"));
		parser.AddOption (L"",	L"encryption",			_("Encryption algorithm"));
		parser.AddSwitch (L"",	L"explore",				_("Open explorer window for mounted volume"));
		parser.AddSwitch (L"",	L"export-token-keyfile",_("Export keyfile from security token"));
		parser.AddOption (L"",	L"filesystem",			_("Filesystem type"));
		parser.AddSwitch (L"f", L"force",				_("Force mount/dismount/overwrite"));
#if !defined(TC_WINDOWS) && !defined(TC_MACOSX)
		parser.AddOption (L"",	L"fs-options",			_("Filesystem mount options"));
#endif
		parser.AddOption (L"",	L"hash",				_("Hash algorithm"));
		parser.AddSwitch (L"h", L"help",				_("Display detailed command line help"), wxCMD_LINE_OPTION_HELP);
		parser.AddSwitch (L"",	L"import-token-keyfiles", _("Import keyfiles to security token"));
		parser.AddOption (L"k", L"keyfiles",			_("Keyfiles"));
		parser.AddSwitch (L"l", L"list",				_("List mounted volumes"));
		parser.AddSwitch (L"",	L"list-token-keyfiles",	_("List security token keyfiles"));
		parser.AddSwitch (L"",	L"load-preferences",	_("Load user preferences"));
		parser.AddSwitch (L"",	L"mount",				_("Mount volume interactively"));
		parser.AddOption (L"m", L"mount-options",		_("VeraCrypt volume mount options"));
		parser.AddOption (L"",	L"new-keyfiles",		_("New keyfiles"));
		parser.AddOption (L"",	L"new-password",		_("New password"));
		parser.AddSwitch (L"",	L"non-interactive",		_("Do not interact with user"));
		parser.AddOption (L"p", L"password",			_("Password"));
		parser.AddOption (L"",	L"protect-hidden",		_("Protect hidden volume"));
		parser.AddOption (L"",	L"protection-keyfiles",	_("Keyfiles for protected hidden volume"));
		parser.AddOption (L"",	L"protection-password",	_("Password for protected hidden volume"));
		parser.AddOption (L"",	L"random-source",		_("Use file as source of random data"));
		parser.AddSwitch (L"",  L"restore-headers",		_("Restore volume headers"));
		parser.AddSwitch (L"",	L"save-preferences",	_("Save user preferences"));
		parser.AddSwitch (L"",	L"quick",				_("Enable quick format"));
		parser.AddOption (L"",	L"size",				_("Size in bytes"));
		parser.AddOption (L"",	L"slot",				_("Volume slot number"));
		parser.AddSwitch (L"",	L"test",				_("Test internal algorithms"));
		parser.AddSwitch (L"t", L"text",				_("Use text user interface"));
		parser.AddOption (L"",	L"token-lib",			_("Security token library"));
		parser.AddSwitch (L"v", L"verbose",				_("Enable verbose output"));
		parser.AddSwitch (L"",	L"version",				_("Display version information"));
		parser.AddSwitch (L"",	L"volume-properties",	_("Display volume properties"));
		parser.AddOption (L"",	L"volume-type",			_("Volume type"));
		parser.AddParam (								_("Volume path"), wxCMD_LINE_VAL_STRING, wxCMD_LINE_PARAM_OPTIONAL);
		parser.AddParam (								_("Mount point"), wxCMD_LINE_VAL_STRING, wxCMD_LINE_PARAM_OPTIONAL);

		wxString str;
		bool param1IsVolume = false;
		bool param1IsMountedVolumeSpec = false;
		bool param1IsMountPoint = false;
		bool param1IsFile = false;

		if (parser.Parse () > 0)
			throw_err (_("Incorrect command line specified."));
		
		if (parser.Found (L"help"))
		{
			ArgCommand = CommandId::Help;
			return;
		}

		if (parser.Found (L"text") && interfaceType != UserInterfaceType::Text)
		{
			wstring msg = wstring (_("Option -t or --text must be specified as the first argument."));
			wcerr << msg << endl;
			throw_err (msg);
		}

		if (parser.Found (L"version"))
		{
			ArgCommand = CommandId::DisplayVersion;
			return;
		}

		// Preferences
		if (parser.Found (L"load-preferences"))
		{
			// Load preferences first to allow command line options to override them
			Preferences.Load();
			ArgMountOptions = Preferences.DefaultMountOptions;
		}

		// Commands
		if (parser.Found (L"auto-mount", &str))
		{
			CheckCommandSingle();

			wxStringTokenizer tokenizer (str, L",");
			while (tokenizer.HasMoreTokens())
			{
				wxString token = tokenizer.GetNextToken();

				if (token == L"devices")
				{
					if (ArgCommand == CommandId::AutoMountFavorites)
						ArgCommand = CommandId::AutoMountDevicesFavorites;
					else
						ArgCommand = CommandId::AutoMountDevices;

					param1IsMountPoint = true;
				}
				else if (token == L"favorites")
				{
					if (ArgCommand == CommandId::AutoMountDevices)
						ArgCommand = CommandId::AutoMountDevicesFavorites;
					else
						ArgCommand = CommandId::AutoMountFavorites;
				}
				else
				{
					throw_err (LangString["UNKNOWN_OPTION"] + L": " + token);
				}
			}
		}

		if (parser.Found (L"backup-headers"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::BackupHeaders;
			param1IsVolume = true;
		}

		if (parser.Found (L"change"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::ChangePassword;
			param1IsVolume = true;
		}

		if (parser.Found (L"create"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::CreateVolume;
			param1IsVolume = true;
		}

		if (parser.Found (L"create-keyfile"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::CreateKeyfile;
			param1IsFile = true;
		}
			
		if (parser.Found (L"delete-token-keyfiles"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::DeleteSecurityTokenKeyfiles;
		}

		if (parser.Found (L"dismount"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::DismountVolumes;
			param1IsMountedVolumeSpec = true;
		}
		
		if (parser.Found (L"export-token-keyfile"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::ExportSecurityTokenKeyfile;
		}

		if (parser.Found (L"import-token-keyfiles"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::ImportSecurityTokenKeyfiles;
		}

		if (parser.Found (L"list"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::ListVolumes;
			param1IsMountedVolumeSpec = true;
		}

		if (parser.Found (L"list-token-keyfiles"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::ListSecurityTokenKeyfiles;
		}

		if (parser.Found (L"mount"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::MountVolume;
			param1IsVolume = true;
		}

		if (parser.Found (L"save-preferences"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::SavePreferences;
		}

		if (parser.Found (L"test"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::Test;
		}

		if (parser.Found (L"volume-properties"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::DisplayVolumeProperties;
			param1IsMountedVolumeSpec = true;
		}

		// Options
		if (parser.Found (L"background-task"))
			StartBackgroundTask = true;

#ifdef TC_WINDOWS
		if (parser.Found (L"cache"))
			ArgMountOptions.CachePassword = true;
#endif
		ArgDisplayPassword = parser.Found (L"display-password");

		if (parser.Found (L"encryption", &str))
		{
			ArgEncryptionAlgorithm.reset();

			foreach (shared_ptr <EncryptionAlgorithm> ea, EncryptionAlgorithm::GetAvailableAlgorithms())
			{
				if (!ea->IsDeprecated() && wxString (ea->GetName()).IsSameAs (str, false))
					ArgEncryptionAlgorithm = ea;
			}

			if (!ArgEncryptionAlgorithm)
				throw_err (LangString["UNKNOWN_OPTION"] + L": " + str);
		}

		if (parser.Found (L"explore"))
			Preferences.OpenExplorerWindowAfterMount = true;

		if (parser.Found (L"filesystem", &str))
		{
			if (str.IsSameAs (L"none", false))
			{
				ArgMountOptions.NoFilesystem = true;
				ArgFilesystem = VolumeCreationOptions::FilesystemType::None;
			}
			else
			{
				ArgMountOptions.FilesystemType = wstring (str);
				
				if (str.IsSameAs (L"FAT", false))
					ArgFilesystem = VolumeCreationOptions::FilesystemType::FAT;
				else
					ArgFilesystem = VolumeCreationOptions::FilesystemType::None;
			}
		}

		ArgForce = parser.Found (L"force");

#if !defined(TC_WINDOWS) && !defined(TC_MACOSX)
		if (parser.Found (L"fs-options", &str))
			ArgMountOptions.FilesystemOptions = str;
#endif

		if (parser.Found (L"hash", &str))
		{
			ArgHash.reset();

			foreach (shared_ptr <Hash> hash, Hash::GetAvailableAlgorithms())
			{
				if (wxString (hash->GetName()).IsSameAs (str, false))
					ArgHash = hash;
			}

			if (!ArgHash)
				throw_err (LangString["UNKNOWN_OPTION"] + L": " + str);
		}

		if (parser.Found (L"keyfiles", &str))
			ArgKeyfiles = ToKeyfileList (str);

		if (parser.Found (L"mount-options", &str))
		{
			wxStringTokenizer tokenizer (str, L",");
			while (tokenizer.HasMoreTokens())
			{
				wxString token = tokenizer.GetNextToken();

				if (token == L"headerbak")
					ArgMountOptions.UseBackupHeaders = true;
				else if (token == L"nokernelcrypto")
					ArgMountOptions.NoKernelCrypto = true;
				else if (token == L"readonly" || token == L"ro")
					ArgMountOptions.Protection = VolumeProtection::ReadOnly;
				else if (token == L"system")
					ArgMountOptions.PartitionInSystemEncryptionScope = true;
				else if (token == L"timestamp" || token == L"ts")
					ArgMountOptions.PreserveTimestamps = false;
#ifdef TC_WINDOWS
				else if (token == L"removable" || token == L"rm")
					ArgMountOptions.Removable = true;
#endif
				else
					throw_err (LangString["UNKNOWN_OPTION"] + L": " + token);
			}
		}

		if (parser.Found (L"new-keyfiles", &str))
			ArgNewKeyfiles = ToKeyfileList (str);

		if (parser.Found (L"new-password", &str))
			ArgNewPassword.reset (new VolumePassword (wstring (str)));
		
		if (parser.Found (L"non-interactive"))
		{
			if (interfaceType != UserInterfaceType::Text)
				throw_err (L"--non-interactive is supported only in text mode");

			Preferences.NonInteractive = true;
		}

		if (parser.Found (L"password", &str))
			ArgPassword.reset (new VolumePassword (wstring (str)));

		if (parser.Found (L"protect-hidden", &str))
		{
			if (str == L"yes")
			{
				if (ArgMountOptions.Protection != VolumeProtection::ReadOnly)
					ArgMountOptions.Protection = VolumeProtection::HiddenVolumeReadOnly;
			}
			else if (str == L"no")
				ArgNoHiddenVolumeProtection = true;
			else
				throw_err (LangString["UNKNOWN_OPTION"] + L": " + str);
		}

		if (parser.Found (L"protection-keyfiles", &str))
		{
			ArgMountOptions.ProtectionKeyfiles = ToKeyfileList (str);
			ArgMountOptions.Protection = VolumeProtection::HiddenVolumeReadOnly;
		}
		
		if (parser.Found (L"protection-password", &str))
		{
			ArgMountOptions.ProtectionPassword.reset (new VolumePassword (wstring (str)));
			ArgMountOptions.Protection = VolumeProtection::HiddenVolumeReadOnly;
		}

		ArgQuick = parser.Found (L"quick");

		if (parser.Found (L"random-source", &str))
			ArgRandomSourcePath = FilesystemPath (str.wc_str());

		if (parser.Found (L"restore-headers"))
		{
			CheckCommandSingle();
			ArgCommand = CommandId::RestoreHeaders;
			param1IsVolume = true;
		}

		if (parser.Found (L"slot", &str))
		{
			unsigned long number;
			if (!str.ToULong (&number) || number < Core->GetFirstSlotNumber() || number > Core->GetLastSlotNumber())
				throw_err (LangString["PARAMETER_INCORRECT"] + L": " + str);

			ArgMountOptions.SlotNumber = number;

			if (param1IsMountedVolumeSpec)
			{
				shared_ptr <VolumeInfo> volume = Core->GetMountedVolume (number);
				if (!volume)
					throw_err (_("No such volume is mounted."));

				ArgVolumes.push_back (volume);
				param1IsMountedVolumeSpec = false;
			}
		}

		if (parser.Found (L"size", &str))
		{
			try
			{
				ArgSize = StringConverter::ToUInt64 (wstring (str));
			}
			catch (...)
			{
				throw_err (LangString["PARAMETER_INCORRECT"] + L": " + str);
			}
		}

		if (parser.Found (L"token-lib", &str))
			Preferences.SecurityTokenModule = wstring (str);

		if (parser.Found (L"verbose"))
			Preferences.Verbose = true;

		if (parser.Found (L"volume-type", &str))
		{
			if (str.IsSameAs (L"normal", false))
				ArgVolumeType = VolumeType::Normal;
			else if (str.IsSameAs (L"hidden", false))
				ArgVolumeType = VolumeType::Hidden;
			else
				throw_err (LangString["UNKNOWN_OPTION"] + L": " + str);
		}

		// Parameters
		if (parser.GetParamCount() > 0)
		{
			if (ArgCommand == CommandId::None)
			{
				ArgCommand = CommandId::MountVolume;
				param1IsVolume = true;
			}

			if (param1IsVolume)
			{
				wxFileName volPath (parser.GetParam (0));
				
#ifdef TC_WINDOWS
				if (!parser.GetParam (0).StartsWith (L"\\Device\\"))
#endif
					volPath.Normalize (wxPATH_NORM_ABSOLUTE | wxPATH_NORM_DOTS);

				ArgVolumePath.reset (new VolumePath (wstring (volPath.GetFullPath())));
			}

			if (param1IsMountPoint || parser.GetParamCount() >= 2)
			{
				wstring s (parser.GetParam (param1IsMountPoint ? 0 : 1));

				if (s.empty())
					ArgMountOptions.NoFilesystem = true;

				wxFileName mountPoint (wstring (Directory::AppendSeparator (s)));
				mountPoint.Normalize (wxPATH_NORM_ABSOLUTE | wxPATH_NORM_DOTS);
				ArgMountPoint.reset (new DirectoryPath (wstring (mountPoint.GetPath())));
			}

			if (param1IsFile)
			{
				ArgFilePath.reset (new FilePath (parser.GetParam (0).wc_str()));
			}
		}

		if (param1IsMountedVolumeSpec)
			ArgVolumes = GetMountedVolumes (parser.GetParamCount() > 0 ? parser.GetParam (0) : wxString());

		if (ArgCommand == CommandId::None && Application::GetUserInterfaceType() == UserInterfaceType::Text)
			parser.Usage();
	}

	CommandLineInterface::~CommandLineInterface ()
	{
	}

	void CommandLineInterface::CheckCommandSingle () const
	{
		if (ArgCommand != CommandId::None)
			throw_err (_("Only a single command can be specified at a time."));
	}

	shared_ptr <KeyfileList> CommandLineInterface::ToKeyfileList (const wxString &arg) const
	{
		wxStringTokenizer tokenizer (arg, L",", wxTOKEN_RET_EMPTY_ALL);

		// Handle escaped separator
		wxArrayString arr;
		bool prevEmpty = false;
		while (tokenizer.HasMoreTokens())
		{
			wxString token = tokenizer.GetNextToken();

			if (prevEmpty && token.empty() && tokenizer.HasMoreTokens())
			{
				token = tokenizer.GetNextToken();
				if (!token.empty())
				{
					arr.Add (token);
					prevEmpty = true;
					continue;
				}
			}
			
			if (token.empty() && !tokenizer.HasMoreTokens())
				break;

			if (prevEmpty || token.empty())
			{
				if (arr.Count() < 1)
				{
					arr.Add (L"");
					continue;
				}
				arr.Last() += token.empty() ? L"," : token.wc_str();
			}
			else
				arr.Add (token);

			prevEmpty = token.empty();
		}

		make_shared_auto (KeyfileList, keyfileList);
		for (size_t i = 0; i < arr.GetCount(); i++)
		{
			if (!arr[i].empty())
				keyfileList->push_back (make_shared <Keyfile> (wstring (arr[i])));
		}

		return keyfileList;
	}

	VolumeInfoList CommandLineInterface::GetMountedVolumes (const wxString &mountedVolumeSpec) const
	{
		VolumeInfoList volumes = Core->GetMountedVolumes ();
		VolumeInfoList filteredVolumes;

		wxFileName pathFilter;
		if (!mountedVolumeSpec.empty())
		{
			pathFilter = mountedVolumeSpec;
			pathFilter.Normalize (wxPATH_NORM_ABSOLUTE | wxPATH_NORM_DOTS);
		}
		else
			return volumes;

		foreach (shared_ptr <VolumeInfo> volume, volumes)
		{
			if (mountedVolumeSpec.empty())
			{
				filteredVolumes.push_back (volume);
			}
			else if (wxString (wstring(volume->Path)) == pathFilter.GetFullPath())
			{
				filteredVolumes.push_back (volume);
			}
			else if (wxString (wstring(volume->MountPoint)) == pathFilter.GetFullPath()
				|| (wxString (wstring(volume->MountPoint)) + wxFileName::GetPathSeparator()) == pathFilter.GetFullPath())
			{
				filteredVolumes.push_back (volume);
			}
		}
		
		if (!mountedVolumeSpec.IsEmpty() && filteredVolumes.size() < 1)
			throw_err (_("No such volume is mounted."));

		return filteredVolumes;
	}

	auto_ptr <CommandLineInterface> CmdLine;
}
