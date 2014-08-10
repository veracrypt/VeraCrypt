/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include <set>
#include <typeinfo>
#include <wx/apptrait.h>
#include <wx/cmdline.h>
#include "Platform/PlatformTest.h"
#ifdef TC_UNIX
#include <errno.h>
#include "Platform/Unix/Process.h"
#endif
#include "Platform/SystemInfo.h"
#include "Common/SecurityToken.h"
#include "Volume/EncryptionTest.h"
#include "Application.h"
#include "FavoriteVolume.h"
#include "UserInterface.h"

namespace VeraCrypt
{
	UserInterface::UserInterface ()
	{
	}

	UserInterface::~UserInterface ()
	{
		Core->WarningEvent.Disconnect (this);
		Core->VolumeMountedEvent.Disconnect (this);

		try
		{
			if (SecurityToken::IsInitialized())
				SecurityToken::CloseLibrary();
		}
		catch (...) { }
	}

	void UserInterface::CheckRequirementsForMountingVolume () const
	{
#ifdef TC_LINUX
		if (!Preferences.NonInteractive)
		{
			if (!SystemInfo::IsVersionAtLeast (2, 6, 24))
				ShowWarning (_("Your system uses an old version of the Linux kernel.\n\nDue to a bug in the Linux kernel, your system may stop responding when writing data to a VeraCrypt volume. This problem can be solved by upgrading the kernel to version 2.6.24 or later."));
		}
#endif // TC_LINUX
	}

	void UserInterface::CloseExplorerWindows (shared_ptr <VolumeInfo> mountedVolume) const
	{
#ifdef TC_WINDOWS
		struct Args
		{
			HWND ExplorerWindow;
			string DriveRootPath;
		};

		struct Enumerator
		{
			static BOOL CALLBACK ChildWindows (HWND hwnd, LPARAM argsLP)
			{
				Args *args = reinterpret_cast <Args *> (argsLP);
				
				char s[4096];
				SendMessageA (hwnd, WM_GETTEXT, sizeof (s), (LPARAM) s);

				if (strstr (s, args->DriveRootPath.c_str()) != NULL)
				{
					PostMessage (args->ExplorerWindow, WM_CLOSE, 0, 0);
					return FALSE;
				}

				return TRUE;
			}

			static BOOL CALLBACK TopLevelWindows (HWND hwnd, LPARAM argsLP)
			{
				Args *args = reinterpret_cast <Args *> (argsLP);

				char s[4096];
				GetClassNameA (hwnd, s, sizeof s);
				if (strcmp (s, "CabinetWClass") == 0)
				{
					GetWindowTextA (hwnd, s, sizeof s);
					if (strstr (s, args->DriveRootPath.c_str()) != NULL)
					{
						PostMessage (hwnd, WM_CLOSE, 0, 0);
						return TRUE;
					}

					args->ExplorerWindow = hwnd;
					EnumChildWindows (hwnd, ChildWindows, argsLP);
				}

				return TRUE;
			}
		};

		Args args;

		string mountPoint = mountedVolume->MountPoint;
		if (mountPoint.size() < 2 || mountPoint[1] != ':')
			return;

		args.DriveRootPath = string() + mountPoint[0] + string (":\\");
		
		EnumWindows (Enumerator::TopLevelWindows, (LPARAM) &args);
#endif
	}

	void UserInterface::DismountAllVolumes (bool ignoreOpenFiles, bool interactive) const
	{
		try
		{
			VolumeInfoList mountedVolumes = Core->GetMountedVolumes();

			if (mountedVolumes.size() < 1)
				ShowInfo (LangString["NO_VOLUMES_MOUNTED"]);

			BusyScope busy (this);
			DismountVolumes (mountedVolumes, ignoreOpenFiles, interactive);
		}
		catch (exception &e)
		{
			ShowError (e);
		}
	}

	void UserInterface::DismountVolume (shared_ptr <VolumeInfo> volume, bool ignoreOpenFiles, bool interactive) const
	{
		VolumeInfoList volumes;
		volumes.push_back (volume);

		DismountVolumes (volumes, ignoreOpenFiles, interactive);
	}

	void UserInterface::DismountVolumes (VolumeInfoList volumes, bool ignoreOpenFiles, bool interactive) const
	{
		BusyScope busy (this);

		volumes.sort (VolumeInfo::FirstVolumeMountedAfterSecond);

		wxString message;
		bool twoPassMode = volumes.size() > 1;
		bool volumesInUse = false;
		bool firstPass = true;

#ifdef TC_WINDOWS
		if (Preferences.CloseExplorerWindowsOnDismount)
		{
			foreach (shared_ptr <VolumeInfo> volume, volumes)
				CloseExplorerWindows (volume);
		}
#endif
		while (!volumes.empty())
		{
			VolumeInfoList volumesLeft;
			foreach (shared_ptr <VolumeInfo> volume, volumes)
			{
				try
				{
					BusyScope busy (this);
					volume = Core->DismountVolume (volume, ignoreOpenFiles);
				}
				catch (MountedVolumeInUse&)
				{
					if (!firstPass)
						throw;

					if (twoPassMode || !interactive)
					{
						volumesInUse = true;
						volumesLeft.push_back (volume);
						continue;
					}
					else
					{
						if (AskYesNo (StringFormatter (LangString["UNMOUNT_LOCK_FAILED"], wstring (volume->Path)), true, true))
						{
							BusyScope busy (this);
							volume = Core->DismountVolume (volume, true);
						}
						else
							throw UserAbort (SRC_POS);
					}
				}
				catch (...)
				{
					if (twoPassMode && firstPass)
						volumesLeft.push_back (volume);
					else
						throw;
				}

				if (volume->HiddenVolumeProtectionTriggered)
					ShowWarning (StringFormatter (LangString["DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"], wstring (volume->Path)));

				if (Preferences.Verbose)
				{
					if (!message.IsEmpty())
						message += L'\n';
					message += StringFormatter (_("Volume \"{0}\" has been dismounted."), wstring (volume->Path));
				}
			}

			if (twoPassMode && firstPass)
			{
				volumes = volumesLeft;

				if (volumesInUse && interactive)
				{
					if (AskYesNo (LangString["UNMOUNTALL_LOCK_FAILED"], true, true))
						ignoreOpenFiles = true;
					else
						throw UserAbort (SRC_POS);
				}
			}
			else
				break;

			firstPass = false;
		}

		if (Preferences.Verbose && !message.IsEmpty())
			ShowInfo (message);
	}
		
	void UserInterface::DisplayVolumeProperties (const VolumeInfoList &volumes) const
	{
		if (volumes.size() < 1)
			throw_err (LangString["NO_VOLUMES_MOUNTED"]);

		wxString prop;

		foreach_ref (const VolumeInfo &volume, volumes)
		{
			prop << _("Slot") << L": " << StringConverter::FromNumber (volume.SlotNumber) << L'\n';
			prop << LangString["VOLUME"] << L": " << wstring (volume.Path) << L'\n';
#ifndef TC_WINDOWS
			prop << LangString["VIRTUAL_DEVICE"] << L": " << wstring (volume.VirtualDevice) << L'\n';
#endif
			prop << LangString["MOUNT_POINT"] << L": " << wstring (volume.MountPoint) << L'\n';
			prop << LangString["SIZE"] << L": " << SizeToString (volume.Size) << L'\n';
			prop << LangString["TYPE"] << L": " << VolumeTypeToString (volume.Type, volume.Protection) << L'\n';

			prop << LangString["READ_ONLY"] << L": " << LangString [volume.Protection == VolumeProtection::ReadOnly ? "UISTR_YES" : "UISTR_NO"] << L'\n';

			wxString protection;
			if (volume.Type == VolumeType::Hidden)
				protection = LangString["NOT_APPLICABLE_OR_NOT_AVAILABLE"];
			else if (volume.HiddenVolumeProtectionTriggered)
				protection = LangString["HID_VOL_DAMAGE_PREVENTED"];
			else
				protection = LangString [volume.Protection == VolumeProtection::HiddenVolumeReadOnly ? "UISTR_YES" : "UISTR_NO"];

			prop << LangString["HIDDEN_VOL_PROTECTION"] << L": " << protection << L'\n';
			prop << LangString["ENCRYPTION_ALGORITHM"] << L": " << volume.EncryptionAlgorithmName << L'\n';
			prop << LangString["KEY_SIZE"] << L": " << StringFormatter (L"{0} {1}", volume.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]) << L'\n';

			if (volume.EncryptionModeName == L"XTS")
				prop << LangString["SECONDARY_KEY_SIZE_XTS"] << L": " << StringFormatter (L"{0} {1}", volume.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]) << L'\n';;

			wstringstream blockSize;
			blockSize << volume.EncryptionAlgorithmBlockSize * 8;
			if (volume.EncryptionAlgorithmBlockSize != volume.EncryptionAlgorithmMinBlockSize)
				blockSize << L"/" << volume.EncryptionAlgorithmMinBlockSize * 8;

			prop << LangString["BLOCK_SIZE"] << L": " << blockSize.str() + L" " + LangString ["BITS"] << L'\n';
			prop << LangString["MODE_OF_OPERATION"] << L": " << volume.EncryptionModeName << L'\n';
			prop << LangString["PKCS5_PRF"] << L": " << volume.Pkcs5PrfName << L'\n';
	
			prop << LangString["VOLUME_FORMAT_VERSION"] << L": " << (volume.MinRequiredProgramVersion < 0x10b ? 1 : 2) << L'\n';
			prop << LangString["BACKUP_HEADER"] << L": " << LangString[volume.MinRequiredProgramVersion >= 0x10b ? "UISTR_YES" : "UISTR_NO"] << L'\n';

#ifdef TC_LINUX
			if (string (volume.VirtualDevice).find ("/dev/mapper/veracrypt") != 0)
			{
#endif
			prop << LangString["TOTAL_DATA_READ"] << L": " << SizeToString (volume.TotalDataRead) << L'\n';
			prop << LangString["TOTAL_DATA_WRITTEN"] << L": " << SizeToString (volume.TotalDataWritten) << L'\n';
#ifdef TC_LINUX
			}
#endif
		
			prop << L'\n';
		}

		ShowString (prop);
	}

	wxString UserInterface::ExceptionToMessage (const exception &ex) const
	{
		wxString message;
		
		const Exception *e = dynamic_cast <const Exception *> (&ex);
		if (e)
		{
			message = ExceptionToString (*e);

			// System exception
			const SystemException *sysEx = dynamic_cast <const SystemException *> (&ex);
			if (sysEx)
			{
				if (!message.IsEmpty())
				{
					message += L"\n\n";
				}

				message += wxString (sysEx->SystemText()).Trim (true);
			}

			if (!message.IsEmpty())
			{
				// Subject
				if (!e->GetSubject().empty())
				{
					message = message.Trim (true);

					if (message.EndsWith (L"."))
						message.Truncate (message.size() - 1);

					if (!message.EndsWith (L":"))
						message << L":\n";
					else
						message << L"\n";

					message << e->GetSubject();
				}

#ifdef TC_UNIX
				if (sysEx && sysEx->GetErrorCode() == EIO)
					message << L"\n\n" << LangString["ERR_HARDWARE_ERROR"];
#endif

#ifdef DEBUG
				if (sysEx && sysEx->what())
					message << L"\n\n" << StringConverter::ToWide (sysEx->what());
#endif
				return message;
			}
		}

		// bad_alloc
		const bad_alloc *outOfMemory = dynamic_cast <const bad_alloc *> (&ex);
		if (outOfMemory)
			return _("Out of memory.");

		// Unresolved exceptions
		string typeName (StringConverter::GetTypeName (typeid (ex)));
		size_t pos = typeName.find ("VeraCrypt::");
		if (pos != string::npos)
		{
			return StringConverter::ToWide (typeName.substr (pos + string ("VeraCrypt::").size()))
				+ L" at " + StringConverter::ToWide (ex.what());
		}

		return StringConverter::ToWide (typeName) + L" at " + StringConverter::ToWide (ex.what());
	}

	wxString UserInterface::ExceptionToString (const Exception &ex) const
	{
		// Error messages
		const ErrorMessage *errMsgEx = dynamic_cast <const ErrorMessage *> (&ex);
		if (errMsgEx)
			return wstring (*errMsgEx).c_str();

		// ExecutedProcessFailed
		const ExecutedProcessFailed *execEx = dynamic_cast <const ExecutedProcessFailed *> (&ex);
		if (execEx)
		{
			wstring errOutput;

			// ElevationFailed
			if (dynamic_cast <const ElevationFailed*> (&ex))
				errOutput += wxString (_("Failed to obtain administrator privileges")) + (StringConverter::Trim (execEx->GetErrorOutput()).empty() ? L". " : L": ");

			errOutput += StringConverter::ToWide (execEx->GetErrorOutput());

			if (errOutput.empty())
				return errOutput + StringFormatter (_("Command \"{0}\" returned error {1}."), execEx->GetCommand(), execEx->GetExitCode());

			return wxString (errOutput).Trim (true);
		}

		// PasswordIncorrect 
		if (dynamic_cast <const PasswordException *> (&ex))
		{
			wxString message = ExceptionTypeToString (typeid (ex));

#ifndef TC_NO_GUI
			if (Application::GetUserInterfaceType() == UserInterfaceType::Graphic && wxGetKeyState (WXK_CAPITAL))
				message += wxString (L"\n\n") + LangString["CAPSLOCK_ON"];
#endif
			if (Keyfile::WasHiddenFilePresentInKeyfilePath())
			{
#ifdef TC_UNIX
				message += _("\n\nWarning: Hidden files are present in a keyfile path. If you need to use them as keyfiles, remove the leading dot from their filenames. Hidden files are visible only if enabled in system options.");
#else
				message += LangString["HIDDEN_FILES_PRESENT_IN_KEYFILE_PATH"];
#endif
			}

			return message;
		}

		// PKCS#11 Exception
		if (dynamic_cast <const Pkcs11Exception *> (&ex))
		{
			string errorString = string (dynamic_cast <const Pkcs11Exception &> (ex));
			
			if (LangString.Exists (errorString))
				return LangString[errorString];

			if (errorString.find ("CKR_") == 0)
			{
				errorString = errorString.substr (4);
				for (size_t i = 0; i < errorString.size(); ++i)
				{
					if (errorString[i] == '_')
						errorString[i] = ' ';
				}
			}

			return LangString["SECURITY_TOKEN_ERROR"] + L":\n\n" + StringConverter::ToWide (errorString);
		}

		// Other library exceptions
		return ExceptionTypeToString (typeid (ex));
	}

	wxString UserInterface::ExceptionTypeToString (const std::type_info &ex) const
	{
#define EX2MSG(exception, message) do { if (ex == typeid (exception)) return (message); } while (false)
		EX2MSG (DriveLetterUnavailable,				LangString["DRIVE_LETTER_UNAVAILABLE"]);
		EX2MSG (EncryptedSystemRequired,			_("This operation must be performed only when the system hosted on the volume is running."));
		EX2MSG (ExternalException,					LangString["EXCEPTION_OCCURRED"]);
		EX2MSG (InsufficientData,					_("Not enough data available."));
		EX2MSG (InvalidSecurityTokenKeyfilePath,	LangString["INVALID_TOKEN_KEYFILE_PATH"]);
		EX2MSG (HigherVersionRequired,				LangString["NEW_VERSION_REQUIRED"]);
		EX2MSG (KernelCryptoServiceTestFailed,		_("Kernel cryptographic service test failed. The cryptographic service of your kernel most likely does not support volumes larger than 2 TB.\n\nPossible solutions:\n- Upgrade the Linux kernel to version 2.6.33 or later.\n- Disable use of the kernel cryptographic services (Settings > Preferences > System Integration) or use 'nokernelcrypto' mount option on the command line."));
		EX2MSG (KeyfilePathEmpty,					LangString["ERR_KEYFILE_PATH_EMPTY"]);
		EX2MSG (LoopDeviceSetupFailed,				_("Failed to set up a loop device."));
		EX2MSG (MissingArgument,					_("A required argument is missing."));
		EX2MSG (MissingVolumeData,					_("Volume data missing."));
		EX2MSG (MountPointRequired,					_("Mount point required."));
		EX2MSG (MountPointUnavailable,				_("Mount point is already in use."));
		EX2MSG (NoDriveLetterAvailable,				LangString["NO_FREE_DRIVES"]);
		EX2MSG (PasswordEmpty,						_("No password or keyfile specified."));
		EX2MSG (PasswordIncorrect,					LangString["PASSWORD_WRONG"]);
		EX2MSG (PasswordKeyfilesIncorrect,			LangString["PASSWORD_OR_KEYFILE_WRONG"]);
		EX2MSG (PasswordOrKeyboardLayoutIncorrect,	LangString["PASSWORD_OR_KEYFILE_WRONG"] + _("\n\nNote that pre-boot authentication passwords need to be typed in the pre-boot environment where non-US keyboard layouts are not available. Therefore, pre-boot authentication passwords must always be typed using the standard US keyboard layout (otherwise, the password will be typed incorrectly in most cases). However, note that you do NOT need a real US keyboard; you just need to change the keyboard layout in your operating system."));
		EX2MSG (PasswordOrMountOptionsIncorrect,	LangString["PASSWORD_OR_KEYFILE_OR_MODE_WRONG"] + _("\n\nNote: If you are attempting to mount a partition located on an encrypted system drive without pre-boot authentication or to mount the encrypted system partition of an operating system that is not running, you can do so by selecting 'Options >' > 'Mount partition using system encryption'."));
		EX2MSG (PasswordTooLong,					StringFormatter (_("Password is longer than {0} characters."), (int) VolumePassword::MaxSize));
		EX2MSG (PartitionDeviceRequired,			_("Partition device required."));
		EX2MSG (ProtectionPasswordIncorrect,		_("Incorrect password to the protected hidden volume or the hidden volume does not exist."));
		EX2MSG (ProtectionPasswordKeyfilesIncorrect,_("Incorrect keyfile(s) and/or password to the protected hidden volume or the hidden volume does not exist."));
		EX2MSG (RootDeviceUnavailable,				LangString["NODRIVER"]);
		EX2MSG (SecurityTokenKeyfileAlreadyExists,	LangString["TOKEN_KEYFILE_ALREADY_EXISTS"]);
		EX2MSG (SecurityTokenKeyfileNotFound,		LangString["TOKEN_KEYFILE_NOT_FOUND"]);
		EX2MSG (SecurityTokenLibraryNotInitialized,	LangString["PKCS11_MODULE_INIT_FAILED"]);
		EX2MSG (StringConversionFailed,				_("Invalid characters encountered."));
		EX2MSG (StringFormatterException,			_("Error while parsing formatted string."));
		EX2MSG (TemporaryDirectoryFailure,			_("Failed to create a file or directory in a temporary directory.\n\nPlease make sure that the temporary directory exists, its security permissions allow you to access it, and there is sufficient disk space."));
		EX2MSG (UnportablePassword,					LangString["UNSUPPORTED_CHARS_IN_PWD"]);

#if defined (TC_LINUX)
		EX2MSG (UnsupportedSectorSize,				LangString["SECTOR_SIZE_UNSUPPORTED"]);
		EX2MSG (UnsupportedSectorSizeHiddenVolumeProtection, _("Error: The drive uses a sector size other than 512 bytes.\n\nDue to limitations of components available on your platform, outer volumes hosted on the drive cannot be mounted using hidden volume protection.\n\nPossible solutions:\n- Use a drive with 512-byte sectors.\n- Create a file-hosted volume (container) on the drive.\n- Backup the contents of the hidden volume and then update the outer volume."));
		EX2MSG (UnsupportedSectorSizeNoKernelCrypto, _("Error: The drive uses a sector size other than 512 bytes.\n\nDue to limitations of components available on your platform, partition/device-hosted volumes on the drive can only be mounted using kernel cryptographic services.\n\nPossible solutions:\n- Enable use of the kernel cryptographic services (Preferences > System Integration).\n- Use a drive with 512-byte sectors.\n- Create a file-hosted volume (container) on the drive."));
#else
		EX2MSG (UnsupportedSectorSize,				_("Error: The drive uses a sector size other than 512 bytes.\n\nDue to limitations of components available on your platform, partition/device-hosted volumes cannot be created/used on the drive.\n\nPossible solutions:\n- Create a file-hosted volume (container) on the drive.\n- Use a drive with 512-byte sectors.\n- Use VeraCrypt on another platform."));
#endif

		EX2MSG (VolumeAlreadyMounted,				LangString["VOL_ALREADY_MOUNTED"]);
		EX2MSG (VolumeEncryptionNotCompleted,		LangString["ERR_ENCRYPTION_NOT_COMPLETED"]);
		EX2MSG (VolumeHostInUse,					_("The host file/device is already in use."));
		EX2MSG (VolumeSlotUnavailable,				_("Volume slot unavailable."));

#ifdef TC_MACOSX
		EX2MSG (HigherFuseVersionRequired,			_("VeraCrypt requires OSXFUSE 2.3 or later."));
#endif

#undef EX2MSG
		return L"";
	}

	void UserInterface::Init ()
	{
		SetAppName (Application::GetName());
		SetClassName (Application::GetName());

		LangString.Init();
		Core->Init();

		wxCmdLineParser parser;
		parser.SetCmdLine (argc, argv);
		CmdLine.reset (new CommandLineInterface (parser, InterfaceType));
		SetPreferences (CmdLine->Preferences);

		Core->SetApplicationExecutablePath (Application::GetExecutablePath());

		if (!Preferences.NonInteractive)
		{
			Core->SetAdminPasswordCallback (GetAdminPasswordRequestHandler());
		}
		else
		{
			struct AdminPasswordRequestHandler : public GetStringFunctor
			{
				virtual void operator() (string &str)
				{
					throw ElevationFailed (SRC_POS, "sudo", 1, "");
				}
			};

			Core->SetAdminPasswordCallback (shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler));
		}

		Core->WarningEvent.Connect (EventConnector <UserInterface> (this, &UserInterface::OnWarning));
		Core->VolumeMountedEvent.Connect (EventConnector <UserInterface> (this, &UserInterface::OnVolumeMounted));

		if (!CmdLine->Preferences.SecurityTokenModule.IsEmpty() && !SecurityToken::IsInitialized())
		{
			try
			{
				InitSecurityTokenLibrary();
			}
			catch (exception &e)
			{
				if (Preferences.NonInteractive)
					throw;

				ShowError (e);
			}
		}
	}
	
	void UserInterface::ListMountedVolumes (const VolumeInfoList &volumes) const
	{
		if (volumes.size() < 1)
			throw_err (LangString["NO_VOLUMES_MOUNTED"]);

		wxString message;

		foreach_ref (const VolumeInfo &volume, volumes)
		{
			message << volume.SlotNumber << L": " << StringConverter::QuoteSpaces (volume.Path);

			if (!volume.VirtualDevice.IsEmpty())
				message << L' ' << wstring (volume.VirtualDevice);
			else
				message << L" - ";

			if (!volume.MountPoint.IsEmpty())
				message << L' ' << StringConverter::QuoteSpaces (volume.MountPoint);
			else
				message << L" - ";

			message << L'\n';
		}

		ShowString (message);
	}

	VolumeInfoList UserInterface::MountAllDeviceHostedVolumes (MountOptions &options) const
	{
		BusyScope busy (this);

		VolumeInfoList newMountedVolumes;

		if (!options.MountPoint)
			options.MountPoint.reset (new DirectoryPath);

		Core->CoalesceSlotNumberAndMountPoint (options);

		bool sharedAccessAllowed = options.SharedAccessAllowed;
		bool someVolumesShared = false;

		HostDeviceList devices;
		foreach (shared_ptr <HostDevice> device, Core->GetHostDevices (true))
		{
			devices.push_back (device);

			foreach (shared_ptr <HostDevice> partition, device->Partitions)
				devices.push_back (partition);
		}

		set <wstring> mountedVolumes;
		foreach_ref (const VolumeInfo &v, Core->GetMountedVolumes())
			mountedVolumes.insert (v.Path);

		bool protectedVolumeMounted = false;
		bool legacyVolumeMounted = false;

		foreach_ref (const HostDevice &device, devices)
		{
			if (mountedVolumes.find (wstring (device.Path)) != mountedVolumes.end())
				continue;

			Yield();
			options.SlotNumber = Core->GetFirstFreeSlotNumber (options.SlotNumber);
			options.MountPoint.reset (new DirectoryPath);
			options.Path.reset (new VolumePath (device.Path));

			try
			{
				try
				{
					options.SharedAccessAllowed = sharedAccessAllowed;
					newMountedVolumes.push_back (Core->MountVolume (options));
				}
				catch (VolumeHostInUse&)
				{
					if (!sharedAccessAllowed)
					{
						try
						{
							options.SharedAccessAllowed = true;
							newMountedVolumes.push_back (Core->MountVolume (options));
							someVolumesShared = true;
						}
						catch (VolumeHostInUse&)
						{
							continue;
						}
					}
					else
						continue;
				}

				if (newMountedVolumes.back()->Protection == VolumeProtection::HiddenVolumeReadOnly)
					protectedVolumeMounted = true;

				if (newMountedVolumes.back()->EncryptionAlgorithmMinBlockSize == 8)
					legacyVolumeMounted = true;
			}
			catch (DriverError&) { }
			catch (MissingVolumeData&) { }
			catch (PasswordException&) { }
			catch (SystemException&) { }
			catch (ExecutedProcessFailed&) { }
		}

		if (newMountedVolumes.empty())
		{
			ShowWarning (LangString [options.Keyfiles && !options.Keyfiles->empty() ? "PASSWORD_OR_KEYFILE_WRONG_AUTOMOUNT" : "PASSWORD_WRONG_AUTOMOUNT"]);
		}
		else
		{
			if (someVolumesShared)
				ShowWarning ("DEVICE_IN_USE_INFO");

			if (legacyVolumeMounted)
				ShowWarning ("WARN_64_BIT_BLOCK_CIPHER");

			if (protectedVolumeMounted)
				ShowInfo (LangString[newMountedVolumes.size() > 1 ? "HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL" : "HIDVOL_PROT_WARN_AFTER_MOUNT"]);
		}

		if (!newMountedVolumes.empty() && GetPreferences().CloseSecurityTokenSessionsAfterMount)
			SecurityToken::CloseAllSessions();

		return newMountedVolumes;
	}

	VolumeInfoList UserInterface::MountAllFavoriteVolumes (MountOptions &options)
	{
		BusyScope busy (this);
		
		VolumeInfoList newMountedVolumes;
		foreach_ref (const FavoriteVolume &favorite, FavoriteVolume::LoadList())
		{
			shared_ptr <VolumeInfo> mountedVolume = Core->GetMountedVolume (favorite.Path);
			if (mountedVolume)
			{
				if (mountedVolume->MountPoint != favorite.MountPoint)
					ShowInfo (StringFormatter (LangString["VOLUME_ALREADY_MOUNTED"], wstring (favorite.Path)));
				continue;
			}

			favorite.ToMountOptions (options);

			if (Preferences.NonInteractive)
			{
				BusyScope busy (this);
				newMountedVolumes.push_back (Core->MountVolume (options));
			}
			else
			{
				try
				{
					BusyScope busy (this);
					newMountedVolumes.push_back (Core->MountVolume (options));
				}
				catch (...)
				{
					UserPreferences prefs = GetPreferences();
					if (prefs.CloseSecurityTokenSessionsAfterMount)
						Preferences.CloseSecurityTokenSessionsAfterMount = false;

					shared_ptr <VolumeInfo> volume = MountVolume (options);

					if (prefs.CloseSecurityTokenSessionsAfterMount)
						Preferences.CloseSecurityTokenSessionsAfterMount = true;

					if (!volume)
						break;
					newMountedVolumes.push_back (volume);
				}
			}
		}

		if (!newMountedVolumes.empty() && GetPreferences().CloseSecurityTokenSessionsAfterMount)
			SecurityToken::CloseAllSessions();

		return newMountedVolumes;
	}

	shared_ptr <VolumeInfo> UserInterface::MountVolume (MountOptions &options) const
	{
		shared_ptr <VolumeInfo> volume;

		try
		{
			volume = Core->MountVolume (options);
		}
		catch (VolumeHostInUse&)
		{
			if (options.SharedAccessAllowed)
				throw_err (LangString["FILE_IN_USE_FAILED"]);

			if (!AskYesNo (StringFormatter (LangString["VOLUME_HOST_IN_USE"], wstring (*options.Path)), false, true))
				throw UserAbort (SRC_POS);

			try
			{
				options.SharedAccessAllowed = true;
				volume = Core->MountVolume (options);
			}
			catch (VolumeHostInUse&)
			{
				throw_err (LangString["FILE_IN_USE_FAILED"]);
			}
		}

		if (volume->EncryptionAlgorithmMinBlockSize == 8)
			ShowWarning ("WARN_64_BIT_BLOCK_CIPHER");

		if (VolumeHasUnrecommendedExtension (*options.Path))
			ShowWarning ("EXE_FILE_EXTENSION_MOUNT_WARNING");

		if (options.Protection == VolumeProtection::HiddenVolumeReadOnly)
			ShowInfo ("HIDVOL_PROT_WARN_AFTER_MOUNT");

		if (GetPreferences().CloseSecurityTokenSessionsAfterMount)
			SecurityToken::CloseAllSessions();

		return volume;
	}

	void UserInterface::OnUnhandledException ()
	{
		try
		{
			throw;
		}
		catch (UserAbort&)
		{
		}
		catch (exception &e)
		{
			ShowError (e);
		}
		catch (...)
		{
			ShowError (_("Unknown exception occurred."));
		}

		Yield();
		Application::SetExitCode (1);
	}

	void UserInterface::OnVolumeMounted (EventArgs &args)
	{
		shared_ptr <VolumeInfo> mountedVolume = (dynamic_cast <VolumeEventArgs &> (args)).mVolume;

		if (Preferences.OpenExplorerWindowAfterMount && !mountedVolume->MountPoint.IsEmpty())
			OpenExplorerWindow (mountedVolume->MountPoint);
	}
	
	void UserInterface::OnWarning (EventArgs &args)
	{
		ExceptionEventArgs &e = dynamic_cast <ExceptionEventArgs &> (args);
		ShowWarning (e.mException);
	}

	void UserInterface::OpenExplorerWindow (const DirectoryPath &path)
	{
		if (path.IsEmpty())
			return;

		list <string> args;

#ifdef TC_WINDOWS

		wstring p (Directory::AppendSeparator (path));
		SHFILEINFO fInfo;
		SHGetFileInfo (p.c_str(), 0, &fInfo, sizeof (fInfo), 0); // Force explorer to discover the drive
		ShellExecute (GetTopWindow() ? static_cast <HWND> (GetTopWindow()->GetHandle()) : nullptr, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);

#elif defined (TC_MACOSX)

		args.push_back (string (path));
		try
		{
			Process::Execute ("open", args);
		}
		catch (exception &e) { ShowError (e); }

#else
		// MIME handler for directory seems to be unavailable through wxWidgets
		wxString desktop = GetTraits()->GetDesktopEnvironment();

		if (desktop == L"GNOME" || desktop.empty())
		{
			args.push_back ("--no-default-window");
			args.push_back ("--no-desktop");
			args.push_back (string (path));
			try
			{
				Process::Execute ("nautilus", args, 2000);
			}
			catch (TimeOut&) { }
			catch (exception &e) { ShowError (e); }
		}
		else if (desktop == L"KDE")
		{
			try
			{
				args.push_back (string (path));
				Process::Execute ("dolphin", args, 2000);
			}
			catch (TimeOut&) { }
			catch (exception&)
			{
				args.clear();
				args.push_back ("openURL");
				args.push_back (string (path));
				try
				{
					Process::Execute ("kfmclient", args, 2000);
				}
				catch (TimeOut&) { }
				catch (exception &e) { ShowError (e); }
			}
		}
#endif
	}

	bool UserInterface::ProcessCommandLine ()
	{
		CommandLineInterface &cmdLine = *CmdLine;

		switch (cmdLine.ArgCommand)
		{
		case CommandId::None:
			return false;

		case CommandId::AutoMountDevices:
		case CommandId::AutoMountFavorites:
		case CommandId::AutoMountDevicesFavorites:
		case CommandId::MountVolume:
			{
				cmdLine.ArgMountOptions.Path = cmdLine.ArgVolumePath;
				cmdLine.ArgMountOptions.MountPoint = cmdLine.ArgMountPoint;
				cmdLine.ArgMountOptions.Password = cmdLine.ArgPassword;
				cmdLine.ArgMountOptions.Keyfiles = cmdLine.ArgKeyfiles;
				cmdLine.ArgMountOptions.SharedAccessAllowed = cmdLine.ArgForce;

				VolumeInfoList mountedVolumes;
				switch (cmdLine.ArgCommand)
				{
				case CommandId::AutoMountDevices:
				case CommandId::AutoMountFavorites:
				case CommandId::AutoMountDevicesFavorites:
					{
						if (cmdLine.ArgCommand == CommandId::AutoMountDevices || cmdLine.ArgCommand == CommandId::AutoMountDevicesFavorites)
						{
							if (Preferences.NonInteractive)
								mountedVolumes = UserInterface::MountAllDeviceHostedVolumes (cmdLine.ArgMountOptions);
							else
								mountedVolumes = MountAllDeviceHostedVolumes (cmdLine.ArgMountOptions);
						}

						if (cmdLine.ArgCommand == CommandId::AutoMountFavorites || cmdLine.ArgCommand == CommandId::AutoMountDevicesFavorites)
						{
							foreach (shared_ptr <VolumeInfo> v, MountAllFavoriteVolumes(cmdLine.ArgMountOptions))
								mountedVolumes.push_back (v);
						}
					}
					break;


					break;

				case CommandId::MountVolume:
					if (Preferences.OpenExplorerWindowAfterMount)
					{
						// Open explorer window for an already mounted volume
						shared_ptr <VolumeInfo> mountedVolume = Core->GetMountedVolume (*cmdLine.ArgMountOptions.Path);
						if (mountedVolume && !mountedVolume->MountPoint.IsEmpty())
						{
							OpenExplorerWindow (mountedVolume->MountPoint);
							break;
						}
					}

					if (Preferences.NonInteractive)
					{
						// Volume path
						if (!cmdLine.ArgMountOptions.Path)
							throw MissingArgument (SRC_POS);

						mountedVolumes.push_back (Core->MountVolume (cmdLine.ArgMountOptions));
					}
					else
					{
						shared_ptr <VolumeInfo> volume = MountVolume (cmdLine.ArgMountOptions);
						if (!volume)
						{
							Application::SetExitCode (1);
							throw UserAbort (SRC_POS);
						}
						mountedVolumes.push_back (volume);
					}
					break;

				default:
					throw ParameterIncorrect (SRC_POS);
				}

				if (Preferences.Verbose && !mountedVolumes.empty())
				{
					wxString message;
					foreach_ref (const VolumeInfo &volume, mountedVolumes)
					{
						if (!message.IsEmpty())
							message += L'\n';
						message += StringFormatter (_("Volume \"{0}\" has been mounted."), wstring (volume.Path));
					}
					ShowInfo (message);
				}
			}
			return true;

		case CommandId::BackupHeaders:
			BackupVolumeHeaders (cmdLine.ArgVolumePath);
			return true;

		case CommandId::ChangePassword:
			ChangePassword (cmdLine.ArgVolumePath, cmdLine.ArgPassword, cmdLine.ArgKeyfiles, cmdLine.ArgNewPassword, cmdLine.ArgNewKeyfiles, cmdLine.ArgHash);
			return true;

		case CommandId::CreateKeyfile:
			CreateKeyfile (cmdLine.ArgFilePath);
			return true;

		case CommandId::CreateVolume:
			{
				make_shared_auto (VolumeCreationOptions, options);

				if (cmdLine.ArgHash)
				{
					options->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*cmdLine.ArgHash);
					RandomNumberGenerator::SetHash (cmdLine.ArgHash);
				}
				
				options->EA = cmdLine.ArgEncryptionAlgorithm;
				options->Filesystem = cmdLine.ArgFilesystem;
				options->Keyfiles = cmdLine.ArgKeyfiles;
				options->Password = cmdLine.ArgPassword;
				options->Quick = cmdLine.ArgQuick;
				options->Size = cmdLine.ArgSize;
				options->Type = cmdLine.ArgVolumeType;

				if (cmdLine.ArgVolumePath)
					options->Path = VolumePath (*cmdLine.ArgVolumePath);

				CreateVolume (options);
				return true;
			}

		case CommandId::DeleteSecurityTokenKeyfiles:
			DeleteSecurityTokenKeyfiles();
			return true;

		case CommandId::DismountVolumes:
			DismountVolumes (cmdLine.ArgVolumes, cmdLine.ArgForce, !Preferences.NonInteractive);
			return true;

		case CommandId::DisplayVersion:
			ShowString (Application::GetName() + L" " + StringConverter::ToWide (Version::String()) + L"\n");
			return true;

		case CommandId::DisplayVolumeProperties:
			DisplayVolumeProperties (cmdLine.ArgVolumes);
			return true;

		case CommandId::Help:
			{
				wstring helpText = StringConverter::ToWide (
					"Synopsis:\n"
					"\n"
					"veracrypt [OPTIONS] COMMAND\n"
					"veracrypt [OPTIONS] VOLUME_PATH [MOUNT_DIRECTORY]\n"
					"\n"
					"\n"
					"Commands:\n"
					"\n"
					"--auto-mount=devices|favorites\n"
					" Auto mount device-hosted or favorite volumes.\n"
					"\n"
					"--backup-headers[=VOLUME_PATH]\n"
					" Backup volume headers to a file. All required options are requested from the\n"
					" user.\n"
					"\n"
					"-c, --create[=VOLUME_PATH]\n"
					" Create a new volume. Most options are requested from the user if not specified\n"
					" on command line. See also options --encryption, -k, --filesystem, --hash, -p,\n"
					" --random-source, --quick, --size, --volume-type. Note that passing some of the\n"
					" options may affect security of the volume (see option -p for more information).\n"
					"\n"
					" Inexperienced users should use the graphical user interface to create a hidden\n"
					" volume. When using the text user interface, the following procedure must be\n"
					" followed to create a hidden volume:\n"
					"  1) Create an outer volume with no filesystem.\n"
					"  2) Create a hidden volume within the outer volume.\n"
					"  3) Mount the outer volume using hidden volume protection.\n"
					"  4) Create a filesystem on the virtual device of the outer volume.\n"
					"  5) Mount the new filesystem and fill it with data.\n"
					"  6) Dismount the outer volume.\n"
					"  If at any step the hidden volume protection is triggered, start again from 1).\n"
					"\n"
					"--create-keyfile[=FILE_PATH]\n"
					" Create a new keyfile containing pseudo-random data.\n"
					"\n"
					"-C, --change[=VOLUME_PATH]\n"
					" Change a password and/or keyfile(s) of a volume. Most options are requested\n"
					" from the user if not specified on command line. PKCS-5 PRF HMAC hash\n"
					" algorithm can be changed with option --hash. See also options -k,\n"
					" --new-keyfiles, --new-password, -p, --random-source.\n"
					"\n"
					"-d, --dismount[=MOUNTED_VOLUME]\n"
					" Dismount a mounted volume. If MOUNTED_VOLUME is not specified, all\n"
					" volumes are dismounted. See below for description of MOUNTED_VOLUME.\n"
					"\n"
					"--delete-token-keyfiles\n"
					" Delete keyfiles from security tokens. See also command --list-token-keyfiles.\n"
					"\n"
					"--export-token-keyfile\n"
					" Export a keyfile from a security token. See also command --list-token-keyfiles.\n"
					"\n"
					"--import-token-keyfiles\n"
					" Import keyfiles to a security token. See also option --token-lib.\n"
					"\n"
					"-l, --list[=MOUNTED_VOLUME]\n"
					" Display a list of mounted volumes. If MOUNTED_VOLUME is not specified, all\n"
					" volumes are listed. By default, the list contains only volume path, virtual\n"
					" device, and mount point. A more detailed list can be enabled by verbose\n"
					" output option (-v). See below for description of MOUNTED_VOLUME.\n"
					"\n"
					"--list-token-keyfiles\n"
					" Display a list of all available security token keyfiles. See also command\n"
					" --import-token-keyfiles.\n"
					"\n"
					"--mount[=VOLUME_PATH]\n"
					" Mount a volume. Volume path and other options are requested from the user\n"
					" if not specified on command line.\n"
					"\n"
					"--restore-headers[=VOLUME_PATH]\n"
					" Restore volume headers from the embedded or an external backup. All required\n"
					" options are requested from the user.\n"
					"\n"
					"--save-preferences\n"
					" Save user preferences.\n"
					"\n"
					"--test\n"
					" Test internal algorithms used in the process of encryption and decryption.\n"
					"\n"
					"--version\n"
					" Display program version.\n"
					"\n"
					"--volume-properties[=MOUNTED_VOLUME]\n"
					" Display properties of a mounted volume. See below for description of\n"
					" MOUNTED_VOLUME.\n"
					"\n"
					"MOUNTED_VOLUME:\n"
					" Specifies a mounted volume. One of the following forms can be used:\n"
					" 1) Path to the encrypted VeraCrypt volume.\n"
					" 2) Mount directory of the volume's filesystem (if mounted).\n"
					" 3) Slot number of the mounted volume (requires --slot).\n"
					"\n"
					"\n"
					"Options:\n"
					"\n"
					"--display-password\n"
					" Display password characters while typing.\n"
					"\n"
					"--encryption=ENCRYPTION_ALGORITHM\n"
					" Use specified encryption algorithm when creating a new volume.\n"
					"\n"
					"--filesystem=TYPE\n"
					" Filesystem type to mount. The TYPE argument is passed to mount(8) command\n"
					" with option -t. Default type is 'auto'. When creating a new volume, this\n"
					" option specifies the filesystem to be created on the new volume (only 'FAT'\n"
					" and 'none' TYPE is allowed). Filesystem type 'none' disables mounting or\n"
					" creating a filesystem.\n"
					"\n"
					"--force\n"
					" Force mounting of a volume in use, dismounting of a volume in use, or\n"
					" overwriting a file. Note that this option has no effect on some platforms.\n"
					"\n"
					"--fs-options=OPTIONS\n"
					" Filesystem mount options. The OPTIONS argument is passed to mount(8)\n"
					" command with option -o when a filesystem on a VeraCrypt volume is mounted.\n"
					" This option is not available on some platforms.\n"
					"\n"
					"--hash=HASH\n"
					" Use specified hash algorithm when creating a new volume or changing password\n"
					" and/or keyfiles. This option also specifies the mixing PRF of the random\n"
					" number generator.\n"
					"\n"
					"-k, --keyfiles=KEYFILE1[,KEYFILE2,KEYFILE3,...]\n"
					" Use specified keyfiles when mounting a volume or when changing password\n"
					" and/or keyfiles. When a directory is specified, all files inside it will be\n"
					" used (non-recursively). Multiple keyfiles must be separated by comma.\n"
					" Use double comma (,,) to specify a comma contained in keyfile's name.\n"
					" Keyfile stored on a security token must be specified as\n"
					" token://slot/SLOT_NUMBER/file/FILENAME. An empty keyfile (-k \"\") disables\n"
					" interactive requests for keyfiles. See also options --import-token-keyfiles,\n"
					" --list-token-keyfiles, --new-keyfiles, --protection-keyfiles.\n"
					"\n"
					"--load-preferences\n"
					" Load user preferences.\n"
					"\n"
					"-m, --mount-options=OPTION1[,OPTION2,OPTION3,...]\n"
					" Specifies comma-separated mount options for a VeraCrypt volume:\n"
					"  headerbak: Use backup headers when mounting a volume.\n"
					"  nokernelcrypto: Do not use kernel cryptographic services.\n"
					"  readonly|ro: Mount volume as read-only.\n"
					"  system: Mount partition using system encryption.\n"
					"  timestamp|ts: Do not restore host-file modification timestamp when a volume\n"
					"   is dismounted (note that the operating system under certain circumstances\n"
					"   does not alter host-file timestamps, which may be mistakenly interpreted\n"
					"   to mean that this option does not work).\n"
					" See also option --fs-options.\n"
					"\n"
					"--new-keyfiles=KEYFILE1[,KEYFILE2,KEYFILE3,...]\n"
					" Add specified keyfiles to a volume. This option can only be used with command\n"
					" -C.\n"
					"\n"
					"--new-password=PASSWORD\n"
					" Specifies a new password. This option can only be used with command -C.\n"
					"\n"
					"-p, --password=PASSWORD\n"
					" Use specified password to mount/open a volume. An empty password can also be\n"
					" specified (-p \"\"). Note that passing a password on the command line is\n"
					" potentially insecure as the password may be visible in the process list\n"
					" (see ps(1)) and/or stored in a command history file or system logs.\n"
					"\n"
					"--protect-hidden=yes|no\n"
					" Write-protect a hidden volume when mounting an outer volume. Before mounting\n"
					" the outer volume, the user will be prompted for a password to open the hidden\n"
					" volume. The size and position of the hidden volume is then determined and the\n"
					" outer volume is mounted with all sectors belonging to the hidden volume\n"
					" protected against write operations. When a write to the protected area is\n"
					" prevented, the whole volume is switched to read-only mode. Verbose list\n"
					" (-v -l) can be used to query the state of the hidden volume protection.\n"
					" Warning message is displayed when a volume switched to read-only is being\n"
					" dismounted.\n"
					"\n"
					"--protection-keyfiles=KEYFILE1[,KEYFILE2,KEYFILE3,...]\n"
					" Use specified keyfiles to open a hidden volume to be protected. This option\n"
					" may be used only when mounting an outer volume with hidden volume protected.\n"
					" See also options -k and --protect-hidden.\n"
					"\n"
					"--protection-password=PASSWORD\n"
					" Use specified password to open a hidden volume to be protected. This option\n"
					" may be used only when mounting an outer volume with hidden volume protected.\n"
					" See also options -p and --protect-hidden.\n"
					"\n"
					"--quick\n"
					" Do not encrypt free space when creating a device-hosted volume. This option\n"
					" must not be used when creating an outer volume.\n"
					"\n"
					"--random-source=FILE\n"
					" Use FILE as a source of random data (e.g., when creating a volume) instead\n"
					" of requiring the user to type random characters.\n"
					"\n"
					"--slot=SLOT\n"
					" Use specified slot number when mounting, dismounting, or listing a volume.\n"
					"\n"
					"--size=SIZE\n"
					" Use specified size in bytes when creating a new volume.\n"
					"\n"
					"-t, --text\n"
					" Use text user interface. Graphical user interface is used by default if\n"
					" available. This option must be specified as the first argument.\n"
					"\n"
					"--token-lib=LIB_PATH\n"
					" Use specified PKCS #11 security token library.\n"
					"\n"
					"--volume-type=TYPE\n"
					" Use specified volume type when creating a new volume. TYPE can be 'normal'\n"
					" or 'hidden'. See option -c for more information on creating hidden volumes.\n"
					"\n"
					"-v, --verbose\n"
					" Enable verbose output.\n"
					"\n"
					"\n"
					"IMPORTANT:\n"
					"\n"
					"If you want to use VeraCrypt, you must follow the security requirements and\n"
					"security precautions listed in chapter 'Security Requirements and Precautions'\n"
					"in the VeraCrypt documentation (file 'VeraCrypt User Guide.pdf').\n"
					"\n"
					"\nExamples:\n\n"
					"Create a new volume:\n"
					"veracrypt -t -c\n"
					"\n"
					"Mount a volume:\n"
					"veracrypt volume.hc /media/veracrypt1\n"
					"\n"
					"Mount a volume as read-only, using keyfiles:\n"
					"veracrypt -m ro -k keyfile1,keyfile2 volume.tc\n"
					"\n"
					"Mount a volume without mounting its filesystem:\n"
					"veracrypt --filesystem=none volume.tc\n"
					"\n"
					"Mount a volume prompting only for its password:\n"
					"veracrypt -t -k \"\" --protect-hidden=no volume.hc /media/veracrypt1\n"
					"\n"
					"Dismount a volume:\n"
					"veracrypt -d volume.tc\n"
					"\n"
					"Dismount all mounted volumes:\n"
					"veracrypt -d\n"
				);

#ifndef TC_NO_GUI
				if (Application::GetUserInterfaceType() == UserInterfaceType::Graphic)
				{
					wxDialog dialog (nullptr, wxID_ANY, _("VeraCrypt Command Line Help"), wxDefaultPosition);

					wxTextCtrl *textCtrl = new wxTextCtrl (&dialog, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
					textCtrl->SetFont (wxFont (wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, L"Courier"));
					textCtrl->SetValue (helpText);

					int fontWidth, fontHeight;
					textCtrl->GetTextExtent (L"A", &fontWidth, &fontHeight);
					dialog.SetSize (wxSize (fontWidth * 85, fontHeight * 29));

					wxBoxSizer *sizer = new wxBoxSizer (wxVERTICAL);
					sizer->Add (textCtrl, 1, wxALL | wxEXPAND, 5);
					sizer->Add (new wxButton (&dialog, wxID_OK, _("OK")), 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 5);

					dialog.SetSizer (sizer);
					dialog.Layout();
					dialog.ShowModal();
				}
				else
#endif // !TC_NO_GUI
				{
					ShowString (L"\n\n");
					ShowString (helpText);
				}
			}
			return true;

		case CommandId::ExportSecurityTokenKeyfile:
			ExportSecurityTokenKeyfile();
			return true;

		case CommandId::ImportSecurityTokenKeyfiles:
			ImportSecurityTokenKeyfiles();
			return true;

		case CommandId::ListSecurityTokenKeyfiles:
			ListSecurityTokenKeyfiles();
			return true;

		case CommandId::ListVolumes:
			if (Preferences.Verbose)
				DisplayVolumeProperties (cmdLine.ArgVolumes);
			else
				ListMountedVolumes (cmdLine.ArgVolumes);
			return true;

		case CommandId::RestoreHeaders:
			RestoreVolumeHeaders (cmdLine.ArgVolumePath);
			return true;

		case CommandId::SavePreferences:
			Preferences.Save();
			return true;

		case CommandId::Test:
			Test();
			return true;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		return false;
	}

	void UserInterface::SetPreferences (const UserPreferences &preferences)
	{
		Preferences = preferences;

		Cipher::EnableHwSupport (!preferences.DefaultMountOptions.NoHardwareCrypto);

		PreferencesUpdatedEvent.Raise();
	}

	void UserInterface::ShowError (const exception &ex) const
	{
		if (!dynamic_cast <const UserAbort*> (&ex))
			DoShowError (ExceptionToMessage (ex));
	}

	wxString UserInterface::SizeToString (uint64 size) const
	{
		wstringstream s;
		if (size > 1024ULL*1024*1024*1024*1024*99)
			s << size/1024/1024/1024/1024/1024 << L" " << LangString["PB"].c_str();
		else if (size > 1024ULL*1024*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024/1024/1024), LangString["PB"].c_str());
		else if (size > 1024ULL*1024*1024*1024*99)
			s << size/1024/1024/1024/1024 << L" " << LangString["TB"].c_str();
		else if (size > 1024ULL*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024/1024), LangString["TB"].c_str());
		else if (size > 1024ULL*1024*1024*99)
			s << size/1024/1024/1024 << L" " << LangString["GB"].c_str();
		else if (size > 1024ULL*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024), LangString["GB"].c_str());
		else if (size > 1024ULL*1024*99)
			s << size/1024/1024 << L" " << LangString["MB"].c_str();
		else if (size > 1024ULL*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024), LangString["MB"].c_str());
		else if (size > 1024ULL)
			s << size/1024 << L" " << LangString["KB"].c_str();
		else
			s << size << L" " << LangString["BYTE"].c_str();

		return s.str();
	}

	wxString UserInterface::SpeedToString (uint64 speed) const
	{
		wstringstream s;

		if (speed > 1024ULL*1024*1024*1024*1024*99)
			s << speed/1024/1024/1024/1024/1024 << L" " << LangString["PB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024/1024/1024), LangString["PB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*1024*1024*99)
			s << speed/1024/1024/1024/1024 << L" " << LangString["TB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024/1024), LangString["TB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*1024*99)
			s << speed/1024/1024/1024 << L" " << LangString["GB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*999)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024), LangString["GB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*9)
			s << speed/1024/1024 << L" " << LangString["MB_PER_SEC"].c_str();
		else if (speed > 1024ULL*999)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024), LangString["MB_PER_SEC"].c_str());
		else if (speed > 1024ULL)
			s << speed/1024 << L" " << LangString["KB_PER_SEC"].c_str();
		else
			s << speed << L" " << LangString["B_PER_SEC"].c_str();

		return s.str();
	}

	void UserInterface::Test () const
	{
		if (!PlatformTest::TestAll())
			throw TestFailed (SRC_POS);

		EncryptionTest::TestAll();

		// StringFormatter
		if (StringFormatter (L"{9} {8} {7} {6} {5} {4} {3} {2} {1} {0} {{0}}", "1", L"2", '3', L'4', 5, 6, 7, 8, 9, 10) != L"10 9 8 7 6 5 4 3 2 1 {0}")
			throw TestFailed (SRC_POS);
		try
		{
			StringFormatter (L"{0} {1}", 1);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} {1} {1}", 1, 2, 3);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} 1}", 1, 2);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} {1", 1, 2);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		ShowInfo ("TESTS_PASSED");
	}

	wxString UserInterface::TimeSpanToString (uint64 seconds) const
	{
		wstringstream s;

		if (seconds >= 60 * 60 * 24 * 2)
			s << seconds / (60 * 24 * 60) << L" " << LangString["DAYS"].c_str();
		else if (seconds >= 120 * 60)
			s << seconds / (60 * 60) << L" " << LangString["HOURS"].c_str();
		else if (seconds >= 120)
			s << seconds / 60 << L" " << LangString["MINUTES"].c_str();
		else
			s << seconds << L" " << LangString["SECONDS"].c_str();

		return s.str();
	}
	
	bool UserInterface::VolumeHasUnrecommendedExtension (const VolumePath &path) const
	{
		wxString ext = wxFileName (wxString (wstring (path)).Lower()).GetExt();
		return ext.IsSameAs (L"exe") || ext.IsSameAs (L"sys") || ext.IsSameAs (L"dll");
	}

	wxString UserInterface::VolumeTimeToString (VolumeTime volumeTime) const
	{
		wxString dateStr = VolumeTimeToDateTime (volumeTime).Format();

#ifdef TC_WINDOWS

		FILETIME ft;
		*(unsigned __int64 *)(&ft) = volumeTime;
		SYSTEMTIME st;
		FileTimeToSystemTime (&ft, &st);

		wchar_t wstr[1024];
		if (GetDateFormat (LOCALE_USER_DEFAULT, 0, &st, 0, wstr, array_capacity (wstr)) != 0)
		{
			dateStr = wstr;
			GetTimeFormat (LOCALE_USER_DEFAULT, 0, &st, 0, wstr, array_capacity (wstr));
			dateStr += wxString (L" ") + wstr;
		}
#endif
		return dateStr;
	}

	wxString UserInterface::VolumeTypeToString (VolumeType::Enum type, VolumeProtection::Enum protection) const
	{
		switch (type)
		{
		case VolumeType::Normal:
			return LangString[protection == VolumeProtection::HiddenVolumeReadOnly ? "OUTER" : "NORMAL"];

		case VolumeType::Hidden:
			return LangString["HIDDEN"];

		default:
			return L"?";
		}
	}
}
