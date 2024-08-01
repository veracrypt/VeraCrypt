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

#include "System.h"
#include <set>
#include <typeinfo>
#include <wx/apptrait.h>
#include <wx/cmdline.h>
#include "Crypto/cpu.h"
#include "Platform/PlatformTest.h"
#include "Common/PCSCException.h"
#ifdef TC_UNIX
#include <errno.h>
#include "Platform/Unix/Process.h"
#endif
#include "Platform/SystemInfo.h"
#include "Platform/SystemException.h"
#include "Common/SecurityToken.h"
#include "Volume/EncryptionTest.h"
#include "Application.h"
#include "FavoriteVolume.h"
#include "UserInterface.h"

namespace VeraCrypt
{
	class AdminPasswordRequestHandler : public GetStringFunctor
	{
		public:
		virtual void operator() (string &str)
		{
			throw ElevationFailed (SRC_POS, "sudo", 1, "");
		}
	};

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
				ShowWarning (LangString["LINUX_KERNEL_OLD"]);
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
					message += StringFormatter (LangString["LINUX_VOL_DISMOUNTED"], wstring (volume->Path));
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
			prop << LangString["TOKEN_SLOT_ID"] << L": " << StringConverter::FromNumber (volume.SlotNumber) << L'\n';
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

	wxString UserInterface::ExceptionToMessage (const exception &ex)
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

				if (sysEx && sysEx->what())
					message << L"\n\n" << StringConverter::ToWide (sysEx->what());

				return message;
			}
		}

		// bad_alloc
		const bad_alloc *outOfMemory = dynamic_cast <const bad_alloc *> (&ex);
		if (outOfMemory)
			return LangString["LINUX_OOM"];

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

	wxString UserInterface::ExceptionToString (const Exception &ex)
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
				errOutput += wxString (LangString["LINUX_CANT_GET_ADMIN_PRIV"]) + (StringConverter::Trim (execEx->GetErrorOutput()).empty() ? L". " : L": ");

			errOutput += StringConverter::ToWide (execEx->GetErrorOutput());

			if (errOutput.empty())
				return errOutput + static_cast<wstring>(StringFormatter (LangString["LINUX_COMMAND_GET_ERROR"], execEx->GetCommand(), execEx->GetExitCode()));

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
				message += LangString["LINUX_HIDDEN_FILES_PRESENT_IN_KEYFILE_PATH"];
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


        // PCSC Exception
        if (dynamic_cast <const PCSCException *> (&ex))
        {
            string errorString = string (dynamic_cast <const PCSCException &> (ex));

            if (LangString.Exists (errorString))
                return LangString[errorString];

            if (errorString.find("SCARD_E_") == 0 || errorString.find("SCARD_F_") == 0 || errorString.find("SCARD_W_") == 0)
            {
                errorString = errorString.substr(8);
                for (size_t i = 0; i < errorString.size(); ++i)
                {
                    if (errorString[i] == '_')
                        errorString[i] = ' ';
                }
            }
            return LangString["PCSC_ERROR"] + L":\n\n" + StringConverter::ToWide (errorString);
        }

		// Other library exceptions
		return ExceptionTypeToString (typeid (ex));
	}

	wxString UserInterface::ExceptionTypeToString (const std::type_info &ex)
	{

#define EX2MSG(exception, message) do { if (ex == typeid (exception)) return (message); } while (false)
		EX2MSG (DriveLetterUnavailable,				LangString["DRIVE_LETTER_UNAVAILABLE"]);
		EX2MSG (DeviceSectorSizeMismatch,			LangString["LINUX_EX2MSG_DEVICESECTORSIZEMISMATCH"]);
		EX2MSG (EncryptedSystemRequired,			LangString["LINUX_EX2MSG_ENCRYPTEDSYSTEMREQUIRED"]);
		EX2MSG (ExternalException,					LangString["EXCEPTION_OCCURRED"]);
		EX2MSG (InsufficientData, 					LangString["LINUX_EX2MSG_INSUFFICIENTDATA"]);
		EX2MSG (InvalidSecurityTokenKeyfilePath,	LangString["INVALID_TOKEN_KEYFILE_PATH"]);
		EX2MSG (HigherVersionRequired,				LangString["NEW_VERSION_REQUIRED"]);
		EX2MSG (KernelCryptoServiceTestFailed,		LangString["LINUX_EX2MSG_KERNELCRYPTOSERVICETESTFAILED"]);
		EX2MSG (KeyfilePathEmpty,					LangString["ERR_KEYFILE_PATH_EMPTY"]);
		EX2MSG (LoopDeviceSetupFailed,				LangString["LINUX_EX2MSG_LOOPDEVICESETUPFAILED"]);
		EX2MSG (MissingArgument,					LangString["LINUX_EX2MSG_MISSINGARGUMENT"]);
		EX2MSG (MissingVolumeData,					LangString["LINUX_EX2MSG_MISSINGVOLUMEDATA"]);
		EX2MSG (MountPointRequired,					LangString["LINUX_EX2MSG_MOUNTPOINTREQUIRED"]);
		EX2MSG (MountPointUnavailable,				LangString["LINUX_EX2MSG_MOUNTPOINTUNAVAILABLE"]);
		EX2MSG (NoDriveLetterAvailable,				LangString["NO_FREE_DRIVES"]);
		EX2MSG (PasswordEmpty,						LangString["LINUX_EX2MSG_PASSWORDEMPTY"]);
		EX2MSG (PasswordIncorrect,					LangString["PASSWORD_WRONG"]);
		EX2MSG (PasswordKeyfilesIncorrect,			LangString["PASSWORD_OR_KEYFILE_WRONG"]);
		EX2MSG (PasswordOrKeyboardLayoutIncorrect,	LangString["PASSWORD_OR_KEYFILE_WRONG"] + LangString["LINUX_EX2MSG_PASSWORDORKEYBOARDLAYOUTINCORRECT"]);
		EX2MSG (PasswordOrMountOptionsIncorrect,	LangString["PASSWORD_OR_KEYFILE_OR_MODE_WRONG"] + LangString["LINUX_EX2MSG_PASSWORDORMOUNTOPTIONSINCORRECT"]);
		EX2MSG (PasswordTooLong,					StringFormatter (LangString["LINUX_EX2MSG_PASSWORDTOOLONG"], (int) VolumePassword::MaxSize));
		EX2MSG (PasswordUTF8TooLong,				LangString["PASSWORD_UTF8_TOO_LONG"]);
		EX2MSG (PasswordLegacyUTF8TooLong,			LangString["LEGACY_PASSWORD_UTF8_TOO_LONG"]);
		EX2MSG (PasswordUTF8Invalid,				LangString["PASSWORD_UTF8_INVALID"]);
		EX2MSG (PartitionDeviceRequired,			LangString["LINUX_EX2MSG_PARTITIONDEVICEREQUIRED"]);
		EX2MSG (ProtectionPasswordIncorrect,		LangString["LINUX_EX2MSG_PROTECTIONPASSWORDINCORRECT"]);
		EX2MSG (ProtectionPasswordKeyfilesIncorrect, LangString["LINUX_EX2MSG_PROTECTIONPASSWORDKEYFILESINCORRECT"]);
		EX2MSG (RootDeviceUnavailable,				LangString["NODRIVER"]);
		EX2MSG (SecurityTokenKeyfileAlreadyExists,	LangString["TOKEN_KEYFILE_ALREADY_EXISTS"]);
		EX2MSG (SecurityTokenKeyfileNotFound,		LangString["TOKEN_KEYFILE_NOT_FOUND"]);
		EX2MSG (SecurityTokenLibraryNotInitialized,	LangString["PKCS11_MODULE_INIT_FAILED"]);
		EX2MSG (StringConversionFailed,				LangString["LINUX_EX2MSG_STRINGCONVERSIONFAILED"]);
		EX2MSG (StringFormatterException,			LangString["LINUX_EX2MSG_STRINGFORMATTEREXCEPTION"]);
		EX2MSG (TemporaryDirectoryFailure,			LangString["LINUX_EX2MSG_TEMPORARYDIRECTORYFAILURE"]);
		EX2MSG (UnportablePassword,					LangString["UNSUPPORTED_CHARS_IN_PWD"]);

		EX2MSG (CommandAPDUNotValid,				LangString["COMMAND_APDU_INVALID"]);
		EX2MSG (ExtendedAPDUNotSupported,			LangString["EXTENDED_APDU_UNSUPPORTED"]);
		EX2MSG (ScardLibraryInitializationFailed,	LangString["SCARD_MODULE_INIT_FAILED"]);
		EX2MSG (EMVUnknownCardType,					LangString["EMV_UNKNOWN_CARD_TYPE"]);
		EX2MSG (EMVSelectAIDFailed,					LangString["EMV_SELECT_AID_FAILED"]);
		EX2MSG (EMVIccCertNotFound,					LangString["EMV_ICC_CERT_NOTFOUND"]);
		EX2MSG (EMVIssuerCertNotFound,				LangString["EMV_ISSUER_CERT_NOTFOUND"]);
		EX2MSG (EMVCPLCNotFound,					LangString["EMV_CPLC_NOTFOUND"]);
		EX2MSG (InvalidEMVPath,						LangString["INVALID_EMV_PATH"]);
		EX2MSG (EMVKeyfileDataNotFound,				LangString["EMV_KEYFILE_DATA_NOTFOUND"]);
		EX2MSG (EMVPANNotFound,						LangString["EMV_PAN_NOTFOUND"]);

#if defined (TC_LINUX)
		EX2MSG (TerminalNotFound,					LangString["LINUX_EX2MSG_TERMINALNOTFOUND"]);
		EX2MSG (UnsupportedSectorSize,				LangString["SECTOR_SIZE_UNSUPPORTED"]);
		EX2MSG (UnsupportedSectorSizeHiddenVolumeProtection, LangString["LINUX_EX2MSG_UNSUPPORTEDSECTORSIZEHIDDENVOLUMEPROTECTION"]);
		EX2MSG (UnsupportedSectorSizeNoKernelCrypto, LangString["LINUX_EX2MSG_UNSUPPORTEDSECTORSIZENOKERNELCRYPTO"]);
#else
		EX2MSG (UnsupportedSectorSize,				LangString["LINUX_EX2MSG_UNSUPPORTEDSECTORSIZE"]);
#endif

		EX2MSG (VolumeAlreadyMounted,				LangString["VOL_ALREADY_MOUNTED"]);
		EX2MSG (VolumeEncryptionNotCompleted,		LangString["ERR_ENCRYPTION_NOT_COMPLETED"]);
		EX2MSG (VolumeHostInUse,					LangString["LINUX_EX2MSG_VOLUMEHOSTINUSE"]);
		EX2MSG (VolumeSlotUnavailable,				LangString["LINUX_EX2MSG_VOLUMESLOTUNAVAILABLE"]);

#ifdef TC_MACOSX
		EX2MSG (HigherFuseVersionRequired,			LangString["LINUX_EX2MSG_HIGHERFUSEVERSIONREQUIRED"]);
#endif

#undef EX2MSG
		return L"";
	}

	void UserInterface::Init ()
	{
		SetAppName (Application::GetName());
		SetClassName (Application::GetName());

#ifdef CRYPTOPP_CPUID_AVAILABLE
		DetectX86Features ();
#endif
		LangString.Init();
		Core->Init();

		CmdLine.reset (new CommandLineInterface (argc, argv, InterfaceType));
		SetPreferences (CmdLine->Preferences);

		Core->SetApplicationExecutablePath (Application::GetExecutablePath());

		if (!Preferences.NonInteractive)
		{
			Core->SetAdminPasswordCallback (GetAdminPasswordRequestHandler());
		}
		else
		{
			Core->SetAdminPasswordCallback (shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler));
		}

#if defined(TC_LINUX ) || defined (TC_FREEBSD)
		Core->ForceUseDummySudoPassword (CmdLine->ArgUseDummySudoPassword);
#endif

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
			if (device->Partitions.empty())
				devices.push_back (device);
			else
			{
				foreach (shared_ptr <HostDevice> partition, device->Partitions)
					devices.push_back (partition);
			}
		}

		set <wstring> mountedVolumes;
		foreach_ref (const VolumeInfo &v, Core->GetMountedVolumes())
			mountedVolumes.insert (v.Path);

		bool protectedVolumeMounted = false;
		bool legacyVolumeMounted = false;
		bool vulnerableVolumeMounted = false;

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

				if (newMountedVolumes.back()->MasterKeyVulnerable)
					vulnerableVolumeMounted = true;
				
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
			if (vulnerableVolumeMounted)
				ShowWarning ("ERR_XTS_MASTERKEY_VULNERABLE");

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

			bool mountPerformed = false;
			if (Preferences.NonInteractive)
			{
				BusyScope busy (this);
				newMountedVolumes.push_back (Core->MountVolume (options));
				mountPerformed = true;
			}
			else
			{
				try
				{
					BusyScope busy (this);
					newMountedVolumes.push_back (Core->MountVolume (options));
					mountPerformed = true;
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
			
			if (mountPerformed && newMountedVolumes.back()->MasterKeyVulnerable)
				ShowWarning ("ERR_XTS_MASTERKEY_VULNERABLE");
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
			volume = MountVolumeThread (options);

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

		if (volume->MasterKeyVulnerable)
			ShowWarning ("ERR_XTS_MASTERKEY_VULNERABLE");

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
			ShowError (LangString["LINUX_UNKNOWN_EXC_OCCURRED"]);
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
		bool xdgOpenPresent = wxFileName::IsFileExecutable (wxT("/usr/bin/xdg-open")) || wxFileName::IsFileExecutable (wxT("/usr/local/bin/xdg-open"));
		bool nautilusPresent = wxFileName::IsFileExecutable (wxT("/usr/bin/nautilus")) || wxFileName::IsFileExecutable (wxT("/usr/local/bin/nautilus"));

		if (desktop == L"GNOME" || (desktop.empty() && !xdgOpenPresent && nautilusPresent))
		{
			// args.push_back ("--no-default-window"); // This option causes nautilus not to launch under FreeBSD 11
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
		else if (xdgOpenPresent)
		{
			// Fallback on the standard xdg-open command
			// which is not always available by default
			args.push_back (string (path));
			try
			{
				Process::Execute ("xdg-open", args, 2000);
			}
			catch (TimeOut&) { }
			catch (exception &e) { ShowError (e); }
		}
		else
		{
			ShowWarning (wxT("Unable to find a file manager to open the mounted volume"));
		}
#endif
	}

	bool UserInterface::ProcessCommandLine ()
	{
		CommandLineInterface &cmdLine = *CmdLine;

		if (cmdLine.ArgCommand == CommandId::None)
			return false;

		if (Preferences.UseStandardInput)
		{
			wstring pwdInput;
			getline(wcin, pwdInput);

			size_t maxUtf8Len = cmdLine.ArgUseLegacyPassword? VolumePassword::MaxLegacySize : VolumePassword::MaxSize;
			cmdLine.ArgPassword = ToUTF8Password ( pwdInput.c_str (), pwdInput.size (), maxUtf8Len);
		}

		switch (cmdLine.ArgCommand)
		{
		case CommandId::AutoMountDevices:
		case CommandId::AutoMountFavorites:
		case CommandId::AutoMountDevicesFavorites:
		case CommandId::MountVolume:
			{
				cmdLine.ArgMountOptions.Path = cmdLine.ArgVolumePath;
				cmdLine.ArgMountOptions.MountPoint = cmdLine.ArgMountPoint;
				cmdLine.ArgMountOptions.Password = cmdLine.ArgPassword;
				cmdLine.ArgMountOptions.Pim = cmdLine.ArgPim;
				cmdLine.ArgMountOptions.Keyfiles = cmdLine.ArgKeyfiles;
				cmdLine.ArgMountOptions.SharedAccessAllowed = cmdLine.ArgForce;
				if (cmdLine.ArgHash)
				{
					cmdLine.ArgMountOptions.Kdf = Pkcs5Kdf::GetAlgorithm (*cmdLine.ArgHash);
				}


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
						message += StringFormatter (LangString["LINUX_VOL_MOUNTED"], wstring (volume.Path));
					}
					ShowInfo (message);
				}
			}
			return true;

		case CommandId::BackupHeaders:
			BackupVolumeHeaders (cmdLine.ArgVolumePath);
			return true;

		case CommandId::ChangePassword:
			ChangePassword (cmdLine.ArgVolumePath, cmdLine.ArgPassword, cmdLine.ArgPim, cmdLine.ArgHash, cmdLine.ArgKeyfiles, cmdLine.ArgNewPassword, cmdLine.ArgNewPim, cmdLine.ArgNewKeyfiles, cmdLine.ArgNewHash);
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
				options->Pim = cmdLine.ArgPim;
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
					" Export a keyfile from a token. See also command --list-token-keyfiles.\n"
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
					" Display a list of all available token keyfiles. See also command\n"
					" --import-token-keyfiles.\n"
					"\n""--list-securitytoken-keyfiles\n"
                    " Display a list of all available security token keyfiles. See also command\n"
                    " --import-token-keyfiles.\n"
                    "\n"
                    "\n""--list-emvtoken-keyfiles\n"
                    " Display a list of all available emv token keyfiles. See also command\n"
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
					" Use specified encryption algorithm when creating a new volume. When cascading\n"
					" algorithms, they must be separated by a dash. For example: AES-Twofish.\n"
					"\n"
					"--filesystem=TYPE\n"
					" Filesystem type to mount. The TYPE argument is passed to mount(8) command\n"
					" with option -t. Default type is 'auto'. When creating a new volume, this\n"
					" option specifies the filesystem to be created on the new volume.\n"
					" Filesystem type 'none' disables mounting or creating a filesystem.\n"
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
					" token://slot/SLOT_NUMBER/file/FILENAME for a security token keyfile\n"
                    " and emv://slot/SLOT_NUMBER for an EMV token keyfile.\n"
                    " An empty keyfile (-k \"\") disables\n"
					" interactive requests for keyfiles. See also options --import-token-keyfiles,\n"
					" --list-token-keyfiles, --list-securitytoken-keyfiles, --list-emvtoken-keyfiles,\n"
                    " --new-keyfiles, --protection-keyfiles.\n"
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
					"--new-pim=PIM\n"
					" Specifies a new PIM. This option can only be used with command -C.\n"
					"\n"
					"-p, --password=PASSWORD\n"
					" Use specified password to mount/open a volume. An empty password can also be\n"
					" specified (-p \"\"). Note that passing a password on the command line is\n"
					" potentially insecure as the password may be visible in the process list\n"
					" (see ps(1)) and/or stored in a command history file or system logs.\n"
					"\n"
					"--pim=PIM\n"
					" Use specified PIM to mount/open a volume. Note that passing a PIM on the \n"
					" command line is potentially insecure as the PIM may be visible in the process \n"
					" list (see ps(1)) and/or stored in a command history file or system logs.\n"
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
					"--size=SIZE[K|KiB|M|MiB|G|GiB|T|TiB] or --size=max\n"
					" Use specified size when creating a new volume. If no suffix is indicated,\n"
					" then SIZE is interpreted in bytes. Suffixes K, M, G or T can be used to\n"
					" indicate a value in KiB, MiB, GiB or TiB respectively.\n"
					" If max is specified, the new volume will use all available free disk space.\n"
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
					"veracrypt -m ro -k keyfile1,keyfile2 volume.hc\n"
					"\n"
					"Mount a volume without mounting its filesystem:\n"
					"veracrypt --filesystem=none volume.hc\n"
					"\n"
					"Mount a volume prompting only for its password:\n"
					"veracrypt -t -k \"\" --pim=0 --protect-hidden=no volume.hc /media/veracrypt1\n"
					"\n"
					"Dismount a volume:\n"
					"veracrypt -d volume.hc\n"
					"\n"
					"Dismount all mounted volumes:\n"
					"veracrypt -d\n"
				);

#ifndef TC_NO_GUI
				if (Application::GetUserInterfaceType() == UserInterfaceType::Graphic)
				{
					wxDialog dialog (nullptr, wxID_ANY, LangString["LINUX_CMD_HELP"], wxDefaultPosition);

					wxTextCtrl *textCtrl = new wxTextCtrl (&dialog, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
					textCtrl->SetFont (wxFont (wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, L"Courier"));
					textCtrl->SetValue (helpText);

					int fontWidth, fontHeight;
					textCtrl->GetTextExtent (L"A", &fontWidth, &fontHeight);
					dialog.SetSize (wxSize (fontWidth * 85, fontHeight * 29));

					wxBoxSizer *sizer = new wxBoxSizer (wxVERTICAL);
					sizer->Add (textCtrl, 1, wxALL | wxEXPAND, 5);
					sizer->Add (new wxButton (&dialog, wxID_OK, LangString["IDOK"]), 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 5);

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

		case CommandId::ExportTokenKeyfile:
			ExportTokenKeyfile();
			return true;

		case CommandId::ImportTokenKeyfiles:
			ImportTokenKeyfiles();
			return true;

		case CommandId::ListTokenKeyfiles:
			ListTokenKeyfiles();
			return true;

        case CommandId::ListSecurityTokenKeyfiles:
             ListSecurityTokenKeyfiles();
             return true;

        case CommandId::ListEMVTokenKeyfiles:
            ListEMVTokenKeyfiles();
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
		if (static_cast<wstring>(StringFormatter (L"{9} {8} {7} {6} {5} {4} {3} {2} {1} {0} {{0}}", "1", L"2", '3', L'4', 5, 6, 7, 8, 9, 10)) != L"10 9 8 7 6 5 4 3 2 1 {0}")
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
		wxString sResult;
		switch (type)
		{
		case VolumeType::Normal:
			sResult = LangString[protection == VolumeProtection::HiddenVolumeReadOnly ? "OUTER" : "NORMAL"];
			break;

		case VolumeType::Hidden:
			sResult = LangString["HIDDEN"];
			break;

		default:
			sResult = L"?";
			break;
		}

		return sResult;
	}

	#define VC_CONVERT_EXCEPTION(NAME) if (dynamic_cast<NAME*> (ex)) throw (NAME&) *ex;

	void UserInterface::ThrowException (Exception* ex)
	{
		VC_CONVERT_EXCEPTION (PasswordIncorrect);
		VC_CONVERT_EXCEPTION (PasswordKeyfilesIncorrect);
		VC_CONVERT_EXCEPTION (PasswordOrKeyboardLayoutIncorrect);
		VC_CONVERT_EXCEPTION (PasswordOrMountOptionsIncorrect);
		VC_CONVERT_EXCEPTION (ProtectionPasswordIncorrect);
		VC_CONVERT_EXCEPTION (ProtectionPasswordKeyfilesIncorrect);
		VC_CONVERT_EXCEPTION (PasswordEmpty);
		VC_CONVERT_EXCEPTION (PasswordTooLong);
		VC_CONVERT_EXCEPTION (PasswordUTF8TooLong);
		VC_CONVERT_EXCEPTION (PasswordLegacyUTF8TooLong);
		VC_CONVERT_EXCEPTION (PasswordUTF8Invalid);
		VC_CONVERT_EXCEPTION (UnportablePassword);
		VC_CONVERT_EXCEPTION (ElevationFailed);
		VC_CONVERT_EXCEPTION (RootDeviceUnavailable);
		VC_CONVERT_EXCEPTION (DriveLetterUnavailable);
		VC_CONVERT_EXCEPTION (DriverError);
		VC_CONVERT_EXCEPTION (DeviceSectorSizeMismatch);
		VC_CONVERT_EXCEPTION (EncryptedSystemRequired);
		VC_CONVERT_EXCEPTION (HigherFuseVersionRequired);
		VC_CONVERT_EXCEPTION (KernelCryptoServiceTestFailed);
		VC_CONVERT_EXCEPTION (LoopDeviceSetupFailed);
		VC_CONVERT_EXCEPTION (MountPointRequired);
		VC_CONVERT_EXCEPTION (MountPointUnavailable);
		VC_CONVERT_EXCEPTION (NoDriveLetterAvailable);
		VC_CONVERT_EXCEPTION (TemporaryDirectoryFailure);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSizeHiddenVolumeProtection);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSizeNoKernelCrypto);
		VC_CONVERT_EXCEPTION (VolumeAlreadyMounted);
		VC_CONVERT_EXCEPTION (VolumeSlotUnavailable);
		VC_CONVERT_EXCEPTION (UserInterfaceException);
		VC_CONVERT_EXCEPTION (MissingArgument);
		VC_CONVERT_EXCEPTION (NoItemSelected);
		VC_CONVERT_EXCEPTION (StringFormatterException);
		VC_CONVERT_EXCEPTION (ExecutedProcessFailed);
		VC_CONVERT_EXCEPTION (AlreadyInitialized);
		VC_CONVERT_EXCEPTION (AssertionFailed);
		VC_CONVERT_EXCEPTION (ExternalException);
		VC_CONVERT_EXCEPTION (InsufficientData);
		VC_CONVERT_EXCEPTION (NotApplicable);
		VC_CONVERT_EXCEPTION (NotImplemented);
		VC_CONVERT_EXCEPTION (NotInitialized);
		VC_CONVERT_EXCEPTION (ParameterIncorrect);
		VC_CONVERT_EXCEPTION (ParameterTooLarge);
		VC_CONVERT_EXCEPTION (PartitionDeviceRequired);
		VC_CONVERT_EXCEPTION (StringConversionFailed);
		VC_CONVERT_EXCEPTION (TerminalNotFound);
		VC_CONVERT_EXCEPTION (TestFailed);
		VC_CONVERT_EXCEPTION (TimeOut);
		VC_CONVERT_EXCEPTION (UnknownException);
		VC_CONVERT_EXCEPTION (UserAbort)
		VC_CONVERT_EXCEPTION (CipherInitError);
		VC_CONVERT_EXCEPTION (WeakKeyDetected);
		VC_CONVERT_EXCEPTION (HigherVersionRequired);
		VC_CONVERT_EXCEPTION (KeyfilePathEmpty);
		VC_CONVERT_EXCEPTION (MissingVolumeData);
		VC_CONVERT_EXCEPTION (MountedVolumeInUse);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSize);
		VC_CONVERT_EXCEPTION (VolumeEncryptionNotCompleted);
		VC_CONVERT_EXCEPTION (VolumeHostInUse);
		VC_CONVERT_EXCEPTION (VolumeProtected);
		VC_CONVERT_EXCEPTION (VolumeReadOnly);
		VC_CONVERT_EXCEPTION (Pkcs11Exception);
		VC_CONVERT_EXCEPTION (InvalidSecurityTokenKeyfilePath);
		VC_CONVERT_EXCEPTION (SecurityTokenLibraryNotInitialized);
		VC_CONVERT_EXCEPTION (SecurityTokenKeyfileAlreadyExists);
		VC_CONVERT_EXCEPTION (SecurityTokenKeyfileNotFound);
		VC_CONVERT_EXCEPTION (SystemException);
		VC_CONVERT_EXCEPTION (CipherException);
		VC_CONVERT_EXCEPTION (VolumeException);
		VC_CONVERT_EXCEPTION (PasswordException);

		VC_CONVERT_EXCEPTION (PCSCException);
		VC_CONVERT_EXCEPTION (CommandAPDUNotValid);
		VC_CONVERT_EXCEPTION (ExtendedAPDUNotSupported);
		VC_CONVERT_EXCEPTION (ScardLibraryInitializationFailed);
		VC_CONVERT_EXCEPTION (EMVUnknownCardType);
		VC_CONVERT_EXCEPTION (EMVSelectAIDFailed);
		VC_CONVERT_EXCEPTION (EMVIccCertNotFound);
		VC_CONVERT_EXCEPTION (EMVIssuerCertNotFound);
		VC_CONVERT_EXCEPTION (EMVCPLCNotFound);
		VC_CONVERT_EXCEPTION (InvalidEMVPath);
		VC_CONVERT_EXCEPTION (EMVKeyfileDataNotFound);
		VC_CONVERT_EXCEPTION (EMVPANNotFound);

		throw *ex;
	}
}
