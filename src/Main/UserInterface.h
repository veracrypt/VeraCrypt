/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_UserInterface
#define TC_HEADER_Main_UserInterface

#include "System.h"
#include "Core/Core.h"
#include "Main.h"
#include "CommandLineInterface.h"
#include "FavoriteVolume.h"
#include "LanguageStrings.h"
#include "UserPreferences.h"
#include "UserInterfaceException.h"
#include "UserInterfaceType.h"

namespace VeraCrypt
{
	class UserInterface : public wxApp
	{
	public:
		virtual ~UserInterface ();

		virtual bool AskYesNo (const wxString &message, bool defaultYes = false, bool warning = false) const = 0;
		virtual void BackupVolumeHeaders (shared_ptr <VolumePath> volumePath) const = 0;
		virtual void BeginBusyState () const = 0;
		virtual void ChangePassword (shared_ptr <VolumePath> volumePath = shared_ptr <VolumePath>(), shared_ptr <VolumePassword> password = shared_ptr <VolumePassword>(), int pim = 0, shared_ptr <Hash> currentHash = shared_ptr <Hash>(), bool truecryptMode = false, shared_ptr <KeyfileList> keyfiles = shared_ptr <KeyfileList>(), shared_ptr <VolumePassword> newPassword = shared_ptr <VolumePassword>(), int newPim = 0, shared_ptr <KeyfileList> newKeyfiles = shared_ptr <KeyfileList>(), shared_ptr <Hash> newHash = shared_ptr <Hash>()) const = 0;
		virtual void CheckRequirementsForMountingVolume () const;
		virtual void CloseExplorerWindows (shared_ptr <VolumeInfo> mountedVolume) const;
		virtual void CreateKeyfile (shared_ptr <FilePath> keyfilePath = shared_ptr <FilePath>()) const = 0;
		virtual void CreateVolume (shared_ptr <VolumeCreationOptions> options) const = 0;
		virtual void DeleteSecurityTokenKeyfiles () const = 0;
		virtual void DismountAllVolumes (bool ignoreOpenFiles = false, bool interactive = true) const;
		virtual void DismountVolume (shared_ptr <VolumeInfo> volume, bool ignoreOpenFiles = false, bool interactive = true) const;
		virtual void DismountVolumes (VolumeInfoList volumes, bool ignoreOpenFiles = false, bool interactive = true) const;
		virtual void DisplayVolumeProperties (const VolumeInfoList &volumes) const;
		virtual void DoShowError (const wxString &message) const = 0;
		virtual void DoShowInfo (const wxString &message) const = 0;
		virtual void DoShowString (const wxString &str) const = 0;
		virtual void DoShowWarning (const wxString &message) const = 0;
		virtual void EndBusyState () const = 0;
		static wxString ExceptionToMessage (const exception &ex);
		virtual void ExportSecurityTokenKeyfile () const = 0;
		virtual shared_ptr <GetStringFunctor> GetAdminPasswordRequestHandler () = 0;
		virtual const UserPreferences &GetPreferences () const { return Preferences; }
		virtual void ImportSecurityTokenKeyfiles () const = 0;
		virtual void Init ();
		virtual void InitSecurityTokenLibrary () const = 0;
		virtual void ListMountedVolumes (const VolumeInfoList &volumes) const;
		virtual void ListSecurityTokenKeyfiles () const = 0;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options) const;
		virtual shared_ptr <VolumeInfo> MountVolumeThread (MountOptions &options) const { return Core->MountVolume (options);}
		virtual VolumeInfoList MountAllDeviceHostedVolumes (MountOptions &options) const;
		virtual VolumeInfoList MountAllFavoriteVolumes (MountOptions &options);
		virtual void OpenExplorerWindow (const DirectoryPath &path);
		virtual void RestoreVolumeHeaders (shared_ptr <VolumePath> volumePath) const = 0;
		virtual void SetPreferences (const UserPreferences &preferences);
		virtual void ShowError (const exception &ex) const;
		virtual void ShowError (const char *langStringId) const { DoShowError (LangString[langStringId]); }
		virtual void ShowError (const wxString &message) const { DoShowError (message); }
		virtual void ShowInfo (const exception &ex) const { DoShowInfo (ExceptionToMessage (ex)); }
		virtual void ShowInfo (const char *langStringId) const { DoShowInfo (LangString[langStringId]); }
		virtual void ShowInfo (const wxString &message) const { DoShowInfo (message); }
		virtual void ShowWarning (const exception &ex) const { DoShowWarning (ExceptionToMessage (ex)); }
		virtual void ShowWarning (const char *langStringId) const { DoShowWarning (LangString[langStringId]); }
		virtual void ShowString (const wxString &str) const { DoShowString (str); }
		virtual void ShowWarning (const wxString &message) const { DoShowWarning (message); }
		virtual wxString SizeToString (uint64 size) const;
		virtual wxString SpeedToString (uint64 speed) const;
		virtual void Test () const;
		virtual wxString TimeSpanToString (uint64 seconds) const;
		virtual bool VolumeHasUnrecommendedExtension (const VolumePath &path) const;
		virtual void Yield () const = 0;
		virtual WaitThreadUI* GetWaitThreadUI(WaitThreadRoutine *pRoutine) const { return new WaitThreadUI(pRoutine);}
		virtual wxDateTime VolumeTimeToDateTime (VolumeTime volumeTime) const { return wxDateTime ((time_t) (volumeTime / 1000ULL / 1000 / 10 - 134774ULL * 24 * 3600)); }
		virtual wxString VolumeTimeToString (VolumeTime volumeTime) const;
		virtual wxString VolumeTypeToString (VolumeType::Enum type, bool truecryptMode, VolumeProtection::Enum protection) const;

		Event PreferencesUpdatedEvent;

		struct BusyScope
		{
			BusyScope (const UserInterface *userInterface) : UI (userInterface) { UI->BeginBusyState (); }
			~BusyScope () { UI->EndBusyState (); }
			const UserInterface *UI;
		};

		static void ThrowException (Exception* ex);

	protected:
		UserInterface ();
		virtual bool OnExceptionInMainLoop () { throw; }
		virtual void OnUnhandledException ();
		virtual void OnVolumeMounted (EventArgs &args);
		virtual void OnWarning (EventArgs &args);
		virtual bool ProcessCommandLine ();

		static wxString ExceptionToString (const Exception &ex);
		static wxString ExceptionTypeToString (const std::type_info &ex);

		UserPreferences Preferences;
		UserInterfaceType::Enum InterfaceType;

	private:
		UserInterface (const UserInterface &);
		UserInterface &operator= (const UserInterface &);
	};
}

#endif // TC_HEADER_Main_UserInterface
