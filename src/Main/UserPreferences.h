/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_UserPreferences
#define TC_HEADER_Main_UserPreferences

#include "System.h"
#include "Main.h"
#include "Hotkey.h"

namespace VeraCrypt
{
	struct UserPreferences
	{
		UserPreferences ()
			:
			BackgroundTaskEnabled (true),
			BackgroundTaskMenuDismountItemsEnabled (true),
			BackgroundTaskMenuMountItemsEnabled (true),
			BackgroundTaskMenuOpenItemsEnabled (true),
			BeepAfterHotkeyMountDismount (false),
			CloseBackgroundTaskOnNoVolumes (true),
			CloseExplorerWindowsOnDismount (true),
			CloseSecurityTokenSessionsAfterMount (false),
			DisableKernelEncryptionModeWarning (false),
			DismountOnInactivity (false),
			DismountOnLogOff (true),
			DismountOnPowerSaving (false),
			DismountOnScreenSaver (false),
			DisplayMessageAfterHotkeyDismount (false),
			ForceAutoDismount (true),
			LastSelectedSlotNumber (0),
			MaxVolumeIdleTime (60),
			MountDevicesOnLogon (false),
			MountFavoritesOnLogon (false),
			NonInteractive (false),
			OpenExplorerWindowAfterMount (false),
			SaveHistory (false),
			StartOnLogon (false),
			UseKeyfiles (false),
			Verbose (false),
			WipeCacheOnAutoDismount (true),
			WipeCacheOnClose (false)
		{
		}

		virtual ~UserPreferences ()
		{
		}
		void Load();
		void Save() const;

		HotkeyList Hotkeys;
		KeyfileList DefaultKeyfiles;
		MountOptions DefaultMountOptions;

		bool BackgroundTaskEnabled;
		bool BackgroundTaskMenuDismountItemsEnabled;
		bool BackgroundTaskMenuMountItemsEnabled;
		bool BackgroundTaskMenuOpenItemsEnabled;
		bool BeepAfterHotkeyMountDismount;
		bool CloseBackgroundTaskOnNoVolumes;
		bool CloseExplorerWindowsOnDismount;
		bool CloseSecurityTokenSessionsAfterMount;
		bool DisableKernelEncryptionModeWarning;
		bool DismountOnInactivity;
		bool DismountOnLogOff;
		bool DismountOnPowerSaving;
		bool DismountOnScreenSaver;
		bool DisplayMessageAfterHotkeyDismount;
		bool ForceAutoDismount;
		uint64 LastSelectedSlotNumber;
		int32 MaxVolumeIdleTime;
		bool MountDevicesOnLogon;
		bool MountFavoritesOnLogon;
		bool NonInteractive;
		bool OpenExplorerWindowAfterMount;
		bool SaveHistory;
		FilePath SecurityTokenModule;
		bool StartOnLogon;
		bool UseKeyfiles;
		bool Verbose;
		bool WipeCacheOnAutoDismount;
		bool WipeCacheOnClose;

	protected:
		wxString GetDefaultKeyfilesFileName () const { return L"Default Keyfiles.xml"; }
#ifdef TC_PROTOTYPE
		wxString GetPreferencesFileName () const { return L"Configuration_Debug.xml"; }
#else
		wxString GetPreferencesFileName () const { return L"Configuration.xml"; }
#endif
		void SetValue (const wxString &cfgText, bool &cfgVar);
		void SetValue (const wxString &cfgText, int &cfgVar);
		void SetValue (const wxString &cfgText, uint64 &cfgVar);
		void SetValue (const wxString &cfgText, wstring &cfgVar);
		void SetValue (const wxString &cfgText, wxString &cfgVar);
		void SetValue (const wxString &cfgText, FilesystemPath &cfgVar);
	};
}

#endif // TC_HEADER_Main_UserPreferences
