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
#include <wx/dynlib.h>
#ifdef TC_WINDOWS
#include <wx/msw/registry.h>
#else
#include <wx/dir.h>
#include <wx/arrstr.h>
#endif
#include "Common/SecurityToken.h"
#include "Main/Main.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
#include "Volume/Cipher.h"
#include "PreferencesDialog.h"

namespace VeraCrypt
{
	PreferencesDialog::PreferencesDialog (wxWindow* parent)
		: PreferencesDialogBase (parent),
		LastVirtualKeyPressed (0),
		Preferences (Gui->GetPreferences()),
		RestoreValidatorBell (false)
	{
#define TC_CHECK_BOX_VALIDATOR(NAME) (TC_JOIN(NAME,CheckBox))->SetValidator (wxGenericValidator (&Preferences.NAME));

#ifdef TC_MACOSX
		PreferencesNotebook->SetMinSize (wxSize (Gui->GetCharWidth (PreferencesNotebook) * 108, -1));
#endif
		// Security
		TC_CHECK_BOX_VALIDATOR (DismountOnLogOff);
		TC_CHECK_BOX_VALIDATOR (DismountOnPowerSaving);
		TC_CHECK_BOX_VALIDATOR (DismountOnScreenSaver);
		TC_CHECK_BOX_VALIDATOR (DismountOnInactivity);
		DismountOnInactivitySpinCtrl->SetValidator (wxGenericValidator (&Preferences.MaxVolumeIdleTime));
		TC_CHECK_BOX_VALIDATOR (ForceAutoDismount);
		PreserveTimestampsCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.PreserveTimestamps));
		TC_CHECK_BOX_VALIDATOR (WipeCacheOnAutoDismount);
		TC_CHECK_BOX_VALIDATOR (WipeCacheOnClose);

		// Mount options
		CachePasswordsCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.CachePassword));
		MountReadOnlyCheckBox->SetValue (Preferences.DefaultMountOptions.Protection == VolumeProtection::ReadOnly);
		MountRemovableCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.Removable));

		FilesystemOptionsTextCtrl->SetValue (Preferences.DefaultMountOptions.FilesystemOptions);

		int index, prfInitialIndex = 0;
		Pkcs5PrfChoice->Append (LangString["AUTODETECTION"]);

		foreach_ref (const Pkcs5Kdf &kdf, Pkcs5Kdf::GetAvailableAlgorithms())
		{
			index = Pkcs5PrfChoice->Append (kdf.GetName());
			if (Preferences.DefaultMountOptions.Kdf
				&& (Preferences.DefaultMountOptions.Kdf->GetName() == kdf.GetName())
				)
			{
				prfInitialIndex = index;
			}
		}
		Pkcs5PrfChoice->Select (prfInitialIndex);

		// Language for non-Windows
#ifndef TC_WINDOWS
#if defined (TC_MACOSX)
		wxDir languagesFolder(StringConverter::ToSingle (Application::GetExecutableDirectory()) + "/../Resources/languages/");
#else
		wxDir languagesFolder("/usr/share/veracrypt/languages/");
#endif
		wxArrayString langArray;
		LanguageListBox->Append("System default");
		LanguageListBox->Append("English");

		langEntries = {
				{"system", L"System default"},
				{"ar", L"العربية"},
				{"be", L"Беларуская"},
				{"bg", L"Български"},
				{"ca", L"Català"},
				{"co", L"Corsu"},
				{"cs", L"Čeština"},
				{"da", L"Dansk"},
				{"de", L"Deutsch"},
				{"el", L"Ελληνικά"},
				{"en", L"English"},
				{"es", L"Español"},
				{"et", L"Eesti"},
				{"eu", L"Euskara"},
				{"fa", L"فارسي"},
				{"fi", L"Suomi"},
				{"fr", L"Français"},
				{"he", L"עברית"},
				{"hu", L"Magyar"},
				{"id", L"Bahasa Indonesia"},
				{"it", L"Italiano"},
				{"ja", L"日本語"},
				{"ka", L"ქართული"},
				{"ko", L"한국어"},
				{"lv", L"Latviešu"},
				{"nb", L"Norsk Bokmål"},
				{"nl", L"Nederlands"},
				{"nn", L"Norsk Nynorsk"},
				{"pl", L"Polski"},
				{"ro", L"Română"},
				{"ru", L"Русский"},
				{"pt-br", L"Português-Brasil"},
				{"sk", L"Slovenčina"},
				{"sl", L"Slovenščina"},
				{"sv", L"Svenska"},
				{"th", L"ภาษาไทย"},
				{"tr", L"Türkçe"},
				{"uk", L"Українська"},
				{"uz", L"Ўзбекча"},
				{"vi", L"Tiếng Việt"},
				{"zh-cn", L"简体中文"},
				{"zh-hk", L"繁體中文(香港)"},
				{"zh-tw", L"繁體中文"}
		};

		if (wxDir::Exists(languagesFolder.GetName())) {
			size_t langCount;
			langCount = wxDir::GetAllFiles(languagesFolder.GetName(), &langArray, wxEmptyString, wxDIR_FILES);
			for (size_t i = 0; i < langCount; ++i) {
				wxFileName filename(langArray[i]);
				wxString langId = filename.GetName().AfterLast('.');
				wxString langNative = langEntries[langId];
				if (!langNative.empty()) {
					LanguageListBox->Append(langNative);
				}
			}
		}
#endif


		// Keyfiles
		TC_CHECK_BOX_VALIDATOR (UseKeyfiles);

		DefaultKeyfilesPanel = new KeyfilesPanel (DefaultKeyfilesPage, make_shared <KeyfileList> (Preferences.DefaultKeyfiles));
		DefaultKeyfilesSizer->Add (DefaultKeyfilesPanel, 1, wxALL | wxEXPAND);
		DefaultKeyfilesSizer->Layout();

		TC_CHECK_BOX_VALIDATOR (BackgroundTaskEnabled);
		TC_CHECK_BOX_VALIDATOR (CloseBackgroundTaskOnNoVolumes);
		CloseBackgroundTaskOnNoVolumesCheckBox->Show (!Core->IsInPortableMode());
		TC_CHECK_BOX_VALIDATOR (BackgroundTaskMenuDismountItemsEnabled);
		TC_CHECK_BOX_VALIDATOR (BackgroundTaskMenuMountItemsEnabled);
		TC_CHECK_BOX_VALIDATOR (BackgroundTaskMenuOpenItemsEnabled);

		// Encryption
		AesHwCpuSupportedStaticText->SetLabel (
#ifdef TC_AES_HW_CPU
			(HasAESNI() ? LangString["UISTR_YES"] : LangString["UISTR_NO"]));
#else
			LangString["NOT_APPLICABLE_OR_NOT_AVAILABLE"]);
#endif
		NoHardwareCryptoCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.NoHardwareCrypto));

		// Security tokens
		Pkcs11ModulePathTextCtrl->SetValue (wstring (Preferences.SecurityTokenModule));
		TC_CHECK_BOX_VALIDATOR (CloseSecurityTokenSessionsAfterMount);
		TC_CHECK_BOX_VALIDATOR (EMVSupportEnabled);

		// System integration
		TC_CHECK_BOX_VALIDATOR (StartOnLogon);
		TC_CHECK_BOX_VALIDATOR (MountDevicesOnLogon);
		TC_CHECK_BOX_VALIDATOR (MountFavoritesOnLogon);

		TC_CHECK_BOX_VALIDATOR (CloseExplorerWindowsOnDismount);
		TC_CHECK_BOX_VALIDATOR (OpenExplorerWindowAfterMount);

		NoKernelCryptoCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.NoKernelCrypto));

#ifdef TC_WINDOWS
		// Hotkeys
		TC_CHECK_BOX_VALIDATOR (BeepAfterHotkeyMountDismount);
		TC_CHECK_BOX_VALIDATOR (DisplayMessageAfterHotkeyDismount);
#endif

		TransferDataToWindow();		// Code below relies on TransferDataToWindow() called at this point

#if defined (TC_WINDOWS) || defined (TC_MACOSX)
		FilesystemSizer->Show (false);
#else
		// Auto-dismount is not supported on Linux as dismount may require the user to enter admin password
		AutoDismountSizer->Show (false);
		WipeCacheOnAutoDismountCheckBox->Show (false);
#endif

#ifndef TC_WINDOWS
		LogOnSizer->Show (false);
		MountRemovableCheckBox->Show (false);
		CloseExplorerWindowsOnDismountCheckBox->Show (false);
#endif

#ifndef wxHAS_POWER_EVENTS
		DismountOnPowerSavingCheckBox->Show (false);
#endif

#ifdef TC_MACOSX
		DismountOnScreenSaverCheckBox->Show (false);
		DismountOnLogOffCheckBox->SetLabel (LangString["LINUX_VC_QUITS"]);
		OpenExplorerWindowAfterMountCheckBox->SetLabel (LangString["LINUX_OPEN_FINDER"]);

		MountRemovableCheckBox->Show (false);
		FilesystemSizer->Show (false);
		LogOnSizer->Show (false);
		CloseExplorerWindowsOnDismountCheckBox->Show (false);
#endif

#ifndef TC_LINUX
		KernelServicesSizer->Show (false);
#endif

#ifdef TC_WINDOWS
		// Hotkeys
		list <int> colPermilles;
		HotkeyListCtrl->InsertColumn (ColumnHotkeyDescription, LangString["ACTION"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (642);
		HotkeyListCtrl->InsertColumn (ColumnHotkey, LangString["SHORTCUT"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (358);

		vector <wstring> fields (HotkeyListCtrl->GetColumnCount());

		UnregisteredHotkeys = Preferences.Hotkeys;
		Hotkey::UnregisterList (Gui->GetMainFrame(), UnregisteredHotkeys);

		foreach (shared_ptr <Hotkey> hotkey, Preferences.Hotkeys)
		{
			fields[ColumnHotkeyDescription] = hotkey->Description;
			fields[ColumnHotkey] = hotkey->GetShortcutString();
			Gui->AppendToListCtrl (HotkeyListCtrl, fields, -1, hotkey.get());
		}

		Gui->SetListCtrlHeight (HotkeyListCtrl, 5);

		Layout();
		Fit();
		Gui->SetListCtrlColumnWidths (HotkeyListCtrl, colPermilles);

		RestoreValidatorBell = !wxTextValidator::IsSilent();
		wxTextValidator::SuppressBellOnError (true);
		HotkeyTextCtrl->SetValidator (wxTextValidator (wxFILTER_INCLUDE_CHAR_LIST));

		UpdateHotkeyButtons();
#endif

		// Page setup
		for (size_t page = 0; page < PreferencesNotebook->GetPageCount(); page++)
		{
			wxNotebookPage *np = PreferencesNotebook->GetPage (page);
			if (np == HotkeysPage)
			{
#ifndef TC_WINDOWS
				PreferencesNotebook->RemovePage (page--);
				continue;
#endif
			}

			np->Layout();
		}

		Layout();
		Fit();
		Center();

		OKButton->SetDefault();

#ifdef TC_WINDOWS
		// Hotkey timer
		class Timer : public wxTimer
		{
		public:
			Timer (PreferencesDialog *dialog) : Dialog (dialog) { }

			void Notify()
			{
				Dialog->OnTimer();
			}

			PreferencesDialog *Dialog;
		};

		mTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		mTimer->Start (25);
#endif
	}

	PreferencesDialog::~PreferencesDialog ()
	{
#ifdef TC_WINDOWS
		if (RestoreValidatorBell)
			wxTextValidator::SuppressBellOnError (false);
#endif
	}

	void PreferencesDialog::SelectPage (wxPanel *page)
	{
		for (size_t pageIndex = 0; pageIndex < PreferencesNotebook->GetPageCount(); pageIndex++)
		{
			if (PreferencesNotebook->GetPage (pageIndex) == page)
				PreferencesNotebook->ChangeSelection (pageIndex);
		}
	}

	void PreferencesDialog::OnSysDefaultLangButtonClick (wxCommandEvent& event)
	{
		// SetStringSelection()'s Assert currently broken in sorted ListBoxes on macOS, workaround:
		int itemIndex = LanguageListBox->FindString("System default", true);
		if (itemIndex != wxNOT_FOUND) {
			LanguageListBox->SetSelection(itemIndex);
		}
	}

	void PreferencesDialog::OnAssignHotkeyButtonClick (wxCommandEvent& event)
	{
#ifdef TC_WINDOWS
		foreach (long item, Gui->GetListCtrlSelectedItems (HotkeyListCtrl))
		{
			Hotkey *hotkey = reinterpret_cast <Hotkey *> (HotkeyListCtrl->GetItemData (item));

			int mods = 0;
			mods |=	HotkeyShiftCheckBox->IsChecked() ? wxMOD_SHIFT : 0;
			mods |=	HotkeyControlCheckBox->IsChecked() ? wxMOD_CONTROL : 0;
			mods |=	HotkeyAltCheckBox->IsChecked() ? wxMOD_ALT : 0;
			mods |=	HotkeyWinCheckBox->IsChecked() ? wxMOD_WIN : 0;

			// F1 is help and F12 is reserved for use by the debugger at all times
			if (mods == 0 && (LastVirtualKeyPressed == VK_F1 || LastVirtualKeyPressed == VK_F12))
			{
				Gui->ShowError ("CANNOT_USE_RESERVED_KEY");
				return;
			}

			// Test if the hotkey can be registered
			if (!this->RegisterHotKey (hotkey->Id, mods, LastVirtualKeyPressed))
			{
				Gui->ShowError (SystemException (SRC_POS));
				return;
			}
			UnregisterHotKey (hotkey->Id);

			foreach_ref (const Hotkey &h, Preferences.Hotkeys)
			{
				if (h.Id != hotkey->Id && h.VirtualKeyCode == LastVirtualKeyPressed && h.VirtualKeyModifiers == mods)
				{
					Gui->ShowError ("SHORTCUT_ALREADY_IN_USE");
					return;
				}
			}

			hotkey->VirtualKeyCode = LastVirtualKeyPressed;
			hotkey->VirtualKeyModifiers = mods;

			vector <wstring> fields (HotkeyListCtrl->GetColumnCount());
			fields[ColumnHotkeyDescription] = hotkey->Description;
			fields[ColumnHotkey] = hotkey->GetShortcutString();
			Gui->UpdateListCtrlItem (HotkeyListCtrl, item, fields);

			UpdateHotkeyButtons();
		}
#endif // TC_WINDOWS
	}

	void PreferencesDialog::OnBackgroundTaskEnabledCheckBoxClick (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			BackgroundTaskEnabledCheckBox->SetValue (!Gui->AskYesNo (LangString["CONFIRM_BACKGROUND_TASK_DISABLED"], false, true));
	}

	void PreferencesDialog::OnNoHardwareCryptoCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked())
		{
			if (Gui->AskYesNo (LangString["CONFIRM_SETTING_DEGRADES_PERFORMANCE"], true, true))
			{
#ifdef TC_LINUX
				Gui->ShowWarning (LangString["LINUX_DISABLE_KERNEL_ONLY_SETTING"]);
#endif
			}
			else
				NoHardwareCryptoCheckBox->SetValue (false);
		}

		Gui->ShowWarning (LangString["LINUX_REMOUNT_BECAUSEOF_SETTING"]);
	}

	void PreferencesDialog::OnNoKernelCryptoCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked())
			NoKernelCryptoCheckBox->SetValue (Gui->AskYesNo (LangString["LINUX_DISABLE_KERNEL_CRYPT_CONFIRM"], false, true));
	}

	void PreferencesDialog::OnClose (wxCloseEvent& event)
	{
#ifdef TC_WINDOWS
		Hotkey::RegisterList (Gui->GetMainFrame(), UnregisteredHotkeys);
#endif
		event.Skip();
	}

	void PreferencesDialog::OnDismountOnPowerSavingCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked() && !ForceAutoDismountCheckBox->IsChecked())
			Gui->ShowWarning ("WARN_PREF_AUTO_DISMOUNT");
	}

	void PreferencesDialog::OnDismountOnScreenSaverCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked() && !ForceAutoDismountCheckBox->IsChecked())
			Gui->ShowWarning ("WARN_PREF_AUTO_DISMOUNT");
	}

	void PreferencesDialog::OnForceAutoDismountCheckBoxClick (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			ForceAutoDismountCheckBox->SetValue (!Gui->AskYesNo (LangString["CONFIRM_NO_FORCED_AUTODISMOUNT"], false, true));
	}

	void PreferencesDialog::OnHotkeyListItemDeselected (wxListEvent& event)
	{
		UpdateHotkeyButtons();
	}

	void PreferencesDialog::OnHotkeyListItemSelected (wxListEvent& event)
	{
		UpdateHotkeyButtons();
		HotkeyTextCtrl->ChangeValue (LangString ["PRESS_A_KEY_TO_ASSIGN"]);
		AssignHotkeyButton->Enable (false);
	}

	// Fixes an issue where going through PreferencesNotebook tabs would unintentionally select the first entry
	// in the LanguageListBox and thus cause a language change on OKButton press.
	void PreferencesDialog::OnPageChanged(wxBookCtrlEvent &event)
	{
		LanguageListBox->DeselectAll();
	}

	void PreferencesDialog::OnOKButtonClick (wxCommandEvent& event)
	{
#ifdef TC_WINDOWS
		HotkeyTextCtrl->SetValidator (wxTextValidator (wxFILTER_NONE));
#endif
		if (!Validate())
			return;

		shared_ptr <Pkcs5Kdf> selectedKdf;
		if (Pkcs5PrfChoice->GetSelection () != 0)
		{
			try
			{
				selectedKdf = Pkcs5Kdf::GetAlgorithm (wstring (Pkcs5PrfChoice->GetStringSelection ()));
			}
			catch (ParameterIncorrect&)
			{
				return;
			}
		}

		TransferDataFromWindow();

		Preferences.DefaultMountOptions.Protection = MountReadOnlyCheckBox->IsChecked() ? VolumeProtection::ReadOnly : VolumeProtection::None;
		Preferences.DefaultMountOptions.FilesystemOptions = FilesystemOptionsTextCtrl->GetValue();
		Preferences.DefaultKeyfiles = *DefaultKeyfilesPanel->GetKeyfiles();

		Preferences.DefaultMountOptions.Kdf = selectedKdf;
		Preferences.DefaultMountOptions.ProtectionKdf = selectedKdf;

		bool securityTokenModuleChanged = (Preferences.SecurityTokenModule != wstring (Pkcs11ModulePathTextCtrl->GetValue()));
		Preferences.SecurityTokenModule = wstring (Pkcs11ModulePathTextCtrl->GetValue());

		if (LanguageListBox->GetSelection() != wxNOT_FOUND) {
			wxString langToFind = LanguageListBox->GetString(LanguageListBox->GetSelection());
			for (map<wxString, std::wstring>::const_iterator each = langEntries.begin(); each != langEntries.end(); ++each) {
				if (each->second == langToFind) {
					Preferences.Language = each->first;
#ifdef DEBUG
					cout << "Lang set to: " << each->first << endl;
#endif
				}
			}
			Gui->ShowInfo (LangString["LINUX_RESTART_FOR_LANGUAGE_CHANGE"]);
		}

		Gui->SetPreferences (Preferences);

		try
		{
			if (securityTokenModuleChanged)
			{
				if (Preferences.SecurityTokenModule.IsEmpty())
				{
					if (SecurityToken::IsInitialized())
						SecurityToken::CloseLibrary ();
				}
				else
				{
					Gui->InitSecurityTokenLibrary();
				}
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}

#ifdef TC_WINDOWS
		// Hotkeys
		Hotkey::RegisterList (Gui->GetMainFrame(), Preferences.Hotkeys);
#endif

		EndModal (wxID_OK);
	}

	void PreferencesDialog::OnPreserveTimestampsCheckBoxClick (wxCommandEvent& event)
	{
#ifdef TC_LINUX
		if (!event.IsChecked())
			Gui->ShowInfo (LangString["LINUX_KERNEL_CRYPT_OPTION_CHANGE_MOUNTED_HINT"]);
#endif
	}

	void PreferencesDialog::OnRemoveHotkeyButtonClick (wxCommandEvent& event)
	{
#ifdef TC_WINDOWS
		foreach (long item, Gui->GetListCtrlSelectedItems (HotkeyListCtrl))
		{
			Hotkey *hotkey = reinterpret_cast <Hotkey *> (HotkeyListCtrl->GetItemData (item));
			hotkey->VirtualKeyCode = 0;
			hotkey->VirtualKeyModifiers = 0;

			vector <wstring> fields (HotkeyListCtrl->GetColumnCount());
			fields[ColumnHotkeyDescription] = hotkey->Description;
			fields[ColumnHotkey] = hotkey->GetShortcutString();
			Gui->UpdateListCtrlItem (HotkeyListCtrl, item, fields);

			UpdateHotkeyButtons();
		}
#endif
	}

	void PreferencesDialog::OnSelectPkcs11ModuleButtonClick (wxCommandEvent& event)
	{
		list < pair <wstring, wstring> > extensions;
		wxString libExtension;
		libExtension = wxDynamicLibrary::CanonicalizeName (L"x");

#ifdef TC_MACOSX
		extensions.push_back (make_pair (L"dylib", LangString["DLL_FILES"].ToStdWstring()));
#endif
		if (!libExtension.empty())
		{
			extensions.push_back (make_pair (libExtension.Mid (libExtension.find (L'.') + 1).ToStdWstring(), LangString["DLL_FILES"].ToStdWstring()));
			extensions.push_back (make_pair (L"*", L""));
		}

		string libDir;

#ifdef TC_WINDOWS

		char sysDir[TC_MAX_PATH];
		GetSystemDirectoryA (sysDir, sizeof (sysDir));
		libDir = sysDir;

#elif defined (TC_MACOSX)
		libDir = "/usr/local/lib";
#elif defined (TC_UNIX)
		libDir = "/usr/lib";
#endif

		Gui->ShowInfo ("SELECT_PKCS11_MODULE_HELP");

		FilePathList files = Gui->SelectFiles (this, LangString["SELECT_PKCS11_MODULE"], false, false, extensions, libDir);
		if (!files.empty())
			Pkcs11ModulePathTextCtrl->SetValue (wstring (*files.front()));
	}

	void PreferencesDialog::OnTimer ()
	{
#ifdef TC_WINDOWS
		for (UINT vKey = 0; vKey <= 0xFF; vKey++)
		{
			if (GetAsyncKeyState (vKey) < 0)
			{
				bool shift = wxGetKeyState (WXK_SHIFT);
				bool control = wxGetKeyState (WXK_CONTROL);
				bool alt = wxGetKeyState (WXK_ALT);
				bool win = wxGetKeyState (WXK_WINDOWS_LEFT) || wxGetKeyState (WXK_WINDOWS_RIGHT);

				if (!Hotkey::GetVirtualKeyCodeString (vKey).empty())	// If the key is allowed and its name has been resolved
				{
					LastVirtualKeyPressed = vKey;

					HotkeyShiftCheckBox->SetValue (shift);
					HotkeyControlCheckBox->SetValue (control);
					HotkeyAltCheckBox->SetValue (alt);
					HotkeyWinCheckBox->SetValue (win);

					HotkeyTextCtrl->ChangeValue (Hotkey::GetVirtualKeyCodeString (LastVirtualKeyPressed));
					UpdateHotkeyButtons();
					return;
				}
			}
		}
#endif
	}

	void PreferencesDialog::UpdateHotkeyButtons()
	{
		AssignHotkeyButton->Enable (!HotkeyTextCtrl->IsEmpty() && HotkeyListCtrl->GetSelectedItemCount() > 0);

		bool remove = false;
		foreach (long item, Gui->GetListCtrlSelectedItems (HotkeyListCtrl))
		{
			if (reinterpret_cast <Hotkey *> (HotkeyListCtrl->GetItemData (item))->VirtualKeyCode != 0)
				remove = true;
		}
		RemoveHotkeyButton->Enable (remove);
	}
}
