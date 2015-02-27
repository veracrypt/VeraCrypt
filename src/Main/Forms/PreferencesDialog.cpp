/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include <wx/dynlib.h>
#ifdef TC_WINDOWS
#include <wx/msw/registry.h>
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
			(is_aes_hw_cpu_supported() ? LangString["UISTR_YES"] : LangString["UISTR_NO"]));
#else
			LangString["NOT_APPLICABLE_OR_NOT_AVAILABLE"]);
#endif
		NoHardwareCryptoCheckBox->SetValidator (wxGenericValidator (&Preferences.DefaultMountOptions.NoHardwareCrypto));

		// Security tokens
		Pkcs11ModulePathTextCtrl->SetValue (wstring (Preferences.SecurityTokenModule));
		TC_CHECK_BOX_VALIDATOR (CloseSecurityTokenSessionsAfterMount);

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
		DismountOnLogOffCheckBox->SetLabel (_("VeraCrypt quits"));
		OpenExplorerWindowAfterMountCheckBox->SetLabel (_("Open Finder window for successfully mounted volume"));

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

		StdButtonsOK->SetDefault();

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
				Gui->ShowWarning (_("Please note that this setting takes effect only if use of the kernel cryptographic services is disabled."));
#endif
			}
			else
				NoHardwareCryptoCheckBox->SetValue (false);
		}

		Gui->ShowWarning (_("Please note that any currently mounted volumes need to be remounted before they can use this setting."));
	}

	void PreferencesDialog::OnNoKernelCryptoCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked())
			NoKernelCryptoCheckBox->SetValue (Gui->AskYesNo (_("Disabling the use of kernel cryptographic services can degrade performance.\n\nAre you sure?"), false, true));
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

	void PreferencesDialog::OnOKButtonClick (wxCommandEvent& event)
	{
#ifdef TC_WINDOWS
		HotkeyTextCtrl->SetValidator (wxTextValidator (wxFILTER_NONE));
#endif
		if (!Validate())
			return;

		TransferDataFromWindow();

		Preferences.DefaultMountOptions.Protection = MountReadOnlyCheckBox->IsChecked() ? VolumeProtection::ReadOnly : VolumeProtection::None;
		Preferences.DefaultMountOptions.FilesystemOptions = FilesystemOptionsTextCtrl->GetValue();
		Preferences.DefaultKeyfiles = *DefaultKeyfilesPanel->GetKeyfiles();

		bool securityTokenModuleChanged = (Preferences.SecurityTokenModule != wstring (Pkcs11ModulePathTextCtrl->GetValue()));
		Preferences.SecurityTokenModule = wstring (Pkcs11ModulePathTextCtrl->GetValue());

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
			Gui->ShowInfo (_("Please note that disabling this option may have no effect on volumes mounted using kernel cryptographic services."));
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
		extensions.push_back (make_pair (L"dylib", LangString["DLL_FILES"]));
#endif
		if (!libExtension.empty())
		{
			extensions.push_back (make_pair (libExtension.Mid (libExtension.find (L'.') + 1), LangString["DLL_FILES"]));
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
