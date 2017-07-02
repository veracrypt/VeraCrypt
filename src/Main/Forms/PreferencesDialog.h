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

#ifndef TC_HEADER_Main_Forms_PreferencesDialog
#define TC_HEADER_Main_Forms_PreferencesDialog

#include "Forms.h"
#include "Main/Main.h"
#include "KeyfilesPanel.h"

namespace VeraCrypt
{
	class PreferencesDialog : public PreferencesDialogBase
	{
	public:
		PreferencesDialog (wxWindow* parent);
		~PreferencesDialog ();

		void SelectPage (wxPanel *page);

	protected:
		void OnAssignHotkeyButtonClick (wxCommandEvent& event);
		void OnBackgroundTaskEnabledCheckBoxClick (wxCommandEvent& event);
		void OnCancelButtonClick (wxCommandEvent& event) { EndModal (wxID_CANCEL); }
		void OnClose (wxCloseEvent& event);
		void OnDismountOnPowerSavingCheckBoxClick (wxCommandEvent& event);
		void OnDismountOnScreenSaverCheckBoxClick (wxCommandEvent& event);
		void OnForceAutoDismountCheckBoxClick (wxCommandEvent& event);
		void OnHotkeyListItemDeselected (wxListEvent& event);
		void OnHotkeyListItemSelected (wxListEvent& event);
		void OnNoHardwareCryptoCheckBoxClick (wxCommandEvent& event);
		void OnNoKernelCryptoCheckBoxClick (wxCommandEvent& event);
		void OnOKButtonClick (wxCommandEvent& event);
		void OnPreserveTimestampsCheckBoxClick (wxCommandEvent& event);
		void OnRemoveHotkeyButtonClick (wxCommandEvent& event);
		void OnSelectPkcs11ModuleButtonClick (wxCommandEvent& event);
		void OnTimer ();
		void UpdateHotkeyButtons();

		enum
		{
			ColumnHotkeyDescription = 0,
			ColumnHotkey
		};

		KeyfilesPanel *DefaultKeyfilesPanel;
		int LastVirtualKeyPressed;
		auto_ptr <wxTimer> mTimer;
		UserPreferences Preferences;
		bool RestoreValidatorBell;
		HotkeyList UnregisteredHotkeys;
	};
}

#endif // TC_HEADER_Main_Forms_PreferencesDialog
