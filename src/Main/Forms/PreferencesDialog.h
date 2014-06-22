/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
		void OnCancelButtonClick (wxCommandEvent& event) { Close(); }
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
