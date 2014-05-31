/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_ChangePasswordDialog
#define TC_HEADER_Main_Forms_ChangePasswordDialog

#include "Forms.h"
#include "Main/Main.h"
#include "VolumePasswordPanel.h"

namespace TrueCrypt
{
	class ChangePasswordDialog : public ChangePasswordDialogBase
	{
	public:
		struct Mode
		{
			enum Enum
			{
				ChangePasswordAndKeyfiles,
				ChangeKeyfiles,
				RemoveAllKeyfiles,
				ChangePkcs5Prf
			};
		};

		ChangePasswordDialog (wxWindow* parent, shared_ptr <VolumePath> volumePath, Mode::Enum mode = Mode::ChangePasswordAndKeyfiles, shared_ptr <VolumePassword> password = shared_ptr <VolumePassword> (), shared_ptr <KeyfileList> keyfiles = shared_ptr <KeyfileList> (), shared_ptr <VolumePassword> newPassword = shared_ptr <VolumePassword> (), shared_ptr <KeyfileList> newKeyfiles = shared_ptr <KeyfileList> ());
		virtual ~ChangePasswordDialog ();

	protected:
		void OnOKButtonClick (wxCommandEvent& event);
		void OnPasswordPanelUpdate ();
		void OnPasswordPanelUpdate (EventArgs &args) { OnPasswordPanelUpdate(); }

		Mode::Enum DialogMode;

		VolumePasswordPanel *CurrentPasswordPanel;
		VolumePasswordPanel *NewPasswordPanel;
		shared_ptr <VolumePath> Path;
	};
}

#endif // TC_HEADER_Main_Forms_ChangePasswordDialog
