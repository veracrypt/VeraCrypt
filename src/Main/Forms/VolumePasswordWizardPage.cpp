/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumePasswordWizardPage.h"

namespace VeraCrypt
{
	VolumePasswordWizardPage::VolumePasswordWizardPage (wxPanel* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableConfirmation)
		: VolumePasswordWizardPageBase (parent), ConfirmationMode (enableConfirmation)
	{
		PasswordPanel = new VolumePasswordPanel (this, password, keyfiles, false, true, true, enableConfirmation);
		PasswordPanel->UpdateEvent.Connect (EventConnector <VolumePasswordWizardPage> (this, &VolumePasswordWizardPage::OnPasswordPanelUpdate));

		PasswordPanelSizer->Add (PasswordPanel, 1, wxALL | wxEXPAND);
	}

	VolumePasswordWizardPage::~VolumePasswordWizardPage ()
	{
		PasswordPanel->UpdateEvent.Disconnect (this);
	}

	bool VolumePasswordWizardPage::IsValid ()
	{
		if (ConfirmationMode && !PasswordPanel->PasswordsMatch())
			return false;

		shared_ptr <KeyfileList> keyfiles (GetKeyfiles());
		shared_ptr <VolumePassword> password (GetPassword());

		return (password && !GetPassword()->IsEmpty()) || (keyfiles && !keyfiles->empty());
	}
}
