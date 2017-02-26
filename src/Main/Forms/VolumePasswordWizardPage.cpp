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

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumePasswordWizardPage.h"

namespace VeraCrypt
{
	VolumePasswordWizardPage::VolumePasswordWizardPage (wxPanel* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableConfirmation)
		: VolumePasswordWizardPageBase (parent), ConfirmationMode (enableConfirmation)
	{
		PasswordPanel = new VolumePasswordPanel (this, NULL, password, true, keyfiles, false, true, true, enableConfirmation, !enableConfirmation, !enableConfirmation);
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

		try
		{
			shared_ptr <KeyfileList> keyfiles (GetKeyfiles());
			shared_ptr <VolumePassword> password (GetPassword());

			return (password && !GetPassword()->IsEmpty()) || (keyfiles && !keyfiles->empty());
		}
		catch (PasswordException&)
		{
			return false;
		}
	}
}
