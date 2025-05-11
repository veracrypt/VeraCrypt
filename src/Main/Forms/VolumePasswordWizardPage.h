/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumePasswordWizardPage
#define TC_HEADER_Main_Forms_VolumePasswordWizardPage

#include "Forms.h"
#include "VolumePasswordPanel.h"

namespace VeraCrypt
{
	class VolumePasswordWizardPage : public VolumePasswordWizardPageBase
	{
	public:
		VolumePasswordWizardPage (wxPanel* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableConfirmation = true);
		~VolumePasswordWizardPage ();

		shared_ptr <KeyfileList> GetKeyfiles () const { return PasswordPanel->GetKeyfiles(); }
		shared_ptr <VolumePassword> GetPassword () const { return PasswordPanel->GetPassword(); }
		void EnableUsePim () { PasswordPanel->EnableUsePim (); }
		bool IsPimSelected () const { return PasswordPanel->IsUsePimChecked ();}
		void SetPimSelected (bool selected) const { PasswordPanel->SetUsePimChecked (selected);}

		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf () const { return PasswordPanel->GetPkcs5Kdf(); }
		bool IsValid ();
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }

	protected:
		void OnPasswordPanelUpdate (EventArgs &args) { PageUpdatedEvent.Raise(); }

		bool ConfirmationMode;
		VolumePasswordPanel *PasswordPanel;
	};
}

#endif // TC_HEADER_Main_Forms_VolumePasswordWizardPage
