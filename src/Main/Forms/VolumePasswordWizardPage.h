/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumePasswordWizardPage
#define TC_HEADER_Main_Forms_VolumePasswordWizardPage

#include "Forms.h"
#include "VolumePasswordPanel.h"

namespace TrueCrypt
{
	class VolumePasswordWizardPage : public VolumePasswordWizardPageBase
	{
	public:
		VolumePasswordWizardPage (wxPanel* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableConfirmation = true);
		~VolumePasswordWizardPage ();

		shared_ptr <KeyfileList> GetKeyfiles () const { return PasswordPanel->GetKeyfiles(); }
		shared_ptr <VolumePassword> GetPassword () const { return PasswordPanel->GetPassword(); }
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
