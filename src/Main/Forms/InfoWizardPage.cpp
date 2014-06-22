/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "InfoWizardPage.h"

namespace VeraCrypt
{
	InfoWizardPage::InfoWizardPage (wxPanel *parent, const wxString &actionButtonText, shared_ptr <Functor> actionFunctor)
		: InfoWizardPageBase (parent)
	{
		if (!actionButtonText.empty())
		{
			wxButton *actionButton = new wxButton (this, wxID_ANY, actionButtonText);
			ActionFunctor = actionFunctor;
			actionButton->Connect (wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler (InfoWizardPage::OnActionButtonClick), nullptr, this);

			InfoPageSizer->Add (actionButton, 0, wxALL, 5);
		}

		InfoStaticText->SetFocus();
	}

	void InfoWizardPage::SetMaxStaticTextWidth (int width)
	{
		InfoStaticText->Wrap (width);
	}
}
