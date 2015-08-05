/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
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
