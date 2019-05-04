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

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "NewSecurityTokenKeyfileDialog.h"

namespace VeraCrypt
{
	NewSecurityTokenKeyfileDialog::NewSecurityTokenKeyfileDialog (wxWindow* parent, const wstring &keyfileName) : NewSecurityTokenKeyfileDialogBase (parent)
	{
		list <SecurityTokenInfo> tokens = SecurityToken::GetAvailableTokens();

		if (tokens.empty())
			throw_err (LangString ["NO_TOKENS_FOUND"]);

		foreach (const SecurityTokenInfo &token, tokens)
		{
			wstringstream tokenLabel;
			tokenLabel << L"[" << token.SlotId << L"] " << token.Label;

			SecurityTokenChoice->Append (tokenLabel.str(), (void *) token.SlotId);
		}

		SecurityTokenChoice->Select (0);
		KeyfileNameTextCtrl->SetValue (keyfileName);

		KeyfileNameTextCtrl->SetMinSize (wxSize (Gui->GetCharWidth (KeyfileNameTextCtrl) * 32, -1));

		Fit();
		Layout();
		Center();
	}

	void NewSecurityTokenKeyfileDialog::OnKeyfileNameChanged (wxCommandEvent& event)
	{
		StdButtonsOK->Enable (!KeyfileNameTextCtrl->GetValue().empty());
		event.Skip();
	}
}
