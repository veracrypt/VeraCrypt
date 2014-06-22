/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
