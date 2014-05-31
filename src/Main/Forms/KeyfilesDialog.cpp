/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "KeyfilesDialog.h"

namespace TrueCrypt
{
	KeyfilesDialog::KeyfilesDialog (wxWindow* parent, shared_ptr <KeyfileList> keyfiles)
		: KeyfilesDialogBase (parent), Keyfiles (keyfiles)
	{
		mKeyfilesPanel = new KeyfilesPanel (this, keyfiles);
		PanelSizer->Add (mKeyfilesPanel, 1, wxALL | wxEXPAND);

		WarningStaticText->SetLabel (LangString["IDT_KEYFILE_WARNING"]);
		WarningStaticText->Wrap (Gui->GetCharWidth (this) * 15);

		Layout();
		Fit();

		KeyfilesNoteStaticText->SetLabel (LangString["KEYFILES_NOTE"]);
		KeyfilesNoteStaticText->Wrap (UpperSizer->GetSize().GetWidth() - Gui->GetCharWidth (this) * 2);

		Layout();
		Fit();
		Center();
	}
			
	void KeyfilesDialog::OnCreateKeyfileButttonClick (wxCommandEvent& event)
	{
		Gui->CreateKeyfile();
	}

	void KeyfilesDialog::OnKeyfilesHyperlinkClick (wxHyperlinkEvent& event)
	{
		Gui->OpenHomepageLink (this, L"keyfiles");
	}
}
