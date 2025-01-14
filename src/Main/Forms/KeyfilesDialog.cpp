/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "KeyfilesDialog.h"

namespace VeraCrypt
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
