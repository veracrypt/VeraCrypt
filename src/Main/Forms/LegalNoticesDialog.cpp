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
#include "LegalNoticesDialog.h"
#include "Main/GraphicUserInterface.h"
#include "Main/Resources.h"

namespace VeraCrypt
{
	LegalNoticesDialog::LegalNoticesDialog (wxWindow* parent) : LegalNoticesDialogBase (parent)
	{
		LegalNoticesTextCtrl->SetMinSize (wxSize (
			Gui->GetCharWidth (LegalNoticesTextCtrl) * 88,
			Gui->GetCharHeight (LegalNoticesTextCtrl) * 28));

		Layout();
		Fit();
		Center();

		LegalNoticesTextCtrl->ChangeValue (StringConverter::ToWide (Resources::GetLegalNotices()));
	}
}
