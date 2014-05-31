/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Volume/Hash.h"
#include "RandomPoolEnrichmentDialog.h"

namespace TrueCrypt
{
	RandomPoolEnrichmentDialog::RandomPoolEnrichmentDialog (wxWindow* parent) : RandomPoolEnrichmentDialogBase (parent) 
	{
		RandomNumberGenerator::Start();
		
		Hashes = Hash::GetAvailableAlgorithms();
		foreach (shared_ptr <Hash> hash, Hashes)
		{
			if (!hash->IsDeprecated())
			{
				HashChoice->Append (hash->GetName(), hash.get());

				if (typeid (*hash) == typeid (*RandomNumberGenerator::GetHash()))
					HashChoice->Select (HashChoice->GetCount() - 1);
			}
		}

		ShowBytes (RandomPoolStaticText, RandomNumberGenerator::PeekPool().GetRange (0, 24));
		MouseStaticText->Wrap (Gui->GetCharWidth (MouseStaticText) * 70);

		MainSizer->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 24));

		Layout();
		Fit();
		Center();

		foreach (wxWindow *c, this->GetChildren())
			c->Connect (wxEVT_MOTION, wxMouseEventHandler (RandomPoolEnrichmentDialog::OnMouseMotion), nullptr, this);
	}

	RandomPoolEnrichmentDialog::~RandomPoolEnrichmentDialog ()
	{
	}

	void RandomPoolEnrichmentDialog::OnHashSelected (wxCommandEvent& event)
	{
		RandomNumberGenerator::SetHash (Gui->GetSelectedData <Hash> (HashChoice)->GetNew());
	}

	void RandomPoolEnrichmentDialog::OnMouseMotion (wxMouseEvent& event)
	{
		event.Skip();

		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&event), sizeof (event)));

		long coord = event.GetX();
		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));
		coord = event.GetY();
		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));

		if (ShowRandomPoolCheckBox->IsChecked())
			ShowBytes (RandomPoolStaticText, RandomNumberGenerator::PeekPool().GetRange (0, 24));
	}

	void RandomPoolEnrichmentDialog::OnShowRandomPoolCheckBoxClicked (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			RandomPoolStaticText->SetLabel (L"");
	}

	void RandomPoolEnrichmentDialog::ShowBytes (wxStaticText *textCtrl, const ConstBufferPtr &buffer)
	{
		wxString str;

		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			str += wxString::Format (L"%02X", buffer[i]);
		}

		str += L"..";

		textCtrl->SetLabel (str.c_str());

		for (size_t i = 0; i < str.size(); ++i)
		{
			str[i] = L'X';
		}
	}
}
