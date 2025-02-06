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
#include "Volume/Hash.h"
#include "RandomPoolEnrichmentDialog.h"

namespace VeraCrypt
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

		HideBytes (RandomPoolStaticText, 24);
		MouseStaticText->Wrap (Gui->GetCharWidth (MouseStaticText) * 70);

		CollectedEntropy->SetRange (RNG_POOL_SIZE * 8);

		MainSizer->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 24));

		Layout();
		Fit();
		Center();

		MouseEventsCounter = 0;

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

		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&event), sizeof (event)));

		long coord = event.GetX();
		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&coord), sizeof (coord)));
		coord = event.GetY();
		RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <uint8 *> (&coord), sizeof (coord)));

		if (ShowRandomPoolCheckBox->IsChecked())
			ShowBytes (RandomPoolStaticText, RandomNumberGenerator::PeekPool().GetRange (0, 24));
		else
			HideBytes (RandomPoolStaticText, 24);

		/* conservative estimate: 1 mouse move event brings 1 bit of entropy
		 * https://security.stackexchange.com/questions/32844/for-how-much-time-should-i-randomly-move-the-mouse-for-generating-encryption-key/32848#32848
		 */
		ScopeLock lock (AccessMutex);
		if (MouseEventsCounter < (RNG_POOL_SIZE * 8))
			CollectedEntropy->SetValue (++MouseEventsCounter);
	}

	void RandomPoolEnrichmentDialog::OnShowRandomPoolCheckBoxClicked (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			HideBytes (RandomPoolStaticText, 24);
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

	void RandomPoolEnrichmentDialog::HideBytes (wxStaticText *textCtrl, size_t len)
	{
		wxString str;

		for (size_t i = 0; i < len + 1; ++i)
		{
			str += L"**";
		}

		textCtrl->SetLabel (str.c_str());
	}
}
