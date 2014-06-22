/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Volume/Hash.h"
#include "KeyfileGeneratorDialog.h"

namespace VeraCrypt
{
	KeyfileGeneratorDialog::KeyfileGeneratorDialog (wxWindow* parent) : KeyfileGeneratorDialogBase (parent) 
	{
		RandomNumberGenerator::Start();
		
		Hashes = Hash::GetAvailableAlgorithms();
		foreach (shared_ptr <Hash> hash, Hashes)
		{
			if (!hash->IsDeprecated())
				HashChoice->Append (hash->GetName(), hash.get());
		}

		HashChoice->Select (0);
		RandomNumberGenerator::SetHash (Gui->GetSelectedData <Hash> (HashChoice)->GetNew());

		ShowBytes (RandomPoolStaticText, RandomNumberGenerator::PeekPool().GetRange (0, 24));
		MouseStaticText->Wrap (Gui->GetCharWidth (MouseStaticText) * 70);

		MainSizer->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 24));

		Layout();
		Fit();
		Center();

		foreach (wxWindow *c, this->GetChildren())
			c->Connect (wxEVT_MOTION, wxMouseEventHandler (KeyfileGeneratorDialog::OnMouseMotion), nullptr, this);
	}

	KeyfileGeneratorDialog::~KeyfileGeneratorDialog ()
	{
	}

	void KeyfileGeneratorDialog::OnGenerateButtonClick (wxCommandEvent& event)
	{
		try
		{
			FilePathList files = Gui->SelectFiles (Gui->GetActiveWindow(), wxEmptyString, true);

			if (files.empty())
				return;

			SecureBuffer keyfileBuffer (VolumePassword::MaxSize);
			RandomNumberGenerator::GetData (keyfileBuffer);

			{
				File keyfile;
				keyfile.Open (*files.front(), File::CreateWrite);
				keyfile.Write (keyfileBuffer);
			}

			Gui->ShowInfo ("KEYFILE_CREATED");
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void KeyfileGeneratorDialog::OnHashSelected (wxCommandEvent& event)
	{
		RandomNumberGenerator::SetHash (Gui->GetSelectedData <Hash> (HashChoice)->GetNew());
	}

	void KeyfileGeneratorDialog::OnMouseMotion (wxMouseEvent& event)
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
	
	void KeyfileGeneratorDialog::OnShowRandomPoolCheckBoxClicked (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			RandomPoolStaticText->SetLabel (L"");
	}

	void KeyfileGeneratorDialog::ShowBytes (wxStaticText *textCtrl, const ConstBufferPtr &buffer, bool appendDots)
	{
		wxString str;

		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			str += wxString::Format (L"%02X", buffer[i]);
		}

		if (appendDots)
			str += L"..";

		textCtrl->SetLabel (str.c_str());

		for (size_t i = 0; i < str.size(); ++i)
		{
			str[i] = L'X';
		}
	}
}
