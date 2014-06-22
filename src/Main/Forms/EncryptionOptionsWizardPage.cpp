/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Volume/EncryptionTest.h"
#include "Volume/Hash.h"
#include "Main/GraphicUserInterface.h"
#include "BenchmarkDialog.h"
#include "EncryptionOptionsWizardPage.h"
#include "EncryptionTestDialog.h"

namespace VeraCrypt
{
	EncryptionOptionsWizardPage::EncryptionOptionsWizardPage (wxPanel* parent)
		: EncryptionOptionsWizardPageBase (parent)
	{

		EncryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();
		foreach (shared_ptr <EncryptionAlgorithm> ea, EncryptionAlgorithms)
		{
			if (!ea->IsDeprecated())
				EncryptionAlgorithmChoice->Append (ea->GetName(), ea.get());
		}

		EncryptionAlgorithmChoice->Select (0);
		
		Hashes = Hash::GetAvailableAlgorithms();
		foreach (shared_ptr <Hash> hash, Hashes)
		{
			if (!hash->IsDeprecated())
				HashChoice->Append (hash->GetName(), hash.get());
		}

		HashChoice->Select (0);
		OnEncryptionAlgorithmSelected();

	}

	shared_ptr <EncryptionAlgorithm> EncryptionOptionsWizardPage::GetEncryptionAlgorithm () const
	{
		return Gui->GetSelectedData <EncryptionAlgorithm> (EncryptionAlgorithmChoice)->GetNew();
	}

	shared_ptr <Hash> EncryptionOptionsWizardPage::GetHash () const
	{
		return Gui->GetSelectedData <Hash> (HashChoice)->GetNew();
	}

	void EncryptionOptionsWizardPage::OnBenchmarkButtonClick (wxCommandEvent& event)
	{
		BenchmarkDialog dialog (this);
		dialog.ShowModal();
	}

	void EncryptionOptionsWizardPage::OnEncryptionAlgorithmSelected ()
	{
		FreezeScope freeze (this);

		shared_ptr <EncryptionAlgorithm> ea = GetEncryptionAlgorithm();
		CipherList ciphers = ea->GetCiphers();

		if (ciphers.size() == 1)
		{
			EncryptionAlgorithmHyperlink->SetLabel (StringFormatter (LangString["MORE_INFO_ABOUT"], ea->GetName()));

			if (typeid (*ea) == typeid (AES))
				EncryptionAlgorithmStaticText->SetLabel (LangString["AES_HELP"]);
			else if (typeid (*ea) == typeid (Serpent))
				EncryptionAlgorithmStaticText->SetLabel (LangString["SERPENT_HELP"]);
			else if (typeid (*ea) == typeid (Twofish))
				EncryptionAlgorithmStaticText->SetLabel (LangString["TWOFISH_HELP"]);
			else
				EncryptionAlgorithmStaticText->SetLabel (L"");
		}
		else
		{
			if (ciphers.size() == 2)
			{
				EncryptionAlgorithmStaticText->SetLabel (StringFormatter (LangString["TWO_LAYER_CASCADE_HELP"],
					ciphers[0]->GetName(), (int) ciphers[0]->GetKeySize() * 8,
					ciphers[1]->GetName(), (int) ciphers[1]->GetKeySize() * 8));
			}
			else if (ciphers.size() == 3)
			{
				EncryptionAlgorithmStaticText->SetLabel (StringFormatter (LangString["THREE_LAYER_CASCADE_HELP"],
					ciphers[0]->GetName(), (int) ciphers[0]->GetKeySize() * 8,
					ciphers[1]->GetName(), (int) ciphers[1]->GetKeySize() * 8,
					ciphers[2]->GetName(), (int) ciphers[2]->GetKeySize() * 8));
			}
			else
				EncryptionAlgorithmStaticText->SetLabel (L"");

			EncryptionAlgorithmHyperlink->SetLabel (_("More information"));
		}

		Layout();
	}

	void EncryptionOptionsWizardPage::OnEncryptionAlgorithmHyperlinkClick (wxHyperlinkEvent& event)
	{
		if (GetEncryptionAlgorithm()->GetCiphers().size() == 1)
			Gui->OpenHomepageLink (this, wxString (GetEncryptionAlgorithm()->GetName()).Lower());
		else
			Gui->OpenHomepageLink (this, L"cascades");
	}

	void EncryptionOptionsWizardPage::OnHashHyperlinkClick (wxHyperlinkEvent& event)
	{
		Gui->OpenHomepageLink (this, L"hashalgorithms");
	}
	
	void EncryptionOptionsWizardPage::OnTestButtonClick (wxCommandEvent& event)
	{
		EncryptionTestDialog dialog (this);
		dialog.ShowModal();
	}

	void EncryptionOptionsWizardPage::SetEncryptionAlgorithm (shared_ptr <EncryptionAlgorithm> algorithm)
	{
		if (algorithm)
		{
			EncryptionAlgorithmChoice->SetStringSelection (algorithm->GetName());
			OnEncryptionAlgorithmSelected ();
		}
	}

	void EncryptionOptionsWizardPage::SetHash (shared_ptr <Hash> hash)
	{
		if (hash)
			HashChoice->SetStringSelection (hash->GetName());
	}
}
