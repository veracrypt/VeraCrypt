/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Volume/EncryptionModeXTS.h"
#include "Volume/EncryptionTest.h"
#include "Main/GraphicUserInterface.h"
#include "EncryptionTestDialog.h"

namespace TrueCrypt
{
	EncryptionTestDialog::EncryptionTestDialog (wxWindow* parent)
		: EncryptionTestDialogBase (parent)
	{
		EncryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();
		foreach (shared_ptr <EncryptionAlgorithm> ea, EncryptionAlgorithms)
		{
			if (!ea->IsDeprecated())
				EncryptionAlgorithmChoice->Append (ea->GetName(), ea.get());
		}

		EncryptionAlgorithmChoice->Select (0);
		Reset();

		Fit();
		Layout();
		Center();
	}

	void EncryptionTestDialog::EncryptOrDecrypt (bool encrypt)
	{
		try
		{
			bool xts = XtsModeCheckBox->IsChecked();

			shared_ptr <EncryptionAlgorithm> ea = GetSelectedEncryptionAlgorithm();

			Buffer key;
			GetTextCtrlData (KeyTextCtrl, key);
			
			if (key.Size() != ea->GetKeySize())
				throw_err (LangString["TEST_KEY_SIZE"]);

			ea->SetKey (key);

			Buffer data;
			GetTextCtrlData (encrypt ? PlainTextTextCtrl : CipherTextTextCtrl, data);

			if (data.Size() != ea->GetMaxBlockSize())
				throw_err (LangString[encrypt ? "TEST_PLAINTEXT_SIZE" : "TEST_CIPHERTEXT_SIZE"]);

			if (xts)
			{
				Buffer secondaryKey;
				GetTextCtrlData (SecondaryKeyTextCtrl, secondaryKey);

				if (secondaryKey.Size() != ea->GetKeySize())
					throw_err (LangString["TEST_INCORRECT_SECONDARY_KEY_SIZE"]);

				uint64 dataUnitNumber;
				size_t blockNumber;

				try
				{
					dataUnitNumber = StringConverter::ToUInt64 (wstring (DataUnitNumberTextCtrl->GetValue()));
				}
				catch (...)
				{
					DataUnitNumberTextCtrl->SetFocus();
					throw StringConversionFailed (SRC_POS);
				}

				try
				{
					blockNumber = StringConverter::ToUInt32 (wstring (BlockNumberTextCtrl->GetValue()));
					if (blockNumber > 31)
					{
						blockNumber = 31;
						BlockNumberTextCtrl->SetValue (L"31");
					}
				}
				catch (...)
				{
					BlockNumberTextCtrl->SetFocus();
					throw StringConversionFailed (SRC_POS);
				}

				shared_ptr <EncryptionMode> xts (new EncryptionModeXTS);
				xts->SetKey (secondaryKey);
				ea->SetMode (xts);

				Buffer sector (ENCRYPTION_DATA_UNIT_SIZE);
				BufferPtr block = sector.GetRange (blockNumber * ea->GetMaxBlockSize(), ea->GetMaxBlockSize());
				
				block.CopyFrom (data);

				if (encrypt)
					ea->EncryptSectors (sector, dataUnitNumber, 1, sector.Size());
				else
					ea->DecryptSectors (sector, dataUnitNumber, 1, sector.Size());

				data.CopyFrom (block);
			}
			else
			{
				if (encrypt)
					ea->GetCiphers().front()->EncryptBlock (data);
				else
					ea->GetCiphers().front()->DecryptBlock (data);
			}

			SetTextCtrlData (encrypt ? CipherTextTextCtrl : PlainTextTextCtrl, data);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	shared_ptr <EncryptionAlgorithm> EncryptionTestDialog::GetSelectedEncryptionAlgorithm () const
	{
		return Gui->GetSelectedData <EncryptionAlgorithm> (EncryptionAlgorithmChoice)->GetNew();
	}
	
	void EncryptionTestDialog::GetTextCtrlData (wxTextCtrl *textCtrl, Buffer &buffer) const
	{
		vector <byte> data;
		string dataStr = StringConverter::ToSingle (wstring (textCtrl->GetValue()));

		for (size_t i = 0; i < dataStr.size() / 2; ++i)
		{
			unsigned int dataByte;
			if (sscanf (dataStr.substr (i * 2, 2).c_str(), "%x", &dataByte) != 1)
			{
				textCtrl->SetFocus();
				throw StringConversionFailed (SRC_POS);
			}

			data.push_back ((byte) dataByte);
		}

		if (data.empty())
			return;

		buffer.CopyFrom (ConstBufferPtr (&data.front(), data.size()));
	}

	void EncryptionTestDialog::OnAutoTestAllButtonClick (wxCommandEvent& event)
	{
		try
		{
			{
				wxBusyCursor busy;
				EncryptionTest::TestAll();
			}

			Gui->ShowInfo ("TESTS_PASSED");
		}
		catch (Exception &e)
		{
			Gui->ShowError (e);
			Gui->ShowError ("TESTS_FAILED");
		}
	}

	void EncryptionTestDialog::OnEncryptionAlgorithmSelected ()
	{
		shared_ptr <EncryptionAlgorithm> ea = GetSelectedEncryptionAlgorithm();

		KeySizeStaticText->SetLabel (StringFormatter (L"{0} {1}", (uint32) ea->GetKeySize() * 8, LangString["BITS"]));

		Buffer key (ea->GetKeySize());
		key.Zero();
		SetTextCtrlData (KeyTextCtrl, key);
		SetTextCtrlData (SecondaryKeyTextCtrl, key);

		Buffer block (ea->GetMaxBlockSize());
		block.Zero();
		SetTextCtrlData (PlainTextTextCtrl, block);
		SetTextCtrlData (CipherTextTextCtrl, block);

		if (ea->GetCiphers().size() > 1)
		{
			XtsModeCheckBox->Disable();
			XtsModeCheckBox->SetValue (true);
			SecondaryKeyTextCtrl->Enable (true);
			DataUnitNumberTextCtrl->Enable (true);
			BlockNumberTextCtrl->Enable (true);
		}
		else
			XtsModeCheckBox->Enable();
	}

	void EncryptionTestDialog::OnXtsModeCheckBoxClick (wxCommandEvent& event)
	{
		bool enabled = event.IsChecked();
		SecondaryKeyTextCtrl->Enable (enabled);
		DataUnitNumberTextCtrl->Enable (enabled);
		BlockNumberTextCtrl->Enable (enabled);
	}

	void EncryptionTestDialog::SetTextCtrlData (wxTextCtrl *textCtrl, const BufferPtr &data)
	{
		wstring str;
		for (size_t i = 0; i < data.Size(); i++)
		{
			char strBuf[3];
			sprintf (strBuf, "%02x", (int) data[i]);
			str += StringConverter::ToWide (strBuf);
		}

		textCtrl->SetValue (str);
	}

	void EncryptionTestDialog::Reset ()
	{
		OnEncryptionAlgorithmSelected();

		DataUnitNumberTextCtrl->SetValue (L"0");
		BlockNumberTextCtrl->SetValue (L"0");
	}
}
