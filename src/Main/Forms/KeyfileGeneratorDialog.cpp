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

		HideBytes (RandomPoolStaticText, 24);
		MouseStaticText->Wrap (Gui->GetCharWidth (MouseStaticText) * 70);

		CollectedEntropy->SetRange (RNG_POOL_SIZE * 8);

		MainSizer->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 24));

		Layout();
		Fit();
		Center();

		MouseEventsCounter = 0;

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
			int keyfilesCount = NumberOfKeyfiles->GetValue();
			int keyfilesSize = KeyfilesSize->GetValue();
			bool useRandomSize = RandomSizeCheckBox->IsChecked();
			wxString keyfileBaseName = KeyfilesBaseName->GetValue();
			keyfileBaseName.Trim(true);
			keyfileBaseName.Trim(false);

			if (keyfileBaseName.IsEmpty())
			{
				Gui->ShowWarning("KEYFILE_EMPTY_BASE_NAME");
				return;
			}

			wxFileName baseFileName = wxFileName::FileName (keyfileBaseName);
			if (!baseFileName.IsOk())
			{
				Gui->ShowWarning("KEYFILE_INVALID_BASE_NAME");
				return;
			}

			DirectoryPath keyfilesDir = Gui->SelectDirectory (Gui->GetActiveWindow(), LangString["SELECT_KEYFILE_GENERATION_DIRECTORY"], false);
			if (keyfilesDir.IsEmpty())
				return;

			wxFileName dirFileName = wxFileName::DirName( wstring(keyfilesDir).c_str() );
			if (!dirFileName.IsDirWritable ())
			{
				Gui->ShowWarning(L"You don't have write permission on the selected directory");
				return;
			}

			wxBusyCursor busy;
			for (int i = 0; i < keyfilesCount; i++)
			{
				int bufferLen;
				if (useRandomSize)
				{
					SecureBuffer sizeBuffer (sizeof(int));
					RandomNumberGenerator::GetData (sizeBuffer, true);

					memcpy(&bufferLen, sizeBuffer.Ptr(), sizeof(int));

					/* since keyfilesSize < 1024 * 1024, we mask with 0x000FFFFF */
					bufferLen = (long) (((unsigned long) bufferLen) & 0x000FFFFF);

					bufferLen %= ((1024*1024 - 64) + 1);
					bufferLen += 64;
				}
				else
					bufferLen = keyfilesSize;

				SecureBuffer keyfileBuffer (bufferLen);
				RandomNumberGenerator::GetData (keyfileBuffer, true);

				wstringstream convertStream;
				convertStream << i;
				wxString suffix = L"_";
				suffix += convertStream.str().c_str();

				wxFileName keyfileName;
				if (i == 0)
				{
					keyfileName.Assign(dirFileName.GetPath(), keyfileBaseName);
				}
				else
				{
					if (baseFileName.HasExt())
					{
						keyfileName.Assign(dirFileName.GetPath(), baseFileName.GetName() + suffix + L"." + baseFileName.GetExt());
					}
					else
					{
						keyfileName.Assign(dirFileName.GetPath(), keyfileBaseName + suffix);
					}
				}

				if (keyfileName.Exists())
				{
					wxString msg = wxString::Format(LangString["KEYFILE_ALREADY_EXISTS"], keyfileName.GetFullPath());
					if (!Gui->AskYesNo (msg, false, true))
						return;
				}

				{
					FilePath keyfilePath((const wchar_t*) keyfileName.GetFullPath().c_str());
					File keyfile;
					keyfile.Open (keyfilePath, File::CreateWrite);
					keyfile.Write (keyfileBuffer);
				}

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

	void KeyfileGeneratorDialog::OnShowRandomPoolCheckBoxClicked (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			HideBytes (RandomPoolStaticText, 24);
	}

	void KeyfileGeneratorDialog::OnRandomSizeCheckBoxClicked (wxCommandEvent& event)
	{
		if (!event.IsChecked())
			KeyfilesSize->Enable();
		else
			KeyfilesSize->Disable();
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

	void KeyfileGeneratorDialog::HideBytes (wxStaticText *textCtrl, size_t len)
	{
		wxString str;

		for (size_t i = 0; i < len + 1; ++i)
		{
			str += L"**";
		}

		textCtrl->SetLabel (str.c_str());
	}
}
