/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "KeyfilesDialog.h"
#include "VolumePasswordPanel.h"
#include "SecurityTokenKeyfilesDialog.h"

namespace VeraCrypt
{
	VolumePasswordPanel::VolumePasswordPanel (wxWindow* parent, MountOptions* options, shared_ptr <VolumePassword> password, bool disableTruecryptMode, shared_ptr <KeyfileList> keyfiles, bool enableCache, bool enablePassword, bool enableKeyfiles, bool enableConfirmation, bool enablePkcs5Prf, bool isMountPassword, const wxString &passwordLabel)
		: VolumePasswordPanelBase (parent), Keyfiles (new KeyfileList), EnablePimEntry (true)
	{
		if (keyfiles)
		{
			*Keyfiles = *keyfiles;
			UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
		}
		else
		{
			*Keyfiles = Gui->GetPreferences().DefaultKeyfiles;
			UseKeyfilesCheckBox->SetValue (Gui->GetPreferences().UseKeyfiles && !Keyfiles->empty());
		}

		PasswordTextCtrl->SetMaxLength (VolumePassword::MaxSize);
		ConfirmPasswordTextCtrl->SetMaxLength (VolumePassword::MaxSize);

		if (!passwordLabel.empty())
		{
			PasswordStaticText->SetLabel (passwordLabel);
			GridBagSizer->Detach (PasswordStaticText);
			GridBagSizer->Add (PasswordStaticText, wxGBPosition (0, 1), wxGBSpan (1, 1), wxALIGN_CENTER_VERTICAL | wxBOTTOM, Gui->GetDefaultBorderSize());
		}

		CacheCheckBox->Show (enableCache);

		if (!enablePassword && enableKeyfiles)
		{
			Layout();
			Fit();
			PasswordPlaceholderSizer->SetMinSize (wxSize (PasswordTextCtrl->GetSize().GetWidth(), -1));
		}
		else if (!enablePkcs5Prf)
		{
			GridBagSizer->Remove (PasswordPlaceholderSizer);
		}

		PasswordStaticText->Show (enablePassword);
		PasswordTextCtrl->Show (enablePassword);
		DisplayPasswordCheckBox->Show (enablePassword);


		EnablePimEntry = enablePassword && (!enableConfirmation || (enablePkcs5Prf && !isMountPassword));
		PimCheckBox->Show (EnablePimEntry);
		VolumePimStaticText->Show (false);
		VolumePimTextCtrl->SetMaxLength (MAX_PIM_DIGITS);
		VolumePimTextCtrl->Show (false);
		VolumePimHelpStaticText->Show (false);

		SetPimValidator ();

		ConfirmPasswordStaticText->Show (enableConfirmation);
		ConfirmPasswordTextCtrl->Show (enableConfirmation);

		UseKeyfilesCheckBox->Show (enableKeyfiles);
		KeyfilesButton->Show (enableKeyfiles);

		Pkcs5PrfStaticText->Show (enablePkcs5Prf);
		Pkcs5PrfChoice->Show (enablePkcs5Prf);
		TrueCryptModeCheckBox->Show (!disableTruecryptMode);
		HeaderWipeCountText->Show (enablePkcs5Prf && !isMountPassword);
		HeaderWipeCount->Show (enablePkcs5Prf && !isMountPassword);

		if (options && !disableTruecryptMode)
		{
			TrueCryptModeCheckBox->SetValue (options->TrueCryptMode);
			if (options->TrueCryptMode)
			{
				PimCheckBox->Enable (false);
				VolumePimStaticText->Enable (false);
				VolumePimTextCtrl->Enable (false);
				VolumePimHelpStaticText->Enable (false);
			}
		}

		if (EnablePimEntry && options && options->Pim > 0)
		{
			PimCheckBox->SetValue (true);
			PimCheckBox->Show (false);
			VolumePimStaticText->Show (true);
			VolumePimTextCtrl->Show (true);
			VolumePimHelpStaticText->Show (true);
			SetVolumePim (options->Pim);
		}

		if (enablePkcs5Prf)
		{
			int index, prfInitialIndex = 0;
			if (isMountPassword)
			{
				// case of password for mounting
				Pkcs5PrfChoice->Delete (0);
				Pkcs5PrfChoice->Append (LangString["AUTODETECTION"]);
			}
			foreach_ref (const Pkcs5Kdf &kdf, Pkcs5Kdf::GetAvailableAlgorithms(false))
			{
				if (!kdf.IsDeprecated() || isMountPassword)
				{
					index = Pkcs5PrfChoice->Append (kdf.GetName());
					if (isMountPassword && options && options->Kdf
						&& (options->Kdf->GetName() == kdf.GetName())
					   )
					{
						prfInitialIndex = index;
					}
				}
			}
			Pkcs5PrfChoice->Select (prfInitialIndex);
		}

		if (!enablePkcs5Prf || (!enablePassword && !enableKeyfiles))
		{
			GridBagSizer->Remove (Pkcs5PrfSizer);
		}

		// Keyfiles drag & drop
		class FileDropTarget : public wxFileDropTarget
		{
		public:
			FileDropTarget (VolumePasswordPanel *panel) : Panel (panel) { }

			wxDragResult OnDragOver (wxCoord x, wxCoord y, wxDragResult def)
			{
				return wxDragLink;
			}

			bool OnDropFiles (wxCoord x, wxCoord y, const wxArrayString &filenames)
			{
				foreach (const wxString &f, filenames)
					Panel->AddKeyfile (make_shared <Keyfile> (wstring (f)));

				return true;
			}

		protected:
			VolumePasswordPanel *Panel;
		};

		if (enableKeyfiles)
		{
			SetDropTarget (new FileDropTarget (this));
			foreach (wxWindow *c, GetChildren())
				c->SetDropTarget (new FileDropTarget (this));
		}

		Layout();
		Fit();
	}

	VolumePasswordPanel::~VolumePasswordPanel ()
	{
		WipeTextCtrl (PasswordTextCtrl);
		WipeTextCtrl (ConfirmPasswordTextCtrl);
	}

	void VolumePasswordPanel::AddKeyfile (shared_ptr <Keyfile> keyfile)
	{
		if (!Keyfiles)
			Keyfiles.reset (new KeyfileList);

		Keyfiles->push_back (keyfile);
		UseKeyfilesCheckBox->SetValue (true);
	}

	void VolumePasswordPanel::SetPimValidator ()
	{
		wxTextValidator validator (wxFILTER_INCLUDE_CHAR_LIST);  // wxFILTER_NUMERIC does not exclude - . , etc.
		const wxChar *valArr[] = { L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8", L"9" };
		validator.SetIncludes (wxArrayString (array_capacity (valArr), (const wxChar **) &valArr));
		VolumePimTextCtrl->SetValidator (validator);
	}

	void VolumePasswordPanel::DisplayPassword (bool display, wxTextCtrl **textCtrl, int row)
	{
		FreezeScope freeze (this);
		bool isPim = (*textCtrl == VolumePimTextCtrl);
		int colspan = isPim? 1 : 2;

		wxTextCtrl *newTextCtrl = new wxTextCtrl (this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, display ? 0 : wxTE_PASSWORD);
		newTextCtrl->SetMaxLength (isPim? MAX_PIM_DIGITS : VolumePassword::MaxSize);
		newTextCtrl->SetValue ((*textCtrl)->GetValue());
		newTextCtrl->SetMinSize ((*textCtrl)->GetSize());

		GridBagSizer->Detach ((*textCtrl));
		GridBagSizer->Add (newTextCtrl, wxGBPosition (row, 1), wxGBSpan (1, colspan), wxEXPAND|wxBOTTOM|wxALIGN_CENTER_VERTICAL, 5);
		(*textCtrl)->Show (false);
		WipeTextCtrl (*textCtrl);

		Fit();
		Layout();
		newTextCtrl->SetMinSize ((*textCtrl)->GetMinSize());

		newTextCtrl->Connect (wxEVT_COMMAND_TEXT_UPDATED, isPim? wxCommandEventHandler (VolumePasswordPanel::OnPimChanged): wxCommandEventHandler (VolumePasswordPanel::OnTextChanged), nullptr, this);
		delete *textCtrl;
		*textCtrl = newTextCtrl;
		if (isPim)
			SetPimValidator ();
	}

	shared_ptr <VolumePassword> VolumePasswordPanel::GetPassword (bool bForceLegacyPassword) const
	{
		return GetPassword (PasswordTextCtrl, bForceLegacyPassword || GetTrueCryptMode());
	}

	shared_ptr <VolumePassword> VolumePasswordPanel::GetPassword (wxTextCtrl *textCtrl, bool bLegacyPassword) const
	{
		shared_ptr <VolumePassword> password;
		wchar_t passwordBuf[VolumePassword::MaxSize + 1];
		size_t maxPasswordLength = bLegacyPassword? VolumePassword::MaxLegacySize: VolumePassword::MaxSize;
		finally_do_arg (BufferPtr, BufferPtr (reinterpret_cast <byte *> (passwordBuf), sizeof (passwordBuf)), { finally_arg.Erase(); });

#ifdef TC_WINDOWS
		int len = GetWindowText (static_cast <HWND> (textCtrl->GetHandle()), passwordBuf, VolumePassword::MaxSize + 1);
		password = ToUTF8Password (passwordBuf, len);
#else
		wxString passwordStr (textCtrl->GetValue());	// A copy of the password is created here by wxWidgets, which cannot be erased
		for (size_t i = 0; i < passwordStr.size() && i < maxPasswordLength; ++i)
		{
			passwordBuf[i] = (wchar_t) passwordStr[i];
			passwordStr[i] = L'X';
		}
		password = ToUTF8Password (passwordBuf, passwordStr.size() <= maxPasswordLength ? passwordStr.size() : maxPasswordLength);
#endif
		return password;
	}

	shared_ptr <Pkcs5Kdf> VolumePasswordPanel::GetPkcs5Kdf (bool &bUnsupportedKdf) const
	{
		return GetPkcs5Kdf (GetTrueCryptMode(), bUnsupportedKdf);
	}

	shared_ptr <Pkcs5Kdf> VolumePasswordPanel::GetPkcs5Kdf (bool bTrueCryptMode, bool &bUnsupportedKdf) const
	{
		bUnsupportedKdf = false;
		try
		{
			int index = Pkcs5PrfChoice->GetSelection ();
			if ((wxNOT_FOUND == index) || (0 == index))
			{
				// auto-detection
				return shared_ptr <Pkcs5Kdf> ();
			}
			else
				return Pkcs5Kdf::GetAlgorithm (wstring (Pkcs5PrfChoice->GetStringSelection()), bTrueCryptMode);
		}
		catch (ParameterIncorrect&)
		{
			bUnsupportedKdf = true;
			return shared_ptr <Pkcs5Kdf> ();
		}
	}

	int VolumePasswordPanel::GetVolumePim () const
	{
		if (VolumePimTextCtrl->IsEnabled () && VolumePimTextCtrl->IsShown ())
		{
			wxString pimStr (VolumePimTextCtrl->GetValue());
			long pim = 0;
			if (pimStr.IsEmpty())
				return 0;
			if (((size_t) wxNOT_FOUND == pimStr.find_first_not_of (wxT("0123456789")))
				&& pimStr.ToLong (&pim)
				&& pim <= MAX_PIM_VALUE)
				return (int) pim;
			else
				return -1;
		}
		else
			return 0;
	}

	void VolumePasswordPanel::SetVolumePim (int pim)
	{
		if (pim > 0)
		{
			VolumePimTextCtrl->SetValue (StringConverter::FromNumber (pim));
		}
		else
		{
			VolumePimTextCtrl->SetValue (wxT(""));
		}
	}

	bool VolumePasswordPanel::GetTrueCryptMode () const
	{
		return TrueCryptModeCheckBox->GetValue ();
	}
	
	void VolumePasswordPanel::SetTrueCryptMode (bool trueCryptMode)
	{
		bool bEnablePIM = !trueCryptMode;
		TrueCryptModeCheckBox->SetValue (trueCryptMode);
		PimCheckBox->Enable (bEnablePIM);
		VolumePimStaticText->Enable (bEnablePIM);
		VolumePimTextCtrl->Enable (bEnablePIM);
		VolumePimHelpStaticText->Enable (bEnablePIM);
	}

	int VolumePasswordPanel::GetHeaderWipeCount () const
	{
		try
		{
			long wipeCount;
			wxString wipeCountStrDesc = HeaderWipeCount->GetStringSelection();
			wxString wipeCountStr = wipeCountStrDesc.BeforeFirst(wxT('-'));
			if (!wipeCountStr.ToLong(&wipeCount))
				wipeCount = PRAND_HEADER_WIPE_PASSES;
			return (int) wipeCount;
		}
		catch (ParameterIncorrect&)
		{
			return PRAND_HEADER_WIPE_PASSES;
		}
	}

	void VolumePasswordPanel::OnAddKeyfileDirMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			DirectoryPath dir = Gui->SelectDirectory (this, LangString["SELECT_KEYFILE_PATH"]);

			if (!dir.IsEmpty())
			{
				Keyfiles->push_back (make_shared <Keyfile> (dir));

				UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
				OnUpdate();
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnAddKeyfilesMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			FilePathList files = Gui->SelectFiles (this, LangString["SELECT_KEYFILES"], false, true);

			if (!files.empty())
			{
				foreach_ref (const FilePath &f, files)
					Keyfiles->push_back (make_shared <Keyfile> (f));

				UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
				OnUpdate();
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnAddSecurityTokenSignatureMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			SecurityTokenKeyfilesDialog dialog (this);
			if (dialog.ShowModal() == wxID_OK)
			{
				foreach (const SecurityTokenKeyfilePath &path, dialog.GetSelectedSecurityTokenKeyfilePaths())
				{
					Keyfiles->push_back (make_shared <Keyfile> (wstring (path)));
				}

				if (!dialog.GetSelectedSecurityTokenKeyfilePaths().empty())
				{
					UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
					OnUpdate();
				}
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnDisplayPasswordCheckBoxClick (wxCommandEvent& event)
	{
		DisplayPassword (event.IsChecked(), &PasswordTextCtrl, 1);

		if (ConfirmPasswordTextCtrl->IsShown())
			DisplayPassword (event.IsChecked(), &ConfirmPasswordTextCtrl, 2);

		if (VolumePimTextCtrl->IsShown())
			DisplayPassword (event.IsChecked(), &VolumePimTextCtrl, 3);

		OnUpdate();
	}

	void VolumePasswordPanel::OnKeyfilesButtonClick (wxCommandEvent& event)
	{
		KeyfilesDialog dialog (GetParent(), Keyfiles);

		if (dialog.ShowModal() == wxID_OK)
		{
			Keyfiles = dialog.GetKeyfiles();

			UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
			OnUpdate();
		}
	}

	void VolumePasswordPanel::OnKeyfilesButtonRightClick (wxMouseEvent& event)
	{
		wxMenu popup;
		Gui->AppendToMenu (popup, LangString["IDC_KEYADD"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddKeyfilesMenuItemSelected));
		Gui->AppendToMenu (popup, LangString["IDC_ADD_KEYFILE_PATH"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddKeyfileDirMenuItemSelected));
		Gui->AppendToMenu (popup, LangString["IDC_TOKEN_FILES_ADD"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddSecurityTokenSignatureMenuItemSelected));

		PopupMenu (&popup, KeyfilesButton->GetPosition().x + 2, KeyfilesButton->GetPosition().y + 2);
	}

	void VolumePasswordPanel::OnKeyfilesButtonRightDown (wxMouseEvent& event)
	{
#ifndef TC_MACOSX
		event.Skip();
#endif
	}

	bool VolumePasswordPanel::PasswordsMatch () const
	{
		assert (ConfirmPasswordStaticText->IsShown());
		try
		{
			return *GetPassword (PasswordTextCtrl) == *GetPassword (ConfirmPasswordTextCtrl);
		}
		catch (PasswordException&)
		{
			return false;
		}
	}

	void VolumePasswordPanel::WipeTextCtrl (wxTextCtrl *textCtrl)
	{
		textCtrl->SetValue (wxString (L'X', textCtrl->GetLineLength(0)));
		GetPassword (textCtrl);
	}

	bool VolumePasswordPanel::UpdatePimHelpText (bool pimChanged)
	{
		bool guiUpdated = false;
		if (pimChanged && VolumePimHelpStaticText->GetForegroundColour() != *wxRED)
		{
			VolumePimHelpStaticText->SetForegroundColour(*wxRED);
			VolumePimHelpStaticText->SetLabel(LangString["PIM_CHANGE_WARNING"]);
			guiUpdated = true;
		}
		if (!pimChanged && VolumePimHelpStaticText->GetForegroundColour() != *wxBLACK)
		{
			VolumePimHelpStaticText->SetForegroundColour(*wxBLACK);
			VolumePimHelpStaticText->SetLabel(LangString["IDC_PIM_HELP"]);
			guiUpdated = true;
		}

		if (guiUpdated)
		{
			Layout();
			Fit();
			GetParent()->Layout();
			GetParent()->Fit();
		}
		return guiUpdated;
	}

	void VolumePasswordPanel::OnUsePimCheckBoxClick( wxCommandEvent& event )
	{
		if (EnablePimEntry)
		{
			PimCheckBox->Show (false);
			VolumePimStaticText->Show (true);
			VolumePimTextCtrl->Show (true);
			VolumePimHelpStaticText->Show (true);

			if (DisplayPasswordCheckBox->IsChecked ())
				DisplayPassword (true, &VolumePimTextCtrl, 3);
			else
			{
				Layout();
				Fit();
			}

			GetParent()->Layout();
			GetParent()->Fit();
		}
	}

	void VolumePasswordPanel::OnTrueCryptModeChecked( wxCommandEvent& event )
	{
		bool bEnablePIM = !GetTrueCryptMode ();
		PimCheckBox->Enable (bEnablePIM);
		VolumePimStaticText->Enable (bEnablePIM);
		VolumePimTextCtrl->Enable (bEnablePIM);
		VolumePimHelpStaticText->Enable (bEnablePIM);
	}
}
