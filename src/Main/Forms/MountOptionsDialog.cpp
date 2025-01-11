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
#include "Main/Main.h"
#include "Main/GraphicUserInterface.h"
#include "MountOptionsDialog.h"

namespace VeraCrypt
{
#ifdef TC_MACOSX

	bool MountOptionsDialog::ProcessEvent(wxEvent& event)
	{
		if(GraphicUserInterface::HandlePasswordEntryCustomEvent (event))
			return true;
		else
			return MountOptionsDialogBase::ProcessEvent(event);
	}
#endif

	MountOptionsDialog::MountOptionsDialog (wxWindow *parent, MountOptions &options, const wxString &title, bool disableMountOptions)
		: MountOptionsDialogBase (parent, wxID_ANY, wxString()
#ifdef __WXGTK__ // GTK apparently needs wxRESIZE_BORDER to support dynamic resizing
		, wxDefaultPosition, wxSize (-1,-1), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER
#endif
		), Options (options)
#ifdef TC_UNIX
		, m_showRedBorder(false)
#endif
	{
		if (!title.empty())
			this->SetTitle (title);
		else if (options.Path && !options.Path->IsEmpty())
			this->SetTitle (StringFormatter (LangString["ENTER_PASSWORD_FOR"], wstring (*options.Path)));
		else
			this->SetTitle (LangString["ENTER_TC_VOL_PASSWORD"]);

#ifdef TC_UNIX
		if (Gui->InsecureMountAllowed())
		{
			this->SetTitle (LangString["INSECURE_MODE"] + L" - " + this->GetTitle());
			m_showRedBorder = true;
			Bind(wxEVT_PAINT, &MountOptionsDialog::OnPaint, this);  
			Bind(wxEVT_SIZE, &MountOptionsDialog::OnSize, this);
		}
#endif

		if (disableMountOptions)
			OptionsButton->Show (false);
			

#ifdef TC_MACOSX
		GraphicUserInterface::InstallPasswordEntryCustomKeyboardShortcuts (this);
#endif

		PasswordPanel = new VolumePasswordPanel (this, &options, options.Password, options.Keyfiles, !disableMountOptions, true, true, false, true, true);
		PasswordPanel->SetCacheCheckBoxValidator (wxGenericValidator (&Options.CachePassword));

		PasswordSizer->Add (PasswordPanel, 1, wxALL | wxEXPAND);

#ifdef __WXGTK__
		FilesystemOptionsSizer->Remove (FilesystemSpacer);
		OptionsPanel->Show (false);
		Fit();
		Layout();
		SetMinSize (GetSize());
#endif

		NoFilesystemCheckBox->SetValidator (wxGenericValidator (&Options.NoFilesystem));
		RemovableCheckBox->SetValidator (wxGenericValidator (&Options.Removable));
		PartitionInSystemEncryptionScopeCheckBox->SetValidator (wxGenericValidator (&Options.PartitionInSystemEncryptionScope));

		TransferDataToWindow();

		if (Options.MountPoint && !Options.MountPoint->IsEmpty())
			 MountPointTextCtrl->SetValue (wstring (*Options.MountPoint));

		FilesystemOptionsTextCtrl->SetValue (Options.FilesystemOptions);

		ReadOnlyCheckBox->SetValue (Options.Protection == VolumeProtection::ReadOnly);
		BackupHeaderCheckBox->SetValidator (wxGenericValidator (&Options.UseBackupHeaders));
		ProtectionCheckBox->SetValue (Options.Protection == VolumeProtection::HiddenVolumeReadOnly);

		OptionsButtonLabel = OptionsButton->GetLabel();
		OptionsButton->SetLabel (OptionsButtonLabel + L" >");
		OptionsPanel->Show (false);

		ProtectionPasswordPanel = new VolumePasswordPanel (ProtectionSizer->GetStaticBox(), &options, options.ProtectionPassword, options.ProtectionKeyfiles, false, true, true, false, true, true, LangString["IDT_HIDDEN_PROT_PASSWD"]);
		ProtectionPasswordPanel->TopOwnerParent = this;
		ProtectionPasswordSizer->Add (ProtectionPasswordPanel, 1, wxALL | wxEXPAND);

		UpdateDialog();
		Center();
	}

	void MountOptionsDialog::OnInitDialog (wxInitDialogEvent& event)
	{
		PasswordPanel->SetFocusToPasswordTextCtrl();
	}

	void MountOptionsDialog::OnMountPointButtonClick (wxCommandEvent& event)
	{
		DirectoryPath dir = Gui->SelectDirectory (this, wxEmptyString, false);
		if (!dir.IsEmpty())
			MountPointTextCtrl->SetValue (wstring (dir));
	}

	void MountOptionsDialog::OnOKButtonClick (wxCommandEvent& event)
	{
		/* verify that PIM values are valid before continuing*/
		int Pim = PasswordPanel->GetVolumePim();
		int ProtectionPim = (!ReadOnlyCheckBox->IsChecked() && ProtectionCheckBox->IsChecked())?
			ProtectionPasswordPanel->GetVolumePim() : 0;

		/* invalid PIM: set focus to PIM field and stop processing */
		if (-1 == Pim || (PartitionInSystemEncryptionScopeCheckBox->IsChecked() && Pim > MAX_BOOT_PIM_VALUE))
		{
			PasswordPanel->SetFocusToPimTextCtrl();
			return;
		}

		if (-1 == ProtectionPim || (PartitionInSystemEncryptionScopeCheckBox->IsChecked() && ProtectionPim > MAX_BOOT_PIM_VALUE))
		{
			ProtectionPasswordPanel->SetFocusToPimTextCtrl();
			return;
		}

		TransferDataFromWindow();

		try
		{
			Options.Password = PasswordPanel->GetPassword(Options.PartitionInSystemEncryptionScope);
		}
		catch (PasswordException& e)
		{
			Gui->ShowWarning (e);
			return;
		}
		
		if (Options.PartitionInSystemEncryptionScope && Options.Password->Size() > VolumePassword::MaxLegacySize)
		{
			Gui->ShowWarning (StringFormatter (LangString["LINUX_SYSTEM_ENC_PW_LENGTH_NOTE"], (int) VolumePassword::MaxLegacySize));
			return;
		}
		
		Options.Pim = Pim;
		Options.Kdf = PasswordPanel->GetPkcs5Kdf();
		Options.Keyfiles = PasswordPanel->GetKeyfiles();

		if (ReadOnlyCheckBox->IsChecked())
		{
			Options.Protection = VolumeProtection::ReadOnly;
		}
		else if (ProtectionCheckBox->IsChecked())
		{
			try
			{
				Options.ProtectionPassword = ProtectionPasswordPanel->GetPassword(false);
			}
			catch (PasswordException& e)
			{
				Gui->ShowWarning (e);
				return;
			}
			Options.Protection = VolumeProtection::HiddenVolumeReadOnly;
			Options.ProtectionPim = ProtectionPim;
			Options.ProtectionKdf = ProtectionPasswordPanel->GetPkcs5Kdf();
			Options.ProtectionKeyfiles = ProtectionPasswordPanel->GetKeyfiles();
		}
		else
		{
			Options.Protection = VolumeProtection::None;
		}

		wstring mountPoint (MountPointTextCtrl->GetValue());
		if (!mountPoint.empty())
			Options.MountPoint = make_shared <DirectoryPath> (mountPoint);

		Options.FilesystemOptions = FilesystemOptionsTextCtrl->GetValue();
		Options.EMVSupportEnabled = Gui->GetPreferences().EMVSupportEnabled;

		EndModal (wxID_OK);
	}

	void MountOptionsDialog::OnOptionsButtonClick (wxCommandEvent& event)
	{
		FreezeScope freeze (this);
		OptionsPanel->Show (!OptionsPanel->IsShown());
		UpdateDialog();
		OptionsButton->SetLabel (OptionsButtonLabel + (OptionsPanel->IsShown() ? L" <" : L" >"));
	}

	void MountOptionsDialog::OnProtectionCheckBoxClick (wxCommandEvent& event)
	{
		FreezeScope freeze (this);
		ProtectionPasswordPanel->Show (event.IsChecked());
		Fit();
		Layout();
		ProtectionPasswordPanel->SetFocusToPasswordTextCtrl();
	}

	void MountOptionsDialog::OnProtectionHyperlinkClick (wxHyperlinkEvent& event)
	{
		Gui->OpenHomepageLink (this, L"hiddenvolprotection");
	}

	void MountOptionsDialog::UpdateDialog ()
	{
		FreezeScope freeze (this);

#ifdef TC_WINDOWS
		FilesystemSizer->Show (false);
#else
		FilesystemOptionsSizer->Show (!NoFilesystemCheckBox->IsChecked());

#	ifdef TC_MACOSX
		FilesystemOptionsStaticText->Show (false);
		FilesystemOptionsTextCtrl->Show (false);
#	endif

		if (!Options.Path || Options.Path->IsEmpty())
		{
			MountPointTextCtrlStaticText->Show (false);
			MountPointTextCtrl->Show (false);
			MountPointButton->Show (false);
		}
		RemovableCheckBox->Show (false);
#endif
		ProtectionSizer->Show (!ReadOnlyCheckBox->IsChecked());
		ProtectionPasswordPanel->Show (!ReadOnlyCheckBox->IsChecked() && ProtectionCheckBox->IsChecked());

		Fit();
		Layout();
		MainSizer->Fit( this );
	}

#ifdef TC_UNIX
	void MountOptionsDialog::OnPaint(wxPaintEvent& event)  
	{  
		wxPaintDC dc(this);  
		if (m_showRedBorder)  
		{  
			wxSize size = GetClientSize();  
			wxPen pen(*wxRED, 3); // 3 pixels width  
			dc.SetPen(pen);  
			dc.SetBrush(*wxTRANSPARENT_BRUSH);  
			dc.DrawRectangle(0, 0, size.GetWidth(), size.GetHeight());  
		}  
		event.Skip();  
	}  
	
	void MountOptionsDialog::OnSize(wxSizeEvent& event)  
	{  
		event.Skip();  
		if (m_showRedBorder)  
			Refresh();  
	}
#endif
}
