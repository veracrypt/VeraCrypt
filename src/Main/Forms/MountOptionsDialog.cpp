/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/Main.h"
#include "Main/GraphicUserInterface.h"
#include "MountOptionsDialog.h"

namespace TrueCrypt
{
	MountOptionsDialog::MountOptionsDialog (wxWindow *parent, MountOptions &options, const wxString &title, bool disableMountOptions)
		: MountOptionsDialogBase (parent, wxID_ANY, wxString()
#ifdef __WXGTK__ // GTK apparently needs wxRESIZE_BORDER to support dynamic resizing
		, wxDefaultPosition, wxSize (-1,-1), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER
#endif
		), Options (options)
	{
		if (!title.empty())
			this->SetTitle (title);
		else if (options.Path && !options.Path->IsEmpty())
			this->SetTitle (StringFormatter (LangString["ENTER_PASSWORD_FOR"], wstring (*options.Path)));
		else
			this->SetTitle (LangString["ENTER_TC_VOL_PASSWORD"]);

		if (disableMountOptions)
			OptionsButton->Show (false);

		PasswordPanel = new VolumePasswordPanel (this, options.Password, options.Keyfiles, !disableMountOptions);
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
		ProtectionCheckBox->SetValue (Options.Protection == VolumeProtection::HiddenVolumeReadOnly);

		OptionsButtonLabel = OptionsButton->GetLabel();
		OptionsButton->SetLabel (OptionsButtonLabel + L" >");
		OptionsPanel->Show (false);

		ProtectionPasswordPanel = new VolumePasswordPanel (OptionsPanel, options.ProtectionPassword, options.ProtectionKeyfiles, false, true, true, false, false, _("P&assword to hidden volume:"));
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
		TransferDataFromWindow();

		Options.Password = PasswordPanel->GetPassword();
		Options.Keyfiles = PasswordPanel->GetKeyfiles();

		if (ReadOnlyCheckBox->IsChecked())
		{
			Options.Protection = VolumeProtection::ReadOnly;
		}
		else if (ProtectionCheckBox->IsChecked())
		{
			Options.Protection = VolumeProtection::HiddenVolumeReadOnly;
			Options.ProtectionPassword = ProtectionPasswordPanel->GetPassword();
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

		try
		{
			if (Options.Password)
				Options.Password->CheckPortability();
		}
		catch (UnportablePassword &)
		{
			Gui->ShowWarning (LangString ["UNSUPPORTED_CHARS_IN_PWD_RECOM"]);
		}

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
	}
}
