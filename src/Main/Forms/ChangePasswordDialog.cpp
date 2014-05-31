/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/Main.h"
#include "Main/GraphicUserInterface.h"
#include "ChangePasswordDialog.h"

namespace TrueCrypt
{
	ChangePasswordDialog::ChangePasswordDialog (wxWindow* parent, shared_ptr <VolumePath> volumePath, Mode::Enum mode, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles)
		: ChangePasswordDialogBase (parent), DialogMode (mode), Path (volumePath)
	{
		bool enableNewPassword = false;
		bool enableNewKeyfiles = false;
		bool enablePkcs5Prf = false;

		switch (mode)
		{
		case Mode::ChangePasswordAndKeyfiles:
			enableNewPassword = true;
			enableNewKeyfiles = true;
			enablePkcs5Prf = true;
			SetTitle (_("Change Volume Password and Keyfiles"));
			break;

		case Mode::ChangeKeyfiles:
			enableNewKeyfiles = true;
			SetTitle (_("Add/Remove Keyfiles to/from Volume"));
			break;

		case Mode::RemoveAllKeyfiles:
			SetTitle (_("Remove All Keyfiles from Volume"));
			break;

		case Mode::ChangePkcs5Prf:
			enablePkcs5Prf = true;
			SetTitle (_("Change Header Key Derivation Algorithm"));
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		CurrentPasswordPanel = new VolumePasswordPanel (this, password, keyfiles);
		CurrentPasswordPanel->UpdateEvent.Connect (EventConnector <ChangePasswordDialog> (this, &ChangePasswordDialog::OnPasswordPanelUpdate));
		CurrentPasswordPanelSizer->Add (CurrentPasswordPanel, 1, wxALL | wxEXPAND);

		NewPasswordPanel = new VolumePasswordPanel (this, newPassword, newKeyfiles, false, enableNewPassword, enableNewKeyfiles, enableNewPassword, enablePkcs5Prf);
		NewPasswordPanel->UpdateEvent.Connect (EventConnector <ChangePasswordDialog> (this, &ChangePasswordDialog::OnPasswordPanelUpdate));
		NewPasswordPanelSizer->Add (NewPasswordPanel, 1, wxALL | wxEXPAND);
		
		if (mode == Mode::RemoveAllKeyfiles)
			NewSizer->Show (false);

		Layout();
		Fit();
		Center();

		OnPasswordPanelUpdate();
		CurrentPasswordPanel->SetFocusToPasswordTextCtrl();
	}

	ChangePasswordDialog::~ChangePasswordDialog ()
	{
		CurrentPasswordPanel->UpdateEvent.Disconnect (this);
		NewPasswordPanel->UpdateEvent.Disconnect (this);
	}

	void ChangePasswordDialog::OnOKButtonClick (wxCommandEvent& event)
	{
		// Avoid a GTK bug
		if (!OKButton->IsEnabled())
			return;

		try
		{
			shared_ptr <VolumePassword> newPassword;
			if (DialogMode == Mode::ChangePasswordAndKeyfiles)
			{
				newPassword = NewPasswordPanel->GetPassword();
				newPassword->CheckPortability();

				if (newPassword->Size() > 0 && newPassword->Size() < VolumePassword::WarningSizeThreshold
					&& !Gui->AskYesNo (LangString ["PASSWORD_LENGTH_WARNING"], false, true))
				{
					NewPasswordPanel->SetFocusToPasswordTextCtrl();
					return;
				}
			}
			else
				newPassword = CurrentPasswordPanel->GetPassword();

			shared_ptr <KeyfileList> newKeyfiles;
			if (DialogMode == Mode::ChangePasswordAndKeyfiles || DialogMode == Mode::ChangeKeyfiles)
				newKeyfiles = NewPasswordPanel->GetKeyfiles();
			else if (DialogMode != Mode::RemoveAllKeyfiles)
				newKeyfiles = CurrentPasswordPanel->GetKeyfiles();

			Gui->UserEnrichRandomPool (this, NewPasswordPanel->GetPkcs5Kdf() ? NewPasswordPanel->GetPkcs5Kdf()->GetHash() : shared_ptr <Hash>());

			{
#ifdef TC_UNIX
				// Temporarily take ownership of a device if the user is not an administrator
				UserId origDeviceOwner ((uid_t) -1);

				if (!Core->HasAdminPrivileges() && Path->IsDevice())
				{
					origDeviceOwner = FilesystemPath (wstring (*Path)).GetOwner();
					Core->SetFileOwner (*Path, UserId (getuid()));
				}

				finally_do_arg2 (FilesystemPath, *Path, UserId, origDeviceOwner,
				{
					if (finally_arg2.SystemId != (uid_t) -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				});
#endif
				wxBusyCursor busy;
				Core->ChangePassword (Path,	Gui->GetPreferences().DefaultMountOptions.PreserveTimestamps,
					CurrentPasswordPanel->GetPassword(), CurrentPasswordPanel->GetKeyfiles(),
					newPassword, newKeyfiles, NewPasswordPanel->GetPkcs5Kdf());
			}

			switch (DialogMode)
			{
			case Mode::ChangePasswordAndKeyfiles:
				Gui->ShowInfo ("PASSWORD_CHANGED");
				break;

			case Mode::ChangeKeyfiles:
			case Mode::RemoveAllKeyfiles:
				Gui->ShowInfo ("KEYFILE_CHANGED");
				break;

			case Mode::ChangePkcs5Prf:
				Gui->ShowInfo ("PKCS5_PRF_CHANGED");
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}

			EndModal (wxID_OK);
		}
		catch (UnportablePassword &e)
		{
			Gui->ShowError (e);
			NewPasswordPanel->SetFocusToPasswordTextCtrl();
		}
		catch (PasswordException &e)
		{
			Gui->ShowWarning (e);
			CurrentPasswordPanel->SetFocusToPasswordTextCtrl();
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void ChangePasswordDialog::OnPasswordPanelUpdate ()
	{
		bool ok = true;

		bool passwordEmpty = CurrentPasswordPanel->GetPassword()->IsEmpty();
		bool keyfilesEmpty = !CurrentPasswordPanel->GetKeyfiles() || CurrentPasswordPanel->GetKeyfiles()->empty();

		if (passwordEmpty && keyfilesEmpty)
			ok = false;

		if (DialogMode == Mode::RemoveAllKeyfiles && (passwordEmpty || keyfilesEmpty))
			ok = false;

		if (DialogMode == Mode::ChangePasswordAndKeyfiles || DialogMode == Mode::ChangeKeyfiles)
		{
			bool newKeyfilesEmpty = !NewPasswordPanel->GetKeyfiles() || NewPasswordPanel->GetKeyfiles()->empty();

			if (DialogMode == Mode::ChangeKeyfiles
				&& ((passwordEmpty && newKeyfilesEmpty) || (keyfilesEmpty && newKeyfilesEmpty)))
				ok = false;

			if (DialogMode == Mode::ChangePasswordAndKeyfiles
				&& ((NewPasswordPanel->GetPassword()->IsEmpty() && newKeyfilesEmpty) || !NewPasswordPanel->PasswordsMatch()))
				ok = false;
		}

		OKButton->Enable (ok);
	}
}
