/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_PasswordPanel
#define TC_HEADER_Main_Forms_PasswordPanel

#include "Forms.h"
#include "Platform/Functor.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class VolumePasswordPanel : public VolumePasswordPanelBase
	{
	public:
		VolumePasswordPanel (wxWindow* parent, MountOptions* options, shared_ptr <VolumePassword> password, bool disableTruecryptMode, shared_ptr <KeyfileList> keyfiles, bool enableCache = false, bool enablePassword = true, bool enableKeyfiles = true, bool enableConfirmation = false, bool enablePkcs5Prf = false, bool isMountPassword = false, const wxString &passwordLabel = wxString());
		virtual ~VolumePasswordPanel ();

		void AddKeyfile (shared_ptr <Keyfile> keyfile);
		shared_ptr <KeyfileList> GetKeyfiles () const { return UseKeyfilesCheckBox->IsChecked() ? Keyfiles : shared_ptr <KeyfileList> (); }
		shared_ptr <VolumePassword> GetPassword () const;
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf (bool &bUnsupportedKdf) const;
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf (bool bTrueCryptMode, bool &bUnsupportedKdf) const;
		int GetVolumePim () const;
		bool GetTrueCryptMode () const;
		int GetHeaderWipeCount () const;
		void SetCacheCheckBoxValidator (const wxGenericValidator &validator) { CacheCheckBox->SetValidator (validator); }
		void SetFocusToPasswordTextCtrl () { PasswordTextCtrl->SetSelection (-1, -1); PasswordTextCtrl->SetFocus(); }
		void SetFocusToPimTextCtrl () { VolumePimTextCtrl->SetSelection (-1, -1); VolumePimTextCtrl->SetFocus(); }
		void SetVolumePim (int pim);
		bool PasswordsMatch () const;
		void EnableUsePim () { PimCheckBox->Enable (true); PimCheckBox->Show (true); }
		bool IsUsePimChecked () const { return PimCheckBox->GetValue (); }
		void SetUsePimChecked (bool checked) const { PimCheckBox->SetValue (checked); }
		bool UpdatePimHelpText (bool pimChanged);

		Event UpdateEvent;

	protected:
		void SetPimValidator ();
		void DisplayPassword (bool display, wxTextCtrl **textCtrl, int row);
		shared_ptr <VolumePassword> GetPassword (wxTextCtrl *textCtrl) const;
		void OnAddKeyfileDirMenuItemSelected (wxCommandEvent& event);
		void OnAddKeyfilesMenuItemSelected (wxCommandEvent& event);
		void OnAddSecurityTokenSignatureMenuItemSelected (wxCommandEvent& event);
		void OnDisplayPasswordCheckBoxClick (wxCommandEvent& event);
		void OnKeyfilesButtonClick (wxCommandEvent& event);
		void OnKeyfilesButtonRightClick (wxMouseEvent& event);
		void OnKeyfilesButtonRightDown (wxMouseEvent& event);
		void OnTextChanged (wxCommandEvent& event) { OnUpdate(); }
		void OnPimChanged  (wxCommandEvent& event) { OnUpdate(); }
		void OnUsePimCheckBoxClick( wxCommandEvent& event );
		void OnUpdate () { UpdateEvent.Raise(); }
		void OnUseKeyfilesCheckBoxClick (wxCommandEvent& event) { OnUpdate(); }
		void WipeTextCtrl (wxTextCtrl *textCtrl);
		void OnTrueCryptModeChecked( wxCommandEvent& event );

		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <Functor> UpdateCallback;
		bool EnablePimEntry;
	};
}

#endif // TC_HEADER_Main_Forms_PasswordPanel
