/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
		VolumePasswordPanel (wxWindow* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableCache = false, bool enablePassword = true, bool enableKeyfiles = true, bool enableConfirmation = false, bool enablePkcs5Prf = false, const wxString &passwordLabel = wxString());
		virtual ~VolumePasswordPanel ();

		void AddKeyfile (shared_ptr <Keyfile> keyfile);
		shared_ptr <KeyfileList> GetKeyfiles () const { return UseKeyfilesCheckBox->IsChecked() ? Keyfiles : shared_ptr <KeyfileList> (); }
		shared_ptr <VolumePassword> GetPassword () const;
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf () const;
		int GetHeaderWipeCount () const;
		void SetCacheCheckBoxValidator (const wxGenericValidator &validator) { CacheCheckBox->SetValidator (validator); }
		void SetFocusToPasswordTextCtrl () { PasswordTextCtrl->SetSelection (-1, -1); PasswordTextCtrl->SetFocus(); }
		bool PasswordsMatch () const;

		Event UpdateEvent;

	protected:
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
		void OnUpdate () { UpdateEvent.Raise(); }
		void OnUseKeyfilesCheckBoxClick (wxCommandEvent& event) { OnUpdate(); }
		void WipeTextCtrl (wxTextCtrl *textCtrl);

		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <Functor> UpdateCallback;
	};
}

#endif // TC_HEADER_Main_Forms_PasswordPanel
