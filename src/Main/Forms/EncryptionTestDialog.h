/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2015 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_EncryptionTestDialog
#define TC_HEADER_Main_Forms_EncryptionTestDialog

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class EncryptionTestDialog : public EncryptionTestDialogBase
	{
	public:
		EncryptionTestDialog (wxWindow* parent);

	protected:
		void EncryptOrDecrypt (bool encrypt);
		shared_ptr <EncryptionAlgorithm> GetSelectedEncryptionAlgorithm () const;
		void GetTextCtrlData (wxTextCtrl *textCtrl, Buffer &buffer) const;
		void OnAutoTestAllButtonClick (wxCommandEvent& event);
		void OnDecryptButtonClick (wxCommandEvent& event) { EncryptOrDecrypt (false); }
		void OnEncryptButtonClick (wxCommandEvent& event) { EncryptOrDecrypt (true); }
		void OnEncryptionAlgorithmSelected ();
		void OnEncryptionAlgorithmSelected (wxCommandEvent& event) { OnEncryptionAlgorithmSelected(); }
		void OnResetButtonClick (wxCommandEvent& event) { Reset(); }
		void OnXtsModeCheckBoxClick (wxCommandEvent& event);
		void SetTextCtrlData (wxTextCtrl *textCtrl, const BufferPtr &data);
		void Reset ();

		EncryptionAlgorithmList EncryptionAlgorithms;
	};
}

#endif // TC_HEADER_Main_Forms_EncryptionTestDialog
