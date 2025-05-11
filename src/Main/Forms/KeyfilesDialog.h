/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_KeyfilesDialog
#define TC_HEADER_Main_Forms_KeyfilesDialog

#include "Forms.h"
#include "Main/Main.h"
#include "KeyfilesPanel.h"

namespace VeraCrypt
{
	class KeyfilesDialog : public KeyfilesDialogBase
	{
	public:
		KeyfilesDialog (wxWindow* parent, shared_ptr <KeyfileList> keyfiles);
		shared_ptr <KeyfileList> GetKeyfiles () const { return mKeyfilesPanel->GetKeyfiles(); }

	protected:
		void OnCreateKeyfileButttonClick (wxCommandEvent& event);
		void OnKeyfilesHyperlinkClick (wxHyperlinkEvent& event);

		shared_ptr <KeyfileList> Keyfiles;
		KeyfilesPanel *mKeyfilesPanel;
	};
}

#endif // TC_HEADER_Main_Forms_KeyfilesDialog
