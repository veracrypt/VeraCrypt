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

#ifndef TC_HEADER_Main_Forms_KeyfilesPanel
#define TC_HEADER_Main_Forms_KeyfilesPanel

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class KeyfilesPanel : public KeyfilesPanelBase
	{
	public:
		KeyfilesPanel (wxWindow* parent, shared_ptr <KeyfileList> keyfiles);
		void AddKeyfile (shared_ptr <Keyfile> keyfile);
		shared_ptr <KeyfileList> GetKeyfiles () const;

	protected:
		void OnAddFilesButtonClick (wxCommandEvent& event);
		void OnAddDirectoryButtonClick (wxCommandEvent& event);
		void OnAddSecurityTokenSignatureButtonClick (wxCommandEvent& event);
		void OnListItemDeselected (wxListEvent& event) { UpdateButtons(); }
		void OnListItemSelected (wxListEvent& event) { UpdateButtons(); }
		void OnListSizeChanged (wxSizeEvent& event);
		void OnRemoveButtonClick (wxCommandEvent& event);
		void OnRemoveAllButtonClick (wxCommandEvent& event);
		void UpdateButtons ();
	};
}

#endif // TC_HEADER_Main_Forms_KeyfilesPanel
