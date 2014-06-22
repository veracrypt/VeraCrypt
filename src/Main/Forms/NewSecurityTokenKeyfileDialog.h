/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_NewSecurityTokenKeyfileDialog
#define TC_HEADER_Main_Forms_NewSecurityTokenKeyfileDialog

#include "Forms.h"
#include "Common/SecurityToken.h"

namespace VeraCrypt
{
	class NewSecurityTokenKeyfileDialog : public NewSecurityTokenKeyfileDialogBase
	{
	public:
		NewSecurityTokenKeyfileDialog (wxWindow* parent, const wstring &keyfileName);

		wstring GetKeyfileName () const { return wstring (KeyfileNameTextCtrl->GetValue()); }
		CK_SLOT_ID GetSelectedSlotId () const { return reinterpret_cast <CK_SLOT_ID> (SecurityTokenChoice->GetClientData (SecurityTokenChoice->GetSelection())); }

	protected:
		void OnKeyfileNameChanged (wxCommandEvent& event);
	};
}

#endif // TC_HEADER_Main_Forms_NewSecurityTokenKeyfileDialog
