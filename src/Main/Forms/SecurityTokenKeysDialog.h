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

#ifndef TC_HEADER_Main_Forms_SecurityTokenKeysDialog
#define TC_HEADER_Main_Forms_SecurityTokenKeysDialog

#include "Forms.h"
#include "Common/SecurityToken.h"
#include "Main/Main.h"

namespace VeraCrypt
{

	enum KeyType {
		PRIVATE,
		PUBLIC
	};

	class SecurityTokenKeysDialog : public SecurityTokenKeysDialogBase
	{
	public:
		SecurityTokenKeysDialog (wxWindow* parent, SecurityTokenKeyOperation mode, bool selectionMode = true);
		wstring GetSelectedSecurityTokenKeySpec() const { return SelectedSecurityTokenKeySpec; }

	protected:
		enum
		{
			ColumnSecurityTokenSlotId = 0,
			ColumnSecurityTokenLabel,
			ColumnSecurityTokenKeyLabel,
		};

		void FillSecurityTokenKeyListCtrl (KeyType keyType);
		void OnListItemActivated (wxListEvent& event) { OnOKButtonClick(); }
		void OnListItemDeselected (wxListEvent& event);
		void OnListItemSelected (wxListEvent& event);
		void OnOKButtonClick ();
		void OnOKButtonClick (wxCommandEvent& event) { OnOKButtonClick(); }

		vector <SecurityTokenKey> SecurityTokenKeyList;
		wstring SelectedSecurityTokenKeySpec;
	};
}

#endif // TC_HEADER_Main_Forms_SecurityTokenKeysDialog
