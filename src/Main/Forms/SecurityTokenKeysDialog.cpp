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

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Common/SecurityToken.h"
#include "NewSecurityTokenKeyfileDialog.h"
#include "SecurityTokenKeysDialog.h"
#include <sstream>

namespace VeraCrypt
{
	SecurityTokenKeysDialog::SecurityTokenKeysDialog (wxWindow* parent, SecurityTokenKeyOperation mode, bool selectionMode)
		: SecurityTokenKeysDialogBase (parent)
	{
		if (selectionMode)
			SetTitle (_("SELECT_TOKEN_KEYS"));

		list <int> colPermilles;

		SecurityTokenKeyListCtrl->InsertColumn (ColumnSecurityTokenSlotId, _("TOKEN_SLOT_ID"), wxLIST_FORMAT_CENTER, 1);
		colPermilles.push_back (102);
		SecurityTokenKeyListCtrl->InsertColumn (ColumnSecurityTokenLabel, _("TOKEN_NAME"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (368);
		SecurityTokenKeyListCtrl->InsertColumn (ColumnSecurityTokenKeyLabel, _("TOKEN_KEY_LABEL"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (529);

		KeyType keyType = KeyType::PUBLIC;
		if (mode == SecurityTokenKeyOperation::DECRYPT) {
			keyType = KeyType::PRIVATE;
		}
		FillSecurityTokenKeyListCtrl(keyType);

		Gui->SetListCtrlWidth (SecurityTokenKeyListCtrl, 65);
		Gui->SetListCtrlHeight (SecurityTokenKeyListCtrl, 16);
		Gui->SetListCtrlColumnWidths (SecurityTokenKeyListCtrl, colPermilles);

		Fit();
		Layout();
		Center();

		OKButton->SetDefault();
	}

	void SecurityTokenKeysDialog::FillSecurityTokenKeyListCtrl (KeyType keyType)
	{
		wxBusyCursor busy;

		SecurityTokenKeyListCtrl->DeleteAllItems();
		switch (keyType) {
			case KeyType::PRIVATE:
				SecurityTokenKeyList = SecurityToken::GetAvailablePrivateKeys();
				break;
			case KeyType::PUBLIC:
				SecurityTokenKeyList = SecurityToken::GetAvailablePublicKeys();
				break;
			default:
				throw_err("Unknown key type");
		}

		size_t i = 0;
		foreach (const SecurityTokenKey &key, SecurityTokenKeyList)
		{
			vector <wstring> fields (SecurityTokenKeyListCtrl->GetColumnCount());

			fields[ColumnSecurityTokenSlotId] = StringConverter::ToWide ((uint64) key.SlotId);
			fields[ColumnSecurityTokenLabel] = key.Token.Label;
			fields[ColumnSecurityTokenKeyLabel] = key.Id;

			Gui->AppendToListCtrl (SecurityTokenKeyListCtrl, fields, 0, &SecurityTokenKeyList[i++]); 
		}
		
	}

	
	void SecurityTokenKeysDialog::OnListItemDeselected (wxListEvent& event)
	{
	}

	void SecurityTokenKeysDialog::OnListItemSelected (wxListEvent& event)
	{
	}

	void SecurityTokenKeysDialog::OnOKButtonClick ()
	{
		foreach (long item, Gui->GetListCtrlSelectedItems (SecurityTokenKeyListCtrl))
		{
			SecurityTokenKey *key = reinterpret_cast <SecurityTokenKey *> (SecurityTokenKeyListCtrl->GetItemData (item));
			wstringstream ss;
			ss << key->SlotId << ":" << key->Id;
			SelectedSecurityTokenKeySpec = ss.str();
		}

		EndModal (wxID_OK);
	}
}
