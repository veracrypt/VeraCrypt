/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 with contributions Copyright (c) 2024-2025 Anton Dubenchuk
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Common/SecurityToken.h"
#include "SecurityTokenSchemesDialog.h"
#include <sstream>

namespace VeraCrypt
{
	SecurityTokenSchemesDialog::SecurityTokenSchemesDialog (wxWindow* parent, SecurityTokenKeyOperation mode, bool selectionMode)
		: SecurityTokenSchemesDialogBase (parent)
	{
		if (selectionMode)
			SetTitle (_("SELECT_TOKEN_KEYS"));

		list <int> colPermilles;

		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenSlotId, _("TOKEN_SLOT_ID"), wxLIST_FORMAT_CENTER, 1);
		colPermilles.push_back (80);
		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenLabel, _("TOKEN_NAME"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (170);
		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenKeyLabel, _("TOKEN_KEY_LABEL"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (200);
		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenMechanismLabel, _("TOKEN_KEY_MECHANISM_LABEL"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (270);
		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenKeyId, LangString["TOKEN_KEY_ID"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (160);
		SecurityTokenSchemeListCtrl->InsertColumn (ColumnSecurityTokenKeySize, LangString["TOKEN_KEY_SIZE"], wxLIST_FORMAT_RIGHT, 1);
		colPermilles.push_back (120);


		KeyType keyType = KeyType::Public;
		if (mode == SecurityTokenKeyOperation::Decrypt) {
			keyType = KeyType::Private;
		}
		FillSecurityTokenSchemesListCtrl(keyType);

		Gui->SetListCtrlWidth (SecurityTokenSchemeListCtrl, 95);
		Gui->SetListCtrlHeight (SecurityTokenSchemeListCtrl, 16);
		Gui->SetListCtrlColumnWidths (SecurityTokenSchemeListCtrl, colPermilles);

		Fit();
		Layout();
		Center();

		OKButton->Enable (false);
		OKButton->SetDefault();
	}

	void SecurityTokenSchemesDialog::FillSecurityTokenSchemesListCtrl (KeyType keyType)
	{
		wxBusyCursor busy;

		SecurityTokenSchemeListCtrl->DeleteAllItems();
		switch (keyType) {
			case KeyType::Private:
				SecurityTokenSchemeList = SecurityToken::GetAvailablePrivateKeys();
				break;
			case KeyType::Public:
				SecurityTokenSchemeList = SecurityToken::GetAvailablePublicKeys();
				break;
			default:
				throw_err("Unknown key type");
		}

		size_t i = 0;
		foreach (const SecurityTokenScheme &scheme, SecurityTokenSchemeList)
		{
			vector <wstring> fields (SecurityTokenSchemeListCtrl->GetColumnCount());

			fields[ColumnSecurityTokenSlotId] = StringConverter::ToWide ((uint64) scheme.SlotId);
			fields[ColumnSecurityTokenLabel] = scheme.Token.Label;
			fields[ColumnSecurityTokenKeyLabel] = scheme.Id;
			fields[ColumnSecurityTokenMechanismLabel] = scheme.MechanismLabel;
			wxString id;
			foreach (uint8 value, scheme.ObjectId) id += wxString::Format (L"%02x", static_cast<unsigned int> (value));
			fields[ColumnSecurityTokenKeyId] = id.ToStdWstring();
			fields[ColumnSecurityTokenKeySize] = StringConverter::ToWide (static_cast<uint64> (scheme.RsaKeyBits));

			Gui->AppendToListCtrl (SecurityTokenSchemeListCtrl, fields, 0, &SecurityTokenSchemeList[i++]); 
		}
		
	}

	
	void SecurityTokenSchemesDialog::OnListItemDeselected (wxListEvent& event)
	{
		OKButton->Enable (SecurityTokenSchemeListCtrl->GetSelectedItemCount() == 1);
	}

	void SecurityTokenSchemesDialog::OnListItemSelected (wxListEvent& event)
	{
		OKButton->Enable (SecurityTokenSchemeListCtrl->GetSelectedItemCount() == 1);
	}

	void SecurityTokenSchemesDialog::OnOKButtonClick ()
	{
		if (SecurityTokenSchemeListCtrl->GetSelectedItemCount() != 1)
			return;

		foreach (long item, Gui->GetListCtrlSelectedItems (SecurityTokenSchemeListCtrl))
		{
			SecurityTokenScheme *key = reinterpret_cast <SecurityTokenScheme *> (SecurityTokenSchemeListCtrl->GetItemData (item));
			bool useSlot = false;
			foreach (const SecurityTokenScheme &candidate, SecurityTokenSchemeList)
				if (candidate.SlotId != key->SlotId && candidate.Token.SerialNumber == key->Token.SerialNumber
					&& candidate.ObjectId == key->ObjectId)
					useSlot = true;
			SelectedSecurityTokenSchemeSpec = key->GetSpec (useSlot);
		}

		EndModal (wxID_OK);
	}
}
