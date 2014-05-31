/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Common/SecurityToken.h"
#include "NewSecurityTokenKeyfileDialog.h"
#include "SecurityTokenKeyfilesDialog.h"

namespace TrueCrypt
{
	SecurityTokenKeyfilesDialog::SecurityTokenKeyfilesDialog (wxWindow* parent, bool selectionMode)
		: SecurityTokenKeyfilesDialogBase (parent)
	{
		if (selectionMode)
			SetTitle (LangString["SELECT_TOKEN_KEYFILES"]);

		list <int> colPermilles;

		SecurityTokenKeyfileListCtrl->InsertColumn (ColumnSecurityTokenSlotId, LangString["TOKEN_SLOT_ID"], wxLIST_FORMAT_CENTER, 1);
		colPermilles.push_back (102);
		SecurityTokenKeyfileListCtrl->InsertColumn (ColumnSecurityTokenLabel, LangString["TOKEN_NAME"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (368);
		SecurityTokenKeyfileListCtrl->InsertColumn (ColumnSecurityTokenKeyfileLabel, LangString["TOKEN_DATA_OBJECT_LABEL"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (529);

		FillSecurityTokenKeyfileListCtrl();

		Gui->SetListCtrlWidth (SecurityTokenKeyfileListCtrl, 65);
		Gui->SetListCtrlHeight (SecurityTokenKeyfileListCtrl, 16);
		Gui->SetListCtrlColumnWidths (SecurityTokenKeyfileListCtrl, colPermilles);

		Fit();
		Layout();
		Center();

		DeleteButton->Disable();
		ExportButton->Disable();
		OKButton->Disable();
		OKButton->SetDefault();
	}

	void SecurityTokenKeyfilesDialog::FillSecurityTokenKeyfileListCtrl ()
	{
		wxBusyCursor busy;

		SecurityTokenKeyfileListCtrl->DeleteAllItems();
		SecurityTokenKeyfileList = SecurityToken::GetAvailableKeyfiles();

		size_t i = 0;
		foreach (const SecurityTokenKeyfile &key, SecurityTokenKeyfileList)
		{
			vector <wstring> fields (SecurityTokenKeyfileListCtrl->GetColumnCount());

			fields[ColumnSecurityTokenSlotId] = StringConverter::ToWide ((uint64) key.SlotId);
			fields[ColumnSecurityTokenLabel] = key.Token.Label;
			fields[ColumnSecurityTokenKeyfileLabel] = key.Id;

			Gui->AppendToListCtrl (SecurityTokenKeyfileListCtrl, fields, 0, &SecurityTokenKeyfileList[i++]); 
		}
	}

	void SecurityTokenKeyfilesDialog::OnDeleteButtonClick (wxCommandEvent& event)
	{
		try
		{
			if (!Gui->AskYesNo (LangString["CONFIRM_SEL_FILES_DELETE"]))
				return;

			wxBusyCursor busy;

			foreach (long item, Gui->GetListCtrlSelectedItems (SecurityTokenKeyfileListCtrl))
			{
				SecurityToken::DeleteKeyfile (*reinterpret_cast <SecurityTokenKeyfile *> (SecurityTokenKeyfileListCtrl->GetItemData (item)));
			}

			FillSecurityTokenKeyfileListCtrl();
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void SecurityTokenKeyfilesDialog::OnExportButtonClick (wxCommandEvent& event)
	{
		try
		{
			foreach (long item, Gui->GetListCtrlSelectedItems (SecurityTokenKeyfileListCtrl))
			{
				SecurityTokenKeyfile *keyfile = reinterpret_cast <SecurityTokenKeyfile *> (SecurityTokenKeyfileListCtrl->GetItemData (item));

				FilePathList files = Gui->SelectFiles (this, wxEmptyString, true);

				if (!files.empty())
				{
					wxBusyCursor busy;

					vector <byte> keyfileData;
					SecurityToken::GetKeyfileData (*keyfile, keyfileData);

					BufferPtr keyfileDataBuf (&keyfileData.front(), keyfileData.size());
					finally_do_arg (BufferPtr, keyfileDataBuf, { finally_arg.Erase(); });

					File keyfile;
					keyfile.Open (*files.front(), File::CreateWrite);
					keyfile.Write (keyfileDataBuf);
				}
				else
					break;

				Gui->ShowInfo ("KEYFILE_EXPORTED");
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void SecurityTokenKeyfilesDialog::OnImportButtonClick (wxCommandEvent& event)
	{
		try
		{
			FilePathList keyfilePaths = Gui->SelectFiles (this, LangString["SELECT_KEYFILES"], false);

			if (keyfilePaths.empty())
				return;

			FilePath keyfilePath = *keyfilePaths.front();

			File keyfile;
			keyfile.Open (keyfilePath, File::OpenRead, File::ShareReadWrite, File::PreserveTimestamps);

			if (keyfile.Length() > 0)
			{
				vector <byte> keyfileData (keyfile.Length());
				BufferPtr keyfileDataBuf (&keyfileData.front(), keyfileData.size());

				keyfile.ReadCompleteBuffer (keyfileDataBuf);
				finally_do_arg (BufferPtr, keyfileDataBuf, { finally_arg.Erase(); });

				NewSecurityTokenKeyfileDialog newKeyfileDialog (this, keyfilePath.ToBaseName());

				if (newKeyfileDialog.ShowModal() == wxID_OK)
				{
					wxBusyCursor busy;
					SecurityToken::CreateKeyfile (newKeyfileDialog.GetSelectedSlotId(), keyfileData, StringConverter::ToSingle (newKeyfileDialog.GetKeyfileName()));
					
					FillSecurityTokenKeyfileListCtrl();
				}
			}
			else
				throw InsufficientData (SRC_POS, keyfilePath);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void SecurityTokenKeyfilesDialog::OnListItemDeselected (wxListEvent& event)
	{
		if (SecurityTokenKeyfileListCtrl->GetSelectedItemCount() == 0)
		{
			DeleteButton->Disable();
			ExportButton->Disable();
			OKButton->Disable();
		}
	}

	void SecurityTokenKeyfilesDialog::OnListItemSelected (wxListEvent& event)
	{
		if (event.GetItem().GetData() != (wxUIntPtr) nullptr)
		{
			DeleteButton->Enable();
			ExportButton->Enable();
			OKButton->Enable();
		}
	}

	void SecurityTokenKeyfilesDialog::OnOKButtonClick ()
	{
		foreach (long item, Gui->GetListCtrlSelectedItems (SecurityTokenKeyfileListCtrl))
		{
			SecurityTokenKeyfile *key = reinterpret_cast <SecurityTokenKeyfile *> (SecurityTokenKeyfileListCtrl->GetItemData (item));
			SelectedSecurityTokenKeyfilePaths.push_back (*key);
		}

		EndModal (wxID_OK);
	}
}
