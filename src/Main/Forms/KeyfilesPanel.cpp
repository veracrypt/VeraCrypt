/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "KeyfilesPanel.h"
#include "SecurityTokenKeyfilesDialog.h"

namespace TrueCrypt
{
	KeyfilesPanel::KeyfilesPanel (wxWindow* parent, shared_ptr <KeyfileList> keyfiles)
		: KeyfilesPanelBase (parent)
	{
		KeyfilesListCtrl->InsertColumn (0, LangString["KEYFILE"], wxLIST_FORMAT_LEFT, 1);
		Gui->SetListCtrlHeight (KeyfilesListCtrl, 10);

		Layout();
		Fit();

		if (keyfiles)
		{
			foreach_ref (const Keyfile &k, *keyfiles)
			{
				vector <wstring> fields;
				fields.push_back (FilesystemPath (k));
				Gui->AppendToListCtrl (KeyfilesListCtrl, fields);
			}
		}

		class FileDropTarget : public wxFileDropTarget
		{
		public:
			FileDropTarget (KeyfilesPanel *panel) : Panel (panel) { }

			wxDragResult OnDragOver (wxCoord x, wxCoord y, wxDragResult def)
			{
				return wxDragLink;
			}

			bool OnDropFiles (wxCoord x, wxCoord y, const wxArrayString &filenames)
			{
				foreach (const wxString &f, filenames)
					Panel->AddKeyfile (make_shared <Keyfile> (wstring (f)));
				return true;
			}

		protected:
			KeyfilesPanel *Panel;
		};

		SetDropTarget (new FileDropTarget (this));
		KeyfilesListCtrl->SetDropTarget (new FileDropTarget (this));
#ifdef TC_MACOSX
		foreach (wxWindow *c, GetChildren())
			c->SetDropTarget (new FileDropTarget (this));
#endif

		UpdateButtons();
	}

	void KeyfilesPanel::AddKeyfile (shared_ptr <Keyfile> keyfile)
	{
		vector <wstring> fields;
		fields.push_back (FilesystemPath (*keyfile));
		Gui->AppendToListCtrl (KeyfilesListCtrl, fields);
		UpdateButtons();
	}

	shared_ptr <KeyfileList> KeyfilesPanel::GetKeyfiles () const
	{
		make_shared_auto (KeyfileList, keyfiles);

		for (long i = 0; i < KeyfilesListCtrl->GetItemCount(); i++)
			keyfiles->push_back (make_shared <Keyfile> (wstring (KeyfilesListCtrl->GetItemText (i))));

		return keyfiles;
	}
	
	void KeyfilesPanel::OnAddDirectoryButtonClick (wxCommandEvent& event)
	{
		DirectoryPath dir = Gui->SelectDirectory (this, LangString["SELECT_KEYFILE_PATH"]);
		if (!dir.IsEmpty())
		{
			vector <wstring> fields;
			fields.push_back (dir);
			Gui->AppendToListCtrl (KeyfilesListCtrl, fields);
			UpdateButtons();
		}
	}

	void KeyfilesPanel::OnAddFilesButtonClick (wxCommandEvent& event)
	{
		FilePathList files = Gui->SelectFiles (this, LangString["SELECT_KEYFILES"], false, true);

		foreach_ref (const FilePath &f, files)
		{
			vector <wstring> fields;
			fields.push_back (f);
			Gui->AppendToListCtrl (KeyfilesListCtrl, fields);
		}
		UpdateButtons();
	}

	void KeyfilesPanel::OnAddSecurityTokenSignatureButtonClick (wxCommandEvent& event)
	{
		try
		{
			SecurityTokenKeyfilesDialog dialog (this);
			if (dialog.ShowModal() == wxID_OK)
			{
				foreach (const SecurityTokenKeyfilePath &path, dialog.GetSelectedSecurityTokenKeyfilePaths())
				{
					vector <wstring> fields;
					fields.push_back (path);
					Gui->AppendToListCtrl (KeyfilesListCtrl, fields);
				}

				UpdateButtons();
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void KeyfilesPanel::OnListSizeChanged (wxSizeEvent& event)
	{
		list <int> colPermilles;
		colPermilles.push_back (1000);
		Gui->SetListCtrlColumnWidths (KeyfilesListCtrl, colPermilles);
		event.Skip();
	}

	void KeyfilesPanel::OnRemoveAllButtonClick (wxCommandEvent& event)
	{
		KeyfilesListCtrl->DeleteAllItems();
		UpdateButtons();
	}

	void KeyfilesPanel::OnRemoveButtonClick (wxCommandEvent& event)
	{
		long offset = 0;
		foreach (long item, Gui->GetListCtrlSelectedItems (KeyfilesListCtrl))
			KeyfilesListCtrl->DeleteItem (item - offset++);

		UpdateButtons();
	}

	void KeyfilesPanel::UpdateButtons ()
	{
		RemoveAllButton->Enable (KeyfilesListCtrl->GetItemCount() > 0);
		RemoveButton->Enable (KeyfilesListCtrl->GetSelectedItemCount() > 0);
	}
}
