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

#ifndef TC_HEADER_Main_Forms_SecurityTokenKeyfilesDialog
#define TC_HEADER_Main_Forms_SecurityTokenKeyfilesDialog

#include "Forms.h"
#include "Common/SecurityToken.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class SecurityTokenKeyfilesDialog : public SecurityTokenKeyfilesDialogBase
	{
	public:
		SecurityTokenKeyfilesDialog (wxWindow* parent, bool selectionMode = true);
		list <SecurityTokenKeyfilePath> GetSelectedSecurityTokenKeyfilePaths() const { return SelectedSecurityTokenKeyfilePaths; }

	protected:
		enum
		{
			ColumnSecurityTokenSlotId = 0,
			ColumnSecurityTokenLabel,
			ColumnSecurityTokenKeyfileLabel,
		};

		void FillSecurityTokenKeyfileListCtrl ();
		void OnDeleteButtonClick (wxCommandEvent& event);
		void OnExportButtonClick (wxCommandEvent& event);
		void OnImportButtonClick (wxCommandEvent& event);
		void OnListItemActivated (wxListEvent& event) { OnOKButtonClick(); }
		void OnListItemDeselected (wxListEvent& event);
		void OnListItemSelected (wxListEvent& event);
		void OnOKButtonClick ();
		void OnOKButtonClick (wxCommandEvent& event) { OnOKButtonClick(); }

		vector <SecurityTokenKeyfile> SecurityTokenKeyfileList;
		list <SecurityTokenKeyfilePath> SelectedSecurityTokenKeyfilePaths;
	};
}

#endif // TC_HEADER_Main_Forms_SecurityTokenKeyfilesDialog
