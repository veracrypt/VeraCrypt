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

#ifndef TC_HEADER_Main_Forms_SelectDirectoryWizardPage
#define TC_HEADER_Main_Forms_SelectDirectoryWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class SelectDirectoryWizardPage : public SelectDirectoryWizardPageBase
	{
	public:
		SelectDirectoryWizardPage (wxPanel* parent) : SelectDirectoryWizardPageBase (parent) { }

		DirectoryPath GetDirectory () const { return DirectoryPath (DirectoryTextCtrl->GetValue().wc_str()); }
		bool IsValid ();
		void SetDirectory (const DirectoryPath &path) { DirectoryTextCtrl->SetValue (wstring (path)); }
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }

	protected:
		void OnBrowseButtonClick (wxCommandEvent& event);
		void OnDirectoryTextChanged (wxCommandEvent& event) { PageUpdatedEvent.Raise(); }
	};
}

#endif // TC_HEADER_Main_Forms_SelectDirectoryWizardPage
