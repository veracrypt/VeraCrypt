/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
