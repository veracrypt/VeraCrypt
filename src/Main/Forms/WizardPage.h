/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_WizardPage
#define TC_HEADER_Main_Forms_WizardPage

#include "Main/Main.h"

namespace TrueCrypt
{
	class WizardPage : public wxPanel
	{
	public:
		WizardPage (wxWindow *parent, wxWindowID id, const wxPoint &pos, const wxSize &size, long style)
			: wxPanel (parent, id, pos, size, style)
		{ }
		virtual ~WizardPage () { }

		wxString GetPageTitle () const { return PageTitle; }
		virtual bool IsValid () = 0;
		virtual void OnPageChanging (bool forward) { }
		wxString GetNextButtonText () const { return NextButtonText; }
		void SetNextButtonText (const wxString &text) { NextButtonText = text; }
		virtual void SetMaxStaticTextWidth (int width) { }
		void SetPageTitle (const wxString &title) { PageTitle = title; }
		virtual void SetPageText (const wxString &text) = 0;

		Event PageUpdatedEvent;

	protected:
		wxString PageTitle;
		wxString NextButtonText;
	};
}

#endif // TC_HEADER_Main_Forms_WizardPage
