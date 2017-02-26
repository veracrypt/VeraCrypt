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

#ifndef TC_HEADER_Main_Forms_WizardPage
#define TC_HEADER_Main_Forms_WizardPage

#include "Main/Main.h"

namespace VeraCrypt
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
