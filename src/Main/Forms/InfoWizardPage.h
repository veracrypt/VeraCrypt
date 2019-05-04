/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_InfoWizardPage
#define TC_HEADER_Main_Forms_InfoWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class InfoWizardPage : public InfoWizardPageBase
	{
	public:
		InfoWizardPage (wxPanel *parent, const wxString &actionButtonText = wxEmptyString, shared_ptr <Functor> actionFunctor = shared_ptr <Functor> ());

		bool IsValid () { return true; }
		void SetMaxStaticTextWidth (int width);
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }

	protected:
		virtual void OnActionButtonClick (wxCommandEvent& event) { (*ActionFunctor)(); }

		shared_ptr <Functor> ActionFunctor;
	};
}

#endif // TC_HEADER_Main_Forms_InfoWizardPage
