/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_InfoWizardPage
#define TC_HEADER_Main_Forms_InfoWizardPage

#include "Forms.h"

namespace TrueCrypt
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
