/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_ProgressWizardPage
#define TC_HEADER_Main_Forms_ProgressWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class ProgressWizardPage : public ProgressWizardPageBase
	{
	public:
		ProgressWizardPage (wxPanel* parent, bool enableAbort = false);
		~ProgressWizardPage () { }

		void EnableAbort (bool enable = true) { AbortButton->Enable (enable); }
		bool IsValid () { return true; }
		void SetMaxStaticTextWidth (int width);
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void SetProgressRange (uint64 progressBarRange);

		Event AbortEvent;
		SharedVal <uint64> ProgressValue;

	protected:
		void OnAbortButtonClick (wxCommandEvent& event);
		void OnTimer ();

		unique_ptr <wxTimer> mTimer;
		int PreviousGaugeValue;
		uint64 ProgressBarRange;
		int RealProgressBarRange;
	};
}

#endif // TC_HEADER_Main_Forms_ProgressWizardPage
