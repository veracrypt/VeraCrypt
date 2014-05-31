/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_ProgressWizardPage
#define TC_HEADER_Main_Forms_ProgressWizardPage

#include "Forms.h"

namespace TrueCrypt
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

		auto_ptr <wxTimer> mTimer;
		int PreviousGaugeValue;
		uint64 ProgressBarRange;
		int RealProgressBarRange;
	};
}

#endif // TC_HEADER_Main_Forms_ProgressWizardPage
