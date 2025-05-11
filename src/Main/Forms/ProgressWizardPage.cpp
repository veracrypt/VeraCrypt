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

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "ProgressWizardPage.h"

namespace VeraCrypt
{
	ProgressWizardPage::ProgressWizardPage (wxPanel* parent, bool enableAbort)
		: ProgressWizardPageBase (parent),
		PreviousGaugeValue (0),
		ProgressBarRange (1),
		RealProgressBarRange (1)
	{
#ifdef TC_MACOSX
		ProgressGauge->SetMinSize (wxSize (-1, 12)); // OS X apparently supports only up to 12px thick progress bars
#else
		ProgressGauge->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 2));
#endif

		ProgressValue.Set (0);
		ProgressGauge->SetValue (0);

		AbortButton->Show (enableAbort);

		class Timer : public wxTimer
		{
		public:
			Timer (ProgressWizardPage *page) : Page (page) { }

			void Notify()
			{
				Page->OnTimer();
			}

			ProgressWizardPage *Page;
		};

		mTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		mTimer->Start (30);
	}

	void ProgressWizardPage::OnAbortButtonClick (wxCommandEvent& event)
	{
		AbortEvent.Raise();
	}

	void ProgressWizardPage::OnTimer ()
	{
		uint64 value = ProgressValue.Get();
		int gaugeValue = static_cast <int> (value * RealProgressBarRange / ProgressBarRange);

		if (value == ProgressBarRange)
			gaugeValue = RealProgressBarRange; // Prevent round-off error

		if (gaugeValue != PreviousGaugeValue)
		{
			ProgressGauge->SetValue (gaugeValue);
			PreviousGaugeValue = gaugeValue;
		}
	}

	void ProgressWizardPage::SetMaxStaticTextWidth (int width)
	{
		InfoStaticText->Wrap (width);
	}

	void ProgressWizardPage::SetProgressRange (uint64 progressBarRange)
	{
		ProgressBarRange = progressBarRange;
		RealProgressBarRange = ProgressGauge->GetSize().GetWidth();
		ProgressGauge->SetRange (RealProgressBarRange);
	}
}
