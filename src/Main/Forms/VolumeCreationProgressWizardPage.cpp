/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumeCreationProgressWizardPage.h"

namespace TrueCrypt
{
	VolumeCreationProgressWizardPage::VolumeCreationProgressWizardPage (wxPanel* parent, bool displayKeyInfo)
		: VolumeCreationProgressWizardPageBase (parent),
		PreviousGaugeValue (0),
		ProgressBarRange (1),
		RealProgressBarRange (1),
		VolumeCreatorRunning (false)
	{
		DisplayKeysCheckBox->SetValue (displayKeyInfo);
#ifdef TC_WINDOWS
		DisplayKeysCheckBox->SetLabel (L"");
#endif

#ifdef TC_MACOSX
		ProgressGauge->SetMinSize (wxSize (-1, 12)); // OS X apparently supports only up to 12px thick progress bars
		KeySamplesUpperSizer->Remove (KeySamplesUpperInnerSizer);
#else
		ProgressGauge->SetMinSize (wxSize (-1, Gui->GetCharHeight (this) * 2));
#endif

		if (DisplayKeysCheckBox->IsChecked())
			ShowBytes (RandomPoolSampleStaticText, RandomNumberGenerator::PeekPool(), true);
		else
			ShowAsterisks (RandomPoolSampleStaticText);

		class Timer : public wxTimer
		{
		public:
			Timer (VolumeCreationProgressWizardPage *page) : Page (page) { }

			void Notify()
			{
				Page->OnRandomPoolTimer();
			}

			VolumeCreationProgressWizardPage *Page;
		}; 

		RandomPoolTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		RandomPoolTimer->Start (30);

		AbortButton->Disable();
		ProgressGauge->SetValue (0);

	}

	void VolumeCreationProgressWizardPage::OnAbortButtonClick (wxCommandEvent& event)
	{
		AbortEvent.Raise();
	}

	void VolumeCreationProgressWizardPage::OnDisplayKeysCheckBoxClick (wxCommandEvent& event)
	{
		if (!event.IsChecked())
		{
			ShowAsterisks (RandomPoolSampleStaticText); 
			ShowAsterisks (HeaderKeySampleStaticText); 
			ShowAsterisks (MasterKeySampleStaticText); 
		}
		else
		{
			RandomPoolSampleStaticText->SetLabel (L"");
			HeaderKeySampleStaticText->SetLabel (L"");
			MasterKeySampleStaticText->SetLabel (L"");
		}
	}
	
	void VolumeCreationProgressWizardPage::OnRandomPoolTimer ()
	{
		if (!VolumeCreatorRunning && DisplayKeysCheckBox->IsChecked())
			ShowBytes (RandomPoolSampleStaticText, RandomNumberGenerator::PeekPool(), true);
	}

	void VolumeCreationProgressWizardPage::SetKeyInfo (const VolumeCreator::KeyInfo &keyInfo)
	{
		if (DisplayKeysCheckBox->IsChecked())
		{
			ShowBytes (RandomPoolSampleStaticText, RandomNumberGenerator::PeekPool(), true);
			ShowBytes (HeaderKeySampleStaticText, keyInfo.HeaderKey);
			ShowBytes (MasterKeySampleStaticText, keyInfo.MasterKey);
		}
	}

	void VolumeCreationProgressWizardPage::ShowAsterisks (wxStaticText *textCtrl)
	{
		wxString str;
		for (size_t i = 0; i < MaxDisplayedKeyBytes + 1; ++i)
		{
			str += L"**";
		}

		textCtrl->SetLabel (str.c_str());
	}

	void VolumeCreationProgressWizardPage::ShowBytes (wxStaticText *textCtrl, const ConstBufferPtr &buffer, bool appendDots)
	{
		wxString str;

		for (size_t i = 0; i < MaxDisplayedKeyBytes && i < buffer.Size(); ++i)
		{
			str += wxString::Format (L"%02X", buffer[i]);
		}

		if (appendDots)
			str += L"..";

		textCtrl->SetLabel (str.c_str());

		for (size_t i = 0; i < str.size(); ++i)
		{
			str[i] = L'X';
		}
	}

	void VolumeCreationProgressWizardPage::SetProgressValue (uint64 value)
	{
		int gaugeValue = static_cast <int> (value * RealProgressBarRange / ProgressBarRange);

		if (value == ProgressBarRange)
			gaugeValue = RealProgressBarRange; // Prevent round-off error

		if (gaugeValue != PreviousGaugeValue)
		{
			ProgressGauge->SetValue (gaugeValue);
			PreviousGaugeValue = gaugeValue;
		}

		if (value != 0)
		{
			SizeDoneStaticText->SetLabel (wxString::Format (L"%7.3f%%", 100.0 - double (ProgressBarRange - value) / (double (ProgressBarRange) / 100.0)));

			wxLongLong timeDiff = wxGetLocalTimeMillis() - StartTime;
			if (timeDiff.GetValue() > 0)
			{
				uint64 speed = value * 1000 / timeDiff.GetValue();

				if (ProgressBarRange != value)
					SpeedStaticText->SetLabel (Gui->SpeedToString (speed));

				TimeLeftStaticText->SetLabel (speed > 0 ? Gui->TimeSpanToString ((ProgressBarRange - value) / speed) : L"");
			}
		}
		else
		{
			SizeDoneStaticText->SetLabel (L"");
			SpeedStaticText->SetLabel (L"");
			TimeLeftStaticText->SetLabel (L"");
		}
	}

	void VolumeCreationProgressWizardPage::SetMaxStaticTextWidth (int width)
	{
		InfoStaticText->Wrap (width);
	}

	void VolumeCreationProgressWizardPage::SetProgressState (bool volumeCreatorRunning)
	{
		if (volumeCreatorRunning)
			StartTime = wxGetLocalTimeMillis();

		VolumeCreatorRunning = volumeCreatorRunning;
	}

	void VolumeCreationProgressWizardPage::SetProgressRange (uint64 progressBarRange)
	{
		ProgressBarRange = progressBarRange;
		RealProgressBarRange = ProgressGauge->GetSize().GetWidth();
		ProgressGauge->SetRange (RealProgressBarRange);
	}
}
