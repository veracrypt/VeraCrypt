/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Main/Resources.h"
#include "WizardFrame.h"

namespace TrueCrypt
{
	WizardFrame::WizardFrame (wxWindow* parent)
		: WizardFrameBase (parent),
		CurrentPage (nullptr),
		CurrentStep (-1),
		MaxStaticTextWidth (-1),
		WorkInProgress (false)
	{
		SetIcon (Resources::GetTrueCryptIcon());

		PageTitleStaticText->SetFont (wxFont (
#ifdef TC_WINDOWS
			16
#elif defined(TC_MACOSX)
			18
#elif defined(__WXGTK__)
			14
#endif
			* Gui->GetCharHeight (this) / 13, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, L"Times New Roman"));

		UpdateControls();
		this->SetDefaultItem (NextButton);
		NextButton->SetFocus();

		foreach (wxWindow *c, MainPanel->GetChildren())
			c->Connect (wxEVT_MOTION, wxMouseEventHandler (WizardFrame::OnMouseMotion), nullptr, this);
	}

	WizardFrame::~WizardFrame ()
	{
		if (CurrentPage)
			CurrentPage->Destroy();
	}

	void WizardFrame::ClearHistory ()
	{
		StepHistory.clear();
		UpdateControls();
	}

	void WizardFrame::OnActivate (wxActivateEvent& event)
	{
		Gui->SetActiveFrame (this);
		event.Skip();
	}
	
	void WizardFrame::OnClose (wxCloseEvent& event)
	{
		if (WorkInProgress)
			return;

		Gui->SetActiveFrame (nullptr);
		event.Skip();
	}

	void WizardFrame::OnHelpButtonClick (wxCommandEvent& event)
	{
		Gui->OpenUserGuide (this);
	}

	void WizardFrame::OnNextButtonClick (wxCommandEvent& event)
	{
		if (CurrentPage->IsValid())
		{
			WizardStep nextStep = ProcessPageChangeRequest (true);
			if (nextStep != CurrentStep)
				SetStep (nextStep);
		}
	}

	void WizardFrame::OnPreviousButtonClick (wxCommandEvent& event)
	{
		ProcessPageChangeRequest (false);

		if (!StepHistory.empty())
		{
			WizardStep prevStep = *StepHistory.rbegin();
			StepHistory.pop_back();
			SetStep (prevStep, false);
		}
	}
	
	void WizardFrame::SetCancelButtonText (const wxString &text)
	{
		CancelButton->SetLabel (text.empty() ? wxString (_("Cancel")) : text);
	}
	
	void WizardFrame::SetImage (const wxBitmap &bitmap)
	{
		WizardBitmap->SetBitmap (bitmap);
	}

	void WizardFrame::SetMaxStaticTextWidth (size_t charCount)
	{
		MaxStaticTextWidth = Gui->GetCharWidth (this) * charCount;
	}

	void WizardFrame::SetStep (WizardStep newStep)
	{
		SetStep (newStep, true);
	}

	void WizardFrame::SetStep (WizardStep newStep, bool forward)
	{
		bool init = false;
		FreezeScope freeze (this);

#ifdef TC_WINDOWS
		HelpButton->Disable(); // Prevent Help button from getting default focus
		NextButton->Enable();
#endif
		if (CurrentPage)
		{
			if (forward)
				StepHistory.push_back (CurrentStep);

			CurrentPage->OnPageChanging (forward);
			CurrentPage->Destroy();
			CurrentPage = nullptr;
		}
		else
			init = true;

		CurrentStep = newStep;
		CurrentPage = GetPage (newStep);

		CurrentPage->PageUpdatedEvent.Connect (EventConnector <WizardFrame> (this, &WizardFrame::OnPageUpdated));
		
		CurrentPage->Connect (wxEVT_MOTION, wxMouseEventHandler (WizardFrame::OnMouseMotion), nullptr, this);
		foreach (wxWindow *c, CurrentPage->GetChildren())
			c->Connect (wxEVT_MOTION, wxMouseEventHandler (WizardFrame::OnMouseMotion), nullptr, this);

		if (MaxStaticTextWidth > 0)
			CurrentPage->SetMaxStaticTextWidth (MaxStaticTextWidth);

		PageTitleStaticText->SetLabel (CurrentPage->GetPageTitle());
		PageSizer->Add (CurrentPage, 1, wxALL | wxEXPAND);

		if (init)
		{
			Fit();
			Layout();
			Center();
		}
		else
			MainPanel->Layout();

		CurrentPage->SetFocus();

		wxString nextButtonText = CurrentPage->GetNextButtonText();
		if (nextButtonText.empty())
			NextButton->SetLabel (_("&Next >"));
		else
			NextButton->SetLabel (nextButtonText);

#ifdef TC_WINDOWS
		HelpButton->Enable();
#endif
		UpdateControls();
	}

	void WizardFrame::SetWorkInProgress (bool state)
	{
		WorkInProgress = state;
		UpdateControls();
	}

	void WizardFrame::UpdateControls ()
	{
		CancelButton->Enable (!WorkInProgress);
		HelpButton->Enable (!WorkInProgress);
		NextButton->Enable (!WorkInProgress && CurrentPage != nullptr && CurrentPage->IsValid());
		PreviousButton->Enable (!WorkInProgress && !StepHistory.empty());
	}
}
