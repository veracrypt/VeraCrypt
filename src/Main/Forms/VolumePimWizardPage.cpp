/*
 Copyright (c) 2015-2016 Mounir IDRASSI for the VeraCrypt project.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumePimWizardPage.h"

namespace VeraCrypt
{
	VolumePimWizardPage::VolumePimWizardPage (wxPanel* parent)
		: VolumePimWizardPageBase (parent)
	{
		VolumePimTextCtrl->SetMinSize (wxSize (Gui->GetCharWidth (VolumePimTextCtrl) * 15, -1));
		SetPimValidator ();
	}

	VolumePimWizardPage::~VolumePimWizardPage ()
	{
	}

	int VolumePimWizardPage::GetVolumePim () const
	{
		if (VolumePimTextCtrl->IsEnabled ())
		{
			wxString pimStr (VolumePimTextCtrl->GetValue());
			long pim = 0;
			if (pimStr.IsEmpty())
				return 0;
			if (((size_t) wxNOT_FOUND == pimStr.find_first_not_of (wxT("0123456789")))
				&& pimStr.ToLong (&pim)
				&& pim <= MAX_PIM_VALUE)
				return (int) pim;
			else
				return -1;
		}
		else
			return 0;
	}

	void VolumePimWizardPage::SetVolumePim (int pim)
	{
		if (pim > 0)
		{
			VolumePimTextCtrl->SetValue (StringConverter::FromNumber (pim));
		}
		else
		{
			VolumePimTextCtrl->SetValue (wxT(""));
		}

		OnPimValueChanged (pim);
	}

	bool VolumePimWizardPage::IsValid ()
	{
		return true;
	}

	void VolumePimWizardPage::OnPimChanged  (wxCommandEvent& event)
	{
		OnPimValueChanged (GetVolumePim ());
	}

	void VolumePimWizardPage::OnPimValueChanged  (int pim)
	{
		if (pim > 0)
		{
			VolumePimHelpStaticText->SetForegroundColour(*wxRED);
			VolumePimHelpStaticText->SetLabel(LangString["PIM_CHANGE_WARNING"]);
		}
		else
		{
			VolumePimHelpStaticText->SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT));
			VolumePimHelpStaticText->SetLabel(LangString["IDC_PIM_HELP"]);
		}
		Fit();
		Layout();
	}

	void VolumePimWizardPage::SetPimValidator ()
	{
		wxTextValidator validator (wxFILTER_DIGITS);
		VolumePimTextCtrl->SetValidator (validator);
	}

	void VolumePimWizardPage::OnDisplayPimCheckBoxClick( wxCommandEvent& event )
	{
		FreezeScope freeze (this);

		bool display = event.IsChecked ();

		wxTextCtrl *newTextCtrl = new wxTextCtrl (this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, display ? 0 : wxTE_PASSWORD);
		newTextCtrl->SetMaxLength (MAX_PIM_DIGITS);
		newTextCtrl->SetValue (VolumePimTextCtrl->GetValue());
		newTextCtrl->SetMinSize (VolumePimTextCtrl->GetSize());

		PimSizer->Replace (VolumePimTextCtrl, newTextCtrl);
		VolumePimTextCtrl->Show (false);
		int txtLen = VolumePimTextCtrl->GetLineLength(0);
		if (txtLen > 0)
		{
			VolumePimTextCtrl->SetValue (wxString (L'X', txtLen));
		}
		GetVolumePim ();

		Fit();
		Layout();
		newTextCtrl->SetMinSize (VolumePimTextCtrl->GetMinSize());

		newTextCtrl->Connect (wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler (VolumePimWizardPage::OnPimChanged), nullptr, this);
		delete VolumePimTextCtrl;
		VolumePimTextCtrl = newTextCtrl;
		SetPimValidator ();
		OnPimValueChanged (GetVolumePim ());
	}
}
