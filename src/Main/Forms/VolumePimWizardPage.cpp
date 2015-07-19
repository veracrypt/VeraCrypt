/*
 Copyright (c) 2015 Mounir IDRASSI for the VeraCrypt project.

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
		wxTextValidator validator (wxFILTER_INCLUDE_CHAR_LIST);  // wxFILTER_NUMERIC does not exclude - . , etc.
		const wxChar *valArr[] = { L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8", L"9" };
		validator.SetIncludes (wxArrayString (array_capacity (valArr), (const wxChar **) &valArr));
		VolumePimTextCtrl->SetValidator (validator);
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
			if (pimStr.ToLong (&pim))
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

		OnPimChanged (pim);
	}

	bool VolumePimWizardPage::IsValid ()
	{
		return true;
	}
	
	void VolumePimWizardPage::OnPimChanged  (wxCommandEvent& event)
	{
		OnPimChanged (GetVolumePim ());
	}

	void VolumePimWizardPage::OnPimChanged  (int pim)
	{
		if (pim > 0)
		{
			VolumePimHelpStaticText->SetForegroundColour(*wxRED);
			VolumePimHelpStaticText->SetLabel(LangString["PIM_CHANGE_WARNING"]);
		}
		else
		{
			VolumePimHelpStaticText->SetForegroundColour(*wxBLACK);
			VolumePimHelpStaticText->SetLabel(LangString["IDC_PIM_HELP"]);
		}			
	}
}
