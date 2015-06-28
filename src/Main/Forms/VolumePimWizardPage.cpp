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
	}

	VolumePimWizardPage::~VolumePimWizardPage ()
	{
	}
	
	int VolumePimWizardPage::GetVolumePim () const
	{
		if (VolumePimTextCtrl->IsEnabled ())
		{
			wxString pinStr (VolumePimTextCtrl->GetValue());
			long pin = 0;
			if (pinStr.IsEmpty())
				return 0;
			if (pinStr.ToLong (&pin))
				return (int) pin;
			else
				return -1;
		}
		else
			return 0;
	}

	bool VolumePimWizardPage::IsValid ()
	{
		return true;
	}
	
	void VolumePimWizardPage::OnPimChanged  (wxCommandEvent& event)
	{
		if (GetVolumePim() != 0)
		{
			VolumePinHelpStaticText->SetForegroundColour(*wxRED);
			VolumePinHelpStaticText->SetLabel(LangString["PIM_CHANGE_WARNING"]);
		}
		else
		{
			VolumePinHelpStaticText->SetForegroundColour(*wxBLACK);
			VolumePinHelpStaticText->SetLabel(LangString["IDC_PIM_HELP"]);
		}			
	}
}
