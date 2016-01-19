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

#ifndef VC_HEADER_Main_Forms_VolumePimWizardPage
#define VC_HEADER_Main_Forms_VolumePimWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class VolumePimWizardPage : public VolumePimWizardPageBase
	{
	public:
		VolumePimWizardPage (wxPanel* parent);
		~VolumePimWizardPage ();

		int GetVolumePim () const;
		void SetVolumePim (int pim);
		bool IsValid ();
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void OnDisplayPimCheckBoxClick( wxCommandEvent& event );
		
	protected:
		void SetPimValidator ();
		void OnPimChanged  (wxCommandEvent& event);
		void OnPimValueChanged  (int pim);
	};
}

#endif // VC_HEADER_Main_Forms_VolumePimWizardPage
