/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumeLocationWizardPage
#define TC_HEADER_Main_Forms_VolumeLocationWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class VolumeLocationWizardPage : public VolumeLocationWizardPageBase
	{
	public:
		VolumeLocationWizardPage (wxPanel* parent, VolumeHostType::Enum hostType = VolumeHostType::Unknown, bool selectExisting = false);
		~VolumeLocationWizardPage ();

		VolumePath GetVolumePath () const { return VolumePath (wstring (VolumePathComboBox->GetValue())); }
		bool IsValid () { return !VolumePathComboBox->GetValue().IsEmpty(); }
		void OnPageChanging (bool forward);
		void SetVolumePath (const VolumePath &path);
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }

	protected:
		void OnVolumePathTextChanged (wxCommandEvent& event) { PageUpdatedEvent.Raise(); }
		void OnNoHistoryCheckBoxClick (wxCommandEvent& event);
		void OnSelectDeviceButtonClick (wxCommandEvent& event);
		void OnSelectFileButtonClick (wxCommandEvent& event);
		void OnPreferencesUpdated (EventArgs &args);

		bool SelectExisting;
	};
}

#endif // TC_HEADER_Main_Forms_VolumeLocationWizardPage
