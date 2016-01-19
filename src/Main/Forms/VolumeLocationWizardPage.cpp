/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Main/VolumeHistory.h"
#include "VolumeLocationWizardPage.h"

namespace VeraCrypt
{
	VolumeLocationWizardPage::VolumeLocationWizardPage (wxPanel* parent, VolumeHostType::Enum hostType, bool selectExisting)
		: VolumeLocationWizardPageBase (parent),
		SelectExisting (selectExisting)
	{
		switch (hostType)
		{
		case VolumeHostType::Device:
			SelectFileButton->Show (false);
			break;

		case VolumeHostType::File:
			SelectDeviceButton->Show (false);
			break;

		default:
			break;
		}

		Gui->PreferencesUpdatedEvent.Connect (EventConnector <VolumeLocationWizardPage> (this, &VolumeLocationWizardPage::OnPreferencesUpdated));
		VolumeHistory::ConnectComboBox (VolumePathComboBox);

		NoHistoryCheckBox->SetValue (!Gui->GetPreferences().SaveHistory);
	}

	VolumeLocationWizardPage::~VolumeLocationWizardPage ()
	{
		Gui->PreferencesUpdatedEvent.Disconnect (this);
		VolumeHistory::DisconnectComboBox (VolumePathComboBox);
	}

	void VolumeLocationWizardPage::OnNoHistoryCheckBoxClick (wxCommandEvent& event)
	{
		UserPreferences prefs = Gui->GetPreferences();
		prefs.SaveHistory = !event.IsChecked();
		Gui->SetPreferences (prefs);

		if (event.IsChecked())
		{
			try
			{
				VolumeHistory::Clear();
			}
			catch (exception &e) { Gui->ShowError (e); }
		}
	}
	
	void VolumeLocationWizardPage::OnPageChanging (bool forward)
	{
		if (forward)
		{
			VolumePath path = GetVolumePath();
			if (!path.IsEmpty())
				VolumeHistory::Add (path);
		}
	}

	void VolumeLocationWizardPage::OnPreferencesUpdated (EventArgs &args)
	{
		NoHistoryCheckBox->SetValue (!Gui->GetPreferences().SaveHistory);
	}

	void VolumeLocationWizardPage::OnSelectFileButtonClick (wxCommandEvent& event)
	{
		FilePath path = Gui->SelectVolumeFile (this, !SelectExisting);

		if (!path.IsEmpty())
			SetVolumePath (path);
	}

	void VolumeLocationWizardPage::OnSelectDeviceButtonClick (wxCommandEvent& event)
	{
		DevicePath path = Gui->SelectDevice (this);

		if (!path.IsEmpty())
			SetVolumePath (path);
	}

	void VolumeLocationWizardPage::SetVolumePath (const VolumePath &path)
	{
		VolumePathComboBox->SetValue (wstring (path));
		PageUpdatedEvent.Raise();
	}
}
