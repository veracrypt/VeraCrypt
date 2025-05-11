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

#ifndef TC_HEADER_Main_Forms_VolumeSizeWizardPage
#define TC_HEADER_Main_Forms_VolumeSizeWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class VolumeSizeWizardPage : public VolumeSizeWizardPageBase
	{
	public:
		VolumeSizeWizardPage (wxPanel* parent, const VolumePath &volumePath, uint32 sectorSize, const wxString &freeSpaceText = wxEmptyString);

		uint64 GetVolumeSize () const;
		bool IsValid ();
		void SetMaxStaticTextWidth (int width);
		void SetMaxVolumeSize (uint64 size) { MaxVolumeSize = size; MaxVolumeSizeValid = true; }
		void SetMinVolumeSize (uint64 size) { MinVolumeSize = size; }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void SetVolumeSize (uint64 size);

	protected:
		struct Prefix
		{
			enum
			{
				KB = 0,
				MB,
				GB,
				TB
			};
		};

		void OnBrowseButtonClick (wxCommandEvent& event);
		void OnVolumeSizePrefixSelected (wxCommandEvent& event) { PageUpdatedEvent.Raise(); }
		void OnVolumeSizeTextChanged (wxCommandEvent& event) { PageUpdatedEvent.Raise(); }
		void OnUseAllFreeSpaceCheckBoxClick( wxCommandEvent& event );

		uint64 MaxVolumeSize;
		bool MaxVolumeSizeValid;
		uint64 MinVolumeSize;
		uint32 SectorSize;
		uint64 AvailableDiskSpace;
	};
}

#endif // TC_HEADER_Main_Forms_VolumeSizeWizardPage
