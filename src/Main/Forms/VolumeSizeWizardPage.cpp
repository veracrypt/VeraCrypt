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
#include "VolumeSizeWizardPage.h"

namespace VeraCrypt
{
	VolumeSizeWizardPage::VolumeSizeWizardPage (wxPanel* parent, const VolumePath &volumePath, uint32 sectorSize, const wxString &freeSpaceText)
		: VolumeSizeWizardPageBase (parent),
		MaxVolumeSize (0),
		MaxVolumeSizeValid (false),
		MinVolumeSize (1),
		SectorSize (sectorSize),
		AvailableDiskSpace (0)
	{
		VolumeSizePrefixChoice->Append (LangString["KB"], reinterpret_cast <void *> (1));
		VolumeSizePrefixChoice->Append (LangString["MB"], reinterpret_cast <void *> (2));
		VolumeSizePrefixChoice->Append (LangString["GB"], reinterpret_cast <void *> (3));
		VolumeSizePrefixChoice->Append (LangString["TB"], reinterpret_cast <void *> (4));
		VolumeSizePrefixChoice->Select (Prefix::MB);

		wxLongLong diskSpace = 0;
		if (!wxGetDiskSpace (wxFileName (wstring (volumePath)).GetPath(), nullptr, &diskSpace))
		{
			VolumeSizeTextCtrl->Disable();
			VolumeSizeTextCtrl->SetValue (L"");
			UseAllFreeSpaceCheckBox->Disable();
		}
		else
		{
			if (!volumePath.IsDevice())
			{
				wxULongLong containerSizeUnsigned = wxFileName (wstring (volumePath)).GetSize();
				if (containerSizeUnsigned != wxInvalidSize)
					diskSpace += static_cast<wxLongLong_t>(containerSizeUnsigned.GetValue());
			}
			AvailableDiskSpace = (uint64) diskSpace.GetValue ();
		}

		FreeSpaceStaticText->SetFont (Gui->GetDefaultBoldFont (this));

		if (!freeSpaceText.empty())
		{
			FreeSpaceStaticText->SetLabel (freeSpaceText);
		}
		else
		{
#ifdef TC_WINDOWS
			wxString drive = wxFileName (wstring (volumePath)).GetVolume();
			if (!drive.empty())
			{
				FreeSpaceStaticText->SetLabel (StringFormatter (LangString["LINUX_FREE_SPACE_ON_DRIVE"],
					drive, Gui->SizeToString (diskSpace.GetValue())));
			}
			else
#endif
			{
				FreeSpaceStaticText->SetLabel (StringFormatter (LangString["DISK_FREE"],
					Gui->SizeToString (diskSpace.GetValue())));
			}
		}

		VolumeSizeTextCtrl->SetMinSize (wxSize (Gui->GetCharWidth (VolumeSizeTextCtrl) * 20, -1));

		wxTextValidator validator (wxFILTER_DIGITS);
		VolumeSizeTextCtrl->SetValidator (validator);
	}

	uint64 VolumeSizeWizardPage::GetVolumeSize () const
	{
		uint64 prefixMult = 1;
		uint64 val;
		if (UseAllFreeSpaceCheckBox->IsChecked ())
		{
			val = MaxVolumeSizeValid ? MaxVolumeSize : AvailableDiskSpace;
		}
		else
		{
			int selection = VolumeSizePrefixChoice->GetSelection();
			if (selection == wxNOT_FOUND)
				return 0;

			uint64 counter = reinterpret_cast <uint64> (VolumeSizePrefixChoice->GetClientData (selection));
			while (counter)
			{
				prefixMult *= 1024;
				counter--;
			}
			val = StringConverter::ToUInt64 (wstring(VolumeSizeTextCtrl->GetValue()));
		}
		if (val <= 0x7fffFFFFffffFFFFull / prefixMult)
		{
			val *= prefixMult;

			uint32 sectorSizeRem = val % SectorSize;

			if (sectorSizeRem != 0)
				val += SectorSize - sectorSizeRem;

			return val;
		}
		else
			return 0;
	}

	bool VolumeSizeWizardPage::IsValid ()
	{
		if ((!VolumeSizeTextCtrl->GetValue().empty() || UseAllFreeSpaceCheckBox->IsChecked ()) && Validate())
		{
			try
			{
				uint64 uiVolumeSize = GetVolumeSize();
				if (uiVolumeSize >= MinVolumeSize && (!MaxVolumeSizeValid || uiVolumeSize <= MaxVolumeSize) && (MaxVolumeSizeValid || CmdLine->ArgDisableFileSizeCheck || !AvailableDiskSpace || uiVolumeSize <= AvailableDiskSpace))
					return true;
			}
			catch (...) { }
		}
		return false;
	}

	void VolumeSizeWizardPage::SetMaxStaticTextWidth (int width)
	{
		FreeSpaceStaticText->Wrap (width);
		InfoStaticText->Wrap (width);
	}

	void VolumeSizeWizardPage::SetVolumeSize (uint64 size)
	{
		if (size == 0)
		{
			VolumeSizePrefixChoice->Select (Prefix::MB);
			VolumeSizeTextCtrl->SetValue (L"");
			return;
		}

		if (size % (1024ULL * 1024ULL * 1024ULL * 1024ULL) == 0)
		{
			size /= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
			VolumeSizePrefixChoice->Select (Prefix::TB);
		}
		else if (size % (1024 * 1024 * 1024) == 0)
		{
			size /= 1024 * 1024 * 1024;
			VolumeSizePrefixChoice->Select (Prefix::GB);
		}
		else if (size % (1024 * 1024) == 0)
		{
			size /= 1024 * 1024;
			VolumeSizePrefixChoice->Select (Prefix::MB);
		}
		else
		{
			size /= 1024;
			VolumeSizePrefixChoice->Select (Prefix::KB);
		}

		VolumeSizeTextCtrl->SetValue (StringConverter::FromNumber (size));
	}

	void VolumeSizeWizardPage::OnUseAllFreeSpaceCheckBoxClick( wxCommandEvent& event )
	{
		if (UseAllFreeSpaceCheckBox->IsChecked ())
		{
			VolumeSizePrefixChoice->Select (Prefix::MB);
			VolumeSizeTextCtrl->SetValue (L"");
			VolumeSizePrefixChoice->Disable();
			VolumeSizeTextCtrl->Disable();
		}
		else
		{
			VolumeSizePrefixChoice->Enable();
			VolumeSizeTextCtrl->SetValue (L"");
			VolumeSizeTextCtrl->Enable();
		}
	}
}
