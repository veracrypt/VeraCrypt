/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
		SectorSize (sectorSize)
	{
		VolumeSizePrefixChoice->Append (LangString["KB"], reinterpret_cast <void *> (1024));
		VolumeSizePrefixChoice->Append (LangString["MB"], reinterpret_cast <void *> (1024 * 1024));
		VolumeSizePrefixChoice->Append (LangString["GB"], reinterpret_cast <void *> (1024 * 1024 * 1024));
		VolumeSizePrefixChoice->Select (Prefix::MB);

		wxLongLong diskSpace = 0;
		if (!wxGetDiskSpace (wxFileName (wstring (volumePath)).GetPath(), nullptr, &diskSpace))
		{
			VolumeSizeTextCtrl->Disable();
			VolumeSizeTextCtrl->SetValue (L"");
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
				FreeSpaceStaticText->SetLabel (StringFormatter (_("Free space on drive {0}: is {1}."),
					drive, Gui->SizeToString (diskSpace.GetValue())));
			}
			else
#endif
			{
				FreeSpaceStaticText->SetLabel (StringFormatter (_("Free space available: {0}"),
					Gui->SizeToString (diskSpace.GetValue())));
			}
		}

		VolumeSizeTextCtrl->SetMinSize (wxSize (Gui->GetCharWidth (VolumeSizeTextCtrl) * 20, -1));

		wxTextValidator validator (wxFILTER_INCLUDE_CHAR_LIST);  // wxFILTER_NUMERIC does not exclude - . , etc.
		const wxChar *valArr[] = { L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8", L"9" };
		validator.SetIncludes (wxArrayString (array_capacity (valArr), (const wxChar **) &valArr));
		VolumeSizeTextCtrl->SetValidator (validator);
	}

	uint64 VolumeSizeWizardPage::GetVolumeSize () const
	{
		uint64 prefixMult = 1;
		int selection = VolumeSizePrefixChoice->GetSelection();
		if (selection == wxNOT_FOUND)
			return 0;

		prefixMult = reinterpret_cast <uint64> (VolumeSizePrefixChoice->GetClientData (selection));
		
		uint64 val = StringConverter::ToUInt64 (wstring (VolumeSizeTextCtrl->GetValue()));
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
		if (!VolumeSizeTextCtrl->IsEmpty() && Validate())
		{
			try
			{
				if (GetVolumeSize() >= MinVolumeSize && (!MaxVolumeSizeValid || GetVolumeSize() <= MaxVolumeSize))
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
		
		if (size % (1024 * 1024 * 1024) == 0)
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
}
