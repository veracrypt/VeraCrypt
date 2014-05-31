/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/Main.h"
#include "Main/GraphicUserInterface.h"
#include "VolumePropertiesDialog.h"

namespace TrueCrypt
{
	VolumePropertiesDialog::VolumePropertiesDialog (wxWindow* parent, const VolumeInfo &volumeInfo)
		: VolumePropertiesDialogBase (parent)
	{
		list <int> colPermilles;

		PropertiesListCtrl->InsertColumn (0, LangString["PROPERTY"], wxLIST_FORMAT_LEFT, 208);
		colPermilles.push_back (500);
		PropertiesListCtrl->InsertColumn (1, LangString["VALUE"], wxLIST_FORMAT_LEFT, 192);
		colPermilles.push_back (500);

		Gui->SetListCtrlWidth (PropertiesListCtrl, 70, false);
		Gui->SetListCtrlHeight (PropertiesListCtrl, 17);
		Gui->SetListCtrlColumnWidths (PropertiesListCtrl, colPermilles, false);

		AppendToList ("LOCATION", wstring (volumeInfo.Path));
#ifndef TC_WINDOWS
		AppendToList ("VIRTUAL_DEVICE", wstring (volumeInfo.VirtualDevice));
#endif
		AppendToList ("SIZE", Gui->SizeToString (volumeInfo.Size));
		AppendToList ("TYPE", Gui->VolumeTypeToString (volumeInfo.Type, volumeInfo.Protection));
		AppendToList ("READ_ONLY", LangString [volumeInfo.Protection == VolumeProtection::ReadOnly ? "UISTR_YES" : "UISTR_NO"]);
		
		wxString protection;
		if (volumeInfo.Type == VolumeType::Hidden)
			protection = LangString["NOT_APPLICABLE_OR_NOT_AVAILABLE"];
		else if (volumeInfo.HiddenVolumeProtectionTriggered)
			protection = LangString["HID_VOL_DAMAGE_PREVENTED"];
		else
			protection = LangString [volumeInfo.Protection == VolumeProtection::HiddenVolumeReadOnly ? "UISTR_YES" : "UISTR_NO"];

		AppendToList ("HIDDEN_VOL_PROTECTION", protection);
		AppendToList ("ENCRYPTION_ALGORITHM", volumeInfo.EncryptionAlgorithmName);
		AppendToList ("KEY_SIZE", StringFormatter (L"{0} {1}", volumeInfo.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]));

		if (volumeInfo.EncryptionModeName == L"XTS")
			AppendToList ("SECONDARY_KEY_SIZE_XTS", StringFormatter (L"{0} {1}", volumeInfo.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]));

		wstringstream blockSize;
		blockSize << volumeInfo.EncryptionAlgorithmBlockSize * 8;
		if (volumeInfo.EncryptionAlgorithmBlockSize != volumeInfo.EncryptionAlgorithmMinBlockSize)
			blockSize << L"/" << volumeInfo.EncryptionAlgorithmMinBlockSize * 8;

		AppendToList ("BLOCK_SIZE", blockSize.str() + L" " + LangString ["BITS"]);
		AppendToList ("MODE_OF_OPERATION", volumeInfo.EncryptionModeName);
		AppendToList ("PKCS5_PRF", volumeInfo.Pkcs5PrfName);

#if 0
		AppendToList ("PKCS5_ITERATIONS", StringConverter::FromNumber (volumeInfo.Pkcs5IterationCount));
		AppendToList ("VOLUME_CREATE_DATE", Gui->VolumeTimeToString (volumeInfo.VolumeCreationTime));
		AppendToList ("VOLUME_HEADER_DATE", Gui->VolumeTimeToString (volumeInfo.HeaderCreationTime));
#endif

		AppendToList ("VOLUME_FORMAT_VERSION", StringConverter::ToWide (volumeInfo.MinRequiredProgramVersion < 0x600 ? 1 : 2));
		AppendToList ("BACKUP_HEADER", LangString[volumeInfo.MinRequiredProgramVersion >= 0x600 ? "UISTR_YES" : "UISTR_NO"]);

#ifdef TC_LINUX
		if (string (volumeInfo.VirtualDevice).find ("/dev/mapper/veracrypt") != 0)
		{
#endif
		AppendToList ("TOTAL_DATA_READ", Gui->SizeToString (volumeInfo.TotalDataRead));
		AppendToList ("TOTAL_DATA_WRITTEN", Gui->SizeToString (volumeInfo.TotalDataWritten));
#ifdef TC_LINUX
		}
#endif
		
		Layout();
		Fit();
		Center();

		StdButtonsOK->SetDefault();
	}

	void VolumePropertiesDialog::AppendToList (const string &name, const wxString &value)
	{
		vector <wstring> fields (PropertiesListCtrl->GetColumnCount());

		fields[0] = LangString[name];
		fields[1] = value;

		Gui->AppendToListCtrl (PropertiesListCtrl, fields);
	}
}
