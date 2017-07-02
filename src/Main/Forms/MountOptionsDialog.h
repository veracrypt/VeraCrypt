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

#ifndef TC_HEADER_Main_Forms_MountOptionsDialog
#define TC_HEADER_Main_Forms_MountOptionsDialog

#include "Forms.h"
#include "Main/Main.h"
#include "VolumePasswordPanel.h"

namespace VeraCrypt
{
	class MountOptionsDialog : public MountOptionsDialogBase
	{
	public:
		MountOptionsDialog (wxWindow* parent, MountOptions &options, const wxString &title = wxEmptyString, bool disableMountOptions = false);
		void OnShow ();

	protected:
		void OnInitDialog (wxInitDialogEvent& event);
		void OnMountPointButtonClick (wxCommandEvent& event);
		void OnNoFilesystemCheckBoxClick (wxCommandEvent& event) { UpdateDialog(); }
		void OnOKButtonClick (wxCommandEvent& event);
		void OnOptionsButtonClick (wxCommandEvent& event);
		void OnProtectionCheckBoxClick (wxCommandEvent& event);
		void OnProtectionHyperlinkClick (wxHyperlinkEvent& event);
		void OnReadOnlyCheckBoxClick (wxCommandEvent& event) { UpdateDialog(); }
		void UpdateDialog ();

		MountOptions &Options;
		wxString OptionsButtonLabel;
		VolumePasswordPanel *PasswordPanel;
		VolumePasswordPanel *ProtectionPasswordPanel;
	};
}

#endif // TC_HEADER_Main_Forms_MountOptionsDialog
