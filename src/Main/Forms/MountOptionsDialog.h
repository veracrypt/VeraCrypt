/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
