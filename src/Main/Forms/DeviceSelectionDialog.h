/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_DeviceSelectionDialog
#define TC_HEADER_Main_Forms_DeviceSelectionDialog

#include "Forms.h"
#include "Main/Main.h"

namespace TrueCrypt
{
	class DeviceSelectionDialog : public DeviceSelectionDialogBase
	{
	public:
		DeviceSelectionDialog (wxWindow* parent);

		HostDeviceList DeviceList;
		HostDevice SelectedDevice;

	protected:
		enum
		{
			ColumnDevice = 0,
#ifdef TC_WINDOWS
			ColumnDrive,
#endif
			ColumnSize,
#ifdef TC_WINDOWS
			ColumnName
#else
			ColumnMountPoint
#endif
		};

		void OnListItemActivated (wxListEvent& event);
		void OnListItemDeselected (wxListEvent& event);
		void OnListItemSelected (wxListEvent& event);
	};
}

#endif // TC_HEADER_Main_Forms_DeviceSelectionDialog
