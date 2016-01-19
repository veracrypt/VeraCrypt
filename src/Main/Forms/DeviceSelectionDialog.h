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

#ifndef TC_HEADER_Main_Forms_DeviceSelectionDialog
#define TC_HEADER_Main_Forms_DeviceSelectionDialog

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
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
