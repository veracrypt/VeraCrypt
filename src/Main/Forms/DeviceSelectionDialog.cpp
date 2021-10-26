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

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "Main/Resources.h"
#include "DeviceSelectionDialog.h"

namespace VeraCrypt
{
	DeviceSelectionDialog::DeviceSelectionDialog (wxWindow* parent)
		: DeviceSelectionDialogBase (parent)
	{
		wxBusyCursor busy;

		list <int> colPermilles;

		DeviceListCtrl->InsertColumn (ColumnDevice, LangString["DEVICE"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (447);
#ifdef TC_WINDOWS
		DeviceListCtrl->InsertColumn (ColumnDrive, LangString["DRIVE"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (91);
#endif
		DeviceListCtrl->InsertColumn (ColumnSize, LangString["SIZE"], wxLIST_FORMAT_RIGHT, 1);
		colPermilles.push_back (153);
#ifdef TC_WINDOWS
		DeviceListCtrl->InsertColumn (ColumnName, LangString["LABEL"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (307);
#else
		DeviceListCtrl->InsertColumn (ColumnMountPoint, LangString["MOUNT_POINT"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (396);
#endif

		wxImageList *imageList = new wxImageList (16, 12, true);
		imageList->Add (Resources::GetDriveIconBitmap(), Resources::GetDriveIconMaskBitmap());
		DeviceListCtrl->AssignImageList (imageList, wxIMAGE_LIST_SMALL);

		DeviceList = Core->GetHostDevices();

		foreach_ref (HostDevice &device, DeviceList)
		{
			vector <wstring> fields (DeviceListCtrl->GetColumnCount());
			
			if (DeviceListCtrl->GetItemCount() > 0)
				Gui->AppendToListCtrl (DeviceListCtrl, fields);
			
			//	i.e. /dev/rdisk0 might have size = 0 in case open() fails because, for example on OSX, 
			//	SIP is enabled on the machine ; 
			//	This does not mean that it does not have partitions that have been successfully opened
			//	and have a size != 0 ;
			//	Therefore, we do not show the device ONLY if it does not have partitions with size != 0 ;
			if (device.Size == 0)
			{
				bool bHasNonEmptyPartition = false;
				foreach_ref (HostDevice &partition, device.Partitions)
				{
					if (partition.Size)
					{
						bHasNonEmptyPartition = true;
						break;
					}
				}
				
				if (!bHasNonEmptyPartition)
					continue;
			}

#ifdef TC_WINDOWS
			fields[ColumnDevice] = StringFormatter (L"{0} {1}:", LangString["HARDDISK"], device.SystemNumber);
			fields[ColumnDrive] = device.MountPoint;
			fields[ColumnName] = device.Name;
#else
			fields[ColumnDevice] = wstring (device.Path) + L":";
			fields[ColumnMountPoint] = device.MountPoint;
#endif
			//	If the size of the device is 0, we do not show the size to avoid confusing the user ;
			if (device.Size)
				fields[ColumnSize] = Gui->SizeToString (device.Size);
			else
				fields[ColumnSize] = L"";
			Gui->AppendToListCtrl (DeviceListCtrl, fields, 0, &device);

			foreach_ref (HostDevice &partition, device.Partitions)
			{
				//	If a partition's size is 0, there is no need to show it in the list 
				//	since this means it is not usable (i.e on OSX, because of SIP enabled in the machine) ;
				if (!partition.Size)
					continue;

				fields[ColumnDevice] =
#ifndef TC_WINDOWS
					wstring (L"      ") +
#endif
					wstring (partition.Path);

#ifdef TC_WINDOWS
				fields[ColumnDrive] = partition.MountPoint;
				fields[ColumnName] = partition.Name;
#else
				fields[ColumnMountPoint] = partition.MountPoint;
#endif
				fields[ColumnSize] = Gui->SizeToString (partition.Size);
				Gui->AppendToListCtrl (DeviceListCtrl, fields, -1, &partition);
			}
		}

		Gui->SetListCtrlWidth (DeviceListCtrl, 73);
		Gui->SetListCtrlHeight (DeviceListCtrl, 16);
		Gui->SetListCtrlColumnWidths (DeviceListCtrl, colPermilles);

		Fit();
		Layout();
		Center();
		OKButton->Disable();
		OKButton->SetDefault();
	}

	void DeviceSelectionDialog::OnListItemActivated (wxListEvent& event)
	{
		if (OKButton->IsEnabled())
			EndModal (wxID_OK);
	}

	void DeviceSelectionDialog::OnListItemDeselected (wxListEvent& event)
	{
		if (DeviceListCtrl->GetSelectedItemCount() == 0)
			OKButton->Disable();
	}

	void DeviceSelectionDialog::OnListItemSelected (wxListEvent& event)
	{
		HostDevice *device = (HostDevice *) (event.GetItem().GetData());
		//	If a device's size is 0, we do not enable the 'OK' button since it is not usable
		if (device && device->Size)
		{
			SelectedDevice = *device;
			OKButton->Enable();
		}
		else
			OKButton->Disable();
	}
}
