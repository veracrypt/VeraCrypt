/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
			if (device.Size == 0)
				continue;

			vector <wstring> fields (DeviceListCtrl->GetColumnCount());

			if (DeviceListCtrl->GetItemCount() > 0)
				Gui->AppendToListCtrl (DeviceListCtrl, fields);

#ifdef TC_WINDOWS
			fields[ColumnDevice] = StringFormatter (L"{0} {1}:", _("Harddisk"), device.SystemNumber);
			fields[ColumnDrive] = device.MountPoint;
			fields[ColumnName] = device.Name;
#else
			fields[ColumnDevice] = wstring (device.Path) + L":";
			fields[ColumnMountPoint] = device.MountPoint;
#endif
			fields[ColumnSize] = Gui->SizeToString (device.Size);
			Gui->AppendToListCtrl (DeviceListCtrl, fields, 0, &device); 

			foreach_ref (HostDevice &partition, device.Partitions)
			{
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

		StdButtonsOK->Disable();
		StdButtonsOK->SetDefault();
	}
	
	void DeviceSelectionDialog::OnListItemActivated (wxListEvent& event)
	{
		if (StdButtonsOK->IsEnabled())
			EndModal (wxID_OK);
	}

	void DeviceSelectionDialog::OnListItemDeselected (wxListEvent& event)
	{
		if (DeviceListCtrl->GetSelectedItemCount() == 0)
			StdButtonsOK->Disable();
	}

	void DeviceSelectionDialog::OnListItemSelected (wxListEvent& event)
	{
		HostDevice *device = (HostDevice *) (event.GetItem().GetData());
		if (device)
		{
			SelectedDevice = *device;
			StdButtonsOK->Enable();
		}
		else
			StdButtonsOK->Disable();
	}
}
