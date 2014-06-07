/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"

#ifdef TC_UNIX
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "Common/SecurityToken.h"
#include "Main/Main.h"
#include "Main/Resources.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
#include "Main/VolumeHistory.h"
#include "Main/Xml.h"
#include "MainFrame.h"
#include "AboutDialog.h"
#include "BenchmarkDialog.h"
#include "ChangePasswordDialog.h"
#include "EncryptionTestDialog.h"
#include "FavoriteVolumesDialog.h"
#include "LegalNoticesDialog.h"
#include "PreferencesDialog.h"
#include "SecurityTokenKeyfilesDialog.h"
#include "VolumeCreationWizard.h"
#include "VolumePropertiesDialog.h"

namespace TrueCrypt
{
	MainFrame::MainFrame (wxWindow* parent) : MainFrameBase (parent),
		ListItemRightClickEventPending (false),
		SelectedItemIndex (-1),
		SelectedSlotNumber (0),
		ShowRequestFifo (-1)
	{
		wxBusyCursor busy;

		SetName (Application::GetName());
		SetTitle (Application::GetName());
		SetIcon (Resources::GetTrueCryptIcon());

#if defined(TC_UNIX) && !defined(TC_MACOSX)
		try
		{
			string fifoPath = GetShowRequestFifoPath();

			remove (fifoPath.c_str());
			throw_sys_if (mkfifo (fifoPath.c_str(), S_IRUSR | S_IWUSR) == -1);

			ShowRequestFifo = open (fifoPath.c_str(), O_RDONLY | O_NONBLOCK);
			throw_sys_if (ShowRequestFifo == -1);
		}
		catch (...)
		{
#ifdef DEBUG
			throw;
#endif
		}
#endif

		InitControls();
		InitPreferences();
		InitTaskBarIcon();
		InitEvents();
		InitMessageFilter();

		if (!GetPreferences().SecurityTokenModule.IsEmpty() && !SecurityToken::IsInitialized())
		{
			try
			{
				Gui->InitSecurityTokenLibrary();
			}
			catch (exception &e)
			{
				Gui->ShowError (e);
			}
		}
	}

	MainFrame::~MainFrame ()
	{
#if defined(TC_UNIX) && !defined(TC_MACOSX)
		if (ShowRequestFifo != -1)
		{
			try
			{
				close (ShowRequestFifo);
				remove (string (GetShowRequestFifoPath()).c_str());
			}
			catch (...) { }
		}
#endif

		Core->VolumeMountedEvent.Disconnect (this);
		Core->VolumeDismountedEvent.Disconnect (this);
		Gui->OpenVolumeSystemRequestEvent.Disconnect (this);
		Gui->PreferencesUpdatedEvent.Disconnect (this);

		VolumeHistory::DisconnectComboBox (VolumePathComboBox);

#ifdef TC_WINDOWS
		Hotkey::UnregisterList (this, GetPreferences().Hotkeys);
#endif
	}

	void MainFrame::AddToFavorites (const VolumeInfoList &volumes)
	{
		try
		{
			FavoriteVolumeList newFavorites;

			// Delete duplicates
			foreach (shared_ptr <FavoriteVolume> favorite, FavoriteVolume::LoadList())
			{
				bool mounted = false;
				foreach_ref (const VolumeInfo &volume, volumes)
				{
					if (volume.Path == favorite->Path)
					{
						mounted = true;
						break;
					}
				}
				if (!mounted)
					newFavorites.push_back (favorite);
			}

			size_t newItemCount = 0;
			foreach_ref (const VolumeInfo &volume, volumes)
			{
				newFavorites.push_back (shared_ptr <FavoriteVolume> (new FavoriteVolume (volume.Path, volume.MountPoint, volume.SlotNumber, volume.Protection == VolumeProtection::ReadOnly, volume.SystemEncryption)));
				++newItemCount;
			}

			OrganizeFavorites (newFavorites, newItemCount);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	bool MainFrame::CanExit () const
	{
		return Gui->IsTheOnlyTopLevelWindow (this);
	}

	void MainFrame::ChangePassword (ChangePasswordDialog::Mode::Enum mode)
	{
		if (!CheckVolumePathNotEmpty ())
			return;

		shared_ptr <VolumePath> volumePath = GetSelectedVolumePath();

#ifdef TC_WINDOWS
		if (Core->IsVolumeMounted (*volumePath))
		{
			Gui->ShowInfo (LangString [mode == ChangePasswordDialog::Mode::ChangePkcs5Prf ? "MOUNTED_NO_PKCS5_PRF_CHANGE" : "MOUNTED_NOPWCHANGE"]);
			return;
		}
#endif

		ChangePasswordDialog dialog (this, volumePath, mode);
		dialog.ShowModal();
	}

	void MainFrame::CheckFilesystem (bool repair)
	{
		shared_ptr <VolumeInfo> selectedVolume = GetSelectedVolume();
		if (selectedVolume)
		{
			try
			{
#ifdef TC_WINDOWS
				string mountPoint = selectedVolume->MountPoint;

				wstring args = StringFormatter (repair ? L"/C echo {0} & chkdsk {1} /F /X & pause" : L"/C echo {0} & chkdsk {1} & pause",
					StringFormatter (LangString[repair ? "REPAIRING_FS" : "CHECKING_FS"], mountPoint), mountPoint);

				ShellExecute (static_cast <HWND> (GetHandle()), 
					L"runas",
					L"cmd.exe", args.c_str(), nullptr, SW_SHOW);
#else
#	ifdef TC_MACOSX
				Gui->ShowInfo (_("Disk Utility will be launched after you press 'OK'.\n\nPlease select your volume in the Disk Utility window and press 'Verify Disk' or 'Repair Disk' button on the 'First Aid' page."));
#	endif
				Core->CheckFilesystem (selectedVolume, repair);
				UpdateVolumeList();
#endif
			}
			catch (exception &e)
			{
				Gui->ShowError (e);
			}
		}
	}

	bool MainFrame::CheckVolumePathNotEmpty () const
	{
		if (VolumePathComboBox->GetValue().empty())
		{
			Gui->ShowInfo ("NO_VOLUME_SELECTED");
			return false;
		}
		return true;
	}

	void MainFrame::DismountVolume (shared_ptr <VolumeInfo> volume)
	{
		try
		{
			if (!volume)
				volume = GetSelectedVolume();

			if (volume)
				Gui->DismountVolume (volume);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	shared_ptr <VolumeInfo> MainFrame::GetSelectedVolume () const
	{
		return Core->GetMountedVolume (SelectedSlotNumber);
	}

	void MainFrame::InitControls ()
	{
		LogoBitmap->SetBitmap (Resources::GetLogoBitmap());
		
		list <int> colPermilles;

#ifndef TC_WINDOWS
		SettingsMenu->Remove (HotkeysMenuItem);
#endif

#ifdef TC_MACOSX
		SettingsMenu->Remove (PreferencesMenuItem);
		SettingsMenu->AppendSeparator();
		SettingsMenu->Append (PreferencesMenuItem);

		LowStaticBoxSizer->Detach (HigherButtonSizer);
		VolumeStaticBoxSizer->Detach (VolumeGridBagSizer);
		VolumeStaticBoxSizer->Add (VolumeGridBagSizer, 1, wxEXPAND, 0);

		ExitButton->SetLabel (_("Close"));
		MountAllDevicesButton->SetLabel (_("Mount All Devices"));
#endif

#ifdef TC_WINDOWS		 
		SlotListCtrl->InsertColumn (ColumnSlot, LangString["DRIVE"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (75);
#else
		SlotListCtrl->InsertColumn (ColumnSlot, _("Slot"), wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (82);
#endif

		SlotListCtrl->InsertColumn (ColumnPath, LangString["VOLUME"], wxLIST_FORMAT_LEFT, 1);
#ifdef TC_WINDOWS		 
		colPermilles.push_back (487);
#else
		colPermilles.push_back (429);
#endif

		SlotListCtrl->InsertColumn (ColumnSize, LangString["SIZE"], wxLIST_FORMAT_RIGHT, 1);
#ifdef TC_WINDOWS		 
		colPermilles.push_back (126);
#else
		colPermilles.push_back (130);
#endif

#ifdef TC_WINDOWS		 
		SlotListCtrl->InsertColumn (ColumnEA, LangString["ENCRYPTION_ALGORITHM_LV"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (233);
#else
		SlotListCtrl->InsertColumn (ColumnMountPoint, LangString["MOUNT_POINT"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (259);
#endif

		SlotListCtrl->InsertColumn (ColumnType, LangString["TYPE"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (100);

		wxImageList *imageList = new wxImageList (16, 12, true);
		imageList->Add (Resources::GetDriveIconBitmap(), Resources::GetDriveIconMaskBitmap());
		SlotListCtrl->AssignImageList (imageList, wxIMAGE_LIST_SMALL);

		SetMinSize (wxSize (-1, -1));

		size_t slotListRowCount = 12;

#ifndef TC_WINDOWS
		int screenHeight = wxSystemSettings::GetMetric (wxSYS_SCREEN_Y);
		
		if (screenHeight < 480)
			slotListRowCount = 1;
		else if (screenHeight <= 600)
			slotListRowCount = slotListRowCount * screenHeight / 1000;
#endif

		Gui->SetListCtrlHeight (SlotListCtrl, slotListRowCount);

#ifdef __WXGTK__
		wxSize size (-1, (int) ((double) Gui->GetCharHeight (this) * 1.53));
		CreateVolumeButton->SetMinSize (size);
		VolumePropertiesButton->SetMinSize (size);
		WipeCacheButton->SetMinSize (size);
		VolumePathComboBox->SetMinSize (size);
		SelectFileButton->SetMinSize (size);
		SelectDeviceButton->SetMinSize (size);
		VolumeToolsButton->SetMinSize (size);
		size = wxSize (-1, 38);
		VolumeButton->SetMinSize (size);
#endif
		Fit();
		Layout();
		Center();

		VolumePathComboBox->SetMinSize (VolumePathComboBox->GetSize());
		VolumePathComboBox->SetMaxSize (VolumePathComboBox->GetSize());

		SetMinSize (GetSize());
		SetMaxSize (GetSize());

		Gui->SetListCtrlColumnWidths (SlotListCtrl, colPermilles);
		
		UpdateVolumeList();
		UpdateWipeCacheButton();
	}

	void MainFrame::InitEvents ()
	{
		Core->VolumeMountedEvent.Connect (EventConnector <MainFrame> (this, &MainFrame::OnVolumeMounted));
		Core->VolumeDismountedEvent.Connect (EventConnector <MainFrame> (this, &MainFrame::OnVolumeDismounted));
		Gui->OpenVolumeSystemRequestEvent.Connect (EventConnector <MainFrame> (this, &MainFrame::OnOpenVolumeSystemRequestEvent));
		Gui->PreferencesUpdatedEvent.Connect (EventConnector <MainFrame> (this, &MainFrame::OnPreferencesUpdated));

		// Drag & drop
		class FileDropTarget : public wxFileDropTarget
		{
		public:
			FileDropTarget (MainFrame *frame) : Frame (frame) { }

			wxDragResult OnDragOver (wxCoord x, wxCoord y, wxDragResult def)
			{
				wxPoint p;
				wxWindow *w = wxFindWindowAtPointer (p);
				if (w == Frame || wxGetTopLevelParent (w) == Frame)
					return wxDragLink;
				return wxDragNone;
			}

			bool OnDropFiles (wxCoord x, wxCoord y, const wxArrayString &filenames)
			{
				if (!filenames.empty())
					Frame->SetVolumePath (wstring (filenames.front()));
				return true;
			}

			MainFrame *Frame;
		};

		SetDropTarget (new FileDropTarget (this));
#ifdef TC_MACOSX
		foreach (wxWindow *c, MainPanel->GetChildren())
			c->SetDropTarget (new FileDropTarget (this));
#endif

		// Volume history
		VolumeHistory::ConnectComboBox (VolumePathComboBox);

#ifdef TC_WINDOWS
		// Hotkeys
		Hotkey::RegisterList (this, GetPreferences().Hotkeys);
		Connect (wxEVT_HOTKEY, wxKeyEventHandler (MainFrame::OnHotkey));
#endif

		// Timer
		class Timer : public wxTimer
		{
		public:
			Timer (MainFrame *frame) : Frame (frame) { }

			void Notify()
			{
				Frame->OnTimer();
			}

			MainFrame *Frame;
		};

		mTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		mTimer->Start (2000);
	}

#ifdef TC_WINDOWS
#include <dbt.h>
	static WNDPROC MainFrameWndProc;
	static LRESULT CALLBACK MainFrameWndProcFilter (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		if (message == WM_DEVICECHANGE && !Core->IsDeviceChangeInProgress())
		{
			MainFrame *frame = dynamic_cast <MainFrame *> (Gui->GetMainFrame());
			PDEV_BROADCAST_HDR hdr = (PDEV_BROADCAST_HDR) lParam;
			
			if (wParam == DBT_DEVICEREMOVECOMPLETE && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
			{
				PDEV_BROADCAST_VOLUME vol = (PDEV_BROADCAST_VOLUME) lParam;
				for (wchar_t driveNo = 0; driveNo < 26; ++driveNo)
				{
					if (vol->dbcv_unitmask & (1 << driveNo))
						frame->OnDeviceChange (wstring (StringFormatter (L"{0}:\\", wchar_t (L'A' + driveNo))));
				}
			}
			else
			{
				frame->OnDeviceChange ();
			}
		}

		return CallWindowProc (MainFrameWndProc, hwnd, message, wParam, lParam);
	}
#endif

	void MainFrame::InitMessageFilter ()
	{
#ifdef TC_WINDOWS
		HWND mainFrameHwnd = static_cast <HWND> (GetHandle());
		MainFrameWndProc = (WNDPROC) GetWindowLongPtr (mainFrameHwnd, GWL_WNDPROC);
		SetWindowLongPtr (mainFrameHwnd, GWL_WNDPROC, (LONG_PTR) MainFrameWndProcFilter);
#endif
	}

	void MainFrame::InitPreferences ()
	{
		try
		{
			LoadPreferences();

			VolumeSlotNumber lastSelectedSlotNumber = GetPreferences().LastSelectedSlotNumber;
			if (Core->IsSlotNumberValid (lastSelectedSlotNumber))
			{
				long slotIndex = SlotNumberToItemIndex (lastSelectedSlotNumber);
				if (slotIndex >= 0)
				{
					SlotListCtrl->SetItemState (slotIndex, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
					SlotListCtrl->EnsureVisible (slotIndex);
				}
			}

			LoadFavoriteVolumes();
			VolumeHistory::Load();

			if (VolumePathComboBox->GetValue().empty() && !VolumeHistory::Get().empty())
				SetVolumePath (VolumeHistory::Get().front());
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
			Gui->ShowError (_("Error while loading configuration files located in ") + wstring (Application::GetConfigFilePath (L"")));
		}
	}

	void MainFrame::InitTaskBarIcon ()
	{
		class TaskBarIcon : public wxTaskBarIcon
		{
		public:
			TaskBarIcon (MainFrame *frame) : Busy (false), Frame (frame)
			{
				Connect (wxEVT_TASKBAR_LEFT_DOWN, wxTaskBarIconEventHandler (TaskBarIcon::OnLeftButtonDown));
			}

			wxMenu *CreatePopupMenu ()
			{ 
				auto_ptr <wxMenu> popup (new wxMenu);

				Gui->AppendToMenu (*popup, LangString[Gui->IsInBackgroundMode() ? "SHOW_TC" : "HIDE_TC"], this, wxCommandEventHandler (TaskBarIcon::OnShowHideMenuItemSelected));
				
				popup->AppendSeparator();
				Gui->AppendToMenu (*popup, _("Mount All Favorite Volumes"), this, wxCommandEventHandler (TaskBarIcon::OnMountAllFavoritesMenuItemSelected))->Enable (!Busy);
				Gui->AppendToMenu (*popup, _("Dismount All Mounted Volumes"), this, wxCommandEventHandler (TaskBarIcon::OnDismountAllMenuItemSelected))->Enable (!Busy);
				
				// Favorite volumes
				if (Gui->GetPreferences().BackgroundTaskMenuMountItemsEnabled && !Frame->FavoriteVolumesMenuMap.empty())
				{
					popup->AppendSeparator();
					typedef pair <int, FavoriteVolume> FavMapPair;
					foreach (FavMapPair fp, Frame->FavoriteVolumesMenuMap)
					{
						Gui->AppendToMenu (*popup, LangString["MOUNT"] + L" " + wstring (fp.second.Path) + (fp.second.MountPoint.IsEmpty() ? L"" : L"  " + wstring (fp.second.MountPoint)),
							this, wxCommandEventHandler (TaskBarIcon::OnFavoriteVolumeMenuItemSelected), fp.first)->Enable (!Busy);
					}
				}

				// Mounted volumes
				VolumeInfoList mountedVolumes = Core->GetMountedVolumes();
				if (!mountedVolumes.empty())
				{
					if (Gui->GetPreferences().BackgroundTaskMenuOpenItemsEnabled)
					{
						popup->AppendSeparator();
						OpenMap.clear();
						foreach (shared_ptr <VolumeInfo> volume, mountedVolumes)
						{
							if (!volume->MountPoint.IsEmpty())
							{
								wxString label = LangString["OPEN"] + L" " + wstring (volume->MountPoint) + L" (" + wstring (volume->Path) + L")";
								wxMenuItem *item = Gui->AppendToMenu (*popup, label, this, wxCommandEventHandler (TaskBarIcon::OnOpenMenuItemSelected));
								OpenMap[item->GetId()] = volume;
							}
						}
					}

					if (Gui->GetPreferences().BackgroundTaskMenuDismountItemsEnabled)
					{
						popup->AppendSeparator();
						DismountMap.clear();
						foreach (shared_ptr <VolumeInfo> volume, mountedVolumes)
						{
							wxString label = LangString["DISMOUNT"] + L" ";

							if (!volume->MountPoint.IsEmpty())
								label += wstring (volume->MountPoint) + L" (" + wstring (volume->Path) + L")";
							else
								label += wstring (volume->Path);

							wxMenuItem *item = Gui->AppendToMenu (*popup, label, this, wxCommandEventHandler (TaskBarIcon::OnDismountMenuItemSelected));
							item->Enable (!Busy);
							DismountMap[item->GetId()] = volume;
						}
					}
				}

				popup->AppendSeparator();
				Gui->AppendToMenu (*popup, _("Preferences..."), this, wxCommandEventHandler (TaskBarIcon::OnPreferencesMenuItemSelected))->Enable (!Busy);
#ifndef TC_MACOSX
				popup->AppendSeparator();
				Gui->AppendToMenu (*popup, _("Exit"), this, wxCommandEventHandler (TaskBarIcon::OnExitMenuItemSelected))->Enable (!Busy && Frame->CanExit());
#endif
				return popup.release();
			}

			void OnDismountAllMenuItemSelected (wxCommandEvent& event) { Busy = true; Frame->OnDismountAllButtonClick (event); Busy = false; }
			void OnDismountMenuItemSelected (wxCommandEvent& event) { Busy = true; Frame->DismountVolume (DismountMap[event.GetId()]); Busy = false; }
			void OnFavoriteVolumeMenuItemSelected (wxCommandEvent& event) { Busy = true; Frame->OnFavoriteVolumeMenuItemSelected (event); Busy = false; }
			void OnMountAllFavoritesMenuItemSelected (wxCommandEvent& event) { Busy = true; Frame->MountAllFavorites (); Busy = false; }

			void OnExitMenuItemSelected (wxCommandEvent& event)
			{
				Busy = true;
				if (Core->GetMountedVolumes().empty() || Gui->AskYesNo (LangString ["CONFIRM_EXIT"], false, true))
					Frame->Close (true);
				Busy = false;
			}

			void OnLeftButtonDown (wxTaskBarIconEvent& event) { Gui->SetBackgroundMode (false); }
			void OnOpenMenuItemSelected (wxCommandEvent& event) { Gui->OpenExplorerWindow (OpenMap[event.GetId()]->MountPoint); }
			void OnPreferencesMenuItemSelected (wxCommandEvent& event) { Busy = true; Frame->OnPreferencesMenuItemSelected (event); Busy = false; }
			void OnShowHideMenuItemSelected (wxCommandEvent& event) { Gui->SetBackgroundMode (!Gui->IsInBackgroundMode()); }

			bool Busy;
			map < int, shared_ptr <VolumeInfo> > DismountMap;
			MainFrame *Frame;
			map < int, shared_ptr <VolumeInfo> > OpenMap;
		};

		mTaskBarIcon.reset (new TaskBarIcon (this));
		ShowTaskBarIcon (GetPreferences().BackgroundTaskEnabled);
	}

	void MainFrame::LoadFavoriteVolumes ()
	{
		typedef pair <int, FavoriteVolume> FavMapPair;
		foreach (FavMapPair p, FavoriteVolumesMenuMap)
		{
			FavoritesMenu->Delete (p.first);
		}
		FavoriteVolumesMenuMap.clear();

		foreach_ref (const FavoriteVolume &favorite, FavoriteVolume::LoadList())
		{
			wstring label = wstring (favorite.Path);
			if (!favorite.MountPoint.IsEmpty())
				label += wstring (L"   ") + wstring (favorite.MountPoint);

			wxMenuItem *item = Gui->AppendToMenu (*FavoritesMenu, label, this, wxCommandEventHandler (MainFrame::OnFavoriteVolumeMenuItemSelected));
			FavoriteVolumesMenuMap[item->GetId()] = favorite;
		}
	}

	void MainFrame::LoadPreferences ()
	{
		UserPreferences prefs;
		prefs.Load();
		Gui->SetPreferences (prefs);
		NoHistoryCheckBox->SetValue (!prefs.SaveHistory);
	}
	
	void MainFrame::MountAllDevices ()
	{
		try
		{
			MountOptions mountOptions (GetPreferences().DefaultMountOptions);

			if (SlotListCtrl->GetSelectedItemCount() == 1)
				mountOptions.SlotNumber = SelectedSlotNumber;

			Gui->MountAllDeviceHostedVolumes (mountOptions);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::MountAllFavorites ()
	{
		try
		{
			MountOptions mountOptions (GetPreferences().DefaultMountOptions);
			Gui->MountAllFavoriteVolumes (mountOptions);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::MountVolume ()
	{
		if (!IsFreeSlotSelected())
		{
			Gui->ShowWarning (_("Please select a free drive slot from the list."));
			return;
		}

		if (!CheckVolumePathNotEmpty())
			return;

		MountOptions mountOptions (GetPreferences().DefaultMountOptions);
		mountOptions.SlotNumber = SelectedSlotNumber;
		mountOptions.Path = GetSelectedVolumePath();

		try
		{
			if (Gui->MountVolume (mountOptions) && GetPreferences().SaveHistory)
				VolumeHistory::Add (*mountOptions.Path);
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnAboutMenuItemSelected (wxCommandEvent& event)
	{
		AboutDialog dialog (this);
		dialog.ShowModal();
	}

	void MainFrame::OnActivate (wxActivateEvent& event)
	{
		Gui->SetActiveFrame (this);

#ifdef TC_MACOSX
		if (event.GetActive() && Gui->IsInBackgroundMode())
			Gui->SetBackgroundMode (false);
#endif
		event.Skip();
	}

	void MainFrame::OnAddAllMountedToFavoritesMenuItemSelected (wxCommandEvent& event)
	{
		AddToFavorites (MountedVolumes);
	}

	void MainFrame::OnAddToFavoritesMenuItemSelected (wxCommandEvent& event)
	{
		shared_ptr <VolumeInfo> selectedVolume = GetSelectedVolume();
		if (selectedVolume)
		{
			VolumeInfoList volumes;
			volumes.push_back (selectedVolume);
			AddToFavorites (volumes);
		}
	}

	void MainFrame::OnBackupVolumeHeadersMenuItemSelected (wxCommandEvent& event)
	{
		if (!CheckVolumePathNotEmpty ())
			return;

		try
		{
			Gui->BackupVolumeHeaders (GetSelectedVolumePath());
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnBenchmarkMenuItemSelected (wxCommandEvent& event)
	{
		BenchmarkDialog dialog (this);
		dialog.ShowModal();
	}

	void MainFrame::OnClearSlotSelectionMenuItemSelected (wxCommandEvent& event)
	{
		Gui->ClearListCtrlSelection (SlotListCtrl);
		UpdateControls();
	}

	void MainFrame::OnClose (wxCloseEvent& event)
	{
		if (GetPreferences().WipeCacheOnClose)
			Core->WipePasswordCache();

#ifdef TC_MACOSX
		if (!event.CanVeto() && GetPreferences().DismountOnLogOff)
		{
			try
			{
				Gui->DismountVolumes (Core->GetMountedVolumes(), GetPreferences().ForceAutoDismount, false);
			}
			catch (...) { }
		}
#endif

		if (!Gui->IsTheOnlyTopLevelWindow (this))
		{
			// Bring first frame to foreground
			wxFrame *frame = nullptr;
			foreach (wxWindow *window, wxTopLevelWindows)
			{
				if (window != this
					&& dynamic_cast <wxFrame *> (window)
					&& StringConverter::GetTypeName (typeid (*window)).find ("wxTaskBarIcon") == string::npos)
				{
					frame = dynamic_cast <wxFrame *> (window);
					if (window->IsShown())
						break;
				}
			}

			if (frame)
			{
				frame->Show();
				if (frame->IsIconized())
					frame->Iconize(false);
				frame->Raise();
			}
		}
		else if (event.CanVeto() && GetPreferences().BackgroundTaskEnabled
			&& (!GetPreferences().CloseBackgroundTaskOnNoVolumes || !MountedVolumes.empty()))
		{
			// Enter background mode
			if (!Gui->IsInBackgroundMode())
				Gui->SetBackgroundMode (true);
		}
		else
		{
#ifdef __WXGTK__
			Show();
#endif
			SavePreferences();

			Destroy();
		}

		 // Cancel close - veto is not used to prevent aborting log off procedure on Windows
		return;
	}

	void MainFrame::OnCloseAllSecurityTokenSessionsMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			{
				wxBusyCursor busy;
				SecurityToken::CloseAllSessions();
			}
			Gui->ShowInfo ("ALL_TOKEN_SESSIONS_CLOSED");
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnCreateVolumeButtonClick (wxCommandEvent& event)
	{
		try
		{
			(new VolumeCreationWizard (nullptr))->Show();
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnDefaultKeyfilesMenuItemSelected (wxCommandEvent& event)
	{
		PreferencesDialog dialog (this);
		dialog.SelectPage (dialog.DefaultKeyfilesPage);
		dialog.ShowModal();
	}

	void MainFrame::OnDeviceChange (const DirectoryPath &mountPoint)
	{
		// Check if any host device has been removed and force dismount of volumes accordingly
		VolumeInfoList removedVolumes;
		foreach (shared_ptr <VolumeInfo> volume, Core->GetMountedVolumes())
		{
			// File-hosted volumes
			if (!volume->Path.IsDevice() && !mountPoint.IsEmpty())
			{
				if (wxString (wstring(volume->Path)).Upper().StartsWith (wstring (mountPoint).c_str()))
				{
					removedVolumes.push_back (volume);
					continue;
				}
			}

			// Device-hosted volumes
			if (volume->Path.IsDevice() && !Core->IsDevicePresent (volume->Path))
				removedVolumes.push_back (volume);
		}
		
		if (!removedVolumes.empty())
			Gui->AutoDismountVolumes (removedVolumes, true);
	}

	void MainFrame::OnDismountAllButtonClick (wxCommandEvent& event)
	{
		Gui->DismountAllVolumes();
	}

	void MainFrame::OnEncryptionTestMenuItemSelected (wxCommandEvent& event)
	{
		EncryptionTestDialog dialog (this);
		dialog.ShowModal();
	}

	void MainFrame::OnExitButtonClick (wxCommandEvent& event)
	{
		Close();
	}

	void MainFrame::OnFavoriteVolumeMenuItemSelected (wxCommandEvent& event)
	{
		FavoriteVolume favorite = FavoriteVolumesMenuMap[event.GetId()];
		if (!favorite.Path.IsEmpty())
		{
			SetVolumePath (favorite.Path);

			MountOptions mountOptions (GetPreferences().DefaultMountOptions);
			favorite.ToMountOptions (mountOptions);

			shared_ptr <VolumeInfo> volume = Gui->MountVolume (mountOptions);
			if (volume)
				SlotListCtrl->EnsureVisible (SlotNumberToItemIndex (volume->SlotNumber));
		}
	}

	void MainFrame::OnHiddenVolumeProtectionTriggered (shared_ptr <VolumeInfo> protectedVolume)
	{
		Gui->ShowWarningTopMost (StringFormatter (LangString["DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"], wstring (protectedVolume->Path)));
	}

	void MainFrame::OnHotkey (wxKeyEvent& event)
	{
#ifdef TC_WINDOWS
		switch (event.GetId())
		{
		case Hotkey::Id::CloseAllSecurityTokenSessions:
			try
			{
				SecurityToken::CloseAllSessions();
				Gui->ShowInfo ("ALL_TOKEN_SESSIONS_CLOSED");
			}
			catch (exception &e) { Gui->ShowError (e); }
			break;

		case Hotkey::Id::DismountAll:
		case Hotkey::Id::DismountAllWipeCache:
			{
				if (event.GetId() == Hotkey::Id::DismountAllWipeCache)
					WipeCache();

				size_t mountedCount = Core->GetMountedVolumes().size();
				Gui->DismountAllVolumes();
				size_t newMountedCount = Core->GetMountedVolumes().size();

				if (newMountedCount < mountedCount)
				{
					if (newMountedCount == 0 && GetPreferences().DisplayMessageAfterHotkeyDismount)
						Gui->ShowInfo ("MOUNTED_VOLUMES_DISMOUNTED");
					else if (GetPreferences().BeepAfterHotkeyMountDismount)
						MessageBeep((UINT) -1);
				}
			}
			break;

		case Hotkey::Id::ForceDismountAllWipeCache:
		case Hotkey::Id::ForceDismountAllWipeCacheExit:
			{
				bool mounted = !Core->GetMountedVolumes().empty();

				WipeCache();
				Gui->DismountAllVolumes (true, true);

				if (mounted && GetPreferences().DisplayMessageAfterHotkeyDismount)
					Gui->ShowInfo ("VOLUMES_DISMOUNTED_CACHE_WIPED");
				else if (mounted && GetPreferences().BeepAfterHotkeyMountDismount)
					MessageBeep((UINT) -1);

				if (event.GetId() == Hotkey::Id::ForceDismountAllWipeCacheExit)
					Close (true);
			}
			break;

		case Hotkey::Id::MountAllDevices:
		case Hotkey::Id::MountAllFavorites:
			{
				size_t mountedCount = Core->GetMountedVolumes().size();
				
				if (event.GetId() == Hotkey::Id::MountAllDevices)
					MountAllDevices();
				else
					MountAllFavorites();

				if (Core->GetMountedVolumes().size() > mountedCount && GetPreferences().BeepAfterHotkeyMountDismount)
					MessageBeep((UINT) -1);
			}
			break;

		case Hotkey::Id::ShowHideApplication:
			Gui->SetBackgroundMode (!Gui->IsInBackgroundMode());
			break;

		case Hotkey::Id::WipeCache:
			WipeCache();
			Gui->ShowInfo ("PASSWORD_CACHE_WIPED");
			break;

		default:
			assert (false);
			break;
		}
#endif // TC_WINDOWS
	}

	void MainFrame::OnHotkeysMenuItemSelected (wxCommandEvent& event)
	{
		PreferencesDialog dialog (this);
		dialog.SelectPage (dialog.HotkeysPage);
		dialog.ShowModal();
	}

	void MainFrame::OnLegalNoticesMenuItemSelected (wxCommandEvent& event)
	{
		LegalNoticesDialog dialog (this);
		dialog.ShowModal();
	}

	void MainFrame::OnListChanged ()
	{
		OnListItemSelectionChanged();
		UpdateControls();
	}

	void MainFrame::OnListItemActivated (wxListEvent& event)
	{
		if (IsMountedSlotSelected())
			OpenSelectedVolume();
		else
			MountVolume();
	}

	void MainFrame::OnListItemDeleted (long itemIndex)
	{
		if (SelectedItemIndex > itemIndex)
			--SelectedItemIndex;
	}
	
	void MainFrame::OnListItemDeselected (wxListEvent& event)
	{
		OnListItemSelectionChanged();
	}

	void MainFrame::OnListItemInserted (long itemIndex)
	{
		if (SelectedItemIndex >= itemIndex)
			++SelectedItemIndex;
	}

	void MainFrame::OnListItemRightClick (wxListEvent& event)
	{
#ifdef TC_MACOSX
		if (SelectedItemIndex != event.GetIndex())
		{
			SelectedItemIndex = event.GetIndex();
			OnListItemSelectionChanged();
		}

		if (!ListItemRightClickEventPending)
		{
			ListItemRightClickEventPending = true;
			SlotListCtrl->AddPendingEvent (event);
			return;
		}

		ListItemRightClickEventPending = false;
#endif

		wxMenu popup;
		if (IsMountedSlotSelected())
		{
			Gui->AppendToMenu (popup, LangString["DISMOUNT"], this, wxCommandEventHandler (MainFrame::OnDismountVolumeMenuItemSelected));
			Gui->AppendToMenu (popup, LangString["OPEN"], this, wxCommandEventHandler (MainFrame::OnOpenVolumeMenuItemSelected));
			Gui->AppendToMenu (popup, _("Deselect"), this, wxCommandEventHandler (MainFrame::OnClearSlotSelectionMenuItemSelected));

			popup.AppendSeparator();
			Gui->AppendToMenu (popup, _("Add to Favorites..."), this, wxCommandEventHandler (MainFrame::OnAddToFavoritesMenuItemSelected));

			popup.AppendSeparator();
			Gui->AppendToMenu (popup, LangString["IDPM_CHECK_FILESYS"], this, wxCommandEventHandler (MainFrame::OnCheckFilesystemMenuItemSelected));
			Gui->AppendToMenu (popup, LangString["IDPM_REPAIR_FILESYS"], this, wxCommandEventHandler (MainFrame::OnRepairFilesystemMenuItemSelected));

			popup.AppendSeparator();
			Gui->AppendToMenu (popup, LangString["IDPM_PROPERTIES"], this, wxCommandEventHandler (MainFrame::OnVolumePropertiesButtonClick));

			PopupMenu (&popup);
		}
		else if (IsFreeSlotSelected())
		{
			Gui->AppendToMenu (popup, _("Mount Volume"), this, wxCommandEventHandler (MainFrame::OnMountVolumeMenuItemSelected));
			
			popup.AppendSeparator();

			Gui->AppendToMenu (popup, LangString["SELECT_FILE_AND_MOUNT"], this, wxCommandEventHandler (MainFrame::OnSelectFileAndMountMenuItemSelected));
			Gui->AppendToMenu (popup, LangString["SELECT_DEVICE_AND_MOUNT"], this, wxCommandEventHandler (MainFrame::OnSelectDeviceAndMountMenuItemSelected));

			popup.AppendSeparator();

			Gui->AppendToMenu (popup, _("Deselect"), this, wxCommandEventHandler (MainFrame::OnClearSlotSelectionMenuItemSelected));

			PopupMenu (&popup);
		}
	}

	void MainFrame::OnListItemSelected (wxListEvent& event)
	{
		SelectedItemIndex = event.GetIndex();
		OnListItemSelectionChanged();
	}
			
	void MainFrame::OnListItemSelectionChanged ()
	{
		if (SlotListCtrl->GetSelectedItemCount() < 1)
			SelectedItemIndex = -1;
		
		if (SelectedItemIndex >= 0)
			SelectedSlotNumber = (VolumeSlotNumber) SlotListCtrl->GetItemData (SelectedItemIndex);
		else
			SelectedSlotNumber = 0;

		UpdateControls();
	}
	
	void MainFrame::OnManageSecurityTokenKeyfilesMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			SecurityTokenKeyfilesDialog dialog (this, false);
			dialog.ShowModal();
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnMountAllDevicesButtonClick (wxCommandEvent& event)
	{
		MountAllDevices();
	}

	void MainFrame::OnMountAllFavoritesMenuItemSelected (wxCommandEvent& event)
	{
		MountAllFavorites();
	}

	void MainFrame::OnNoHistoryCheckBoxClick (wxCommandEvent& event)
	{
		UserPreferences prefs = GetPreferences();
		prefs.SaveHistory = !event.IsChecked();
		Gui->SetPreferences (prefs);

		if (event.IsChecked())
		{
			try
			{
				VolumeHistory::Clear();
			}
			catch (exception &e) { Gui->ShowError (e); }
		}
	}

	void MainFrame::OnOrganizeFavoritesMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			OrganizeFavorites (FavoriteVolume::LoadList());
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnPreferencesMenuItemSelected (wxCommandEvent& event)
	{
		PreferencesDialog dialog (this);
		dialog.ShowModal();
	}

	void MainFrame::OnPreferencesUpdated (EventArgs &args)
	{
		const UserPreferences &prefs = GetPreferences();

		NoHistoryCheckBox->SetValue (!prefs.SaveHistory);

		ShowTaskBarIcon (prefs.BackgroundTaskEnabled);
		if (Gui->IsInBackgroundMode() && !prefs.BackgroundTaskEnabled)
			Close (true);

		SavePreferences();
	}
	
	void MainFrame::OnRestoreVolumeHeaderMenuItemSelected (wxCommandEvent& event)
	{
		if (!CheckVolumePathNotEmpty ())
			return;

		try
		{
			Gui->RestoreVolumeHeaders (GetSelectedVolumePath());
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnSecurityTokenPreferencesMenuItemSelected (wxCommandEvent& event)
	{
		PreferencesDialog dialog (this);
		dialog.SelectPage (dialog.SecurityTokensPage);
		dialog.ShowModal();
	}

	
	void MainFrame::OnSelectDeviceAndMountMenuItemSelected (wxCommandEvent& event)
	{
		DevicePath path = Gui->SelectDevice (this);

		if (!path.IsEmpty())
		{
			SetVolumePath (path);
			OnMountVolumeMenuItemSelected (event);
		}
	}

	void MainFrame::OnSelectDeviceButtonClick (wxCommandEvent& event)
	{
		DevicePath path = Gui->SelectDevice (this);

		if (!path.IsEmpty())
			SetVolumePath (path);
	}

	void MainFrame::OnSelectFileAndMountMenuItemSelected (wxCommandEvent& event)
	{
		FilePath path = Gui->SelectVolumeFile (this);

		if (!path.IsEmpty())
		{
			SetVolumePath (path);
			OnMountVolumeMenuItemSelected (event);
		}
	}

	void MainFrame::OnSelectFileButtonClick (wxCommandEvent& event)
	{
		FilePath path = Gui->SelectVolumeFile (this);
		if (!path.IsEmpty())
			SetVolumePath (path);
	}
	
	void MainFrame::OnTimer ()
	{
		try
		{
			UpdateVolumeList();
			UpdateWipeCacheButton();

			if (GetPreferences().BackgroundTaskEnabled)
			{
				// Inactivity auto-dismount
				if (GetPreferences().DismountOnInactivity)
				{
					VolumeInfoList inactiveVolumes;
					wxLongLong currentTime = wxGetLocalTimeMillis().GetValue();

					map <wstring, VolumeActivityMapEntry> newActivityTimeMap;

					foreach (shared_ptr <VolumeInfo> volume, MountedVolumes)
					{
						if (VolumeActivityMap.find (volume->Path) != VolumeActivityMap.end()
							&& VolumeActivityMap[volume->Path].SerialInstanceNumber == volume->SerialInstanceNumber)
						{
							VolumeActivityMapEntry ae = VolumeActivityMap[volume->Path];

							if (volume->TotalDataRead != ae.TotalDataRead || volume->TotalDataWritten != ae.TotalDataWritten)
							{
								ae.LastActivityTime = currentTime;
								ae.TotalDataRead = volume->TotalDataRead;
								ae.TotalDataWritten = volume->TotalDataWritten;
							}
							else if ((currentTime - ae.LastActivityTime) > GetPreferences().MaxVolumeIdleTime * 1000LL * 60)
							{
								inactiveVolumes.push_back (volume);
							}

							newActivityTimeMap[volume->Path] = ae;
						}
						else
						{
							newActivityTimeMap[volume->Path] = VolumeActivityMapEntry (*volume, currentTime);
						}
					}

					VolumeActivityMap = newActivityTimeMap;

					if (!inactiveVolumes.empty())
						Gui->AutoDismountVolumes (inactiveVolumes);
				}

				// Screen saver auto-dismount
				if (GetPreferences().DismountOnScreenSaver)
				{
#ifdef TC_WINDOWS
					bool running;
					if (SystemParametersInfo (SPI_GETSCREENSAVERRUNNING, 0, &running, 0) != 0)
					{
						static bool previousState = false;
						if (running && !previousState)
						{
							previousState = true;
							Gui->OnAutoDismountAllEvent();
						}
						else
						{
							previousState = running;
						}
					}
#endif
				}
			}

			if (Gui->IsInBackgroundMode())
			{
				if (!GetPreferences().BackgroundTaskEnabled)
				{
					Close (true);
				}
				else if (MountedVolumes.empty() && (GetPreferences().CloseBackgroundTaskOnNoVolumes || Core->IsInPortableMode()))
				{
					Close (true);
				}
			}

#if defined(TC_UNIX) && !defined(TC_MACOSX)
			try
			{
				byte buf[128];
				if (read (ShowRequestFifo, buf, sizeof (buf)) > 0 && Gui->IsInBackgroundMode())
					Gui->SetBackgroundMode (false);
			}
			catch (...)
			{
#ifdef DEBUG
				throw;
#endif
			}
#endif
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void MainFrame::OnVolumeButtonClick (wxCommandEvent& event)
	{
		if (IsMountedSlotSelected())
			DismountVolume();
		else
			MountVolume();
	}

	void MainFrame::OnVolumePropertiesButtonClick (wxCommandEvent& event)
	{
		shared_ptr <VolumeInfo> selectedVolume = GetSelectedVolume();
		if (selectedVolume)
		{
			VolumePropertiesDialog dialog (this, *selectedVolume);
			dialog.ShowModal();
		}
	}

	void MainFrame::OnVolumeToolsButtonClick (wxCommandEvent& event)
	{
		if (!CheckVolumePathNotEmpty())
			return;

		wxMenu popup;

		Gui->AppendToMenu (popup, _("Change Volume Password..."), this, wxCommandEventHandler (MainFrame::OnChangePasswordMenuItemSelected));

		popup.AppendSeparator ();

		Gui->AppendToMenu (popup, _("Add/Remove Keyfiles to/from Volume..."), this, wxCommandEventHandler (MainFrame::OnChangeKeyfilesMenuItemSelected));
		Gui->AppendToMenu (popup, _("Remove All Keyfiles from Volume..."), this, wxCommandEventHandler (MainFrame::OnRemoveKeyfilesMenuItemSelected));

		popup.AppendSeparator ();

		Gui->AppendToMenu (popup, _("Change Header Key Derivation Algorithm..."), this, wxCommandEventHandler (MainFrame::OnChangePkcs5PrfMenuItemSelected));

		popup.AppendSeparator ();

		Gui->AppendToMenu (popup, _("Backup Volume Header..."), this, wxCommandEventHandler (MainFrame::OnBackupVolumeHeadersMenuItemSelected));
		Gui->AppendToMenu (popup, _("Restore Volume Header..."), this, wxCommandEventHandler (MainFrame::OnRestoreVolumeHeaderMenuItemSelected));

		PopupMenu (&popup, VolumeToolsButton->GetPosition().x + 2, VolumeToolsButton->GetPosition().y + 2);
	}

	void MainFrame::OnWipeCacheButtonClick (wxCommandEvent& event)
	{
		WipeCache();
		Gui->ShowInfo ("PASSWORD_CACHE_WIPED");
	}
	
	void MainFrame::OpenSelectedVolume () const
	{
		shared_ptr <VolumeInfo> selectedVolume = GetSelectedVolume();
		if (selectedVolume)
		{
			try
			{
				wxBusyCursor busy;
				Gui->OpenExplorerWindow (selectedVolume->MountPoint);
			}
			catch (exception &e)
			{
				Gui->ShowError (e);
			}
		}
	}

	void MainFrame::OrganizeFavorites (const FavoriteVolumeList &favorites, size_t newItemCount)
	{
		FavoriteVolumesDialog dialog (this, favorites, newItemCount);

		if (dialog.ShowModal() == wxID_OK)
		{
			FavoriteVolume::SaveList (dialog.GetFavorites());
			LoadFavoriteVolumes();
		}
	}

	void MainFrame::SavePreferences () const
	{
		try
		{
			UserPreferences prefs = GetPreferences();
			prefs.LastSelectedSlotNumber = SelectedSlotNumber;
			prefs.Save();

			VolumeHistory::Save();
		}
		catch (exception &e)
		{
			if (!Core->IsInPortableMode())
				Gui->ShowError (e);
		}
	}

	void MainFrame::ShowTaskBarIcon (bool show)
	{
		if (!show && mTaskBarIcon->IsIconInstalled())
		{
			mTaskBarIcon->RemoveIcon();
		}
		else if (show && !mTaskBarIcon->IsIconInstalled())
		{
#ifndef TC_MACOSX
			mTaskBarIcon->SetIcon (Resources::GetTrueCryptIcon(), L"VeraCrypt");
#endif
		}
	}

	long MainFrame::SlotNumberToItemIndex (uint32 slotNumber) const
	{
		for (long itemIndex = 0; itemIndex < SlotListCtrl->GetItemCount(); itemIndex++)
		{
			wxListItem item;
			item.SetId (itemIndex);
			if (slotNumber == (uint32) SlotListCtrl->GetItemData (item))
				return itemIndex;
		}
		return -1;
	}
	
	void MainFrame::UpdateControls ()
	{
		bool mounted = IsMountedSlotSelected();

		VolumeButton->SetLabel (mounted ? LangString["DISMOUNT"] : wxString (_("Mount")));
		VolumePropertiesButton->Enable (mounted);

		DismountVolumeMenuItem->Enable (mounted); 
		MountVolumeMenuItem->Enable (!mounted);
		VolumePropertiesMenuItem->Enable (mounted);
		AddToFavoritesMenuItem->Enable (mounted);
		AddAllMountedToFavoritesMenuItem->Enable (!MountedVolumes.empty());
		UpdateWipeCacheButton();
	}

	void MainFrame::UpdateVolumeList ()
	{
		static Mutex mutex;
		ScopeLock lock (mutex);

		bool listChanged = false;

		MountedVolumes = Core->GetMountedVolumes();
		
		map < VolumeSlotNumber, shared_ptr <VolumeInfo> > mountedVolumesMap;
		foreach (shared_ptr <VolumeInfo> volume, MountedVolumes)
		{
			mountedVolumesMap[volume->SlotNumber] = volume;
		}

		VolumeInfoList protectionTriggeredVolumes;

		// Update list
		long prevItemIndex = -1;
		for (VolumeSlotNumber slotNumber = Core->GetFirstSlotNumber(); slotNumber <= Core->GetLastSlotNumber(); ++slotNumber)
		{
			long itemIndex = SlotNumberToItemIndex (slotNumber);
			vector <wstring> fields (SlotListCtrl->GetColumnCount());

			if (mountedVolumesMap.find (slotNumber) != mountedVolumesMap.end())
			{
				shared_ptr <VolumeInfo> volume = mountedVolumesMap[slotNumber];

#ifdef TC_WINDOWS
				fields[ColumnSlot] = volume->MountPoint;
				fields[ColumnEA] = volume->EncryptionAlgorithmName;
#else
				fields[ColumnSlot] = StringConverter::FromNumber (slotNumber);
				fields[ColumnMountPoint] = volume->MountPoint;
#endif
				fields[ColumnPath] = volume->Path;
				fields[ColumnSize] = Gui->SizeToString (volume->Size);
				fields[ColumnType] = Gui->VolumeTypeToString (volume->Type, volume->Protection);
				
				if (volume->HiddenVolumeProtectionTriggered)
				{
					fields[ColumnType] += L"(!)";
				}

				bool slotUpdated = false;
				if (itemIndex == -1)
				{
					Gui->InsertToListCtrl (SlotListCtrl, ++prevItemIndex, fields, 0, (void *) volume->SlotNumber);
					OnListItemInserted (prevItemIndex);

					listChanged |= true;
					slotUpdated = true;
				}
				else
				{
					if (Gui->UpdateListCtrlItem (SlotListCtrl, itemIndex, fields))
					{
						listChanged = true;
						slotUpdated = true;
					}
					prevItemIndex = itemIndex;
				}

				if (slotUpdated && volume->HiddenVolumeProtectionTriggered)
					protectionTriggeredVolumes.push_back (volume);
			}
			else
			{
#ifdef TC_WINDOWS
				fields[ColumnSlot] = Core->SlotNumberToMountPoint (slotNumber);
#else
				fields[ColumnSlot] = StringConverter::FromNumber (slotNumber);
#endif
				
#ifdef TC_WINDOWS
				if (Core->IsMountPointAvailable (fields[ColumnSlot]))
#else
				if (true)
#endif
				{
					if (itemIndex == -1)
					{
						Gui->InsertToListCtrl (SlotListCtrl, ++prevItemIndex, fields, 0, (void *) slotNumber);
						OnListItemInserted (prevItemIndex);
						listChanged |= true;
					}
					else
					{
						listChanged |= Gui->UpdateListCtrlItem (SlotListCtrl, itemIndex, fields);
						prevItemIndex = itemIndex;
					}
				}
				else if (itemIndex != -1)
				{
					SlotListCtrl->DeleteItem (itemIndex);
					OnListItemDeleted (itemIndex);
					listChanged = true;
				}
			}
		}

		if (listChanged)
			OnListChanged();

		foreach (shared_ptr <VolumeInfo> volume, protectionTriggeredVolumes)
			OnHiddenVolumeProtectionTriggered (volume);
	}

	void MainFrame::UpdateWipeCacheButton ()
	{
		bool enabled = WipeCacheButton->IsEnabled();
		bool empty = Core->IsPasswordCacheEmpty();

		if (empty && enabled)
		{
			WipeCacheButton->Disable();
			WipeCachedPasswordsMenuItem->Enable (false);
		}
		else if (!empty && !enabled)
		{
			WipeCacheButton->Enable();
			WipeCachedPasswordsMenuItem->Enable();
		}
	}

	void MainFrame::WipeCache ()
	{
		Core->WipePasswordCache();
		UpdateWipeCacheButton();
	}
}
