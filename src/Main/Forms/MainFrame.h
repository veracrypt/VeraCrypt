/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_MainFrame
#define TC_HEADER_Main_Forms_MainFrame

#include "Forms.h"
#include "ChangePasswordDialog.h"

namespace TrueCrypt
{
	struct FavoriteVolume;

	class MainFrame : public MainFrameBase
	{
	public:
		MainFrame (wxWindow* parent);
		virtual ~MainFrame ();

		void OnDeviceChange (const DirectoryPath &mountPoint = DirectoryPath());
#ifdef TC_UNIX
		static FilePath GetShowRequestFifoPath () { return Application::GetConfigFilePath (L".show-request-queue", true); }
#endif

	protected:
		enum
		{
			ColumnSlot = 0,
			ColumnPath,
			ColumnSize,
#ifdef TC_WINDOWS
			ColumnEA,
#else
			ColumnMountPoint,
#endif
			ColumnType
		};

		void AddToFavorites (const VolumeInfoList &volumes);
		bool CanExit () const;
		void ChangePassword (ChangePasswordDialog::Mode::Enum mode = ChangePasswordDialog::Mode::ChangePasswordAndKeyfiles);
		void CheckFilesystem (bool repair = false);
		bool CheckVolumePathNotEmpty () const;
		void DismountVolume (shared_ptr <VolumeInfo> volume = shared_ptr <VolumeInfo> ());
		const UserPreferences &GetPreferences () const { return Gui->GetPreferences(); }
		shared_ptr <VolumeInfo> GetSelectedVolume () const;
		shared_ptr <VolumePath> GetSelectedVolumePath () const { return make_shared <VolumePath> (wstring (VolumePathComboBox->GetValue())); }
		void InitControls ();
		void InitEvents ();
		void InitMessageFilter ();
		void InitPreferences ();
		void InitTaskBarIcon ();
		bool IsFreeSlotSelected () const { return SlotListCtrl->GetSelectedItemCount() == 1 && Gui->GetListCtrlSubItemText (SlotListCtrl, SelectedItemIndex, ColumnPath).empty(); }
		bool IsMountedSlotSelected () const { return SlotListCtrl->GetSelectedItemCount() == 1 && !Gui->GetListCtrlSubItemText (SlotListCtrl, SelectedItemIndex, ColumnPath).empty(); }
		void LoadFavoriteVolumes ();
		void LoadPreferences ();
		void MountAllDevices ();
		void MountAllFavorites ();
		void MountVolume ();
		void OnAboutMenuItemSelected (wxCommandEvent& event);
		void OnActivate (wxActivateEvent& event);
		void OnAddAllMountedToFavoritesMenuItemSelected (wxCommandEvent& event);
		void OnAddToFavoritesMenuItemSelected (wxCommandEvent& event);
		void OnBackupVolumeHeadersMenuItemSelected (wxCommandEvent& event);
		void OnBeginnersTutorialMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"tutorial"); }
		void OnBenchmarkMenuItemSelected (wxCommandEvent& event);
		void OnChangeKeyfilesMenuItemSelected (wxCommandEvent& event) { ChangePassword (ChangePasswordDialog::Mode::ChangeKeyfiles); }
		void OnChangePasswordMenuItemSelected (wxCommandEvent& event) { ChangePassword (); }
		void OnChangePkcs5PrfMenuItemSelected (wxCommandEvent& event) { ChangePassword (ChangePasswordDialog::Mode::ChangePkcs5Prf); }
		void OnCheckFilesystemMenuItemSelected( wxCommandEvent& event ) { CheckFilesystem (); }
		void OnClearSlotSelectionMenuItemSelected (wxCommandEvent& event);
		void OnClose (wxCloseEvent& event);
		void OnCloseAllSecurityTokenSessionsMenuItemSelected (wxCommandEvent& event);
		void OnContactMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"contact"); }
		void OnCreateKeyfileMenuItemSelected (wxCommandEvent& event) { Gui->CreateKeyfile(); }
		void OnCreateVolumeButtonClick (wxCommandEvent& event);
		void OnDefaultKeyfilesMenuItemSelected (wxCommandEvent& event);
		void OnDismountAllButtonClick (wxCommandEvent& event);
		void OnDismountVolumeMenuItemSelected (wxCommandEvent& event) { DismountVolume(); }
		void OnDownloadsMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"downloads"); }
		void OnEncryptionTestMenuItemSelected (wxCommandEvent& event);
		void OnExitButtonClick (wxCommandEvent& event);
		void OnFavoriteVolumeMenuItemSelected (wxCommandEvent& event);
		void OnFaqMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"faq"); }
		void OnHiddenVolumeProtectionTriggered (shared_ptr <VolumeInfo> protectedVolume);
		void OnHotkey (wxKeyEvent& event);
		void OnHotkeysMenuItemSelected (wxCommandEvent& event);
		void OnLegalNoticesMenuItemSelected (wxCommandEvent& event);
		void OnListChanged ();
		void OnListItemActivated (wxListEvent& event);
		void OnListItemDeleted (long itemIndex);
		void OnListItemDeselected (wxListEvent& event);
		void OnListItemInserted (long itemIndex);
		void OnListItemRightClick (wxListEvent& event);
		void OnListItemSelected (wxListEvent& event);
		void OnListItemSelectionChanged ();
		void OnLogoBitmapClick (wxMouseEvent &event) { wxCommandEvent ev; OnAboutMenuItemSelected (ev); }
		void OnManageSecurityTokenKeyfilesMenuItemSelected (wxCommandEvent& event);
		void OnMountAllDevicesButtonClick (wxCommandEvent& event);
		void OnMountAllFavoritesMenuItemSelected (wxCommandEvent& event);
		void OnMountVolumeMenuItemSelected (wxCommandEvent& event) { MountVolume(); }
		void OnNewsMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"news"); }
		void OnNoHistoryCheckBoxClick (wxCommandEvent& event);
		void OnOnlineHelpMenuItemSelected (wxCommandEvent& event) { Gui->OpenOnlineHelp (this); }
		void OnOpenVolumeMenuItemSelected (wxCommandEvent& event) { OpenSelectedVolume(); }
		void OnOpenVolumeSystemRequestEvent (EventArgs &args) { SetVolumePath (wstring (dynamic_cast <OpenVolumeSystemRequestEventArgs &> (args).mVolumePath)); }
		void OnOrganizeFavoritesMenuItemSelected (wxCommandEvent& event);
		void OnPreferencesMenuItemSelected (wxCommandEvent& event);
		void OnPreferencesUpdated (EventArgs &args);
		void OnRemoveKeyfilesMenuItemSelected (wxCommandEvent& event) { ChangePassword (ChangePasswordDialog::Mode::RemoveAllKeyfiles); }
		void OnRepairFilesystemMenuItemSelected( wxCommandEvent& event ) { CheckFilesystem (true); }
		void OnRestoreVolumeHeaderMenuItemSelected (wxCommandEvent& event);
		void OnSecurityTokenPreferencesMenuItemSelected (wxCommandEvent& event);
		void OnSelectDeviceAndMountMenuItemSelected (wxCommandEvent& event);
		void OnSelectDeviceButtonClick (wxCommandEvent& event);
		void OnSelectFileAndMountMenuItemSelected (wxCommandEvent& event);
		void OnSelectFileButtonClick (wxCommandEvent& event);
		void OnTimer ();
		void OnVersionHistoryMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"history"); }
		void OnVolumePropertiesButtonClick (wxCommandEvent& event);
		void OnVolumeToolsButtonClick (wxCommandEvent& event);
		void OnVolumeButtonClick (wxCommandEvent& event);
		void OnVolumeDismounted (EventArgs &args) { UpdateVolumeList(); }
		void OnVolumeMounted (EventArgs &args) { UpdateVolumeList(); }
		void OnUserGuideMenuItemSelected (wxCommandEvent& event) { Gui->OpenUserGuide (this); }
		void OnWebsiteMenuItemSelected (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"website"); }
		void OnWipeCacheButtonClick (wxCommandEvent& event);
		void OrganizeFavorites (const FavoriteVolumeList &favorites, size_t newItemCount = 0);
		void OpenSelectedVolume () const;
		void SavePreferences () const;
		long SlotNumberToItemIndex (uint32 slotNumber) const;
		void SetVolumePath (const VolumePath &path) { VolumePathComboBox->SetValue (wstring (path)); }
		void ShowTaskBarIcon (bool show = true);
		void UpdateControls ();
		void UpdateVolumeList ();
		void UpdateWipeCacheButton ();
		void WipeCache ();
	
		struct VolumeActivityMapEntry
		{
			VolumeActivityMapEntry () { }

			VolumeActivityMapEntry (const VolumeInfo &volume, wxLongLong lastActivityTime)
				: LastActivityTime (lastActivityTime),
				SerialInstanceNumber (volume.SerialInstanceNumber),
				TotalDataRead (volume.TotalDataRead),
				TotalDataWritten (volume.TotalDataWritten)
			{ }

			wxLongLong LastActivityTime;
			uint64 SerialInstanceNumber;
			uint64 TotalDataRead;
			uint64 TotalDataWritten;
		};

		map <int, FavoriteVolume> FavoriteVolumesMenuMap;
		bool ListItemRightClickEventPending;
		VolumeInfoList MountedVolumes;
		auto_ptr <wxTaskBarIcon> mTaskBarIcon;
		auto_ptr <wxTimer> mTimer;
		long SelectedItemIndex;
		VolumeSlotNumber SelectedSlotNumber;
		int ShowRequestFifo;
		map <wstring, VolumeActivityMapEntry> VolumeActivityMap;
	};
}

#endif // TC_HEADER_Main_Forms_MainFrame
