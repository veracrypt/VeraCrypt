///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __Forms__
#define __Forms__

#include <wx/intl.h>

class WizardPage;

#include "WizardPage.h"
#include <wx/string.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/menu.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/listctrl.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/button.h>
#include <wx/statbmp.h>
#include <wx/combobox.h>
#include <wx/checkbox.h>
#include <wx/gbsizer.h>
#include <wx/panel.h>
#include <wx/frame.h>
#include <wx/stattext.h>
#include <wx/hyperlink.h>
#include <wx/statline.h>
#include <wx/textctrl.h>
#include <wx/dialog.h>
#include <wx/choice.h>
#include <wx/spinctrl.h>
#include <wx/notebook.h>
#include <wx/gauge.h>

///////////////////////////////////////////////////////////////////////////

namespace TrueCrypt
{
	///////////////////////////////////////////////////////////////////////////////
	/// Class MainFrameBase
	///////////////////////////////////////////////////////////////////////////////
	class MainFrameBase : public wxFrame 
	{
		private:
		
		protected:
			wxMenuBar* MainMenuBar;
			wxMenu* VolumesMenu;
			wxMenuItem* MountVolumeMenuItem;
			wxMenuItem* DismountVolumeMenuItem;
			wxMenuItem* DismountAllMenuItem;
			wxMenuItem* VolumePropertiesMenuItem;
			wxMenu* FavoritesMenu;
			wxMenuItem* AddToFavoritesMenuItem;
			wxMenuItem* AddAllMountedToFavoritesMenuItem;
			wxMenu* ToolsMenu;
			wxMenuItem* BackupVolumeHeadersMenuItem;
			wxMenuItem* RestoreVolumeHeaderMenuItem;
			wxMenuItem* WipeCachedPasswordsMenuItem;
			wxMenu* SettingsMenu;
			wxMenuItem* HotkeysMenuItem;
			wxMenuItem* PreferencesMenuItem;
			wxMenu* HelpMenu;
			wxPanel* MainPanel;
			wxListCtrl* SlotListCtrl;
			wxStaticBoxSizer* LowStaticBoxSizer;
			wxBoxSizer* HigherButtonSizer;
			wxButton* CreateVolumeButton;
			wxButton* VolumePropertiesButton;
			wxButton* WipeCacheButton;
			
			wxStaticBoxSizer* VolumeStaticBoxSizer;
			wxGridBagSizer* VolumeGridBagSizer;
			wxStaticBitmap* LogoBitmap;
			wxComboBox* VolumePathComboBox;
			wxButton* SelectFileButton;
			wxCheckBox* NoHistoryCheckBox;
			wxButton* VolumeToolsButton;
			wxButton* SelectDeviceButton;
			
			wxButton* VolumeButton;
			wxButton* MountAllDevicesButton;
			wxButton* DismountAllButton;
			wxButton* ExitButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnActivate( wxActivateEvent& event ){ event.Skip(); }
			virtual void OnClose( wxCloseEvent& event ){ event.Skip(); }
			virtual void OnCreateVolumeButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnMountVolumeMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnMountAllDevicesButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDismountVolumeMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDismountAllButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnChangePasswordMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnChangePkcs5PrfMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnChangeKeyfilesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveKeyfilesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnVolumePropertiesButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAddToFavoritesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAddAllMountedToFavoritesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOrganizeFavoritesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnMountAllFavoritesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnBenchmarkMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnEncryptionTestMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnBackupVolumeHeadersMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRestoreVolumeHeaderMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnCreateKeyfileMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnManageSecurityTokenKeyfilesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnCloseAllSecurityTokenSessionsMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnWipeCacheButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnHotkeysMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDefaultKeyfilesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnSecurityTokenPreferencesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnPreferencesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnUserGuideMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOnlineHelpMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnBeginnersTutorialMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnFaqMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnWebsiteMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDownloadsMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNewsMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnVersionHistoryMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnContactMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnLegalNoticesMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAboutMenuItemSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnListItemActivated( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemRightClick( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemSelected( wxListEvent& event ){ event.Skip(); }
			virtual void OnLogoBitmapClick( wxMouseEvent& event ){ event.Skip(); }
			virtual void OnSelectFileButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNoHistoryCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnVolumeToolsButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnSelectDeviceButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnVolumeButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnExitButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			MainFrameBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("VeraCrypt"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,496 ), long style = wxCAPTION|wxCLOSE_BOX|wxMINIMIZE_BOX|wxSYSTEM_MENU|wxTAB_TRAVERSAL );
			~MainFrameBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class WizardFrameBase
	///////////////////////////////////////////////////////////////////////////////
	class WizardFrameBase : public wxFrame 
	{
		private:
		
		protected:
			wxPanel* MainPanel;
			wxStaticBitmap* WizardBitmap;
			wxStaticText* PageTitleStaticText;
			wxBoxSizer* PageSizer;
			
			wxButton* HelpButton;
			
			wxButton* PreviousButton;
			wxButton* NextButton;
			
			wxButton* CancelButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnActivate( wxActivateEvent& event ){ event.Skip(); }
			virtual void OnClose( wxCloseEvent& event ){ event.Skip(); }
			virtual void OnMouseMotion( wxMouseEvent& event ){ event.Skip(); }
			virtual void OnHelpButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnPreviousButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNextButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnCancelButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			WizardFrameBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxCAPTION|wxCLOSE_BOX|wxMINIMIZE_BOX|wxSYSTEM_MENU|wxTAB_TRAVERSAL );
			~WizardFrameBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class AboutDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class AboutDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxPanel* m_panel14;
			
			wxStaticBitmap* LogoBitmap;
			wxStaticText* VersionStaticText;
			
			wxStaticText* CopyrightStaticText;
			
			wxHyperlinkCtrl* WebsiteHyperlink;
			wxStaticLine* m_staticline3;
			wxTextCtrl* CreditsTextCtrl;
			
			wxStaticLine* m_staticline4;
			wxStaticLine* m_staticline5;
			
			
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnWebsiteHyperlinkClick( wxHyperlinkEvent& event ){ event.Skip(); }
			
		
		public:
			AboutDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~AboutDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class BenchmarkDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class BenchmarkDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxChoice* BufferSizeChoice;
			wxListCtrl* BenchmarkListCtrl;
			wxBoxSizer* RightSizer;
			wxButton* BenchmarkButton;
			
			wxStaticText* BenchmarkNoteStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnBenchmarkButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			BenchmarkDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("VeraCrypt - Encryption Algorithm Benchmark"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~BenchmarkDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class ChangePasswordDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class ChangePasswordDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxStaticBoxSizer* CurrentSizer;
			wxBoxSizer* CurrentPasswordPanelSizer;
			wxStaticBoxSizer* NewSizer;
			wxBoxSizer* NewPasswordPanelSizer;
			wxButton* OKButton;
			wxButton* CancelButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnOKButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			ChangePasswordDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~ChangePasswordDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class DeviceSelectionDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class DeviceSelectionDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxListCtrl* DeviceListCtrl;
			wxStdDialogButtonSizer* StdButtons;
			wxButton* StdButtonsOK;
			wxButton* StdButtonsCancel;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnListItemActivated( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemSelected( wxListEvent& event ){ event.Skip(); }
			
		
		public:
			DeviceSelectionDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Select a Partition or Device"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxDEFAULT_DIALOG_STYLE );
			~DeviceSelectionDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class EncryptionTestDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class EncryptionTestDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxChoice* EncryptionAlgorithmChoice;
			wxCheckBox* XtsModeCheckBox;
			wxTextCtrl* KeyTextCtrl;
			wxStaticText* KeySizeStaticText;
			wxTextCtrl* SecondaryKeyTextCtrl;
			wxTextCtrl* DataUnitNumberTextCtrl;
			wxTextCtrl* BlockNumberTextCtrl;
			wxTextCtrl* PlainTextTextCtrl;
			wxTextCtrl* CipherTextTextCtrl;
			wxButton* EncryptButton;
			wxButton* DecryptButton;
			wxButton* AutoTestAllButton;
			wxButton* ResetButton;
			wxButton* CloseButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnEncryptionAlgorithmSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnXtsModeCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnEncryptButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDecryptButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAutoTestAllButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnResetButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			EncryptionTestDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("VeraCrypt - Test Vectors"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~EncryptionTestDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class FavoriteVolumesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class FavoriteVolumesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxListCtrl* FavoritesListCtrl;
			wxButton* MoveUpButton;
			wxButton* MoveDownButton;
			wxButton* RemoveButton;
			wxButton* RemoveAllButton;
			
			wxButton* OKButton;
			wxButton* CancelButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemSelected( wxListEvent& event ){ event.Skip(); }
			virtual void OnMoveUpButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnMoveDownButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveAllButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOKButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			FavoriteVolumesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Favorite Volumes"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~FavoriteVolumesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class KeyfilesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class KeyfilesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxBoxSizer* UpperSizer;
			wxBoxSizer* PanelSizer;
			wxButton* OKButton;
			wxButton* CancelButton;
			wxStaticText* WarningStaticText;
			wxBoxSizer* KeyfilesNoteSizer;
			wxStaticText* KeyfilesNoteStaticText;
			wxHyperlinkCtrl* KeyfilesHyperlink;
			wxButton* CreateKeyfileButtton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnKeyfilesHyperlinkClick( wxHyperlinkEvent& event ){ event.Skip(); }
			virtual void OnCreateKeyfileButttonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			KeyfilesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Select Keyfiles"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~KeyfilesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class KeyfileGeneratorDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class KeyfileGeneratorDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxBoxSizer* MainSizer;
			
			wxChoice* HashChoice;
			
			wxStaticText* RandomPoolStaticText;
			wxCheckBox* ShowRandomPoolCheckBox;
			
			wxStaticText* MouseStaticText;
			
			wxButton* GenerateButton;
			
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnMouseMotion( wxMouseEvent& event ){ event.Skip(); }
			virtual void OnHashSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnShowRandomPoolCheckBoxClicked( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnGenerateButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			KeyfileGeneratorDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~KeyfileGeneratorDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class LegalNoticesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class LegalNoticesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxTextCtrl* LegalNoticesTextCtrl;
		
		public:
			LegalNoticesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("VeraCrypt - Legal Notices"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~LegalNoticesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class MountOptionsDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class MountOptionsDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxBoxSizer* PasswordSizer;
			wxButton* OKButton;
			wxButton* CancelButton;
			
			wxButton* OptionsButton;
			wxPanel* OptionsPanel;
			wxStaticBoxSizer* OptionsSizer;
			
			wxCheckBox* ReadOnlyCheckBox;
			wxCheckBox* RemovableCheckBox;
			wxCheckBox* PartitionInSystemEncryptionScopeCheckBox;
			wxStaticBoxSizer* ProtectionSizer;
			wxCheckBox* ProtectionCheckBox;
			wxBoxSizer* ProtectionPasswordSizer;
			wxHyperlinkCtrl* ProtectionHyperlinkCtrl;
			wxBoxSizer* FilesystemSizer;
			wxPanel* m_panel8;
			wxCheckBox* NoFilesystemCheckBox;
			wxGridBagSizer* FilesystemOptionsSizer;
			wxBoxSizer* FilesystemSpacer;
			wxStaticText* MountPointTextCtrlStaticText;
			wxTextCtrl* MountPointTextCtrl;
			wxButton* MountPointButton;
			wxStaticText* FilesystemOptionsStaticText;
			wxTextCtrl* FilesystemOptionsTextCtrl;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnInitDialog( wxInitDialogEvent& event ){ event.Skip(); }
			virtual void OnOKButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOptionsButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnReadOnlyCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnProtectionCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnProtectionHyperlinkClick( wxHyperlinkEvent& event ){ event.Skip(); }
			virtual void OnNoFilesystemCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnMountPointButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			MountOptionsDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Enter VeraCrypt Volume Password"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxDEFAULT_DIALOG_STYLE );
			~MountOptionsDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class NewSecurityTokenKeyfileDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class NewSecurityTokenKeyfileDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxChoice* SecurityTokenChoice;
			wxTextCtrl* KeyfileNameTextCtrl;
			wxStdDialogButtonSizer* StdButtons;
			wxButton* StdButtonsOK;
			wxButton* StdButtonsCancel;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnKeyfileNameChanged( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			NewSecurityTokenKeyfileDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("New Security Token Keyfile Properties"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~NewSecurityTokenKeyfileDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class PreferencesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class PreferencesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxNotebook* PreferencesNotebook;
			wxPanel* SecurityPage;
			wxStaticBoxSizer* AutoDismountSizer;
			wxCheckBox* DismountOnLogOffCheckBox;
			wxCheckBox* DismountOnScreenSaverCheckBox;
			wxCheckBox* DismountOnPowerSavingCheckBox;
			wxCheckBox* DismountOnInactivityCheckBox;
			wxSpinCtrl* DismountOnInactivitySpinCtrl;
			wxCheckBox* ForceAutoDismountCheckBox;
			wxStaticBoxSizer* FilesystemSecuritySizer;
			wxCheckBox* PreserveTimestampsCheckBox;
			wxCheckBox* WipeCacheOnCloseCheckBox;
			wxCheckBox* WipeCacheOnAutoDismountCheckBox;
			wxPanel* DefaultMountOptionsPage;
			wxCheckBox* MountReadOnlyCheckBox;
			wxCheckBox* MountRemovableCheckBox;
			wxCheckBox* CachePasswordsCheckBox;
			wxStaticBoxSizer* FilesystemSizer;
			wxTextCtrl* FilesystemOptionsTextCtrl;
			wxPanel* BackgroundTaskPanel;
			wxCheckBox* BackgroundTaskEnabledCheckBox;
			wxCheckBox* CloseBackgroundTaskOnNoVolumesCheckBox;
			wxCheckBox* BackgroundTaskMenuMountItemsEnabledCheckBox;
			wxCheckBox* BackgroundTaskMenuOpenItemsEnabledCheckBox;
			wxCheckBox* BackgroundTaskMenuDismountItemsEnabledCheckBox;
			wxPanel* SystemIntegrationPage;
			wxStaticBoxSizer* LogOnSizer;
			wxCheckBox* StartOnLogonCheckBox;
			wxCheckBox* MountFavoritesOnLogonCheckBox;
			wxCheckBox* MountDevicesOnLogonCheckBox;
			wxStaticBoxSizer* ExplorerSizer;
			wxCheckBox* OpenExplorerWindowAfterMountCheckBox;
			wxCheckBox* CloseExplorerWindowsOnDismountCheckBox;
			wxStaticBoxSizer* KernelServicesSizer;
			wxCheckBox* NoKernelCryptoCheckBox;
			wxPanel* PerformanceOptionsPage;
			wxStaticText* AesHwCpuSupportedStaticText;
			
			wxCheckBox* NoHardwareCryptoCheckBox;
			wxBoxSizer* DefaultKeyfilesSizer;
			wxCheckBox* UseKeyfilesCheckBox;
			wxTextCtrl* Pkcs11ModulePathTextCtrl;
			wxButton* SelectPkcs11ModuleButton;
			wxCheckBox* CloseSecurityTokenSessionsAfterMountCheckBox;
			wxListCtrl* HotkeyListCtrl;
			wxTextCtrl* HotkeyTextCtrl;
			wxButton* AssignHotkeyButton;
			
			wxCheckBox* HotkeyControlCheckBox;
			wxCheckBox* HotkeyShiftCheckBox;
			wxCheckBox* HotkeyAltCheckBox;
			wxCheckBox* HotkeyWinCheckBox;
			wxButton* RemoveHotkeyButton;
			wxCheckBox* BeepAfterHotkeyMountDismountCheckBox;
			wxCheckBox* DisplayMessageAfterHotkeyDismountCheckBox;
			wxStdDialogButtonSizer* StdButtons;
			wxButton* StdButtonsOK;
			wxButton* StdButtonsCancel;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnClose( wxCloseEvent& event ){ event.Skip(); }
			virtual void OnDismountOnScreenSaverCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDismountOnPowerSavingCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnForceAutoDismountCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnPreserveTimestampsCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnBackgroundTaskEnabledCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNoKernelCryptoCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNoHardwareCryptoCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnSelectPkcs11ModuleButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnHotkeyListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnHotkeyListItemSelected( wxListEvent& event ){ event.Skip(); }
			virtual void OnAssignHotkeyButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveHotkeyButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnCancelButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOKButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			wxPanel* DefaultKeyfilesPage;
			wxPanel* SecurityTokensPage;
			wxPanel* HotkeysPage;
			PreferencesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Preferences"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~PreferencesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class RandomPoolEnrichmentDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class RandomPoolEnrichmentDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxBoxSizer* MainSizer;
			
			wxChoice* HashChoice;
			
			wxStaticText* RandomPoolStaticText;
			wxCheckBox* ShowRandomPoolCheckBox;
			
			wxStaticText* MouseStaticText;
			
			
			wxButton* ContinueButton;
			
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnMouseMotion( wxMouseEvent& event ){ event.Skip(); }
			virtual void OnHashSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnShowRandomPoolCheckBoxClicked( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			RandomPoolEnrichmentDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("VeraCrypt - Random Pool Enrichment"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~RandomPoolEnrichmentDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class SecurityTokenKeyfilesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class SecurityTokenKeyfilesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxListCtrl* SecurityTokenKeyfileListCtrl;
			wxButton* ExportButton;
			wxButton* DeleteButton;
			
			wxButton* ImportButton;
			wxButton* OKButton;
			wxButton* CancelButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnListItemActivated( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemSelected( wxListEvent& event ){ event.Skip(); }
			virtual void OnExportButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDeleteButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnImportButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnOKButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			SecurityTokenKeyfilesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Security Token Keyfiles"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxDEFAULT_DIALOG_STYLE );
			~SecurityTokenKeyfilesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumePropertiesDialogBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumePropertiesDialogBase : public wxDialog 
	{
		private:
		
		protected:
			wxListCtrl* PropertiesListCtrl;
			wxStdDialogButtonSizer* StdButtons;
			wxButton* StdButtonsOK;
		
		public:
			VolumePropertiesDialogBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Volume Properties"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE );
			~VolumePropertiesDialogBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class EncryptionOptionsWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class EncryptionOptionsWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxChoice* EncryptionAlgorithmChoice;
			wxButton* TestButton;
			wxStaticText* EncryptionAlgorithmStaticText;
			wxHyperlinkCtrl* EncryptionAlgorithmHyperlink;
			
			wxButton* BenchmarkButton;
			wxChoice* HashChoice;
			wxHyperlinkCtrl* HashHyperlink;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnEncryptionAlgorithmSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnTestButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnEncryptionAlgorithmHyperlinkClick( wxHyperlinkEvent& event ){ event.Skip(); }
			virtual void OnBenchmarkButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnHashHyperlinkClick( wxHyperlinkEvent& event ){ event.Skip(); }
			
		
		public:
			EncryptionOptionsWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~EncryptionOptionsWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class InfoWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class InfoWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxBoxSizer* InfoPageSizer;
			wxStaticText* InfoStaticText;
		
		public:
			InfoWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~InfoWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class KeyfilesPanelBase
	///////////////////////////////////////////////////////////////////////////////
	class KeyfilesPanelBase : public wxPanel 
	{
		private:
		
		protected:
			wxListCtrl* KeyfilesListCtrl;
			wxButton* AddFilesButton;
			wxButton* AddDirectoryButton;
			wxButton* AddSecurityTokenSignatureButton;
			wxButton* RemoveButton;
			wxButton* RemoveAllButton;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnListItemDeselected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListItemSelected( wxListEvent& event ){ event.Skip(); }
			virtual void OnListSizeChanged( wxSizeEvent& event ){ event.Skip(); }
			virtual void OnAddFilesButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAddDirectoryButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAddSecurityTokenSignatureButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnRemoveAllButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			KeyfilesPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,300 ), long style = wxTAB_TRAVERSAL );
			~KeyfilesPanelBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class ProgressWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class ProgressWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxBoxSizer* ProgressSizer;
			wxGauge* ProgressGauge;
			wxButton* AbortButton;
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnAbortButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			ProgressWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~ProgressWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class SelectDirectoryWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class SelectDirectoryWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxTextCtrl* DirectoryTextCtrl;
			wxButton* BrowseButton;
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnDirectoryTextChanged( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnBrowseButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			SelectDirectoryWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 200,65 ), long style = wxTAB_TRAVERSAL );
			~SelectDirectoryWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class SingleChoiceWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class SingleChoiceWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			
			wxBoxSizer* OuterChoicesSizer;
			wxBoxSizer* ChoicesSizer;
			wxStaticText* InfoStaticText;
		
		public:
			SingleChoiceWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~SingleChoiceWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumeCreationProgressWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumeCreationProgressWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxBoxSizer* KeySamplesUpperSizer;
			wxBoxSizer* KeySamplesUpperInnerSizer;
			wxStaticText* RandomPoolSampleStaticText;
			wxCheckBox* DisplayKeysCheckBox;
			wxStaticText* HeaderKeySampleStaticText;
			wxStaticText* MasterKeySampleStaticText;
			wxGauge* ProgressGauge;
			wxButton* AbortButton;
			wxStaticText* m_staticText31;
			wxPanel* m_panel12;
			wxStaticText* SizeDoneStaticText;
			wxStaticText* m_staticText311;
			wxPanel* m_panel121;
			wxStaticText* SpeedStaticText;
			wxStaticText* m_staticText312;
			wxPanel* m_panel122;
			wxStaticText* TimeLeftStaticText;
			
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnDisplayKeysCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnAbortButtonClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			VolumeCreationProgressWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumeCreationProgressWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumeLocationWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumeLocationWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			
			wxComboBox* VolumePathComboBox;
			wxButton* SelectFileButton;
			wxButton* SelectDeviceButton;
			
			wxCheckBox* NoHistoryCheckBox;
			
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnVolumePathTextChanged( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnSelectFileButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnSelectDeviceButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnNoHistoryCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			VolumeLocationWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumeLocationWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumeFormatOptionsWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumeFormatOptionsWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxStaticText* m_staticText43;
			wxChoice* FilesystemTypeChoice;
			wxCheckBox* QuickFormatCheckBox;
			
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnFilesystemTypeSelected( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnQuickFormatCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			VolumeFormatOptionsWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumeFormatOptionsWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumePasswordPanelBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumePasswordPanelBase : public wxPanel 
	{
		private:
		
		protected:
			wxGridBagSizer* GridBagSizer;
			wxStaticText* PasswordStaticText;
			wxTextCtrl* PasswordTextCtrl;
			wxStaticText* ConfirmPasswordStaticText;
			wxTextCtrl* ConfirmPasswordTextCtrl;
			wxCheckBox* CacheCheckBox;
			wxCheckBox* DisplayPasswordCheckBox;
			wxCheckBox* UseKeyfilesCheckBox;
			wxButton* KeyfilesButton;
			wxBoxSizer* Pkcs5PrfSizer;
			wxStaticText* Pkcs5PrfStaticText;
			wxChoice* Pkcs5PrfChoice;
			wxBoxSizer* PasswordPlaceholderSizer;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnTextChanged( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnDisplayPasswordCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnUseKeyfilesCheckBoxClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnKeyfilesButtonClick( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnKeyfilesButtonRightDown( wxMouseEvent& event ){ event.Skip(); }
			virtual void OnKeyfilesButtonRightClick( wxMouseEvent& event ){ event.Skip(); }
			
		
		public:
			VolumePasswordPanelBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumePasswordPanelBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumePasswordWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumePasswordWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			wxBoxSizer* PasswordPanelSizer;
			wxStaticText* InfoStaticText;
		
		public:
			VolumePasswordWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumePasswordWizardPageBase();
		
	};
	
	///////////////////////////////////////////////////////////////////////////////
	/// Class VolumeSizeWizardPageBase
	///////////////////////////////////////////////////////////////////////////////
	class VolumeSizeWizardPageBase : public WizardPage
	{
		private:
		
		protected:
			
			wxTextCtrl* VolumeSizeTextCtrl;
			wxChoice* VolumeSizePrefixChoice;
			
			wxStaticText* FreeSpaceStaticText;
			
			wxStaticText* InfoStaticText;
			
			// Virtual event handlers, overide them in your derived class
			virtual void OnVolumeSizeTextChanged( wxCommandEvent& event ){ event.Skip(); }
			virtual void OnVolumeSizePrefixSelected( wxCommandEvent& event ){ event.Skip(); }
			
		
		public:
			VolumeSizeWizardPageBase( wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxTAB_TRAVERSAL );
			~VolumeSizeWizardPageBase();
		
	};
	
} // namespace TrueCrypt

#endif //__Forms__
