///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version 3.10.1-0-g8feb16b3)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "System.h"

#include "Forms.h"

///////////////////////////////////////////////////////////////////////////
using namespace VeraCrypt;

MainFrameBase::MainFrameBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( -1,496 ), wxDefaultSize );

	MainMenuBar = new wxMenuBar( 0 );
	VolumesMenu = new wxMenu();
	wxMenuItem* CreateNewVolumeMenuItem;
	CreateNewVolumeMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_CREATE_VOLUME") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( CreateNewVolumeMenuItem );

	VolumesMenu->AppendSeparator();

	MountVolumeMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_MOUNT_VOLUME") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( MountVolumeMenuItem );

	wxMenuItem* AutoMountDevicesMenuItem;
	AutoMountDevicesMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_MOUNTALL") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( AutoMountDevicesMenuItem );

	VolumesMenu->AppendSeparator();

	DismountVolumeMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_UNMOUNT_VOLUME") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( DismountVolumeMenuItem );

	DismountAllMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_UNMOUNTALL") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( DismountAllMenuItem );

	VolumesMenu->AppendSeparator();

	wxMenuItem* ChangePasswordMenuItem;
	ChangePasswordMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_CHANGE_PASSWORD") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( ChangePasswordMenuItem );

	wxMenuItem* ChangePkcs5PrfMenuItem;
	ChangePkcs5PrfMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_CHANGE_HEADER_KEY_DERIV_ALGO") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( ChangePkcs5PrfMenuItem );

	wxMenuItem* ChangeKeyfilesMenuItem;
	ChangeKeyfilesMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDD_PCDM_ADD_REMOVE_VOL_KEYFILES") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( ChangeKeyfilesMenuItem );

	wxMenuItem* RemoveKeyfilesMenuItem;
	RemoveKeyfilesMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDM_REMOVE_ALL_KEYFILES_FROM_VOL") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( RemoveKeyfilesMenuItem );

	VolumesMenu->AppendSeparator();

	VolumePropertiesMenuItem = new wxMenuItem( VolumesMenu, wxID_ANY, wxString( _("IDC_VOLUME_PROPERTIES") ) , wxEmptyString, wxITEM_NORMAL );
	VolumesMenu->Append( VolumePropertiesMenuItem );

	MainMenuBar->Append( VolumesMenu, _("MENU_VOLUMES") );

	FavoritesMenu = new wxMenu();
	AddToFavoritesMenuItem = new wxMenuItem( FavoritesMenu, wxID_ANY, wxString( _("IDM_ADD_VOLUME_TO_FAVORITES") ) , wxEmptyString, wxITEM_NORMAL );
	FavoritesMenu->Append( AddToFavoritesMenuItem );

	AddAllMountedToFavoritesMenuItem = new wxMenuItem( FavoritesMenu, wxID_ANY, wxString( _("IDM_ADD_ALL_VOLUME_TO_FAVORITES") ) , wxEmptyString, wxITEM_NORMAL );
	FavoritesMenu->Append( AddAllMountedToFavoritesMenuItem );

	wxMenuItem* OrganizeFavoritesMenuItem;
	OrganizeFavoritesMenuItem = new wxMenuItem( FavoritesMenu, wxID_ANY, wxString( _("IDM_ORGANIZE_FAVORITES") ) , wxEmptyString, wxITEM_NORMAL );
	FavoritesMenu->Append( OrganizeFavoritesMenuItem );

	FavoritesMenu->AppendSeparator();

	wxMenuItem* MountAllFavoritesMenuItem;
	MountAllFavoritesMenuItem = new wxMenuItem( FavoritesMenu, wxID_ANY, wxString( _("IDM_MOUNT_FAVORITE_VOLUMES") ) , wxEmptyString, wxITEM_NORMAL );
	FavoritesMenu->Append( MountAllFavoritesMenuItem );

	FavoritesMenu->AppendSeparator();

	MainMenuBar->Append( FavoritesMenu, _("MENU_FAVORITES") );

	ToolsMenu = new wxMenu();
	wxMenuItem* BenchmarkMenuItem;
	BenchmarkMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_BENCHMARK") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( BenchmarkMenuItem );

	wxMenuItem* EncryptionTestMenuItem;
	EncryptionTestMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_TEST_VECTORS") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( EncryptionTestMenuItem );

	ToolsMenu->AppendSeparator();

	wxMenuItem* VolumeCreationWizardMenuItem;
	VolumeCreationWizardMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_VOLUME_WIZARD") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( VolumeCreationWizardMenuItem );

	ToolsMenu->AppendSeparator();

	BackupVolumeHeadersMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_BACKUP_VOL_HEADER") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( BackupVolumeHeadersMenuItem );

	RestoreVolumeHeaderMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_RESTORE_VOL_HEADER") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( RestoreVolumeHeaderMenuItem );

	ToolsMenu->AppendSeparator();

	wxMenuItem* CreateKeyfileMenuItem;
	CreateKeyfileMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_KEYFILE_GENERATOR") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( CreateKeyfileMenuItem );

	wxMenuItem* ManageSecurityTokenKeyfilesMenuItem;
	ManageSecurityTokenKeyfilesMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_MANAGE_TOKEN_KEYFILES") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( ManageSecurityTokenKeyfilesMenuItem );

	wxMenuItem* RevealRedkeyMenuItem;
	RevealRedkeyMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_REVEAL_REDKEY") ), wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( RevealRedkeyMenuItem );
	
	wxMenuItem* CloseAllSecurityTokenSessionsMenuItem;
	CloseAllSecurityTokenSessionsMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_CLOSE_ALL_TOKEN_SESSIONS") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( CloseAllSecurityTokenSessionsMenuItem );

	ToolsMenu->AppendSeparator();

	WipeCachedPasswordsMenuItem = new wxMenuItem( ToolsMenu, wxID_ANY, wxString( _("IDM_WIPE_CACHE") ) , wxEmptyString, wxITEM_NORMAL );
	ToolsMenu->Append( WipeCachedPasswordsMenuItem );

	MainMenuBar->Append( ToolsMenu, _("MENU_TOOLS") );

	SettingsMenu = new wxMenu();
	wxMenuItem* LanguageMenuItem;
	LanguageMenuItem = new wxMenuItem( SettingsMenu, wxID_ANY, wxString( _("IDM_LANGUAGE") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( LanguageMenuItem );

	HotkeysMenuItem = new wxMenuItem( SettingsMenu, wxID_ANY, wxString( _("IDM_HOTKEY_SETTINGS") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( HotkeysMenuItem );

	wxMenuItem* DefaultKeyfilesMenuItem;
	DefaultKeyfilesMenuItem = new wxMenuItem( SettingsMenu, wxID_ANY, wxString( _("IDM_DEFAULT_KEYFILES") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( DefaultKeyfilesMenuItem );

	wxMenuItem* DefaultMountParametersMenuItem;
	DefaultMountParametersMenuItem = new wxMenuItem( SettingsMenu, wxID_ANY, wxString( _("IDM_DEFAULT_MOUNT_PARAMETERS") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( DefaultMountParametersMenuItem );

	wxMenuItem* SecurityTokenPreferencesMenuItem;
	SecurityTokenPreferencesMenuItem = new wxMenuItem( SettingsMenu, wxID_ANY, wxString( _("IDM_TOKEN_PREFERENCES") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( SecurityTokenPreferencesMenuItem );

	SettingsMenu->AppendSeparator();

	PreferencesMenuItem = new wxMenuItem( SettingsMenu, wxID_PREFERENCES, wxString( _("IDM_PREFERENCES") ) , wxEmptyString, wxITEM_NORMAL );
	SettingsMenu->Append( PreferencesMenuItem );

	MainMenuBar->Append( SettingsMenu, _("MENU_SETTINGS") );

	HelpMenu = new wxMenu();
	wxMenuItem* UserGuideMenuItem;
	UserGuideMenuItem = new wxMenuItem( HelpMenu, wxID_HELP, wxString( _("IDM_HELP") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( UserGuideMenuItem );

	wxMenuItem* OnlineHelpMenuItem;
	OnlineHelpMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_ONLINE_HELP") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( OnlineHelpMenuItem );

	wxMenuItem* BeginnersTutorialMenuItem;
	BeginnersTutorialMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_ONLINE_TUTORIAL") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( BeginnersTutorialMenuItem );

	wxMenuItem* FaqMenuItem;
	FaqMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_FAQ") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( FaqMenuItem );

	HelpMenu->AppendSeparator();

	wxMenuItem* WebsiteMenuItem;
	WebsiteMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_WEBSITE") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( WebsiteMenuItem );

	wxMenuItem* DownloadsMenuItem;
	DownloadsMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_TC_DOWNLOADS") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( DownloadsMenuItem );

	wxMenuItem* NewsMenuItem;
	NewsMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_NEWS") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( NewsMenuItem );

	wxMenuItem* VersionHistoryMenuItem;
	VersionHistoryMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_VERSION_HISTORY") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( VersionHistoryMenuItem );

	HelpMenu->AppendSeparator();

	wxMenuItem* DonateMenuItem;
	DonateMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_DONATE") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( DonateMenuItem );

	wxMenuItem* ContactMenuItem;
	ContactMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_CONTACT") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( ContactMenuItem );

	wxMenuItem* LegalNoticesMenuItem;
	LegalNoticesMenuItem = new wxMenuItem( HelpMenu, wxID_ANY, wxString( _("IDM_LICENSE") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( LegalNoticesMenuItem );

	wxMenuItem* AboutMenuItem;
	AboutMenuItem = new wxMenuItem( HelpMenu, wxID_ABOUT, wxString( _("ABOUTBOX") ) , wxEmptyString, wxITEM_NORMAL );
	HelpMenu->Append( AboutMenuItem );

	MainMenuBar->Append( HelpMenu, _("MENU_HELP") );

	this->SetMenuBar( MainMenuBar );

	wxBoxSizer* bSizer1;
	bSizer1 = new wxBoxSizer( wxVERTICAL );

	MainPanel = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer2;
	bSizer2 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer48;
	bSizer48 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer1;
	sbSizer1 = new wxStaticBoxSizer( new wxStaticBox( MainPanel, wxID_ANY, wxEmptyString ), wxVERTICAL );

	SlotListCtrl = new wxListCtrl( sbSizer1->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_SINGLE_SEL|wxLC_VRULES|wxBORDER_SUNKEN );
	sbSizer1->Add( SlotListCtrl, 1, wxALL|wxEXPAND, 5 );


	bSizer48->Add( sbSizer1, 1, wxEXPAND, 5 );

	LowStaticBoxSizer = new wxStaticBoxSizer( new wxStaticBox( MainPanel, wxID_ANY, wxEmptyString ), wxVERTICAL );

	HigherButtonSizer = new wxBoxSizer( wxVERTICAL );


	LowStaticBoxSizer->Add( HigherButtonSizer, 0, wxEXPAND|wxTOP, 2 );

	wxGridSizer* gSizer1;
	gSizer1 = new wxGridSizer( 1, 3, 0, 0 );

	wxBoxSizer* bSizer17;
	bSizer17 = new wxBoxSizer( wxVERTICAL );

	bSizer17->SetMinSize( wxSize( 138,34 ) );
	CreateVolumeButton = new wxButton( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_CREATE_VOLUME"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer17->Add( CreateVolumeButton, 1, wxALL|wxEXPAND, 5 );


	gSizer1->Add( bSizer17, 0, 0, 5 );

	wxBoxSizer* bSizer18;
	bSizer18 = new wxBoxSizer( wxVERTICAL );

	bSizer18->SetMinSize( wxSize( 138,34 ) );
	VolumePropertiesButton = new wxButton( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_VOLUME_PROPERTIES"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer18->Add( VolumePropertiesButton, 1, wxALL|wxEXPAND, 5 );


	gSizer1->Add( bSizer18, 0, wxALIGN_CENTER_HORIZONTAL, 5 );

	wxBoxSizer* bSizer19;
	bSizer19 = new wxBoxSizer( wxVERTICAL );

	bSizer19->SetMinSize( wxSize( 138,34 ) );
	WipeCacheButton = new wxButton( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, _("HK_WIPE_CACHE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer19->Add( WipeCacheButton, 1, wxALL|wxEXPAND, 5 );


	gSizer1->Add( bSizer19, 0, wxALIGN_RIGHT, 5 );


	LowStaticBoxSizer->Add( gSizer1, 0, wxEXPAND|wxRIGHT|wxLEFT, 5 );


	LowStaticBoxSizer->Add( 0, 0, 0, 0, 5 );

	VolumeStaticBoxSizer = new wxStaticBoxSizer( new wxStaticBox( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDT_VOLUME") ), wxVERTICAL );

	VolumeGridBagSizer = new wxGridBagSizer( 0, 0 );
	VolumeGridBagSizer->SetFlexibleDirection( wxBOTH );
	VolumeGridBagSizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	LogoBitmap = new wxStaticBitmap( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, wxBORDER_SUNKEN );
	LogoBitmap->SetMinSize( wxSize( 42,52 ) );

	VolumeGridBagSizer->Add( LogoBitmap, wxGBPosition( 0, 0 ), wxGBSpan( 2, 1 ), wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	VolumePathComboBox = new wxComboBox( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, NULL, wxCB_DROPDOWN );
	VolumeGridBagSizer->Add( VolumePathComboBox, wxGBPosition( 0, 1 ), wxGBSpan( 1, 2 ), wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer191;
	bSizer191 = new wxBoxSizer( wxVERTICAL );

	bSizer191->SetMinSize( wxSize( 138,34 ) );
	SelectFileButton = new wxButton( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_SELECT_FILE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer191->Add( SelectFileButton, 1, wxALL|wxEXPAND, 5 );


	VolumeGridBagSizer->Add( bSizer191, wxGBPosition( 0, 3 ), wxGBSpan( 1, 1 ), wxEXPAND, 5 );

	NoHistoryCheckBox = new wxCheckBox( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_NO_HISTORY"), wxDefaultPosition, wxDefaultSize, 0 );
	VolumeGridBagSizer->Add( NoHistoryCheckBox, wxGBPosition( 1, 1 ), wxGBSpan( 1, 1 ), wxBOTTOM|wxRIGHT|wxLEFT, 5 );

	wxBoxSizer* bSizer20;
	bSizer20 = new wxBoxSizer( wxVERTICAL );

	bSizer20->SetMinSize( wxSize( 138,34 ) );
	VolumeToolsButton = new wxButton( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_VOLUME_TOOLS"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer20->Add( VolumeToolsButton, 1, wxALL|wxEXPAND, 5 );


	VolumeGridBagSizer->Add( bSizer20, wxGBPosition( 1, 2 ), wxGBSpan( 1, 1 ), wxALIGN_RIGHT, 5 );

	wxBoxSizer* bSizer21;
	bSizer21 = new wxBoxSizer( wxVERTICAL );

	bSizer21->SetMinSize( wxSize( 138,34 ) );
	SelectDeviceButton = new wxButton( VolumeStaticBoxSizer->GetStaticBox(), wxID_ANY, _("IDC_SELECT_DEVICE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer21->Add( SelectDeviceButton, 1, wxEXPAND|wxALL, 5 );


	VolumeGridBagSizer->Add( bSizer21, wxGBPosition( 1, 3 ), wxGBSpan( 1, 1 ), wxEXPAND, 5 );


	VolumeGridBagSizer->AddGrowableCol( 1 );
	VolumeGridBagSizer->AddGrowableRow( 0 );

	VolumeStaticBoxSizer->Add( VolumeGridBagSizer, 1, wxEXPAND|wxALL, 4 );


	LowStaticBoxSizer->Add( VolumeStaticBoxSizer, 1, wxEXPAND|wxALL, 5 );


	LowStaticBoxSizer->Add( 0, 0, 0, 0, 5 );

	wxGridSizer* gSizer2;
	gSizer2 = new wxGridSizer( 1, 4, 0, 0 );

	wxStaticBoxSizer* sbSizer4;
	sbSizer4 = new wxStaticBoxSizer( new wxStaticBox( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, wxEmptyString ), wxVERTICAL );

	sbSizer4->SetMinSize( wxSize( 139,-1 ) );
	VolumeButton = new wxButton( sbSizer4->GetStaticBox(), wxID_ANY, _("MOUNT_BUTTON"), wxDefaultPosition, wxDefaultSize, 0 );

	VolumeButton->SetDefault();
	VolumeButton->SetMinSize( wxSize( -1,32 ) );

	sbSizer4->Add( VolumeButton, 1, wxEXPAND|wxALL, 2 );


	gSizer2->Add( sbSizer4, 1, wxEXPAND, 0 );

	wxStaticBoxSizer* sbSizer41;
	sbSizer41 = new wxStaticBoxSizer( new wxStaticBox( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, wxEmptyString ), wxVERTICAL );

	sbSizer41->SetMinSize( wxSize( 139,-1 ) );
	MountAllDevicesButton = new wxButton( sbSizer41->GetStaticBox(), wxID_ANY, _("IDC_MOUNTALL"), wxDefaultPosition, wxDefaultSize, 0 );
	MountAllDevicesButton->SetMinSize( wxSize( -1,32 ) );

	sbSizer41->Add( MountAllDevicesButton, 1, wxEXPAND|wxALL, 2 );


	gSizer2->Add( sbSizer41, 1, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer42;
	sbSizer42 = new wxStaticBoxSizer( new wxStaticBox( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, wxEmptyString ), wxVERTICAL );

	sbSizer42->SetMinSize( wxSize( 139,-1 ) );
	DismountAllButton = new wxButton( sbSizer42->GetStaticBox(), wxID_ANY, _("IDC_UNMOUNTALL"), wxDefaultPosition, wxDefaultSize, 0 );
	DismountAllButton->SetMinSize( wxSize( -1,32 ) );

	sbSizer42->Add( DismountAllButton, 1, wxEXPAND|wxALL, 2 );


	gSizer2->Add( sbSizer42, 1, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer43;
	sbSizer43 = new wxStaticBoxSizer( new wxStaticBox( LowStaticBoxSizer->GetStaticBox(), wxID_ANY, wxEmptyString ), wxVERTICAL );

	sbSizer43->SetMinSize( wxSize( 139,-1 ) );
	ExitButton = new wxButton( sbSizer43->GetStaticBox(), wxID_ANY, _("IDC_EXIT"), wxDefaultPosition, wxDefaultSize, 0 );
	ExitButton->SetMinSize( wxSize( -1,32 ) );

	sbSizer43->Add( ExitButton, 1, wxEXPAND|wxALL, 2 );


	gSizer2->Add( sbSizer43, 1, wxEXPAND, 5 );


	LowStaticBoxSizer->Add( gSizer2, 0, wxEXPAND|wxALL, 5 );


	bSizer48->Add( LowStaticBoxSizer, 0, wxEXPAND, 5 );


	bSizer2->Add( bSizer48, 1, wxEXPAND, 5 );


	MainPanel->SetSizer( bSizer2 );
	MainPanel->Layout();
	bSizer2->Fit( MainPanel );
	bSizer1->Add( MainPanel, 1, wxEXPAND, 0 );


	this->SetSizer( bSizer1 );
	this->Layout();
	bSizer1->Fit( this );

	this->Centre( wxBOTH );

	// Connect Events
	this->Connect( wxEVT_ACTIVATE, wxActivateEventHandler( MainFrameBase::OnActivate ) );
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( MainFrameBase::OnClose ) );
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnCreateVolumeButtonClick ), this, CreateNewVolumeMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnMountVolumeMenuItemSelected ), this, MountVolumeMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnMountAllDevicesButtonClick ), this, AutoMountDevicesMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDismountVolumeMenuItemSelected ), this, DismountVolumeMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDismountAllButtonClick ), this, DismountAllMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnChangePasswordMenuItemSelected ), this, ChangePasswordMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnChangePkcs5PrfMenuItemSelected ), this, ChangePkcs5PrfMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnChangeKeyfilesMenuItemSelected ), this, ChangeKeyfilesMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnRemoveKeyfilesMenuItemSelected ), this, RemoveKeyfilesMenuItem->GetId());
	VolumesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnVolumePropertiesButtonClick ), this, VolumePropertiesMenuItem->GetId());
	FavoritesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnAddToFavoritesMenuItemSelected ), this, AddToFavoritesMenuItem->GetId());
	FavoritesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnAddAllMountedToFavoritesMenuItemSelected ), this, AddAllMountedToFavoritesMenuItem->GetId());
	FavoritesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnOrganizeFavoritesMenuItemSelected ), this, OrganizeFavoritesMenuItem->GetId());
	FavoritesMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnMountAllFavoritesMenuItemSelected ), this, MountAllFavoritesMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnBenchmarkMenuItemSelected ), this, BenchmarkMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnEncryptionTestMenuItemSelected ), this, EncryptionTestMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnCreateVolumeButtonClick ), this, VolumeCreationWizardMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnBackupVolumeHeadersMenuItemSelected ), this, BackupVolumeHeadersMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnRestoreVolumeHeaderMenuItemSelected ), this, RestoreVolumeHeaderMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnCreateKeyfileMenuItemSelected ), this, CreateKeyfileMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnRevealRedkeyMenuItemSelected ), this, RevealRedkeyMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnManageSecurityTokenKeyfilesMenuItemSelected ), this, ManageSecurityTokenKeyfilesMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnCloseAllSecurityTokenSessionsMenuItemSelected ), this, CloseAllSecurityTokenSessionsMenuItem->GetId());
	ToolsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnWipeCacheButtonClick ), this, WipeCachedPasswordsMenuItem->GetId());
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnLanguageMenuItemSelected ), this, LanguageMenuItem->GetId());
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnHotkeysMenuItemSelected ), this, HotkeysMenuItem->GetId());
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDefaultKeyfilesMenuItemSelected ), this, DefaultKeyfilesMenuItem->GetId());
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDefaultMountParametersMenuItemSelected ), this, DefaultMountParametersMenuItem->GetId());
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnSecurityTokenPreferencesMenuItemSelected ), this, SecurityTokenPreferencesMenuItem->GetId());
#ifdef TC_MACOSX
	this->Connect( PreferencesMenuItem->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnPreferencesMenuItemSelected ) );
	this->Connect( UserGuideMenuItem->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnUserGuideMenuItemSelected ) );
#else
	SettingsMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnPreferencesMenuItemSelected ), this, PreferencesMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnUserGuideMenuItemSelected ), this, UserGuideMenuItem->GetId());
#endif
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnOnlineHelpMenuItemSelected ), this, OnlineHelpMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnBeginnersTutorialMenuItemSelected ), this, BeginnersTutorialMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnFaqMenuItemSelected ), this, FaqMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnWebsiteMenuItemSelected ), this, WebsiteMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDownloadsMenuItemSelected ), this, DownloadsMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnNewsMenuItemSelected ), this, NewsMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnVersionHistoryMenuItemSelected ), this, VersionHistoryMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnDonateMenuItemSelected ), this, DonateMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnContactMenuItemSelected ), this, ContactMenuItem->GetId());
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnLegalNoticesMenuItemSelected ), this, LegalNoticesMenuItem->GetId());
#ifdef TC_MACOSX
	this->Connect( AboutMenuItem->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnAboutMenuItemSelected ) );
#else
	HelpMenu->Bind(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnAboutMenuItemSelected ), this, AboutMenuItem->GetId());
#endif
	SlotListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( MainFrameBase::OnListItemActivated ), NULL, this );
	SlotListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( MainFrameBase::OnListItemDeselected ), NULL, this );
	SlotListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK, wxListEventHandler( MainFrameBase::OnListItemRightClick ), NULL, this );
	SlotListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( MainFrameBase::OnListItemSelected ), NULL, this );
	CreateVolumeButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnCreateVolumeButtonClick ), NULL, this );
	VolumePropertiesButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumePropertiesButtonClick ), NULL, this );
	WipeCacheButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnWipeCacheButtonClick ), NULL, this );
	LogoBitmap->Connect( wxEVT_LEFT_DOWN, wxMouseEventHandler( MainFrameBase::OnLogoBitmapClick ), NULL, this );
	SelectFileButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnSelectFileButtonClick ), NULL, this );
	NoHistoryCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MainFrameBase::OnNoHistoryCheckBoxClick ), NULL, this );
	VolumeToolsButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumeToolsButtonClick ), NULL, this );
	SelectDeviceButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnSelectDeviceButtonClick ), NULL, this );
	VolumeButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumeButtonClick ), NULL, this );
	MountAllDevicesButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnMountAllDevicesButtonClick ), NULL, this );
	DismountAllButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnDismountAllButtonClick ), NULL, this );
	ExitButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnExitButtonClick ), NULL, this );
}

MainFrameBase::~MainFrameBase()
{
	// Disconnect Events
#ifdef TC_MACOSX
	this->Disconnect( wxID_PREFERENCES, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnPreferencesMenuItemSelected ) );
	this->Disconnect( wxID_HELP, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnUserGuideMenuItemSelected ) );
	this->Disconnect( wxID_ABOUT, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( MainFrameBase::OnAboutMenuItemSelected ) );
#endif
	this->Disconnect( wxEVT_ACTIVATE, wxActivateEventHandler( MainFrameBase::OnActivate ) );
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( MainFrameBase::OnClose ) );
	SlotListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( MainFrameBase::OnListItemActivated ), NULL, this );
	SlotListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( MainFrameBase::OnListItemDeselected ), NULL, this );
	SlotListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK, wxListEventHandler( MainFrameBase::OnListItemRightClick ), NULL, this );
	SlotListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( MainFrameBase::OnListItemSelected ), NULL, this );
	CreateVolumeButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnCreateVolumeButtonClick ), NULL, this );
	VolumePropertiesButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumePropertiesButtonClick ), NULL, this );
	WipeCacheButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnWipeCacheButtonClick ), NULL, this );
	LogoBitmap->Disconnect( wxEVT_LEFT_DOWN, wxMouseEventHandler( MainFrameBase::OnLogoBitmapClick ), NULL, this );
	SelectFileButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnSelectFileButtonClick ), NULL, this );
	NoHistoryCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MainFrameBase::OnNoHistoryCheckBoxClick ), NULL, this );
	VolumeToolsButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumeToolsButtonClick ), NULL, this );
	SelectDeviceButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnSelectDeviceButtonClick ), NULL, this );
	VolumeButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnVolumeButtonClick ), NULL, this );
	MountAllDevicesButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnMountAllDevicesButtonClick ), NULL, this );
	DismountAllButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnDismountAllButtonClick ), NULL, this );
	ExitButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MainFrameBase::OnExitButtonClick ), NULL, this );

}

WizardFrameBase::WizardFrameBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 800,500 ), wxDefaultSize );

	MainSizer = new wxBoxSizer( wxVERTICAL );

	MainPanel = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer63;
	bSizer63 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer64;
	bSizer64 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer27;
	sbSizer27 = new wxStaticBoxSizer( new wxStaticBox( MainPanel, wxID_ANY, wxEmptyString ), wxHORIZONTAL );

	WizardBitmap = new wxStaticBitmap( sbSizer27->GetStaticBox(), wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer27->Add( WizardBitmap, 0, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer66;
	bSizer66 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer126;
	bSizer126 = new wxBoxSizer( wxHORIZONTAL );

	PageTitleStaticText = new wxStaticText( sbSizer27->GetStaticBox(), wxID_ANY, _("Page Title"), wxDefaultPosition, wxDefaultSize, 0 );
	PageTitleStaticText->Wrap( -1 );
	PageTitleStaticText->SetFont( wxFont( 16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Times New Roman") ) );

	bSizer126->Add( PageTitleStaticText, 0, wxALL, 5 );


	bSizer66->Add( bSizer126, 0, wxLEFT, 5 );

	PageSizer = new wxBoxSizer( wxVERTICAL );


	bSizer66->Add( PageSizer, 1, wxEXPAND|wxTOP|wxBOTTOM|wxLEFT, 5 );


	sbSizer27->Add( bSizer66, 1, wxEXPAND|wxLEFT, 5 );


	bSizer64->Add( sbSizer27, 1, wxEXPAND|wxRIGHT|wxLEFT, 5 );

	wxBoxSizer* bSizer70;
	bSizer70 = new wxBoxSizer( wxHORIZONTAL );


	bSizer70->Add( 0, 0, 1, wxEXPAND, 5 );

	HelpButton = new wxButton( MainPanel, wxID_HELP, _("IDHELP"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer70->Add( HelpButton, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer70->Add( 2, 0, 0, wxLEFT, 5 );

	PreviousButton = new wxButton( MainPanel, wxID_ANY, _("PREV"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer70->Add( PreviousButton, 0, wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	NextButton = new wxButton( MainPanel, wxID_ANY, _("NEXT"), wxDefaultPosition, wxDefaultSize, 0|wxWANTS_CHARS );

	NextButton->SetDefault();
	bSizer70->Add( NextButton, 0, wxTOP|wxBOTTOM|wxRIGHT|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer70->Add( 2, 0, 0, wxLEFT, 5 );

	CancelButton = new wxButton( MainPanel, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer70->Add( CancelButton, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer64->Add( bSizer70, 0, wxEXPAND|wxALL, 5 );


	bSizer63->Add( bSizer64, 1, wxEXPAND, 5 );


	MainPanel->SetSizer( bSizer63 );
	MainPanel->Layout();
	bSizer63->Fit( MainPanel );
	MainSizer->Add( MainPanel, 1, wxEXPAND, 5 );


	this->SetSizer( MainSizer );
	this->Layout();
	MainSizer->Fit( this );

	// Connect Events
	this->Connect( wxEVT_ACTIVATE, wxActivateEventHandler( WizardFrameBase::OnActivate ) );
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( WizardFrameBase::OnClose ) );
	MainPanel->Connect( wxEVT_MOTION, wxMouseEventHandler( WizardFrameBase::OnMouseMotion ), NULL, this );
	HelpButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnHelpButtonClick ), NULL, this );
	PreviousButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnPreviousButtonClick ), NULL, this );
	NextButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnNextButtonClick ), NULL, this );
	CancelButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnCancelButtonClick ), NULL, this );
}

WizardFrameBase::~WizardFrameBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_ACTIVATE, wxActivateEventHandler( WizardFrameBase::OnActivate ) );
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( WizardFrameBase::OnClose ) );
	MainPanel->Disconnect( wxEVT_MOTION, wxMouseEventHandler( WizardFrameBase::OnMouseMotion ), NULL, this );
	HelpButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnHelpButtonClick ), NULL, this );
	PreviousButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnPreviousButtonClick ), NULL, this );
	NextButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnNextButtonClick ), NULL, this );
	CancelButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( WizardFrameBase::OnCancelButtonClick ), NULL, this );

}

AboutDialogBase::AboutDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer116;
	bSizer116 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer117;
	bSizer117 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer120;
	bSizer120 = new wxBoxSizer( wxVERTICAL );

	bSizer120->SetMinSize( wxSize( -1,78 ) );
	m_panel14 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_panel14->SetBackgroundColour( wxColour( 10, 108, 206 ) );

	wxBoxSizer* bSizer121;
	bSizer121 = new wxBoxSizer( wxVERTICAL );


	bSizer121->Add( 0, 0, 1, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer122;
	bSizer122 = new wxBoxSizer( wxVERTICAL );

	LogoBitmap = new wxStaticBitmap( m_panel14, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	bSizer122->Add( LogoBitmap, 0, wxALL, 10 );


	bSizer121->Add( bSizer122, 0, wxEXPAND|wxLEFT, 8 );


	m_panel14->SetSizer( bSizer121 );
	m_panel14->Layout();
	bSizer121->Fit( m_panel14 );
	bSizer120->Add( m_panel14, 1, wxEXPAND, 5 );


	bSizer117->Add( bSizer120, 0, wxEXPAND, 5 );

	wxBoxSizer* bSizer118;
	bSizer118 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer123;
	bSizer123 = new wxBoxSizer( wxVERTICAL );

	VersionStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	VersionStaticText->Wrap( -1 );
	bSizer123->Add( VersionStaticText, 0, wxTOP|wxRIGHT|wxLEFT, 5 );


	bSizer123->Add( 0, 0, 0, wxTOP, 3 );

	CopyrightStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	CopyrightStaticText->Wrap( -1 );
	bSizer123->Add( CopyrightStaticText, 0, wxBOTTOM|wxRIGHT|wxLEFT, 5 );


	bSizer123->Add( 0, 0, 0, wxTOP, 3 );

	WebsiteHyperlink = new wxHyperlinkCtrl( this, wxID_ANY, wxEmptyString, wxT("."), wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );

	WebsiteHyperlink->SetHoverColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	WebsiteHyperlink->SetNormalColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	WebsiteHyperlink->SetVisitedColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	bSizer123->Add( WebsiteHyperlink, 0, wxALL, 5 );


	bSizer118->Add( bSizer123, 1, wxEXPAND|wxLEFT, 5 );


	bSizer117->Add( bSizer118, 1, wxALL|wxEXPAND, 15 );

	m_staticline3 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	bSizer117->Add( m_staticline3, 0, wxEXPAND|wxBOTTOM, 5 );

	CreditsTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE|wxTE_READONLY|wxBORDER_SUNKEN );
	bSizer117->Add( CreditsTextCtrl, 0, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 10 );


	bSizer117->Add( 0, 0, 0, wxTOP, 5 );

	m_staticline4 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	bSizer117->Add( m_staticline4, 0, wxEXPAND|wxTOP|wxBOTTOM, 3 );

	m_staticline5 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	bSizer117->Add( m_staticline5, 0, wxEXPAND|wxBOTTOM, 5 );

	wxBoxSizer* bSizer119;
	bSizer119 = new wxBoxSizer( wxHORIZONTAL );


	bSizer119->Add( 0, 0, 1, wxEXPAND|wxALL, 5 );

	wxButton* OKButton;
	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer119->Add( OKButton, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer119->Add( 0, 0, 0, wxLEFT, 5 );


	bSizer117->Add( bSizer119, 0, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 6 );


	bSizer116->Add( bSizer117, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer116 );
	this->Layout();
	bSizer116->Fit( this );

	// Connect Events
	WebsiteHyperlink->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( AboutDialogBase::OnWebsiteHyperlinkClick ), NULL, this );
}

AboutDialogBase::~AboutDialogBase()
{
	// Disconnect Events
	WebsiteHyperlink->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( AboutDialogBase::OnWebsiteHyperlinkClick ), NULL, this );

}

BenchmarkDialogBase::BenchmarkDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer153;
	bSizer153 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer154;
	bSizer154 = new wxBoxSizer( wxVERTICAL );

	wxFlexGridSizer* fgSizer9;
	fgSizer9 = new wxFlexGridSizer( 3, 2, 0, 0 );
	fgSizer9->AddGrowableCol( 1 );
	fgSizer9->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer9->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	m_staticText70 = new wxStaticText( this, wxID_ANY, _("IDT_BENCHMARK"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText70->Wrap( -1 );
	fgSizer9->Add( m_staticText70, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	wxString BenchmarkChoiceChoices[] = { _("ENCRYPTION_ALGORITHM"), _("PKCS5_PRF"), _("IDT_HASH_ALGO") };
	int BenchmarkChoiceNChoices = sizeof( BenchmarkChoiceChoices ) / sizeof( wxString );
	BenchmarkChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, BenchmarkChoiceNChoices, BenchmarkChoiceChoices, 0 );
	BenchmarkChoice->SetSelection( 0 );
	fgSizer9->Add( BenchmarkChoice, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	m_bufferSizeLabel = new wxStaticText( this, wxID_ANY, _("IDT_BUFFER_SIZE"), wxDefaultPosition, wxDefaultSize, 0 );
	m_bufferSizeLabel->Wrap( -1 );
	fgSizer9->Add( m_bufferSizeLabel, 0, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxLEFT, 5 );

	wxArrayString BufferSizeChoiceChoices;
	BufferSizeChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, BufferSizeChoiceChoices, 0 );
	BufferSizeChoice->SetSelection( 0 );
	fgSizer9->Add( BufferSizeChoice, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	m_volumePimLabel = new wxStaticText( this, wxID_ANY, _("IDT_PIM"), wxDefaultPosition, wxDefaultSize, 0 );
	m_volumePimLabel->Wrap( -1 );
	fgSizer9->Add( m_volumePimLabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	VolumePimText = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	#ifdef __WXGTK__
	if ( !VolumePimText->HasFlag( wxTE_MULTILINE ) )
	{
	VolumePimText->SetMaxLength( 7 );
	}
	#else
	VolumePimText->SetMaxLength( 7 );
	#endif
	fgSizer9->Add( VolumePimText, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );


	bSizer154->Add( fgSizer9, 0, wxEXPAND, 5 );

	wxStaticLine* m_staticline6;
	m_staticline6 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	bSizer154->Add( m_staticline6, 0, wxEXPAND | wxALL, 5 );

	wxBoxSizer* bSizer156;
	bSizer156 = new wxBoxSizer( wxHORIZONTAL );

	BenchmarkListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxBORDER_SUNKEN );
	bSizer156->Add( BenchmarkListCtrl, 1, wxALL|wxEXPAND, 5 );

	RightSizer = new wxBoxSizer( wxVERTICAL );

	BenchmarkButton = new wxButton( this, wxID_OK, _("IDC_PERFORM_BENCHMARK"), wxDefaultPosition, wxDefaultSize, 0 );

	BenchmarkButton->SetDefault();
	RightSizer->Add( BenchmarkButton, 0, wxALL|wxEXPAND, 5 );

	wxButton* CancelButton;
	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCLOSE"), wxDefaultPosition, wxDefaultSize, 0 );
	RightSizer->Add( CancelButton, 0, wxALL|wxEXPAND, 5 );


	RightSizer->Add( 0, 0, 0, wxEXPAND|wxTOP|wxBOTTOM, 5 );

	BenchmarkNoteStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	BenchmarkNoteStaticText->Wrap( -1 );
	RightSizer->Add( BenchmarkNoteStaticText, 1, wxALL|wxEXPAND, 5 );


	bSizer156->Add( RightSizer, 0, wxEXPAND, 5 );


	bSizer154->Add( bSizer156, 1, wxEXPAND, 5 );


	bSizer153->Add( bSizer154, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer153 );
	this->Layout();
	bSizer153->Fit( this );

	// Connect Events
	BenchmarkChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( BenchmarkDialogBase::OnBenchmarkChoiceSelected ), NULL, this );
	BenchmarkButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( BenchmarkDialogBase::OnBenchmarkButtonClick ), NULL, this );
}

BenchmarkDialogBase::~BenchmarkDialogBase()
{
	// Disconnect Events
	BenchmarkChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( BenchmarkDialogBase::OnBenchmarkChoiceSelected ), NULL, this );
	BenchmarkButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( BenchmarkDialogBase::OnBenchmarkButtonClick ), NULL, this );

}

ChangePasswordDialogBase::ChangePasswordDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	wxBoxSizer* bSizer30;
	bSizer30 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer31;
	bSizer31 = new wxBoxSizer( wxHORIZONTAL );

	wxBoxSizer* bSizer32;
	bSizer32 = new wxBoxSizer( wxVERTICAL );

	CurrentSizer = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_CURRENT") ), wxVERTICAL );

	CurrentPasswordPanelSizer = new wxBoxSizer( wxVERTICAL );


	CurrentSizer->Add( CurrentPasswordPanelSizer, 0, wxALIGN_LEFT, 5 );


	bSizer32->Add( CurrentSizer, 0, wxEXPAND, 5 );

	NewSizer = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_NEW") ), wxVERTICAL );

	NewPasswordPanelSizer = new wxBoxSizer( wxVERTICAL );


	NewSizer->Add( NewPasswordPanelSizer, 0, wxALIGN_LEFT, 5 );


	bSizer32->Add( NewSizer, 0, wxTOP|wxEXPAND, 5 );


	bSizer31->Add( bSizer32, 1, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer33;
	bSizer33 = new wxBoxSizer( wxVERTICAL );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer33->Add( OKButton, 0, wxALL|wxEXPAND, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer33->Add( CancelButton, 0, wxALL|wxEXPAND, 5 );


	bSizer31->Add( bSizer33, 0, 0, 5 );


	bSizer30->Add( bSizer31, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer30 );
	this->Layout();
	bSizer30->Fit( this );

	// Connect Events
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ChangePasswordDialogBase::OnOKButtonClick ), NULL, this );
}

ChangePasswordDialogBase::~ChangePasswordDialogBase()
{
	// Disconnect Events
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ChangePasswordDialogBase::OnOKButtonClick ), NULL, this );

}

DeviceSelectionDialogBase::DeviceSelectionDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( -1,-1 ), wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	wxBoxSizer* bSizer3;
	bSizer3 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer4;
	bSizer4 = new wxBoxSizer( wxVERTICAL );

	DeviceListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_SINGLE_SEL|wxLC_VRULES|wxBORDER_SUNKEN );
	bSizer4->Add( DeviceListCtrl, 1, wxALL|wxEXPAND, 5 );


	bSizer3->Add( bSizer4, 1, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer166;
	bSizer166 = new wxBoxSizer( wxHORIZONTAL );


	bSizer166->Add( 0, 0, 1, wxEXPAND, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer166->Add( CancelButton, 0, wxALL, 5 );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer166->Add( OKButton, 0, wxALL, 5 );


	bSizer3->Add( bSizer166, 0, wxALL|wxEXPAND, 5 );


	this->SetSizer( bSizer3 );
	this->Layout();
	bSizer3->Fit( this );

	this->Centre( wxBOTH );

	// Connect Events
	DeviceListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemActivated ), NULL, this );
	DeviceListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemDeselected ), NULL, this );
	DeviceListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemSelected ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( DeviceSelectionDialogBase::OnOKButtonClick ), NULL, this );
}

DeviceSelectionDialogBase::~DeviceSelectionDialogBase()
{
	// Disconnect Events
	DeviceListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemActivated ), NULL, this );
	DeviceListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemDeselected ), NULL, this );
	DeviceListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( DeviceSelectionDialogBase::OnListItemSelected ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( DeviceSelectionDialogBase::OnOKButtonClick ), NULL, this );

}

EncryptionTestDialogBase::EncryptionTestDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer132;
	bSizer132 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer133;
	bSizer133 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer134;
	bSizer134 = new wxBoxSizer( wxHORIZONTAL );

	wxStaticText* m_staticText41;
	m_staticText41 = new wxStaticText( this, wxID_ANY, _("IDT_CIPHER"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText41->Wrap( -1 );
	bSizer134->Add( m_staticText41, 0, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxLEFT, 5 );

	wxArrayString EncryptionAlgorithmChoiceChoices;
	EncryptionAlgorithmChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, EncryptionAlgorithmChoiceChoices, 0 );
	EncryptionAlgorithmChoice->SetSelection( 0 );
	bSizer134->Add( EncryptionAlgorithmChoice, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	XtsModeCheckBox = new wxCheckBox( this, wxID_ANY, _("IDT_XTS_MODE"), wxDefaultPosition, wxDefaultSize, 0 );
	XtsModeCheckBox->SetValue(true);
	bSizer134->Add( XtsModeCheckBox, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer133->Add( bSizer134, 0, wxALIGN_CENTER_HORIZONTAL, 5 );

	wxStaticBoxSizer* sbSizer38;
	sbSizer38 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_TEST_KEY") ), wxVERTICAL );

	KeyTextCtrl = new wxTextCtrl( sbSizer38->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	KeyTextCtrl->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier") ) );

	sbSizer38->Add( KeyTextCtrl, 1, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer135;
	bSizer135 = new wxBoxSizer( wxHORIZONTAL );

	wxStaticText* m_staticText43;
	m_staticText43 = new wxStaticText( sbSizer38->GetStaticBox(), wxID_ANY, _("IDT_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText43->Wrap( -1 );
	bSizer135->Add( m_staticText43, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT|wxLEFT, 5 );

	KeySizeStaticText = new wxStaticText( sbSizer38->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	KeySizeStaticText->Wrap( -1 );
	bSizer135->Add( KeySizeStaticText, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxRIGHT, 5 );


	sbSizer38->Add( bSizer135, 0, wxEXPAND, 5 );


	bSizer133->Add( sbSizer38, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer39;
	sbSizer39 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_XTS_MODE") ), wxVERTICAL );

	wxStaticText* m_staticText45;
	m_staticText45 = new wxStaticText( sbSizer39->GetStaticBox(), wxID_ANY, _("IDT_SECONDARY_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText45->Wrap( -1 );
	sbSizer39->Add( m_staticText45, 0, wxTOP|wxRIGHT|wxLEFT, 5 );

	SecondaryKeyTextCtrl = new wxTextCtrl( sbSizer39->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	SecondaryKeyTextCtrl->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier") ) );

	sbSizer39->Add( SecondaryKeyTextCtrl, 0, wxEXPAND|wxALL, 5 );

	wxStaticText* m_staticText46;
	m_staticText46 = new wxStaticText( sbSizer39->GetStaticBox(), wxID_ANY, _("IDT_TEST_DATA_UNIT_NUMBER"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText46->Wrap( -1 );
	sbSizer39->Add( m_staticText46, 0, wxTOP|wxRIGHT|wxLEFT, 5 );

	DataUnitNumberTextCtrl = new wxTextCtrl( sbSizer39->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer39->Add( DataUnitNumberTextCtrl, 0, wxALL, 5 );

	wxStaticText* m_staticText47;
	m_staticText47 = new wxStaticText( sbSizer39->GetStaticBox(), wxID_ANY, _("IDT_TEST_BLOCK_NUMBER"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText47->Wrap( -1 );
	sbSizer39->Add( m_staticText47, 0, wxTOP|wxRIGHT|wxLEFT, 5 );

	BlockNumberTextCtrl = new wxTextCtrl( sbSizer39->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer39->Add( BlockNumberTextCtrl, 0, wxALL, 5 );


	bSizer133->Add( sbSizer39, 1, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer40;
	sbSizer40 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_TEST_PLAINTEXT") ), wxVERTICAL );

	PlainTextTextCtrl = new wxTextCtrl( sbSizer40->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	PlainTextTextCtrl->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier") ) );

	sbSizer40->Add( PlainTextTextCtrl, 0, wxALL|wxEXPAND, 5 );


	bSizer133->Add( sbSizer40, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer41;
	sbSizer41 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_TEST_CIPHERTEXT") ), wxVERTICAL );

	CipherTextTextCtrl = new wxTextCtrl( sbSizer41->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	CipherTextTextCtrl->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier") ) );

	sbSizer41->Add( CipherTextTextCtrl, 0, wxALL|wxEXPAND, 5 );


	bSizer133->Add( sbSizer41, 0, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer136;
	bSizer136 = new wxBoxSizer( wxHORIZONTAL );

	EncryptButton = new wxButton( this, wxID_ANY, _("ENCRYPT"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer136->Add( EncryptButton, 0, wxALL, 5 );

	DecryptButton = new wxButton( this, wxID_ANY, _("DECRYPT"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer136->Add( DecryptButton, 0, wxALL, 5 );

	AutoTestAllButton = new wxButton( this, wxID_ANY, _("IDC_AUTO"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer136->Add( AutoTestAllButton, 0, wxALL, 5 );

	ResetButton = new wxButton( this, wxID_ANY, _("IDC_RESET"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer136->Add( ResetButton, 0, wxALL, 5 );

	CloseButton = new wxButton( this, wxID_CANCEL, _("IDCLOSE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer136->Add( CloseButton, 0, wxALL, 5 );


	bSizer133->Add( bSizer136, 0, wxEXPAND, 5 );


	bSizer132->Add( bSizer133, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer132 );
	this->Layout();
	bSizer132->Fit( this );

	// Connect Events
	EncryptionAlgorithmChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( EncryptionTestDialogBase::OnEncryptionAlgorithmSelected ), NULL, this );
	XtsModeCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnXtsModeCheckBoxClick ), NULL, this );
	EncryptButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnEncryptButtonClick ), NULL, this );
	DecryptButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnDecryptButtonClick ), NULL, this );
	AutoTestAllButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnAutoTestAllButtonClick ), NULL, this );
	ResetButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnResetButtonClick ), NULL, this );
}

EncryptionTestDialogBase::~EncryptionTestDialogBase()
{
	// Disconnect Events
	EncryptionAlgorithmChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( EncryptionTestDialogBase::OnEncryptionAlgorithmSelected ), NULL, this );
	XtsModeCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnXtsModeCheckBoxClick ), NULL, this );
	EncryptButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnEncryptButtonClick ), NULL, this );
	DecryptButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnDecryptButtonClick ), NULL, this );
	AutoTestAllButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnAutoTestAllButtonClick ), NULL, this );
	ResetButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionTestDialogBase::OnResetButtonClick ), NULL, this );

}

FavoriteVolumesDialogBase::FavoriteVolumesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer57;
	bSizer57 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer60;
	bSizer60 = new wxBoxSizer( wxHORIZONTAL );

	wxBoxSizer* bSizer58;
	bSizer58 = new wxBoxSizer( wxVERTICAL );

	FavoritesListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VRULES|wxBORDER_SUNKEN );
	bSizer58->Add( FavoritesListCtrl, 1, wxALL|wxEXPAND, 5 );

	wxGridSizer* gSizer5;
	gSizer5 = new wxGridSizer( 1, 4, 0, 0 );

	MoveUpButton = new wxButton( this, wxID_ANY, _("IDC_FAVORITE_MOVE_UP"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer5->Add( MoveUpButton, 0, wxEXPAND|wxTOP|wxBOTTOM|wxRIGHT, 5 );

	MoveDownButton = new wxButton( this, wxID_ANY, _("IDC_FAVORITE_MOVE_DOWN"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer5->Add( MoveDownButton, 0, wxEXPAND|wxTOP|wxBOTTOM|wxRIGHT, 5 );

	RemoveButton = new wxButton( this, wxID_ANY, _("IDC_KEYREMOVE"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer5->Add( RemoveButton, 0, wxEXPAND|wxTOP|wxBOTTOM|wxLEFT, 5 );

	RemoveAllButton = new wxButton( this, wxID_ANY, _("IDC_KEYREMOVEALL"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer5->Add( RemoveAllButton, 0, wxEXPAND|wxTOP|wxBOTTOM|wxLEFT, 5 );


	bSizer58->Add( gSizer5, 0, wxEXPAND|wxRIGHT|wxLEFT, 5 );

	wxFlexGridSizer* fgSizer4;
	fgSizer4 = new wxFlexGridSizer( 1, 5, 0, 0 );
	fgSizer4->AddGrowableCol( 2 );
	fgSizer4->SetFlexibleDirection( wxBOTH );
	fgSizer4->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );


	fgSizer4->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer58->Add( fgSizer4, 0, wxEXPAND, 5 );


	bSizer60->Add( bSizer58, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer59;
	bSizer59 = new wxBoxSizer( wxVERTICAL );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer59->Add( OKButton, 0, wxALL, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer59->Add( CancelButton, 0, wxALL, 5 );


	bSizer60->Add( bSizer59, 0, wxEXPAND, 5 );


	bSizer57->Add( bSizer60, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer57 );
	this->Layout();
	bSizer57->Fit( this );

	// Connect Events
	FavoritesListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( FavoriteVolumesDialogBase::OnListItemDeselected ), NULL, this );
	FavoritesListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( FavoriteVolumesDialogBase::OnListItemSelected ), NULL, this );
	MoveUpButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnMoveUpButtonClick ), NULL, this );
	MoveDownButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnMoveDownButtonClick ), NULL, this );
	RemoveButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnRemoveButtonClick ), NULL, this );
	RemoveAllButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnRemoveAllButtonClick ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnOKButtonClick ), NULL, this );
}

FavoriteVolumesDialogBase::~FavoriteVolumesDialogBase()
{
	// Disconnect Events
	FavoritesListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( FavoriteVolumesDialogBase::OnListItemDeselected ), NULL, this );
	FavoritesListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( FavoriteVolumesDialogBase::OnListItemSelected ), NULL, this );
	MoveUpButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnMoveUpButtonClick ), NULL, this );
	MoveDownButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnMoveDownButtonClick ), NULL, this );
	RemoveButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnRemoveButtonClick ), NULL, this );
	RemoveAllButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnRemoveAllButtonClick ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( FavoriteVolumesDialogBase::OnOKButtonClick ), NULL, this );

}

KeyfilesDialogBase::KeyfilesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	wxBoxSizer* bSizer26;
	bSizer26 = new wxBoxSizer( wxVERTICAL );

	UpperSizer = new wxBoxSizer( wxHORIZONTAL );

	PanelSizer = new wxBoxSizer( wxVERTICAL );


	UpperSizer->Add( PanelSizer, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer22;
	bSizer22 = new wxBoxSizer( wxVERTICAL );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer22->Add( OKButton, 0, wxALL|wxEXPAND, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer22->Add( CancelButton, 0, wxALL|wxEXPAND, 5 );

	WarningStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	WarningStaticText->Wrap( -1 );
	bSizer22->Add( WarningStaticText, 1, wxALL|wxEXPAND, 5 );


	UpperSizer->Add( bSizer22, 0, wxEXPAND, 5 );


	bSizer26->Add( UpperSizer, 1, wxTOP|wxRIGHT|wxLEFT, 5 );

	wxBoxSizer* bSizer23;
	bSizer23 = new wxBoxSizer( wxVERTICAL );

	KeyfilesNoteSizer = new wxBoxSizer( wxVERTICAL );

	wxStaticLine* m_staticline1;
	m_staticline1 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	KeyfilesNoteSizer->Add( m_staticline1, 0, wxEXPAND | wxALL, 5 );

	KeyfilesNoteStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	KeyfilesNoteStaticText->Wrap( -1 );
	KeyfilesNoteSizer->Add( KeyfilesNoteStaticText, 0, wxALL|wxEXPAND, 5 );

	wxStaticLine* m_staticline2;
	m_staticline2 = new wxStaticLine( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL );
	KeyfilesNoteSizer->Add( m_staticline2, 0, wxEXPAND | wxALL, 5 );


	bSizer23->Add( KeyfilesNoteSizer, 1, wxEXPAND, 5 );

	wxFlexGridSizer* fgSizer2;
	fgSizer2 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer2->AddGrowableCol( 0 );
	fgSizer2->SetFlexibleDirection( wxBOTH );
	fgSizer2->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	KeyfilesHyperlink = new wxHyperlinkCtrl( this, wxID_ANY, _("IDC_LINK_KEYFILES_INFO"), wxEmptyString, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );

	KeyfilesHyperlink->SetHoverColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	KeyfilesHyperlink->SetNormalColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	KeyfilesHyperlink->SetVisitedColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	fgSizer2->Add( KeyfilesHyperlink, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	CreateKeyfileButtton = new wxButton( this, wxID_ANY, _("IDC_GENERATE_KEYFILE"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer2->Add( CreateKeyfileButtton, 0, wxALL, 5 );


	bSizer23->Add( fgSizer2, 0, wxEXPAND, 5 );


	bSizer26->Add( bSizer23, 0, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 5 );


	this->SetSizer( bSizer26 );
	this->Layout();
	bSizer26->Fit( this );

	// Connect Events
	KeyfilesHyperlink->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( KeyfilesDialogBase::OnKeyfilesHyperlinkClick ), NULL, this );
	CreateKeyfileButtton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesDialogBase::OnCreateKeyfileButttonClick ), NULL, this );
}

KeyfilesDialogBase::~KeyfilesDialogBase()
{
	// Disconnect Events
	KeyfilesHyperlink->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( KeyfilesDialogBase::OnKeyfilesHyperlinkClick ), NULL, this );
	CreateKeyfileButtton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesDialogBase::OnCreateKeyfileButttonClick ), NULL, this );

}

KeyfileGeneratorDialogBase::KeyfileGeneratorDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	MainSizer = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer144;
	bSizer144 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer145;
	bSizer145 = new wxBoxSizer( wxHORIZONTAL );


	bSizer145->Add( 0, 0, 1, wxEXPAND, 5 );

	wxStaticText* m_staticText49;
	m_staticText49 = new wxStaticText( this, wxID_ANY, _("IDT_PRF"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText49->Wrap( -1 );
	bSizer145->Add( m_staticText49, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	wxArrayString HashChoiceChoices;
	HashChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, HashChoiceChoices, 0 );
	HashChoice->SetSelection( 0 );
	bSizer145->Add( HashChoice, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer145->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer144->Add( bSizer145, 0, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer43;
	sbSizer43 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, wxEmptyString ), wxVERTICAL );

	wxBoxSizer* bSizer147;
	bSizer147 = new wxBoxSizer( wxHORIZONTAL );

	wxStaticText* m_staticText52;
	m_staticText52 = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_RANDOM_POOL"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText52->Wrap( -1 );
	bSizer147->Add( m_staticText52, 0, wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	RandomPoolStaticText = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	RandomPoolStaticText->Wrap( -1 );
	RandomPoolStaticText->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier New") ) );

	bSizer147->Add( RandomPoolStaticText, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	ShowRandomPoolCheckBox = new wxCheckBox( sbSizer43->GetStaticBox(), wxID_ANY, _("IDC_DISPLAY_POOL_CONTENTS"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer147->Add( ShowRandomPoolCheckBox, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	sbSizer43->Add( bSizer147, 0, wxEXPAND|wxTOP, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer45;
	sbSizer45 = new wxStaticBoxSizer( new wxStaticBox( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_ENTROPY_BAR") ), wxVERTICAL );

	CollectedEntropy = new wxGauge( sbSizer45->GetStaticBox(), wxID_ANY, 2560, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL|wxGA_SMOOTH );
	CollectedEntropy->SetValue( 0 );
	sbSizer45->Add( CollectedEntropy, 1, wxALL|wxEXPAND, 5 );


	sbSizer43->Add( sbSizer45, 0, wxBOTTOM|wxEXPAND|wxTOP, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );

	MouseStaticText = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_KEYFILE_GENERATOR_NOTE"), wxDefaultPosition, wxDefaultSize, 0 );
	MouseStaticText->Wrap( -1 );
	sbSizer43->Add( MouseStaticText, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer144->Add( sbSizer43, 1, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 5 );

	wxBoxSizer* bSizer162;
	bSizer162 = new wxBoxSizer( wxVERTICAL );

	wxFlexGridSizer* fgSizer8;
	fgSizer8 = new wxFlexGridSizer( 4, 3, 0, 0 );
	fgSizer8->AddGrowableCol( 2 );
	fgSizer8->SetFlexibleDirection( wxBOTH );
	fgSizer8->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	m_staticText60 = new wxStaticText( this, wxID_ANY, _("IDT_NUMBER_KEYFILES"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText60->Wrap( -1 );
	fgSizer8->Add( m_staticText60, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	NumberOfKeyfiles = new wxSpinCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1, 9999999, 1 );
	fgSizer8->Add( NumberOfKeyfiles, 0, wxALL, 5 );

	m_panel18 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	fgSizer8->Add( m_panel18, 1, wxEXPAND | wxALL, 5 );

	m_staticText63 = new wxStaticText( this, wxID_ANY, _("IDT_KEYFILES_SIZE"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText63->Wrap( -1 );
	fgSizer8->Add( m_staticText63, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	KeyfilesSize = new wxSpinCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 64, 1048576, 64 );
	fgSizer8->Add( KeyfilesSize, 0, wxALL, 5 );

	RandomSizeCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_KEYFILES_RANDOM_SIZE"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( RandomSizeCheckBox, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	m_staticText65 = new wxStaticText( this, wxID_ANY, _("IDT_KEYFILES_BASE_NAME"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText65->Wrap( -1 );
	fgSizer8->Add( m_staticText65, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	KeyfilesBaseName = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add( KeyfilesBaseName, 0, wxALL, 5 );

	m_panel20 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	fgSizer8->Add( m_panel20, 1, wxEXPAND | wxALL, 5 );

	m_staticText66 = new wxStaticText( this, wxID_ANY, _("IDC_SECURITY_TOKEN_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText66->Wrap( -1 );
	
	fgSizer8->Add( m_staticText66, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	SecurityTokenSchemeDesc = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
	ChooseSecurityTokenButton = new wxButton( this, wxID_ANY, _("IDC_SECURITY_TOKEN_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer8->Add(SecurityTokenSchemeDesc, 0, wxALL, 5 );
	fgSizer8->Add(ChooseSecurityTokenButton, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	

	m_panel19 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	fgSizer8->Add( m_panel19, 1, wxEXPAND | wxALL, 5 );


	bSizer162->Add( fgSizer8, 1, wxEXPAND, 5 );


	bSizer144->Add( bSizer162, 1, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer146;
	bSizer146 = new wxBoxSizer( wxHORIZONTAL );

	GenerateButton = new wxButton( this, wxID_ANY, _("IDC_GENERATE_AND_SAVE_KEYFILE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer146->Add( GenerateButton, 0, wxALL, 5 );


	bSizer146->Add( 0, 0, 1, wxEXPAND, 5 );

	wxButton* m_button61;
	m_button61 = new wxButton( this, wxID_CANCEL, _("IDCLOSE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer146->Add( m_button61, 0, wxALL, 5 );


	bSizer144->Add( bSizer146, 0, wxEXPAND, 5 );


	MainSizer->Add( bSizer144, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( MainSizer );
	this->Layout();
	MainSizer->Fit( this );

	// Connect Events
	this->Connect( wxEVT_MOTION, wxMouseEventHandler( KeyfileGeneratorDialogBase::OnMouseMotion ) );
	HashChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnHashSelected ), NULL, this );
	ShowRandomPoolCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnShowRandomPoolCheckBoxClicked ), NULL, this );
	RandomSizeCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnRandomSizeCheckBoxClicked ), NULL, this );
	GenerateButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnGenerateButtonClick ), NULL, this );
	ChooseSecurityTokenButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnSelectSecurityTokenSchemeClick ), NULL, this);
}

KeyfileGeneratorDialogBase::~KeyfileGeneratorDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_MOTION, wxMouseEventHandler( KeyfileGeneratorDialogBase::OnMouseMotion ) );
	HashChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnHashSelected ), NULL, this );
	ShowRandomPoolCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnShowRandomPoolCheckBoxClicked ), NULL, this );
	RandomSizeCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnRandomSizeCheckBoxClicked ), NULL, this );
	GenerateButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnGenerateButtonClick ), NULL, this );
	ChooseSecurityTokenButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfileGeneratorDialogBase::OnSelectSecurityTokenSchemeClick ), NULL, this);
}

LegalNoticesDialogBase::LegalNoticesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer114;
	bSizer114 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer115;
	bSizer115 = new wxBoxSizer( wxVERTICAL );

	LegalNoticesTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE|wxTE_READONLY );
	bSizer115->Add( LegalNoticesTextCtrl, 1, wxALL|wxEXPAND, 5 );

	wxButton* OKButton;
	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer115->Add( OKButton, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );


	bSizer114->Add( bSizer115, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer114 );
	this->Layout();
	bSizer114->Fit( this );
}

LegalNoticesDialogBase::~LegalNoticesDialogBase()
{
}

MountOptionsDialogBase::MountOptionsDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	MainSizer = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer19;
	bSizer19 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer14;
	bSizer14 = new wxBoxSizer( wxHORIZONTAL );

	PasswordSizer = new wxBoxSizer( wxVERTICAL );


	bSizer14->Add( PasswordSizer, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer9;
	bSizer9 = new wxBoxSizer( wxVERTICAL );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer9->Add( OKButton, 0, wxALL|wxEXPAND, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer9->Add( CancelButton, 0, wxALL|wxEXPAND, 5 );


	bSizer9->Add( 0, 0, 1, wxTOP|wxEXPAND, 5 );

	OptionsButton = new wxButton( this, wxID_ANY, _("IDT_FORMAT_OPTIONS"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer9->Add( OptionsButton, 0, wxALL|wxEXPAND, 5 );


	bSizer14->Add( bSizer9, 0, wxEXPAND, 5 );


	bSizer19->Add( bSizer14, 0, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer6;
	bSizer6 = new wxBoxSizer( wxVERTICAL );

	OptionsPanel = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	OptionsSizer = new wxStaticBoxSizer( new wxStaticBox( OptionsPanel, wxID_ANY, wxEmptyString ), wxVERTICAL );


	OptionsSizer->Add( 0, 0, 0, wxTOP, 5 );

	ReadOnlyCheckBox = new wxCheckBox( OptionsSizer->GetStaticBox(), wxID_ANY, _("IDC_MOUNT_READONLY"), wxDefaultPosition, wxDefaultSize, 0 );
	OptionsSizer->Add( ReadOnlyCheckBox, 0, wxALL, 5 );

	RemovableCheckBox = new wxCheckBox( OptionsSizer->GetStaticBox(), wxID_ANY, _("IDC_MOUNT_REMOVABLE"), wxDefaultPosition, wxDefaultSize, 0 );
	OptionsSizer->Add( RemovableCheckBox, 0, wxALL, 5 );

	BackupHeaderCheckBox = new wxCheckBox( OptionsSizer->GetStaticBox(), wxID_ANY, _("IDC_USE_EMBEDDED_HEADER_BAK"), wxDefaultPosition, wxDefaultSize, 0 );
	OptionsSizer->Add( BackupHeaderCheckBox, 0, wxALL, 5 );

	PartitionInSystemEncryptionScopeCheckBox = new wxCheckBox( OptionsSizer->GetStaticBox(), wxID_ANY, _("LINUX_MOUNT_SYSTEM_ENC_PREBOOT"), wxDefaultPosition, wxDefaultSize, 0 );
	OptionsSizer->Add( PartitionInSystemEncryptionScopeCheckBox, 0, wxALL, 5 );

	ProtectionSizer = new wxStaticBoxSizer( new wxStaticBox( OptionsSizer->GetStaticBox(), wxID_ANY, _("IDT_HIDDEN_VOL_PROTECTION") ), wxVERTICAL );

	ProtectionCheckBox = new wxCheckBox( ProtectionSizer->GetStaticBox(), wxID_ANY, _("IDC_PROTECT_HIDDEN_VOL"), wxDefaultPosition, wxDefaultSize, 0 );
	ProtectionSizer->Add( ProtectionCheckBox, 0, wxALL, 5 );

	ProtectionPasswordSizer = new wxBoxSizer( wxVERTICAL );


	ProtectionSizer->Add( ProtectionPasswordSizer, 1, wxEXPAND|wxLEFT, 5 );

	ProtectionHyperlinkCtrl = new wxHyperlinkCtrl( ProtectionSizer->GetStaticBox(), wxID_ANY, _("IDC_LINK_HIDVOL_PROTECTION_INFO"), wxEmptyString, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );

	ProtectionHyperlinkCtrl->SetHoverColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	ProtectionHyperlinkCtrl->SetNormalColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	ProtectionHyperlinkCtrl->SetVisitedColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	ProtectionSizer->Add( ProtectionHyperlinkCtrl, 0, wxALL, 5 );


	OptionsSizer->Add( ProtectionSizer, 1, wxEXPAND|wxALL, 5 );

	FilesystemSizer = new wxBoxSizer( wxVERTICAL );

	m_panel8 = new wxPanel( OptionsSizer->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxStaticBoxSizer* sbSizer28;
	sbSizer28 = new wxStaticBoxSizer( new wxStaticBox( m_panel8, wxID_ANY, _("IDT_FILESYSTEM") ), wxVERTICAL );

	wxBoxSizer* bSizer54;
	bSizer54 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer55;
	bSizer55 = new wxBoxSizer( wxVERTICAL );

	NoFilesystemCheckBox = new wxCheckBox( sbSizer28->GetStaticBox(), wxID_ANY, _("LINUX_DO_NOT_MOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer55->Add( NoFilesystemCheckBox, 0, wxTOP|wxRIGHT|wxLEFT, 5 );


	bSizer54->Add( bSizer55, 1, wxEXPAND, 5 );

	FilesystemOptionsSizer = new wxGridBagSizer( 0, 0 );
	FilesystemOptionsSizer->SetFlexibleDirection( wxBOTH );
	FilesystemOptionsSizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	FilesystemOptionsSizer->SetEmptyCellSize( wxSize( 0,0 ) );

	FilesystemSpacer = new wxBoxSizer( wxVERTICAL );


	FilesystemOptionsSizer->Add( FilesystemSpacer, wxGBPosition( 0, 0 ), wxGBSpan( 1, 1 ), wxEXPAND|wxTOP, 5 );

	MountPointTextCtrlStaticText = new wxStaticText( sbSizer28->GetStaticBox(), wxID_ANY, _("LINUX_MOUNT_AT_DIR"), wxDefaultPosition, wxDefaultSize, 0 );
	MountPointTextCtrlStaticText->Wrap( -1 );
	FilesystemOptionsSizer->Add( MountPointTextCtrlStaticText, wxGBPosition( 1, 0 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxBOTTOM|wxLEFT, 5 );

	MountPointTextCtrl = new wxTextCtrl( sbSizer28->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	FilesystemOptionsSizer->Add( MountPointTextCtrl, wxGBPosition( 1, 1 ), wxGBSpan( 1, 1 ), wxALL|wxEXPAND, 5 );

	MountPointButton = new wxButton( sbSizer28->GetStaticBox(), wxID_ANY, _("LINUX_SELECT"), wxDefaultPosition, wxDefaultSize, 0 );
	FilesystemOptionsSizer->Add( MountPointButton, wxGBPosition( 1, 2 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxRIGHT|wxLEFT, 5 );

	FilesystemOptionsStaticText = new wxStaticText( sbSizer28->GetStaticBox(), wxID_ANY, _("IDT_LINUX_PREF_TAB_MOUNT_OPTIONS"), wxDefaultPosition, wxDefaultSize, 0 );
	FilesystemOptionsStaticText->Wrap( -1 );
	FilesystemOptionsSizer->Add( FilesystemOptionsStaticText, wxGBPosition( 2, 0 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxLEFT, 5 );

	FilesystemOptionsTextCtrl = new wxTextCtrl( sbSizer28->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	FilesystemOptionsSizer->Add( FilesystemOptionsTextCtrl, wxGBPosition( 2, 1 ), wxGBSpan( 1, 2 ), wxEXPAND|wxTOP|wxRIGHT|wxLEFT, 5 );


	FilesystemOptionsSizer->AddGrowableCol( 1 );

	bSizer54->Add( FilesystemOptionsSizer, 0, wxEXPAND, 5 );


	sbSizer28->Add( bSizer54, 0, wxEXPAND|wxBOTTOM, 5 );


	m_panel8->SetSizer( sbSizer28 );
	m_panel8->Layout();
	sbSizer28->Fit( m_panel8 );
	FilesystemSizer->Add( m_panel8, 0, wxEXPAND | wxALL, 5 );


	OptionsSizer->Add( FilesystemSizer, 0, wxEXPAND, 5 );


	OptionsPanel->SetSizer( OptionsSizer );
	OptionsPanel->Layout();
	OptionsSizer->Fit( OptionsPanel );
	bSizer6->Add( OptionsPanel, 1, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 5 );


	bSizer19->Add( bSizer6, 0, wxEXPAND, 5 );


	MainSizer->Add( bSizer19, 1, wxEXPAND, 5 );


	this->SetSizer( MainSizer );
	this->Layout();
	MainSizer->Fit( this );

	this->Centre( wxBOTH );

	// Connect Events
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( MountOptionsDialogBase::OnInitDialog ) );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnOKButtonClick ), NULL, this );
	OptionsButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnOptionsButtonClick ), NULL, this );
	ReadOnlyCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnReadOnlyCheckBoxClick ), NULL, this );
	ProtectionCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnProtectionCheckBoxClick ), NULL, this );
	ProtectionHyperlinkCtrl->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( MountOptionsDialogBase::OnProtectionHyperlinkClick ), NULL, this );
	NoFilesystemCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnNoFilesystemCheckBoxClick ), NULL, this );
	MountPointButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnMountPointButtonClick ), NULL, this );
}

MountOptionsDialogBase::~MountOptionsDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( MountOptionsDialogBase::OnInitDialog ) );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnOKButtonClick ), NULL, this );
	OptionsButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnOptionsButtonClick ), NULL, this );
	ReadOnlyCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnReadOnlyCheckBoxClick ), NULL, this );
	ProtectionCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnProtectionCheckBoxClick ), NULL, this );
	ProtectionHyperlinkCtrl->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( MountOptionsDialogBase::OnProtectionHyperlinkClick ), NULL, this );
	NoFilesystemCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnNoFilesystemCheckBoxClick ), NULL, this );
	MountPointButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( MountOptionsDialogBase::OnMountPointButtonClick ), NULL, this );

}

NewSecurityTokenKeyfileDialogBase::NewSecurityTokenKeyfileDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer143;
	bSizer143 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer144;
	bSizer144 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer42;
	sbSizer42 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, wxEmptyString ), wxVERTICAL );

	wxFlexGridSizer* fgSizer7;
	fgSizer7 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer7->SetFlexibleDirection( wxBOTH );
	fgSizer7->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	wxStaticText* m_staticText47;
	m_staticText47 = new wxStaticText( sbSizer42->GetStaticBox(), wxID_ANY, _("IDT_SECURITY_TOKEN"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_staticText47->Wrap( -1 );
	fgSizer7->Add( m_staticText47, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxBOTTOM|wxLEFT, 5 );

	wxArrayString SecurityTokenChoiceChoices;
	SecurityTokenChoice = new wxChoice( sbSizer42->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, SecurityTokenChoiceChoices, 0 );
	SecurityTokenChoice->SetSelection( 0 );
	fgSizer7->Add( SecurityTokenChoice, 0, wxALL|wxEXPAND, 5 );

	wxStaticText* m_staticText48;
	m_staticText48 = new wxStaticText( sbSizer42->GetStaticBox(), wxID_ANY, _("IDT_TOKEN_KEYFILE_NAME"), wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT );
	m_staticText48->Wrap( -1 );
	fgSizer7->Add( m_staticText48, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxBOTTOM|wxLEFT, 5 );

	KeyfileNameTextCtrl = new wxTextCtrl( sbSizer42->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer7->Add( KeyfileNameTextCtrl, 0, wxEXPAND|wxALL, 5 );


	sbSizer42->Add( fgSizer7, 1, wxEXPAND|wxTOP, 5 );


	bSizer144->Add( sbSizer42, 1, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer167;
	bSizer167 = new wxBoxSizer( wxHORIZONTAL );


	bSizer167->Add( 0, 0, 1, wxEXPAND, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer167->Add( CancelButton, 0, wxALL, 5 );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer167->Add( OKButton, 0, wxALL, 5 );


	bSizer144->Add( bSizer167, 0, wxEXPAND, 5 );


	bSizer143->Add( bSizer144, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer143 );
	this->Layout();
	bSizer143->Fit( this );

	// Connect Events
	KeyfileNameTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( NewSecurityTokenKeyfileDialogBase::OnKeyfileNameChanged ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( NewSecurityTokenKeyfileDialogBase::OnOKButtonClick ), NULL, this );
}

NewSecurityTokenKeyfileDialogBase::~NewSecurityTokenKeyfileDialogBase()
{
	// Disconnect Events
	KeyfileNameTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( NewSecurityTokenKeyfileDialogBase::OnKeyfileNameChanged ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( NewSecurityTokenKeyfileDialogBase::OnOKButtonClick ), NULL, this );

}

PreferencesDialogBase::PreferencesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	bSizer32 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer178;
	bSizer178 = new wxBoxSizer( wxVERTICAL );

	PreferencesNotebook = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0 );
	SecurityPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer44;
	bSizer44 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer33;
	bSizer33 = new wxBoxSizer( wxVERTICAL );

	AutoDismountSizer = new wxStaticBoxSizer( new wxStaticBox( SecurityPage, wxID_ANY, _("IDT_AUTO_UNMOUNT") ), wxVERTICAL );

	wxStaticBoxSizer* sbSizer13;
	sbSizer13 = new wxStaticBoxSizer( new wxStaticBox( AutoDismountSizer->GetStaticBox(), wxID_ANY, _("LINUX_UNMOUNT_ALL_WHEN") ), wxVERTICAL );

	DismountOnLogOffCheckBox = new wxCheckBox( sbSizer13->GetStaticBox(), wxID_ANY, _("IDC_PREF_UNMOUNT_LOGOFF"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer13->Add( DismountOnLogOffCheckBox, 0, wxALL, 5 );

	DismountOnScreenSaverCheckBox = new wxCheckBox( sbSizer13->GetStaticBox(), wxID_ANY, _("IDC_PREF_UNMOUNT_SCREENSAVER"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer13->Add( DismountOnScreenSaverCheckBox, 0, wxALL, 5 );

	DismountOnPowerSavingCheckBox = new wxCheckBox( sbSizer13->GetStaticBox(), wxID_ANY, _("LINUX_ENTERING_POVERSAWING"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer13->Add( DismountOnPowerSavingCheckBox, 0, wxALL, 5 );


	AutoDismountSizer->Add( sbSizer13, 0, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer34;
	bSizer34 = new wxBoxSizer( wxHORIZONTAL );

	DismountOnInactivityCheckBox = new wxCheckBox( AutoDismountSizer->GetStaticBox(), wxID_ANY, _("IDC_PREF_UNMOUNT_INACTIVE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer34->Add( DismountOnInactivityCheckBox, 0, wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	DismountOnInactivitySpinCtrl = new wxSpinCtrl( AutoDismountSizer->GetStaticBox(), wxID_ANY, wxT("1"), wxDefaultPosition, wxSize( -1,-1 ), wxSP_ARROW_KEYS, 1, 9999, 1 );
	DismountOnInactivitySpinCtrl->SetMinSize( wxSize( 60,-1 ) );

	bSizer34->Add( DismountOnInactivitySpinCtrl, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	wxStaticText* m_staticText5;
	m_staticText5 = new wxStaticText( AutoDismountSizer->GetStaticBox(), wxID_ANY, _("MINUTES"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText5->Wrap( -1 );
	bSizer34->Add( m_staticText5, 1, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxRIGHT, 5 );


	AutoDismountSizer->Add( bSizer34, 0, wxEXPAND, 5 );

	ForceAutoDismountCheckBox = new wxCheckBox( AutoDismountSizer->GetStaticBox(), wxID_ANY, _("IDC_PREF_FORCE_AUTO_UNMOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	AutoDismountSizer->Add( ForceAutoDismountCheckBox, 0, wxALL, 5 );


	bSizer33->Add( AutoDismountSizer, 0, wxEXPAND|wxALL, 5 );

	FilesystemSecuritySizer = new wxStaticBoxSizer( new wxStaticBox( SecurityPage, wxID_ANY, _("LINUX_PREF_TAB_MOUNT_OPTIONS_FS") ), wxVERTICAL );

	PreserveTimestampsCheckBox = new wxCheckBox( FilesystemSecuritySizer->GetStaticBox(), wxID_ANY, _("IDC_PRESERVE_TIMESTAMPS"), wxDefaultPosition, wxDefaultSize, 0 );
	FilesystemSecuritySizer->Add( PreserveTimestampsCheckBox, 0, wxALL, 5 );


	bSizer33->Add( FilesystemSecuritySizer, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer14;
	sbSizer14 = new wxStaticBoxSizer( new wxStaticBox( SecurityPage, wxID_ANY, _("IDT_PW_CACHE_OPTIONS") ), wxVERTICAL );

	WipeCacheOnCloseCheckBox = new wxCheckBox( sbSizer14->GetStaticBox(), wxID_ANY, _("IDC_PREF_WIPE_CACHE_ON_EXIT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer14->Add( WipeCacheOnCloseCheckBox, 0, wxALL, 5 );

	WipeCacheOnAutoDismountCheckBox = new wxCheckBox( sbSizer14->GetStaticBox(), wxID_ANY, _("IDC_PREF_WIPE_CACHE_ON_AUTOUNMOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer14->Add( WipeCacheOnAutoDismountCheckBox, 0, wxALL, 5 );


	bSizer33->Add( sbSizer14, 0, wxEXPAND|wxALL, 5 );


	bSizer44->Add( bSizer33, 1, wxEXPAND|wxALL, 5 );


	SecurityPage->SetSizer( bSizer44 );
	SecurityPage->Layout();
	bSizer44->Fit( SecurityPage );
	PreferencesNotebook->AddPage( SecurityPage, _("LINUX_PREF_TAB_SECURITY"), true );
	DefaultMountOptionsPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer46;
	bSizer46 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer35;
	bSizer35 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer15;
	sbSizer15 = new wxStaticBoxSizer( new wxStaticBox( DefaultMountOptionsPage, wxID_ANY, _("IDT_DEFAULT_MOUNT_OPTIONS") ), wxVERTICAL );

	MountReadOnlyCheckBox = new wxCheckBox( sbSizer15->GetStaticBox(), wxID_ANY, _("IDC_PREF_MOUNT_READONLY"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer15->Add( MountReadOnlyCheckBox, 0, wxALL, 5 );

	MountRemovableCheckBox = new wxCheckBox( sbSizer15->GetStaticBox(), wxID_ANY, _("IDC_PREF_MOUNT_REMOVABLE"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer15->Add( MountRemovableCheckBox, 0, wxALL, 5 );

	CachePasswordsCheckBox = new wxCheckBox( sbSizer15->GetStaticBox(), wxID_ANY, _("IDC_TRAV_CACHE_PASSWORDS"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer15->Add( CachePasswordsCheckBox, 0, wxALL, 5 );

	wxBoxSizer* bSizer163;
	bSizer163 = new wxBoxSizer( wxHORIZONTAL );

	Pkcs5PrfStaticText = new wxStaticText( sbSizer15->GetStaticBox(), wxID_ANY, _("PKCS5_PRF"), wxDefaultPosition, wxDefaultSize, 0 );
	Pkcs5PrfStaticText->Wrap( -1 );
	bSizer163->Add( Pkcs5PrfStaticText, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	wxArrayString Pkcs5PrfChoiceChoices;
	Pkcs5PrfChoice = new wxChoice( sbSizer15->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, Pkcs5PrfChoiceChoices, 0 );
	Pkcs5PrfChoice->SetSelection( 0 );
	bSizer163->Add( Pkcs5PrfChoice, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );


	sbSizer15->Add( bSizer163, 0, wxEXPAND, 5 );


	bSizer35->Add( sbSizer15, 0, wxEXPAND|wxALL, 5 );

	FilesystemSizer = new wxStaticBoxSizer( new wxStaticBox( DefaultMountOptionsPage, wxID_ANY, _("LINUX_PREF_TAB_MOUNT_OPTIONS_FS") ), wxVERTICAL );

	wxFlexGridSizer* fgSizer3;
	fgSizer3 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer3->AddGrowableCol( 1 );
	fgSizer3->SetFlexibleDirection( wxBOTH );
	fgSizer3->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	wxStaticText* m_staticText6;
	m_staticText6 = new wxStaticText( FilesystemSizer->GetStaticBox(), wxID_ANY, _("IDT_LINUX_PREF_TAB_MOUNT_OPTIONS"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText6->Wrap( -1 );
	fgSizer3->Add( m_staticText6, 0, wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT, 5 );

	FilesystemOptionsTextCtrl = new wxTextCtrl( FilesystemSizer->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer3->Add( FilesystemOptionsTextCtrl, 0, wxALL|wxEXPAND, 5 );


	FilesystemSizer->Add( fgSizer3, 1, wxEXPAND, 5 );


	bSizer35->Add( FilesystemSizer, 0, wxEXPAND|wxALL, 5 );


	bSizer46->Add( bSizer35, 1, wxEXPAND|wxALL, 5 );


	DefaultMountOptionsPage->SetSizer( bSizer46 );
	DefaultMountOptionsPage->Layout();
	bSizer46->Fit( DefaultMountOptionsPage );
	PreferencesNotebook->AddPage( DefaultMountOptionsPage, _("LINUX_PREF_TAB_MOUNT_OPTIONS"), false );
	BackgroundTaskPanel = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer61;
	bSizer61 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer62;
	bSizer62 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer18;
	sbSizer18 = new wxStaticBoxSizer( new wxStaticBox( BackgroundTaskPanel, wxID_ANY, _("IDT_TASKBAR_ICON") ), wxVERTICAL );

	BackgroundTaskEnabledCheckBox = new wxCheckBox( sbSizer18->GetStaticBox(), wxID_ANY, _("IDC_PREF_BKG_TASK_ENABLE"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer18->Add( BackgroundTaskEnabledCheckBox, 0, wxALL, 5 );

	CloseBackgroundTaskOnNoVolumesCheckBox = new wxCheckBox( sbSizer18->GetStaticBox(), wxID_ANY, _("IDC_CLOSE_BKG_TASK_WHEN_NOVOL"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer18->Add( CloseBackgroundTaskOnNoVolumesCheckBox, 0, wxALL, 5 );

	wxStaticBoxSizer* sbSizer26;
	sbSizer26 = new wxStaticBoxSizer( new wxStaticBox( sbSizer18->GetStaticBox(), wxID_ANY, _("TASKICON_PREF_MENU_ITEMS") ), wxVERTICAL );

	BackgroundTaskMenuMountItemsEnabledCheckBox = new wxCheckBox( sbSizer26->GetStaticBox(), wxID_ANY, _("HK_MOUNT_FAVORITE_VOLUMES"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer26->Add( BackgroundTaskMenuMountItemsEnabledCheckBox, 0, wxALL, 5 );

	BackgroundTaskMenuOpenItemsEnabledCheckBox = new wxCheckBox( sbSizer26->GetStaticBox(), wxID_ANY, _("TASKICON_PREF_OPEN_VOL"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer26->Add( BackgroundTaskMenuOpenItemsEnabledCheckBox, 0, wxALL, 5 );

	BackgroundTaskMenuDismountItemsEnabledCheckBox = new wxCheckBox( sbSizer26->GetStaticBox(), wxID_ANY, _("TASKICON_PREF_UNMOUNT_VOL"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer26->Add( BackgroundTaskMenuDismountItemsEnabledCheckBox, 0, wxALL, 5 );


	sbSizer18->Add( sbSizer26, 1, wxEXPAND|wxALL, 5 );


	bSizer62->Add( sbSizer18, 0, wxEXPAND|wxALL, 5 );


	bSizer61->Add( bSizer62, 1, wxEXPAND|wxALL, 5 );


	BackgroundTaskPanel->SetSizer( bSizer61 );
	BackgroundTaskPanel->Layout();
	bSizer61->Fit( BackgroundTaskPanel );
	PreferencesNotebook->AddPage( BackgroundTaskPanel, _("LINUX_PREF_TAB_BACKGROUND_TASK"), false );
	SystemIntegrationPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer49;
	bSizer49 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer37;
	bSizer37 = new wxBoxSizer( wxVERTICAL );

	LogOnSizer = new wxStaticBoxSizer( new wxStaticBox( SystemIntegrationPage, wxID_ANY, _("LINUX_LOGIN_ACTION") ), wxVERTICAL );

	StartOnLogonCheckBox = new wxCheckBox( LogOnSizer->GetStaticBox(), wxID_ANY, _("IDC_PREF_LOGON_START"), wxDefaultPosition, wxDefaultSize, 0 );
	LogOnSizer->Add( StartOnLogonCheckBox, 0, wxALL, 5 );

	MountFavoritesOnLogonCheckBox = new wxCheckBox( LogOnSizer->GetStaticBox(), wxID_ANY, _("HK_MOUNT_FAVORITE_VOLUMES"), wxDefaultPosition, wxDefaultSize, 0 );
	LogOnSizer->Add( MountFavoritesOnLogonCheckBox, 0, wxALL, 5 );

	MountDevicesOnLogonCheckBox = new wxCheckBox( LogOnSizer->GetStaticBox(), wxID_ANY, _("IDC_PREF_LOGON_MOUNT_DEVICES"), wxDefaultPosition, wxDefaultSize, 0 );
	LogOnSizer->Add( MountDevicesOnLogonCheckBox, 0, wxALL, 5 );


	bSizer37->Add( LogOnSizer, 0, wxALL|wxEXPAND, 5 );

	ExplorerSizer = new wxStaticBoxSizer( new wxStaticBox( SystemIntegrationPage, wxID_ANY, _("LINUX_PREF_TAB_SYSTEM_INTEGRATION_EXPLORER") ), wxVERTICAL );

	OpenExplorerWindowAfterMountCheckBox = new wxCheckBox( ExplorerSizer->GetStaticBox(), wxID_ANY, _("IDC_PREF_OPEN_EXPLORER"), wxDefaultPosition, wxDefaultSize, 0 );
	ExplorerSizer->Add( OpenExplorerWindowAfterMountCheckBox, 0, wxALL, 5 );

	CloseExplorerWindowsOnDismountCheckBox = new wxCheckBox( ExplorerSizer->GetStaticBox(), wxID_ANY, _("LINUX_CLOSE_EXPL_ON_UNMOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	ExplorerSizer->Add( CloseExplorerWindowsOnDismountCheckBox, 0, wxALL, 5 );


	bSizer37->Add( ExplorerSizer, 0, wxEXPAND|wxALL, 5 );

	KernelServicesSizer = new wxStaticBoxSizer( new wxStaticBox( SystemIntegrationPage, wxID_ANY, _("LINUX_PREF_KERNEL_SERVICES") ), wxVERTICAL );

	NoKernelCryptoCheckBox = new wxCheckBox( KernelServicesSizer->GetStaticBox(), wxID_ANY, _("LINUX_PREF_KERNEL_CRYPT"), wxDefaultPosition, wxDefaultSize, 0 );
	KernelServicesSizer->Add( NoKernelCryptoCheckBox, 0, wxALL, 5 );


	bSizer37->Add( KernelServicesSizer, 0, wxEXPAND|wxALL, 5 );


	bSizer49->Add( bSizer37, 1, wxEXPAND|wxALL, 5 );


	SystemIntegrationPage->SetSizer( bSizer49 );
	SystemIntegrationPage->Layout();
	bSizer49->Fit( SystemIntegrationPage );
	PreferencesNotebook->AddPage( SystemIntegrationPage, _("LINUX_PREF_TAB_SYSTEM_INTEGRATION"), false );
	PerformanceOptionsPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer151;
	bSizer151 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer152;
	bSizer152 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer44;
	sbSizer44 = new wxStaticBoxSizer( new wxStaticBox( PerformanceOptionsPage, wxID_ANY, _("IDT_ACCELERATION_OPTIONS") ), wxVERTICAL );

	wxBoxSizer* bSizer158;
	bSizer158 = new wxBoxSizer( wxHORIZONTAL );

	wxStaticText* m_staticText57;
	m_staticText57 = new wxStaticText( sbSizer44->GetStaticBox(), wxID_ANY, _("IDT_HW_AES_SUPPORTED_BY_CPU"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText57->Wrap( -1 );
	bSizer158->Add( m_staticText57, 0, wxALL, 5 );

	AesHwCpuSupportedStaticText = new wxStaticText( sbSizer44->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0|wxBORDER_SUNKEN );
	AesHwCpuSupportedStaticText->Wrap( -1 );
	bSizer158->Add( AesHwCpuSupportedStaticText, 0, wxALL, 5 );


	sbSizer44->Add( bSizer158, 1, wxEXPAND, 5 );


	sbSizer44->Add( 0, 0, 0, wxBOTTOM, 5 );

	NoHardwareCryptoCheckBox = new wxCheckBox( sbSizer44->GetStaticBox(), wxID_ANY, _("IDC_ENABLE_HARDWARE_ENCRYPTION_NEG"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer44->Add( NoHardwareCryptoCheckBox, 0, wxALL, 5 );


	bSizer152->Add( sbSizer44, 0, wxEXPAND|wxALL, 5 );


	bSizer151->Add( bSizer152, 1, wxALL|wxEXPAND, 5 );


	PerformanceOptionsPage->SetSizer( bSizer151 );
	PerformanceOptionsPage->Layout();
	bSizer151->Fit( PerformanceOptionsPage );
	PreferencesNotebook->AddPage( PerformanceOptionsPage, _("LINUX_PREF_TAB_PERFORMANCE"), false );
	DefaultKeyfilesPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer40;
	bSizer40 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer43;
	bSizer43 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* bSizer42;
	bSizer42 = new wxStaticBoxSizer( new wxStaticBox( DefaultKeyfilesPage, wxID_ANY, _("IDD_KEYFILES") ), wxVERTICAL );

	DefaultKeyfilesSizer = new wxBoxSizer( wxVERTICAL );


	bSizer42->Add( DefaultKeyfilesSizer, 1, wxEXPAND, 5 );


	bSizer43->Add( bSizer42, 1, wxEXPAND|wxALL, 5 );

	UseKeyfilesCheckBox = new wxCheckBox( DefaultKeyfilesPage, wxID_ANY, _("IDC_KEYFILES_ENABLE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer43->Add( UseKeyfilesCheckBox, 0, wxALL, 5 );


	bSizer40->Add( bSizer43, 1, wxEXPAND|wxALL, 5 );


	DefaultKeyfilesPage->SetSizer( bSizer40 );
	DefaultKeyfilesPage->Layout();
	bSizer40->Fit( DefaultKeyfilesPage );
	PreferencesNotebook->AddPage( DefaultKeyfilesPage, _("LINUX_PREF_TAB_KEYFILES"), false );
	SecurityTokensPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer127;
	bSizer127 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer128;
	bSizer128 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer36;
	sbSizer36 = new wxStaticBoxSizer( new wxStaticBox( SecurityTokensPage, wxID_ANY, _("IDT_PKCS11_LIB_PATH") ), wxVERTICAL );

	wxBoxSizer* bSizer129;
	bSizer129 = new wxBoxSizer( wxHORIZONTAL );

	Pkcs11ModulePathTextCtrl = new wxTextCtrl( sbSizer36->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	bSizer129->Add( Pkcs11ModulePathTextCtrl, 1, wxALL, 5 );

	SelectPkcs11ModuleButton = new wxButton( sbSizer36->GetStaticBox(), wxID_ANY, _("IDC_SELECT_PKCS11_MODULE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer129->Add( SelectPkcs11ModuleButton, 0, wxALL, 5 );


	sbSizer36->Add( bSizer129, 1, wxEXPAND, 5 );


	bSizer128->Add( sbSizer36, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer37;
	sbSizer37 = new wxStaticBoxSizer( new wxStaticBox( SecurityTokensPage, wxID_ANY, _("IDT_SECURITY_OPTIONS") ), wxVERTICAL );

	CloseSecurityTokenSessionsAfterMountCheckBox = new wxCheckBox( sbSizer37->GetStaticBox(), wxID_ANY, _("IDC_CLOSE_TOKEN_SESSION_AFTER_MOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer37->Add( CloseSecurityTokenSessionsAfterMountCheckBox, 0, wxALL, 5 );


	bSizer128->Add( sbSizer37, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer38;
	sbSizer38 = new wxStaticBoxSizer( new wxStaticBox( SecurityTokensPage, wxID_ANY, _("IDT_EMV_OPTIONS") ), wxVERTICAL );

	EMVSupportEnabledCheckBox = new wxCheckBox( sbSizer38->GetStaticBox(), wxID_ANY, _("IDC_ENABLE_EMV_SUPPORT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer38->Add( EMVSupportEnabledCheckBox, 0, wxALL, 5 );


	bSizer128->Add( sbSizer38, 0, wxALL|wxEXPAND, 5 );


	bSizer127->Add( bSizer128, 1, wxEXPAND|wxALL, 5 );


	SecurityTokensPage->SetSizer( bSizer127 );
	SecurityTokensPage->Layout();
	bSizer127->Fit( SecurityTokensPage );
	PreferencesNotebook->AddPage( SecurityTokensPage, _("LINUX_PREF_TAB_TOKENS"), false );
	HotkeysPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer51;
	bSizer51 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer38;
	bSizer38 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer21;
	sbSizer21 = new wxStaticBoxSizer( new wxStaticBox( HotkeysPage, wxID_ANY, _("LINUX_SYSTEM_HOTKEYS") ), wxVERTICAL );

	HotkeyListCtrl = new wxListCtrl( sbSizer21->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_SINGLE_SEL|wxLC_VRULES|wxBORDER_SUNKEN );
	sbSizer21->Add( HotkeyListCtrl, 1, wxALL|wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer23;
	sbSizer23 = new wxStaticBoxSizer( new wxStaticBox( sbSizer21->GetStaticBox(), wxID_ANY, _("SHORTCUT") ), wxVERTICAL );

	wxFlexGridSizer* fgSizer4;
	fgSizer4 = new wxFlexGridSizer( 2, 3, 0, 0 );
	fgSizer4->SetFlexibleDirection( wxBOTH );
	fgSizer4->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	wxStaticText* m_staticText10;
	m_staticText10 = new wxStaticText( sbSizer23->GetStaticBox(), wxID_ANY, _("IDT_HOTKEY_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText10->Wrap( -1 );
	fgSizer4->Add( m_staticText10, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxBOTTOM|wxLEFT, 5 );

	HotkeyTextCtrl = new wxTextCtrl( sbSizer23->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer4->Add( HotkeyTextCtrl, 0, wxALL|wxEXPAND, 5 );

	AssignHotkeyButton = new wxButton( sbSizer23->GetStaticBox(), wxID_ANY, _("IDC_HOTKEY_ASSIGN"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer4->Add( AssignHotkeyButton, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	fgSizer4->Add( 0, 0, 1, wxEXPAND, 5 );

	wxGridSizer* gSizer4;
	gSizer4 = new wxGridSizer( 1, 4, 0, 0 );

	HotkeyControlCheckBox = new wxCheckBox( sbSizer23->GetStaticBox(), wxID_ANY, _("VK_CONTROL"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer4->Add( HotkeyControlCheckBox, 0, wxALL, 5 );

	HotkeyShiftCheckBox = new wxCheckBox( sbSizer23->GetStaticBox(), wxID_ANY, _("VK_SHIFT"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer4->Add( HotkeyShiftCheckBox, 0, wxALL, 5 );

	HotkeyAltCheckBox = new wxCheckBox( sbSizer23->GetStaticBox(), wxID_ANY, _("VK_ALT"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer4->Add( HotkeyAltCheckBox, 0, wxALL, 5 );

	HotkeyWinCheckBox = new wxCheckBox( sbSizer23->GetStaticBox(), wxID_ANY, _("VK_WIN"), wxDefaultPosition, wxDefaultSize, 0 );
	gSizer4->Add( HotkeyWinCheckBox, 0, wxALL, 5 );


	fgSizer4->Add( gSizer4, 1, wxEXPAND, 5 );

	RemoveHotkeyButton = new wxButton( sbSizer23->GetStaticBox(), wxID_ANY, _("IDC_KEYREMOVE"), wxDefaultPosition, wxDefaultSize, 0 );
	fgSizer4->Add( RemoveHotkeyButton, 1, wxALL, 5 );


	sbSizer23->Add( fgSizer4, 1, wxALIGN_RIGHT, 5 );


	sbSizer21->Add( sbSizer23, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer24;
	sbSizer24 = new wxStaticBoxSizer( new wxStaticBox( sbSizer21->GetStaticBox(), wxID_ANY, _("IDT_FORMAT_OPTIONS") ), wxVERTICAL );

	BeepAfterHotkeyMountDismountCheckBox = new wxCheckBox( sbSizer24->GetStaticBox(), wxID_ANY, _("LINUX_SOUND_NOTIFICATION"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer24->Add( BeepAfterHotkeyMountDismountCheckBox, 0, wxALL, 5 );

	DisplayMessageAfterHotkeyDismountCheckBox = new wxCheckBox( sbSizer24->GetStaticBox(), wxID_ANY, _("LINUX_CONFIRM_AFTER_UNMOUNT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer24->Add( DisplayMessageAfterHotkeyDismountCheckBox, 0, wxALL, 5 );


	sbSizer21->Add( sbSizer24, 0, wxEXPAND|wxALL, 5 );


	bSizer38->Add( sbSizer21, 1, wxEXPAND|wxALL, 5 );


	bSizer51->Add( bSizer38, 1, wxEXPAND|wxALL, 5 );


	HotkeysPage->SetSizer( bSizer51 );
	HotkeysPage->Layout();
	bSizer51->Fit( HotkeysPage );
	PreferencesNotebook->AddPage( HotkeysPage, _("LINUX_HOTKEYS"), false );
	LanguagesPage = new wxPanel( PreferencesNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer170;
	bSizer170 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer171;
	bSizer171 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer173;
	bSizer173 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer49;
	sbSizer49 = new wxStaticBoxSizer( new wxStaticBox( LanguagesPage, wxID_ANY, _("LINUX_LANGUAGE") ), wxVERTICAL );

	wxBoxSizer* bSizer174;
	bSizer174 = new wxBoxSizer( wxHORIZONTAL );

	m_staticText73 = new wxStaticText( sbSizer49->GetStaticBox(), wxID_ANY, _("IDT_ACTIVE_LANG_PACK"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText73->Wrap( -1 );
	bSizer174->Add( m_staticText73, 0, wxLEFT|wxTOP, 5 );

	m_staticText74 = new wxStaticText( sbSizer49->GetStaticBox(), wxID_ANY, _("CURRENT_LANGUAGE_PACK"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText74->Wrap( -1 );
	bSizer174->Add( m_staticText74, 0, wxLEFT|wxRIGHT|wxTOP, 5 );


	sbSizer49->Add( bSizer174, 0, wxBOTTOM, 5 );

	wxWrapSizer* wSizer1;
	wSizer1 = new wxWrapSizer( wxHORIZONTAL, wxWRAPSIZER_DEFAULT_FLAGS );

	m_staticText72 = new wxStaticText( sbSizer49->GetStaticBox(), wxID_ANY, _("IDT_LANGPACK_AUTHORS"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText72->Wrap( -1 );
	wSizer1->Add( m_staticText72, 0, wxBOTTOM|wxLEFT, 5 );

	m_staticText71 = new wxStaticText( sbSizer49->GetStaticBox(), wxID_ANY, _("LANGUAGE_TRANSLATORS"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText71->Wrap( -1 );
	wSizer1->Add( m_staticText71, 0, wxALIGN_CENTER_VERTICAL|wxBOTTOM|wxLEFT|wxRIGHT, 5 );


	sbSizer49->Add( wSizer1, 0, 0, 5 );

	LanguageListBox = new wxListBox( sbSizer49->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_SINGLE|wxLB_SORT );
	sbSizer49->Add( LanguageListBox, 1, wxEXPAND|wxLEFT|wxRIGHT|wxTOP, 5 );

	SysDefaultLangButton = new wxButton( sbSizer49->GetStaticBox(), wxID_ANY, _("LINUX_SELECT_SYS_DEFAULT_LANG"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer49->Add( SysDefaultLangButton, 0, wxALIGN_BOTTOM|wxALL|wxEXPAND, 5 );


	bSizer173->Add( sbSizer49, 1, wxALL|wxEXPAND, 5 );


	bSizer171->Add( bSizer173, 1, wxEXPAND, 5 );


	bSizer170->Add( bSizer171, 1, wxALL|wxEXPAND, 5 );


	LanguagesPage->SetSizer( bSizer170 );
	LanguagesPage->Layout();
	bSizer170->Fit( LanguagesPage );
	PreferencesNotebook->AddPage( LanguagesPage, _("LINUX_LANGUAGE"), false );

	bSizer178->Add( PreferencesNotebook, 1, wxEXPAND | wxALL, 5 );

	wxBoxSizer* bSizer182;
	bSizer182 = new wxBoxSizer( wxHORIZONTAL );


	bSizer182->Add( 0, 0, 1, wxEXPAND, 5 );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer182->Add( OKButton, 0, wxALL, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer182->Add( CancelButton, 0, wxALL, 5 );


	bSizer178->Add( bSizer182, 0, wxALL|wxEXPAND, 5 );


	bSizer32->Add( bSizer178, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer32 );
	this->Layout();
	bSizer32->Fit( this );

	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( PreferencesDialogBase::OnClose ) );
	PreferencesNotebook->Connect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler( PreferencesDialogBase::OnPageChanged ), NULL, this );
	DismountOnScreenSaverCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnDismountOnScreenSaverCheckBoxClick ), NULL, this );
	DismountOnPowerSavingCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnDismountOnPowerSavingCheckBoxClick ), NULL, this );
	ForceAutoDismountCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnForceAutoDismountCheckBoxClick ), NULL, this );
	PreserveTimestampsCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnPreserveTimestampsCheckBoxClick ), NULL, this );
	BackgroundTaskEnabledCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnBackgroundTaskEnabledCheckBoxClick ), NULL, this );
	NoKernelCryptoCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnNoKernelCryptoCheckBoxClick ), NULL, this );
	NoHardwareCryptoCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnNoHardwareCryptoCheckBoxClick ), NULL, this );
	SelectPkcs11ModuleButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnSelectPkcs11ModuleButtonClick ), NULL, this );
	HotkeyListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( PreferencesDialogBase::OnHotkeyListItemDeselected ), NULL, this );
	HotkeyListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( PreferencesDialogBase::OnHotkeyListItemSelected ), NULL, this );
	AssignHotkeyButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnAssignHotkeyButtonClick ), NULL, this );
	RemoveHotkeyButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnRemoveHotkeyButtonClick ), NULL, this );
	SysDefaultLangButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnSysDefaultLangButtonClick ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnOKButtonClick ), NULL, this );
}

PreferencesDialogBase::~PreferencesDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( PreferencesDialogBase::OnClose ) );
	PreferencesNotebook->Disconnect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler( PreferencesDialogBase::OnPageChanged ), NULL, this );
	DismountOnScreenSaverCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnDismountOnScreenSaverCheckBoxClick ), NULL, this );
	DismountOnPowerSavingCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnDismountOnPowerSavingCheckBoxClick ), NULL, this );
	ForceAutoDismountCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnForceAutoDismountCheckBoxClick ), NULL, this );
	PreserveTimestampsCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnPreserveTimestampsCheckBoxClick ), NULL, this );
	BackgroundTaskEnabledCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnBackgroundTaskEnabledCheckBoxClick ), NULL, this );
	NoKernelCryptoCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnNoKernelCryptoCheckBoxClick ), NULL, this );
	NoHardwareCryptoCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnNoHardwareCryptoCheckBoxClick ), NULL, this );
	SelectPkcs11ModuleButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnSelectPkcs11ModuleButtonClick ), NULL, this );
	HotkeyListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( PreferencesDialogBase::OnHotkeyListItemDeselected ), NULL, this );
	HotkeyListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( PreferencesDialogBase::OnHotkeyListItemSelected ), NULL, this );
	AssignHotkeyButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnAssignHotkeyButtonClick ), NULL, this );
	RemoveHotkeyButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnRemoveHotkeyButtonClick ), NULL, this );
	SysDefaultLangButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnSysDefaultLangButtonClick ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PreferencesDialogBase::OnOKButtonClick ), NULL, this );

}

RandomPoolEnrichmentDialogBase::RandomPoolEnrichmentDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	MainSizer = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer144;
	bSizer144 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer145;
	bSizer145 = new wxBoxSizer( wxHORIZONTAL );


	bSizer145->Add( 0, 0, 1, wxEXPAND, 5 );

	wxStaticText* m_staticText49;
	m_staticText49 = new wxStaticText( this, wxID_ANY, _("IDT_PRF"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText49->Wrap( -1 );
	bSizer145->Add( m_staticText49, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	wxArrayString HashChoiceChoices;
	HashChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, HashChoiceChoices, 0 );
	HashChoice->SetSelection( 0 );
	bSizer145->Add( HashChoice, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer145->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer144->Add( bSizer145, 0, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer43;
	sbSizer43 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, wxEmptyString ), wxVERTICAL );

	wxBoxSizer* bSizer147;
	bSizer147 = new wxBoxSizer( wxHORIZONTAL );

	wxStaticText* m_staticText52;
	m_staticText52 = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_RANDOM_POOL"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText52->Wrap( -1 );
	bSizer147->Add( m_staticText52, 0, wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	RandomPoolStaticText = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	RandomPoolStaticText->Wrap( -1 );
	RandomPoolStaticText->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier New") ) );

	bSizer147->Add( RandomPoolStaticText, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	ShowRandomPoolCheckBox = new wxCheckBox( sbSizer43->GetStaticBox(), wxID_ANY, _("IDC_DISPLAY_POOL_CONTENTS"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer147->Add( ShowRandomPoolCheckBox, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	sbSizer43->Add( bSizer147, 0, wxEXPAND|wxTOP, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer45;
	sbSizer45 = new wxStaticBoxSizer( new wxStaticBox( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_ENTROPY_BAR") ), wxVERTICAL );

	CollectedEntropy = new wxGauge( sbSizer45->GetStaticBox(), wxID_ANY, 2560, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL|wxGA_SMOOTH );
	CollectedEntropy->SetValue( 0 );
	sbSizer45->Add( CollectedEntropy, 0, wxALL|wxEXPAND, 5 );


	sbSizer43->Add( sbSizer45, 0, wxBOTTOM|wxEXPAND|wxTOP, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );

	MouseStaticText = new wxStaticText( sbSizer43->GetStaticBox(), wxID_ANY, _("IDT_RANDOM_POOL_ENRICHMENT_NOTE"), wxDefaultPosition, wxDefaultSize, 0 );
	MouseStaticText->Wrap( -1 );
	sbSizer43->Add( MouseStaticText, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );


	sbSizer43->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer144->Add( sbSizer43, 1, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 5 );

	wxBoxSizer* bSizer146;
	bSizer146 = new wxBoxSizer( wxHORIZONTAL );


	bSizer146->Add( 0, 0, 1, wxEXPAND, 5 );

	ContinueButton = new wxButton( this, wxID_OK, _("CONTINUE"), wxDefaultPosition, wxDefaultSize, 0 );

	ContinueButton->SetDefault();
	bSizer146->Add( ContinueButton, 0, wxALL, 5 );


	bSizer146->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer144->Add( bSizer146, 0, wxEXPAND, 5 );


	MainSizer->Add( bSizer144, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( MainSizer );
	this->Layout();
	MainSizer->Fit( this );

	this->Centre( wxBOTH );

	// Connect Events
	this->Connect( wxEVT_MOTION, wxMouseEventHandler( RandomPoolEnrichmentDialogBase::OnMouseMotion ) );
	HashChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( RandomPoolEnrichmentDialogBase::OnHashSelected ), NULL, this );
	ShowRandomPoolCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( RandomPoolEnrichmentDialogBase::OnShowRandomPoolCheckBoxClicked ), NULL, this );
}

RandomPoolEnrichmentDialogBase::~RandomPoolEnrichmentDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_MOTION, wxMouseEventHandler( RandomPoolEnrichmentDialogBase::OnMouseMotion ) );
	HashChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( RandomPoolEnrichmentDialogBase::OnHashSelected ), NULL, this );
	ShowRandomPoolCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( RandomPoolEnrichmentDialogBase::OnShowRandomPoolCheckBoxClicked ), NULL, this );

}

SecurityTokenKeyfilesDialogBase::SecurityTokenKeyfilesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( -1,-1 ), wxDefaultSize );
	this->SetExtraStyle( this->GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );

	wxBoxSizer* bSizer3;
	bSizer3 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer138;
	bSizer138 = new wxBoxSizer( wxHORIZONTAL );

	wxBoxSizer* bSizer142;
	bSizer142 = new wxBoxSizer( wxVERTICAL );

	SecurityTokenKeyfileListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VRULES|wxBORDER_SUNKEN );
	bSizer142->Add( SecurityTokenKeyfileListCtrl, 1, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer141;
	bSizer141 = new wxBoxSizer( wxHORIZONTAL );

	ExportButton = new wxButton( this, wxID_ANY, _("IDC_EXPORT"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer141->Add( ExportButton, 0, wxALL, 5 );

	DeleteButton = new wxButton( this, wxID_ANY, _("VKEY_2E"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer141->Add( DeleteButton, 0, wxALL, 5 );


	bSizer141->Add( 0, 0, 1, wxEXPAND|wxLEFT, 5 );

	ImportButton = new wxButton( this, wxID_ANY, _("IDC_IMPORT_KEYFILE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer141->Add( ImportButton, 0, wxALL, 5 );


	bSizer142->Add( bSizer141, 0, wxEXPAND, 5 );


	bSizer138->Add( bSizer142, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer139;
	bSizer139 = new wxBoxSizer( wxVERTICAL );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer139->Add( OKButton, 0, wxALL, 5 );

	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer139->Add( CancelButton, 0, wxALL, 5 );


	bSizer138->Add( bSizer139, 0, wxEXPAND, 5 );


	bSizer3->Add( bSizer138, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer3 );
	this->Layout();
	bSizer3->Fit( this );

	// Connect Events
	SecurityTokenKeyfileListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemActivated ), NULL, this );
	SecurityTokenKeyfileListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemDeselected ), NULL, this );
	SecurityTokenKeyfileListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemSelected ), NULL, this );
	ExportButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnExportButtonClick ), NULL, this );
	DeleteButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnDeleteButtonClick ), NULL, this );
	ImportButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnImportButtonClick ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnOKButtonClick ), NULL, this );
}

SecurityTokenKeyfilesDialogBase::~SecurityTokenKeyfilesDialogBase()
{
	// Disconnect Events
	SecurityTokenKeyfileListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemActivated ), NULL, this );
	SecurityTokenKeyfileListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemDeselected ), NULL, this );
	SecurityTokenKeyfileListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( SecurityTokenKeyfilesDialogBase::OnListItemSelected ), NULL, this );
	ExportButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnExportButtonClick ), NULL, this );
	DeleteButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnDeleteButtonClick ), NULL, this );
	ImportButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnImportButtonClick ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenKeyfilesDialogBase::OnOKButtonClick ), NULL, this );

}

SecurityTokenSchemesDialogBase::SecurityTokenSchemesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style )  : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( -1,-1 ), wxDefaultSize );
	this->SetExtraStyle( GetExtraStyle() | wxWS_EX_VALIDATE_RECURSIVELY );
	
	// whole dialog sizer
	wxBoxSizer* bSizer3;
	bSizer3 = new wxBoxSizer( wxVERTICAL );
	
	// list control sizer for list control and buttons sizer (remove)
	wxBoxSizer* bSizer138;
	bSizer138 = new wxBoxSizer( wxHORIZONTAL );
	
	// sizer for list control only
	wxBoxSizer* bSizer142;
	bSizer142 = new wxBoxSizer( wxVERTICAL );
	
	SecurityTokenSchemeListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VRULES|wxSUNKEN_BORDER );
	bSizer142->Add( SecurityTokenSchemeListCtrl, 1, wxALL|wxEXPAND, 5 );


	bSizer138->Add( bSizer142, 1, wxEXPAND, 5 );

	// ok cancel buttons
	wxBoxSizer* bSizer139;
	bSizer139 = new wxBoxSizer( wxVERTICAL );
	
	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );
	OKButton->SetDefault(); 
	bSizer139->Add( OKButton, 0, wxALL, 5 );
	
	CancelButton = new wxButton( this, wxID_CANCEL, _("IDCANCEL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer139->Add( CancelButton, 0, wxALL, 5 );
	
	
	bSizer138->Add( bSizer139, 0, wxEXPAND, 5 );
	
	
	bSizer3->Add( bSizer138, 1, wxEXPAND|wxALL, 5 );

	this->SetSizer( bSizer3 );
	this->Layout();
	bSizer3->Fit( this );
	
	// Connect Events
	SecurityTokenSchemeListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemActivated ), NULL, this );
	SecurityTokenSchemeListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemDeselected ), NULL, this );
	SecurityTokenSchemeListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemSelected ), NULL, this );
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenSchemesDialogBase::OnOKButtonClick ), NULL, this );
}

SecurityTokenSchemesDialogBase::~SecurityTokenSchemesDialogBase()
{
	SecurityTokenSchemeListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemActivated ), NULL, this );
	SecurityTokenSchemeListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemDeselected ), NULL, this );
	SecurityTokenSchemeListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( SecurityTokenSchemesDialogBase::OnListItemSelected ), NULL, this );
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SecurityTokenSchemesDialogBase::OnOKButtonClick ), NULL, this );
}

VolumePropertiesDialogBase::VolumePropertiesDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer49;
	bSizer49 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer50;
	bSizer50 = new wxBoxSizer( wxVERTICAL );

	PropertiesListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxLC_VRULES|wxBORDER_SUNKEN );
	bSizer50->Add( PropertiesListCtrl, 1, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer169;
	bSizer169 = new wxBoxSizer( wxHORIZONTAL );


	bSizer169->Add( 0, 0, 1, wxEXPAND, 5 );

	OKButton = new wxButton( this, wxID_OK, _("IDOK"), wxDefaultPosition, wxDefaultSize, 0 );

	OKButton->SetDefault();
	bSizer169->Add( OKButton, 0, wxALL, 5 );


	bSizer169->Add( 0, 0, 1, wxEXPAND, 5 );


	bSizer50->Add( bSizer169, 0, wxALL|wxEXPAND, 5 );


	bSizer49->Add( bSizer50, 1, wxEXPAND|wxALL, 5 );


	this->SetSizer( bSizer49 );
	this->Layout();
	bSizer49->Fit( this );

	// Connect Events
	OKButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumePropertiesDialogBase::OnOKButtonClick ), NULL, this );
}

VolumePropertiesDialogBase::~VolumePropertiesDialogBase()
{
	// Disconnect Events
	OKButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumePropertiesDialogBase::OnOKButtonClick ), NULL, this );

}

EncryptionOptionsWizardPageBase::EncryptionOptionsWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer93;
	bSizer93 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer94;
	bSizer94 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer95;
	bSizer95 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer29;
	sbSizer29 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("ENCRYPTION_ALGORITHM_LV") ), wxVERTICAL );

	wxBoxSizer* bSizer96;
	bSizer96 = new wxBoxSizer( wxHORIZONTAL );

	wxArrayString EncryptionAlgorithmChoiceChoices;
	EncryptionAlgorithmChoice = new wxChoice( sbSizer29->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, EncryptionAlgorithmChoiceChoices, 0 );
	EncryptionAlgorithmChoice->SetSelection( 0 );
	bSizer96->Add( EncryptionAlgorithmChoice, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	TestButton = new wxButton( sbSizer29->GetStaticBox(), wxID_ANY, _("TEST"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer96->Add( TestButton, 0, wxALL|wxEXPAND, 5 );


	sbSizer29->Add( bSizer96, 0, wxEXPAND, 5 );

	EncryptionAlgorithmStaticText = new wxStaticText( sbSizer29->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	EncryptionAlgorithmStaticText->Wrap( -1 );
	sbSizer29->Add( EncryptionAlgorithmStaticText, 1, wxALL|wxEXPAND, 5 );

	wxBoxSizer* bSizer97;
	bSizer97 = new wxBoxSizer( wxHORIZONTAL );

	EncryptionAlgorithmHyperlink = new wxHyperlinkCtrl( sbSizer29->GetStaticBox(), wxID_ANY, _("IDC_LINK_MORE_INFO_ABOUT_CIPHER"), wxEmptyString, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );

	EncryptionAlgorithmHyperlink->SetHoverColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	EncryptionAlgorithmHyperlink->SetNormalColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	EncryptionAlgorithmHyperlink->SetVisitedColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	bSizer97->Add( EncryptionAlgorithmHyperlink, 0, wxALL, 5 );


	bSizer97->Add( 0, 0, 1, wxEXPAND, 5 );

	BenchmarkButton = new wxButton( sbSizer29->GetStaticBox(), wxID_ANY, _("IDC_BENCHMARK"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer97->Add( BenchmarkButton, 0, wxALL, 5 );


	sbSizer29->Add( bSizer97, 0, wxEXPAND, 5 );


	bSizer95->Add( sbSizer29, 1, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer30;
	sbSizer30 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_HASH_ALGO") ), wxHORIZONTAL );

	wxArrayString HashChoiceChoices;
	HashChoice = new wxChoice( sbSizer30->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, HashChoiceChoices, 0 );
	HashChoice->SetSelection( 0 );
	sbSizer30->Add( HashChoice, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	HashHyperlink = new wxHyperlinkCtrl( sbSizer30->GetStaticBox(), wxID_ANY, _("IDC_LINK_HASH_INFO"), wxEmptyString, wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );

	HashHyperlink->SetHoverColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	HashHyperlink->SetNormalColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	HashHyperlink->SetVisitedColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOWTEXT ) );
	sbSizer30->Add( HashHyperlink, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer95->Add( sbSizer30, 0, wxEXPAND|wxALL, 5 );


	bSizer94->Add( bSizer95, 1, wxEXPAND, 5 );


	bSizer93->Add( bSizer94, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer93 );
	this->Layout();
	bSizer93->Fit( this );

	// Connect Events
	EncryptionAlgorithmChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnEncryptionAlgorithmSelected ), NULL, this );
	TestButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnTestButtonClick ), NULL, this );
	EncryptionAlgorithmHyperlink->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( EncryptionOptionsWizardPageBase::OnEncryptionAlgorithmHyperlinkClick ), NULL, this );
	BenchmarkButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnBenchmarkButtonClick ), NULL, this );
	HashHyperlink->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( EncryptionOptionsWizardPageBase::OnHashHyperlinkClick ), NULL, this );
}

EncryptionOptionsWizardPageBase::~EncryptionOptionsWizardPageBase()
{
	// Disconnect Events
	EncryptionAlgorithmChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnEncryptionAlgorithmSelected ), NULL, this );
	TestButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnTestButtonClick ), NULL, this );
	EncryptionAlgorithmHyperlink->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( EncryptionOptionsWizardPageBase::OnEncryptionAlgorithmHyperlinkClick ), NULL, this );
	BenchmarkButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( EncryptionOptionsWizardPageBase::OnBenchmarkButtonClick ), NULL, this );
	HashHyperlink->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( EncryptionOptionsWizardPageBase::OnHashHyperlinkClick ), NULL, this );

}

InfoWizardPageBase::InfoWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer71;
	bSizer71 = new wxBoxSizer( wxVERTICAL );

	InfoPageSizer = new wxBoxSizer( wxVERTICAL );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	InfoPageSizer->Add( InfoStaticText, 1, wxALL|wxEXPAND, 5 );


	bSizer71->Add( InfoPageSizer, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer71 );
	this->Layout();
	bSizer71->Fit( this );
}

InfoWizardPageBase::~InfoWizardPageBase()
{
}

KeyfilesPanelBase::KeyfilesPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : wxPanel( parent, id, pos, size, style, name )
{
	this->SetMinSize( wxSize( 500,300 ) );

	wxBoxSizer* bSizer19;
	bSizer19 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer20;
	bSizer20 = new wxBoxSizer( wxHORIZONTAL );

	wxBoxSizer* bSizer21;
	bSizer21 = new wxBoxSizer( wxVERTICAL );

	KeyfilesListCtrl = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_NO_SORT_HEADER|wxLC_REPORT|wxBORDER_SUNKEN );
	bSizer21->Add( KeyfilesListCtrl, 1, wxEXPAND|wxALL, 5 );

	wxBoxSizer* bSizer137;
	bSizer137 = new wxBoxSizer( wxHORIZONTAL );

	AddFilesButton = new wxButton( this, wxID_ANY, _("IDC_KEYADD"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer137->Add( AddFilesButton, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxTOP, 5 );

	AddDirectoryButton = new wxButton( this, wxID_ANY, _("IDC_ADD_KEYFILE_PATH"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer137->Add( AddDirectoryButton, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxTOP, 5 );

	AddSecurityTokenSignatureButton = new wxButton( this, wxID_ANY, _("IDC_TOKEN_FILES_ADD"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer137->Add( AddSecurityTokenSignatureButton, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxTOP, 5 );

	RemoveButton = new wxButton( this, wxID_ANY, _("IDC_KEYREMOVE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer137->Add( RemoveButton, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxTOP, 5 );

	RemoveAllButton = new wxButton( this, wxID_ANY, _("IDC_KEYREMOVEALL"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer137->Add( RemoveAllButton, 0, wxALL|wxEXPAND, 5 );


	bSizer21->Add( bSizer137, 0, wxEXPAND, 5 );


	bSizer20->Add( bSizer21, 1, wxEXPAND, 5 );


	bSizer19->Add( bSizer20, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer19 );
	this->Layout();
	bSizer19->Fit( this );

	// Connect Events
	KeyfilesListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( KeyfilesPanelBase::OnListItemDeselected ), NULL, this );
	KeyfilesListCtrl->Connect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( KeyfilesPanelBase::OnListItemSelected ), NULL, this );
	KeyfilesListCtrl->Connect( wxEVT_SIZE, wxSizeEventHandler( KeyfilesPanelBase::OnListSizeChanged ), NULL, this );
	AddFilesButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddFilesButtonClick ), NULL, this );
	AddDirectoryButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddDirectoryButtonClick ), NULL, this );
	AddSecurityTokenSignatureButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddSecurityTokenSignatureButtonClick ), NULL, this );
	RemoveButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnRemoveButtonClick ), NULL, this );
	RemoveAllButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnRemoveAllButtonClick ), NULL, this );
}

KeyfilesPanelBase::~KeyfilesPanelBase()
{
	// Disconnect Events
	KeyfilesListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEventHandler( KeyfilesPanelBase::OnListItemDeselected ), NULL, this );
	KeyfilesListCtrl->Disconnect( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEventHandler( KeyfilesPanelBase::OnListItemSelected ), NULL, this );
	KeyfilesListCtrl->Disconnect( wxEVT_SIZE, wxSizeEventHandler( KeyfilesPanelBase::OnListSizeChanged ), NULL, this );
	AddFilesButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddFilesButtonClick ), NULL, this );
	AddDirectoryButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddDirectoryButtonClick ), NULL, this );
	AddSecurityTokenSignatureButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnAddSecurityTokenSignatureButtonClick ), NULL, this );
	RemoveButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnRemoveButtonClick ), NULL, this );
	RemoveAllButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( KeyfilesPanelBase::OnRemoveAllButtonClick ), NULL, this );

}

ProgressWizardPageBase::ProgressWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer81;
	bSizer81 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer82;
	bSizer82 = new wxBoxSizer( wxVERTICAL );

	ProgressSizer = new wxBoxSizer( wxHORIZONTAL );

	ProgressGauge = new wxGauge( this, wxID_ANY, 100, wxDefaultPosition, wxSize( -1,-1 ), wxGA_HORIZONTAL|wxGA_SMOOTH );
	ProgressGauge->SetValue( 0 );
	ProgressSizer->Add( ProgressGauge, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	AbortButton = new wxButton( this, wxID_ANY, _("IDC_ABORT_BUTTON"), wxDefaultPosition, wxDefaultSize, 0 );
	AbortButton->Enable( false );

	ProgressSizer->Add( AbortButton, 0, wxTOP|wxBOTTOM|wxRIGHT|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer82->Add( ProgressSizer, 0, wxEXPAND, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer82->Add( InfoStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer81->Add( bSizer82, 0, wxEXPAND, 5 );


	this->SetSizer( bSizer81 );
	this->Layout();
	bSizer81->Fit( this );

	// Connect Events
	AbortButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ProgressWizardPageBase::OnAbortButtonClick ), NULL, this );
}

ProgressWizardPageBase::~ProgressWizardPageBase()
{
	// Disconnect Events
	AbortButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ProgressWizardPageBase::OnAbortButtonClick ), NULL, this );

}

SelectDirectoryWizardPageBase::SelectDirectoryWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	this->SetMinSize( wxSize( 200,65 ) );

	wxBoxSizer* bSizer68;
	bSizer68 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer69;
	bSizer69 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer70;
	bSizer70 = new wxBoxSizer( wxHORIZONTAL );

	DirectoryTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	bSizer70->Add( DirectoryTextCtrl, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	BrowseButton = new wxButton( this, wxID_ANY, _("IDC_BROWSE_FILES"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer70->Add( BrowseButton, 0, wxALL|wxALIGN_CENTER_VERTICAL, 5 );


	bSizer69->Add( bSizer70, 0, wxEXPAND, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( 300 );
	bSizer69->Add( InfoStaticText, 1, wxALL|wxEXPAND, 5 );


	bSizer68->Add( bSizer69, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer68 );
	this->Layout();
	bSizer68->Fit( this );

	// Connect Events
	DirectoryTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( SelectDirectoryWizardPageBase::OnDirectoryTextChanged ), NULL, this );
	BrowseButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SelectDirectoryWizardPageBase::OnBrowseButtonClick ), NULL, this );
}

SelectDirectoryWizardPageBase::~SelectDirectoryWizardPageBase()
{
	// Disconnect Events
	DirectoryTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( SelectDirectoryWizardPageBase::OnDirectoryTextChanged ), NULL, this );
	BrowseButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( SelectDirectoryWizardPageBase::OnBrowseButtonClick ), NULL, this );

}

SingleChoiceWizardPageBase::SingleChoiceWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer71;
	bSizer71 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer77;
	bSizer77 = new wxBoxSizer( wxVERTICAL );


	bSizer77->Add( 0, 0, 0, wxEXPAND|wxTOP, 5 );

	OuterChoicesSizer = new wxBoxSizer( wxVERTICAL );

	ChoicesSizer = new wxBoxSizer( wxVERTICAL );


	OuterChoicesSizer->Add( ChoicesSizer, 0, wxEXPAND, 5 );


	bSizer77->Add( OuterChoicesSizer, 0, wxEXPAND, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer77->Add( InfoStaticText, 1, wxALL|wxEXPAND, 5 );


	bSizer71->Add( bSizer77, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer71 );
	this->Layout();
	bSizer71->Fit( this );
}

SingleChoiceWizardPageBase::~SingleChoiceWizardPageBase()
{
}

VolumeCreationProgressWizardPageBase::VolumeCreationProgressWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer104;
	bSizer104 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer105;
	bSizer105 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer31;
	sbSizer31 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, wxEmptyString ), wxVERTICAL );

	KeySamplesUpperSizer = new wxBoxSizer( wxVERTICAL );

	KeySamplesUpperInnerSizer = new wxBoxSizer( wxVERTICAL );


	KeySamplesUpperSizer->Add( KeySamplesUpperInnerSizer, 1, wxEXPAND|wxTOP, 3 );


	sbSizer31->Add( KeySamplesUpperSizer, 1, wxEXPAND, 30 );

	wxFlexGridSizer* fgSizer5;
	fgSizer5 = new wxFlexGridSizer( 3, 2, 0, 0 );
	fgSizer5->SetFlexibleDirection( wxBOTH );
	fgSizer5->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	wxStaticText* m_staticText25;
	m_staticText25 = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, _("IDT_RANDOM_POOL"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText25->Wrap( -1 );
	fgSizer5->Add( m_staticText25, 0, wxALL|wxALIGN_RIGHT|wxALIGN_BOTTOM, 5 );

	wxBoxSizer* bSizer126;
	bSizer126 = new wxBoxSizer( wxHORIZONTAL );

	RandomPoolSampleStaticText = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	RandomPoolSampleStaticText->Wrap( -1 );
	RandomPoolSampleStaticText->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier New") ) );

	bSizer126->Add( RandomPoolSampleStaticText, 0, wxEXPAND|wxTOP|wxRIGHT, 7 );

	DisplayKeysCheckBox = new wxCheckBox( sbSizer31->GetStaticBox(), wxID_ANY, _("IDC_DISPLAY_POOL_CONTENTS"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer126->Add( DisplayKeysCheckBox, 0, wxEXPAND|wxRIGHT, 5 );


	fgSizer5->Add( bSizer126, 1, wxEXPAND, 5 );

	wxStaticText* m_staticText28;
	m_staticText28 = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, _("IDT_HEADER_KEY"), wxDefaultPosition, wxSize( -1,-1 ), 0 );
	m_staticText28->Wrap( -1 );
	fgSizer5->Add( m_staticText28, 0, wxALIGN_RIGHT|wxBOTTOM|wxRIGHT|wxLEFT|wxALIGN_BOTTOM, 5 );

	HeaderKeySampleStaticText = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	HeaderKeySampleStaticText->Wrap( -1 );
	HeaderKeySampleStaticText->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier New") ) );

	fgSizer5->Add( HeaderKeySampleStaticText, 0, wxEXPAND|wxTOP|wxRIGHT, 2 );

	wxStaticText* m_staticText29;
	m_staticText29 = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, _("IDT_MASTER_KEY"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText29->Wrap( -1 );
	fgSizer5->Add( m_staticText29, 0, wxALIGN_RIGHT|wxBOTTOM|wxRIGHT|wxLEFT|wxALIGN_BOTTOM, 5 );

	MasterKeySampleStaticText = new wxStaticText( sbSizer31->GetStaticBox(), wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	MasterKeySampleStaticText->Wrap( -1 );
	MasterKeySampleStaticText->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, wxT("Courier New") ) );

	fgSizer5->Add( MasterKeySampleStaticText, 0, wxEXPAND|wxTOP|wxRIGHT, 2 );


	sbSizer31->Add( fgSizer5, 0, wxEXPAND, 5 );


	bSizer105->Add( sbSizer31, 0, wxALL|wxEXPAND, 5 );

	wxStaticBoxSizer* sbSizer45;
	sbSizer45 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_ENTROPY_BAR") ), wxVERTICAL );

	CollectedEntropy = new wxGauge( sbSizer45->GetStaticBox(), wxID_ANY, 2560, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL|wxGA_SMOOTH );
	CollectedEntropy->SetValue( 0 );
	sbSizer45->Add( CollectedEntropy, 0, wxALL|wxEXPAND, 5 );


	bSizer105->Add( sbSizer45, 0, wxEXPAND|wxLEFT|wxRIGHT, 5 );

	wxStaticBoxSizer* sbSizer32;
	sbSizer32 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, wxEmptyString ), wxVERTICAL );

	wxBoxSizer* bSizer106;
	bSizer106 = new wxBoxSizer( wxHORIZONTAL );

	ProgressGauge = new wxGauge( sbSizer32->GetStaticBox(), wxID_ANY, 100, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL|wxGA_SMOOTH );
	bSizer106->Add( ProgressGauge, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	AbortButton = new wxButton( sbSizer32->GetStaticBox(), wxID_ANY, _("IDC_ABORT_BUTTON"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer106->Add( AbortButton, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );


	sbSizer32->Add( bSizer106, 0, wxEXPAND, 5 );

	wxGridSizer* gSizer6;
	gSizer6 = new wxGridSizer( 1, 3, 0, 0 );

	wxBoxSizer* bSizer108;
	bSizer108 = new wxBoxSizer( wxHORIZONTAL );

	m_staticText31 = new wxStaticText( sbSizer32->GetStaticBox(), wxID_ANY, _("IDT_DONE"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText31->Wrap( -1 );
	bSizer108->Add( m_staticText31, 0, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxLEFT, 5 );

	m_panel12 = new wxPanel( sbSizer32->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxSize( -1,-1 ), wxBORDER_SUNKEN );
	wxBoxSizer* bSizer115;
	bSizer115 = new wxBoxSizer( wxHORIZONTAL );

	SizeDoneStaticText = new wxStaticText( m_panel12, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT|wxST_NO_AUTORESIZE );
	SizeDoneStaticText->Wrap( -1 );
	bSizer115->Add( SizeDoneStaticText, 1, wxEXPAND|wxALL, 3 );


	m_panel12->SetSizer( bSizer115 );
	m_panel12->Layout();
	bSizer115->Fit( m_panel12 );
	bSizer108->Add( m_panel12, 1, wxEXPAND|wxALL, 5 );


	gSizer6->Add( bSizer108, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer1081;
	bSizer1081 = new wxBoxSizer( wxHORIZONTAL );

	m_staticText311 = new wxStaticText( sbSizer32->GetStaticBox(), wxID_ANY, _("IDT_SPEED"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText311->Wrap( -1 );
	bSizer1081->Add( m_staticText311, 0, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxLEFT, 5 );

	m_panel121 = new wxPanel( sbSizer32->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxBORDER_SUNKEN );
	wxBoxSizer* bSizer1151;
	bSizer1151 = new wxBoxSizer( wxHORIZONTAL );

	SpeedStaticText = new wxStaticText( m_panel121, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT|wxST_NO_AUTORESIZE );
	SpeedStaticText->Wrap( -1 );
	bSizer1151->Add( SpeedStaticText, 1, wxALL|wxEXPAND, 3 );


	m_panel121->SetSizer( bSizer1151 );
	m_panel121->Layout();
	bSizer1151->Fit( m_panel121 );
	bSizer1081->Add( m_panel121, 1, wxALL|wxEXPAND, 5 );


	gSizer6->Add( bSizer1081, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer1082;
	bSizer1082 = new wxBoxSizer( wxHORIZONTAL );

	m_staticText312 = new wxStaticText( sbSizer32->GetStaticBox(), wxID_ANY, _("IDT_LEFT"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText312->Wrap( -1 );
	bSizer1082->Add( m_staticText312, 0, wxALIGN_CENTER_VERTICAL|wxTOP|wxBOTTOM|wxLEFT, 5 );

	m_panel122 = new wxPanel( sbSizer32->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL|wxBORDER_SUNKEN );
	wxBoxSizer* bSizer1152;
	bSizer1152 = new wxBoxSizer( wxHORIZONTAL );

	TimeLeftStaticText = new wxStaticText( m_panel122, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxALIGN_RIGHT|wxST_NO_AUTORESIZE );
	TimeLeftStaticText->Wrap( -1 );
	bSizer1152->Add( TimeLeftStaticText, 1, wxALL|wxEXPAND, 3 );


	m_panel122->SetSizer( bSizer1152 );
	m_panel122->Layout();
	bSizer1152->Fit( m_panel122 );
	bSizer1082->Add( m_panel122, 1, wxALL|wxEXPAND, 5 );


	gSizer6->Add( bSizer1082, 1, wxEXPAND, 5 );


	sbSizer32->Add( gSizer6, 0, wxEXPAND|wxTOP, 2 );


	bSizer105->Add( sbSizer32, 0, wxEXPAND|wxBOTTOM|wxRIGHT|wxLEFT, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer105->Add( InfoStaticText, 0, wxBOTTOM|wxLEFT|wxRIGHT, 5 );


	bSizer104->Add( bSizer105, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer104 );
	this->Layout();
	bSizer104->Fit( this );

	// Connect Events
	DisplayKeysCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeCreationProgressWizardPageBase::OnDisplayKeysCheckBoxClick ), NULL, this );
	AbortButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeCreationProgressWizardPageBase::OnAbortButtonClick ), NULL, this );
}

VolumeCreationProgressWizardPageBase::~VolumeCreationProgressWizardPageBase()
{
	// Disconnect Events
	DisplayKeysCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeCreationProgressWizardPageBase::OnDisplayKeysCheckBoxClick ), NULL, this );
	AbortButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeCreationProgressWizardPageBase::OnAbortButtonClick ), NULL, this );

}

VolumeLocationWizardPageBase::VolumeLocationWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer86;
	bSizer86 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer87;
	bSizer87 = new wxBoxSizer( wxVERTICAL );


	bSizer87->Add( 0, 0, 0, wxEXPAND|wxTOP, 5 );

	wxBoxSizer* bSizer88;
	bSizer88 = new wxBoxSizer( wxHORIZONTAL );

	wxBoxSizer* bSizer89;
	bSizer89 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer126;
	bSizer126 = new wxBoxSizer( wxHORIZONTAL );

	VolumePathComboBox = new wxComboBox( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, NULL, wxCB_DROPDOWN );
	bSizer126->Add( VolumePathComboBox, 1, wxALL|wxALIGN_CENTER_VERTICAL, 5 );

	wxBoxSizer* bSizer90;
	bSizer90 = new wxBoxSizer( wxVERTICAL );

	SelectFileButton = new wxButton( this, wxID_ANY, _("IDC_SELECT_FILE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer90->Add( SelectFileButton, 0, wxALL|wxEXPAND, 5 );

	SelectDeviceButton = new wxButton( this, wxID_ANY, _("IDC_SELECT_DEVICE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer90->Add( SelectDeviceButton, 0, wxALL|wxEXPAND, 5 );


	bSizer126->Add( bSizer90, 0, wxALIGN_CENTER_VERTICAL, 5 );


	bSizer89->Add( bSizer126, 0, wxEXPAND, 5 );

	wxBoxSizer* bSizer91;
	bSizer91 = new wxBoxSizer( wxHORIZONTAL );


	bSizer91->Add( 0, 0, 0, wxLEFT, 5 );

	NoHistoryCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_NO_HISTORY"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer91->Add( NoHistoryCheckBox, 0, wxALL|wxEXPAND, 5 );


	bSizer89->Add( bSizer91, 0, wxEXPAND, 5 );


	bSizer88->Add( bSizer89, 1, wxEXPAND, 5 );


	bSizer87->Add( bSizer88, 0, wxEXPAND, 5 );


	bSizer87->Add( 0, 0, 0, wxEXPAND|wxBOTTOM, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer87->Add( InfoStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer86->Add( bSizer87, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer86 );
	this->Layout();
	bSizer86->Fit( this );

	// Connect Events
	VolumePathComboBox->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnVolumePathTextChanged ), NULL, this );
	SelectFileButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnSelectFileButtonClick ), NULL, this );
	SelectDeviceButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnSelectDeviceButtonClick ), NULL, this );
	NoHistoryCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnNoHistoryCheckBoxClick ), NULL, this );
}

VolumeLocationWizardPageBase::~VolumeLocationWizardPageBase()
{
	// Disconnect Events
	VolumePathComboBox->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnVolumePathTextChanged ), NULL, this );
	SelectFileButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnSelectFileButtonClick ), NULL, this );
	SelectDeviceButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnSelectDeviceButtonClick ), NULL, this );
	NoHistoryCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeLocationWizardPageBase::OnNoHistoryCheckBoxClick ), NULL, this );

}

VolumeFormatOptionsWizardPageBase::VolumeFormatOptionsWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer124;
	bSizer124 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer125;
	bSizer125 = new wxBoxSizer( wxVERTICAL );

	wxStaticBoxSizer* sbSizer33;
	sbSizer33 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_FORMAT_OPTIONS") ), wxVERTICAL );

	wxFlexGridSizer* fgSizer6;
	fgSizer6 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer6->SetFlexibleDirection( wxBOTH );
	fgSizer6->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );

	m_staticText43 = new wxStaticText( sbSizer33->GetStaticBox(), wxID_ANY, _("IDT_FILESYSTEM"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText43->Wrap( -1 );
	fgSizer6->Add( m_staticText43, 0, wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxTOP|wxBOTTOM|wxLEFT, 5 );

	wxArrayString FilesystemTypeChoiceChoices;
	FilesystemTypeChoice = new wxChoice( sbSizer33->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, FilesystemTypeChoiceChoices, 0 );
	FilesystemTypeChoice->SetSelection( 0 );
	fgSizer6->Add( FilesystemTypeChoice, 0, wxALL, 5 );


	sbSizer33->Add( fgSizer6, 1, wxEXPAND, 5 );


	bSizer125->Add( sbSizer33, 0, wxEXPAND|wxALL, 5 );

	wxStaticBoxSizer* sbSizer34;
	sbSizer34 = new wxStaticBoxSizer( new wxStaticBox( this, wxID_ANY, _("IDT_FORMAT_OPTIONS") ), wxVERTICAL );

	QuickFormatCheckBox = new wxCheckBox( sbSizer34->GetStaticBox(), wxID_ANY, _("IDC_QUICKFORMAT"), wxDefaultPosition, wxDefaultSize, 0 );
	sbSizer34->Add( QuickFormatCheckBox, 0, wxALL, 5 );


	bSizer125->Add( sbSizer34, 0, wxEXPAND|wxALL, 5 );


	bSizer125->Add( 0, 0, 1, wxEXPAND|wxTOP|wxBOTTOM, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer125->Add( InfoStaticText, 0, wxALL, 5 );


	bSizer124->Add( bSizer125, 0, wxEXPAND, 5 );


	this->SetSizer( bSizer124 );
	this->Layout();
	bSizer124->Fit( this );

	// Connect Events
	FilesystemTypeChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( VolumeFormatOptionsWizardPageBase::OnFilesystemTypeSelected ), NULL, this );
	QuickFormatCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeFormatOptionsWizardPageBase::OnQuickFormatCheckBoxClick ), NULL, this );
}

VolumeFormatOptionsWizardPageBase::~VolumeFormatOptionsWizardPageBase()
{
	// Disconnect Events
	FilesystemTypeChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( VolumeFormatOptionsWizardPageBase::OnFilesystemTypeSelected ), NULL, this );
	QuickFormatCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeFormatOptionsWizardPageBase::OnQuickFormatCheckBoxClick ), NULL, this );

}

VolumePasswordPanelBase::VolumePasswordPanelBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : wxPanel( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer7;
	bSizer7 = new wxBoxSizer( wxVERTICAL );

	GridBagSizer = new wxGridBagSizer( 0, 0 );
	GridBagSizer->SetFlexibleDirection( wxBOTH );
	GridBagSizer->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	GridBagSizer->SetEmptyCellSize( wxSize( 0,0 ) );

	PasswordStaticText = new wxStaticText( this, wxID_ANY, _("IDT_NEW_PASSWORD"), wxDefaultPosition, wxDefaultSize, 0 );
	PasswordStaticText->Wrap( -1 );
	GridBagSizer->Add( PasswordStaticText, wxGBPosition( 1, 0 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxBOTTOM|wxRIGHT, 5 );

	PasswordTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	#ifdef __WXGTK__
	if ( !PasswordTextCtrl->HasFlag( wxTE_MULTILINE ) )
	{
	PasswordTextCtrl->SetMaxLength( 1 );
	}
	#else
	PasswordTextCtrl->SetMaxLength( 1 );
	#endif
	PasswordTextCtrl->SetMinSize( wxSize( 232,-1 ) );

	GridBagSizer->Add( PasswordTextCtrl, wxGBPosition( 1, 1 ), wxGBSpan( 1, 2 ), wxBOTTOM|wxEXPAND, 5 );

	ConfirmPasswordStaticText = new wxStaticText( this, wxID_ANY, _("IDT_CONFIRM_PASSWORD"), wxDefaultPosition, wxDefaultSize, 0 );
	ConfirmPasswordStaticText->Wrap( -1 );
	GridBagSizer->Add( ConfirmPasswordStaticText, wxGBPosition( 2, 0 ), wxGBSpan( 1, 1 ), wxBOTTOM|wxRIGHT|wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT, 5 );

	ConfirmPasswordTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	#ifdef __WXGTK__
	if ( !ConfirmPasswordTextCtrl->HasFlag( wxTE_MULTILINE ) )
	{
	ConfirmPasswordTextCtrl->SetMaxLength( 1 );
	}
	#else
	ConfirmPasswordTextCtrl->SetMaxLength( 1 );
	#endif
	ConfirmPasswordTextCtrl->SetMinSize( wxSize( 232,-1 ) );

	GridBagSizer->Add( ConfirmPasswordTextCtrl, wxGBPosition( 2, 1 ), wxGBSpan( 1, 2 ), wxBOTTOM|wxEXPAND, 5 );

	VolumePimStaticText = new wxStaticText( this, wxID_ANY, _("IDT_PIM"), wxDefaultPosition, wxDefaultSize, 0 );
	VolumePimStaticText->Wrap( -1 );
	GridBagSizer->Add( VolumePimStaticText, wxGBPosition( 3, 0 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxBOTTOM|wxRIGHT, 5 );

	VolumePimTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	#ifdef __WXGTK__
	if ( !VolumePimTextCtrl->HasFlag( wxTE_MULTILINE ) )
	{
	VolumePimTextCtrl->SetMaxLength( 7 );
	}
	#else
	VolumePimTextCtrl->SetMaxLength( 7 );
	#endif
	GridBagSizer->Add( VolumePimTextCtrl, wxGBPosition( 3, 1 ), wxGBSpan( 1, 1 ), wxBOTTOM|wxEXPAND, 5 );

	VolumePimHelpStaticText = new wxStaticText( this, wxID_ANY, _("IDC_PIM_HELP"), wxDefaultPosition, wxDefaultSize, 0 );
	VolumePimHelpStaticText->Wrap( -1 );
	GridBagSizer->Add( VolumePimHelpStaticText, wxGBPosition( 3, 2 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxBOTTOM|wxLEFT|wxRIGHT, 5 );

	PimCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_NEW_PIM_ENABLE"), wxDefaultPosition, wxDefaultSize, 0 );
	GridBagSizer->Add( PimCheckBox, wxGBPosition( 4, 1 ), wxGBSpan( 1, 2 ), wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	CacheCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_CACHE"), wxDefaultPosition, wxDefaultSize, 0 );
	GridBagSizer->Add( CacheCheckBox, wxGBPosition( 5, 1 ), wxGBSpan( 1, 2 ), wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	DisplayPasswordCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_SHOW_PASSWORD_MO"), wxDefaultPosition, wxDefaultSize, 0 );
	GridBagSizer->Add( DisplayPasswordCheckBox, wxGBPosition( 6, 1 ), wxGBSpan( 1, 2 ), wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5 );

	UseKeyfilesCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_KEYFILES_ENABLE_HIDVOL_PROT"), wxDefaultPosition, wxDefaultSize, 0 );
	GridBagSizer->Add( UseKeyfilesCheckBox, wxGBPosition( 7, 1 ), wxGBSpan( 1, 1 ), wxTOP|wxRIGHT|wxLEFT, 5 );

	KeyfilesButton = new wxButton( this, wxID_ANY, _("IDC_KEYFILES_HIDVOL_PROT"), wxDefaultPosition, wxDefaultSize, 0 );
	GridBagSizer->Add( KeyfilesButton, wxGBPosition( 7, 2 ), wxGBSpan( 1, 1 ), wxALIGN_RIGHT|wxALIGN_BOTTOM|wxLEFT, 5 );

	SecurityTokenSchemeSpecText = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
	SecurityTokenSchemeSpecButton = new wxButton(this, wxID_ANY, _("IDC_SECURITY_TOKEN_KEY"), wxDefaultPosition, wxDefaultSize, 0);
	GridBagSizer->Add (SecurityTokenSchemeSpecText, wxGBPosition(8, 1), wxGBSpan( 1, 1), wxTOP | wxRIGHT | wxLEFT, 5);
	GridBagSizer->Add (SecurityTokenSchemeSpecButton, wxGBPosition (8, 2), wxGBSpan( 1, 1), wxALIGN_RIGHT|wxALIGN_BOTTOM|wxLEFT, 5);

	Pkcs5PrfSizer = new wxBoxSizer( wxVERTICAL );


	GridBagSizer->Add( Pkcs5PrfSizer, wxGBPosition( 8, 1 ), wxGBSpan( 1, 1 ), wxEXPAND|wxTOP|wxBOTTOM, 5 );

	Pkcs5PrfStaticText = new wxStaticText( this, wxID_ANY, _("IDT_NEW_PKCS5_PRF"), wxDefaultPosition, wxDefaultSize, 0 );
	Pkcs5PrfStaticText->Wrap( -1 );
	GridBagSizer->Add( Pkcs5PrfStaticText, wxGBPosition( 9, 0 ), wxGBSpan( 1, 1 ), wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxRIGHT, 5 );

	wxString Pkcs5PrfChoiceChoices[] = { _("UNCHANGED") };
	int Pkcs5PrfChoiceNChoices = sizeof( Pkcs5PrfChoiceChoices ) / sizeof( wxString );
	Pkcs5PrfChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, Pkcs5PrfChoiceNChoices, Pkcs5PrfChoiceChoices, 0 );
	Pkcs5PrfChoice->SetSelection( 0 );
	GridBagSizer->Add( Pkcs5PrfChoice, wxGBPosition( 9, 1 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxLEFT, 5 );

	HeaderWipeCountText = new wxStaticText( this, wxID_ANY, _("IDT_WIPE_MODE"), wxDefaultPosition, wxDefaultSize, 0 );
	HeaderWipeCountText->Wrap( -1 );
	GridBagSizer->Add( HeaderWipeCountText, wxGBPosition( 10, 0 ), wxGBSpan( 1, 1 ), wxALIGN_CENTER_VERTICAL|wxALIGN_RIGHT|wxRIGHT, 5 );

	wxString HeaderWipeCountChoices[] = { _("WIPE_MODE_1_RAND"), _("WIPE_MODE_3_DOD_5220"), _("WIPE_MODE_7_DOD_5220"), _("WIPE_MODE_35_GUTMANN"), _("WIPE_MODE_256") };
	int HeaderWipeCountNChoices = sizeof( HeaderWipeCountChoices ) / sizeof( wxString );
	HeaderWipeCount = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, HeaderWipeCountNChoices, HeaderWipeCountChoices, 0 );
	HeaderWipeCount->SetSelection( 1 );
	GridBagSizer->Add( HeaderWipeCount, wxGBPosition( 10, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );

	PasswordPlaceholderSizer = new wxBoxSizer( wxVERTICAL );


	GridBagSizer->Add( PasswordPlaceholderSizer, wxGBPosition( 11, 1 ), wxGBSpan( 1, 2 ), wxTOP|wxEXPAND, 5 );


	GridBagSizer->AddGrowableCol( 1 );

	bSizer7->Add( GridBagSizer, 1, wxALL|wxEXPAND, 5 );


	this->SetSizer( bSizer7 );
	this->Layout();
	bSizer7->Fit( this );

	// Connect Events
	PasswordTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnTextChanged ), NULL, this );
	ConfirmPasswordTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnTextChanged ), NULL, this );
	VolumePimTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnPimChanged ), NULL, this );
	PimCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnUsePimCheckBoxClick ), NULL, this );
	DisplayPasswordCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnDisplayPasswordCheckBoxClick ), NULL, this );
	UseKeyfilesCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnUseKeyfilesCheckBoxClick ), NULL, this );
	KeyfilesButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonClick ), NULL, this );
	KeyfilesButton->Connect( wxEVT_RIGHT_DOWN, wxMouseEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonRightDown ), NULL, this );
	KeyfilesButton->Connect( wxEVT_RIGHT_UP, wxMouseEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonRightClick ), NULL, this );
	SecurityTokenSchemeSpecButton->Connect(wxEVT_COMMAND_BUTTON_CLICKED,  wxMouseEventHandler( VolumePasswordPanelBase::OnSecurityTokenSchemeSpecButtonClick ), NULL, this );
}

VolumePasswordPanelBase::~VolumePasswordPanelBase()
{
	// Disconnect Events
	PasswordTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnTextChanged ), NULL, this );
	ConfirmPasswordTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnTextChanged ), NULL, this );
	VolumePimTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePasswordPanelBase::OnPimChanged ), NULL, this );
	PimCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnUsePimCheckBoxClick ), NULL, this );
	DisplayPasswordCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnDisplayPasswordCheckBoxClick ), NULL, this );
	UseKeyfilesCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnUseKeyfilesCheckBoxClick ), NULL, this );
	KeyfilesButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonClick ), NULL, this );
	KeyfilesButton->Disconnect( wxEVT_RIGHT_DOWN, wxMouseEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonRightDown ), NULL, this );
	KeyfilesButton->Disconnect( wxEVT_RIGHT_UP, wxMouseEventHandler( VolumePasswordPanelBase::OnKeyfilesButtonRightClick ), NULL, this );
	SecurityTokenSchemeSpecButton->Disconnect(wxEVT_COMMAND_BUTTON_CLICKED,  wxMouseEventHandler( VolumePasswordPanelBase::OnSecurityTokenSchemeSpecButtonClick ), NULL, this );
}

VolumePasswordWizardPageBase::VolumePasswordWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer101;
	bSizer101 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer102;
	bSizer102 = new wxBoxSizer( wxVERTICAL );

	PasswordPanelSizer = new wxBoxSizer( wxVERTICAL );


	bSizer102->Add( PasswordPanelSizer, 0, wxEXPAND, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer102->Add( InfoStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer101->Add( bSizer102, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer101 );
	this->Layout();
	bSizer101->Fit( this );
}

VolumePasswordWizardPageBase::~VolumePasswordWizardPageBase()
{
}

VolumePimWizardPageBase::VolumePimWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer101;
	bSizer101 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer102;
	bSizer102 = new wxBoxSizer( wxVERTICAL );

	PimPanelSizer = new wxBoxSizer( wxVERTICAL );

	PimSizer = new wxBoxSizer( wxHORIZONTAL );

	VolumePimStaticText = new wxStaticText( this, wxID_ANY, _("IDT_PIM"), wxDefaultPosition, wxDefaultSize, 0 );
	VolumePimStaticText->Wrap( -1 );
	PimSizer->Add( VolumePimStaticText, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );

	VolumePimTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	#ifdef __WXGTK__
	if ( !VolumePimTextCtrl->HasFlag( wxTE_MULTILINE ) )
	{
	VolumePimTextCtrl->SetMaxLength( 7 );
	}
	#else
	VolumePimTextCtrl->SetMaxLength( 7 );
	#endif
	PimSizer->Add( VolumePimTextCtrl, 0, wxALL, 5 );

	VolumePimHelpStaticText = new wxStaticText( this, wxID_ANY, _("IDC_PIM_HELP"), wxDefaultPosition, wxDefaultSize, 0 );
	VolumePimHelpStaticText->Wrap( -1 );
	PimSizer->Add( VolumePimHelpStaticText, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );


	PimPanelSizer->Add( PimSizer, 1, wxEXPAND, 5 );

	wxBoxSizer* bSizer166;
	bSizer166 = new wxBoxSizer( wxHORIZONTAL );

	DisplayPimCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_SHOW_PIM"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer166->Add( DisplayPimCheckBox, 1, wxALL|wxEXPAND, 5 );


	PimPanelSizer->Add( bSizer166, 1, wxEXPAND, 5 );


	bSizer102->Add( PimPanelSizer, 0, wxEXPAND, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer102->Add( InfoStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer101->Add( bSizer102, 1, wxEXPAND, 5 );


	this->SetSizer( bSizer101 );
	this->Layout();
	bSizer101->Fit( this );

	// Connect Events
	VolumePimTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePimWizardPageBase::OnPimChanged ), NULL, this );
	DisplayPimCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePimWizardPageBase::OnDisplayPimCheckBoxClick ), NULL, this );
}

VolumePimWizardPageBase::~VolumePimWizardPageBase()
{
	// Disconnect Events
	VolumePimTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumePimWizardPageBase::OnPimChanged ), NULL, this );
	DisplayPimCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumePimWizardPageBase::OnDisplayPimCheckBoxClick ), NULL, this );

}

VolumeSizeWizardPageBase::VolumeSizeWizardPageBase( wxWindow* parent, wxWindowID id, const wxPoint& pos, const wxSize& size, long style, const wxString& name ) : WizardPage( parent, id, pos, size, style, name )
{
	wxBoxSizer* bSizer98;
	bSizer98 = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* bSizer99;
	bSizer99 = new wxBoxSizer( wxVERTICAL );


	bSizer99->Add( 0, 0, 0, wxEXPAND|wxTOP|wxBOTTOM, 5 );

	wxBoxSizer* bSizer100;
	bSizer100 = new wxBoxSizer( wxHORIZONTAL );

	VolumeSizeTextCtrl = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	bSizer100->Add( VolumeSizeTextCtrl, 0, wxALL, 5 );

	wxArrayString VolumeSizePrefixChoiceChoices;
	VolumeSizePrefixChoice = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, VolumeSizePrefixChoiceChoices, 0 );
	VolumeSizePrefixChoice->SetSelection( 0 );
	bSizer100->Add( VolumeSizePrefixChoice, 0, wxALL, 5 );


	bSizer99->Add( bSizer100, 0, wxEXPAND, 5 );


	bSizer99->Add( 0, 0, 0, wxEXPAND|wxTOP|wxBOTTOM, 5 );

	UseAllFreeSpaceCheckBox = new wxCheckBox( this, wxID_ANY, _("IDC_USE_ALL_FREE_SPACE"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer99->Add( UseAllFreeSpaceCheckBox, 0, wxALL|wxEXPAND, 5 );


	bSizer99->Add( 0, 0, 0, wxBOTTOM|wxEXPAND|wxTOP, 5 );

	FreeSpaceStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	FreeSpaceStaticText->Wrap( -1 );
	bSizer99->Add( FreeSpaceStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer99->Add( 0, 0, 0, wxEXPAND|wxTOP|wxBOTTOM, 5 );

	InfoStaticText = new wxStaticText( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	InfoStaticText->Wrap( -1 );
	bSizer99->Add( InfoStaticText, 0, wxALL|wxEXPAND, 5 );


	bSizer98->Add( bSizer99, 0, wxEXPAND, 5 );


	this->SetSizer( bSizer98 );
	this->Layout();
	bSizer98->Fit( this );

	// Connect Events
	VolumeSizeTextCtrl->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnVolumeSizeTextChanged ), NULL, this );
	VolumeSizePrefixChoice->Connect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnVolumeSizePrefixSelected ), NULL, this );
	UseAllFreeSpaceCheckBox->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnUseAllFreeSpaceCheckBoxClick ), NULL, this );
}

VolumeSizeWizardPageBase::~VolumeSizeWizardPageBase()
{
	// Disconnect Events
	VolumeSizeTextCtrl->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnVolumeSizeTextChanged ), NULL, this );
	VolumeSizePrefixChoice->Disconnect( wxEVT_COMMAND_CHOICE_SELECTED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnVolumeSizePrefixSelected ), NULL, this );
	UseAllFreeSpaceCheckBox->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( VolumeSizeWizardPageBase::OnUseAllFreeSpaceCheckBoxClick ), NULL, this );

}

WaitDialogBase::WaitDialogBase( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* bSizer160;
	bSizer160 = new wxBoxSizer( wxVERTICAL );

	WaitStaticText = new wxStaticText( this, wxID_ANY, _("MyLabel"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL );
	WaitStaticText->Wrap( -1 );
	bSizer160->Add( WaitStaticText, 0, wxALL|wxEXPAND, 5 );

	WaitProgessBar = new wxGauge( this, wxID_ANY, 100, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL|wxGA_SMOOTH );
	WaitProgessBar->SetValue( 0 );
	bSizer160->Add( WaitProgessBar, 0, wxALL|wxEXPAND, 5 );


	this->SetSizer( bSizer160 );
	this->Layout();
	bSizer160->Fit( this );

	this->Centre( wxBOTH );

	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( WaitDialogBase::OnWaitDialogClose ) );
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( WaitDialogBase::OnWaitDialogInit ) );
}

WaitDialogBase::~WaitDialogBase()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( WaitDialogBase::OnWaitDialogClose ) );
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( WaitDialogBase::OnWaitDialogInit ) );

}
