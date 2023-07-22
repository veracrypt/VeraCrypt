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

#include "Tcdefs.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include "BootEncryption.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Mount.h"
#include "Common/Resource.h"
#include "Resource.h"
#include "Xml.h"
#include "Favorites.h"
#include "Pkcs5.h"

using namespace std;

namespace VeraCrypt
{
	vector <FavoriteVolume> FavoriteVolumes;
	vector <FavoriteVolume> SystemFavoriteVolumes;
	list <FavoriteVolume> FavoritesOnArrivalMountRequired;
	list <FavoriteVolume> FavoritesMountedOnArrivalStillConnected;
	HMENU FavoriteVolumesMenu;


	BOOL AddMountedVolumeToFavorites (HWND hwndDlg, int driveNo, bool systemFavorites)
	{
		VOLUME_PROPERTIES_STRUCT prop;
		DWORD bytesReturned;

		memset (&prop, 0, sizeof (prop));
		prop.driveNo = driveNo;

		if (!DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &bytesReturned, NULL))
		{
			handleWin32Error (hwndDlg, SRC_POS);
			return FALSE;
		}

		FavoriteVolume favorite;
		favorite.MountPoint = L"X:\\";
		favorite.MountPoint[0] = (wchar_t) (prop.driveNo + L'A');

		favorite.Path = prop.wszVolume;
		if (favorite.Path.find (L"\\??\\") == 0)
			favorite.Path = favorite.Path.substr (4);

		if (wcslen (prop.wszLabel))
		{
			favorite.Label = prop.wszLabel;
			favorite.UseLabelInExplorer = true;
		}

		if (IsVolumeDeviceHosted (favorite.Path.c_str()))
		{
			// Get GUID path
			wstring volumeDevPath = favorite.Path;

			wchar_t resolvedVolumeDevPath[TC_MAX_PATH];
			if (ResolveSymbolicLink (volumeDevPath.c_str(), resolvedVolumeDevPath, sizeof(resolvedVolumeDevPath)))
				volumeDevPath = resolvedVolumeDevPath;

			wchar_t volumeName[TC_MAX_PATH];
			HANDLE find = FindFirstVolume (volumeName, ARRAYSIZE (volumeName));

			if (find != INVALID_HANDLE_VALUE)
			{
				do
				{
					wchar_t findVolumeDevPath[TC_MAX_PATH];
					wstring vn = volumeName;

					if (QueryDosDevice (vn.substr (4, vn.size() - 5).c_str(), findVolumeDevPath, ARRAYSIZE (findVolumeDevPath)) != 0
						&& volumeDevPath == findVolumeDevPath)
					{
						favorite.VolumePathId = volumeName;
						break;
					}

				} while (FindNextVolume (find, volumeName, ARRAYSIZE (volumeName)));

				FindVolumeClose (find);
			}
		}

		favorite.ReadOnly = prop.readOnly ? true : false;
		favorite.Removable = prop.removable ? true : false;
		favorite.SystemEncryption = prop.partitionInInactiveSysEncScope ? true : false;
		favorite.OpenExplorerWindow = (bExplore == TRUE);
		favorite.Pim = prop.volumePim;
		favorite.Pkcs5 = prop.pkcs5;
		memcpy (favorite.VolumeID, prop.volumeID, VOLUME_ID_SIZE);

		if (favorite.VolumePathId.empty()
			&& IsVolumeDeviceHosted (favorite.Path.c_str())
			&& favorite.Path.find (L"\\\\?\\Volume{") != 0)
		{
			Warning (favorite.Path.find (L"\\Partition0") == wstring::npos ? "FAVORITE_ADD_PARTITION_TYPE_WARNING" : "FAVORITE_ADD_DRIVE_DEV_WARNING", hwndDlg);
		}

		return OrganizeFavoriteVolumes (hwndDlg, systemFavorites, favorite);
	}


	static BOOL CALLBACK FavoriteVolumesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		/* This dialog is used both for System Favorites and non-system Favorites.

		The following options have different meaning in System Favorites mode:

		IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT	=> MOUNT_SYSTEM_FAVORITES_ON_BOOT
		IDC_FAVORITE_DISABLE_HOTKEY		=> DISABLE_NONADMIN_SYS_FAVORITES_ACCESS

		*/

		WORD lw = LOWORD (wParam);
		WORD hw = HIWORD (wParam);
		static bool SystemFavoritesMode;
		static vector <FavoriteVolume> Favorites;
		static int SelectedItem;
		static HWND FavoriteListControl;

		switch (msg)
		{
		case WM_INITDIALOG:
			{
				try
				{
					FavoriteListControl = GetDlgItem (hwndDlg, IDC_FAVORITE_VOLUMES_LIST);

					FavoriteVolumesDlgProcArguments *args = (FavoriteVolumesDlgProcArguments *) lParam;
					SystemFavoritesMode = args->SystemFavorites;

					LocalizeDialog (hwndDlg, SystemFavoritesMode ? "SYSTEM_FAVORITES_DLG_TITLE" : "IDD_FAVORITE_VOLUMES");

					if (SystemFavoritesMode)
					{
						RECT rec;

						BootEncryptionStatus bootEncStatus = BootEncryption (hwndDlg).GetStatus();

						if (!bootEncStatus.DriveMounted)
							throw ErrorException ("SYS_FAVORITES_REQUIRE_PBA", SRC_POS);

						ShowWindow (GetDlgItem(hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON), SW_HIDE);
						ShowWindow (GetDlgItem(hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL), SW_HIDE);

						// MOUNT_SYSTEM_FAVORITES_ON_BOOT

						SetWindowTextW (GetDlgItem (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT), GetString ("MOUNT_SYSTEM_FAVORITES_ON_BOOT"));

						// DISABLE_NONADMIN_SYS_FAVORITES_ACCESS

						SetWindowTextW (GetDlgItem (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY), GetString ("DISABLE_NONADMIN_SYS_FAVORITES_ACCESS"));

						// Group box

						GetClientRect (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), &rec);

						SetWindowPos (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), 0, 0, 0,
							rec.right,
							rec.bottom - CompensateYDPI (95),
							SWP_NOMOVE | SWP_NOZORDER);

						InvalidateRect (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), NULL, TRUE);
					}
					else
					{
						ShowWindow (GetDlgItem(hwndDlg, IDC_FAV_VOL_OPTIONS_GLOBAL_SETTINGS_BOX), SW_HIDE);
					}

					Favorites.clear();

					LVCOLUMNW column;
					SendMessageW (FavoriteListControl, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);

					memset (&column, 0, sizeof (column));
					column.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;
					column.pszText = GetString ("DRIVE");
					column.cx = CompensateXDPI (38);
					column.fmt = LVCFMT_CENTER;
					SendMessageW (FavoriteListControl, LVM_INSERTCOLUMNW, 1, (LPARAM) &column);

					++column.iSubItem;
					column.fmt = LVCFMT_LEFT;
					column.pszText = GetString ("LABEL");
					column.cx = CompensateXDPI (160);
					SendMessageW (FavoriteListControl, LVM_INSERTCOLUMNW, 2, (LPARAM) &column);

					++column.iSubItem;
					column.fmt = LVCFMT_LEFT;
					column.pszText = GetString ("VOLUME");
					column.cx = CompensateXDPI (330);
					SendMessageW (FavoriteListControl, LVM_INSERTCOLUMNW, 3, (LPARAM) &column);

					SetControls (hwndDlg, FavoriteVolume(), SystemFavoritesMode, false);

					if (SystemFavoritesMode)
						LoadFavoriteVolumes (Favorites, true);
					else
						Favorites = FavoriteVolumes;

					if (args->AddFavoriteVolume)
						Favorites.push_back (args->NewFavoriteVolume);

					FillListControl (FavoriteListControl, Favorites);

					SelectedItem = -1;

					if (args->AddFavoriteVolume)
					{
						ListView_SetItemState (FavoriteListControl, Favorites.size() - 1, LVIS_SELECTED, LVIS_SELECTED);
						ListView_EnsureVisible (FavoriteListControl, Favorites.size() - 1, FALSE);
					}

					if (SystemFavoritesMode)
						SetDlgItemTextW (hwndDlg, IDC_FAVORITES_HELP_LINK, GetString ("SYS_FAVORITES_HELP_LINK"));

					ToHyperlink (hwndDlg, IDC_FAVORITES_HELP_LINK);
				}
				catch (Exception &e)
				{
					e.Show (hwndDlg);
					EndDialog (hwndDlg, IDCLOSE);
				}
			}
			return 1;

		case WM_COMMAND:

			switch (lw)
			{
			case IDOK:
				{
					BOOL bInitialOptionValue = NeedPeriodicDeviceListUpdate;

					/* Global System Favorites settings */

					if (SystemFavoritesMode)
					{
						BootEncryption BootEncObj (NULL);

						if (BootEncObj.GetStatus().DriveMounted)
						{
							try
							{
								uint32 reqConfig = IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT) ? TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES : 0;
								if (reqConfig != (ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES))
									BootEncObj.SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES, reqConfig ? true : false);

								if (!BootEncObj.IsSystemFavoritesServiceRunning())
								{
									// The system favorites service should be always running
									// If it is stopped for some reason, we reconfigure it
									BootEncObj.RegisterSystemFavoritesService (TRUE);
								}

								SetDriverConfigurationFlag (TC_DRIVER_CONFIG_DISABLE_NONADMIN_SYS_FAVORITES_ACCESS, IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY));
							}
							catch (Exception &e)
							{
								e.Show (hwndDlg);
							}
						}
					}

					/* (System) Favorites list */

					if (SelectedItem != -1 && !Favorites.empty())
						SetFavoriteVolume (hwndDlg, Favorites[SelectedItem], SystemFavoritesMode);

					if (SaveFavoriteVolumes (hwndDlg, Favorites, SystemFavoritesMode))
					{
						if (!SystemFavoritesMode)
						{
							bMountFavoritesOnLogon = FALSE;

							foreach (const FavoriteVolume &favorite, Favorites)
							{
								if (favorite.MountOnLogOn)
								{
									bMountFavoritesOnLogon = TRUE;
									break;
								}
							}

							if (!bEnableBkgTask || bCloseBkgTaskWhenNoVolumes || IsNonInstallMode())
							{
								foreach (const FavoriteVolume favorite, Favorites)
								{
									if (favorite.MountOnArrival)
									{
										Warning ("FAVORITE_ARRIVAL_MOUNT_BACKGROUND_TASK_ERR", hwndDlg);
										break;
									}
								}
							}

							if (!bInitialOptionValue && NeedPeriodicDeviceListUpdate)
							{
								// a favorite was set to use VolumeID. We update the list of devices available for mounting as early as possible
								UpdateMountableHostDeviceList ();
							}

							FavoriteVolumes = Favorites;

							ManageStartupSeq();
							SaveSettings (hwndDlg);
						}
						else
							SystemFavoriteVolumes = Favorites;

						OnFavoriteVolumesUpdated();
						LoadDriveLetters (hwndDlg, GetDlgItem (MainDlg, IDC_DRIVELIST), 0);

						EndDialog (hwndDlg, IDOK);
					}
				}
				return 1;

			case IDCANCEL:
				EndDialog (hwndDlg, IDCLOSE);
				return 1;

			case IDC_FAVORITE_MOVE_DOWN:
				if (SelectedItem != -1 && Favorites.size() > (size_t) SelectedItem + 1)
				{
					swap (Favorites[SelectedItem], Favorites[SelectedItem + 1]);

					FillListControl (FavoriteListControl, Favorites);
					++SelectedItem;
					ListView_SetItemState (FavoriteListControl, SelectedItem, LVIS_SELECTED, LVIS_SELECTED);
					ListView_EnsureVisible (FavoriteListControl, SelectedItem, FALSE);
				}
				return 1;

			case IDC_FAVORITE_MOVE_UP:
				if (SelectedItem > 0)
				{
					swap (Favorites[SelectedItem], Favorites[SelectedItem - 1]);

					FillListControl (FavoriteListControl, Favorites);
					--SelectedItem;
					ListView_SetItemState (FavoriteListControl, SelectedItem, LVIS_SELECTED, LVIS_SELECTED);
					ListView_EnsureVisible (FavoriteListControl, SelectedItem, FALSE);
				}
				return 1;

			case IDC_FAVORITE_REMOVE:
				if (SelectedItem != -1)
				{
					Favorites.erase (Favorites.begin() + SelectedItem);
					FillListControl (GetDlgItem (hwndDlg, IDC_FAVORITE_VOLUMES_LIST), Favorites);
					SetControls (hwndDlg, FavoriteVolume(), SystemFavoritesMode, false);
					SelectedItem = -1;
				}
				return 1;


			case IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT:	// Note that this option means "MOUNT_SYSTEM_FAVORITES_ON_BOOT" when SystemFavoritesMode is true
				if (SystemFavoritesMode)
				{
					// MOUNT_SYSTEM_FAVORITES_ON_BOOT

					if (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT))
					{
						WarningDirect ((wstring (GetString ("SYS_FAVORITES_KEYBOARD_WARNING")) + L"\n\n" + GetString ("BOOT_PASSWORD_CACHE_KEYBOARD_WARNING")).c_str(), hwndDlg);

						if (!IsServerOS() && !IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY))
							Info ("SYS_FAVORITES_ADMIN_ONLY_INFO", hwndDlg);
					}
				}
				return 1;

			case IDC_FAVORITE_DISABLE_HOTKEY: // Note that this option means "DISABLE_NONADMIN_SYS_FAVORITES_ACCESS" when SystemFavoritesMode is true
				if (SystemFavoritesMode)
				{
					// DISABLE_NONADMIN_SYS_FAVORITES_ACCESS

					if (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY))
						WarningDirect ((wstring (GetString ("SYS_FAVORITES_ADMIN_ONLY_WARNING")) + L"\n\n" + GetString ("SETTING_REQUIRES_REBOOT")).c_str(), hwndDlg);
					else
						Warning ("SETTING_REQUIRES_REBOOT", hwndDlg);
				}
				return 1;

			case IDC_FAVORITES_HELP_LINK:
				Applink (SystemFavoritesMode ? "sysfavorites" : "favorites");
				return 1;
			case IDC_SHOW_PIM:
				HandleShowPasswordFieldAction (hwndDlg, IDC_SHOW_PIM, IDC_PIM, 0);
				return 1;

			case IDC_PIM:
				if (hw == EN_CHANGE)
				{
					int pim = GetPim (hwndDlg, IDC_PIM, -1);
					if (pim > (SystemFavoritesMode? MAX_BOOT_PIM_VALUE: MAX_PIM_VALUE))
					{
						SetDlgItemText (hwndDlg, IDC_PIM, L"");
						SetFocus (GetDlgItem(hwndDlg, IDC_PIM));
						Warning (SystemFavoritesMode? "PIM_SYSENC_TOO_BIG": "PIM_TOO_BIG", hwndDlg);
						return 1;
					}
				}
				break;
			}

			return 0;

		case WM_NOTIFY:
			if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED)
			{
				static bool reentry = false;
				if (reentry)
					break;

				reentry = true;

				if (SelectedItem != -1)
				{
					SetFavoriteVolume (hwndDlg, Favorites[SelectedItem], SystemFavoritesMode);
					FillListControlSubItems (FavoriteListControl, SelectedItem, Favorites[SelectedItem]);
				}

				SelectedItem = ListView_GetNextItem (GetDlgItem (hwndDlg, IDC_FAVORITE_VOLUMES_LIST), -1, LVIS_SELECTED);

				if (SelectedItem != -1)
					SetControls (hwndDlg, Favorites[SelectedItem], SystemFavoritesMode);
				else
					SetControls (hwndDlg, FavoriteVolume(), SystemFavoritesMode, false);

				reentry = false;
				return 1;
			}
			break;

		case WM_CLOSE:
			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		case WM_CTLCOLORSTATIC:
			{
				HDC hdc = (HDC)	wParam;
				HWND hw = (HWND) lParam;
				if (hw == GetDlgItem(hwndDlg, IDC_FAVORITE_VOLUME_ID))
				{
					// This the favorite ID field. Make its background like normal edit
					HBRUSH hbr = GetSysColorBrush (COLOR_WINDOW);
					::SelectObject(hdc, hbr);
					return (BOOL) hbr;
				}
			}
			break;
		}

		return 0;
	}


	static void FillFavoriteVolumesMenu ()
	{
		while (DeleteMenu (FavoriteVolumesMenu, 7, MF_BYPOSITION)) { }

		if (FavoriteVolumes.empty())
			return;

		AppendMenu (FavoriteVolumesMenu, MF_SEPARATOR, 0, L"");

		int i = 0;
		foreach (const FavoriteVolume &favorite, FavoriteVolumes)
		{
			UINT flags = MF_STRING;

			if (favorite.DisconnectedDevice)
				flags |= MF_GRAYED;

			wstring menuText = favorite.Path;
			if (favorite.DisconnectedDevice)
				menuText = favorite.Label.empty() ? wstring (L"(") + GetString ("FAVORITE_DISCONNECTED_DEV") + L")" : L"";

			if (!favorite.Label.empty())
			{
				if (favorite.DisconnectedDevice)
					menuText = favorite.Label + L" " + menuText;
				else
					menuText = favorite.Label;
			}

			AppendMenuW (FavoriteVolumesMenu, flags, TC_FAVORITE_MENU_CMD_ID_OFFSET + i++,
				(menuText + L"\t" + favorite.MountPoint.substr (0, 2)).c_str());
		}
	}


	static void FillListControl (HWND favoriteListControl, vector <FavoriteVolume> &favorites)
	{
		SendMessage (favoriteListControl, LVM_DELETEALLITEMS, 0, 0);

		int line = 0;
		foreach (const FavoriteVolume favorite, favorites)
		{
			ListItemAdd (favoriteListControl, line, (wchar_t *) favorite.MountPoint.substr (0, 2).c_str());
			FillListControlSubItems (favoriteListControl, line++, favorite);
		}
	}


	static void FillListControlSubItems (HWND FavoriteListControl, int line, const FavoriteVolume &favorite)
	{
		ListSubItemSet (FavoriteListControl, line, 1, (wchar_t *) favorite.Label.c_str());

		if (favorite.DisconnectedDevice)
			ListSubItemSet (FavoriteListControl, line, 2, (wchar_t *) (wstring (L"(") + GetString ("FAVORITE_DISCONNECTED_DEV") + L")").c_str());
		else
			ListSubItemSet (FavoriteListControl, line, 2, (wchar_t *) favorite.Path.c_str());
	}


	wstring GetFavoriteVolumeLabel (const wstring &volumePath, bool& useInExplorer)
	{
		foreach (const FavoriteVolume &favorite, FavoriteVolumes)
		{
			if (favorite.Path == volumePath)
			{
				useInExplorer = favorite.UseLabelInExplorer;
				return favorite.Label;
			}
		}

		foreach (const FavoriteVolume &favorite, SystemFavoriteVolumes)
		{
			if (favorite.Path == volumePath)
			{
				useInExplorer = favorite.UseLabelInExplorer;
				return favorite.Label;
			}
		}

		useInExplorer = false;
		return wstring();
	}


	void LoadFavoriteVolumes ()
	{
		LoadFavoriteVolumes (FavoriteVolumes, false);

		try
		{
			LoadFavoriteVolumes (SystemFavoriteVolumes, true, true);
		}
		catch (...) { }	// Ignore errors as SystemFavoriteVolumes list is used only for resolving volume paths to labels

		OnFavoriteVolumesUpdated();
	}


	void LoadFavoriteVolumes (vector <FavoriteVolume> &favorites, bool systemFavorites, bool noUacElevation)
	{
		bool bVolumeIdInUse = false;
		favorites.clear();
		wstring favoritesFilePath = systemFavorites ? GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false) : GetConfigPath (TC_APPD_FILENAME_FAVORITE_VOLUMES);

		if (systemFavorites && !IsAdmin() && !noUacElevation)
		{
			favoritesFilePath = GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES);

			try
			{
				BootEncryption bootEnc (MainDlg);
				bootEnc.CopyFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false).c_str(), favoritesFilePath.c_str());
			}
			catch (SystemException &e)
			{
				if (e.ErrorCode == ERROR_FILE_NOT_FOUND)
					return;

				throw;
			}
		}

		DWORD size;
		char *favoritesXml = LoadFile (favoritesFilePath.c_str(), &size);

		if (systemFavorites && !IsAdmin() && !noUacElevation)
			DeleteFile (GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES));

		char *xml = favoritesXml;
		char mountPoint[MAX_PATH], volume[MAX_PATH];

		if (xml == NULL)
			return;

		while (xml = XmlFindElement (xml, "volume"))
		{
			FavoriteVolume favorite;

			XmlGetAttributeText (xml, "mountpoint", mountPoint, sizeof (mountPoint));
			favorite.MountPoint = Utf8StringToWide (mountPoint);

			XmlGetNodeText (xml, volume, sizeof (volume));
			favorite.Path = Utf8StringToWide (volume);

			char label[1024];

			XmlGetAttributeText (xml, "ID", label, sizeof (label));
			if (strlen (label) == (2*VOLUME_ID_SIZE))
			{
				std::vector<byte> arr;
				if (HexWideStringToArray (Utf8StringToWide (label).c_str(), arr) && arr.size() == VOLUME_ID_SIZE)
				{
					memcpy (favorite.VolumeID, &arr[0], VOLUME_ID_SIZE);
				}
			}

			XmlGetAttributeText (xml, "label", label, sizeof (label));
			favorite.Label = Utf8StringToWide (label);

			XmlGetAttributeText (xml, "pim", label, sizeof (label));
			if (strlen(label) == 0)
			{
				/* support old attribute name before it was changed to PIM*/
				XmlGetAttributeText (xml, "pin", label, sizeof (label));
			}
			if (label[0])
			{
				favorite.Pim = strtol (label, NULL, 10);
				if (favorite.Pim < 0 || favorite.Pim > (systemFavorites? MAX_BOOT_PIM_VALUE : MAX_PIM_VALUE))
					favorite.Pim = -1;
			}
			else
				favorite.Pim = -1;

			char boolVal[2];
			XmlGetAttributeText (xml, "readonly", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.ReadOnly = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "removable", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.Removable = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "system", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.SystemEncryption = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "noHotKeyMount", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.DisableHotkeyMount = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "openExplorerWindow", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.OpenExplorerWindow = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "mountOnArrival", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.MountOnArrival = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "mountOnLogOn", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.MountOnLogOn = (boolVal[0] == '1');

			XmlGetAttributeText (xml, "useLabelInExplorer", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.UseLabelInExplorer = (boolVal[0] == '1') && !favorite.ReadOnly;

			XmlGetAttributeText (xml, "useVolumeID", boolVal, sizeof (boolVal));
			if (boolVal[0])
				favorite.UseVolumeID = (boolVal[0] == '1') && !IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID));

			if (favorite.Path.find (L"\\\\?\\Volume{") == 0 && favorite.Path.rfind (L"}\\") == favorite.Path.size() - 2)
			{
				wstring resolvedPath = VolumeGuidPathToDevicePath (favorite.Path);
				if (!resolvedPath.empty())
				{
					favorite.DisconnectedDevice = false;
					favorite.VolumePathId = favorite.Path;
					favorite.Path = resolvedPath;
				}
				else
					favorite.DisconnectedDevice = true;
			}

			XmlGetAttributeText (xml, "pkcs5", label, sizeof (label));
			if (label[0])
				favorite.Pkcs5 = strtol (label, NULL, 10);
			else
				favorite.Pkcs5 = -1;
			if 	(	(favorite.Pkcs5 != -1) 
				&&	(  (favorite.Pkcs5 < FIRST_PRF_ID)
						|| (favorite.Pkcs5 > LAST_PRF_ID)
					)
				)
			{
				favorite.Pkcs5 = -1;
			}

			if (!systemFavorites && favorite.UseVolumeID)
				bVolumeIdInUse = true;

			favorites.push_back (favorite);
			xml++;
		}

		if (!systemFavorites)
		{
			if (bVolumeIdInUse && !DisablePeriodicDeviceListUpdate)
				NeedPeriodicDeviceListUpdate = TRUE;
			else
				NeedPeriodicDeviceListUpdate = FALSE;
		}

		free (favoritesXml);
	}


	static void OnFavoriteVolumesUpdated ()
	{
		FillFavoriteVolumesMenu();

		FavoritesOnArrivalMountRequired.clear();

		foreach (const FavoriteVolume favorite, FavoriteVolumes)
		{
			if (favorite.MountOnArrival)
			{
				FavoritesOnArrivalMountRequired.push_back (favorite);

				if (IsMountedVolume (favorite.Path.c_str()))
				{
					bool present = false;

					foreach (const FavoriteVolume favoriteConnected, FavoritesMountedOnArrivalStillConnected)
					{
						if (favorite.Path == favoriteConnected.Path)
						{
							present = true;
							break;
						}
					}

					if (!present)
						FavoritesMountedOnArrivalStillConnected.push_back (favorite);
				}
			}
		}
	}


	BOOL OrganizeFavoriteVolumes (HWND hwndDlg, bool systemFavorites, const FavoriteVolume &newFavorite)
	{
		FavoriteVolumesDlgProcArguments args;
		args.SystemFavorites = systemFavorites;

		if (!newFavorite.Path.empty())
		{
			args.AddFavoriteVolume = true;
			args.NewFavoriteVolume = newFavorite;
		}
		else
			args.AddFavoriteVolume = false;

		return DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_FAVORITE_VOLUMES), hwndDlg, (DLGPROC) FavoriteVolumesDlgProc, (LPARAM) &args) == IDOK;
	}


	bool SaveFavoriteVolumes (HWND hwndDlg, const vector <FavoriteVolume> &favorites, bool systemFavorites)
	{
		FILE *f;
		int cnt = 0;
		bool bVolumeIdInUse = false;

		f = _wfopen (GetConfigPath (systemFavorites ? TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES : TC_APPD_FILENAME_FAVORITE_VOLUMES), L"w,ccs=UTF-8");
		if (f == NULL)
		{
			handleWin32Error (MainDlg, SRC_POS);
			return false;
		}

		XmlWriteHeader (f);
		fputws (L"\n\t<favorites>", f);

		foreach (const FavoriteVolume &favorite, favorites)
		{
			wchar_t tq[2048];

			if (systemFavorites && favorite.Path.find (L"\\\\") == 0 && favorite.Path.find (L"Volume{") == wstring::npos)
				Warning ("SYSTEM_FAVORITE_NETWORK_PATH_ERR", hwndDlg);

			XmlQuoteTextW (!favorite.VolumePathId.empty() ? favorite.VolumePathId.c_str() : favorite.Path.c_str(), tq, ARRAYSIZE (tq));

			wstring s = L"\n\t\t<volume mountpoint=\"" + favorite.MountPoint + L"\"";

			if (!IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID)))
				s += L" ID=\"" + ArrayToHexWideString (favorite.VolumeID, sizeof (favorite.VolumeID)) + L"\"";

			if (!favorite.Label.empty())
				s += L" label=\"" + favorite.Label + L"\"";

			if (favorite.Pim >= 0)
				s += L" pim=\"" + IntToWideString(favorite.Pim) + L"\"";

			if (favorite.Pkcs5 > 0)
				s += L" pkcs5=\"" + IntToWideString(favorite.Pkcs5) + L"\"";

			if (favorite.ReadOnly)
				s += L" readonly=\"1\"";

			if (favorite.Removable)
				s += L" removable=\"1\"";

			if (favorite.SystemEncryption)
				s += L" system=\"1\"";

			if (favorite.MountOnArrival)
				s += L" mountOnArrival=\"1\"";

			if (favorite.MountOnLogOn)
				s += L" mountOnLogOn=\"1\"";

			if (favorite.DisableHotkeyMount)
				s += L" noHotKeyMount=\"1\"";

			if (favorite.OpenExplorerWindow)
				s += L" openExplorerWindow=\"1\"";

			if (favorite.UseLabelInExplorer && !favorite.ReadOnly)
				s += L" useLabelInExplorer=\"1\"";

			if (favorite.UseVolumeID && !IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID)))
			{
				s += L" useVolumeID=\"1\"";
				if (!systemFavorites)
					bVolumeIdInUse = true;
			}

			s += L">" + wstring (tq) + L"</volume>";

			fwprintf (f, L"%ws", s.c_str());
			cnt++;
		}

		fputws (L"\n\t</favorites>", f);
		XmlWriteFooter (f);

		if (!systemFavorites)
		{
			if (bVolumeIdInUse && !DisablePeriodicDeviceListUpdate)
				NeedPeriodicDeviceListUpdate = TRUE;
			else
				NeedPeriodicDeviceListUpdate = FALSE;
		}

		if (!CheckFileStreamWriteErrors (hwndDlg, f, systemFavorites ? TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES : TC_APPD_FILENAME_FAVORITE_VOLUMES))
		{
			fclose (f);
			return false;
		}

		fclose (f);

		BootEncryption bootEnc (MainDlg);

		if (systemFavorites)
		{
			finally_do ({ _wremove (GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES)); });

			try
			{
				bootEnc.DeleteFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false).c_str());
			}
			catch (UserAbort&) { return false; }
			catch (...) { }

			try
			{
				if (cnt != 0)
				{
					bootEnc.CopyFileAdmin (GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES), GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false).c_str());

					if (!(ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES))
						Info ("SYS_FAVORITE_VOLUMES_SAVED", hwndDlg);
				}
			}
			catch (Exception &e)
			{
				e.Show (NULL);
			}
		}

		if (cnt == 0)
		{
			if (systemFavorites)
			{
				try
				{
					bootEnc.DeleteFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES, false).c_str());
				}
				catch (...) { }
			}
			else
				_wremove (GetConfigPath (TC_APPD_FILENAME_FAVORITE_VOLUMES));
		}

		return true;
	}


	static void SetControls (HWND hwndDlg, const FavoriteVolume &favorite, bool systemFavoritesMode, bool enable)
	{
		BOOL bIsDevice = favorite.DisconnectedDevice || IsVolumeDeviceHosted (favorite.Path.c_str()) || !enable;
		if (favorite.Pim > 0)
		{
			wchar_t szTmp[MAX_PIM + 1];
			StringCbPrintfW (szTmp, sizeof(szTmp), L"%d", favorite.Pim);
			SetDlgItemText (hwndDlg, IDC_PIM, szTmp);
		}
		else
			SetDlgItemText (hwndDlg, IDC_PIM, L"");
		SetDlgItemTextW (hwndDlg, IDC_FAVORITE_LABEL, favorite.Label.c_str());
		SetCheckBox (hwndDlg, IDC_FAVORITE_USE_LABEL_IN_EXPLORER, favorite.UseLabelInExplorer);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON, favorite.MountOnLogOn);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL, favorite.MountOnArrival);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_READONLY, favorite.ReadOnly);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_REMOVABLE, favorite.Removable);
		SetCheckBox (hwndDlg, IDC_FAVORITE_USE_VOLUME_ID, favorite.UseVolumeID && bIsDevice);

		/* Populate the PRF algorithms list */
		int nIndex, i, nSelected = 0;
		HWND hComboBox = GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID);
		SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);

		nIndex = (int) SendMessageW (hComboBox, CB_ADDSTRING, 0, (LPARAM) GetString ("AUTODETECTION"));
		SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) 0);

		for (i = FIRST_PRF_ID; i <= LAST_PRF_ID; i++)
		{
			nIndex = (int) SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) get_pkcs5_prf_name(i));
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) i);
			if (favorite.Pkcs5 == i)
				nSelected = nIndex;
		}

		if (favorite.Pkcs5 >= 0)
			SendMessage (hComboBox, CB_SETCURSEL, nSelected, 0);

		if (IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID)) || !bIsDevice)
		{
			SetDlgItemText (hwndDlg, IDC_FAVORITE_VOLUME_ID, L"");
		}
		else
			SetDlgItemText (hwndDlg, IDC_FAVORITE_VOLUME_ID, ArrayToHexWideString (favorite.VolumeID, sizeof (favorite.VolumeID)).c_str());

		if (systemFavoritesMode)
		{
			uint32 driverConfig = ReadDriverConfigurationFlags();

			// MOUNT_SYSTEM_FAVORITES_ON_BOOT
			CheckDlgButton (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT, (driverConfig & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES) ? BST_CHECKED : BST_UNCHECKED);

			// DISABLE_NONADMIN_SYS_FAVORITES_ACCESS
			CheckDlgButton (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY, (driverConfig & TC_DRIVER_CONFIG_DISABLE_NONADMIN_SYS_FAVORITES_ACCESS) ? BST_CHECKED : BST_UNCHECKED);
		}
		else
		{
			SetCheckBox (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT, favorite.OpenExplorerWindow);
			SetCheckBox (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY, favorite.DisableHotkeyMount);
		}

		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOVE_UP), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOVE_DOWN), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_REMOVE), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDT_PKCS5_PRF), enable && !favorite.SystemEncryption);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), enable && !favorite.SystemEncryption);
		EnableWindow (GetDlgItem (hwndDlg, IDT_PIM), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PIM), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_SHOW_PIM), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PIM_HELP), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDT_FAVORITE_LABEL), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_LABEL), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_USE_LABEL_IN_EXPLORER), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON), enable && !systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL), enable && !systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_READONLY), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_REMOVABLE), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT), enable || systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY), enable || systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDT_VOLUME_ID), enable && bIsDevice);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_VOLUME_ID), enable && bIsDevice);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_USE_VOLUME_ID), enable && bIsDevice && !IsRepeatedByteArray (0, favorite.VolumeID, sizeof (favorite.VolumeID)));

		ShowWindow (GetDlgItem (hwndDlg, IDT_VOLUME_ID), bIsDevice? SW_SHOW : SW_HIDE);
		ShowWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_VOLUME_ID), bIsDevice? SW_SHOW : SW_HIDE);
		ShowWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_USE_VOLUME_ID), bIsDevice? SW_SHOW : SW_HIDE);

		// Group box
		RECT boxRect, checkRect, labelRect;

		GetWindowRect (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), &boxRect);
		GetWindowRect (GetDlgItem (hwndDlg, IDC_FAVORITE_USE_VOLUME_ID), &checkRect);
		GetWindowRect (GetDlgItem (hwndDlg, IDT_VOLUME_ID), &labelRect);

		if (!bIsDevice && (boxRect.top < checkRect.top))
		{
			POINT pt = {boxRect.left, checkRect.bottom};
			ScreenToClient (hwndDlg, &pt);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), 0, pt.x, pt.y,
				boxRect.right - boxRect.left,
				boxRect.bottom - checkRect.bottom,
				SWP_NOZORDER);

			InvalidateRect (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), NULL, TRUE);
		}

		if (bIsDevice && (boxRect.top >= checkRect.top))
		{
			POINT pt = {boxRect.left, labelRect.top - CompensateYDPI (10)};
			ScreenToClient (hwndDlg, &pt);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), 0, pt.x, pt.y,
				boxRect.right - boxRect.left,
				boxRect.bottom - labelRect.top + CompensateYDPI (10),
				SWP_NOZORDER);

			InvalidateRect (GetDlgItem (hwndDlg, IDC_FAV_VOL_OPTIONS_GROUP_BOX), NULL, TRUE);
		}
	}


	static void SetFavoriteVolume (HWND hwndDlg, FavoriteVolume &favorite, bool systemFavoritesMode)
	{
		wchar_t label[1024];
		if (GetDlgItemTextW (hwndDlg, IDC_FAVORITE_LABEL, label, ARRAYSIZE (label)) != 0)
		{
			favorite.Label = label;

			for (size_t i = 0; i < favorite.Label.size(); ++i)
			{
				if (favorite.Label[i] == L'"')
					favorite.Label.at (i) = L'\'';
			}
		}
		else
			favorite.Label.clear();

		favorite.Pim = GetPim (hwndDlg, IDC_PIM, -1);
		favorite.UseLabelInExplorer = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_USE_LABEL_IN_EXPLORER) != 0);
		favorite.UseVolumeID = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_USE_VOLUME_ID) != 0);
		int nSelected = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETCURSEL, 0, 0);
		if (nSelected != CB_ERR)
			favorite.Pkcs5 = (int) SendMessage (GetDlgItem (hwndDlg, IDC_PKCS5_PRF_ID), CB_GETITEMDATA, nSelected, 0);
		else
			favorite.Pkcs5 = -1;

		favorite.ReadOnly = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_MOUNT_READONLY) != 0);
		favorite.Removable = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_MOUNT_REMOVABLE) != 0);

		if (!systemFavoritesMode)
		{
			favorite.MountOnLogOn = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON) != 0);
			favorite.MountOnArrival = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL) != 0);
			favorite.DisableHotkeyMount = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY) != 0);
			favorite.OpenExplorerWindow = (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT) != 0);
		}

		if (favorite.VolumePathId.empty()
			&& IsVolumeDeviceHosted (favorite.Path.c_str())
			&& favorite.Path.find (L"\\\\?\\Volume{") != 0)
		{
			bool partition = (favorite.Path.find (L"\\Partition0") == wstring::npos);

			if (!favorite.Label.empty())
			{
				ErrorDirect ((GetString (partition ? "FAVORITE_LABEL_PARTITION_TYPE_ERR" : "FAVORITE_LABEL_DEVICE_PATH_ERR") + wstring (L"\n\n") + favorite.Path).c_str(), hwndDlg);
				favorite.Label.clear();
			}

			if (favorite.MountOnArrival)
			{
				ErrorDirect ((GetString (partition ? "FAVORITE_ARRIVAL_MOUNT_PARTITION_TYPE_ERR" : "FAVORITE_ARRIVAL_MOUNT_DEVICE_PATH_ERR") + wstring (L"\n\n") + favorite.Path).c_str(), hwndDlg);
				favorite.MountOnArrival = false;
			}
		}

		if (favorite.MountOnArrival && favorite.Path.find (L"\\\\") == 0 && favorite.Path.find (L"Volume{") == wstring::npos)
		{
			Error ("FAVORITE_ARRIVAL_MOUNT_NETWORK_PATH_ERR", hwndDlg);
			favorite.MountOnArrival = false;
		}
	}


	void UpdateDeviceHostedFavoriteVolumes ()
	{
		try
		{
			LoadFavoriteVolumes();
		}
		catch (Exception &e)
		{
			e.Show (MainDlg);
		}
	}
}
