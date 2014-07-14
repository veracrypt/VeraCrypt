/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Tcdefs.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include "BootEncryption.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Mount.h"
#include "Resource.h"
#include "Xml.h"
#include "Favorites.h"

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
			handleWin32Error (hwndDlg);
			return FALSE;
		}

		FavoriteVolume favorite;
		favorite.MountPoint = "X:\\";
		favorite.MountPoint[0] = (char) (prop.driveNo + 'A');

		favorite.Path = WideToSingleString ((wchar_t *) prop.wszVolume);
		if (favorite.Path.find ("\\??\\") == 0)
			favorite.Path = favorite.Path.substr (4);

		if (IsVolumeDeviceHosted (favorite.Path.c_str()))
		{
			// Get GUID path
			string volumeDevPath = favorite.Path;

			wchar_t resolvedVolumeDevPath[TC_MAX_PATH];
			if (ResolveSymbolicLink (SingleStringToWide (volumeDevPath).c_str(), resolvedVolumeDevPath, sizeof(resolvedVolumeDevPath)))
				volumeDevPath = WideToSingleString (resolvedVolumeDevPath);

			char volumeName[TC_MAX_PATH];
			HANDLE find = FindFirstVolume (volumeName, sizeof (volumeName));

			if (find != INVALID_HANDLE_VALUE)
			{
				do
				{
					char findVolumeDevPath[TC_MAX_PATH];
					string vn = volumeName;

					if (QueryDosDevice (vn.substr (4, vn.size() - 5).c_str(), findVolumeDevPath, sizeof (findVolumeDevPath)) != 0
						&& volumeDevPath == findVolumeDevPath)
					{
						favorite.VolumePathId = volumeName;
						break;
					}

				} while (FindNextVolume (find, volumeName, sizeof (volumeName)));

				FindVolumeClose (find);
			}
		}

		favorite.ReadOnly = prop.readOnly ? true : false;
		favorite.Removable = prop.removable ? true : false;
		favorite.SystemEncryption = prop.partitionInInactiveSysEncScope ? true : false;
		favorite.OpenExplorerWindow = (bExplore == TRUE);

		if (favorite.VolumePathId.empty()
			&& IsVolumeDeviceHosted (favorite.Path.c_str())
			&& favorite.Path.find ("\\\\?\\Volume{") != 0)
		{
			Warning (favorite.Path.find ("\\Partition0") == string::npos ? "FAVORITE_ADD_PARTITION_TYPE_WARNING" : "FAVORITE_ADD_DRIVE_DEV_WARNING");
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
							throw ErrorException ("SYS_FAVORITES_REQUIRE_PBA");

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
							rec.bottom - CompensateYDPI (90),
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
								BootEncObj.RegisterSystemFavoritesService (reqConfig ? TRUE : FALSE);

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

				if (SaveFavoriteVolumes (Favorites, SystemFavoritesMode))
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
									Warning ("FAVORITE_ARRIVAL_MOUNT_BACKGROUND_TASK_ERR");
									break;
								}
							}
						}

						FavoriteVolumes = Favorites;

						ManageStartupSeq();
						SaveSettings (hwndDlg);
					}
					else
						SystemFavoriteVolumes = Favorites;

					OnFavoriteVolumesUpdated();
					LoadDriveLetters (GetDlgItem (MainDlg, IDC_DRIVELIST), 0);

					EndDialog (hwndDlg, IDOK);
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
						WarningDirect ((wstring (GetString ("SYS_FAVORITES_KEYBOARD_WARNING")) + L"\n\n" + GetString ("BOOT_PASSWORD_CACHE_KEYBOARD_WARNING")).c_str());

						if (!IsServerOS() && !IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY))
							Info ("SYS_FAVORITES_ADMIN_ONLY_INFO");
					}
				}
				return 1;

			case IDC_FAVORITE_DISABLE_HOTKEY: // Note that this option means "DISABLE_NONADMIN_SYS_FAVORITES_ACCESS" when SystemFavoritesMode is true
				if (SystemFavoritesMode)
				{
					// DISABLE_NONADMIN_SYS_FAVORITES_ACCESS

					if (IsDlgButtonChecked (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY))
						WarningDirect ((wstring (GetString ("SYS_FAVORITES_ADMIN_ONLY_WARNING")) + L"\n\n" + GetString ("SETTING_REQUIRES_REBOOT")).c_str());
					else
						Warning ("SETTING_REQUIRES_REBOOT");
				}
				return 1;

			case IDC_FAVORITES_HELP_LINK:
				Applink (SystemFavoritesMode ? "sysfavorites" : "favorites", TRUE, "");
				return 1;
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
		}

		return 0;
	}


	static void FillFavoriteVolumesMenu ()
	{
		while (DeleteMenu (FavoriteVolumesMenu, 7, MF_BYPOSITION)) { }

		if (FavoriteVolumes.empty())
			return;

		AppendMenu (FavoriteVolumesMenu, MF_SEPARATOR, 0, "");
		
		int i = 0;
		foreach (const FavoriteVolume &favorite, FavoriteVolumes)
		{
			UINT flags = MF_STRING;

			if (favorite.DisconnectedDevice)
				flags |= MF_GRAYED;

			wstring menuText = SingleStringToWide (favorite.Path);
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
				(menuText + L"\t" + SingleStringToWide (favorite.MountPoint).substr (0, 2)).c_str());
		}
	}


	static void FillListControl (HWND favoriteListControl, vector <FavoriteVolume> &favorites)
	{
		SendMessage (favoriteListControl, LVM_DELETEALLITEMS, 0, 0);

		int line = 0;
		foreach (const FavoriteVolume favorite, favorites)
		{
			ListItemAdd (favoriteListControl, line, (char *) favorite.MountPoint.substr (0, 2).c_str());
			FillListControlSubItems (favoriteListControl, line++, favorite);
		}
	}


	static void FillListControlSubItems (HWND FavoriteListControl, int line, const FavoriteVolume &favorite)
	{
		ListSubItemSetW (FavoriteListControl, line, 1, (wchar_t *) favorite.Label.c_str());

		if (favorite.DisconnectedDevice)
			ListSubItemSetW (FavoriteListControl, line, 2, (wchar_t *) (wstring (L"(") + GetString ("FAVORITE_DISCONNECTED_DEV") + L")").c_str());
		else
			ListSubItemSet (FavoriteListControl, line, 2, (char *) favorite.Path.c_str());
	}


	wstring GetFavoriteVolumeLabel (const string &volumePath)
	{
		foreach (const FavoriteVolume &favorite, FavoriteVolumes)
		{
			if (favorite.Path == volumePath)
				return favorite.Label;
		}

		foreach (const FavoriteVolume &favorite, SystemFavoriteVolumes)
		{
			if (favorite.Path == volumePath)
				return favorite.Label;
		}

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
		favorites.clear();
		string favoritesFilePath = systemFavorites ? GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES) : GetConfigPath (TC_APPD_FILENAME_FAVORITE_VOLUMES);

		if (systemFavorites && !IsAdmin() && !noUacElevation)
		{
			favoritesFilePath = GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES);

			try
			{
				BootEncryption bootEnc (MainDlg);
				bootEnc.CopyFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES).c_str(), favoritesFilePath.c_str());
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
			favorite.MountPoint = mountPoint;

			XmlGetNodeText (xml, volume, sizeof (volume));
			favorite.Path = WideToSingleString (Utf8StringToWide (volume));

			char label[1024];
			XmlGetAttributeText (xml, "label", label, sizeof (label));
			favorite.Label = Utf8StringToWide (label);

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

			if (favorite.Path.find ("\\\\?\\Volume{") == 0 && favorite.Path.rfind ("}\\") == favorite.Path.size() - 2)
			{
				string resolvedPath = VolumeGuidPathToDevicePath (favorite.Path);
				if (!resolvedPath.empty())
				{
					favorite.DisconnectedDevice = false;
					favorite.VolumePathId = favorite.Path;
					favorite.Path = resolvedPath;
				}
				else
					favorite.DisconnectedDevice = true;
			}

			favorites.push_back (favorite);
			xml++;
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


	static bool SaveFavoriteVolumes (const vector <FavoriteVolume> &favorites, bool systemFavorites)
	{
		FILE *f;
		int cnt = 0;

		f = fopen (GetConfigPath (systemFavorites ? TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES : TC_APPD_FILENAME_FAVORITE_VOLUMES), "w,ccs=UTF-8");
		if (f == NULL)
		{
			handleWin32Error (MainDlg);
			return false;
		}

		XmlWriteHeaderW (f);
		fputws (L"\n\t<favorites>", f);

		foreach (const FavoriteVolume &favorite, favorites)
		{
			char tq[2048];

			if (systemFavorites && favorite.Path.find ("\\\\") == 0 && favorite.Path.find ("Volume{") == string::npos)
				Warning ("SYSTEM_FAVORITE_NETWORK_PATH_ERR");

			XmlQuoteText (!favorite.VolumePathId.empty() ? favorite.VolumePathId.c_str() : favorite.Path.c_str(), tq, sizeof (tq));

			wstring s = L"\n\t\t<volume mountpoint=\"" + SingleStringToWide (favorite.MountPoint) + L"\"";

			if (!favorite.Label.empty())
				s += L" label=\"" + favorite.Label + L"\"";

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

			s += L">" + SingleStringToWide (tq) + L"</volume>";

			fwprintf (f, L"%ws", s.c_str());
			cnt++;
		}

		fputws (L"\n\t</favorites>", f);
		XmlWriteFooterW (f);

		if (!CheckFileStreamWriteErrors (f, systemFavorites ? TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES : TC_APPD_FILENAME_FAVORITE_VOLUMES))
		{
			fclose (f);
			return false;
		}

		fclose (f);

		BootEncryption bootEnc (MainDlg);

		if (systemFavorites)
		{
			finally_do ({ remove (GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES)); });

			try
			{
				bootEnc.DeleteFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES).c_str());
			}
			catch (UserAbort&) { return false; }
			catch (...) { }

			try
			{
				if (cnt != 0)
				{
					bootEnc.CopyFileAdmin (GetConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES), GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES).c_str());

					if (!(ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES))
						Info ("SYS_FAVORITE_VOLUMES_SAVED");
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
					bootEnc.DeleteFileAdmin (GetServiceConfigPath (TC_APPD_FILENAME_SYSTEM_FAVORITE_VOLUMES).c_str());
				}
				catch (...) { }
			}
			else
				remove (GetConfigPath (TC_APPD_FILENAME_FAVORITE_VOLUMES));
		}

		return true;
	}


	static void SetControls (HWND hwndDlg, const FavoriteVolume &favorite, bool systemFavoritesMode, bool enable)
	{
		SetDlgItemTextW (hwndDlg, IDC_FAVORITE_LABEL, favorite.Label.c_str());
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON, favorite.MountOnLogOn);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL, favorite.MountOnArrival);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_READONLY, favorite.ReadOnly);
		SetCheckBox (hwndDlg, IDC_FAVORITE_MOUNT_REMOVABLE, favorite.Removable);

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
		EnableWindow (GetDlgItem (hwndDlg, IDT_FAVORITE_LABEL), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_LABEL), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_ON_LOGON), enable && !systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_ON_ARRIVAL), enable && !systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_READONLY), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_MOUNT_REMOVABLE), enable);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_OPEN_EXPLORER_WIN_ON_MOUNT), enable || systemFavoritesMode);
		EnableWindow (GetDlgItem (hwndDlg, IDC_FAVORITE_DISABLE_HOTKEY), enable || systemFavoritesMode);
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
			&& favorite.Path.find ("\\\\?\\Volume{") != 0)
		{
			bool partition = (favorite.Path.find ("\\Partition0") == string::npos);

			if (!favorite.Label.empty())
			{
				ErrorDirect ((GetString (partition ? "FAVORITE_LABEL_PARTITION_TYPE_ERR" : "FAVORITE_LABEL_DEVICE_PATH_ERR") + wstring (L"\n\n") + SingleStringToWide (favorite.Path)).c_str());
				favorite.Label.clear();
			}

			if (favorite.MountOnArrival)
			{
				ErrorDirect ((GetString (partition ? "FAVORITE_ARRIVAL_MOUNT_PARTITION_TYPE_ERR" : "FAVORITE_ARRIVAL_MOUNT_DEVICE_PATH_ERR") + wstring (L"\n\n") + SingleStringToWide (favorite.Path)).c_str());
				favorite.MountOnArrival = false;
			}
		}

		if (favorite.MountOnArrival && favorite.Path.find ("\\\\") == 0 && favorite.Path.find ("Volume{") == string::npos)
		{
			Error ("FAVORITE_ARRIVAL_MOUNT_NETWORK_PATH_ERR");
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
