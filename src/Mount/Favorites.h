/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Mount_FavoriteVolumes
#define TC_HEADER_Mount_FavoriteVolumes

#include <Tcdefs.h>

namespace VeraCrypt
{
	struct FavoriteVolume
	{
		FavoriteVolume()
			:
			Pim (0),
			Pkcs5 (-1),
			DisableHotkeyMount (false),
			DisconnectedDevice (false),
			MountOnLogOn (false),
			MountOnArrival (false),
			OpenExplorerWindow (false),
			ReadOnly (false),
			Removable (false),
			SystemEncryption (false),
			UseLabelInExplorer (false),
			UseVolumeID (false)
		{
			memset (VolumeID, 0, VOLUME_ID_SIZE);
		}

		wstring Path;
		wstring MountPoint;
		wstring VolumePathId;
		wstring Label;
		int Pim;
		int Pkcs5;
		BYTE VolumeID[VOLUME_ID_SIZE];

		bool DisableHotkeyMount;
		bool DisconnectedDevice;
		bool MountOnLogOn;
		bool MountOnArrival;
		bool OpenExplorerWindow;
		bool ReadOnly;
		bool Removable;
		bool SystemEncryption;
		bool UseLabelInExplorer;
		bool UseVolumeID;
	};

	struct FavoriteVolumesDlgProcArguments
	{
		bool SystemFavorites;
		bool AddFavoriteVolume;
		FavoriteVolume NewFavoriteVolume;
	};

	extern vector <FavoriteVolume> FavoriteVolumes;
	extern vector <FavoriteVolume> SystemFavoriteVolumes;
	extern list <FavoriteVolume> FavoritesOnArrivalMountRequired;
	extern list <FavoriteVolume> FavoritesMountedOnArrivalStillConnected;
	extern HMENU FavoriteVolumesMenu;

	BOOL AddMountedVolumeToFavorites (HWND hwndDlg, int driveNo, bool systemFavorites);
	static BOOL CALLBACK FavoriteVolumesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
	static void FillFavoriteVolumesMenu ();
	static void FillListControl (HWND favoriteListControl, vector <FavoriteVolume> &favorites);
	static void FillListControlSubItems (HWND favoriteListControl, int line, const FavoriteVolume &favorite);
	wstring GetFavoriteVolumeLabel (const wstring &volumePath, bool& useInExplorer);
	void LoadFavoriteVolumes ();
	void LoadFavoriteVolumes (vector <FavoriteVolume> &favorites, bool systemFavorites, bool noUacElevation = false);
	static void OnFavoriteVolumesUpdated ();
	BOOL OrganizeFavoriteVolumes (HWND hwndDlg, bool systemFavorites, const FavoriteVolume &newFavorite = FavoriteVolume());
	bool SaveFavoriteVolumes (HWND hwndDlg, const vector <FavoriteVolume> &favorites, bool systemFavorites);
	static void SetControls (HWND hwndDlg, const FavoriteVolume &favorite, bool systemFavoritesMode, bool enable = true);
	static void SetFavoriteVolume (HWND hwndDlg, FavoriteVolume &favorite, bool systemFavoritesMode);
	void UpdateDeviceHostedFavoriteVolumes ();
}

#endif // TC_HEADER_Mount_FavoriteVolumes
