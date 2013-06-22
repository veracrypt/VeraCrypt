/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Mount_FavoriteVolumes
#define TC_HEADER_Mount_FavoriteVolumes

#include <Tcdefs.h>

namespace TrueCrypt
{
	struct FavoriteVolume
	{
		FavoriteVolume()
			:	
			DisableHotkeyMount (false),
			DisconnectedDevice (false),
			MountOnLogOn (false),
			MountOnArrival (false),
			OpenExplorerWindow (false),
			ReadOnly (false),
			Removable (false),
			SystemEncryption (false)
		{
		}

		string Path;
		string MountPoint;
		string VolumePathId;
		wstring Label;

		bool DisableHotkeyMount;
		bool DisconnectedDevice;
		bool MountOnLogOn;
		bool MountOnArrival;
		bool OpenExplorerWindow;
		bool ReadOnly;
		bool Removable;
		bool SystemEncryption;
	};

	struct FavoriteVolumesDlgProcArguments
	{
		bool SystemFavorites;
		bool AddFavoriteVolume;
		FavoriteVolume NewFavoriteVolume;
	};

	extern vector <FavoriteVolume> FavoriteVolumes;
	extern list <FavoriteVolume> FavoritesOnArrivalMountRequired;
	extern list <FavoriteVolume> FavoritesMountedOnArrivalStillConnected;
	extern HMENU FavoriteVolumesMenu;

	BOOL AddMountedVolumeToFavorites (HWND hwndDlg, int driveNo, bool systemFavorites);
	static BOOL CALLBACK FavoriteVolumesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
	static void FillFavoriteVolumesMenu ();
	static void FillListControl (HWND favoriteListControl, vector <FavoriteVolume> &favorites);
	static void FillListControlSubItems (HWND favoriteListControl, int line, const FavoriteVolume &favorite);
	wstring GetFavoriteVolumeLabel (const string &volumePath);
	void LoadFavoriteVolumes ();
	void LoadFavoriteVolumes (vector <FavoriteVolume> &favorites, bool systemFavorites, bool noUacElevation = false);
	static void OnFavoriteVolumesUpdated ();
	BOOL OrganizeFavoriteVolumes (HWND hwndDlg, bool systemFavorites, const FavoriteVolume &newFavorite = FavoriteVolume());
	static bool SaveFavoriteVolumes (const vector <FavoriteVolume> &favorites, bool systemFavorites);
	static void SetControls (HWND hwndDlg, const FavoriteVolume &favorite, bool systemFavoritesMode, bool enable = true);
	static void SetFavoriteVolume (HWND hwndDlg, FavoriteVolume &favorite, bool systemFavoritesMode);
	void UpdateDeviceHostedFavoriteVolumes ();
}

#endif // TC_HEADER_Mount_FavoriteVolumes
