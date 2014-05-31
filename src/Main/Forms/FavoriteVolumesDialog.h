/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_FavoriteVolumesDialog
#define TC_HEADER_Main_Forms_FavoriteVolumesDialog

#include "Forms.h"
#include "Main/Main.h"
#include "Main/FavoriteVolume.h"

namespace TrueCrypt
{
	class FavoriteVolumesDialog : public FavoriteVolumesDialogBase
	{
	public:
		FavoriteVolumesDialog (wxWindow* parent, const FavoriteVolumeList &favorites, size_t newItemCount = 0);

		FavoriteVolumeList GetFavorites () const { return Favorites; }

	protected:
		void OnListItemDeselected (wxListEvent& event) { UpdateButtons (); }
		void OnListItemSelected (wxListEvent& event) { UpdateButtons (); }
		void OnMoveUpButtonClick (wxCommandEvent& event);
		void OnMoveDownButtonClick (wxCommandEvent& event);
		void OnOKButtonClick (wxCommandEvent& event);
		void OnRemoveAllButtonClick (wxCommandEvent& event);
		void OnRemoveButtonClick (wxCommandEvent& event);
		void UpdateButtons ();
		
		enum
		{
			ColumnVolumePath = 0,
			ColumnMountPoint
		};

		FavoriteVolumeList Favorites;
	};
}

#endif // TC_HEADER_Main_Forms_FavoriteVolumesDialog
