/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "FavoriteVolumesDialog.h"

namespace TrueCrypt
{
	FavoriteVolumesDialog::FavoriteVolumesDialog (wxWindow* parent, const FavoriteVolumeList &favorites, size_t newItemCount)
		: FavoriteVolumesDialogBase (parent), Favorites (favorites)
	{
		list <int> colPermilles;
		FavoritesListCtrl->InsertColumn (ColumnVolumePath, LangString["VOLUME"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (500);
		FavoritesListCtrl->InsertColumn (ColumnMountPoint, LangString["MOUNT_POINT"], wxLIST_FORMAT_LEFT, 1);
		colPermilles.push_back (500);

		FavoritesListCtrl->SetMinSize (wxSize (400, -1));
		Gui->SetListCtrlHeight (FavoritesListCtrl, 15);
		Gui->SetListCtrlColumnWidths (FavoritesListCtrl, colPermilles);

		Layout();
		Fit();
		Center();
				
#ifdef TC_MACOSX
		// wxMac cannot insert items to wxListCtrl due to a bug
		MoveUpButton->Show (false);
		MoveDownButton->Show (false);
#endif

		vector <wstring> fields (FavoritesListCtrl->GetColumnCount());
		size_t itemCount = 0;
		foreach (shared_ptr <FavoriteVolume> favorite, Favorites)
		{
			fields[ColumnVolumePath] = favorite->Path;
			fields[ColumnMountPoint] = favorite->MountPoint;
			Gui->AppendToListCtrl (FavoritesListCtrl, fields, -1, favorite.get());
			
			if (++itemCount > Favorites.size() - newItemCount)
			{
				FavoritesListCtrl->SetItemState (itemCount - 1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
				FavoritesListCtrl->EnsureVisible (itemCount - 1);
			}
		}

		UpdateButtons();
		FavoritesListCtrl->SetFocus();
	}
	
	void FavoriteVolumesDialog::OnMoveDownButtonClick (wxCommandEvent& event)
	{
		FreezeScope freeze (this);
		foreach_reverse (long itemIndex, Gui->GetListCtrlSelectedItems (FavoritesListCtrl))
		{
			if (itemIndex >= FavoritesListCtrl->GetItemCount() - 1)
				break;
			Gui->MoveListCtrlItem (FavoritesListCtrl, itemIndex, itemIndex + 1);
		}
		UpdateButtons();
	}

	void FavoriteVolumesDialog::OnMoveUpButtonClick (wxCommandEvent& event)
	{
		FreezeScope freeze (this);
		foreach (long itemIndex, Gui->GetListCtrlSelectedItems (FavoritesListCtrl))
		{
			if (itemIndex == 0)
				break;

			Gui->MoveListCtrlItem (FavoritesListCtrl, itemIndex, itemIndex - 1);
		}
		UpdateButtons();
	}

	void FavoriteVolumesDialog::OnOKButtonClick (wxCommandEvent& event)
	{
		FavoriteVolumeList newFavorites;

		for (long i = 0; i < FavoritesListCtrl->GetItemCount(); i++)
		{
			newFavorites.push_back (make_shared <FavoriteVolume> (
				*reinterpret_cast <FavoriteVolume *> (FavoritesListCtrl->GetItemData (i))));
		}

		Favorites = newFavorites;
		EndModal (wxID_OK);
	}

	void FavoriteVolumesDialog::OnRemoveAllButtonClick (wxCommandEvent& event)
	{
		FavoritesListCtrl->DeleteAllItems();
		UpdateButtons();
	}

	void FavoriteVolumesDialog::OnRemoveButtonClick (wxCommandEvent& event)
	{
		long offset = 0;
		foreach (long item, Gui->GetListCtrlSelectedItems (FavoritesListCtrl))
			FavoritesListCtrl->DeleteItem (item - offset++);
	}

	void FavoriteVolumesDialog::UpdateButtons ()
	{
		bool selected = FavoritesListCtrl->GetSelectedItemCount() > 0;

		MoveDownButton->Enable (selected);
		MoveUpButton->Enable (selected);
		RemoveAllButton->Enable (FavoritesListCtrl->GetItemCount() > 0);
		RemoveButton->Enable (selected);
	}
}
