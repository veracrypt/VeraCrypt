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

#ifndef TC_HEADER_Main_FavoriteVolume
#define TC_HEADER_Main_FavoriteVolume

#include "System.h"
#include "Main.h"

namespace VeraCrypt
{
	struct FavoriteVolume;
	typedef list < shared_ptr <FavoriteVolume> > FavoriteVolumeList;

	struct FavoriteVolume
	{
	public:
		FavoriteVolume ()
			: ReadOnly (false),
			System (false)
		{
		}

		FavoriteVolume (const VolumePath &path, const DirectoryPath &mountPoint, VolumeSlotNumber slotNumber, bool readOnly, bool system)
			: MountPoint (mountPoint),
			Path (path),
			ReadOnly (readOnly),
			SlotNumber (slotNumber),
			System (system)
		{
		}

		static FavoriteVolumeList LoadList ();
		static void SaveList (const FavoriteVolumeList &favorites);
		void ToMountOptions (MountOptions &options) const;

		DirectoryPath MountPoint;
		VolumePath Path;
		bool ReadOnly;
		VolumeSlotNumber SlotNumber;
		bool System;

	protected:
		static wxString GetFileName () { return L"Favorite Volumes.xml"; }
	};
}

#endif // TC_HEADER_Main_FavoriteVolume
