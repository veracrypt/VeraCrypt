/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Application.h"
#include "FavoriteVolume.h"
#include "Xml.h"

namespace TrueCrypt
{
	FavoriteVolumeList FavoriteVolume::LoadList ()
	{
		FavoriteVolumeList favorites;

		FilePath path = Application::GetConfigFilePath (GetFileName());

		if (path.IsFile())
		{
			foreach (XmlNode node, XmlParser (path).GetNodes (L"volume"))
			{
				VolumeSlotNumber slotNumber = 0;
				wstring attr = wstring (node.Attributes[L"slotnumber"]);
				if (!attr.empty())
					slotNumber = StringConverter::ToUInt64 (attr);
	
				bool readOnly = false;
				attr = wstring (node.Attributes[L"readonly"]);
				if (!attr.empty())
					readOnly = (StringConverter::ToUInt32 (attr) != 0 ? true : false);

				bool system = false;
				attr = wstring (node.Attributes[L"system"]);
				if (!attr.empty())
					system = (StringConverter::ToUInt32 (attr) != 0 ? true : false);

				favorites.push_back (shared_ptr <FavoriteVolume> (
					new FavoriteVolume ((wstring) node.InnerText, wstring (node.Attributes[L"mountpoint"]), slotNumber, readOnly, system)));
			}
		}

		return favorites;
	}

	void FavoriteVolume::SaveList (const FavoriteVolumeList &favorites)
	{
		FilePath favoritesCfgPath = Application::GetConfigFilePath (GetFileName(), true);

		if (favorites.empty())
		{
			if (favoritesCfgPath.IsFile())
				favoritesCfgPath.Delete();
		}
		else
		{
			XmlNode favoritesXml (L"favorites");

			foreach_ref (const FavoriteVolume &favorite, favorites)
			{
				XmlNode node (L"volume", wstring (favorite.Path));
				node.Attributes[L"mountpoint"] = wstring (favorite.MountPoint);
				node.Attributes[L"slotnumber"] = StringConverter::FromNumber (favorite.SlotNumber);
				node.Attributes[L"readonly"] = StringConverter::FromNumber (favorite.ReadOnly ? 1 : 0);
				node.Attributes[L"system"] = StringConverter::FromNumber (favorite.System ? 1 : 0);

				favoritesXml.InnerNodes.push_back (node);
			}

			XmlWriter favoritesWriter (favoritesCfgPath);
			favoritesWriter.WriteNode (favoritesXml);
			favoritesWriter.Close();
		}
	}

	void FavoriteVolume::ToMountOptions (MountOptions &options) const
	{
		if (MountPoint.IsEmpty())
		{
			options.MountPoint.reset();
			options.NoFilesystem = true;
		}
		else
			options.MountPoint.reset (new DirectoryPath (MountPoint));

		options.Path.reset (new VolumePath (Path));
		options.PartitionInSystemEncryptionScope = System;
		options.Protection = (ReadOnly ? VolumeProtection::ReadOnly : VolumeProtection::None);
		options.SlotNumber = SlotNumber;
	}
}
