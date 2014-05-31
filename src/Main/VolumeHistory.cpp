/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Application.h"
#include "GraphicUserInterface.h"
#include "Xml.h"
#include "VolumeHistory.h"

namespace TrueCrypt
{
	VolumeHistory::VolumeHistory ()
	{
	}

	VolumeHistory::~VolumeHistory ()
	{
	}

	void VolumeHistory::Add (const VolumePath &newPath)
	{
		if (Gui->GetPreferences().SaveHistory)
		{
			ScopeLock lock (AccessMutex);

			VolumePathList::iterator iter = VolumePaths.begin();
			foreach (const VolumePath &path, VolumePaths)
			{
				if (newPath == path)
				{
					VolumePaths.erase (iter);
					break;
				}
				iter++;
			}

			VolumePaths.push_front (newPath);
			if (VolumePaths.size() > MaxSize)
				VolumePaths.pop_back();

			foreach (wxComboBox *comboBox, ConnectedComboBoxes)
			{
				UpdateComboBox (comboBox);
			}
		}
	}

	void VolumeHistory::Clear ()
	{
		VolumePaths.clear();
		foreach (wxComboBox *comboBox, ConnectedComboBoxes)
		{
			UpdateComboBox (comboBox);
		}

		Save();
	}

	void VolumeHistory::ConnectComboBox (wxComboBox *comboBox)
	{
		ScopeLock lock (AccessMutex);
		ConnectedComboBoxes.push_back (comboBox);

		UpdateComboBox (comboBox);
	}

	void VolumeHistory::DisconnectComboBox (wxComboBox *comboBox)
	{
		ScopeLock lock (AccessMutex);

		for (list<wxComboBox *>::iterator iter = ConnectedComboBoxes.begin(); iter != ConnectedComboBoxes.end(); ++iter)
		{
			if (comboBox == *iter)
			{
				ConnectedComboBoxes.erase (iter);
				break;
			}
		}
	}

	void VolumeHistory::Load ()
	{
		ScopeLock lock (AccessMutex);
		FilePath historyCfgPath = Application::GetConfigFilePath (GetFileName());

		if (historyCfgPath.IsFile())
		{
			if (!Gui->GetPreferences().SaveHistory)
			{
				historyCfgPath.Delete();
			}
			else
			{
				foreach_reverse (const XmlNode &node, XmlParser (historyCfgPath).GetNodes (L"volume"))
				{
					Add (wstring (node.InnerText));
				}
			}
		}
	}

	void VolumeHistory::Save ()
	{
		ScopeLock lock (AccessMutex);
		FilePath historyCfgPath = Application::GetConfigFilePath (GetFileName(), true);

		if (!Gui->GetPreferences().SaveHistory || VolumePaths.empty())
		{
			if (historyCfgPath.IsFile())
				historyCfgPath.Delete();
		}
		else
		{
			XmlNode historyXml (L"history");

			foreach (const VolumePath &path, VolumePaths)
			{
				historyXml.InnerNodes.push_back (XmlNode (L"volume", wstring (path)));
			}

			XmlWriter historyWriter (historyCfgPath);
			historyWriter.WriteNode (historyXml);
			historyWriter.Close();
		}
	}

	void VolumeHistory::UpdateComboBox (wxComboBox *comboBox)
	{
		wxString curValue = comboBox->GetValue();

		comboBox->Freeze();
		comboBox->Clear();

		foreach (const VolumePath &path, VolumePaths)
		{
			comboBox->Append (wstring (path));
		}

		comboBox->SetValue (curValue);
		comboBox->Thaw();
	}

	list <wxComboBox *> VolumeHistory::ConnectedComboBoxes;
	VolumePathList VolumeHistory::VolumePaths;
	Mutex VolumeHistory::AccessMutex;

}
