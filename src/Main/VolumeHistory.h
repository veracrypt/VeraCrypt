/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_VolumeHistory
#define TC_HEADER_Main_VolumeHistory

#include "System.h"
#include "Main.h"

namespace TrueCrypt
{
	class VolumeHistory
	{
	public:
		VolumeHistory ();
		virtual ~VolumeHistory ();

		static void Add (const VolumePath &path);
		static void Clear ();
		static void ConnectComboBox (wxComboBox *comboBox);
		static void DisconnectComboBox (wxComboBox *comboBox);
		static VolumePathList Get () { return VolumePaths; }
		static void Load ();
		static void Save ();

	protected:
		static void UpdateComboBox (wxComboBox *comboBox);
		static wxString GetFileName () { return L"History.xml"; }

		static const unsigned int MaxSize = 10;
		static list <wxComboBox *> ConnectedComboBoxes;
		static VolumePathList VolumePaths;
		static Mutex AccessMutex;

	private:
		VolumeHistory (const VolumeHistory &);
		VolumeHistory &operator= (const VolumeHistory &);
	};
}

#endif // TC_HEADER_Main_VolumeHistory
