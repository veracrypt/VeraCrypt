/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_VolumeHistory
#define TC_HEADER_Main_VolumeHistory

#include "System.h"
#include "Main.h"

namespace VeraCrypt
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
