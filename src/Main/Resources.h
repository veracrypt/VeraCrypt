/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Resources
#define TC_HEADER_Main_Resources

#include "System.h"
#include "Platform/Platform.h"

namespace VeraCrypt
{
	class Resources
	{
	public:
		static string GetLanguageXml ();
		static string GetLegalNotices ();
#ifndef TC_NO_GUI
		static wxBitmap GetDriveIconBitmap ();
		static wxBitmap GetDriveIconMaskBitmap ();
		static wxBitmap GetLogoBitmap ();
		static wxBitmap GetTextualLogoBitmap ();
		static wxIcon GetVeraCryptIcon ();
		static wxBitmap GetVolumeCreationWizardBitmap (int height = -1);
#endif
	};
}

#endif // TC_HEADER_Main_Resources
