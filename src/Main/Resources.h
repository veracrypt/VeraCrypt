/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
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
		static string GetLanguageXml (string& preferredLang);
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
