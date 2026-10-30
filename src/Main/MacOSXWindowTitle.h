/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_MacOSXWindowTitle
#define TC_HEADER_Main_MacOSXWindowTitle

#ifdef TC_MACOSX
class wxString;
class wxTopLevelWindow;

namespace VeraCrypt
{
	// Set the full title before measuring candidates, so AppKit lays out all
	// available caption space instead of sizing the field to a shorter title.
	bool MacOSXWindowTitleFits (wxTopLevelWindow *window, const wxString &title);
}
#endif

#endif // TC_HEADER_Main_MacOSXWindowTitle
