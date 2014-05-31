/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_System
#define TC_HEADER_Main_System

#ifndef TC_WINDOWS

#include "SystemPrecompiled.h"

#else

#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef TC_LOCAL_WIN32_WINNT_OVERRIDE
#	ifndef _WIN32_WINNT
#		define _WIN32_WINNT 0x0501
#	endif						
#endif						

#ifndef _WIN32_WINDOWS
#define _WIN32_WINDOWS 0x0410
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

#define WIN32_LEAN_AND_MEAN

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif _UNICODE

#include <wx/wxprec.h>
#include <wx/dde.h>
#include <wx/dnd.h>
#include <wx/filename.h>
#include <wx/hyperlink.h>
#include <wx/imaglist.h>
#include <wx/listctrl.h>
#include <wx/mstream.h>
#include <wx/power.h>
#include <wx/snglinst.h>
#include <wx/taskbar.h>
#include <wx/txtstrm.h>
#include <wx/valgen.h>
#include <wx/wfstream.h>
#include <shellapi.h>

#include <iostream>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#endif

#endif // TC_HEADER_Main_System
