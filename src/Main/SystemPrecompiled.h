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

#include <wx/wx.h>
#include <wx/filename.h>
#include <wx/mstream.h>
#include <wx/snglinst.h>
#include <wx/txtstrm.h>
#include <wx/wfstream.h>

#ifndef TC_NO_GUI
#include <wx/dnd.h>
#include <wx/hyperlink.h>
#include <wx/listctrl.h>
#include <wx/imaglist.h>
#include <wx/power.h>
#include <wx/taskbar.h>
#include <wx/valgen.h>
#endif

#include <iostream>
#include <sstream>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
