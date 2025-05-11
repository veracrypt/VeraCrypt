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

#ifndef TC_HEADER_Main_Main
#define TC_HEADER_Main_Main

#include "System.h"
#include "Platform/Platform.h"
#include "Core/Core.h"
#include "Main/StringFormatter.h"

#define MAX_PIM_DIGITS			7		// Maximum allowed digits in a PIM (enough for maximum value)
#define MAX_PIM_VALUE		2147468 // Maximum value to have a positive 32-bit result for formula 15000 + (PIM x 1000)
#define MAX_BOOT_PIM_DIGITS		5		// Maximum allowed digits in a PIM for boot (enough for 16-bit value)
#define MAX_BOOT_PIM_VALUE	65535

#endif // TC_HEADER_Main_Main
