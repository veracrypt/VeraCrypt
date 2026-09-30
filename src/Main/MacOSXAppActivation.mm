/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "MacOSXAppActivation.h"

#ifdef TC_MACOSX
#import <Cocoa/Cocoa.h>

namespace VeraCrypt
{
	// Call only after wxWidgets has created wxNSApplication; never create NSApplication here.
	// Using sharedApplication before wx initialization prevents wx from installing its subclass.
	// On macOS 14+, activate is cooperative and may complete asynchronously.
	void ActivateMacOSXApp ()
	{
		if (NSApp == nil)
			return;

#if defined(MAC_OS_VERSION_14_0) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_14_0
		if (@available(macOS 14.0, *))
		{
			[NSApp activate];
			return;
		}
#endif

		[NSApp activateIgnoringOtherApps:YES];
	}
}
#endif
