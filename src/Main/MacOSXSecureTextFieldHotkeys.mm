/*
 Copyright (c) 2013-2025 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "MacOSXSecureTextFieldHotkeys.h"

#ifdef TC_MACOSX
#import <Cocoa/Cocoa.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(MAC_OS_X_VERSION_10_12) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_12
#define VC_NSEVENT_MASK_KEY_DOWN NSEventMaskKeyDown
#define VC_NSEVENT_MODIFIER_FLAG_COMMAND NSEventModifierFlagCommand
#define VC_NSEVENT_MODIFIER_FLAG_CONTROL NSEventModifierFlagControl
#define VC_NSEVENT_MODIFIER_FLAG_OPTION NSEventModifierFlagOption
#define VC_NSEVENT_MODIFIER_FLAG_SHIFT NSEventModifierFlagShift
#define VC_NSEVENT_TYPE_KEY_DOWN NSEventTypeKeyDown
#else
#define VC_NSEVENT_MASK_KEY_DOWN NSKeyDownMask
#define VC_NSEVENT_MODIFIER_FLAG_COMMAND NSCommandKeyMask
#define VC_NSEVENT_MODIFIER_FLAG_CONTROL NSControlKeyMask
#define VC_NSEVENT_MODIFIER_FLAG_OPTION NSAlternateKeyMask
#define VC_NSEVENT_MODIFIER_FLAG_SHIFT NSShiftKeyMask
#define VC_NSEVENT_TYPE_KEY_DOWN NSKeyDown
#endif

namespace
{
	id SecureTextFieldHotkeyMonitor = nil;

	bool IsCommandA (NSEvent *event)
	{
		if ([event type] != VC_NSEVENT_TYPE_KEY_DOWN)
			return false;

		const NSEventModifierFlags shortcutModifiers =
			VC_NSEVENT_MODIFIER_FLAG_COMMAND | VC_NSEVENT_MODIFIER_FLAG_CONTROL | VC_NSEVENT_MODIFIER_FLAG_OPTION | VC_NSEVENT_MODIFIER_FLAG_SHIFT;

		if (([event modifierFlags] & shortcutModifiers) != VC_NSEVENT_MODIFIER_FLAG_COMMAND)
			return false;

		NSString *characters = [event charactersIgnoringModifiers];
		if ([characters length] != 1)
			return false;

		unichar character = [characters characterAtIndex:0];
		return character == 'a' || character == 'A';
	}

	wxTextCtrl *GetFocusedSecureTextCtrl ()
	{
		wxWindow *focusedCtrl = wxWindow::FindFocus();
		if (!focusedCtrl
			|| !focusedCtrl->IsKindOf (wxCLASSINFO (wxTextCtrl))
			|| !(focusedCtrl->GetWindowStyle() & wxTE_PASSWORD))
		{
			return nullptr;
		}

		return static_cast <wxTextCtrl *> (focusedCtrl);
	}

	NSEvent *HandleSecureTextFieldHotkey (NSEvent *event)
	{
		if (!IsCommandA (event))
			return event;

		wxTextCtrl *secureTextCtrl = GetFocusedSecureTextCtrl();
		if (!secureTextCtrl)
			return event;

		secureTextCtrl->SelectAll();
		return nil;
	}
}

namespace VeraCrypt
{
	void InstallMacOSXSecureTextFieldHotkeys ()
	{
		if (SecureTextFieldHotkeyMonitor)
			return;

		SecureTextFieldHotkeyMonitor = [NSEvent addLocalMonitorForEventsMatchingMask:VC_NSEVENT_MASK_KEY_DOWN handler:^NSEvent *(NSEvent *event) {
			return HandleSecureTextFieldHotkey (event);
		}];
#if !__has_feature(objc_arc)
		[SecureTextFieldHotkeyMonitor retain];
#endif
	}

	void UninstallMacOSXSecureTextFieldHotkeys ()
	{
		if (!SecureTextFieldHotkeyMonitor)
			return;

		id monitor = SecureTextFieldHotkeyMonitor;
		SecureTextFieldHotkeyMonitor = nil;

		[NSEvent removeMonitor:monitor];
#if !__has_feature(objc_arc)
		[monitor release];
#endif
	}
}
#endif
