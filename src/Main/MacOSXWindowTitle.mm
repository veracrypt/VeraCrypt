/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "MacOSXWindowTitle.h"

#ifdef TC_MACOSX
#import <Cocoa/Cocoa.h>
#include <wx/toplevel.h>

namespace
{
	NSTextField *FindTitleField (NSView *view, NSView *contentView, NSString *title)
	{
		if (view == contentView)
			return nil;
		if ([view isKindOfClass:[NSTextField class]] && [[(NSTextField *) view stringValue] isEqualToString:title])
			return (NSTextField *) view;
		for (NSView *child in [view subviews])
		{
			NSTextField *field = FindTitleField (child, contentView, title);
			if (field)
				return field;
		}
		return nil;
	}
}

namespace VeraCrypt
{
	bool MacOSXWindowTitleFits (wxTopLevelWindow *window, const wxString &title)
	{
		NSWindow *nativeWindow = (NSWindow *) window->GetWXWindow();
		NSString *nativeTitle = [NSString stringWithUTF8String:title.utf8_str()];
		NSView *contentView = [nativeWindow contentView];
		NSView *frameView = [contentView superview];
		[frameView layoutSubtreeIfNeeded];
		NSTextField *field = FindTitleField (frameView, contentView, [nativeWindow title]);
		if (field)
		{
			// Use the actual title font and text rectangle: the dialog's font
			// and the window's outer width do not describe its title bar.
			NSFont *font = [field font];
			CGFloat textWidth = [nativeTitle sizeWithAttributes:@{NSFontAttributeName: font}].width;
			CGFloat availableWidth = [[field cell] drawingRectForBounds:[field bounds]].size.width;
			return ceil (textWidth) <= availableWidth;
		}

		// Older AppKit versions may draw the title without a text-field view.
		// Keep a margin in addition to the native minimum frame width.
		return [NSWindow minFrameWidthWithTitle:nativeTitle styleMask:[nativeWindow styleMask]] + 20 <= [nativeWindow frame].size.width;
	}
}
#endif
