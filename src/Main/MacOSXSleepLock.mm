/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "MacOSXSleepLock.h"
#include "Platform/SystemLog.h"

#ifdef TC_MACOSX
#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>

enum VCSessionLockState
{
	VCSessionLockStateUnknown,
	VCSessionLockStateUnlocked,
	VCSessionLockStateLocked
};

static VCSessionLockState LastSessionLockState = VCSessionLockStateUnknown;

static void LogSleepLockError (const char *context, const std::exception *ex)
{
	try
	{
		std::stringstream message;
		message << "macOS " << context << " callback failed";
		if (ex)
			message << ": " << VeraCrypt::StringConverter::ToSingle (VeraCrypt::StringConverter::ToExceptionString (*ex));
		else
			message << ": unknown exception";
		VeraCrypt::SystemLog::WriteError (message.str());
	}
	catch (...) { }
}

// Distributed lock notifications are untrusted hints. Query the window server
// for the actual state and preserve Unknown separately from Unlocked so a
// transient query failure cannot create a false transition.
static VCSessionLockState GetSessionLockState ()
{
	CFDictionaryRef session = CGSessionCopyCurrentDictionary ();
	if (!session)
		return VCSessionLockStateUnknown;

	CFTypeRef value = CFDictionaryGetValue (session, CFSTR ("CGSSessionScreenIsLocked"));
	// The private lock key is absent from a valid dictionary while the session
	// is unlocked. Preserve Unknown only for a query failure or malformed value.
	VCSessionLockState state = VCSessionLockStateUnlocked;
	if (value)
		state = CFGetTypeID (value) == CFBooleanGetTypeID ()
			? (CFBooleanGetValue ((CFBooleanRef) value) ? VCSessionLockStateLocked : VCSessionLockStateUnlocked)
			: VCSessionLockStateUnknown;

	CFRelease (session);
	return state;
}

@interface VCSleepLockObserver : NSObject
- (void) systemWillSleep: (NSNotification *) notification;
- (void) sessionStateChanged: (NSNotification *) notification;
@end

@implementation VCSleepLockObserver

// The callbacks below are entered from AppKit notification dispatch; a C++
// exception must not unwind through those Objective-C frames, so every call
// into VeraCrypt code is guarded and failures are logged without displaying UI.

- (void) systemWillSleep: (NSNotification *) notification
{
	(void) notification;
	try
	{
		VeraCrypt::OnMacOSXSystemWillSleep ();
	}
	catch (const std::exception &e)
	{
		LogSleepLockError ("system sleep", &e);
	}
	catch (...)
	{
		LogSleepLockError ("system sleep", nullptr);
	}
}

- (void) sessionStateChanged: (NSNotification *) notification
{
	(void) notification;
	try
	{
		VeraCrypt::ReconcileMacOSXScreenLockState ();
	}
	catch (const std::exception &e)
	{
		LogSleepLockError ("session state", &e);
	}
	catch (...)
	{
		LogSleepLockError ("session state", nullptr);
	}
}

@end

namespace VeraCrypt
{
	// Non-ARC build (see the .mm compile rule in Build/Include/Makefile.inc),
	// so the observer is retained by alloc/init and released in Uninstall.
	static VCSleepLockObserver *SleepLockObserver = nil;

	void ReconcileMacOSXScreenLockState ()
	{
		try
		{
			VCSessionLockState state = GetSessionLockState ();
			if (state == VCSessionLockStateUnknown)
				return;

			bool enteredLockedState = state == VCSessionLockStateLocked && LastSessionLockState != VCSessionLockStateLocked;
			LastSessionLockState = state;
			if (enteredLockedState)
				OnMacOSXScreenLocked ();
		}
		catch (const std::exception &e)
		{
			LogSleepLockError ("session reconciliation", &e);
		}
		catch (...)
		{
			LogSleepLockError ("session reconciliation", nullptr);
		}
	}

	void InstallMacOSXSleepLockHandler ()
	{
		if (SleepLockObserver)
			return;

		SleepLockObserver = [[VCSleepLockObserver alloc] init];
		LastSessionLockState = VCSessionLockStateUnknown;

		// System sleep (lid close, idle sleep, Apple menu > Sleep). NSWorkspace's
		// notification center is process-local, so external local processes cannot
		// inject this notification as they can with the distributed center below.
		[[[NSWorkspace sharedWorkspace] notificationCenter]
			addObserver: SleepLockObserver
			selector: @selector (systemWillSleep:)
			name: NSWorkspaceWillSleepNotification
			object: nil];

		// macOS exposes no public screen-lock notification. These long-standing
		// distributed notifications are untrusted hints, so both lock and unlock
		// handlers verify the actual session state. DeliverImmediately prevents
		// notification coalescing while VeraCrypt is inactive or hidden.
		[[NSDistributedNotificationCenter defaultCenter]
			addObserver: SleepLockObserver
			selector: @selector (sessionStateChanged:)
			name: @"com.apple.screenIsLocked"
			object: nil
			suspensionBehavior: NSNotificationSuspensionBehaviorDeliverImmediately];
		[[NSDistributedNotificationCenter defaultCenter]
			addObserver: SleepLockObserver
			selector: @selector (sessionStateChanged:)
			name: @"com.apple.screenIsUnlocked"
			object: nil
			suspensionBehavior: NSNotificationSuspensionBehaviorDeliverImmediately];
	}

	void UninstallMacOSXSleepLockHandler ()
	{
		if (!SleepLockObserver)
			return;

		[[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver: SleepLockObserver];
		[[NSDistributedNotificationCenter defaultCenter] removeObserver: SleepLockObserver];
		[SleepLockObserver release];
		SleepLockObserver = nil;
		LastSessionLockState = VCSessionLockStateUnknown;
	}
}
#endif
