/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_MacOSXSleepLock
#define TC_HEADER_Main_MacOSXSleepLock

#ifdef TC_MACOSX
namespace VeraCrypt
{
	// Register/unregister observers for system sleep and screen lock.
	// Implemented in MacOSXSleepLock.mm.
	void InstallMacOSXSleepLockHandler ();
	void UninstallMacOSXSleepLockHandler ();
	void ReconcileMacOSXScreenLockState ();

	// Invoked after a trusted sleep notification or a verified screen-lock
	// transition. Implemented on the C++ side (GraphicUserInterface.cpp) so
	// that all wxWidgets / Core logic stays out of the Objective-C++ file.
	void OnMacOSXSystemWillSleep ();
	void OnMacOSXScreenLocked ();
}
#endif

#endif // TC_HEADER_Main_MacOSXSleepLock
