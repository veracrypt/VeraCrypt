/*
 Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

#ifndef TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperClient
#define TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperClient

#include <string>

namespace VeraCrypt
{
	// Ensures the SMJobBless privileged helper is installed and up to date
	// (showing the native macOS authentication dialog when an install/upgrade
	// is required), then asks it to spawn "appPath --core-service" as root and
	// returns a connected socket file descriptor to that root process. The
	// returned descriptor is owned by the caller and must be closed.
	//
	// Throws a VeraCrypt exception (e.g. ElevationFailed) on any failure.
	int MacOSXConnectElevatedCoreService (const std::string &appPath);
}

#endif // TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperClient
