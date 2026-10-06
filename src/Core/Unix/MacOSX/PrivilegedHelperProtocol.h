/*
 Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

#ifndef TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperProtocol
#define TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperProtocol

// Shared constants for the VeraCrypt privileged helper (SMJobBless / launchd).
// Included by both the helper (PrivilegedHelper/Helper.cpp) and the client glue
// (Core/Unix/MacOSX/PrivilegedHelperClient.mm).

// launchd Label and Mach service name. Must match Helper-Launchd.plist.xml,
// Helper-Info.plist.xml (CFBundleIdentifier) and the SMPrivilegedExecutables
// key of the application's Info.plist.
#define VC_HELPER_LABEL "org.idrix.VeraCrypt.helper"

// Absolute path where SMJobBless installs the helper tool and its launchd job.
#define VC_HELPER_TOOL_PATH    "/Library/PrivilegedHelperTools/" VC_HELPER_LABEL
#define VC_HELPER_PLIST_PATH   "/Library/LaunchDaemons/" VC_HELPER_LABEL ".plist"

// XPC message keys.
#define VC_HELPER_KEY_COMMAND     "command"
#define VC_HELPER_KEY_APP_PATH    "app-path"
#define VC_HELPER_KEY_VERSION     "version"
#define VC_HELPER_KEY_SERVICE_FD  "service-fd"
#define VC_HELPER_KEY_ERROR       "error"

// XPC commands (value of VC_HELPER_KEY_COMMAND).
#define VC_HELPER_CMD_OPEN_CORE_SERVICE "open-core-service"
#define VC_HELPER_CMD_GET_VERSION       "get-version"
#define VC_HELPER_CMD_UNINSTALL         "uninstall"

// Protocol/helper version. Bump whenever Helper.cpp changes so that an outdated
// installed helper is detected by the client and re-blessed (standard pattern).
#define VC_HELPER_VERSION 1

#endif // TC_HEADER_Core_Unix_MacOSX_PrivilegedHelperProtocol
