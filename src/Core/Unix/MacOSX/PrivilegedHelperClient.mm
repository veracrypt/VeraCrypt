/*
 Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

// Client-side glue for the VeraCrypt SMJobBless privileged helper.
//
// This translation unit is compiled as Objective-C++ (".mm") so that it can use
// the Blocks-based XPC and ServiceManagement APIs (the rest of CoreService.cpp
// is plain C++ and is not compiled with -fblocks). It exposes a single plain
// C++ entry point, MacOSXConnectElevatedCoreService(), declared in
// PrivilegedHelperClient.h and called from CoreService::StartElevated().

#include "PrivilegedHelperClient.h"
#include "PrivilegedHelperProtocol.h"

// The Apple framework headers must come first: they typedef BOOL (objc.h),
// which must be seen before Common/Tcdefs.h redefines BOOL as a macro. They
// also pull in <mach/error.h>, whose ERR_SUCCESS macro would otherwise mangle
// the ERR_SUCCESS enumerator in Tcdefs.h, so it is undefined before the
// VeraCrypt headers (reached via SystemException.h) are included.
#include <xpc/xpc.h>
#include <Security/Security.h>
#include <ServiceManagement/ServiceManagement.h>
#include <CoreFoundation/CoreFoundation.h>

#undef ERR_SUCCESS

#include "Platform/SystemException.h"
#include "Core/CoreException.h"

namespace VeraCrypt
{
	// Connects to the helper's privileged Mach service. The connection is
	// returned resumed; the caller owns it and must xpc_connection_cancel() it.
	static xpc_connection_t ConnectToHelper ()
	{
		xpc_connection_t connection = xpc_connection_create_mach_service (
			VC_HELPER_LABEL, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

		if (!connection)
			throw ElevationFailed (SRC_POS, VC_HELPER_LABEL, 1, "xpc_connection_create_mach_service failed");

		// A no-op event handler is mandatory; per-request errors are surfaced
		// synchronously through the reply objects below.
		xpc_connection_set_event_handler (connection, ^(xpc_object_t) { });
		xpc_connection_resume (connection);
		return connection;
	}

	// Returns the version reported by the currently installed helper, or -1 if
	// no helper is installed / reachable.
	static int64_t QueryHelperVersion ()
	{
		xpc_connection_t connection = ConnectToHelper ();

		xpc_object_t message = xpc_dictionary_create (NULL, NULL, 0);
		xpc_dictionary_set_string (message, VC_HELPER_KEY_COMMAND, VC_HELPER_CMD_GET_VERSION);

		xpc_object_t reply = xpc_connection_send_message_with_reply_sync (connection, message);

		int64_t version = -1;
		if (xpc_get_type (reply) == XPC_TYPE_DICTIONARY)
			version = xpc_dictionary_get_int64 (reply, VC_HELPER_KEY_VERSION);

		xpc_connection_cancel (connection);
		return version;
	}

	// Installs (or upgrades) the helper via SMJobBless. This is the call that
	// triggers the native macOS authentication dialog.
	static void BlessHelper ()
	{
		AuthorizationRef authRef = NULL;
		OSStatus status = AuthorizationCreate (NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authRef);
		if (status != errAuthorizationSuccess)
			throw ElevationFailed (SRC_POS, "AuthorizationCreate", status, "");

		AuthorizationItem item = { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
		AuthorizationRights rights = { 1, &item };
		AuthorizationFlags flags = kAuthorizationFlagDefaults
			| kAuthorizationFlagInteractionAllowed
			| kAuthorizationFlagPreAuthorize
			| kAuthorizationFlagExtendRights;

		status = AuthorizationCopyRights (authRef, &rights, kAuthorizationEmptyEnvironment, flags, NULL);
		if (status != errAuthorizationSuccess)
		{
			AuthorizationFree (authRef, kAuthorizationFlagDefaults);
			// errAuthorizationCanceled when the user dismisses the dialog.
			throw ElevationFailed (SRC_POS, "AuthorizationCopyRights", status, "");
		}

		CFErrorRef cfError = NULL;
		Boolean blessed = SMJobBless (kSMDomainSystemLaunchd, CFSTR (VC_HELPER_LABEL), authRef, &cfError);
		AuthorizationFree (authRef, kAuthorizationFlagDefaults);

		if (!blessed)
		{
			long code = cfError ? (long) CFErrorGetCode (cfError) : 0;
			string description = "SMJobBless failed";
			if (cfError)
			{
				CFStringRef desc = CFErrorCopyDescription (cfError);
				if (desc)
				{
					char buffer[512];
					if (CFStringGetCString (desc, buffer, sizeof (buffer), kCFStringEncodingUTF8))
						description = buffer;
					CFRelease (desc);
				}
				CFRelease (cfError);
			}
			throw ElevationFailed (SRC_POS, "SMJobBless", (int) code, description);
		}
	}

	// Installs the helper if it is missing or its version does not match the
	// version this build expects.
	static void EnsureHelperInstalled ()
	{
		if (QueryHelperVersion () == VC_HELPER_VERSION)
			return;

		BlessHelper ();
	}

	int MacOSXConnectElevatedCoreService (const std::string &appPath)
	{
		EnsureHelperInstalled ();

		xpc_connection_t connection = ConnectToHelper ();

		xpc_object_t message = xpc_dictionary_create (NULL, NULL, 0);
		xpc_dictionary_set_string (message, VC_HELPER_KEY_COMMAND, VC_HELPER_CMD_OPEN_CORE_SERVICE);
		xpc_dictionary_set_string (message, VC_HELPER_KEY_APP_PATH, appPath.c_str());
		xpc_dictionary_set_int64 (message, VC_HELPER_KEY_VERSION, VC_HELPER_VERSION);

		xpc_object_t reply = xpc_connection_send_message_with_reply_sync (connection, message);

		if (xpc_get_type (reply) != XPC_TYPE_DICTIONARY)
		{
			xpc_connection_cancel (connection);
			throw ElevationFailed (SRC_POS, VC_HELPER_LABEL, 1, "Privileged helper did not return a valid reply");
		}

		int serviceFD = xpc_dictionary_dup_fd (reply, VC_HELPER_KEY_SERVICE_FD);
		if (serviceFD < 0)
		{
			const char *helperError = xpc_dictionary_get_string (reply, VC_HELPER_KEY_ERROR);
			string description = helperError ? helperError : "Privileged helper refused to open the core service";
			xpc_connection_cancel (connection);
			throw ElevationFailed (SRC_POS, VC_HELPER_LABEL, 1, description);
		}

		xpc_connection_cancel (connection);
		return serviceFD;
	}
}
