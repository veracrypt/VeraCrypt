/*
 Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
 the full text of which is contained in the file License.txt included in
 VeraCrypt binary and source code distribution packages.
*/

// VeraCrypt privileged helper.
//
// A thin, self-contained launchd daemon installed via SMJobBless. It runs as
// root and exposes a single privileged Mach service. Its only job is to:
//
//   1. validate that the connecting client is a genuine, correctly-signed
//      VeraCrypt application (per-connection code-signature check), and
//   2. on request, validate the client-supplied application binary path,
//      then socketpair()/fork()/exec() "<appPath> --core-service" as root,
//      returning one end of the socket pair to the client over XPC.
//
// The exec'd process is the *existing* VeraCrypt core-service entry point
// (CoreService::ProcessElevatedRequests via the "--core-service" command line
// option). The helper never parses or executes privileged requests itself;
// after handing back the socket it goes idle.
//
// The code-signing requirement used for both the peer check and the exec-path
// check is read at runtime from this tool's own embedded Info.plist
// ("SMAuthorizedClients"), which is the single source of truth for the
// authorized client identity (templated with the build's Team ID).

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <Security/Security.h>
#include <ServiceManagement/ServiceManagement.h>
#include <CoreFoundation/CoreFoundation.h>

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <string>

#include "Core/Unix/MacOSX/PrivilegedHelperProtocol.h"

// Not declared in the public XPC headers, but a stable, widely-used SPI that is
// the supported way for a privileged helper to obtain the peer's audit token.
extern "C" void xpc_connection_get_audit_token (xpc_connection_t, audit_token_t *);

// Returns the code-signing requirement that an authorized client (and the
// client-supplied executable) must satisfy. Read from this tool's embedded
// Info.plist "SMAuthorizedClients" array. Caller releases the result.
static SecRequirementRef CopyAuthorizedClientRequirement ()
{
	CFBundleRef bundle = CFBundleGetMainBundle ();
	if (!bundle)
		return NULL;

	CFDictionaryRef info = CFBundleGetInfoDictionary (bundle);
	if (!info)
		return NULL;

	CFArrayRef clients = (CFArrayRef) CFDictionaryGetValue (info, CFSTR ("SMAuthorizedClients"));
	if (!clients || CFGetTypeID (clients) != CFArrayGetTypeID () || CFArrayGetCount (clients) < 1)
		return NULL;

	CFStringRef requirementString = (CFStringRef) CFArrayGetValueAtIndex (clients, 0);
	if (!requirementString || CFGetTypeID (requirementString) != CFStringGetTypeID ())
		return NULL;

	SecRequirementRef requirement = NULL;
	if (SecRequirementCreateWithString (requirementString, kSecCSDefaultFlags, &requirement) != errSecSuccess)
		return NULL;

	return requirement;
}

// Validates the connecting client process against the authorized-client
// requirement using its audit token.
static bool ClientConnectionIsValid (xpc_connection_t connection)
{
	audit_token_t auditToken;
	memset (&auditToken, 0, sizeof (auditToken));
	xpc_connection_get_audit_token (connection, &auditToken);

	CFDataRef tokenData = CFDataCreate (kCFAllocatorDefault, (const UInt8 *) &auditToken, sizeof (auditToken));
	if (!tokenData)
		return false;

	const void *keys[]   = { kSecGuestAttributeAudit };
	const void *values[] = { tokenData };
	CFDictionaryRef attributes = CFDictionaryCreate (kCFAllocatorDefault, keys, values, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease (tokenData);
	if (!attributes)
		return false;

	SecCodeRef code = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes (NULL, attributes, kSecCSDefaultFlags, &code);
	CFRelease (attributes);
	if (status != errSecSuccess || !code)
		return false;

	SecRequirementRef requirement = CopyAuthorizedClientRequirement ();
	if (!requirement)
	{
		CFRelease (code);
		return false;
	}

	status = SecCodeCheckValidity (code, kSecCSDefaultFlags, requirement);

	CFRelease (requirement);
	CFRelease (code);
	return status == errSecSuccess;
}

// Validates that the on-disk executable at "path" satisfies the authorized
// client requirement (defense in depth against directing the helper at an
// attacker-controlled binary).
static bool ExecutablePathIsValid (const char *path)
{
	if (!path || path[0] != '/')
		return false;

	CFURLRef url = CFURLCreateFromFileSystemRepresentation (kCFAllocatorDefault,
		(const UInt8 *) path, (CFIndex) strlen (path), false);
	if (!url)
		return false;

	SecStaticCodeRef staticCode = NULL;
	OSStatus status = SecStaticCodeCreateWithPath (url, kSecCSDefaultFlags, &staticCode);
	CFRelease (url);
	if (status != errSecSuccess || !staticCode)
		return false;

	SecRequirementRef requirement = CopyAuthorizedClientRequirement ();
	if (!requirement)
	{
		CFRelease (staticCode);
		return false;
	}

	status = SecStaticCodeCheckValidity (staticCode, kSecCSDefaultFlags, requirement);

	CFRelease (requirement);
	CFRelease (staticCode);
	return status == errSecSuccess;
}

static gid_t GetAdminGroupId ()
{
	struct group *adminGroup = getgrnam ("admin");
	if (!adminGroup)
		return (gid_t) -1;

	return adminGroup->gr_gid;
}

static bool IsTrustedRootOwnedNode (const struct stat &nodeStat, bool allowAdminGroupWrite)
{
	if (nodeStat.st_uid != 0)
		return false;

	if ((nodeStat.st_mode & S_IWOTH) != 0)
		return false;

	if ((nodeStat.st_mode & S_IWGRP) != 0)
	{
		if (!allowAdminGroupWrite)
			return false;

		gid_t adminGroupId = GetAdminGroupId ();
		if (adminGroupId == (gid_t) -1 || nodeStat.st_gid != adminGroupId)
			return false;
	}

	return true;
}

// The helper cannot fexecve() on macOS, so never launch from a user-writable
// install tree. This limits the remaining path-based exec race to roots/admins,
// who already have equivalent privilege.
static bool ExecutablePathIsInTrustedLocation (const char *path, const struct stat &execStat)
{
	if (!path || path[0] != '/' || !S_ISREG (execStat.st_mode))
		return false;

	if (!IsTrustedRootOwnedNode (execStat, false))
		return false;

	std::string pathString (path);
	const std::string bundleMarker (".app/Contents/MacOS/");
	size_t bundleMarkerPosition = pathString.find (bundleMarker);
	if (bundleMarkerPosition == std::string::npos)
		return false;

	size_t bundleRootEnd = bundleMarkerPosition + 4;
	size_t executableNamePosition = bundleMarkerPosition + bundleMarker.size();
	if (bundleRootEnd == 4 || executableNamePosition >= pathString.size()
		|| pathString.find ('/', executableNamePosition) != std::string::npos)
		return false;

	std::string bundleRoot = pathString.substr (0, bundleRootEnd);
	std::string contentsDirectory = bundleRoot + "/Contents";
	std::string macOSDirectory = contentsDirectory + "/MacOS";

	std::string currentPath ("/");
	struct stat componentStat;

	if (lstat (currentPath.c_str(), &componentStat) != 0
		|| !S_ISDIR (componentStat.st_mode)
		|| !IsTrustedRootOwnedNode (componentStat, true))
		return false;

	size_t position = 1;
	while (position < pathString.size())
	{
		size_t nextSlash = pathString.find ('/', position);
		std::string component = pathString.substr (position, nextSlash == std::string::npos ? std::string::npos : nextSlash - position);

		if (component.empty())
		{
			position = nextSlash == std::string::npos ? pathString.size() : nextSlash + 1;
			continue;
		}

		if (component == "." || component == "..")
			return false;

		if (currentPath.size() > 1)
			currentPath += "/";
		currentPath += component;

		if (lstat (currentPath.c_str(), &componentStat) != 0)
			return false;

		bool isFinalComponent = nextSlash == std::string::npos;
		if (isFinalComponent)
		{
			return S_ISREG (componentStat.st_mode)
				&& componentStat.st_dev == execStat.st_dev
				&& componentStat.st_ino == execStat.st_ino
				&& IsTrustedRootOwnedNode (componentStat, false);
		}

		bool isBundleCriticalDirectory = currentPath == bundleRoot
			|| currentPath == contentsDirectory
			|| currentPath == macOSDirectory
			|| (currentPath.size() > bundleRoot.size()
				&& currentPath.compare (0, bundleRoot.size(), bundleRoot) == 0
				&& currentPath[bundleRoot.size()] == '/');

		if (!S_ISDIR (componentStat.st_mode) || !IsTrustedRootOwnedNode (componentStat, !isBundleCriticalDirectory))
			return false;

		position = nextSlash + 1;
	}

	return false;
}

static void SendError (xpc_connection_t peer, xpc_object_t request, const char *message)
{
	xpc_object_t reply = xpc_dictionary_create_reply (request);
	if (!reply)
		return;
	xpc_dictionary_set_string (reply, VC_HELPER_KEY_ERROR, message);
	xpc_connection_send_message (peer, reply);
}

// Spawns "<appPath> --core-service" as root with both stdin and stdout wired to
// one end of a socket pair, and returns the other end to the client.
//
// The binary is opened first (pinning a specific inode), then validated, and is
// executed only if the path still resolves to that exact inode -- the inode
// check runs in the child immediately before execv(). macOS has no fexecve()
// (and exec via /dev/fd is rejected), so the file cannot be executed straight
// from the descriptor; pinning the inode shrinks the check-to-exec window to a
// few instructions. The mandatory code-signature requirement remains the primary
// guarantee: an attacker cannot substitute a binary that passes it.
static void HandleOpenCoreService (xpc_connection_t peer, xpc_object_t request)
{
	const char *appPath = xpc_dictionary_get_string (request, VC_HELPER_KEY_APP_PATH);
	if (!appPath || appPath[0] != '/')
	{
		SendError (peer, request, "Invalid application path");
		return;
	}

	// O_NOFOLLOW: never traverse a symlink as the final path component. The
	// descriptor pins the inode that is validated and re-checked below.
	int execFd = open (appPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (execFd == -1)
	{
		SendError (peer, request, "Cannot open application binary");
		return;
	}

	struct stat execStat;
	if (fstat (execFd, &execStat) != 0 || !S_ISREG (execStat.st_mode))
	{
		close (execFd);
		SendError (peer, request, "Application binary is not a regular file");
		return;
	}

	if (!ExecutablePathIsInTrustedLocation (appPath, execStat))
	{
		close (execFd);
		SendError (peer, request, "Application binary is not in a trusted install location");
		return;
	}

	if (!ExecutablePathIsValid (appPath))
	{
		close (execFd);
		SendError (peer, request, "Application binary failed code-signature validation");
		return;
	}

	int sockets[2];
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
	{
		close (execFd);
		SendError (peer, request, "socketpair() failed");
		return;
	}

	pid_t pid = fork ();
	if (pid < 0)
	{
		close (execFd);
		close (sockets[0]);
		close (sockets[1]);
		SendError (peer, request, "fork() failed");
		return;
	}

	if (pid == 0)
	{
		// Child: become the VeraCrypt core service. Its STDIN/STDOUT speak the
		// existing CoreServiceRequest/Response protocol over the socket pair.
		dup2 (sockets[1], STDIN_FILENO);
		dup2 (sockets[1], STDOUT_FILENO);

		int devNull = open ("/dev/null", O_WRONLY);
		if (devNull != -1)
		{
			dup2 (devNull, STDERR_FILENO);
			if (devNull > STDERR_FILENO)
				close (devNull);
		}

		close (sockets[0]);
		if (sockets[1] > STDOUT_FILENO)
			close (sockets[1]);

		// Final TOCTOU guard, as late as possible before exec: only proceed if
		// the path still resolves to the exact inode that was opened (execFd,
		// still held open) and validated above.
		struct stat nowStat;
		if (stat (appPath, &nowStat) != 0
			|| nowStat.st_dev != execStat.st_dev
			|| nowStat.st_ino != execStat.st_ino)
			_exit (126);

		char *const argv[] = { (char *) appPath, (char *) "--core-service", (char *) NULL };
		execv (appPath, argv);
		_exit (127);
	}

	// Parent (helper): hand the client its end of the socket pair.
	close (execFd);
	close (sockets[1]);

	xpc_object_t reply = xpc_dictionary_create_reply (request);
	if (reply)
	{
		xpc_dictionary_set_fd (reply, VC_HELPER_KEY_SERVICE_FD, sockets[0]);
		xpc_connection_send_message (peer, reply);
	}
	close (sockets[0]);
}

static void HandleGetVersion (xpc_connection_t peer, xpc_object_t request)
{
	xpc_object_t reply = xpc_dictionary_create_reply (request);
	if (!reply)
		return;
	xpc_dictionary_set_int64 (reply, VC_HELPER_KEY_VERSION, VC_HELPER_VERSION);
	xpc_connection_send_message (peer, reply);
}

static void HandleUninstall (xpc_connection_t peer, xpc_object_t request)
{
	CFErrorRef cfError = NULL;
	SMJobRemove (kSMDomainSystemLaunchd, CFSTR (VC_HELPER_LABEL), NULL, true, &cfError);
	if (cfError)
		CFRelease (cfError);

	unlink (VC_HELPER_PLIST_PATH);
	unlink (VC_HELPER_TOOL_PATH);

	xpc_object_t reply = xpc_dictionary_create_reply (request);
	if (reply)
	{
		xpc_dictionary_set_int64 (reply, VC_HELPER_KEY_VERSION, VC_HELPER_VERSION);
		xpc_connection_send_message (peer, reply);
	}

	// The launchd job and tool are gone; exit cleanly.
	exit (0);
}

static void HandleMessage (xpc_connection_t peer, xpc_object_t event)
{
	if (xpc_get_type (event) != XPC_TYPE_DICTIONARY)
		return;

	// Every privileged operation is gated on a per-connection code-signature
	// check of the calling process.
	if (!ClientConnectionIsValid (peer))
	{
		SendError (peer, event, "Client failed code-signature validation");
		return;
	}

	const char *command = xpc_dictionary_get_string (event, VC_HELPER_KEY_COMMAND);
	if (!command)
		return;

	if (strcmp (command, VC_HELPER_CMD_OPEN_CORE_SERVICE) == 0)
		HandleOpenCoreService (peer, event);
	else if (strcmp (command, VC_HELPER_CMD_GET_VERSION) == 0)
		HandleGetVersion (peer, event);
	else if (strcmp (command, VC_HELPER_CMD_UNINSTALL) == 0)
		HandleUninstall (peer, event);
}

int main (int /*argc*/, const char * /*argv*/ [])
{
	// Reap exec'd core-service children automatically (we never wait on them).
	signal (SIGCHLD, SIG_IGN);

	xpc_connection_t listener = xpc_connection_create_mach_service (
		VC_HELPER_LABEL, dispatch_get_main_queue (), XPC_CONNECTION_MACH_SERVICE_LISTENER);

	xpc_connection_set_event_handler (listener, ^(xpc_object_t peerEvent)
	{
		if (xpc_get_type (peerEvent) != XPC_TYPE_CONNECTION)
			return;

		xpc_connection_t peer = (xpc_connection_t) peerEvent;
		xpc_connection_set_event_handler (peer, ^(xpc_object_t message)
		{
			HandleMessage (peer, message);
		});
		xpc_connection_resume (peer);
	});

	xpc_connection_resume (listener);
	dispatch_main ();
	return 0;
}
