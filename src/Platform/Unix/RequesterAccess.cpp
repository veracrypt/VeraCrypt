/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "Platform/File.h"
#include "Platform/ForEach.h"
#include "Core/Unix/UnixUser.h"

namespace VeraCrypt
{
	// Requester access: a FUSE file system mounted by a user without allow_other,
	// such as a GVfs share, denies root even when its owner can open the file. Once
	// root has been denied, a freshly executed copy of VeraCrypt permanently adopts
	// the credentials of the user who requested elevation, opens the file and
	// passes the descriptor back. Root then performs the I/O through the descriptor.
	// Changing the file's attributes again requires the requester's credentials.
	// Like any I/O on the file, this waits for the requester's file system.

	enum RequesterHelperStage
	{
		RequesterHelperStartup = 1,
		RequesterHelperSucceeded,
		RequesterHelperCredentials,
		RequesterHelperOpen,
		RequesterHelperStat,
		RequesterHelperNotRegular,
		RequesterHelperFlags,
		RequesterHelperTimes
	};

	struct RequesterHelperReply
	{
		int32 Stage;
		int32 Error;
		int64 AccessTime;
		int64 ModificationTime;
	};

	// Both ends run the same executable (/proc/self/exe), including after an upgrade.
	// A request opens the file or, once it has been closed, restores its timestamps.
	struct RequesterHelperRequest
	{
		uint32 OpenFile;
		int32 Flags;
		uid_t UserId;
		gid_t GroupId;
		struct timespec Times[2];
		char Path[PATH_MAX];
	};

	static bool ParseRequesterId (const char *value, uint64 invalidId, uint64 &id)
	{
		if (!value || value[0] < '0' || value[0] > '9')
			return false;

		char *end = nullptr;
		errno = 0;
		unsigned long long parsed = strtoull (value, &end, 10);
		if (errno != 0 || !end || *end != '\0' || parsed >= invalidId)
			return false;

		id = parsed;
		return true;
	}

	// The user who requested elevation, as attributed elsewhere in VeraCrypt (sudo,
	// or the trusted doas service). No identity is guessed if it is missing or invalid.
	static bool GetRequesterIdentity (uid_t &userId, gid_t &groupId)
	{
		if (geteuid () != 0)
			return false;

		const char *sudoUserId = getenv ("SUDO_UID");
		const char *sudoGroupId = getenv ("SUDO_GID");
		if (sudoUserId || sudoGroupId)
		{
			uint64 uid, gid;
			if (!ParseRequesterId (sudoUserId, static_cast <uid_t> (-1), uid)
				|| !ParseRequesterId (sudoGroupId, static_cast <gid_t> (-1), gid))
				return false;

			userId = static_cast <uid_t> (uid);
			groupId = static_cast <gid_t> (gid);
		}
		else if (!GetDoasUserIds (&userId, &groupId))
			return false;

		return userId != 0 && userId != static_cast <uid_t> (-1) && groupId != static_cast <gid_t> (-1);
	}

	// Only after exec: even closing an inherited descriptor may block on FUSE.
	static bool CloseRequesterHelperDescriptors (int keep)
	{
		bool closed = false;
#ifdef SYS_close_range
		closed = (keep == 0 || syscall (SYS_close_range, 0U, static_cast <unsigned int> (keep) - 1, 0) == 0)
			&& syscall (SYS_close_range, static_cast <unsigned int> (keep) + 1, ~0U, 0) == 0;
#endif
		if (!closed)
		{
			// This is a fresh, single-threaded process, so directory enumeration is safe.
			// Do not cap descriptor numbers: inherited fds can exceed today's rlimit.
			DIR *directory = opendir ("/proc/self/fd");
			if (!directory)
				return false;
			int error;
			while (true)
			{
				errno = 0;
				struct dirent *entry = readdir (directory);
				if (!entry)
				{
					error = errno;
					break;
				}
				uint64 fd;
				if (ParseRequesterId (entry->d_name, static_cast <uint64> (INT_MAX) + 1, fd)
					&& static_cast <int> (fd) != keep && static_cast <int> (fd) != dirfd (directory))
					close (static_cast <int> (fd));
			}
			closedir (directory);
			errno = error;
			if (error != 0)
				return false;
		}

		// Occupy 0-2, so that the file opened later cannot become one of them.
		for (int fd = 0; fd < 3; ++fd)
		{
			if (fd != keep && open ("/dev/null", O_RDWR) != fd)
				return false;
		}

		return true;
	}

	// Helper process only.
	static bool SetRequesterCredentials (uid_t userId, gid_t groupId)
	{
		// Supplementary groups of the account, not of the caller's session. FUSE only
		// checks the user and group IDs; other file systems may use the groups.
		struct passwd *entry = getpwuid (userId);
		if ((!entry || initgroups (entry->pw_name, groupId) != 0) && setgroups (1, &groupId) != 0)
			return false;

		if (setresgid (groupId, groupId, groupId) != 0 || setresuid (userId, userId, userId) != 0
			|| prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
			return false;

		uid_t realUserId, effectiveUserId, savedUserId;
		gid_t realGroupId, effectiveGroupId, savedGroupId;
		if (getresuid (&realUserId, &effectiveUserId, &savedUserId) != 0
			|| getresgid (&realGroupId, &effectiveGroupId, &savedGroupId) != 0)
			return false;

		// After exec, the change to nonzero IDs cleared all capabilities, unless
		// SECBIT_NO_SETUID_FIXUP kept them: CAP_SETUID would then restore root.
		if (realUserId != userId || effectiveUserId != userId || savedUserId != userId
			|| realGroupId != groupId || effectiveGroupId != groupId || savedGroupId != groupId
			|| setresuid (0, 0, 0) == 0)
		{
			errno = EPERM;
			return false;
		}

		return true;
	}

	// One packet, optionally carrying one descriptor.
	static int SendRequesterHelperData (int socketFd, const void *buffer, size_t length, int descriptor = -1)
	{
		union
		{
			char Buffer[CMSG_SPACE (sizeof (int))];
			struct cmsghdr Alignment;
		} control;
		memset (&control, 0, sizeof (control));
		struct iovec data = { const_cast <void *> (buffer), length };
		struct msghdr message;
		memset (&message, 0, sizeof (message));
		message.msg_iov = &data;
		message.msg_iovlen = 1;
		if (descriptor != -1)
		{
			message.msg_control = control.Buffer;
			message.msg_controllen = sizeof (control.Buffer);
			struct cmsghdr *header = CMSG_FIRSTHDR (&message);
			header->cmsg_level = SOL_SOCKET;
			header->cmsg_type = SCM_RIGHTS;
			header->cmsg_len = CMSG_LEN (sizeof (int));
			memcpy (CMSG_DATA (header), &descriptor, sizeof (descriptor));
		}

		ssize_t size;
		do
		{
			size = sendmsg (socketFd, &message, MSG_NOSIGNAL);
		} while (size == -1 && errno == EINTR);

		if (size == -1)
			return errno;

		return static_cast <size_t> (size) == length ? 0 : EIO;
	}

	// One packet, optionally carrying one descriptor. Own all received fds.
	static int ReceiveRequesterHelperData (int socketFd, void *buffer, size_t length, int *descriptor = nullptr)
	{
		if (descriptor)
			*descriptor = -1;

		union
		{
			char Buffer[CMSG_SPACE (sizeof (int) * 4)];
			struct cmsghdr Alignment;
		} control;
		memset (&control, 0, sizeof (control));

		struct iovec data = { buffer, length };
		struct msghdr message;
		memset (&message, 0, sizeof (message));
		message.msg_iov = &data;
		message.msg_iovlen = 1;
		message.msg_control = control.Buffer;
		message.msg_controllen = sizeof (control.Buffer);

		ssize_t size;
		do
		{
			size = recvmsg (socketFd, &message, MSG_CMSG_CLOEXEC);
		} while (size == -1 && errno == EINTR);

		if (size == -1)
			return errno;

		// Own every received descriptor before validating the packet.
		vector <int> descriptors;
		bool unexpectedControl = false;

		for (struct cmsghdr *header = CMSG_FIRSTHDR (&message); header; header = CMSG_NXTHDR (&message, header))
		{
			if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS && header->cmsg_len >= CMSG_LEN (0))
			{
				size_t count = (header->cmsg_len - CMSG_LEN (0)) / sizeof (int);
				for (size_t i = 0; i < count; ++i)
				{
					int fd;
					memcpy (&fd, CMSG_DATA (header) + i * sizeof (int), sizeof (fd));
					descriptors.push_back (fd);
				}
			}
			else
				unexpectedControl = true;
		}

		if (static_cast <size_t> (size) != length || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || unexpectedControl
			|| descriptors.size() > (descriptor ? 1U : 0U))
		{
			foreach (int fd, descriptors)
				close (fd);

			return EPROTO;
		}

		if (!descriptors.empty())
			*descriptor = descriptors.front();

		return 0;
	}

	// Returns 0 with a validated reply, or the error that prevented one.
	static int ReceiveRequesterHelperReply (int socketFd, bool descriptorExpected, RequesterHelperReply &reply, int &descriptor)
	{
		memset (&reply, 0, sizeof (reply));
		int error = ReceiveRequesterHelperData (socketFd, &reply, sizeof (reply), &descriptor);
		if (error != 0)
			return error;
		bool succeeded = reply.Stage == RequesterHelperSucceeded;
		if (reply.Stage < RequesterHelperSucceeded || reply.Stage > RequesterHelperTimes
			|| (succeeded ? reply.Error != 0 : reply.Error <= 0)
			|| (descriptor != -1) != (succeeded && descriptorExpected))
		{
			if (descriptor != -1)
				close (descriptor);
			descriptor = -1;
			return EPROTO;
		}
		return 0;
	}

	// Helper process only: never returns.
	static void RunRequesterHelper (int socketFd, const RequesterHelperRequest &request)
	{
		RequesterHelperReply reply;
		memset (&reply, 0, sizeof (reply));
		int fd = -1;
		struct stat statData;

		if (!SetRequesterCredentials (request.UserId, request.GroupId))
		{
			reply.Stage = RequesterHelperCredentials;
			reply.Error = errno;
		}
		else if (!request.OpenFile)
		{
			if (utimensat (AT_FDCWD, request.Path, request.Times, 0) == 0)
				reply.Stage = RequesterHelperSucceeded;
			else
			{
				reply.Stage = RequesterHelperTimes;
				reply.Error = errno;
			}
		}
		else if ((fd = open (request.Path, request.Flags | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)) == -1)
		{
			reply.Stage = RequesterHelperOpen;
			reply.Error = errno;
		}
		else if (fstat (fd, &statData) == -1)
		{
			reply.Stage = RequesterHelperStat;
			reply.Error = errno;
		}
		else if (!S_ISREG (statData.st_mode))
		{
			reply.Stage = RequesterHelperNotRegular;
			reply.Error = S_ISDIR (statData.st_mode) ? EISDIR : EINVAL;
		}
		else
		{
			int flags = fcntl (fd, F_GETFL);
			if (flags == -1 || fcntl (fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
			{
				reply.Stage = RequesterHelperFlags;
				reply.Error = errno;
			}
			else
			{
				reply.Stage = RequesterHelperSucceeded;
				reply.AccessTime = statData.st_atime;
				reply.ModificationTime = statData.st_mtime;
			}
		}

		if (reply.Stage != RequesterHelperSucceeded && reply.Error <= 0)
			reply.Error = EIO;

		// Send a descriptor only with a successful opening reply.
		SendRequesterHelperData (socketFd, &reply, sizeof (reply), request.OpenFile && reply.Stage == RequesterHelperSucceeded ? fd : -1);
		_exit (0);
	}

	int File::RunRequesterHelperService (const char *socketDescriptor)
	{
		try
		{
			uint64 parsedFd;
			if (geteuid() != 0 || !ParseRequesterId (socketDescriptor, static_cast <uint64> (INT_MAX) + 1, parsedFd))
				return 1;
			int socketFd = static_cast <int> (parsedFd);
			int socketType;
			socklen_t size = sizeof (socketType);
			struct ucred peer;
			socklen_t peerSize = sizeof (peer);
			// Only root may send requests. Otherwise a user allowed to run 'sudo veracrypt'
			// could pass a socket of their own and obtain files opened as any other user.
			if (getsockopt (socketFd, SOL_SOCKET, SO_TYPE, &socketType, &size) != 0 || socketType != SOCK_SEQPACKET
				|| getsockopt (socketFd, SOL_SOCKET, SO_PEERCRED, &peer, &peerSize) != 0 || peer.uid != 0)
				return 1;

			// Otherwise named after /proc/self/exe, e.g. in ps.
			prctl (PR_SET_NAME, "veracrypt", 0, 0, 0);

			int32 startupError = 0;
			if (fcntl (socketFd, F_SETFD, FD_CLOEXEC) == -1 || !CloseRequesterHelperDescriptors (socketFd))
				startupError = errno;
			if (SendRequesterHelperData (socketFd, &startupError, sizeof (startupError)) != 0 || startupError != 0)
				return 1;

			RequesterHelperRequest request;
			if (ReceiveRequesterHelperData (socketFd, &request, sizeof (request)) != 0
				|| request.OpenFile > 1 || request.UserId == 0 || request.UserId == static_cast <uid_t> (-1)
				|| request.GroupId == static_cast <gid_t> (-1) || !memchr (request.Path, '\0', sizeof (request.Path))
				|| request.Path[0] == '\0'
				|| (request.OpenFile ? ((request.Flags & ~(O_ACCMODE | O_LARGEFILE | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)) != 0
					|| (request.Flags & O_ACCMODE) == O_ACCMODE)
					: request.Flags != 0))
				return 1;

			RunRequesterHelper (socketFd, request);
		}
		catch (...) { }
		return 1;
	}

	// Returns 0 with a validated reply, or the error that prevented one. Startup
	// failures are reported with the RequesterHelperStartup stage.
	static int RunRequesterHelperProcess (const RequesterHelperRequest &request, RequesterHelperReply &reply, int &descriptor)
	{
		descriptor = -1;
		memset (&reply, 0, sizeof (reply));
		reply.Stage = RequesterHelperStartup;

		int sockets[2];
		if (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == -1)
			return errno;

		// Prepare all allocations before fork; only async-signal-safe calls until exec.
		const string socketArgument = to_string (sockets[1]);
		// AppImage's AppRun supplies the library path used to load this executable.
		// Preserve that setting only, not the caller's other environment/loader hooks.
		const char *libraryPath = getenv ("LD_LIBRARY_PATH");
		const string libraryEnvironment = libraryPath ? string ("LD_LIBRARY_PATH=") + libraryPath : string();
		char *helperArgv[] = { const_cast <char *> ("veracrypt"), const_cast <char *> (TC_REQUESTER_HELPER_CMDLINE_OPTION),
			const_cast <char *> (socketArgument.c_str()), nullptr };
		char *helperEnv[] = { libraryEnvironment.empty() ? nullptr : const_cast <char *> (libraryEnvironment.c_str()), nullptr };

		pid_t pid = fork();
		if (pid == -1)
		{
			int error = errno;
			close (sockets[0]);
			close (sockets[1]);
			return error;
		}

		if (pid == 0)
		{
			// No inherited signal handler may run in this copy of the process; the
			// helper keeps the mask. Do not close inherited descriptors or access the
			// backing filesystem here. Existing CLOEXEC flags take effect at exec;
			// the fresh helper closes the rest.
			sigset_t signals;
			sigfillset (&signals);
			if (sigprocmask (SIG_SETMASK, &signals, nullptr) == 0 && fcntl (sockets[1], F_SETFD, 0) != -1)
				execve ("/proc/self/exe", helperArgv, helperEnv);
			// Preserve the startup errno without allocating or blocking before exec.
			int32 startupError = errno;
			while (send (sockets[1], &startupError, sizeof (startupError), MSG_NOSIGNAL | MSG_DONTWAIT) == -1 && errno == EINTR) { }
			_exit (1); // Never fall back to running the helper with inherited secrets.
		}

		close (sockets[1]);
		// Wait for fresh-process readiness before sending the request. Otherwise a
		// failed exec can race the send and obscure its errno with EPIPE or ECONNRESET.
		int32 startupError;
		int result = ReceiveRequesterHelperData (sockets[0], &startupError, sizeof (startupError));
		if (result == 0)
			result = startupError >= 0 ? startupError : EPROTO;
		if (result == 0)
		{
			reply.Stage = 0;
			result = SendRequesterHelperData (sockets[0], &request, sizeof (request));
		}
		if (result == 0)
			result = ReceiveRequesterHelperReply (sockets[0], request.OpenFile != 0, reply, descriptor);

		// Closing the socket first ends any wait of the helper for this process.
		close (sockets[0]);
		while (waitpid (pid, nullptr, 0) == -1 && errno == EINTR) { }
		return result;
	}

	bool File::OpenAsRequester (const FilePath &path, int sysFlags)
	{
		const string pathString (path);
		RequesterHelperRequest request;
		memset (&request, 0, sizeof (request));

		uid_t userId;
		gid_t groupId;
		if (!GetRequesterIdentity (userId, groupId) || pathString.size() >= sizeof (request.Path))
			return false;

		request.OpenFile = 1;
		// Never create or truncate, block on a FIFO or acquire a controlling terminal.
		request.Flags = (sysFlags & ~(O_CREAT | O_EXCL | O_TRUNC)) | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
		request.UserId = userId;
		request.GroupId = groupId;
		memcpy (request.Path, pathString.c_str(), pathString.size());

		RequesterHelperReply reply;
		int descriptor;
		int result = RunRequesterHelperProcess (request, reply, descriptor);

		if (reply.Stage == RequesterHelperStartup)
		{
			stringstream message;
			message << "Cannot start VeraCrypt's requester-access process (/proc/self/exe): ";
			if (result == EPROTO || result == ECONNRESET)
				message << "the process did not report readiness";
			else
				message << strerror (result);
			message << "\n" << pathString;
			throw ExternalException (SRC_POS, StringConverter::ToWide (message.str()));
		}

		// Failures of the helper itself must not look like access-mode errors,
		// which would make mounting fall back to read-only access.
		if (result != 0 || reply.Stage == RequesterHelperCredentials)
		{
			stringstream message;
			message << "Cannot access the file with the credentials of user " << userId << ": "
				<< strerror (result != 0 ? result : reply.Error) << "\n" << pathString;
			throw ExternalException (SRC_POS, StringConverter::ToWide (message.str()));
		}

		if (reply.Stage != RequesterHelperSucceeded)
		{
			errno = reply.Error;

			// The requester's file system cannot open the file for writing in place,
			// e.g. a GVfs backend without edit support. Report it as read-only, so that
			// mounting can fall back to read-only access. ENOTSUP from any other
			// operation remains an error.
			if (reply.Stage == RequesterHelperOpen && (sysFlags & O_ACCMODE) != O_RDONLY
				&& (reply.Error == ENOTSUP || reply.Error == EOPNOTSUPP))
				errno = EROFS;

			throw SystemException (SRC_POS, wstring (path));
		}

		FileHandle = descriptor;
		AccTime = static_cast <time_t> (reply.AccessTime);
		ModTime = static_cast <time_t> (reply.ModificationTime);
		RequesterBacked = true;
		ReleaseOnly = false;
		RequesterUserId = userId;
		RequesterGroupId = groupId;
		return true;
	}

	// Called once the file is closed, so through its path, as for other files.
	void File::RestoreTimestampsAsRequester () const
	{
		const string pathString (Path);
		RequesterHelperRequest request;
		memset (&request, 0, sizeof (request));
		if (pathString.size() >= sizeof (request.Path))
			return;

		request.Times[0].tv_sec = AccTime;
		request.Times[1].tv_sec = ModTime;
		request.UserId = RequesterUserId;
		request.GroupId = RequesterGroupId;
		memcpy (request.Path, pathString.c_str(), pathString.size());

		// Best effort, like restoring the timestamps of other files.
		RequesterHelperReply reply;
		int descriptor;
		RunRequesterHelperProcess (request, reply, descriptor);
	}
}
