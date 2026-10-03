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

#ifdef TC_OPENBSD
# define FUSE_USE_VERSION 26
#else
# ifndef VC_FUSE_VERSION
#  define VC_FUSE_VERSION 2
# endif
# if VC_FUSE_VERSION < 3
#  define FUSE_USE_VERSION 25
# else
#  define FUSE_USE_VERSION 301
#  define VC_FUSE3 1
# endif
#endif


#ifdef VC_FUSE3
#define VC_FUSE_FILL_DIR(filler, buf, name, st, off) filler(buf, name, st, off, (enum fuse_fill_dir_flags)0)
#else
#define VC_FUSE_FILL_DIR(filler, buf, name, st, off) filler(buf, name, st, off)
#endif

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "FuseService.h"
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
#include <chrono>
#include <fuse_lowlevel.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#undef fuse_unmount
#ifdef ERR_SUCCESS
#undef ERR_SUCCESS
#endif
#endif
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"
#include "Platform/Unix/Pipe.h"
#include "Platform/Unix/Poller.h"
#include "Core/Unix/UnixUser.h"
#include "Volume/EncryptionThreadPool.h"
#include "Core/Core.h"

namespace VeraCrypt
{
	static const ino_t VC_FUSE_INODE_ROOT = 1;
	static const ino_t VC_FUSE_INODE_VOLUME = 2;
	static const ino_t VC_FUSE_INODE_CONTROL = 3;
	static const ino_t VC_FUSE_INODE_AUX_DEVICE_INFO = 4;
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
	static const ino_t VC_FUSE_INODE_SHUTDOWN = 5;
	static const ino_t VC_FUSE_INODE_SHUTDOWN_SOCKET = 6;
	static string FuseServiceShutdownDirectory;
	static const char *VC_FUSE_SHUTDOWN_DIRECTORY_PREFIX = "/private/tmp/.veracrypt-shutdown-";
	static const uint64 VC_FUSE_SHUTDOWN_VERSION = 3;
	static const uint64 VC_FUSE_SHUTDOWN_PROBE = 0;
	static const uint64 VC_FUSE_SHUTDOWN_DISMOUNT = 1;
	static const uint64 VC_FUSE_SHUTDOWN_FORCE = 1;
#endif
	static const uint64 VC_FUSE_BLOCK_SIZE = 4096;
	static const uint64 VC_FUSE_METADATA_SIZE = 64 * 1024;
	static const uint64 VC_FUSE_STAT_BLOCK_SIZE = 512;

	static uint64 fuse_service_ceil_div (uint64 value, uint64 divisor)
	{
		return (value / divisor) + ((value % divisor) ? 1 : 0);
	}

	static void fuse_service_set_stat_blocks (struct stat *statData)
	{
		statData->st_blksize = VC_FUSE_BLOCK_SIZE;
		statData->st_blocks = fuse_service_ceil_div ((uint64) statData->st_size, VC_FUSE_STAT_BLOCK_SIZE);
	}

	static shared_ptr <Buffer> fuse_service_get_control_info (struct fuse_file_info *fi)
	{
		if (fi && fi->fh)
			return *reinterpret_cast <shared_ptr <Buffer> *> (fi->fh);

		return FuseService::GetVolumeInfo();
	}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
	static string fuse_service_get_shutdown_identity ()
	{
		stringstream identity;
		identity << getpid() << " " << FuseService::GetSerialInstanceNumber() << " " << FuseService::GetSlotNumber() << "\n";
		return identity.str();
	}

	static bool fuse_service_parse_shutdown_identity (const string &identity, pid_t &processId, uint64 &serialInstanceNumber, VolumeSlotNumber &slotNumber)
	{
		long long parsedProcessId;
		uint64 parsedSerialInstanceNumber;
		VolumeSlotNumber parsedSlotNumber;
		stringstream parser (identity);

		if (!(parser >> parsedProcessId >> parsedSerialInstanceNumber >> parsedSlotNumber))
			return false;

		parser >> ws;
		if (!parser.eof() || parsedProcessId <= 1 || static_cast <pid_t> (parsedProcessId) != parsedProcessId)
			return false;

		processId = static_cast <pid_t> (parsedProcessId);
		serialInstanceNumber = parsedSerialInstanceNumber;
		slotNumber = parsedSlotNumber;
		return true;
	}

	static sockaddr_un fuse_service_shutdown_address (const string &directory)
	{
		string path = directory + "/socket";
		sockaddr_un address;
		Memory::Zero (&address, sizeof (address));
		if (path.size() >= sizeof (address.sun_path))
			throw ParameterIncorrect (SRC_POS);
		address.sun_family = AF_UNIX;
		address.sun_len = sizeof (address);
		memcpy (address.sun_path, path.c_str(), path.size() + 1);
		return address;
	}

	static void fuse_service_configure_socket (int fd)
	{
		throw_sys_if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1);
		throw_sys_if (fcntl (fd, F_SETFL, O_NONBLOCK) == -1);
		int enabled = 1;
		throw_sys_if (setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof (enabled)) == -1);
	}

	typedef chrono::steady_clock FuseServiceClock;

	static int fuse_service_remaining_time (const FuseServiceClock::time_point &deadline)
	{
		long long remaining = chrono::duration_cast <chrono::milliseconds> (deadline - FuseServiceClock::now()).count();
		if (remaining <= 0)
			throw TimeOut (SRC_POS);
		return static_cast <int> (remaining);
	}

	static bool fuse_service_socket_wait (int fd, short events, int stopFd, int timeOut)
	{
		const FuseServiceClock::time_point deadline = FuseServiceClock::now() + chrono::milliseconds (timeOut);
		pollfd descriptors[2] = { { fd, events, 0 }, { stopFd, POLLIN, 0 } };
		int result;
		do { result = poll (descriptors, stopFd == -1 ? 1 : 2, fuse_service_remaining_time (deadline)); } while (result == -1 && errno == EINTR);
		throw_sys_if (result == -1);
		if (result == 0)
			throw TimeOut (SRC_POS);
		return descriptors[1].revents == 0;
	}

	static bool fuse_service_socket_transfer (int fd, void *buffer, size_t size, bool sending, int stopFd = -1, int timeOut = 10000)
	{
		const FuseServiceClock::time_point deadline = FuseServiceClock::now() + chrono::milliseconds (timeOut);
		uint8 *position = static_cast <uint8 *> (buffer);
		while (size > 0)
		{
			if (!fuse_service_socket_wait (fd, sending ? POLLOUT : POLLIN, stopFd, fuse_service_remaining_time (deadline)))
				return false;
			ssize_t transferred = sending ? send (fd, position, size, 0) : recv (fd, position, size, 0);
			if (transferred == -1 && (errno == EINTR || errno == EAGAIN))
				continue;
			throw_sys_if (transferred == -1);
			if (transferred == 0)
				return false;
			position += transferred;
			size -= transferred;
		}
		return true;
	}

	static void fuse_service_unmount (struct fuse *fuseHandle)
	{
		struct fuse_session *session = fuse_get_session (fuseHandle);
		struct fuse_chan *channel = session ? fuse_session_next_chan (session, NULL) : NULL;
		if (channel)
			fuse_unmount (NULL, channel);
	}

	static bool fuse_service_find_mount (const char *mountPoint, fsid_t &mountId)
	{
		int count = getfsstat (NULL, 0, MNT_NOWAIT);
		throw_sys_if (count == -1);
		for (;;)
		{
			vector <struct statfs> mounts (count + 1);
			count = getfsstat (&mounts[0], mounts.size() * sizeof (mounts[0]), MNT_NOWAIT);
			throw_sys_if (count == -1);
			if (static_cast <size_t> (count) >= mounts.size())
				continue;
			for (int i = 0; i < count; ++i)
				if (strcmp (mounts[i].f_mntonname, mountPoint) == 0)
				{
					mountId = mounts[i].f_fsid;
					return true;
				}
			return false;
		}
	}

	static bool fuse_service_same_mount (const fsid_t &left, const fsid_t &right)
	{
		return left.val[0] == right.val[0] && left.val[1] == right.val[1];
	}

	class FuseServiceShutdownContext
	{
	public:
		FuseServiceShutdownContext (struct fuse *fuseHandle, const char *mountPoint, int &startupFd)
			: FuseHandle (fuseHandle), MountPoint (mountPoint), StartupFd (startupFd), ListenFd (-1), DirectoryFd (-1), DirectoryCreated (false),
			ThreadStarted (false), Unmounted (false), MountSeen (false), StartupReported (false), StartupAborted (false) { }

		~FuseServiceShutdownContext () noexcept
		{
			if (ThreadStarted)
			{
				uint8 stop = 0;
				while (write (StopPipe->PeekWriteFD(), &stop, sizeof (stop)) == -1 && errno == EINTR) { }
				try { ShutdownThread.Join(); }
				catch (...)
				{
					// Destroying a context still used by the worker is unsafe. Join
					// failures are fatal, but must not unwind a noexcept destructor.
					SystemLog::WriteError ("Cannot join VeraCrypt FUSE shutdown worker");
					_exit (1);
				}
			}
			if (!Unmounted)
				fuse_service_unmount (FuseHandle);
			if (ListenFd != -1)
				close (ListenFd);
			if (DirectoryCreated)
			{
				// The mounting user may rename the directory of an elevated service.
				// Keep cleanup relative to the original directory, without following links.
				if (DirectoryFd != -1)
				{
					unlinkat (DirectoryFd, "socket", 0);
					close (DirectoryFd);
				}
				rmdir (Directory.c_str());
			}
		}

		void Start ()
		{
			string directoryTemplate = string (VC_FUSE_SHUTDOWN_DIRECTORY_PREFIX) + "XXXXXXXXXXXX";
			vector <char> directory (directoryTemplate.begin(), directoryTemplate.end());
			directory.push_back ('\0');
			throw_sys_if (mkdtemp (&directory[0]) == NULL);
			Directory = &directory[0];
			DirectoryCreated = true;
			FuseServiceShutdownDirectory = Directory;
			DirectoryFd = open (Directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			throw_sys_if (DirectoryFd == -1);
			ListenFd = socket (AF_UNIX, SOCK_STREAM, 0);
			throw_sys_if (ListenFd == -1);
			fuse_service_configure_socket (ListenFd);
			sockaddr_un address = fuse_service_shutdown_address (Directory);
			throw_sys_if (::bind (ListenFd, reinterpret_cast <sockaddr *> (&address), sizeof (address)) == -1);
			throw_sys_if (chmod (address.sun_path, 0600) == -1);
			if (geteuid() == 0)
			{
				throw_sys_if (chown (address.sun_path, FuseService::GetUserId(), FuseService::GetGroupId()) == -1);
				throw_sys_if (chown (Directory.c_str(), FuseService::GetUserId(), FuseService::GetGroupId()) == -1);
			}
			throw_sys_if (listen (ListenFd, 32) == -1);
			StopPipe.reset (new Pipe);
			throw_sys_if (fcntl (StopPipe->PeekReadFD(), F_SETFD, FD_CLOEXEC) == -1);
			throw_sys_if (fcntl (StopPipe->PeekWriteFD(), F_SETFD, FD_CLOEXEC) == -1);
			ShutdownThread.Start (Run, this);
			ThreadStarted = true;
		}

	private:
		static TC_THREAD_PROC Run (void *argument)
		{
			FuseServiceShutdownContext &context = *static_cast <FuseServiceShutdownContext *> (argument);
			for (;;)
			{
				try { context.Serve(); return 0; }
				catch (exception &e) { SystemLog::WriteException (e); }
				catch (...) { SystemLog::WriteException (UnknownException (SRC_POS)); }
				// Transient accept/getfsstat failures must not leave an apparently
				// live endpoint with no worker. Back off, remaining interruptible.
				pollfd stop = { context.StopPipe->PeekReadFD(), POLLIN, 0 };
				int result;
				do { result = poll (&stop, 1, 1000); } while (result == -1 && errno == EINTR);
				if (result > 0)
					return 0;
			}
		}

		bool MountPresent ()
		{
			fsid_t current;
			if (!fuse_service_find_mount (MountPoint, current))
				return false;
			if (!MountSeen)
			{
				MountId = current;
				MountSeen = true;
			}
			return fuse_service_same_mount (MountId, current);
		}

		bool StartupCancelled ()
		{
			if (StartupFd == -1)
				return false;
			if (StartupAborted)
				return true;
			pollfd descriptor = { StartupFd, POLLIN, 0 };
			int result = poll (&descriptor, 1, 0);
			if (result == 0 || (result == -1 && errno == EINTR))
				return false;
			uint8 commit = 0;
			ssize_t size = result > 0 ? recv (StartupFd, &commit, sizeof (commit), 0) : -1;
			if (size == -1 && (errno == EINTR || errno == EAGAIN))
				return false;
			if (size == sizeof (commit) && commit == 1)
			{
				close (StartupFd);
				StartupFd = -1;
				return false;
			}
			// EOF, a broken channel, or anything other than commit means that
			// the mounting caller failed or exited before accepting this service.
			StartupAborted = true;
			return true;
		}

		void Serve ()
		{
			int stopFd = StopPipe->PeekReadFD();
			if (!StartupReported)
			{
				StartupReported = true;
				pid_t processId = getpid();
				fuse_service_socket_transfer (StartupFd, &processId, sizeof (processId), true, stopFd);
			}
			for (;;)
			{
				bool present = MountPresent();
				if (StartupCancelled() && (!present || FuseServiceClock::now() >= NextRollbackAttempt))
				{
					// No disk image has been attached yet. Roll back independently
					// of SMB metadata and the public shutdown socket, while FUSE
					// can still answer the auxiliary filesystem's final requests.
					int error = present && unmount (MountPoint, MNT_FORCE) != 0 ? errno : 0;
					if ((error == EINVAL || error == ENOENT) && !MountPresent())
						error = 0;
					if (error == 0)
					{
						FinishDismount();
						return;
					}
					// Retry without starving the public endpoint. Probes still validate
					// this instance; dismount requests can retry and report the error.
					NextRollbackAttempt = FuseServiceClock::now() + chrono::seconds (1);
				}
				// All clients (including released clients and Finder) can remove
				// SMB without notifying us. Initial absence is not a dismount.
				if (!present && MountSeen)
				{
					FinishDismount();
					return;
				}
				try
				{
					if (!fuse_service_socket_wait (ListenFd, POLLIN, stopFd, 1000))
						return;
				}
				catch (TimeOut&) { continue; }

				int fd = accept (ListenFd, NULL, NULL);
				if (fd == -1 && (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED))
					continue;
				if (fd == -1 && (errno == EBADF || errno == EINVAL || errno == ENOTSOCK))
				{
					// Retire a broken listener, but keep watching for external
					// unmount. Do not advertise an endpoint that cannot answer.
					close (ListenFd);
					ListenFd = -1;
					unlinkat (DirectoryFd, "socket", 0);
				}
				throw_sys_if (fd == -1);
				finally_do_arg (int, fd, { close (finally_arg); });
				bool dismounted = false;
				try
				{
					fuse_service_configure_socket (fd);
					uid_t uid;
					gid_t gid;
					throw_sys_if (getpeereid (fd, &uid, &gid) == -1);
					if (uid != 0 && uid != FuseService::GetUserId())
						continue;

					// One fixed native-endian frame: version, command, PID, serial,
					// slot, flags, and the two words of the auxiliary filesystem ID.
					// A partial request has an absolute deadline, so it cannot keep
					// the mount watcher occupied indefinitely.
					uint64 request[8];
					if (!fuse_service_socket_transfer (fd, request, sizeof (request), false, stopFd, 1000))
						continue;
					bool probe = request[1] == VC_FUSE_SHUTDOWN_PROBE;
					int32 error = EINVAL;
					if (request[0] != VC_FUSE_SHUTDOWN_VERSION)
						error = EPROTONOSUPPORT;
					else if ((probe || request[1] == VC_FUSE_SHUTDOWN_DISMOUNT)
						&& request[2] == static_cast <uint64> (getpid())
						&& request[3] == FuseService::GetSerialInstanceNumber()
						&& request[4] == FuseService::GetSlotNumber()
						&& (request[5] & ~VC_FUSE_SHUTDOWN_FORCE) == 0)
					{
						bool present = MountPresent();
						if (!MountSeen)
							error = EAGAIN;
						else if (request[6] != static_cast <uint32> (MountId.val[0])
							|| request[7] != static_cast <uint32> (MountId.val[1]))
							error = ESTALE;
						else
						{
							error = 0;
							// Keep FUSE answering flush/close requests until unmount
							// finishes. Never act on a replacement at the same path.
							for (int attempt = 0; !probe && present; ++attempt)
							{
								error = unmount (MountPoint, (StartupAborted || (request[5] & VC_FUSE_SHUTDOWN_FORCE)) ? MNT_FORCE : 0) == 0 ? 0 : errno;
								if ((error == EINVAL || error == ENOENT) && !MountPresent())
									error = 0;
								if (error != EBUSY || StartupAborted || attempt == 10)
									break;
								Thread::Sleep (200);
								present = MountPresent();
								if (!present)
									error = 0;
							}
							dismounted = !probe && error == 0;
						}
					}
					// Reply independently of the stop pipe: successful unmount can
					// make the FUSE loop exit before the caller receives its result.
					fuse_service_socket_transfer (fd, &error, sizeof (error), true, -1, 1000);
				}
				catch (TimeOut&) { }
				catch (exception &e) { SystemLog::WriteException (e); }
				catch (...) { SystemLog::WriteException (UnknownException (SRC_POS)); }

				if (dismounted)
				{
					FinishDismount();
					return;
				}
			}
		}

		void FinishDismount ()
		{
			fuse_exit (FuseHandle);
			fuse_service_unmount (FuseHandle);
			Unmounted = true;
		}

		struct fuse *FuseHandle;
		const char *MountPoint;
		int &StartupFd;
		string Directory;
		int ListenFd;
		int DirectoryFd;
		bool DirectoryCreated;
		bool ThreadStarted;
		bool Unmounted;
		bool MountSeen;
		bool StartupReported;
		bool StartupAborted;
		FuseServiceClock::time_point NextRollbackAttempt;
		fsid_t MountId;
		unique_ptr <Pipe> StopPipe;
		Thread ShutdownThread;
	};

	// Hold the original parent across mounting and teardown, then check the
	// directory's identity before removing it. Never follow a replacement symlink.
	class FuseServiceAuxDirectory
	{
	public:
		explicit FuseServiceAuxDirectory (const string &path) : ParentFd (-1)
		{
			char *canonicalPath = realpath (path.c_str(), NULL);
			throw_sys_if (canonicalPath == NULL);
			finally_do_arg (char *, canonicalPath, { free (finally_arg); });
			Path = canonicalPath;
			size_t separator = path.find_last_of ('/');
			if (separator == string::npos || separator + 1 == path.size())
				throw ParameterIncorrect (SRC_POS);
			Name = path.substr (separator + 1);
			ParentFd = open ((separator == 0 ? "/" : path.substr (0, separator)).c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			throw_sys_if (ParentFd == -1);
			if (fstatat (ParentFd, Name.c_str(), &Original, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR (Original.st_mode))
			{
				close (ParentFd);
				ParentFd = -1;
				throw ParameterIncorrect (SRC_POS);
			}
		}

		~FuseServiceAuxDirectory ()
		{
			try
			{
				fsid_t mountId;
				// Do not enter an auxiliary filesystem that may no longer be
				// served. Its absence is checked without querying the mount itself.
				if (!fuse_service_find_mount (Path.c_str(), mountId))
				{
					struct stat current;
					int status = fstatat (ParentFd, Name.c_str(), &current, AT_SYMLINK_NOFOLLOW);
					if ((status == -1 && errno == ENOENT)
						|| (status == 0 && S_ISDIR (current.st_mode) && current.st_dev == Original.st_dev && current.st_ino == Original.st_ino
							&& unlinkat (ParentFd, Name.c_str(), AT_REMOVEDIR) == 0))
						FuseService::RemoveAuxMountParent (Path, ParentFd);
				}
			}
			catch (...) { }
			close (ParentFd);
		}

	private:
		int ParentFd;
		string Name;
		string Path;
		struct stat Original;
	};

	void FuseService::RemoveAuxMountParent (const string &fuseMountPoint, int parentFd)
	{
		const string parent = fuseMountPoint.substr (0, fuseMountPoint.find_last_of ('/'));
		const string name = parent.substr (parent.find_last_of ('/') + 1);
		const string prefix = name.find (".veracrypt_aux_root_") == 0 ? ".veracrypt_aux_root_" : ".veracrypt_aux_";
		const size_t separator = name.find ('-', prefix.size());
		// Only the per-mount format belongs to us. Legacy parents may be a
		// shared per-user directory or an arbitrary caller-selected TMPDIR.
		if (name.compare (0, prefix.size(), prefix) != 0 || separator == string::npos
			|| separator == prefix.size() || name.size() - separator - 1 != 12
			|| name.substr (prefix.size(), separator - prefix.size()).find_first_not_of ("0123456789") != string::npos
			|| name.substr (separator + 1).find_first_not_of ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != string::npos)
			return;
		struct stat current, original;
		if (lstat (parent.c_str(), &current) != 0 || !S_ISDIR (current.st_mode) || current.st_uid != geteuid())
			return;
		if (parentFd != -1 && (fstat (parentFd, &original) != 0
			|| current.st_dev != original.st_dev || current.st_ino != original.st_ino))
			return;
		rmdir (parent.c_str());
	}

	static int fuse_service_main (int argc, char *argv[], const struct fuse_operations *operations, int startupFd)
	{
		// On rollback, EOF must only reach the caller after fuse_destroy has
		// closed the volume. The worker closes this early only after commit.
		finally_do_arg (int *, &startupFd, { if (*finally_arg != -1) close (*finally_arg); });
		if (argc < 2)
			throw ParameterIncorrect (SRC_POS);
		FuseServiceAuxDirectory auxiliaryDirectory (argv[1]);
		// FUSE-T execs its backend during setup. This child no longer needs any
		// inherited descriptors across exec, including helper pipes and /dev/null.
		const int descriptorLimit = getdtablesize();
		for (int fd = 3; fd < descriptorLimit; ++fd)
		{
			int flags = fcntl (fd, F_GETFD);
			if (flags == -1 && errno == EBADF)
				continue;
			throw_sys_if (flags == -1 || fcntl (fd, F_SETFD, flags | FD_CLOEXEC) == -1);
		}
		char *mountPoint = NULL;
		int multithreaded = 0;
		struct fuse *fuseHandle = fuse_setup (argc, argv, operations, sizeof (*operations),
			&mountPoint, &multithreaded, NULL);
		if (!fuseHandle)
			return 1;

		int result = -1;
		try
		{
			FuseServiceShutdownContext shutdown (fuseHandle, mountPoint, startupFd);
			shutdown.Start();
			result = multithreaded ? fuse_loop_mt (fuseHandle) : fuse_loop (fuseHandle);
			// The context wakes and joins the socket worker before destroying the
			// FUSE handle, including when the loop exits without a shutdown request.
		}
		catch (exception &e) { SystemLog::WriteException (e); }
		catch (...) { SystemLog::WriteException (UnknownException (SRC_POS)); }

		// Do not call fuse_teardown: the channel has already been unmounted.
		fuse_remove_signal_handlers (fuse_get_session (fuseHandle));
		fuse_destroy (fuseHandle);
		free (mountPoint);

		return result == -1 ? 1 : 0;
	}
#endif

	static int fuse_service_fill_dir_entry (void *buf, fuse_fill_dir_t filler, const char *name, mode_t mode, ino_t ino, off_t nextOff)
	{
		struct stat st;
		Memory::Zero (&st, sizeof (st));
		st.st_mode = mode;
		st.st_nlink = S_ISDIR (mode) ? 2 : 1;
		st.st_uid = FuseService::GetUserId();
		st.st_gid = FuseService::GetGroupId();
		st.st_ino = ino;
		fuse_service_set_stat_blocks (&st);

		return VC_FUSE_FILL_DIR (filler, buf, name, &st, nextOff);
	}

	static int fuse_service_access (const char *path, int mask)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static void *fuse_service_init_common ()
	{
		try
		{
			// Termination signals are handled by a separate process to allow clean dismount on shutdown
			struct sigaction action;
			Memory::Zero (&action, sizeof (action));
			action.sa_handler = SIG_IGN;

			sigaction (SIGINT, &action, nullptr);
			sigaction (SIGQUIT, &action, nullptr);
			sigaction (SIGTERM, &action, nullptr);

			if (!EncryptionThreadPool::IsRunning())
				EncryptionThreadPool::Start();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}

		return nullptr;
	}

#if defined(VC_FUSE3)
	static void *fuse_service_init (struct fuse_conn_info *conn, struct fuse_config *cfg)
	{
		if (cfg)
		{
			cfg->set_uid = 1;
			cfg->set_gid = 1;
			cfg->uid = FuseService::GetUserId();
			cfg->gid = FuseService::GetGroupId();

			cfg->use_ino = 1;
		}

		return fuse_service_init_common ();
	}
#elif defined(TC_OPENBSD) || (FUSE_USE_VERSION >= 26)
	static void *fuse_service_init (struct fuse_conn_info *conn)
	{
		(void) conn;
		return fuse_service_init_common ();
	}
#else
	static void *fuse_service_init ()
	{
		return fuse_service_init_common ();
	}
#endif

	static void fuse_service_destroy (void *userdata)
	{
		try
		{
			FuseService::Dismount();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}
	}

	static int fuse_service_getattr_impl (const char *path, struct stat *statData)
	{
		try
		{
			Memory::Zero (statData, sizeof(*statData));

			statData->st_uid = FuseService::GetUserId();
			statData->st_gid = FuseService::GetGroupId();
			statData->st_atime = time (NULL);
			statData->st_ctime = time (NULL);
			statData->st_mtime = time (NULL);
			statData->st_blksize = VC_FUSE_BLOCK_SIZE;

			if (strcmp (path, "/") == 0)
			{
				statData->st_mode = S_IFDIR | 0500;
				statData->st_nlink = 2;
				statData->st_ino = VC_FUSE_INODE_ROOT;
			}
			else
			{
				if (!FuseService::CheckAccessRights())
					return -EACCES;

				if (strcmp (path, FuseService::GetAuxDeviceInfoPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = VC_FUSE_METADATA_SIZE;
					statData->st_ino = VC_FUSE_INODE_AUX_DEVICE_INFO;
					fuse_service_set_stat_blocks (statData);
				}
				else if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = FuseService::GetVolumeSize();
					statData->st_ino = VC_FUSE_INODE_VOLUME;
					fuse_service_set_stat_blocks (statData);
				}
				else if (strcmp (path, FuseService::GetControlPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = VC_FUSE_METADATA_SIZE;
					statData->st_ino = VC_FUSE_INODE_CONTROL;
					fuse_service_set_stat_blocks (statData);
				}
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
				else if (strcmp (path, FuseService::GetShutdownPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = fuse_service_get_shutdown_identity().size();
					statData->st_ino = VC_FUSE_INODE_SHUTDOWN;
					fuse_service_set_stat_blocks (statData);
				}
				else if (strcmp (path, FuseService::GetShutdownSocketPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0400;
					statData->st_nlink = 1;
					statData->st_size = FuseServiceShutdownDirectory.size() + 1;
					statData->st_ino = VC_FUSE_INODE_SHUTDOWN_SOCKET;
					fuse_service_set_stat_blocks (statData);
				}
#endif
				else
				{
					return -ENOENT;
				}
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

#if defined(VC_FUSE3)
	static int fuse_service_getattr (const char *path, struct stat *statData, struct fuse_file_info *fi)
	{
		(void) fi;
		return fuse_service_getattr_impl (path, statData);
	}
#else
	static int fuse_service_getattr (const char *path, struct stat *statData)
	{
		return fuse_service_getattr_impl (path, statData);
	}
#endif

	static int fuse_service_statfs (const char *path, struct statvfs *statData)
	{
		try
		{
			(void) path;

			uint64 blockCount = fuse_service_ceil_div (FuseService::GetVolumeSize(), VC_FUSE_BLOCK_SIZE);
			if (blockCount == 0)
				blockCount = 1;

			Memory::Zero (statData, sizeof (*statData));
			statData->f_bsize = VC_FUSE_BLOCK_SIZE;
			statData->f_frsize = VC_FUSE_BLOCK_SIZE;
			statData->f_blocks = blockCount;
			statData->f_bfree = blockCount;
			statData->f_bavail = blockCount;
			statData->f_files = 4;
			statData->f_ffree = 0;
			statData->f_favail = 0;
			statData->f_namemax = 255;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static int fuse_service_opendir (const char *path, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, "/") != 0)
				return -ENOENT;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static int fuse_service_open (const char *path, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				return 0;

			if (strcmp (path, FuseService::GetAuxDeviceInfoPath()) == 0)
			{
				fi->direct_io = 1;
				return 0;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				fi->fh = reinterpret_cast <uint64> (new shared_ptr <Buffer> (FuseService::GetVolumeInfo()));
				fi->direct_io = 1;
				return 0;
			}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			if (strcmp (path, FuseService::GetShutdownPath()) == 0
				|| strcmp (path, FuseService::GetShutdownSocketPath()) == 0)
			{
				fi->direct_io = 1;
				return 0;
			}
#endif
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}
		return -ENOENT;
	}

	static int fuse_service_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				try
				{
					// Test for read beyond the end of the volume
					if ((uint64) offset + size > FuseService::GetVolumeSize())
						size = FuseService::GetVolumeSize() - offset;

					size_t sectorSize = FuseService::GetVolumeSectorSize();
					if (size % sectorSize != 0 || offset % sectorSize != 0)
					{
						// Support for non-sector-aligned read operations is required by some loop device tools
						// which may analyze the volume image before attaching it as a device

						uint64 alignedOffset = offset - (offset % sectorSize);
						uint64 alignedSize = size + (offset % sectorSize);

						if (alignedSize % sectorSize != 0)
							alignedSize += sectorSize - (alignedSize % sectorSize);

						SecureBuffer alignedBuffer (alignedSize);

						FuseService::ReadVolumeSectors (alignedBuffer, alignedOffset);
						BufferPtr ((uint8 *) buf, size).CopyFrom (alignedBuffer.GetRange (offset % sectorSize, size));
					}
					else
					{
						FuseService::ReadVolumeSectors (BufferPtr ((uint8 *) buf, size), offset);
					}
				}
				catch (MissingVolumeData&)
				{
					return 0;
				}

				return size;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				shared_ptr <Buffer> infoBuf = fuse_service_get_control_info (fi);
				BufferPtr outBuf ((uint8 *)buf, size);

				if (offset >= (off_t) infoBuf->Size())
					return 0;

				if (offset + size > infoBuf->Size())
					size = infoBuf->Size () - offset;

				outBuf.CopyFrom (infoBuf->GetRange (offset, size));
				return size;
			}

			if (strcmp (path, FuseService::GetAuxDeviceInfoPath()) == 0)
			{
				shared_ptr <Buffer> infoBuf = FuseService::GetAuxDeviceInfo();
				BufferPtr outBuf ((uint8 *)buf, size);

				if (offset >= (off_t) infoBuf->Size())
					return 0;

				if (offset + size > infoBuf->Size())
					size = infoBuf->Size () - offset;

				outBuf.CopyFrom (infoBuf->GetRange (offset, size));
				return size;
			}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			if (strcmp (path, FuseService::GetShutdownPath()) == 0
				|| strcmp (path, FuseService::GetShutdownSocketPath()) == 0)
			{
				string identity = strcmp (path, FuseService::GetShutdownPath()) == 0
					? fuse_service_get_shutdown_identity() : FuseServiceShutdownDirectory + "\n";
				if (offset < 0)
					return -EINVAL;

				if (offset >= (off_t) identity.size())
					return 0;

				if (offset + size > identity.size())
					size = identity.size() - offset;

				memcpy (buf, identity.data() + offset, size);
				return size;
			}
#endif
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

	static int fuse_service_release (const char *path, struct fuse_file_info *fi)
	{
		try
		{
			if (strcmp (path, FuseService::GetControlPath()) == 0 && fi && fi->fh)
			{
				delete reinterpret_cast <shared_ptr <Buffer> *> (fi->fh);
				fi->fh = 0;
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static int fuse_service_readdir_impl (const char *path, void *buf, fuse_fill_dir_t filler, struct fuse_file_info *fi)
	{
		(void) fi;

		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, "/") != 0)
				return -ENOENT;

			if (fuse_service_fill_dir_entry (buf, filler, ".", S_IFDIR | 0500, VC_FUSE_INODE_ROOT, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, "..", S_IFDIR | 0500, VC_FUSE_INODE_ROOT, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetVolumeImagePath() + 1, S_IFREG | 0600, VC_FUSE_INODE_VOLUME, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetControlPath() + 1, S_IFREG | 0600, VC_FUSE_INODE_CONTROL, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetAuxDeviceInfoPath() + 1, S_IFREG | 0600, VC_FUSE_INODE_AUX_DEVICE_INFO, 0) != 0)
				return 0;
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetShutdownPath() + 1, S_IFREG | 0600, VC_FUSE_INODE_SHUTDOWN, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetShutdownSocketPath() + 1, S_IFREG | 0400, VC_FUSE_INODE_SHUTDOWN_SOCKET, 0) != 0)
				return 0;
#endif
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

#if defined(VC_FUSE3)
	static int fuse_service_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
	{
		(void) offset;
		(void) flags;
		return fuse_service_readdir_impl (path, buf, filler, fi);
	}
#else
	static int fuse_service_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
	{
		(void) offset;
		return fuse_service_readdir_impl (path, buf, filler, fi);
	}
#endif

	static int fuse_service_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				FuseService::WriteVolumeSectors (BufferPtr ((uint8 *) buf, size), offset);
				return size;
			}

			if (strcmp (path, FuseService::GetAuxDeviceInfoPath()) == 0)
			{
				if (FuseService::AuxDeviceInfoReceived())
					return -EACCES;

				FuseService::ReceiveAuxDeviceInfo (ConstBufferPtr ((const uint8 *) buf, size));
				return size;
			}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			if (strcmp (path, FuseService::GetShutdownPath()) == 0)
			{
				pid_t processId;
				uint64 serialInstanceNumber;
				VolumeSlotNumber slotNumber;
				if (offset != 0 || size == 0 || size > 256
					|| !fuse_service_parse_shutdown_identity (string (buf, size), processId, serialInstanceNumber, slotNumber)
					|| processId != getpid() || serialInstanceNumber != FuseService::GetSerialInstanceNumber()
					|| slotNumber != FuseService::GetSlotNumber())
					return -EINVAL;

				// This is a compatibility notification, not an instruction to
				// close FUSE. The worker waits for the client's SMB unmount.
				return size;
			}
#endif

		}
#ifdef TC_FREEBSD
		// FreeBSD apparently retries failed write operations forever, which may lead to a system crash.
		catch (VolumeReadOnly&)
		{
			return size;
		}
		catch (VolumeProtected&)
		{
			return size;
		}
#endif
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

#ifdef TC_LINUX
	static int fuse_service_fsync (const char *path, int datasync, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			// Loop devices turn block-layer flushes into fsync requests on the volume image.
			// Data written by WriteVolumeSectors() reaches the backing storage only when it is synced.
			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				FuseService::FlushVolume();
		}
		catch (...)
		{
			// Never return -ENOSYS, even if the backing storage does: Linux FUSE would then
			// report success for every later fsync on this mount without forwarding it.
			int error = FuseService::ExceptionToErrorCode();
			return error == -ENOSYS ? -EIO : error;
		}

		// Other files have nothing to sync, and must not get -ENOSYS either.
		return 0;
	}
#endif

	bool FuseService::CheckAccessRights ()
	{
		return fuse_get_context()->uid == 0 || fuse_get_context()->uid == UserId;
	}

	void FuseService::CloseMountedVolume ()
	{
		if (MountedVolume)
		{
			// This process will exit before the use count of MountedVolume reaches zero
			if (MountedVolume->GetFile().use_count() > 1)
				MountedVolume->GetFile()->Close();

			if (MountedVolume.use_count() > 1)
				delete MountedVolume.get();

			MountedVolume.reset();
		}
	}

	void FuseService::Dismount ()
	{
		CloseMountedVolume();

		if (EncryptionThreadPool::IsRunning())
			EncryptionThreadPool::Stop();
	}

	int FuseService::ExceptionToErrorCode ()
	{
		try
		{
			throw;
		}
		catch (std::bad_alloc&)
		{
			return -ENOMEM;
		}
		catch (ParameterIncorrect &e)
		{
			SystemLog::WriteException (e);
			return -EINVAL;
		}
		catch (VolumeProtected&)
		{
			return -EPERM;
		}
		catch (VolumeReadOnly&)
		{
			return -EPERM;
		}
		catch (SystemException &e)
		{
			SystemLog::WriteException (e);
			return -static_cast <int> (e.GetErrorCode());
		}
		catch (std::exception &e)
		{
			SystemLog::WriteException (e);
			return -EIO;
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
			return -EIO;
		}
	}

	void FuseService::FlushVolume ()
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->GetFile()->Flush();
	}

	shared_ptr <Buffer> FuseService::GetAuxDeviceInfo ()
	{
		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);

		{
			ScopeLock lock (OpenVolumeInfoMutex);

			sr.Serialize ("VirtualDevice", string (OpenVolumeInfo.VirtualDevice));
			sr.Serialize ("LoopDevice", string (OpenVolumeInfo.LoopDevice));
		}

		ConstBufferPtr infoBuf = dynamic_cast <MemoryStream&> (*stream);
		shared_ptr <Buffer> outBuf (new Buffer (infoBuf.Size()));
		outBuf->CopyFrom (infoBuf);

		return outBuf;
	}

	shared_ptr <Buffer> FuseService::GetVolumeInfo ()
	{
		shared_ptr <Stream> stream (new MemoryStream);

		{
			ScopeLock lock (OpenVolumeInfoMutex);

			OpenVolumeInfo.Set (*MountedVolume);
			OpenVolumeInfo.SlotNumber = SlotNumber;

			OpenVolumeInfo.Serialize (stream);
		}

		ConstBufferPtr infoBuf = dynamic_cast <MemoryStream&> (*stream);
		shared_ptr <Buffer> outBuf (new Buffer (infoBuf.Size()));
		outBuf->CopyFrom (infoBuf);

		return outBuf;
	}

	const char *FuseService::GetVolumeImagePath ()
	{
#ifdef TC_MACOSX
		return "/volume.dmg";
#else
		return "/volume";
#endif
	}

	uint64 FuseService::GetVolumeSize ()
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		return MountedVolume->GetSize();
	}

	uint64 FuseService::Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint)
	{
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		// Keep the descriptor in the service across fork, but do not let exec'd
		// helpers retain the backing file after the service exits.
		openVolume->GetFile()->SetCloseOnExec();
#endif

		list <string> args;
		args.push_back (FuseService::GetDeviceType());
		args.push_back (fuseMountPoint);

#ifdef TC_MACOSX
		args.push_back ("-o");
		args.push_back ("noping_diskarb");
		args.push_back ("-o");
		args.push_back ("nobrowse");

#ifdef VC_MACOSX_FUSET
		// Use FUSE-T's SMB backend for the auxiliary mount. The default NFS
		// backend can be affected by macOS Network Volumes privacy state.
		args.push_back ("-o");
		args.push_back ("backend=smb");
		args.push_back ("-o");
		args.push_back ("nonamedattr");
		args.push_back ("-o");
		args.push_back ("rwsize=262144");
#endif

		if (getuid() == 0 || geteuid() == 0)
#endif
		{
			args.push_back ("-o");
			args.push_back ("allow_other");
		}

#if defined(TC_LINUX) && !defined(VC_FUSE3)
		// FUSE2 has no fuse_config init hook; pass the mount option instead.
		args.push_back ("-o");
		args.push_back ("use_ino");
#endif

		// Generate the serial before forking so the caller can reuse it if
		// the service's control metadata cannot be read.
		struct timeval tv;
		throw_sys_if (gettimeofday (&tv, NULL) != 0);
		const uint64 serialInstanceNumber = (uint64)tv.tv_sec * 1000000ULL + tv.tv_usec;

		ExecFunctor execFunctor (openVolume, slotNumber, serialInstanceNumber);
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		// This inherited channel binds startup to this exact child, without
		// depending on a working public socket or readable SMB metadata.
		int startup[2];
		throw_sys_if (socketpair (AF_UNIX, SOCK_STREAM, 0, startup) == -1);
		finally_do_arg (int *, startup, { if (finally_arg[0] != -1) close (finally_arg[0]); if (finally_arg[1] != -1) close (finally_arg[1]); });
		fuse_service_configure_socket (startup[0]);
		fuse_service_configure_socket (startup[1]);
		execFunctor.StartupFd = startup[1];
		execFunctor.StartupPeerFd = startup[0];
		pid_t startupProcessId = 0;
		try
		{
#endif
		Process::Execute ("fuse", args, -1, &execFunctor);

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		close (startup[1]);
		startup[1] = -1;
		pid_t processId;
		if (!fuse_service_socket_transfer (startup[0], &processId, sizeof (processId), false) || processId <= 1)
			throw SystemException (SRC_POS, EPIPE);
		startupProcessId = processId;
#endif

		for (int t = 0; true; t++)
		{
			try
			{
				if (FilesystemPath (fuseMountPoint + FuseService::GetControlPath()).GetType() == FilesystemPathType::File)
					break;
			}
			catch (...)
			{
				// Ignore exceptions since we will retry
			}

			if (t > 50)
				throw TimeOut (SRC_POS);

			Thread::Sleep (100);
		}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		// Make sure the watcher has observed this mount before a caller can
		// immediately dismount it with a released (non-notifying) client.
		DismountRequest prepared = PrepareDismount (fuseMountPoint, serialInstanceNumber, slotNumber, false);
		if (prepared.LegacyService || prepared.ProcessId != startupProcessId)
			throw ParameterIncorrect (SRC_POS);
		uint8 commit = 1;
		if (!fuse_service_socket_transfer (startup[0], &commit, sizeof (commit), true))
			throw SystemException (SRC_POS, EPIPE);
		}
		catch (...)
		{
			if (startup[1] != -1)
			{
				close (startup[1]);
				startup[1] = -1;
			}
			try
			{
				// Half-close requests rollback; retain the read end to observe
				// teardown even when the original failure was a socket refusal.
				throw_sys_if (shutdown (startup[0], SHUT_WR) == -1 && errno != ENOTCONN);
				uint8 reply;
				const FuseServiceClock::time_point deadline = FuseServiceClock::now() + chrono::seconds (10);
				while (fuse_service_socket_transfer (startup[0], &reply, sizeof (reply), false, -1, fuse_service_remaining_time (deadline))) { }
				if (startupProcessId > 1)
					WaitForDismount (startupProcessId, fuseMountPoint, slotNumber);
			}
			catch (exception &e)
			{
				SystemLog::WriteException (e);
				throw MountServiceCleanupFailed (SRC_POS, StringConverter::ToWide (fuseMountPoint));
			}
			catch (...)
			{
				SystemLog::WriteException (UnknownException (SRC_POS));
				throw MountServiceCleanupFailed (SRC_POS, StringConverter::ToWide (fuseMountPoint));
			}
			throw;
		}
#endif
		return serialInstanceNumber;
	}

	void FuseService::ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->ReadSectors (buffer, byteOffset);
	}

	void FuseService::ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer)
	{
		shared_ptr <Stream> stream (new MemoryStream (buffer));
		Serializer sr (stream);
		DevicePath virtualDevice = sr.DeserializeString ("VirtualDevice");
		DevicePath loopDevice = sr.DeserializeString ("LoopDevice");

		ScopeLock lock (OpenVolumeInfoMutex);
		OpenVolumeInfo.VirtualDevice = virtualDevice;
		OpenVolumeInfo.LoopDevice = loopDevice;
	}

	void FuseService::SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice)
	{
		File fuseServiceControl;
		fuseServiceControl.Open (string (fuseMountPoint) + GetAuxDeviceInfoPath(), File::OpenWrite);

		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);

		sr.Serialize ("VirtualDevice", string (virtualDevice));
		sr.Serialize ("LoopDevice", string (loopDevice));
		fuseServiceControl.Write (dynamic_cast <MemoryStream&> (*stream));
		fuseServiceControl.Close();
	}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
	static string fuse_service_read_metadata (const string &path, size_t limit)
	{
		File file;
		file.Open (path);
		Buffer buffer (limit);
		uint64 size = file.Read (buffer);
		if (size == 0 || size == buffer.Size())
			throw ParameterIncorrect (SRC_POS);
		return string (reinterpret_cast <const char *> (buffer.Ptr()), size);
	}

	static bool fuse_service_request_mount_present (const FuseService::DismountRequest &request)
	{
		fsid_t current;
		return fuse_service_find_mount (request.AuxMountPoint.c_str(), current)
			&& current.val[0] == request.MountId[0] && current.val[1] == request.MountId[1];
	}

	bool FuseService::IsDismountMountPresent (const DismountRequest &request)
	{
		return fuse_service_request_mount_present (request);
	}

	static void fuse_service_validate_legacy (const FuseService::DismountRequest &request)
	{
		string control = fuse_service_read_metadata (request.AuxMountPoint + FuseService::GetControlPath(), 1024 * 1024);
		shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr (reinterpret_cast <const uint8 *> (control.data()), control.size())));
		shared_ptr <VolumeInfo> volume = Serializable::DeserializeNew <VolumeInfo> (stream);
		if (!volume || volume->SerialInstanceNumber != request.SerialInstanceNumber || volume->SlotNumber != request.SlotNumber
			|| !fuse_service_request_mount_present (request))
			throw ParameterIncorrect (SRC_POS);
	}

	static int fuse_service_connect_shutdown (const FuseService::DismountRequest &request)
	{
		// macOS also returns ECONNREFUSED for a full AF_UNIX listen backlog.
		// Retry briefly; an unavailable endpoint is not a protocol mismatch.
		const FuseServiceClock::time_point deadline = FuseServiceClock::now() + chrono::seconds (2);
		for (;;)
		{
			int fd = socket (AF_UNIX, SOCK_STREAM, 0);
			throw_sys_if (fd == -1);
			try
			{
				fuse_service_configure_socket (fd);
				sockaddr_un address = fuse_service_shutdown_address (request.SocketDirectory);
				if (connect (fd, reinterpret_cast <sockaddr *> (&address), sizeof (address)) == -1)
				{
					throw_sys_if (errno != EINPROGRESS);
					fuse_service_socket_wait (fd, POLLOUT, -1, fuse_service_remaining_time (deadline));
					int error;
					socklen_t size = sizeof (error);
					throw_sys_if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &size) == -1);
					if (error != 0)
						throw SystemException (SRC_POS, error);
				}

				pid_t peerPid;
				socklen_t peerPidSize = sizeof (peerPid);
				throw_sys_if (getsockopt (fd, SOL_LOCAL, LOCAL_PEERPID, &peerPid, &peerPidSize) == -1);
				if (peerPid != request.ProcessId || !Process::IsProcessRunning (peerPid, request.ProcessStartTime))
					throw ParameterIncorrect (SRC_POS);
				return fd;
			}
			catch (SystemException &e)
			{
				close (fd);
				if ((e.GetErrorCode() != ECONNREFUSED && e.GetErrorCode() != ENOENT)
					|| FuseServiceClock::now() >= deadline)
					throw;
				Thread::Sleep (100);
			}
			catch (...)
			{
				close (fd);
				throw;
			}
		}
	}

	static int32 fuse_service_shutdown_command (int fd, const FuseService::DismountRequest &request, uint64 command, int timeOut)
	{
		uint64 frame[8] = { VC_FUSE_SHUTDOWN_VERSION, command, static_cast <uint64> (request.ProcessId),
			request.SerialInstanceNumber, request.SlotNumber, request.IgnoreOpenFiles ? VC_FUSE_SHUTDOWN_FORCE : 0,
			static_cast <uint32> (request.MountId[0]), static_cast <uint32> (request.MountId[1]) };
		int32 error;
		if (!fuse_service_socket_transfer (fd, frame, sizeof (frame), true)
			|| !fuse_service_socket_transfer (fd, &error, sizeof (error), false, -1, timeOut))
			throw SystemException (SRC_POS, EPIPE);
		if (error == EPROTONOSUPPORT)
			throw MountServiceIncompatible (SRC_POS);
		return error;
	}

	FuseService::DismountRequest FuseService::PrepareDismount (const DirectoryPath &fuseMountPoint, uint64 serialInstanceNumber, VolumeSlotNumber slotNumber, bool ignoreOpenFiles)
	{
		DismountRequest request = {};
		request.SerialInstanceNumber = serialInstanceNumber;
		request.SlotNumber = slotNumber;
		request.IgnoreOpenFiles = ignoreOpenFiles;
		char *canonicalPath = realpath (string (fuseMountPoint).c_str(), NULL);
		throw_sys_if (canonicalPath == NULL);
		finally_do_arg (char *, canonicalPath, { free (finally_arg); });
		request.AuxMountPoint = canonicalPath;
		fsid_t mountId;
		if (!fuse_service_find_mount (canonicalPath, mountId))
			throw SystemException (SRC_POS, ENOENT);
		request.MountId[0] = mountId.val[0];
		request.MountId[1] = mountId.val[1];

		string identity;
		try { identity = fuse_service_read_metadata (request.AuxMountPoint + GetShutdownPath(), 256); }
		catch (SystemException &e)
		{
			if (e.GetErrorCode() != ENOENT)
				throw;
			// Released versions have no shutdown endpoint. Validate their
			// control metadata and retain the mount instance for the old flow.
			// Never take this fallback for a broken or mismatched socket service.
			fuse_service_validate_legacy (request);
			request.LegacyService = true;
			return request;
		}

		uint64 serviceSerialInstanceNumber;
		VolumeSlotNumber serviceSlotNumber;
		if (!fuse_service_parse_shutdown_identity (identity, request.ProcessId, serviceSerialInstanceNumber, serviceSlotNumber)
			|| serviceSerialInstanceNumber != serialInstanceNumber || serviceSlotNumber != slotNumber)
			throw ParameterIncorrect (SRC_POS);
		request.ProcessStartTime = Process::GetProcessStartTime (request.ProcessId);

		try { request.SocketDirectory = fuse_service_read_metadata (request.AuxMountPoint + GetShutdownSocketPath(), 256); }
		catch (SystemException &e)
		{
			// The file-only development protocol cannot keep FUSE serving
			// throughout SMB unmount. Its clients can still dismount new services.
			if (e.GetErrorCode() == ENOENT)
				throw MountServiceIncompatible (SRC_POS);
			throw;
		}
		const string prefix (VC_FUSE_SHUTDOWN_DIRECTORY_PREFIX);
		if (request.SocketDirectory.size() != prefix.size() + 13 || request.SocketDirectory.back() != '\n'
			|| request.SocketDirectory.compare (0, prefix.size(), prefix) != 0
			|| request.SocketDirectory.find_first_not_of ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", prefix.size()) != request.SocketDirectory.size() - 1)
			throw ParameterIncorrect (SRC_POS);
		request.SocketDirectory.pop_back();
		if (!fuse_service_request_mount_present (request))
			throw SystemException (SRC_POS, ESTALE);

		try
		{
			int fd = fuse_service_connect_shutdown (request);
			finally_do_arg (int, fd, { close (finally_arg); });
			int32 error = fuse_service_shutdown_command (fd, request, VC_FUSE_SHUTDOWN_PROBE, 10000);
			if (error != 0)
				throw SystemException (SRC_POS, error);
		}
		catch (SystemException &e)
		{
			throw MountServiceUnavailable (SRC_POS, StringConverter::ToExceptionString (e));
		}
		catch (TimeOut &e)
		{
			throw MountServiceUnavailable (SRC_POS, StringConverter::ToExceptionString (e));
		}
		return request;
	}

	pid_t FuseService::RequestDismount (const DismountRequest &request)
	{
		try
		{
			// Reconnect after hdiutil detach so a long flush cannot hold open a
			// preflight connection beyond the service's request deadline.
			int fd = fuse_service_connect_shutdown (request);
			finally_do_arg (int, fd, { close (finally_arg); });
			int32 error = fuse_service_shutdown_command (fd, request, VC_FUSE_SHUTDOWN_DISMOUNT, 60000);
			if (error == EBUSY)
				throw MountedVolumeInUse (SRC_POS);
			if (error != 0)
				throw SystemException (SRC_POS, error);
		}
		catch (SystemException &e)
		{
			// External unmount may have completed between preflight and request.
			// It is only success when the captured mount instance is already gone.
			if (e.GetErrorCode() != ENOENT && e.GetErrorCode() != ECONNREFUSED && e.GetErrorCode() != EPIPE)
				throw;
			if (fuse_service_request_mount_present (request))
				throw MountServiceUnavailable (SRC_POS, StringConverter::ToExceptionString (e));
		}
		catch (TimeOut &e)
		{
			if (fuse_service_request_mount_present (request))
				throw MountServiceUnavailable (SRC_POS, StringConverter::ToExceptionString (e));
		}
		return request.ProcessId;
	}

	void FuseService::DismountLegacy (const DismountRequest &request)
	{
		if (!request.LegacyService)
			throw ParameterIncorrect (SRC_POS);
		if (!fuse_service_request_mount_present (request))
			return;
		fuse_service_validate_legacy (request);
		for (int attempt = 0; ; ++attempt)
		{
			if (!fuse_service_request_mount_present (request))
				return;
			if (unmount (request.AuxMountPoint.c_str(), request.IgnoreOpenFiles ? MNT_FORCE : 0) == 0)
				return;
			int error = errno;
			if ((error == EINVAL || error == ENOENT) && !fuse_service_request_mount_present (request))
				return;
			if (error == EBUSY && attempt < 10)
			{
				Thread::Sleep (200);
				continue;
			}
			if (error == EBUSY)
				throw MountedVolumeInUse (SRC_POS);
			throw SystemException (SRC_POS, error);
		}
	}

	void FuseService::WaitForDismount (pid_t processId, const DirectoryPath &fuseMountPoint, VolumeSlotNumber slotNumber, int timeOut, uint64 processStartTime)
	{
		for (int timeTaken = 0; ; timeTaken += 100)
		{
			if (!Process::IsProcessRunning (processId, processStartTime)) return;

			if (timeTaken >= timeOut)
			{
				stringstream logMessage;
				logMessage << "VeraCrypt FUSE service did not terminate after shutdown request: pid=" << processId
					<< ", slot=" << slotNumber << ", auxiliary mount=" << string (fuseMountPoint);
				SystemLog::WriteError (logMessage.str());
				throw DismountServiceCleanupFailed (SRC_POS, StringConverter::ToWide (logMessage.str()));
			}

			Thread::Sleep (100);
		}
	}
#endif

	void FuseService::WriteVolumeSectors (const ConstBufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->WriteSectors (buffer, byteOffset);
	}

	void FuseService::OnSignal (int signal)
	{
		try
		{
			shared_ptr <VolumeInfo> volume = Core->GetMountedVolume (SlotNumber);

			if (volume && volume->SerialInstanceNumber == GetSerialInstanceNumber())
				Core->DismountVolume (volume, true);
		}
		catch (...) { }

		_exit (0);
	}

	void FuseService::ExecFunctor::operator() (int argc, char *argv[])
	{
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		close (StartupPeerFd);
#endif
		FuseService::OpenVolumeInfo.SerialInstanceNumber = SerialInstanceNumber;

		FuseService::MountedVolume = MountedVolume;
		FuseService::SlotNumber = SlotNumber;

		FuseService::UserId = getuid();
		FuseService::GroupId = getgid();

		if (getenv ("SUDO_UID"))
		{
			try
			{
				string s (getenv ("SUDO_UID"));
				FuseService::UserId = static_cast <uid_t> (StringConverter::ToUInt64 (s));

				if (getenv ("SUDO_GID"))
				{
					s = getenv ("SUDO_GID");
					FuseService::GroupId = static_cast <gid_t> (StringConverter::ToUInt64 (s));
				}
			}
			catch (...) { }
		}
		else
		{
			uid_t doasUid;
			gid_t doasGid;
			if (GetDoasUserIds (&doasUid, &doasGid))
			{
				FuseService::UserId = doasUid;
				FuseService::GroupId = doasGid;
			}
		}

		static fuse_operations fuse_service_oper;

		fuse_service_oper.access = fuse_service_access;
		fuse_service_oper.destroy = fuse_service_destroy;
#ifdef TC_LINUX
		fuse_service_oper.fsync = fuse_service_fsync;
#endif
		fuse_service_oper.getattr = fuse_service_getattr;
		fuse_service_oper.init = fuse_service_init;
		fuse_service_oper.open = fuse_service_open;
		fuse_service_oper.opendir = fuse_service_opendir;
		fuse_service_oper.read = fuse_service_read;
		fuse_service_oper.readdir = fuse_service_readdir;
		fuse_service_oper.release = fuse_service_release;
		fuse_service_oper.statfs = fuse_service_statfs;
		fuse_service_oper.write = fuse_service_write;

		// Create a new session
		setsid ();

		// Fork handler of termination signals
		SignalHandlerPipe.reset (new Pipe);

		int forkedPid = fork();
		throw_sys_if (forkedPid == -1);

		if (forkedPid == 0)
		{
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			close (StartupFd);
#endif
			CloseMountedVolume();

			struct sigaction action;
			Memory::Zero (&action, sizeof (action));
			action.sa_handler = OnSignal;

			sigaction (SIGINT, &action, nullptr);
			sigaction (SIGQUIT, &action, nullptr);
			sigaction (SIGTERM, &action, nullptr);

			// Wait for the exit of the main service
			uint8 buf[1];
			if (read (SignalHandlerPipe->GetReadFD(), buf, sizeof (buf))) { } // Errors ignored

			_exit (0);
		}

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		// Keep the backend from delaying EOF when the service exits.
		int signalPipeWriteFd = SignalHandlerPipe->GetWriteFD();
		int signalPipeFlags = fcntl (signalPipeWriteFd, F_GETFD);
		throw_sys_if (signalPipeFlags == -1);
		throw_sys_if (fcntl (signalPipeWriteFd, F_SETFD, signalPipeFlags | FD_CLOEXEC) == -1);
#else
		SignalHandlerPipe->GetWriteFD();
#endif

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		_exit (fuse_service_main (argc, argv, &fuse_service_oper, StartupFd));
#elif defined(VC_FUSE3)
		_exit (fuse_main (argc, argv, &fuse_service_oper, nullptr));
#elif defined(TC_OPENBSD)
		_exit (fuse_main (argc, argv, &fuse_service_oper, NULL));
#else
		_exit (fuse_main (argc, argv, &fuse_service_oper));
#endif
	}

	VolumeInfo FuseService::OpenVolumeInfo;
	Mutex FuseService::OpenVolumeInfoMutex;
	shared_ptr <Volume> FuseService::MountedVolume;
	VolumeSlotNumber FuseService::SlotNumber;
	uid_t FuseService::UserId;
	gid_t FuseService::GroupId;
	unique_ptr <Pipe> FuseService::SignalHandlerPipe;
}
