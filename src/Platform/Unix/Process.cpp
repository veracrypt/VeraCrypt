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

#include <chrono>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <sstream>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef TC_LINUX
#include <sys/prctl.h>
#include <sys/statvfs.h>
#endif
#include "Process.h"
#include "Platform/Exception.h"
#include "Platform/Finally.h"
#include "Platform/FileStream.h"
#include "Platform/ForEach.h"
#include "Platform/MemoryStream.h"
#include "Platform/Mutex.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include "Platform/Unix/Pipe.h"
#ifdef TC_MACOSX
#include <signal.h>
#include <spawn.h>
#include <crt_externs.h>
#include <libproc.h>
#endif

namespace VeraCrypt
{

#ifdef TC_MACOSX
	uint64 Process::GetProcessStartTime (pid_t processId)
	{
		struct proc_bsdinfo info;
		if (proc_pidinfo (processId, PROC_PIDTBSDINFO, 0, &info, sizeof (info)) != sizeof (info))
			return 0;
		return info.pbi_start_tvsec * 1000000ULL + info.pbi_start_tvusec;
	}

	bool Process::IsProcessRunning (pid_t processId, uint64 expectedStartTime)
	{
		if (processId <= 1) throw ParameterIncorrect (SRC_POS);
		if (kill (processId, 0) == -1 && errno == ESRCH) return false;
		uint64 startTime = expectedStartTime ? GetProcessStartTime (processId) : 0;
		// An inaccessible process remains pending. Only absence or a positively
		// identified replacement proves that the captured instance has exited.
		return !expectedStartTime || !startTime || startTime == expectedStartTime;
	}

	// Bounded children that survived SIGKILL, such as a child in uninterruptible
	// sleep. Later calls reap them and start no new child until then, so repeated
	// timeouts cannot accumulate stuck children or zombies. Never destroyed: a
	// detached discovery worker may still run during static destruction.
	static Mutex &GetAbandonedChildrenMutex ()
	{
		static Mutex *mutex = new Mutex;
		return *mutex;
	}

	static vector <pid_t> &GetAbandonedChildren ()
	{
		static vector <pid_t> *children = new vector <pid_t>;
		return *children;
	}

	string Process::ExecuteBounded (const string &processName, const list <string> &arguments, int timeOut, size_t outputLimit)
	{
		if (processName.empty() || processName[0] != '/' || timeOut <= 0 || outputLimit == 0)
			throw ParameterIncorrect (SRC_POS);

		{
			ScopeLock lock (GetAbandonedChildrenMutex());
			vector <pid_t> &children = GetAbandonedChildren();
			for (size_t i = 0; i < children.size(); )
			{
				pid_t waited = waitpid (children[i], NULL, WNOHANG);
				if (waited == 0 || (waited == -1 && errno == EINTR))
					++i;
				else
					children.erase (children.begin() + i);
			}
			if (!children.empty())
				throw TimeOut (SRC_POS, StringConverter::ToWide (processName));
		}

		const auto deadline = chrono::steady_clock::now() + chrono::milliseconds (timeOut);
		int descriptors[4] = { -1, -1, -1, -1 };
		finally_do_arg (int *, descriptors, { for (int i = 0; i < 4; ++i) if (finally_arg[i] != -1) close (finally_arg[i]); });
		throw_sys_if (pipe (descriptors) != 0);
		throw_sys_if (pipe (descriptors + 2) != 0);
		for (int i = 0; i < 4; ++i)
			throw_sys_if (fcntl (descriptors[i], F_SETFD, FD_CLOEXEC) == -1);
		for (int i = 0; i < 4; i += 2)
			throw_sys_if (fcntl (descriptors[i], F_SETFL, O_NONBLOCK) == -1);

		posix_spawn_file_actions_t actions;
		int error = posix_spawn_file_actions_init (&actions);
		if (error) throw SystemException (SRC_POS, error);
		finally_do_arg (posix_spawn_file_actions_t *, &actions, { posix_spawn_file_actions_destroy (finally_arg); });
		posix_spawnattr_t attributes;
		error = posix_spawnattr_init (&attributes);
		if (error) throw SystemException (SRC_POS, error);
		finally_do_arg (posix_spawnattr_t *, &attributes, { posix_spawnattr_destroy (finally_arg); });
		// Avoid fork-side library calls and leaking service/key-bearing descriptors
		// when discovery runs on the GUI's worker thread.
		if ((error = posix_spawnattr_setflags (&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT))
			|| (error = posix_spawn_file_actions_addopen (&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0))
			|| (error = posix_spawn_file_actions_adddup2 (&actions, descriptors[1], STDOUT_FILENO))
			|| (error = posix_spawn_file_actions_adddup2 (&actions, descriptors[3], STDERR_FILENO)))
			throw SystemException (SRC_POS, error);

		vector <char *> args;
		args.push_back (const_cast <char *> (processName.c_str()));
		for (const string &argument : arguments)
			args.push_back (const_cast <char *> (argument.c_str()));
		args.push_back (nullptr);
		pid_t child;
		error = posix_spawn (&child, processName.c_str(), &actions, &attributes, &args[0], *_NSGetEnviron());
		if (error) throw SystemException (SRC_POS, error);
		finally_do_arg (pid_t *, &child, {
			if (*finally_arg > 0)
			{
				// This is our unreaped child, never a PID recovered from metadata.
				// A child in uninterruptible sleep cannot be reaped within the
				// deadline; leave it to a later call rather than blocking this one.
				kill (*finally_arg, SIGKILL);
				bool finished = false;
				for (int attempt = 0; attempt < 100 && !finished; ++attempt)
				{
					pid_t waited = waitpid (*finally_arg, NULL, WNOHANG);
					finished = waited == *finally_arg || (waited == -1 && errno != EINTR);
					if (!finished)
						poll (nullptr, 0, 10);
				}
				if (!finished)
				{
					ScopeLock lock (GetAbandonedChildrenMutex());
					GetAbandonedChildren().push_back (*finally_arg);
				}
			}
		});
		close (descriptors[1]); descriptors[1] = -1;
		close (descriptors[3]); descriptors[3] = -1;
		struct pollfd fds[2] = { { descriptors[0], POLLIN, 0 }, { descriptors[2], POLLIN, 0 } };
		string output[2];
		int status = 0;
		int exitPoll = 1;
		while (child > 0 || fds[0].fd != -1 || fds[1].fd != -1)
		{
			if (child > 0)
			{
				pid_t waited = waitpid (child, &status, WNOHANG);
				if (waited == child) child = -1;
				else if (waited == -1 && errno != EINTR)
				{
					if (errno == ECHILD) child = -1;
					throw SystemException (SRC_POS);
				}
			}
			if (child == -1 && fds[0].fd == -1 && fds[1].fd == -1)
				break;
			auto remaining = chrono::duration_cast <chrono::milliseconds> (deadline - chrono::steady_clock::now()).count();
			if (remaining <= 0) throw TimeOut (SRC_POS, StringConverter::ToWide (processName));
			int pollTimeout = static_cast <int> (remaining < 50 ? remaining : 50);
			if (fds[0].fd == -1 && fds[1].fd == -1)
			{
				// Output is complete and the exit status normally follows at once.
				// Do not sleep a whole output-poll interval before reaping it.
				if (exitPoll < pollTimeout) pollTimeout = exitPoll;
				exitPoll = exitPoll < 25 ? exitPoll * 2 : 50;
			}
			int result = poll (fds, 2, pollTimeout);
			if (result == -1 && errno == EINTR) continue;
			throw_sys_if (result == -1);
			for (int i = 0; i < 2; ++i)
			{
				if (fds[i].fd == -1 || !fds[i].revents) continue;
				char buffer[8192];
				ssize_t count = read (fds[i].fd, buffer, sizeof (buffer));
				if (count > 0)
				{
					if (static_cast <size_t> (count) > outputLimit - output[0].size() - output[1].size())
						throw ParameterTooLarge (SRC_POS);
					output[i].append (buffer, count);
				}
				else if (count == 0) fds[i].fd = -1;
				else if (errno != EINTR && errno != EAGAIN) throw SystemException (SRC_POS);
			}
		}
		int exitCode = WIFEXITED (status) ? WEXITSTATUS (status) : 1;
		if (exitCode != 0)
			throw ExecutedProcessFailed (SRC_POS, processName, exitCode, output[1]);
		return output[0];
	}
#endif

	void Process::DisableCoreDumps ()
	{
		// For processes that hold key material. A core_pattern pipe ignores
		// RLIMIT_CORE on Linux, but not the dumpable flag, which also keeps
		// other processes of the same user from attaching.
		struct rlimit limit;
		limit.rlim_cur = 0;
		limit.rlim_max = 0;
		setrlimit (RLIMIT_CORE, &limit);
#ifdef TC_LINUX
		prctl (PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
	}

	bool Process::IsExecutable(const std::string& path) {
		struct stat sb;
		if (stat(path.c_str(), &sb) == 0) {
			return S_ISREG(sb.st_mode) && (sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
		}
		return false;
	}

#ifdef TC_LINUX
	static bool IsTrustedSystemPathEntry (const string &path, const struct stat &info)
	{
		if (info.st_uid != 0)
			return false;
		if (S_ISLNK (info.st_mode) || !(info.st_mode & (S_IWGRP | S_IWOTH)))
			return true;

		// NixOS exposes its store read-only, but the directory retains group
		// write permission for the build users. Its sticky bit protects existing
		// root-owned entries in the daemon's writable view. All children still
		// have to pass the normal ownership and permission checks below.
		if (path != "/nix/store" || !S_ISDIR (info.st_mode)
			|| !(info.st_mode & S_ISVTX) || (info.st_mode & S_IWOTH))
			return false;
		struct statvfs filesystem;
		return statvfs (path.c_str(), &filesystem) == 0 && (filesystem.f_flag & ST_RDONLY);
	}

	// Walk from the root before following each link. Checking only realpath's
	// result would miss a writable directory containing an earlier symlink.
	// Once checked, a component can only be replaced by a trusted administrator.
	static bool ResolveTrustedSystemPath (const string &path, string &resolved, struct stat &info)
	{
		resolved.clear();
		if (path.empty() || path[0] != '/')
			return false;

		if (lstat ("/", &info) != 0 || !S_ISDIR (info.st_mode) || !IsTrustedSystemPathEntry ("/", info))
			return false;

		string current = "/";
		string remaining = path.substr (1);
		unsigned int links = 0;
		while (!remaining.empty())
		{
			size_t separator = remaining.find ('/');
			bool directoryRequired = separator != string::npos;
			string component = remaining.substr (0, separator);
			remaining = directoryRequired ? remaining.substr (separator + 1) : "";
			if (component.empty())
				continue;

			string candidate = current + (current == "/" ? "" : "/") + component;
			if (candidate.size() >= PATH_MAX || lstat (candidate.c_str(), &info) != 0 || info.st_uid != 0)
				return false;

			if (S_ISLNK (info.st_mode))
			{
				if (++links > 40)
					return false;
				char target[PATH_MAX];
				ssize_t length = readlink (candidate.c_str(), target, sizeof (target));
				if (length <= 0 || static_cast <size_t> (length) >= sizeof (target))
					return false;
				remaining = string (target, length) + (directoryRequired ? "/" + remaining : "");
				if (target[0] == '/')
					current = "/";
				// Symlink mode bits aren't access controls. Its owner and the
				// permissions of its parent and target are checked instead.
				continue;
			}

			if (directoryRequired && !S_ISDIR (info.st_mode))
				return false;
			if (component == "..")
			{
				current.erase (current.find_last_of ('/'));
				if (current.empty())
					current = "/";
			}
			else if (component != ".")
				current = candidate;
			if (!IsTrustedSystemPathEntry (current, info))
				return false;
		}

		if (lstat (current.c_str(), &info) != 0 || S_ISLNK (info.st_mode) || !IsTrustedSystemPathEntry (current, info))
			return false;
		resolved = current;
		return true;
	}

	static bool IsNixOS ()
	{
		string path;
		struct stat info;
		if (!ResolveTrustedSystemPath ("/etc/os-release", path, info) || !S_ISREG (info.st_mode))
			return false;

		// Read only protected system metadata, with no shell or environment override.
		vector <char> buffer (64 * 1024 + 1);
		FILE *file = fopen (path.c_str(), "r");
		if (!file)
			return false;
		size_t size = fread (&buffer[0], 1, buffer.size(), file);
		bool readFailed = ferror (file) != 0;
		fclose (file);
		if (readFailed || size == buffer.size())
			return false;

		std::istringstream contents (string (&buffer[0], size));
		string line;
		bool foundId = false;
		bool nixos = false;
		while (std::getline (contents, line))
		{
			if (!line.empty() && line[line.size() - 1] == '\r')
				line.erase (line.size() - 1);
			if (line.compare (0, 3, "ID=") != 0)
				continue;
			if (foundId)
				return false;
			foundId = true;
			string id = line.substr (3);
			nixos = id == "nixos" || id == "\"nixos\"" || id == "'nixos'";
		}
		return nixos;
	}
#endif

	// Find executable in system paths
	std::string Process::FindSystemBinary(const char* name, std::string& errorMsg) {
		if (!name) {
			errno = EINVAL; // Invalid argument
			errorMsg = "Invalid input: name or paths is NULL";
			return "";
		}

		// Default system directories to search for executables.
		// On macOS, system locations are searched before /usr/local/bin so that
		// a user-writable /usr/local/bin (the default on Homebrew installs)
		// cannot shadow system tools. This matters because this resolver is
		// also used for privileged binaries such as sudo during elevation
		// (see CoreService.cpp); a planted /usr/local/bin/sudo would otherwise
		// receive the admin password.
#ifdef TC_MACOSX
		const char* defaultDirs[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"};
#elif TC_FREEBSD
		const char* defaultDirs[] = {"/sbin", "/bin", "/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin"};
#elif TC_OPENBSD
		const char* defaultDirs[] = {"/sbin", "/bin", "/usr/sbin", "/usr/bin", "/usr/X11R6/bin", "/usr/local/sbin", "/usr/local/bin"};
#else
		const char* defaultDirs[] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"};
#endif
		const size_t defaultDirCount = sizeof(defaultDirs) / sizeof(defaultDirs[0]);

		std::string currentPath(name);

		// If path doesn't start with '/', prepend default directories
		if (currentPath[0] != '/') {
#ifdef TC_LINUX
			if (IsNixOS ())
			{
				// Only NixOS enables these additional locations. The privileged
				// wrapper must precede the system profile's plain sudo binary.
				const char *nixDirs[] = { "/run/wrappers/bin", "/run/current-system/sw/bin" };
				for (size_t i = 0; i < sizeof (nixDirs) / sizeof (nixDirs[0]); ++i)
				{
					string candidate = string (nixDirs[i]) + "/" + currentPath;
					string resolved;
					struct stat info;
					if (ResolveTrustedSystemPath (candidate, resolved, info)
						&& S_ISREG (info.st_mode) && (info.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
						// Preserve argv[0] for helpers such as true that link to a multicall binary.
						return candidate;
				}
			}
#endif
			for (size_t i = 0; i < defaultDirCount; ++i) {
				std::string combinedPath = std::string(defaultDirs[i]) + "/" + currentPath;
				if (IsExecutable(combinedPath)) {
					return combinedPath;
				}
			}
		} else if (IsExecutable(currentPath)) {
			return currentPath;
		}

		// Prepare error message
		errno = ENOENT; // No such file or directory
		errorMsg = std::string(name) + " not found in system directories";
		return "";
	}

	string Process::Execute (const string &processNameArg, const list <string> &arguments, int timeOut, ProcessExecFunctor *execFunctor, const Buffer *inputData)
	{
		char *args[32];
		if (array_capacity (args) <= (arguments.size() + 1))
			throw ParameterTooLarge (SRC_POS);

		// if execFunctor is null and processName is not absolute path, find it in system paths
		string processName;
		if (!execFunctor && (processNameArg[0] != '/'))
		{
			std::string errorMsg;
			processName = FindSystemBinary(processNameArg.c_str(), errorMsg);
			if (processName.empty())
				throw SystemException(SRC_POS, errorMsg);
		}
		else
			processName = processNameArg;

#if 0
		stringstream dbg;
		dbg << "exec " << processName;
		foreach (const string &at, arguments)
			dbg << " " << at;
		trace_msg (dbg.str());
#endif

		Pipe inPipe, outPipe, errPipe, exceptionPipe;
		throw_sys_if (fcntl (exceptionPipe.PeekWriteFD(), F_SETFD, FD_CLOEXEC) == -1);

		int forkedPid = fork();
		throw_sys_if (forkedPid == -1);

		if (forkedPid == 0)
		{
			try
			{
				try
				{
					int argIndex = 0;
					if (!execFunctor)
						args[argIndex++] = const_cast <char*> (processName.c_str());

					for (list<string>::const_iterator it = arguments.begin(); it != arguments.end(); it++)
					{
						args[argIndex++] = const_cast <char*> (it->c_str());
					}
					args[argIndex] = nullptr;

					if (inputData)
					{
						throw_sys_if (dup2 (inPipe.GetReadFD(), STDIN_FILENO) == -1);
						if (inPipe.PeekReadFD() != STDIN_FILENO)
							inPipe.Close();
					}
					else
					{
						inPipe.Close();
						int nullDev = open ("/dev/null", 0);
						throw_sys_sub_if (nullDev == -1, "/dev/null");
						throw_sys_if (dup2 (nullDev, STDIN_FILENO) == -1);
						if (nullDev != STDIN_FILENO)
							close (nullDev);
					}

					throw_sys_if (dup2 (outPipe.GetWriteFD(), STDOUT_FILENO) == -1);
					if (outPipe.PeekWriteFD() != STDOUT_FILENO)
						outPipe.Close();
					throw_sys_if (dup2 (errPipe.GetWriteFD(), STDERR_FILENO) == -1);
					if (errPipe.PeekWriteFD() != STDERR_FILENO)
						errPipe.Close();
					exceptionPipe.GetWriteFD();

					if (execFunctor)
					{
						(*execFunctor)(argIndex, args);
					}
					else
					{
						execvp (args[0], args);
						throw SystemException (SRC_POS, args[0]);
					}
				}
				catch (Exception &)
				{
					throw;
				}
				catch (exception &e)
				{
					throw ExternalException (SRC_POS, StringConverter::ToExceptionString (e));
				}
				catch (...)
				{
					throw UnknownException (SRC_POS);
				}
			}
			catch (Exception &e)
			{
				try
				{
					shared_ptr <Stream> outputStream (new FileStream (exceptionPipe.GetWriteFD()));
					e.Serialize (outputStream);
				}
				catch (...) { }
			}

			_exit (1);
		}

		throw_sys_if (fcntl (outPipe.GetReadFD(), F_SETFL, O_NONBLOCK) == -1);
		throw_sys_if (fcntl (errPipe.GetReadFD(), F_SETFL, O_NONBLOCK) == -1);
		throw_sys_if (fcntl (exceptionPipe.GetReadFD(), F_SETFL, O_NONBLOCK) == -1);

		vector <char> buffer (4096), stdOutput (4096), errOutput (4096), exOutput (4096);
		stdOutput.clear ();
		errOutput.clear ();
		exOutput.clear ();

		struct pollfd fds[3] = {
			{ outPipe.GetReadFD(), POLLIN, 0 },
			{ errPipe.GetReadFD(), POLLIN, 0 },
			{ exceptionPipe.GetReadFD(), POLLIN, 0 }
		};
		vector <char> *output[3] = { &stdOutput, &errOutput, &exOutput };

		if (inputData)
			throw_sys_if (write (inPipe.GetWriteFD(), inputData->Ptr(), inputData->Size()) == -1 && errno != EPIPE);

		inPipe.Close();

		// GCC 4.4 through 4.6 used the earlier name for this clock.
#if defined(__GLIBCXX__) && !defined(__clang__) && __GNUC__ == 4 && __GNUC_MINOR__ < 7
		typedef chrono::monotonic_clock Clock;
#else
		typedef chrono::steady_clock Clock;
#endif
		const Clock::time_point deadline = Clock::now() + chrono::milliseconds (timeOut < 0 ? 0 : timeOut);
		bool childExited = false;
		int status = 0;
		int exitPoll = 1;
		const size_t maxDrainSize = 1024 * 1024;
		size_t drained[3] = { 0, 0, 0 };
		while (true)
		{
			if (!childExited)
			{
				int waited = waitpid (forkedPid, &status, WNOHANG);
				throw_sys_if (waited == -1 && errno != EINTR);
				childExited = waited == forkedPid;
			}

			bool outputClosed = fds[0].fd == -1 && fds[1].fd == -1 && fds[2].fd == -1;
			if (childExited && outputClosed)
				break;

			int pollTimeout = childExited ? 0 : 50;
			// After exit, each pipe's drain limit bounds the remaining reads.
			if (timeOut >= 0 && !childExited)
			{
				int64 remaining = chrono::duration_cast <chrono::milliseconds> (deadline - Clock::now()).count();
				// Preserve the existing timeout behavior: leave the child running.
				if (remaining <= 0)
					throw TimeOut (SRC_POS, StringConverter::ToWide (processName));
				if (remaining < pollTimeout)
					pollTimeout = static_cast <int> (remaining);
			}
			if (outputClosed)
			{
				// EOF can precede exit; check promptly without an untimed waitpid.
				if (exitPoll < pollTimeout)
					pollTimeout = exitPoll;
				exitPoll = exitPoll < 25 ? exitPoll * 2 : 50;
			}

			int pollRes = poll (fds, array_capacity (fds), pollTimeout);
			if (pollRes == -1 && errno == EINTR)
				continue;
			throw_sys_if (pollRes == -1);

			bool readAgain = false;
			for (size_t i = 0; i < array_capacity (fds); ++i)
			{
				if (fds[i].fd == -1 || !fds[i].revents)
					continue;
				size_t readSize = buffer.size();
				if (childExited && readSize > maxDrainSize - drained[i])
					readSize = maxDrainSize - drained[i];
				ssize_t bytesRead = read (fds[i].fd, &buffer[0], readSize);
				if (bytesRead > 0)
				{
					output[i]->insert (output[i]->end(), buffer.begin(), buffer.begin() + bytesRead);
					readAgain = true;
					if (childExited)
					{
						// Bound each pipe's drain even if a descendant keeps writing.
						drained[i] += bytesRead;
						if (drained[i] == maxDrainSize)
							fds[i].fd = -1;
					}
				}
				else if (bytesRead == 0)
					fds[i].fd = -1;
				else if (errno == EINTR)
					readAgain = true;
				else
					throw_sys_if (errno != EAGAIN && errno != EWOULDBLOCK);
			}

			// Drain buffered output, but do not wait for descendants (such as the
			// forked FUSE service) to close their copies after this child exits.
			if (childExited && !readAgain)
				break;
		}

		if (!exOutput.empty())
		{
			shared_ptr <Exception> deserializedException;

			try
			{
				shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr ((uint8 *) &exOutput[0], exOutput.size())));
				deserializedException = Serializable::DeserializeNew <Exception> (stream);
			}
			catch (...)	{ }

			if (deserializedException)
				deserializedException->Throw();
		}

		int exitCode = (WIFEXITED (status) ? WEXITSTATUS (status) : 1);
		if (exitCode != 0)
		{
			string strErrOutput;

			if (!errOutput.empty())
				strErrOutput.insert (strErrOutput.begin(), errOutput.begin(), errOutput.end());

			throw ExecutedProcessFailed (SRC_POS, processName, exitCode, strErrOutput);
		}

		string strOutput;

		if (!stdOutput.empty())
			strOutput.insert (strOutput.begin(), stdOutput.begin(), stdOutput.end());

		return strOutput;
	}

#if defined(TC_LINUX)
	bool Process::IsRunningUnderAppImage (const string &executablePath)
	{
		if (executablePath.empty())
			return false;

		// AppImage detection logic:
		// Check that APPIMAGE and APPDIR environment variables are set
		// Check that the executable path starts with APPDIR
		// Check that APPDIR itself starts with the expected AppImage mount prefix
		const char* appImageEnv = getenv("APPIMAGE");
		const char* appDirEnv = getenv("APPDIR");

		if (appImageEnv && appDirEnv)
		{
			string appDirString = appDirEnv;
			const std::string appImageMountPrefix = "/tmp/.mount_";
			const std::string appImageMountSuffixPattern = "veracr"; // Lowercase for case-insensitive comparison

			if (!appDirString.empty() &&
				executablePath.rfind(appDirString, 0) == 0 &&
				appDirString.rfind(appImageMountPrefix, 0) == 0)
			{
				// Ensure appDirString has enough room for appImageMountPrefix and appImageMountSuffixPattern
				if (appDirString.length() > appImageMountPrefix.length() + appImageMountSuffixPattern.length())
				{
					std::string actualSuffixPart = appDirString.substr(appImageMountPrefix.length(), appImageMountSuffixPattern.length());
					if (StringConverter::ToLower(actualSuffixPart) == appImageMountSuffixPattern)
					{
						// All conditions met, this is the AppImage scenario.
						return true;
					}
				}
			}
		}
		return false;
	}
#endif
}
