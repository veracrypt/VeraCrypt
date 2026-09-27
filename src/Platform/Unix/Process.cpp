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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
#include "Platform/Unix/Poller.h"
#ifdef TC_MACOSX
#include <chrono>
#include <poll.h>
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

	bool Process::IsExecutable(const std::string& path) {
		struct stat sb;
		if (stat(path.c_str(), &sb) == 0) {
			return S_ISREG(sb.st_mode) && (sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
		}
		return false;
	}

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
					}
					else
					{
						inPipe.Close();
						int nullDev = open ("/dev/null", 0);
						throw_sys_sub_if (nullDev == -1, "/dev/null");
						throw_sys_if (dup2 (nullDev, STDIN_FILENO) == -1);
					}

					throw_sys_if (dup2 (outPipe.GetWriteFD(), STDOUT_FILENO) == -1);
					throw_sys_if (dup2 (errPipe.GetWriteFD(), STDERR_FILENO) == -1);
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

		Poller poller (outPipe.GetReadFD(), errPipe.GetReadFD(), exceptionPipe.GetReadFD());
		int status, waitRes;

		if (inputData)
			throw_sys_if (write (inPipe.GetWriteFD(), inputData->Ptr(), inputData->Size()) == -1 && errno != EPIPE);

		inPipe.Close();

		int timeTaken = 0;
		do
		{
			const int pollTimeout = 200;
			try
			{
				ssize_t bytesRead = 0;
				foreach (int fd, poller.WaitForData (pollTimeout))
				{
					bytesRead = read (fd, &buffer[0], buffer.capacity());
					if (bytesRead > 0)
					{
						if (fd == outPipe.GetReadFD())
							stdOutput.insert (stdOutput.end(), buffer.begin(), buffer.begin() + bytesRead);
						else if (fd == errPipe.GetReadFD())
							errOutput.insert (errOutput.end(), buffer.begin(), buffer.begin() + bytesRead);
						else if (fd == exceptionPipe.GetReadFD())
							exOutput.insert (exOutput.end(), buffer.begin(), buffer.begin() + bytesRead);
					}
				}

				if (bytesRead == 0)
				{
					waitRes = waitpid (forkedPid, &status, 0);
					break;
				}
			}
			catch (TimeOut&)
			{
				timeTaken += pollTimeout;
				if (timeOut >= 0 && timeTaken >= timeOut)
					throw;
			}
		} while ((waitRes = waitpid (forkedPid, &status, WNOHANG)) == 0);
		throw_sys_if (waitRes == -1);

		if (!exOutput.empty())
		{
			unique_ptr <Serializable> deserializedObject;
			Exception *deserializedException = nullptr;

			try
			{
				shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr ((uint8 *) &exOutput[0], exOutput.size())));
				deserializedObject.reset (Serializable::DeserializeNew (stream));
				deserializedException = dynamic_cast <Exception*> (deserializedObject.get());
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
