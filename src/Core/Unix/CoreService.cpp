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

#include "CoreService.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <stdio.h>
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"
#include "Platform/Thread.h"
#include "Platform/Unix/Poller.h"
#include "Platform/Unix/Process.h"
#include "Core/Core.h"
#include "CoreUnix.h"
#include "CoreServiceRequest.h"
#include "CoreServiceResponse.h"

namespace VeraCrypt
{
	enum class PrivilegeHelperType
	{
		Sudo,
		Doas
	};

	struct PrivilegeHelper
	{
		PrivilegeHelperType Type;
		string Name;
		string Path;

		bool IsDoas () const { return Type == PrivilegeHelperType::Doas; }
		bool IsSudo () const { return Type == PrivilegeHelperType::Sudo; }
	};

	// Keep the PTY master open while the doas no-fork service is running;
	// closing it can hang up the service controlling terminal.
	static int DoasAuthTerminalFd = -1;

	static void SetCloseOnExec (int fd, bool closeOnExec)
	{
		int flags = fcntl (fd, F_GETFD, 0);
		throw_sys_if (flags == -1);

		int newFlags = closeOnExec ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC);
		if (newFlags != flags)
			throw_sys_if (fcntl (fd, F_SETFD, newFlags) == -1);
	}

	static void SetPipeCloseOnExec (Pipe &pipe)
	{
		SetCloseOnExec (pipe.PeekReadFD(), true);
		SetCloseOnExec (pipe.PeekWriteFD(), true);
	}

	static void DupToStandardFd (int fd, int standardFd)
	{
		if (fd != standardFd)
			throw_sys_if (dup2 (fd, standardFd) == -1);

		// If fd already equals standardFd, dup2() is a no-op and does not clear
		// FD_CLOEXEC. Clear it explicitly for all descriptors kept across exec.
		SetCloseOnExec (standardFd, false);
	}

	static void RedirectStandardErrorToDevNull ()
	{
		int f = open ("/dev/null", O_WRONLY);
		throw_sys_sub_if (f == -1, "/dev/null");
		if (dup2 (f, STDERR_FILENO) == -1)
		{
			close (f);
			throw SystemException (SRC_POS);
		}
		if (f != STDERR_FILENO)
			close (f);
	}

	static PrivilegeHelper FindPrivilegeHelper ()
	{
		std::string errorMsg;
		string path = Process::FindSystemBinary ("sudo", errorMsg);
		if (!path.empty())
			return { PrivilegeHelperType::Sudo, "sudo", path };

		path = Process::FindSystemBinary ("doas", errorMsg);
		if (!path.empty())
			return { PrivilegeHelperType::Doas, "doas", path };

		throw SystemException (SRC_POS, "Neither sudo nor doas was found in system directories");
	}

	static string BuildPrivilegeHelperAuthCheckCommand (const PrivilegeHelper &helper)
	{
		std::string errorMsg;
		string trueAbsolutePath = Process::FindSystemBinary ("true", errorMsg);
		if (trueAbsolutePath.empty())
			throw SystemException (SRC_POS, errorMsg);

		return helper.Path + " -n " + trueAbsolutePath + " > /dev/null 2>&1";
	}

	static bool HasControllingTerminal ()
	{
#ifdef O_CLOEXEC
		int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
#else
		int fd = open ("/dev/tty", O_RDWR);
#endif
		if (fd == -1)
			return false;

#ifndef O_CLOEXEC
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1)
		{
			close (fd);
			return false;
		}
#endif

		close (fd);
		return true;
	}

	static int OpenDoasAuthTerminal (string &slavePath)
	{
#ifdef O_CLOEXEC
		bool fdCloseOnExec = true;
		int fd = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (fd == -1 && errno == EINVAL)
		{
			// Some systems, including OpenBSD, only accept the POSIX
			// pseudoterminal flags here. Set close-on-exec below instead.
			fdCloseOnExec = false;
			fd = posix_openpt (O_RDWR | O_NOCTTY);
		}
#else
		int fd = posix_openpt (O_RDWR | O_NOCTTY);
#endif
		throw_sys_sub_if (fd == -1, "posix_openpt");

#ifdef O_CLOEXEC
		if (!fdCloseOnExec && fcntl (fd, F_SETFD, FD_CLOEXEC) == -1)
		{
			close (fd);
			throw SystemException (SRC_POS);
		}
#else
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1)
		{
			close (fd);
			throw SystemException (SRC_POS);
		}
#endif

		if (grantpt (fd) == -1 || unlockpt (fd) == -1)
		{
			close (fd);
			throw SystemException (SRC_POS, "Failed to initialize doas authentication terminal");
		}

#if defined (TC_LINUX)
		char path[PATH_MAX];
		int ptsStatus = ptsname_r (fd, path, sizeof (path));
		if (ptsStatus != 0)
		{
			close (fd);
			throw SystemException (SRC_POS, ptsStatus);
		}

		slavePath = path;
#else
		char *path = ptsname (fd);
		if (!path)
		{
			close (fd);
			throw SystemException (SRC_POS, "Failed to get doas authentication terminal path");
		}

		slavePath = path;
#endif
		return fd;
	}

	static void CloseDoasAuthTerminal ()
	{
		if (DoasAuthTerminalFd != -1)
		{
			close (DoasAuthTerminalFd);
			DoasAuthTerminalFd = -1;
		}
	}

	static void AttachDoasAuthTerminal (const string &slavePath, bool keepStderrOnTerminal)
	{
		throw_sys_if (setsid () == -1);
#ifdef O_CLOEXEC
		int ttyFd = open (slavePath.c_str(), O_RDWR | O_CLOEXEC);
#else
		int ttyFd = open (slavePath.c_str(), O_RDWR);
#endif
		throw_sys_sub_if (ttyFd == -1, slavePath);

#ifndef O_CLOEXEC
		if (fcntl (ttyFd, F_SETFD, FD_CLOEXEC) == -1)
		{
			close (ttyFd);
			throw SystemException (SRC_POS);
		}
#endif

		// doas reads the passphrase from this terminal with the slave line
		// discipline active. Put it in raw mode so control characters in the
		// admin password (^C, ^U, erase, etc.) reach doas verbatim instead of
		// being interpreted as line editing or signal keys. This only ever
		// touches VeraCrypt's private authentication PTY, never the caller's
		// real terminal. Best effort: on failure we keep the default canonical
		// mode, which still handles ordinary passwords.
		struct termios tios;
		if (tcgetattr (ttyFd, &tios) == 0)
		{
			tios.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ISIG | IEXTEN);
			tios.c_iflag &= ~(BRKINT | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
			tios.c_cc[VMIN] = 1;
			tios.c_cc[VTIME] = 0;
			tcsetattr (ttyFd, TCSANOW, &tios);
		}

#ifdef TIOCSCTTY
		if (ioctl (ttyFd, TIOCSCTTY, 0) == -1 && errno != EINVAL)
		{
			close (ttyFd);
			throw SystemException (SRC_POS, "Failed to set doas authentication terminal as controlling terminal");
		}
#endif
#ifdef TC_OPENBSD
		if (tcsetpgrp (ttyFd, getpgrp()) == -1)
		{
			int err = errno;
			close (ttyFd);
			errno = err;
			throw SystemException (SRC_POS, "Failed to set doas authentication terminal foreground process group");
		}
#else
		tcsetpgrp (ttyFd, getpgrp());
#endif
		bool ttyFdKeptOnStderr = keepStderrOnTerminal && ttyFd == STDERR_FILENO;
		if (keepStderrOnTerminal)
		{
			try
			{
				DupToStandardFd (ttyFd, STDERR_FILENO);
			}
			catch (...)
			{
				if (!ttyFdKeptOnStderr)
					close (ttyFd);
				throw;
			}
		}

		if (!ttyFdKeptOnStderr)
			close (ttyFd);
	}

	static void ReapChildProcessAsync (int pid)
	{
		struct WaitFunctor : public Functor
		{
			WaitFunctor (int processId) : Pid (processId) { }
			virtual void operator() ()
			{
				while (true)
				{
					int status;
					int waitResult = waitpid (Pid, &status, 0);

					if (waitResult == Pid)
						return;

					if (waitResult == -1 && errno == EINTR)
						continue;

					if (waitResult == -1 && errno == ECHILD)
						return;

					return;
				}
			}
			int Pid;
		};

		try
		{
			unique_ptr <Functor> waitFunctor (new WaitFunctor (pid));
			Thread thread;
			thread.Start (waitFunctor.get());
			waitFunctor.release();
			thread.Detach ();
		}
		catch (...) { }
	}

	static void TerminateChildProcessAsync (int pid)
	{
		if (pid <= 0)
			return;

		kill (pid, SIGTERM);
		ReapChildProcessAsync (pid);
	}

	static void ReadAvailableData (int fd, vector <char> &output)
	{
		char buffer[4096];

		while (true)
		{
			ssize_t bytesRead = read (fd, buffer, sizeof (buffer));
			if (bytesRead > 0)
			{
				output.insert (output.end(), buffer, buffer + bytesRead);
				continue;
			}

			if (bytesRead == -1 && errno == EINTR)
				continue;

			if (bytesRead == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				return;

			return;
		}
	}

	static string ErrorOutputToString (const vector <char> &errOutput)
	{
		if (errOutput.empty())
			return string();

		return string (errOutput.begin(), errOutput.end());
	}

	static string NormalizeTerminalOutput (const string &terminalOutput)
	{
		string normalized;
		bool previousNewline = false;

		for (size_t i = 0; i < terminalOutput.size(); ++i)
		{
			char c = terminalOutput[i];
			if (c == '\r')
			{
				if (i + 1 < terminalOutput.size() && terminalOutput[i + 1] == '\n')
					continue;
				c = '\n';
			}

			if (c == '\n')
			{
				if (previousNewline)
					continue;
				previousNewline = true;
			}
			else
				previousNewline = false;

			normalized += c;
		}

		while (!normalized.empty() && normalized[0] == '\n')
			normalized.erase (0, 1);
		while (!normalized.empty() && normalized[normalized.size() - 1] == '\n')
			normalized.erase (normalized.size() - 1);

		return normalized;
	}

	static bool StringEndsWith (const string &str, const string &suffix)
	{
		return str.size() >= suffix.size() && str.compare (str.size() - suffix.size(), suffix.size(), suffix) == 0;
	}

	static string TrimTerminalLine (const string &line)
	{
		size_t first = line.find_first_not_of (" \t");
		if (first == string::npos)
			return string();

		size_t last = line.find_last_not_of (" \t");
		return line.substr (first, last - first + 1);
	}

	static bool IsDoasPasswordPromptLine (const string &line)
	{
		string trimmed = TrimTerminalLine (line);
		return trimmed.find ("doas (") == 0 && StringEndsWith (trimmed, " password:");
	}

	static string NormalizeDoasAuthTerminalOutput (const string &terminalOutput)
	{
		string normalized = NormalizeTerminalOutput (terminalOutput);
		string filtered;
		size_t lineStart = 0;

		while (lineStart <= normalized.size())
		{
			size_t lineEnd = normalized.find ('\n', lineStart);
			string line = lineEnd == string::npos ? normalized.substr (lineStart) : normalized.substr (lineStart, lineEnd - lineStart);

			if (!IsDoasPasswordPromptLine (line))
			{
				if (!filtered.empty())
					filtered += '\n';
				filtered += line;
			}

			if (lineEnd == string::npos)
				break;

			lineStart = lineEnd + 1;
		}

		return NormalizeTerminalOutput (filtered);
	}

	static bool DoasAuthenticationFailed (const vector <char> &authOutput)
	{
		return ErrorOutputToString (authOutput).find ("doas: Authentication failed") != string::npos;
	}

	static string CombineElevationErrorOutput (const vector <char> &errOutput, const vector <char> &authOutput)
	{
		string output = ErrorOutputToString (errOutput);
		string authText = NormalizeDoasAuthTerminalOutput (ErrorOutputToString (authOutput));

		if (!authText.empty())
		{
			if (!output.empty() && output[output.size() - 1] != '\n')
				output += "\n";
			output += authText;
		}

		return output;
	}

	static void ReadAvailableDataIfAny (int fd, vector <char> &output)
	{
		if (fd != -1)
			ReadAvailableData (fd, output);
	}

	static void ThrowSerializedExceptionIfAny (const vector <char> &errOutput)
	{
		if (errOutput.empty())
			return;

		unique_ptr <Serializable> deserializedObject;
		Exception *deserializedException = nullptr;

		try
		{
			shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr ((uint8 *) &errOutput[0], errOutput.size())));
			deserializedObject.reset (Serializable::DeserializeNew (stream));
			deserializedException = dynamic_cast <Exception*> (deserializedObject.get());
		}
		catch (...)	{ }

		if (deserializedException)
			deserializedException->Throw();
	}

	static void WriteAllBestEffort (int fd, const char *data, size_t size, int retryTimeout = 0)
	{
		const int retryDelay = 50;
		int retryTimeLeft = retryTimeout;
		size_t offset = 0;
		while (offset < size)
		{
			ssize_t bytesWritten = write (fd, data + offset, size - offset);
			if (bytesWritten > 0)
			{
				offset += static_cast <size_t> (bytesWritten);
				continue;
			}

			if (bytesWritten == -1 && errno == EINTR)
				continue;

			if (bytesWritten == -1 && retryTimeLeft > 0 && (errno == EIO || errno == EAGAIN || errno == EWOULDBLOCK))
			{
				Thread::Sleep (retryDelay);
				retryTimeLeft -= retryDelay;
				continue;
			}

			return;
		}
	}

#ifdef TC_OPENBSD
	static bool ReadDoasAuthTerminalPromptData (int fd, vector <char> &authOutput)
	{
		char buffer[256];
		bool dataRead = false;

		while (true)
		{
			ssize_t bytesRead = read (fd, buffer, sizeof (buffer));
			if (bytesRead > 0)
			{
				authOutput.insert (authOutput.end(), buffer, buffer + bytesRead);
				dataRead = true;
				continue;
			}

			if (bytesRead == -1 && errno == EINTR)
				continue;

			if (bytesRead == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				return dataRead;

			return dataRead;
		}
	}

	static void WaitForDoasAuthTerminalPrompt (int fd, vector <char> &authOutput, int timeout)
	{
		const int pollInterval = 50;
		int timeLeft = timeout;
		int terminalFlags = fcntl (fd, F_GETFL, 0);
		if (terminalFlags == -1)
			return;

		bool restoreFlags = (terminalFlags & O_NONBLOCK) == 0;
		if (restoreFlags && fcntl (fd, F_SETFL, terminalFlags | O_NONBLOCK) == -1)
			return;

		while (timeLeft > 0)
		{
			struct pollfd pfd;
			memset (&pfd, 0, sizeof (pfd));
			pfd.fd = fd;
			pfd.events = POLLIN;

			int pollTimeout = timeLeft < pollInterval ? timeLeft : pollInterval;
			int pollResult;
			do
			{
				pollResult = poll (&pfd, 1, pollTimeout);
			} while (pollResult == -1 && errno == EINTR);

			if (pollResult == -1)
				break;

			if (pollResult == 0)
			{
				timeLeft -= pollTimeout;
				continue;
			}

			if ((pfd.revents & POLLIN) && ReadDoasAuthTerminalPromptData (fd, authOutput))
				break;

			if (pfd.revents & (POLLERR | POLLNVAL))
				break;

			// On OpenBSD a PTY master reports POLLIN|POLLHUP before the
			// slave is opened. A zero-byte read distinguishes that state from
			// the real doas prompt; wait real time instead of spinning.
			Thread::Sleep (pollTimeout);
			timeLeft -= pollTimeout;
		}

		if (restoreFlags)
			fcntl (fd, F_SETFL, terminalFlags);
	}
#endif

	static void SendElevatedServiceSyncWithTimeout (shared_ptr <Stream> inputStream, int outputFd, int errorFd, int authFd, vector <char> authOutput, int childPid, const string &helperName, int timeout)
	{
		vector <char> errOutput;
		uint8 sync[] = { 0, 0x11, 0x22 };

		try
		{
			inputStream->Write (ConstBufferPtr (sync, array_capacity (sync)));
		}
		catch (...)
		{
			ReadAvailableDataIfAny (errorFd, errOutput);
			ReadAvailableDataIfAny (authFd, authOutput);
			TerminateChildProcessAsync (childPid);
			ThrowSerializedExceptionIfAny (errOutput);
			throw ElevationFailed (SRC_POS, helperName, 1, CombineElevationErrorOutput (errOutput, authOutput));
		}

		const int pollInterval = 200;
		int timeLeft = timeout;
		bool errorFdActive = errorFd != -1;
		bool authFdActive = authFd != -1;
		while (timeLeft > 0)
		{
			struct pollfd fds[3];
			memset (fds, 0, sizeof (fds));
			fds[0].fd = outputFd;
			fds[0].events = POLLIN;
			nfds_t fdCount = 1;
			nfds_t errorFdIndex = 0;
			nfds_t authFdIndex = 0;
			if (errorFdActive)
			{
				errorFdIndex = fdCount;
				fds[fdCount].fd = errorFd;
				fds[fdCount].events = POLLIN;
				++fdCount;
			}
			if (authFdActive)
			{
				authFdIndex = fdCount;
				fds[fdCount].fd = authFd;
				fds[fdCount].events = POLLIN;
				++fdCount;
			}

			int pollTimeout = timeLeft < pollInterval ? timeLeft : pollInterval;
			int pollResult;
			do
			{
				pollResult = poll (fds, fdCount, pollTimeout);
			} while (pollResult == -1 && errno == EINTR);

			throw_sys_if (pollResult == -1);
			timeLeft -= pollTimeout;

			if (errorFdActive && (fds[errorFdIndex].revents & (POLLIN | POLLHUP | POLLERR)))
			{
				size_t previousErrOutputSize = errOutput.size();
				ReadAvailableData (errorFd, errOutput);
				if ((fds[errorFdIndex].revents & (POLLHUP | POLLERR)) && errOutput.size() == previousErrOutputSize)
					errorFdActive = false;
			}
			if (authFdActive && (fds[authFdIndex].revents & (POLLIN | POLLHUP | POLLERR)))
			{
				size_t previousAuthOutputSize = authOutput.size();
				ReadAvailableData (authFd, authOutput);
				if ((fds[authFdIndex].revents & (POLLHUP | POLLERR)) && authOutput.size() == previousAuthOutputSize)
					authFdActive = false;
			}
			if (DoasAuthenticationFailed (authOutput))
			{
				TerminateChildProcessAsync (childPid);
				ThrowSerializedExceptionIfAny (errOutput);
				throw ElevationFailed (SRC_POS, helperName, 1, CombineElevationErrorOutput (errOutput, authOutput));
			}

			if (fds[0].revents & POLLIN)
			{
				uint8 ready;
				ssize_t bytesRead;
				do
				{
					bytesRead = read (outputFd, &ready, 1);
				} while (bytesRead == -1 && errno == EINTR);

				if (bytesRead == 1 && ready == 0x33)
					return;

				TerminateChildProcessAsync (childPid);
				ThrowSerializedExceptionIfAny (errOutput);
				throw ElevationFailed (SRC_POS, helperName, 1, CombineElevationErrorOutput (errOutput, authOutput));
			}

			int status;
			int waitRes;
			do
			{
				waitRes = waitpid (childPid, &status, WNOHANG);
			} while (waitRes == -1 && errno == EINTR);

			if (waitRes == childPid)
			{
				ReadAvailableDataIfAny (errorFd, errOutput);
				ReadAvailableDataIfAny (authFd, authOutput);
				ThrowSerializedExceptionIfAny (errOutput);
				int exitCode = WIFEXITED (status) ? WEXITSTATUS (status) : 1;
				throw ElevationFailed (SRC_POS, helperName, exitCode, CombineElevationErrorOutput (errOutput, authOutput));
			}

			throw_sys_if (waitRes == -1);

			if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
			{
				TerminateChildProcessAsync (childPid);
				ThrowSerializedExceptionIfAny (errOutput);
				throw ElevationFailed (SRC_POS, helperName, 1, CombineElevationErrorOutput (errOutput, authOutput));
			}
		}

		ReadAvailableDataIfAny (errorFd, errOutput);
		ReadAvailableDataIfAny (authFd, authOutput);
		ThrowSerializedExceptionIfAny (errOutput);
		string errorOutput = CombineElevationErrorOutput (errOutput, authOutput);
		if (errorOutput.empty())
			errorOutput = "Timed out while waiting for the elevated VeraCrypt service to start";

		TerminateChildProcessAsync (childPid);
		throw ElevationFailed (SRC_POS, helperName, 1, errorOutput);
	}

#ifdef TC_MACOSX
	static bool IsMacOSXDevicePathWithPrefix (const string &path, const string &prefix)
	{
		if (path.find (prefix) != 0 || path.size() <= prefix.size())
			return false;

		size_t index = prefix.size();
		while (index < path.size() && path[index] >= '0' && path[index] <= '9')
			++index;

		if (index == prefix.size())
			return false;

		if (index == path.size())
			return true;

		if (path[index++] != 's')
			return false;

		size_t sliceStart = index;
		while (index < path.size() && path[index] >= '0' && path[index] <= '9')
			++index;

		return index > sliceStart && index == path.size();
	}

	static bool IsMacOSXFormatterDevicePath (const string &path)
	{
		return IsMacOSXDevicePathWithPrefix (path, "/dev/disk")
			|| IsMacOSXDevicePathWithPrefix (path, "/dev/rdisk");
	}

	// The elevated service runs as root, so it must not be tricked into changing
	// ownership of an arbitrary path. Every legitimate macOS caller of the
	// elevated SetFileOwner targets a real disk device node (/dev/[r]diskN[sM]),
	// so restrict the operation to that. lstat() (not stat) is used so a symlink
	// is rejected outright rather than followed, and the st_mode check confirms an
	// actual block/character device before the chown.
	static void ValidateMacOSXSetFileOwnerTarget (const FilesystemPath &path)
	{
		const string pathStr = path;

		if (!IsMacOSXFormatterDevicePath (pathStr))
			throw ParameterIncorrect (SRC_POS);

		struct stat sb;
		if (lstat (pathStr.c_str(), &sb) != 0)
			throw ParameterIncorrect (SRC_POS);

		if (!S_ISBLK (sb.st_mode) && !S_ISCHR (sb.st_mode))
			throw ParameterIncorrect (SRC_POS);
	}

	static list <string> BuildMacOSXAPFSFormatterArguments (const ExecuteMacOSXAPFSFormatterRequest &request)
	{
		if (!IsMacOSXFormatterDevicePath (request.Device))
			throw ParameterIncorrect (SRC_POS);

		if (request.OwnerUserId > static_cast <uint64> ((uid_t) -1)
			|| request.OwnerGroupId > static_cast <uint64> ((gid_t) -1))
		{
			throw ParameterIncorrect (SRC_POS);
		}

		stringstream uid;
		stringstream gid;
		list <string> arguments;

		uid << request.OwnerUserId;
		gid << request.OwnerGroupId;

		arguments.push_back ("-U");
		arguments.push_back (uid.str());
		arguments.push_back ("-G");
		arguments.push_back (gid.str());
		arguments.push_back (string (request.Device));

		return arguments;
	}
#endif

	unique_ptr <Serializable> CoreService::GetResponseObject ()
	{
		unique_ptr <Serializable> deserializedObject (Serializable::DeserializeNew (ServiceOutputStream));

		Exception *deserializedException = dynamic_cast <Exception*> (deserializedObject.get());
		if (deserializedException)
			deserializedException->Throw();

		return deserializedObject;
	}

	template <class T>
	unique_ptr <T> CoreService::GetResponse ()
	{
		unique_ptr <Serializable> deserializedObject (GetResponseObject());

		if (dynamic_cast <T *> (deserializedObject.get()) == nullptr)
			throw ParameterIncorrect (SRC_POS);

		return unique_ptr <T> (dynamic_cast <T *> (deserializedObject.release()));
	}

	void CoreService::ProcessElevatedRequests (bool forkProcess)
	{
		int pid = forkProcess ? fork() : 0;
		if (forkProcess)
			throw_sys_if (pid == -1);

		if (pid == 0)
		{
			try
			{
				if (forkProcess)
					RedirectStandardErrorToDevNull ();

				// Wait for sync code
				while (true)
				{
					uint8 b;
					throw_sys_if (read (STDIN_FILENO, &b, 1) != 1);
					if (b != 0x00)
						continue;

					throw_sys_if (read (STDIN_FILENO, &b, 1) != 1);
					if (b != 0x11)
						continue;

					throw_sys_if (read (STDIN_FILENO, &b, 1) != 1);
					if (b == 0x22)
						break;
				}

				ElevatedPrivileges = true;
				if (!forkProcess)
				{
					// Only the doas no-fork service emits a readiness byte, so the
					// parent can distinguish a started service from a failed
					// elevation. The sudo fork path keeps its original handshake
					// (no readiness byte) to avoid altering its well-tested startup
					// sequence.
					uint8 ready = 0x33;
					throw_sys_if (write (STDOUT_FILENO, &ready, 1) != 1);

					// Startup diagnostics have been delivered. The parent closes
					// errPipe after synchronization, so keep later service stderr
					// writes away from a closed pipe.
					RedirectStandardErrorToDevNull ();
				}
				ProcessRequests (STDIN_FILENO, STDOUT_FILENO);
				_exit (0);
			}
			catch (exception &e)
			{
#ifdef DEBUG
				SystemLog::WriteException (e);
#endif
			}
			catch (...)	{ }
			_exit (1);
		}
	}

	void CoreService::ProcessRequests (int inputFD, int outputFD)
	{
		finally_do ({ CloseDoasAuthTerminal (); });

		try
		{
			Core = move_ptr(CoreDirect);

			shared_ptr <Stream> inputStream (new FileStream (inputFD != -1 ? inputFD : InputPipe->GetReadFD()));
			shared_ptr <Stream> outputStream (new FileStream (outputFD != -1 ? outputFD : OutputPipe->GetWriteFD()));

			while (true)
			{
				shared_ptr <CoreServiceRequest> request = Serializable::DeserializeNew <CoreServiceRequest> (inputStream);

				// Update Core properties based on the received request
				Core->SetUserEnvPATH (request->UserEnvPATH);
				Core->ForceUseDummySudoPassword(request->UseDummySudoPassword);
				Core->SetAllowInsecureMount(request->AllowInsecureMount);

				try
				{
					// ExitRequest
					if (dynamic_cast <ExitRequest*> (request.get()) != nullptr)
					{
						if (ElevatedServiceAvailable)
							request->Serialize (ServiceInputStream);
						return;
					}

					if (!ElevatedPrivileges && request->ElevateUserPrivileges)
					{
						bool elevatedServiceStarted = false;

						if (!ElevatedServiceAvailable)
						{
							finally_do_arg (string *, &request->AdminPassword, { StringConverter::Erase (*finally_arg); });

							CoreService::StartElevated (*request);
							ElevatedServiceAvailable = true;
							elevatedServiceStarted = true;
						}

						// Report sudo/elevated-service success before executing the request.
						if (elevatedServiceStarted)
							ElevatedServiceStartedResponse().Serialize (outputStream);

						request->Serialize (ServiceInputStream);
						GetResponse <Serializable>()->Serialize (outputStream);
						continue;
					}

					// CheckFilesystemRequest
					CheckFilesystemRequest *checkRequest = dynamic_cast <CheckFilesystemRequest*> (request.get());
					if (checkRequest)
					{
						Core->CheckFilesystem (checkRequest->MountedVolumeInfo, checkRequest->Repair);

						CheckFilesystemResponse().Serialize (outputStream);
						continue;
					}

					// DismountFilesystemRequest
					DismountFilesystemRequest *dismountFsRequest = dynamic_cast <DismountFilesystemRequest*> (request.get());
					if (dismountFsRequest)
					{
						Core->DismountFilesystem (dismountFsRequest->MountPoint, dismountFsRequest->Force);

						DismountFilesystemResponse().Serialize (outputStream);
						continue;
					}

					// DismountVolumeRequest
					DismountVolumeRequest *dismountRequest = dynamic_cast <DismountVolumeRequest*> (request.get());
					if (dismountRequest)
					{
						DismountVolumeResponse response;
						response.DismountedVolumeInfo = Core->DismountVolume (dismountRequest->MountedVolumeInfo, dismountRequest->IgnoreOpenFiles, dismountRequest->SyncVolumeInfo);
						response.Serialize (outputStream);
						continue;
					}

#ifdef TC_LINUX
					// EmergencyDismountVolumeRequest
					EmergencyDismountVolumeRequest *emergencyDismountRequest = dynamic_cast <EmergencyDismountVolumeRequest*> (request.get());
					if (emergencyDismountRequest)
					{
						DismountVolumeResponse response;
						response.DismountedVolumeInfo = Core->EmergencyDismountVolume (emergencyDismountRequest->MountedVolumeInfo);
						response.Serialize (outputStream);
						continue;
					}
#endif

					// GetDeviceSectorSizeRequest
					GetDeviceSectorSizeRequest *getDeviceSectorSizeRequest = dynamic_cast <GetDeviceSectorSizeRequest*> (request.get());
					if (getDeviceSectorSizeRequest)
					{
						GetDeviceSectorSizeResponse response;
						response.Size = Core->GetDeviceSectorSize (getDeviceSectorSizeRequest->Path);
						response.Serialize (outputStream);
						continue;
					}

					// GetDeviceSizeRequest
					GetDeviceSizeRequest *getDeviceSizeRequest = dynamic_cast <GetDeviceSizeRequest*> (request.get());
					if (getDeviceSizeRequest)
					{
						GetDeviceSizeResponse response;
						response.Size = Core->GetDeviceSize (getDeviceSizeRequest->Path);
						response.Serialize (outputStream);
						continue;
					}

					// GetHostDevicesRequest
					GetHostDevicesRequest *getHostDevicesRequest = dynamic_cast <GetHostDevicesRequest*> (request.get());
					if (getHostDevicesRequest)
					{
						GetHostDevicesResponse response;
						response.HostDevices = Core->GetHostDevices (getHostDevicesRequest->PathListOnly);
						response.Serialize (outputStream);
						continue;
					}

#ifdef TC_MACOSX
					// ExecuteMacOSXAPFSFormatterRequest
					ExecuteMacOSXAPFSFormatterRequest *executeAPFSFormatterRequest = dynamic_cast <ExecuteMacOSXAPFSFormatterRequest*> (request.get());
					if (executeAPFSFormatterRequest)
					{
						Process::Execute (CoreService::GetMacOSXAPFSFormatterPath(), BuildMacOSXAPFSFormatterArguments (*executeAPFSFormatterRequest));
						ExecuteMacOSXAPFSFormatterResponse().Serialize (outputStream);
						continue;
					}
#endif

					// MountVolumeRequest
					MountVolumeRequest *mountRequest = dynamic_cast <MountVolumeRequest*> (request.get());
					if (mountRequest)
					{
						MountVolumeResponse (
							Core->MountVolume (*mountRequest->Options)
						).Serialize (outputStream);

						continue;
					}

					// SetFileOwnerRequest
					SetFileOwnerRequest *setFileOwnerRequest = dynamic_cast <SetFileOwnerRequest*> (request.get());
					if (setFileOwnerRequest)
					{
						CoreUnix *coreUnix = dynamic_cast <CoreUnix *> (Core.get());
						if (!coreUnix)
							throw ParameterIncorrect (SRC_POS);

#ifdef TC_MACOSX
						// Restrict the root-privileged chown to real disk device nodes.
						ValidateMacOSXSetFileOwnerTarget (setFileOwnerRequest->Path);
#endif
						coreUnix->SetFileOwner (setFileOwnerRequest->Path, setFileOwnerRequest->Owner);
						SetFileOwnerResponse().Serialize (outputStream);
						continue;
					}

					throw ParameterIncorrect (SRC_POS);
				}
				catch (Exception &e)
				{
					e.Serialize (outputStream);
				}
				catch (exception &e)
				{
					ExternalException (SRC_POS, StringConverter::ToExceptionString (e)).Serialize (outputStream);
				}
			}
		}
		catch (exception &e)
		{
#ifdef DEBUG
			SystemLog::WriteException (e);
#endif
			throw;
		}
	}

	void CoreService::RequestCheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair)
	{
		CheckFilesystemRequest request (mountedVolume, repair);
		SendRequest <CheckFilesystemResponse> (request);
	}

	void CoreService::RequestDismountFilesystem (const DirectoryPath &mountPoint, bool force)
	{
		DismountFilesystemRequest request (mountPoint, force);
		SendRequest <DismountFilesystemResponse> (request);
	}

	shared_ptr <VolumeInfo> CoreService::RequestDismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		DismountVolumeRequest request (mountedVolume, ignoreOpenFiles, syncVolumeInfo);
		return SendRequest <DismountVolumeResponse> (request)->DismountedVolumeInfo;
	}

#ifdef TC_LINUX
	shared_ptr <VolumeInfo> CoreService::RequestEmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume)
	{
		EmergencyDismountVolumeRequest request (mountedVolume);
		return SendRequest <DismountVolumeResponse> (request)->DismountedVolumeInfo;
	}
#endif

	uint32 CoreService::RequestGetDeviceSectorSize (const DevicePath &devicePath)
	{
		GetDeviceSectorSizeRequest request (devicePath);
		return SendRequest <GetDeviceSectorSizeResponse> (request)->Size;
	}

	uint64 CoreService::RequestGetDeviceSize (const DevicePath &devicePath)
	{
		GetDeviceSizeRequest request (devicePath);
		return SendRequest <GetDeviceSizeResponse> (request)->Size;
	}

	HostDeviceList CoreService::RequestGetHostDevices (bool pathListOnly)
	{
		GetHostDevicesRequest request (pathListOnly);
		return SendRequest <GetHostDevicesResponse> (request)->HostDevices;
	}

#ifdef TC_MACOSX
	const char *CoreService::GetMacOSXAPFSFormatterPath ()
	{
		return "/sbin/newfs_apfs";
	}

	void CoreService::RequestExecuteMacOSXAPFSFormatter (const DevicePath &devicePath, uint64 userId, uint64 groupId)
	{
		ExecuteMacOSXAPFSFormatterRequest request (devicePath, userId, groupId);
		SendRequest <ExecuteMacOSXAPFSFormatterResponse> (request);
	}
#endif

	shared_ptr <VolumeInfo> CoreService::RequestMountVolume (MountOptions &options)
	{
		MountVolumeRequest request (&options);
		return SendRequest <MountVolumeResponse> (request)->MountedVolumeInfo;
	}

	void CoreService::RequestSetFileOwner (const FilesystemPath &path, const UserId &owner)
	{
		SetFileOwnerRequest request (path, owner);
		SendRequest <SetFileOwnerResponse> (request);
	}

	template <class T>
	unique_ptr <T> CoreService::SendRequest (CoreServiceRequest &request)
	{
		static Mutex mutex;
		ScopeLock lock (mutex);

		// Copy Core properties to the request so that they can be transferred to the elevated process
		request.ApplicationExecutablePath = Core->GetApplicationExecutablePath();
		request.UserEnvPATH = Core->GetUserEnvPATH();
		request.UseDummySudoPassword = Core->GetUseDummySudoPassword();
		request.AllowInsecureMount = Core->GetAllowInsecureMount();
		finally_do_arg (string *, &request.AdminPassword, { StringConverter::Erase (*finally_arg); });

		if (request.RequiresElevation())
		{
			request.ElevateUserPrivileges = true;
			request.FastElevation = !ElevatedServiceAvailable;
			
			while (!ElevatedServiceAvailable)
			{
				//	Test if the user has an active privilege helper session.
				bool authCheckDone = false;
				bool passwordCollected = false;
				PrivilegeHelper privilegeHelper = FindPrivilegeHelper ();
				if (!Core->GetUseDummySudoPassword ())
				{
					// We are using -n to avoid prompting the user for a password.
					// We are redirecting stderr to stdout and discarding both to avoid any output.
					// This approach also works on newer macOS versions (12.0 and later).
					std::string popenCommand = BuildPrivilegeHelperAuthCheckCommand (privilegeHelper);
					FILE* pipe = popen(popenCommand.c_str(), "r");
					if (pipe)
					{
						// We only care about the exit code
						char buf[128];
						while (!feof(pipe))
						{
							if (fgets(buf, sizeof(buf), pipe) == NULL)
								break;
						}
						int status = pclose(pipe);
						pipe = NULL;

						authCheckDone = true;

						// If exit code != 0, user does NOT have an active session => request password
						if (status != 0)
						{
							(*AdminPasswordCallback)(request.AdminPassword);
							passwordCollected = true;
						}
					}

					if (authCheckDone)
					{
						//	Set to false to force the 'WarningEvent' to be raised in case of and elevation exception.
						request.FastElevation = false;
					}
				}
			
				try
				{
					request.Serialize (ServiceInputStream);

					unique_ptr <Serializable> response (GetResponseObject());
					if (dynamic_cast <ElevatedServiceStartedResponse *> (response.get()) != nullptr)
					{
						// The elevated channel is usable even if the forwarded request fails.
						// Any later failure must be propagated as the real error rather than
						// triggering another administrator-password prompt.
						ElevatedServiceAvailable = true;
						return GetResponse <T> ();
					}

					if (dynamic_cast <T *> (response.get()) == nullptr)
						throw ParameterIncorrect (SRC_POS);

					ElevatedServiceAvailable = true;
					return unique_ptr <T> (dynamic_cast <T *> (response.release()));
				}
				catch (ElevationFailed &e)
				{
					if (ElevatedServiceAvailable)
						throw;

					if (!request.FastElevation)
					{
						ExceptionEventArgs args (e);
						Core->WarningEvent.Raise (args);
					}

					request.FastElevation = false;

					// doas persist is tty/session scoped. If a no-password
					// attempt cannot reuse the caller tty, it may still fail
					// and require a password retry on the authentication PTY.
					if (!authCheckDone || (privilegeHelper.IsDoas() && !passwordCollected))
					{
						(*AdminPasswordCallback) (request.AdminPassword);
						passwordCollected = true;
					}
				}
			}
		}

		request.Serialize (ServiceInputStream);
		return GetResponse <T>();
	}

	void CoreService::Start ()
	{
		InputPipe.reset (new Pipe());
		OutputPipe.reset (new Pipe());

		int pid = fork();
		throw_sys_if (pid == -1);

		if (pid == 0)
		{
			try
			{
				ProcessRequests();
				_exit (0);
			}
			catch (...) { }
			_exit (1);
		}

		ServiceInputStream = shared_ptr <Stream> (new FileStream (InputPipe->GetWriteFD()));
		ServiceOutputStream = shared_ptr <Stream> (new FileStream (OutputPipe->GetReadFD()));
	}

	void CoreService::StartElevated (const CoreServiceRequest &request)
	{
		PrivilegeHelper privilegeHelper = FindPrivilegeHelper ();
		int doasAuthTerminal = -1;
		string doasAuthTerminalPath;
		bool doasNoPasswordAttempt = privilegeHelper.IsDoas() && request.AdminPassword.empty();
		bool useCallerDoasTerminal = doasNoPasswordAttempt && HasControllingTerminal();

		if (privilegeHelper.IsDoas() && !useCallerDoasTerminal)
		{
			doasAuthTerminal = OpenDoasAuthTerminal (doasAuthTerminalPath);
		}

		bool elevatedServiceStarted = false;
		finally_do_arg2 (bool *, &elevatedServiceStarted, int *, &doasAuthTerminal, { if (!*finally_arg && *finally_arg2 != -1) { close (*finally_arg2); *finally_arg2 = -1; } });

		unique_ptr <Pipe> inPipe (new Pipe());
		unique_ptr <Pipe> outPipe (new Pipe());
		Pipe errPipe;
		SetPipeCloseOnExec (*inPipe);
		SetPipeCloseOnExec (*outPipe);
		SetPipeCloseOnExec (errPipe);

		int forkedPid = fork();
		throw_sys_if (forkedPid == -1);

		if (forkedPid == 0)
		{
			try
			{
				try
				{
					std::string errorMsg;
					string appPath = request.ApplicationExecutablePath;
					// if appPath is empty or not absolute, use FindSystemBinary to get the full path of veracrpyt executable
					if (appPath.empty() || appPath[0] != '/')
					{
						appPath = Process::FindSystemBinary("veracrypt", errorMsg);
						if (appPath.empty())
							throw SystemException(SRC_POS, errorMsg);
					}

#if defined(TC_LINUX)
                    // AppImage specific handling:
                    // If running from an AppImage, use the path to the AppImage file itself for the privilege helper.
                    const char* appImageEnv = getenv("APPIMAGE");

					if (Process::IsRunningUnderAppImage(appPath) && appImageEnv != NULL)
					{
						// The path to the AppImage file is stored in the APPIMAGE environment variable.
						// We need to use this path for elevation to work correctly.
                        appPath = appImageEnv;
                    }
#endif
					bool useDoasAuthTerminal = privilegeHelper.IsDoas() && !useCallerDoasTerminal;
#ifdef TC_OPENBSD
					// OpenBSD doas requires stderr to be a terminal while it
					// prompts for the password. Keeping the private PTY slave
					// on stderr satisfies that while stdin/stdout stay as the
					// service pipes.
					bool keepDoasStderrOnAuthTerminal = useDoasAuthTerminal;
#else
					bool keepDoasStderrOnAuthTerminal = false;
#endif
					if (useDoasAuthTerminal)
					{
						AttachDoasAuthTerminal (doasAuthTerminalPath, keepDoasStderrOnAuthTerminal);
					}
					bool doasAuthTerminalReplacedByStderr = keepDoasStderrOnAuthTerminal && doasAuthTerminal == STDERR_FILENO;
					if (doasAuthTerminal != -1 && !doasAuthTerminalReplacedByStderr)
						close (doasAuthTerminal);

					if (!keepDoasStderrOnAuthTerminal)
						DupToStandardFd (errPipe.GetWriteFD(), STDERR_FILENO);
					DupToStandardFd (inPipe->GetReadFD(), STDIN_FILENO);
					DupToStandardFd (outPipe->GetWriteFD(), STDOUT_FILENO);

					const char *sudoArgs[] = { privilegeHelper.Path.c_str(), "-S", "-p", "", appPath.c_str(), TC_CORE_SERVICE_CMDLINE_OPTION, nullptr };
					const char *doasArgs[] = { privilegeHelper.Path.c_str(), appPath.c_str(), TC_CORE_SERVICE_NO_FORK_CMDLINE_OPTION, nullptr };
					const char *doasNoPasswordArgs[] = { privilegeHelper.Path.c_str(), "-n", appPath.c_str(), TC_CORE_SERVICE_NO_FORK_CMDLINE_OPTION, nullptr };
					const char **args = privilegeHelper.IsDoas() ? (doasNoPasswordAttempt ? doasNoPasswordArgs : doasArgs) : sudoArgs;
					execvp (args[0], ((char* const*) args));
					throw SystemException (SRC_POS, args[0]);
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
					shared_ptr <Stream> outputStream (new FileStream (errPipe.GetWriteFD()));
					e.Serialize (outputStream);
				}
				catch (...) { }
			}

			_exit (1);
		}

		int serviceInputFd = inPipe->GetWriteFD();
		int serviceOutputFd = outPipe->GetReadFD();

		vector <char> adminPassword (request.AdminPassword.size() + 1);
		int timeout = 6000;

		//	'request.FastElevation' is always false under Linux / FreeBSD when non-interactive auth checks work properly
		if (request.FastElevation)
		{
			string dummyPassword = "dummy\n";
			adminPassword = vector <char> (dummyPassword.size());
			Memory::Copy (&adminPassword.front(), dummyPassword.c_str(), dummyPassword.size());
			timeout = 1000;
		}
		else
		{
			Memory::Copy (&adminPassword.front(), request.AdminPassword.c_str(), request.AdminPassword.size());
			adminPassword[request.AdminPassword.size()] = '\n';
		}
		vector <char> authOutput;

#if defined(TC_LINUX )
		Thread::Sleep (1000); // wait 1 second for the forked privilege helper to start
#endif
		if (privilegeHelper.IsSudo())
		{
			if (write (serviceInputFd, &adminPassword.front(), adminPassword.size())) { } // Errors ignored
		}
		else if (doasAuthTerminal != -1 && !doasNoPasswordAttempt)
		{
			// doas reads authentication from the controlling terminal, not stdin.
#ifdef TC_OPENBSD
			WaitForDoasAuthTerminalPrompt (doasAuthTerminal, authOutput, 2000);
#endif
			WriteAllBestEffort (doasAuthTerminal, &adminPassword.front(), adminPassword.size(), 2000);
		}

		burn (&adminPassword.front(), adminPassword.size());

		throw_sys_if (fcntl (serviceOutputFd, F_SETFL, O_NONBLOCK) == -1);
		throw_sys_if (fcntl (errPipe.GetReadFD(), F_SETFL, O_NONBLOCK) == -1);

		if (privilegeHelper.IsDoas())
		{
			shared_ptr <Stream> inputStream (new FileStream (serviceInputFd));
			shared_ptr <Stream> outputStream (new FileStream (serviceOutputFd));
			int authOutputFd = -1;

#ifdef TC_OPENBSD
			if (doasAuthTerminal != -1)
			{
				int authTerminalFlags = fcntl (doasAuthTerminal, F_GETFL, 0);
				throw_sys_if (authTerminalFlags == -1);
				throw_sys_if (fcntl (doasAuthTerminal, F_SETFL, authTerminalFlags | O_NONBLOCK) == -1);
				authOutputFd = doasAuthTerminal;
			}
#endif

			SendElevatedServiceSyncWithTimeout (inputStream, serviceOutputFd, errPipe.GetReadFD(), authOutputFd, authOutput, forkedPid, privilegeHelper.Name, timeout);
			throw_sys_if (fcntl (serviceOutputFd, F_SETFL, 0) == -1);
			ReapChildProcessAsync (forkedPid);

			ServiceInputStream = inputStream;
			ServiceOutputStream = outputStream;

			AdminInputPipe = move_ptr(inPipe);
			AdminOutputPipe = move_ptr(outPipe);
			DoasAuthTerminalFd = doasAuthTerminal;
			doasAuthTerminal = -1;
			elevatedServiceStarted = true;
			return;
		}

		char buffer[4096];
		vector <char> errOutput;
		errOutput.reserve (4096);

		Poller poller (serviceOutputFd, errPipe.GetReadFD());
		int status, waitRes;
		int exitCode = 1;

		try
		{
			do
			{
				ssize_t bytesRead = 0;
				foreach (int fd, poller.WaitForData (timeout))
				{
					bytesRead = read (fd, buffer, sizeof (buffer));
					if (bytesRead > 0 && fd == errPipe.GetReadFD())
					{
						errOutput.insert (errOutput.end(), buffer, buffer + bytesRead);

						if (bytesRead > 5 && bytesRead < 80)  // Short message captured
							timeout = 200;
					}
				}

				if (bytesRead == 0)
				{
					waitRes = waitpid (forkedPid, &status, 0);
					break;
				}

			} while ((waitRes = waitpid (forkedPid, &status, WNOHANG)) == 0);
		}
		catch (TimeOut&)
		{
			if ((waitRes = waitpid (forkedPid, &status, WNOHANG)) == 0)
			{
				inPipe->Close();
				outPipe->Close();
				errPipe.Close();

				//	'request.FastElevation' is always false under Linux / FreeBSD when non-interactive auth checks work properly
				if (request.FastElevation)
				{
					// Prevent defunct process
					struct WaitFunctor : public Functor
					{
						WaitFunctor (int pid) : Pid (pid) { }
						virtual void operator() ()
						{
							int status;
							for (int t = 0; t < 10 && waitpid (Pid, &status, WNOHANG) == 0; t++)
								Thread::Sleep (1000);
						}
						int Pid;
					};
					Thread thread;
					thread.Start (new WaitFunctor (forkedPid));
					thread.Detach ();

					throw ElevationFailed (SRC_POS, privilegeHelper.Name, 1, "");
				}

				waitRes = waitpid (forkedPid, &status, 0);
			}
		}

		ThrowSerializedExceptionIfAny (errOutput);

		throw_sys_if (waitRes == -1);
		exitCode = (WIFEXITED (status) ? WEXITSTATUS (status) : 1);
		if (exitCode != 0)
		{
			string strErrOutput;

			if (!errOutput.empty())
				strErrOutput.insert (strErrOutput.begin(), errOutput.begin(), errOutput.end());

			// sudo may require a tty even if -S is used
			if (privilegeHelper.IsSudo() && strErrOutput.find (" tty") != string::npos)
				strErrOutput += "\nTo enable use of 'sudo' by applications without a terminal window, please disable 'requiretty' option in '/etc/sudoers'. Newer versions of sudo automatically determine whether a terminal is required ('requiretty' option is obsolete).";

			throw ElevationFailed (SRC_POS, privilegeHelper.Name, exitCode, strErrOutput);
		}

		throw_sys_if (fcntl (serviceOutputFd, F_SETFL, 0) == -1);

		if (privilegeHelper.IsSudo())
		{
			ServiceInputStream = shared_ptr <Stream> (new FileStream (serviceInputFd));
			ServiceOutputStream = shared_ptr <Stream> (new FileStream (serviceOutputFd));
		}

		// Send sync code (sudo path keeps the original fire-and-forget handshake)
		uint8 sync[] = { 0, 0x11, 0x22 };
		ServiceInputStream->Write (ConstBufferPtr (sync, array_capacity (sync)));

		AdminInputPipe = move_ptr(inPipe);
		AdminOutputPipe = move_ptr(outPipe);
		elevatedServiceStarted = true;
	}

	void CoreService::Stop ()
	{
		ExitRequest exitRequest;
		exitRequest.Serialize (ServiceInputStream);
	}

	shared_ptr <GetStringFunctor> CoreService::AdminPasswordCallback;

	unique_ptr <Pipe> CoreService::AdminInputPipe;
	unique_ptr <Pipe> CoreService::AdminOutputPipe;

	unique_ptr <Pipe> CoreService::InputPipe;
	unique_ptr <Pipe> CoreService::OutputPipe;
	shared_ptr <Stream> CoreService::ServiceInputStream;
	shared_ptr <Stream> CoreService::ServiceOutputStream;

	bool CoreService::ElevatedPrivileges = false;
	bool CoreService::ElevatedServiceAvailable = false;
}
