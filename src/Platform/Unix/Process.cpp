/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
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
#include "Platform/FileStream.h"
#include "Platform/ForEach.h"
#include "Platform/MemoryStream.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include "Platform/Unix/Pipe.h"
#include "Platform/Unix/Poller.h"

namespace VeraCrypt
{

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

		// Default system directories to search for executables
#ifdef TC_MACOSX
		const char* defaultDirs[] = {"/usr/local/bin", "/usr/bin", "/bin", "/user/sbin", "/sbin"};
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
}
