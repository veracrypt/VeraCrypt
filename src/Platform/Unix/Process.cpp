/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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

namespace TrueCrypt
{
	string Process::Execute (const string &processName, const list <string> &arguments, int timeOut, ProcessExecFunctor *execFunctor, const Buffer *inputData)
	{
		char *args[32];
		if (array_capacity (args) <= arguments.size())
			throw ParameterTooLarge (SRC_POS);

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

					foreach (const string &arg, arguments)
					{
						args[argIndex++] = const_cast <char*> (arg.c_str());
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
		buffer.clear ();
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
			auto_ptr <Serializable> deserializedObject;
			Exception *deserializedException = nullptr;

			try
			{
				shared_ptr <Stream> stream (new MemoryStream (ConstBufferPtr ((byte *) &exOutput[0], exOutput.size())));
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
