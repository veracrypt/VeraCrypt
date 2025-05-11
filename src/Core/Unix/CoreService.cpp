/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "CoreService.h"
#include <fcntl.h>
#include <sys/wait.h>
#include <stdio.h>
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"
#include "Platform/Thread.h"
#include "Platform/Unix/Poller.h"
#include "Core/Core.h"
#include "CoreUnix.h"
#include "CoreServiceRequest.h"
#include "CoreServiceResponse.h"

namespace VeraCrypt
{
	template <class T>
	unique_ptr <T> CoreService::GetResponse ()
	{
		unique_ptr <Serializable> deserializedObject (Serializable::DeserializeNew (ServiceOutputStream));

		Exception *deserializedException = dynamic_cast <Exception*> (deserializedObject.get());
		if (deserializedException)
			deserializedException->Throw();

		if (dynamic_cast <T *> (deserializedObject.get()) == nullptr)
			throw ParameterIncorrect (SRC_POS);

		return unique_ptr <T> (dynamic_cast <T *> (deserializedObject.release()));
	}

	void CoreService::ProcessElevatedRequests ()
	{
		int pid = fork();
		throw_sys_if (pid == -1);
		if (pid == 0)
		{
			try
			{
				int f = open ("/dev/null", 0);
				throw_sys_sub_if (f == -1, "/dev/null");
				throw_sys_if (dup2 (f, STDERR_FILENO) == -1);

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
						if (!ElevatedServiceAvailable)
						{
							finally_do_arg (string *, &request->AdminPassword, { StringConverter::Erase (*finally_arg); });

							CoreService::StartElevated (*request);
							ElevatedServiceAvailable = true;
						}

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

		if (request.RequiresElevation())
		{
			request.ElevateUserPrivileges = true;
			request.FastElevation = !ElevatedServiceAvailable;
			
			while (!ElevatedServiceAvailable)
			{
				//	Test if the user has an active "sudo" session.
				bool authCheckDone = false;
				if (!Core->GetUseDummySudoPassword ())
				{	
					// We are using -n to avoid prompting the user for a password.
					// We are redirecting stderr to stdout and discarding both to avoid any output.
					// This approach also works on newer macOS versions (12.0 and later).
					std::string errorMsg;

					string sudoAbsolutePath = Process::FindSystemBinary("sudo", errorMsg);
					if (sudoAbsolutePath.empty())
						throw SystemException(SRC_POS, errorMsg);

					string trueAbsolutePath = Process::FindSystemBinary("true", errorMsg);
					if (trueAbsolutePath.empty())
						throw SystemException(SRC_POS, errorMsg);

					std::string popenCommand = sudoAbsolutePath + " -n " + trueAbsolutePath + " > /dev/null 2>&1";	//	We redirect stderr to stdout (2>&1) to be able to catch the result of the command
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
					unique_ptr <T> response (GetResponse <T>());
					ElevatedServiceAvailable = true;
					return response;
				}
				catch (ElevationFailed &e)
				{
					if (!request.FastElevation)
					{
						ExceptionEventArgs args (e);
						Core->WarningEvent.Raise (args);
					}

					request.FastElevation = false;

					if(!authCheckDone)
						(*AdminPasswordCallback) (request.AdminPassword);
				}
			}
		}

		finally_do_arg (string *, &request.AdminPassword, { StringConverter::Erase (*finally_arg); });

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
		unique_ptr <Pipe> inPipe (new Pipe());
		unique_ptr <Pipe> outPipe (new Pipe());
		Pipe errPipe;

		int forkedPid = fork();
		throw_sys_if (forkedPid == -1);

		if (forkedPid == 0)
		{
			try
			{
				try
				{
					// Throw exception if sudo is not found in secure locations
					std::string errorMsg;
					string sudoPath = Process::FindSystemBinary("sudo", errorMsg);
					if (sudoPath.empty())
						throw SystemException(SRC_POS, errorMsg);

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
                    // If running from an AppImage, use the path to the AppImage file itself for sudo.
                    const char* appImageEnv = getenv("APPIMAGE");

                    if (Process::IsRunningUnderAppImage(appPath) && appImageEnv != NULL)
					{
						// The path to the AppImage file is stored in the APPIMAGE environment variable.
						// We need to use this path for sudo to work correctly.
                        appPath = appImageEnv;
                    }
#endif
					throw_sys_if (dup2 (inPipe->GetReadFD(), STDIN_FILENO) == -1);
					throw_sys_if (dup2 (outPipe->GetWriteFD(), STDOUT_FILENO) == -1);
					throw_sys_if (dup2 (errPipe.GetWriteFD(), STDERR_FILENO) == -1);

					const char *args[] = { sudoPath.c_str(), "-S", "-p", "", appPath.c_str(), TC_CORE_SERVICE_CMDLINE_OPTION, nullptr };
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

		vector <char> adminPassword (request.AdminPassword.size() + 1);
		int timeout = 6000;

		//	'request.FastElevation' is always false under Linux / FreeBSD when "sudo -n" works properly
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

#if defined(TC_LINUX )
		Thread::Sleep (1000); // wait 1 second for the forked sudo to start
#endif
		if (write (inPipe->GetWriteFD(), &adminPassword.front(), adminPassword.size())) { } // Errors ignored

		burn (&adminPassword.front(), adminPassword.size());

		throw_sys_if (fcntl (outPipe->GetReadFD(), F_SETFL, O_NONBLOCK) == -1);
		throw_sys_if (fcntl (errPipe.GetReadFD(), F_SETFL, O_NONBLOCK) == -1);

		vector <char> buffer (4096), errOutput (4096);
		buffer.clear ();
		errOutput.clear ();

		Poller poller (outPipe->GetReadFD(), errPipe.GetReadFD());
		int status, waitRes;
		int exitCode = 1;

		try
		{
			do
			{
				ssize_t bytesRead = 0;
				foreach (int fd, poller.WaitForData (timeout))
				{
					bytesRead = read (fd, &buffer[0], buffer.capacity());
					if (bytesRead > 0 && fd == errPipe.GetReadFD())
					{
						errOutput.insert (errOutput.end(), buffer.begin(), buffer.begin() + bytesRead);

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

				//	'request.FastElevation' is always false under Linux / FreeBSD
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

					throw ElevationFailed (SRC_POS, "sudo", 1, "");
				}

				waitRes = waitpid (forkedPid, &status, 0);
			}
		}

		if (!errOutput.empty())
		{
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

		throw_sys_if (waitRes == -1);
		exitCode = (WIFEXITED (status) ? WEXITSTATUS (status) : 1);
		if (exitCode != 0)
		{
			string strErrOutput;

			if (!errOutput.empty())
				strErrOutput.insert (strErrOutput.begin(), errOutput.begin(), errOutput.end());

			// sudo may require a tty even if -S is used
			if (strErrOutput.find (" tty") != string::npos)
				strErrOutput += "\nTo enable use of 'sudo' by applications without a terminal window, please disable 'requiretty' option in '/etc/sudoers'. Newer versions of sudo automatically determine whether a terminal is required ('requiretty' option is obsolete).";

			throw ElevationFailed (SRC_POS, "sudo", exitCode, strErrOutput);
		}

		throw_sys_if (fcntl (outPipe->GetReadFD(), F_SETFL, 0) == -1);

		ServiceInputStream = shared_ptr <Stream> (new FileStream (inPipe->GetWriteFD()));
		ServiceOutputStream = shared_ptr <Stream> (new FileStream (outPipe->GetReadFD()));

		// Send sync code
		uint8 sync[] = { 0, 0x11, 0x22 };
		ServiceInputStream->Write (ConstBufferPtr (sync, array_capacity (sync)));

		AdminInputPipe = move_ptr(inPipe);
		AdminOutputPipe = move_ptr(outPipe);
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
