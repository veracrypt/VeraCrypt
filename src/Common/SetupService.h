/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0; see License.txt.
*/

#ifndef TC_HEADER_Common_SetupService
#define TC_HEADER_Common_SetupService

#include <windows.h>
#include <cwchar>
#include <string>

namespace VeraCrypt { namespace SetupService
{

	class ProcessHandle
	{
	public:
		ProcessHandle () : Value (NULL) { }
		~ProcessHandle () { if (Value) CloseHandle (Value); }
		HANDLE Value;
	private:
		ProcessHandle (const ProcessHandle &);
		ProcessHandle &operator= (const ProcessHandle &);
	};

	// The caller holds SERVICE_QUERY_STATUS and SERVICE_START/SERVICE_STOP.
	// Return error codes explicitly so handle cleanup cannot mask the failure.
	inline DWORD ChangeState (SC_HANDLE service, bool start, DWORD argc, LPCWSTR *argv)
	{
		const DWORD timeout = 120000;
		const DWORD expected = start ? SERVICE_RUNNING : SERVICE_STOPPED;
		const DWORD pending = start ? SERVICE_START_PENDING : SERVICE_STOP_PENDING;
		DWORD began = GetTickCount (), lastProgress = began, checkpoint = 0, previousState = 0;
		bool stopRequested = false;
		ProcessHandle process;
		if (start && !StartServiceW (service, argc, argv))
		{
			DWORD error = GetLastError ();
			if (error != ERROR_SERVICE_ALREADY_RUNNING) return error;
		}

		for (;;)
		{
			SERVICE_STATUS_PROCESS status = {};
			DWORD bytes;
			if (!QueryServiceStatusEx (service, SC_STATUS_PROCESS_INFO,
				reinterpret_cast<LPBYTE> (&status), sizeof (status), &bytes)) return GetLastError ();

			if (status.dwCurrentState == expected)
			{
				if (!start && process.Value)
				{
					// SERVICE_STOPPED can precede process exit and image unmapping.
					DWORD elapsed = GetTickCount () - began;
					DWORD wait = WaitForSingleObject (process.Value, elapsed < timeout ? timeout - elapsed : 0);
					if (wait == WAIT_FAILED) return GetLastError ();
					if (wait != WAIT_OBJECT_0) return ERROR_SERVICE_REQUEST_TIMEOUT;
				}
				return ERROR_SUCCESS;
			}

			bool acceptsStop = status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED
				|| status.dwCurrentState == SERVICE_PAUSE_PENDING || status.dwCurrentState == SERVICE_CONTINUE_PENDING;
			if (!start && !stopRequested && acceptsStop)
			{
				// Capture the process BEFORE requesting stop: its PID is not valid
				// in SERVICE_STOPPED, and can be invalid in pending start/stop states.
				// Never wait for the lifetime of a shared service host.
				if ((status.dwServiceType & SERVICE_WIN32_OWN_PROCESS) && status.dwProcessId)
				{
					process.Value = OpenProcess (SYNCHRONIZE, FALSE, status.dwProcessId);
					if (!process.Value)
					{
						DWORD error = GetLastError ();
						// The process may have exited between the status query and open.
						if (error != ERROR_INVALID_PARAMETER) return error;
					}
				}
				SERVICE_STATUS stopped = {};
				if (!ControlService (service, SERVICE_CONTROL_STOP, &stopped))
				{
					DWORD error = GetLastError ();
					if (error != ERROR_SERVICE_NOT_ACTIVE) return error;
				}
				stopRequested = true;
				lastProgress = GetTickCount ();
				previousState = 0;
				continue;
			}

			if (status.dwCurrentState != pending
				&& !(status.dwCurrentState == SERVICE_START_PENDING && !start && !stopRequested)
				&& !(!start && stopRequested && acceptsStop))
				return status.dwWin32ExitCode ? status.dwWin32ExitCode : ERROR_SERVICE_REQUEST_TIMEOUT;

			DWORD now = GetTickCount ();
			if (status.dwCurrentState != previousState || status.dwCheckPoint > checkpoint)
			{
				lastProgress = now;
				checkpoint = status.dwCheckPoint;
				previousState = status.dwCurrentState;
			}
			if (now - began >= timeout || now - lastProgress >= (status.dwWaitHint ? status.dwWaitHint : 3000))
				return ERROR_SERVICE_REQUEST_TIMEOUT;
			Sleep (100);
		}
	}

	inline bool FileBusy (DWORD error)
	{
		return error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED || error == ERROR_USER_MAPPED_FILE;
	}

	inline std::wstring TemporaryName (const std::wstring &path, const wchar_t *kind, DWORD attempt)
	{
		wchar_t suffix[96];
		swprintf_s (suffix, ARRAYSIZE (suffix), L".setup-%s.%lu.%llu.%lu", kind,
			GetCurrentProcessId (), GetTickCount64 (), attempt);
		return path + suffix;
	}

	// The source is the executable of the installation directory. The destination
	// is the service executable in the native system directory. Stage there so
	// publication is a same-volume rename, and never truncate the working service
	// executable on a failed copy.
	inline DWORD ReplaceExecutable (const std::wstring &source, const std::wstring &destination)
	{
		std::wstring staged;
		bool reserved = false;
		for (DWORD attempt = 0; attempt < 16; ++attempt)
		{
			staged = TemporaryName (destination, L"new", attempt);
			HANDLE file = CreateFileW (staged.c_str (), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file != INVALID_HANDLE_VALUE)
			{
				CloseHandle (file);
				reserved = true;
				break;
			}
			DWORD error = GetLastError ();
			if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) return error;
		}
		if (!reserved) return ERROR_FILE_EXISTS;

		DWORD error = ERROR_SUCCESS;
		if (!CopyFileW (source.c_str (), staged.c_str (), FALSE))
			error = GetLastError ();
		else
		{
			DWORD began = GetTickCount ();
			for (;;)
			{
				if (MoveFileExW (staged.c_str (), destination.c_str (), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
					return ERROR_SUCCESS;
				error = GetLastError ();
				if (!FileBusy (error) || GetTickCount () - began >= 5000) break;
				Sleep (100);
			}

			if (FileBusy (error))
			{
				// A lingering image mapping can prevent replacement but permit a
				// rename. Keep a unique backup; never overwrite an earlier backup.
				std::wstring backup;
				bool moved = false;
				for (DWORD attempt = 0; attempt < 16; ++attempt)
				{
					backup = TemporaryName (destination, L"old", attempt);
					if (MoveFileExW (destination.c_str (), backup.c_str (), MOVEFILE_WRITE_THROUGH))
					{
						moved = true;
						break;
					}
					error = GetLastError ();
					if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) break;
				}
				if (moved)
				{
					// Do not overwrite a file created by another installer meanwhile.
					if (MoveFileExW (staged.c_str (), destination.c_str (), MOVEFILE_WRITE_THROUGH))
					{
						// Cleanup failure does not invalidate the published executable.
						if (!DeleteFileW (backup.c_str ()))
							MoveFileExW (backup.c_str (), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
						return ERROR_SUCCESS;
					}
					error = GetLastError ();
					if (!MoveFileExW (backup.c_str (), destination.c_str (), MOVEFILE_WRITE_THROUGH))
						// Preserve the backup on failed restoration and report failure.
						error = GetLastError ();
				}
			}
		}
		DeleteFileW (staged.c_str ());
		return error;
	}

	// Replace the executable when Windows restarts, e.g. because the old service
	// process could not be stopped.
	inline DWORD ScheduleReplacement (const std::wstring &source, const std::wstring &destination)
	{
		for (DWORD attempt = 0; attempt < 16; ++attempt)
		{
			std::wstring staged = TemporaryName (destination, L"pending", attempt);
			if (!CopyFileW (source.c_str (), staged.c_str (), TRUE))
			{
				DWORD error = GetLastError ();
				if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
					return error;
				continue;
			}
			if (MoveFileExW (staged.c_str (), destination.c_str (), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING))
				return ERROR_SUCCESS;
			DWORD error = GetLastError ();
			DeleteFileW (staged.c_str ());
			return error;
		}
		return ERROR_FILE_EXISTS;
	}

	// Delete the copies staged by ScheduleReplacement, e.g. at uninstallation, so
	// that none of them replaces the executable when Windows restarts. Returns
	// false if one of them may remain.
	inline bool DeletePendingReplacements (const std::wstring &destination)
	{
		size_t separator = destination.find_last_of (L'\\');
		const std::wstring directory = separator == std::wstring::npos ? std::wstring () : destination.substr (0, separator + 1);
		WIN32_FIND_DATAW data;
		HANDLE find = FindFirstFileW ((destination + L".setup-pending.*").c_str (), &data);
		if (find == INVALID_HANDLE_VALUE)
		{
			DWORD error = GetLastError ();
			return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
		}
		bool deleted = true;
		do
		{
			if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !DeleteFileW ((directory + data.cFileName).c_str ()))
				deleted = false;
		}
		while (FindNextFileW (find, &data));
		FindClose (find);
		return deleted;
	}

	// Returns ERROR_SUCCESS_REBOOT_REQUIRED if the executable will be replaced
	// when Windows restarts, or the error of the failed replacement.
	inline DWORD UpdateExecutable (const std::wstring &source, const std::wstring &destination)
	{
		DWORD error = ReplaceExecutable (source, destination);
		if (error == ERROR_SUCCESS)
		{
			// A copy staged by an earlier installation would otherwise replace this
			// executable when Windows restarts.
			DeletePendingReplacements (destination);
			return ERROR_SUCCESS;
		}
		return ScheduleReplacement (source, destination) == ERROR_SUCCESS ? ERROR_SUCCESS_REBOOT_REQUIRED : error;
	}

} }

#endif
