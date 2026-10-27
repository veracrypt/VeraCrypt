/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0; see License.txt.
*/

#ifndef TC_HEADER_Common_SystemEncryptionSetup
#define TC_HEADER_Common_SystemEncryptionSetup

#include <windows.h>
#include <string>
#include <vector>

// Windows feature update support of system encryption. SetupConfig.ini in the
// Default user profile tells Windows Setup to add the VeraCrypt driver to the
// new system (ReflectDrivers), and to run VeraCrypt once the update is complete
// (PostOOBE), so that it can reinstall its boot loader. Only administrators can
// modify this file and the installation directory.
namespace VeraCrypt { namespace SystemEncryptionSetup
{
	// The script that Windows Setup runs as SYSTEM after a feature update.
	inline DWORD Script (std::wstring installation, std::vector<unsigned char> &script)
	{
		script.clear ();
		while (installation.size () > 3 && installation[installation.size () - 1] == L'\\')
			installation.erase (installation.size () - 1);
		if (installation.size () < 3 || installation[1] != L':' || installation[2] != L'\\'
			|| installation.find_first_of (L"\"\r\n") != std::wstring::npos)
			return ERROR_BAD_PATHNAME;

		// cmd does not necessarily use the ANSI code page, and inherits delayed
		// expansion from its caller. Parse the ASCII preamble on separate lines
		// before reading a UTF-8 command, and never run it if chcp fails.
		std::wstring command = L"@echo off\r\nsetlocal EnableExtensions DisableDelayedExpansion\r\n";
		std::wstring path;
		bool ascii = true;
		for (size_t i = 0; i < installation.size (); ++i)
		{
			if (installation[i] > 0x7f)
				ascii = false;
			// A percent sign starts a variable reference, even between quotes.
			path += installation[i] == L'%' ? std::wstring (L"%%") : std::wstring (1, installation[i]);
		}
		// ASCII paths need no code page change. This includes the usual case of
		// a cmd process without a console, on which chcp could not operate.
		if (!ascii)
			command += L"\"%SystemRoot%\\System32\\chcp.com\" 65001 >nul\r\nif errorlevel 1 exit /b 1\r\n";
		command += L"\"" + path + L"\\VeraCrypt.exe\" /PostOOBE\r\n";

		int length = WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, command.c_str (), (int) command.size (), NULL, 0, NULL, NULL);
		if (length <= 0)
			return GetLastError ();
		script.resize (length);
		if (!WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, command.c_str (), (int) command.size (),
			reinterpret_cast<char *> (&script[0]), length, NULL, NULL))
		{
			script.clear ();
			return GetLastError ();
		}
		return ERROR_SUCCESS;
	}

	// A non-ASCII path requires a code page change in the script, which cmd can
	// only make if it has a console. Use the ASCII short name of the directory if
	// the file system provides one.
	inline std::wstring ScriptInstallationPath (const std::wstring &installation)
	{
		bool ascii = true;
		for (size_t i = 0; i < installation.size () && ascii; ++i)
			ascii = installation[i] <= 0x7f;
		if (ascii)
			return installation;
		wchar_t shortPath[MAX_PATH];
		DWORD length = GetShortPathNameW (installation.c_str (), shortPath, ARRAYSIZE (shortPath));
		if (!length || length >= ARRAYSIZE (shortPath))
			return installation;
		for (DWORD i = 0; i < length; ++i)
		{
			if (shortPath[i] > 0x7f)
				return installation;
		}
		return std::wstring (shortPath, length);
	}

	inline std::wstring NormalizePath (const std::wstring &value)
	{
		// The profile API removes enclosing quotes. Also accept a partially quoted value.
		size_t start = value.find_first_not_of (L" \t\""), end = value.find_last_not_of (L" \t\"");
		std::wstring path = start == std::wstring::npos ? std::wstring () : value.substr (start, end - start + 1);
		for (size_t i = 0; i < path.size (); ++i)
		{
			if (path[i] == L'/')
				path[i] = L'\\';
		}
		while (path.size () > 3 && path[path.size () - 1] == L'\\')
			path.erase (path.size () - 1);
		return path;
	}

	inline bool PathMatches (const std::wstring &value, const std::wstring &path)
	{
		std::wstring first = NormalizePath (value), second = NormalizePath (path);
		return !second.empty () && CompareStringOrdinal (first.c_str (), (int) first.size (),
			second.c_str (), (int) second.size (), TRUE) == CSTR_EQUAL;
	}

	// The profile API returns the default value both for a missing key and for
	// some read failures. Check that an existing file can be read, and keep it
	// open against writes while inspecting it. An absent file/key is a successful
	// empty result.
	inline DWORD GetValue (const std::wstring &file, const wchar_t *key, std::wstring &value)
	{
		value.clear ();
		HANDLE handle = CreateFileW (file.c_str (), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE)
		{
			DWORD error = GetLastError ();
			return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? ERROR_SUCCESS : error;
		}
		DWORD error = ERROR_SUCCESS;
		std::vector<wchar_t> buffer (1024);
		for (;;)
		{
			SetLastError (ERROR_SUCCESS);
			DWORD length = GetPrivateProfileStringW (L"SetupConfig", key, L"", &buffer[0], (DWORD) buffer.size (), file.c_str ());
			DWORD readError = GetLastError ();
			if (!length && readError != ERROR_SUCCESS && readError != ERROR_FILE_NOT_FOUND)
			{
				error = readError;
				break;
			}
			if (length + 1 < buffer.size ())
			{
				value.assign (&buffer[0], length);
				break;
			}
			if (buffer.size () >= 32768)
			{
				error = ERROR_MORE_DATA;
				break;
			}
			buffer.resize (buffer.size () * 2);
		}
		CloseHandle (handle);
		return error;
	}

	// A NULL value removes the key.
	inline DWORD SetValue (const std::wstring &file, const wchar_t *key, const wchar_t *value)
	{
		if (!WritePrivateProfileStringW (L"SetupConfig", key, value, file.c_str ()))
		{
			DWORD error = GetLastError ();
			return error != ERROR_SUCCESS ? error : ERROR_WRITE_FAULT;
		}
		// Flush the copy of the file that the profile API may cache.
		WritePrivateProfileStringW (NULL, NULL, NULL, file.c_str ());
		return ERROR_SUCCESS;
	}

	// The profile API stores the values of an ANSI file in the ANSI code page.
	// Convert such a file to UTF-16 so that it can store any path. The file is
	// rewritten in place to keep its permissions.
	inline DWORD ConvertToUnicode (const std::wstring &file)
	{
		HANDLE handle = CreateFileW (file.c_str (), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE)
			return GetLastError ();
		DWORD error = ERROR_SUCCESS;
		LARGE_INTEGER size;
		std::vector<unsigned char> bytes;
		if (!GetFileSizeEx (handle, &size))
			error = GetLastError ();
		else if (size.QuadPart > 1024 * 1024)
			error = ERROR_FILE_TOO_LARGE;
		else
		{
			bytes.resize ((size_t) size.QuadPart);
			DWORD count = 0;
			if (!bytes.empty () && !ReadFile (handle, &bytes[0], (DWORD) bytes.size (), &count, NULL))
				error = GetLastError ();
			else if (count != bytes.size ())
				error = ERROR_HANDLE_EOF;
		}
		// Never reinterpret a file that has a byte order mark.
		if (error == ERROR_SUCCESS && ((bytes.size () >= 2 && ((bytes[0] == 0xff && bytes[1] == 0xfe) || (bytes[0] == 0xfe && bytes[1] == 0xff)))
			|| (bytes.size () >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf)))
			error = ERROR_NO_UNICODE_TRANSLATION;
		std::wstring text;
		if (error == ERROR_SUCCESS && !bytes.empty ())
		{
			const char *ansi = reinterpret_cast<const char *> (&bytes[0]);
			int length = MultiByteToWideChar (CP_ACP, 0, ansi, (int) bytes.size (), NULL, 0);
			if (length <= 0)
				error = GetLastError ();
			else
			{
				text.resize (length);
				if (!MultiByteToWideChar (CP_ACP, 0, ansi, (int) bytes.size (), &text[0], length))
					error = GetLastError ();
			}
		}
		if (error == ERROR_SUCCESS)
		{
			std::vector<unsigned char> unicode;
			unicode.push_back (0xff);
			unicode.push_back (0xfe);
			for (size_t i = 0; i < text.size (); ++i)
			{
				unicode.push_back ((unsigned char) (text[i] & 0xff));
				unicode.push_back ((unsigned char) (text[i] >> 8));
			}
			LARGE_INTEGER start = {};
			DWORD written = 0;
			if (!SetFilePointerEx (handle, start, NULL, FILE_BEGIN)
				|| !WriteFile (handle, &unicode[0], (DWORD) unicode.size (), &written, NULL)
				|| !SetEndOfFile (handle)
				|| !FlushFileBuffers (handle))
				error = GetLastError ();
			else if (written != unicode.size ())
				error = ERROR_WRITE_FAULT;
		}
		CloseHandle (handle);
		return error;
	}

	struct Registration
	{
		std::wstring Directory;					// Contains SetupConfig.ini
		std::wstring Drivers;					// ReflectDrivers: the installation directory
		std::wstring Script;					// PostOOBE
		std::vector<std::wstring> OwnedDrivers;	// Values that VeraCrypt removes
		std::vector<std::wstring> OwnedScripts;
	};

	inline std::wstring ConfigPath (const Registration &registration)
	{
		return registration.Directory + L"\\SetupConfig.ini";
	}

	// While system encryption is active, VeraCrypt owns ReflectDrivers and
	// PostOOBE, as Windows Setup supports a single value for each of them.
	// Values are written only if they change. PostOOBE is written first, as it
	// replaces the script of VeraCrypt 1.26.29 and older, and a failure to write
	// one value does not prevent writing the other one.
	inline DWORD Register (const Registration &registration)
	{
		if (!CreateDirectoryW (registration.Directory.c_str (), NULL) && GetLastError () != ERROR_ALREADY_EXISTS)
			return GetLastError ();
		const std::wstring file = ConfigPath (registration);
		const wchar_t *keys[] = { L"PostOOBE", L"ReflectDrivers" };
		const std::wstring *values[] = { &registration.Script, &registration.Drivers };
		DWORD result = ERROR_SUCCESS;
		for (size_t i = 0; i < ARRAYSIZE (keys); ++i)
		{
			std::wstring value;
			DWORD error = GetValue (file, keys[i], value);
			if (error == ERROR_SUCCESS && PathMatches (value, *values[i]))
				continue;
			const std::wstring quoted = L"\"" + *values[i] + L"\"";
			if (error == ERROR_SUCCESS)
				error = SetValue (file, keys[i], quoted.c_str ());
			if (error == ERROR_SUCCESS)
				error = GetValue (file, keys[i], value);
			if (error == ERROR_SUCCESS && !PathMatches (value, *values[i]))
			{
				error = ConvertToUnicode (file);
				if (error == ERROR_SUCCESS)
					error = SetValue (file, keys[i], quoted.c_str ());
				if (error == ERROR_SUCCESS)
					error = GetValue (file, keys[i], value);
				if (error == ERROR_SUCCESS && !PathMatches (value, *values[i]))
					error = ERROR_NO_UNICODE_TRANSLATION;
			}
			if (result == ERROR_SUCCESS)
				result = error;
		}
		return result;
	}

	// Remove only the values that VeraCrypt recognizes as its own. PostOOBE is
	// removed first, as it can name the script of VeraCrypt 1.26.29 and older, and
	// a failure to remove one value does not prevent removing the other one.
	inline DWORD Unregister (const Registration &registration)
	{
		const std::wstring file = ConfigPath (registration);
		if (GetFileAttributesW (file.c_str ()) == INVALID_FILE_ATTRIBUTES)
		{
			DWORD error = GetLastError ();
			return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? ERROR_SUCCESS : error;
		}
		const wchar_t *keys[] = { L"PostOOBE", L"ReflectDrivers" };
		const std::vector<std::wstring> *owned[] = { &registration.OwnedScripts, &registration.OwnedDrivers };
		DWORD result = ERROR_SUCCESS;
		for (size_t i = 0; i < ARRAYSIZE (keys); ++i)
		{
			// The profile API only returns the first of duplicated keys.
			DWORD error = ERROR_SUCCESS;
			for (int removed = 0; error == ERROR_SUCCESS; ++removed)
			{
				std::wstring value;
				error = GetValue (file, keys[i], value);
				if (error != ERROR_SUCCESS)
					break;
				bool ours = false;
				for (size_t j = 0; j < owned[i]->size () && !ours; ++j)
					ours = PathMatches (value, (*owned[i])[j]);
				if (!ours)
					break;
				error = removed == 16 ? ERROR_CAN_NOT_COMPLETE : SetValue (file, keys[i], NULL);
			}
			if (result == ERROR_SUCCESS)
				result = error;
		}
		return result;
	}

} }

#endif
