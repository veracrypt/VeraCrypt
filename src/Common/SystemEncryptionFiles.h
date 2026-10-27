/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0; see License.txt.
*/

#ifndef TC_HEADER_Common_SystemEncryptionFiles
#define TC_HEADER_Common_SystemEncryptionFiles

#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <authz.h>
#include <sddl.h>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

// Support files of system encryption: the script that Windows Setup runs after
// a feature update, and the backup of the original system loader.
//
// Current files are stored in the VeraCryptSystem directory of the native
// Common Files folder. As in the installation directory, only administrators
// can create or modify objects there, so these files are used as they are.
//
// VeraCrypt 1.26.29 and older stored them in %ProgramData%\VeraCrypt, where
// standard users can create files and directories. Nothing is executed from
// there anymore, and an old loader backup is only used if its owner and its
// permissions show that only an administrator could have written it.
namespace VeraCrypt { namespace SystemEncryptionFiles
{
	class Handle
	{
	public:
		explicit Handle (HANDLE value = INVALID_HANDLE_VALUE) : Value (value) { }
		~Handle () { if (Value != INVALID_HANDLE_VALUE) CloseHandle (Value); }
		HANDLE Value;
	private:
		Handle (const Handle &);
		Handle &operator= (const Handle &);
	};

	class SecurityDescriptor
	{
	public:
		SecurityDescriptor () : Value (NULL) { }
		~SecurityDescriptor () { if (Value) LocalFree (Value); }
		PSECURITY_DESCRIPTOR Value;
	private:
		SecurityDescriptor (const SecurityDescriptor &);
		SecurityDescriptor &operator= (const SecurityDescriptor &);
	};

	inline bool Missing (DWORD error)
	{
		return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
	}

	// Enable the backup, restore and take ownership privileges of the caller while
	// this object exists. Opened with backup semantics, a directory can then be
	// secured even if a standard user who owns it denied access to administrators.
	// Privileges that the caller does not hold are ignored.
	class AdministratorPrivileges
	{
	public:
		AdministratorPrivileges () : Token (NULL), Changed (false), Previous (sizeof (TOKEN_PRIVILEGES) + 2 * sizeof (LUID_AND_ATTRIBUTES))
		{
			if (!OpenThreadToken (GetCurrentThread (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &Token))
			{
				Token = NULL;
				if (GetLastError () != ERROR_NO_TOKEN || !OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
				{
					Token = NULL;
					return;
				}
			}
			const wchar_t *names[] = { L"SeBackupPrivilege", L"SeRestorePrivilege", L"SeTakeOwnershipPrivilege" };
			std::vector<unsigned char> buffer (Previous.size ());
			TOKEN_PRIVILEGES *privileges = reinterpret_cast<TOKEN_PRIVILEGES *> (&buffer[0]);
			privileges->PrivilegeCount = 0;
			for (size_t i = 0; i < ARRAYSIZE (names); ++i)
			{
				LUID luid;
				if (LookupPrivilegeValueW (NULL, names[i], &luid))
				{
					privileges->Privileges[privileges->PrivilegeCount].Luid = luid;
					privileges->Privileges[privileges->PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;
					++privileges->PrivilegeCount;
				}
			}
			// The previous state lists only the privileges that were changed.
			DWORD size = (DWORD) Previous.size ();
			Changed = privileges->PrivilegeCount != 0
				&& AdjustTokenPrivileges (Token, FALSE, privileges, size, reinterpret_cast<TOKEN_PRIVILEGES *> (&Previous[0]), &size) != FALSE;
		}

		~AdministratorPrivileges ()
		{
			if (Changed)
				AdjustTokenPrivileges (Token, FALSE, reinterpret_cast<TOKEN_PRIVILEGES *> (&Previous[0]), 0, NULL, NULL);
			if (Token)
				CloseHandle (Token);
		}

	private:
		AdministratorPrivileges (const AdministratorPrivileges &);
		AdministratorPrivileges &operator= (const AdministratorPrivileges &);
		HANDLE Token;
		bool Changed;
		std::vector<unsigned char> Previous;
	};

	// Owned by Administrators, with full control for SYSTEM and Administrators.
	// Users can read: the rescue disk wizard reads the loader backup unelevated.
	// Specific rights are used, as Windows stores generic rights mapped to them.
	inline DWORD NewSecurity (SecurityDescriptor &descriptor, bool directory)
	{
		return ConvertStringSecurityDescriptorToSecurityDescriptorW (directory
			? L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
			: L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
			SDDL_REVISION_1, &descriptor.Value, NULL) ? ERROR_SUCCESS : GetLastError ();
	}

	// Whether an object already has the DACL, and optionally the owner, of a
	// security descriptor. This avoids rewriting its metadata on every call.
	inline bool HasSecurity (HANDLE handle, PSECURITY_DESCRIPTOR descriptor, bool owner)
	{
		SecurityDescriptor current;
		PSID currentOwner = NULL, expectedOwner = NULL;
		PACL currentDacl = NULL, expectedDacl = NULL;
		BOOL present = FALSE, defaulted = FALSE;
		SECURITY_DESCRIPTOR_CONTROL currentControl = 0, expectedControl = 0;
		DWORD revision;
		if (GetSecurityInfo (handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
				&currentOwner, NULL, &currentDacl, NULL, &current.Value) != ERROR_SUCCESS
			|| !GetSecurityDescriptorDacl (descriptor, &present, &expectedDacl, &defaulted)
			|| !GetSecurityDescriptorOwner (descriptor, &expectedOwner, &defaulted)
			|| !GetSecurityDescriptorControl (descriptor, &expectedControl, &revision)
			|| !GetSecurityDescriptorControl (current.Value, &currentControl, &revision)
			|| !present || !expectedDacl || !currentDacl
			|| ((currentControl ^ expectedControl) & SE_DACL_PROTECTED)
			|| currentDacl->AceCount != expectedDacl->AceCount)
			return false;
		if (owner && (!currentOwner || !expectedOwner || !EqualSid (currentOwner, expectedOwner)))
			return false;
		for (DWORD i = 0; i < expectedDacl->AceCount; ++i)
		{
			ACE_HEADER *currentAce, *expectedAce;
			if (!GetAce (currentDacl, i, reinterpret_cast<void **> (&currentAce))
				|| !GetAce (expectedDacl, i, reinterpret_cast<void **> (&expectedAce))
				|| currentAce->AceSize != expectedAce->AceSize
				|| memcmp (currentAce, expectedAce, expectedAce->AceSize) != 0)
				return false;
		}
		return true;
	}

	inline DWORD Read (HANDLE file, std::vector<unsigned char> &data, DWORD maxSize)
	{
		data.clear ();
		LARGE_INTEGER size;
		if (!GetFileSizeEx (file, &size))
			return GetLastError ();
		if (size.QuadPart < 0 || size.QuadPart > maxSize)
			return ERROR_FILE_TOO_LARGE;
		data.resize (static_cast<size_t> (size.QuadPart));
		DWORD count = 0;
		if (!data.empty () && !::ReadFile (file, &data[0], static_cast<DWORD> (data.size ()), &count, NULL))
		{
			DWORD error = GetLastError ();
			data.clear ();
			return error;
		}
		if (count != data.size ())
		{
			data.clear ();
			return ERROR_HANDLE_EOF;
		}
		return ERROR_SUCCESS;
	}

	// Writers are excluded while the file is read.
	inline DWORD ReadWhole (const std::wstring &path, std::vector<unsigned char> &data, DWORD maxSize)
	{
		data.clear ();
		Handle file (CreateFileW (path.c_str (), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL));
		if (file.Value == INVALID_HANDLE_VALUE)
			return GetLastError ();
		return Read (file.Value, data, maxSize);
	}

	// Replace a file of a directory prepared by PrepareDirectory with a new file
	// that has the given security, whatever the permissions of the replaced file.
	// Nothing is written if the file already has this content.
	inline DWORD WriteWhole (const std::wstring &directory, const wchar_t *name, const unsigned char *data, DWORD size,
		PSECURITY_DESCRIPTOR descriptor)
	{
		if (size && !data)
			return ERROR_INVALID_PARAMETER;
		const std::wstring path = directory + L"\\" + name;
		std::vector<unsigned char> current;
		if (ReadWhole (path, current, size) == ERROR_SUCCESS && current.size () == size
			&& (size == 0 || memcmp (&current[0], data, size) == 0))
			return ERROR_SUCCESS;

		SECURITY_ATTRIBUTES attributes = { sizeof (attributes), descriptor, FALSE };
		std::wstring temporary;
		Handle file;
		for (DWORD attempt = 0; attempt < 16 && file.Value == INVALID_HANDLE_VALUE; ++attempt)
		{
			wchar_t suffix[64];
			swprintf_s (suffix, ARRAYSIZE (suffix), L".%lu.%llu.%lu.tmp", GetCurrentProcessId (), GetTickCount64 (), attempt);
			temporary = path + suffix;
			file.Value = CreateFileW (temporary.c_str (), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file.Value == INVALID_HANDLE_VALUE && GetLastError () != ERROR_FILE_EXISTS)
				return GetLastError ();
		}
		if (file.Value == INVALID_HANDLE_VALUE)
			return ERROR_FILE_EXISTS;

		DWORD error = ERROR_SUCCESS, written = 0;
		if (size && !::WriteFile (file.Value, data, size, &written, NULL))
			error = GetLastError ();
		else if (written != size)
			error = ERROR_WRITE_FAULT;
		else if (!FlushFileBuffers (file.Value))
			error = GetLastError ();
		CloseHandle (file.Value);
		file.Value = INVALID_HANDLE_VALUE;

		// A virus scanner can briefly keep the replaced file open.
		for (DWORD attempt = 0; error == ERROR_SUCCESS; ++attempt)
		{
			if (MoveFileExW (temporary.c_str (), path.c_str (), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
				return ERROR_SUCCESS;
			error = GetLastError ();
			if ((error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) && attempt < 20)
			{
				error = ERROR_SUCCESS;
				Sleep (100);
			}
		}
		DeleteFileW (temporary.c_str ());
		return error;
	}

	inline bool IsTrustedInstallerSid (PSID sid)
	{
		static const SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
		static const DWORD installer[] = { 80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464 };
		if (*GetSidSubAuthorityCount (sid) != ARRAYSIZE (installer)
			|| memcmp (GetSidIdentifierAuthority (sid), &authority, sizeof (authority)) != 0)
			return false;
		for (DWORD i = 0; i < ARRAYSIZE (installer); ++i)
			if (*GetSidSubAuthority (sid, i) != installer[i])
				return false;
		return true;
	}

	// Whether only administrators can act as this principal: SYSTEM, the
	// Administrators group, TrustedInstaller, or an account that currently is a
	// member of the Administrators group. In VeraCrypt 1.26.29 and older, the
	// unelevated system encryption wizard created BIOS loader backups owned by
	// the account of the administrator who encrypted the system.
	inline bool IsAdministratorSid (PSID sid)
	{
		if (!sid || !IsValidSid (sid))
			return false;
		if (IsWellKnownSid (sid, WinLocalSystemSid) || IsWellKnownSid (sid, WinBuiltinAdministratorsSid) || IsTrustedInstallerSid (sid))
			return true;

		// authz.dll is not a known DLL. Load it from System32 only: a static import
		// would be searched first in the directory of the executable, such as the
		// download directory of the installer.
		static HMODULE authz = LoadLibraryExW (L"authz.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!authz)
			return false;
		decltype (&AuthzInitializeResourceManager) initializeResourceManager = reinterpret_cast<decltype (&AuthzInitializeResourceManager)> (GetProcAddress (authz, "AuthzInitializeResourceManager"));
		decltype (&AuthzInitializeContextFromSid) initializeContextFromSid = reinterpret_cast<decltype (&AuthzInitializeContextFromSid)> (GetProcAddress (authz, "AuthzInitializeContextFromSid"));
		decltype (&AuthzGetInformationFromContext) getInformationFromContext = reinterpret_cast<decltype (&AuthzGetInformationFromContext)> (GetProcAddress (authz, "AuthzGetInformationFromContext"));
		decltype (&AuthzFreeContext) freeContext = reinterpret_cast<decltype (&AuthzFreeContext)> (GetProcAddress (authz, "AuthzFreeContext"));
		decltype (&AuthzFreeResourceManager) freeResourceManager = reinterpret_cast<decltype (&AuthzFreeResourceManager)> (GetProcAddress (authz, "AuthzFreeResourceManager"));
		if (!initializeResourceManager || !initializeContextFromSid || !getInformationFromContext || !freeContext || !freeResourceManager)
			return false;

		AUTHZ_RESOURCE_MANAGER_HANDLE manager = NULL;
		if (!initializeResourceManager (AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, NULL, &manager))
			return false;
		bool administrator = false;
		AUTHZ_CLIENT_CONTEXT_HANDLE context = NULL;
		LUID unused = { 0, 0 };
		if (initializeContextFromSid (0, sid, manager, NULL, unused, NULL, &context))
		{
			DWORD size = 0;
			getInformationFromContext (context, AuthzContextInfoGroupsSids, 0, &size, NULL);
			std::vector<unsigned char> buffer (size);
			if (size >= sizeof (TOKEN_GROUPS) && getInformationFromContext (context, AuthzContextInfoGroupsSids, size, &size, &buffer[0]))
			{
				const TOKEN_GROUPS *groups = reinterpret_cast<const TOKEN_GROUPS *> (&buffer[0]);
				for (DWORD i = 0; i < groups->GroupCount && !administrator; ++i)
					administrator = IsWellKnownSid (groups->Groups[i].Sid, WinBuiltinAdministratorsSid)
						&& !(groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY);
			}
			freeContext (context);
		}
		freeResourceManager (manager);
		return administrator;
	}

	// Whether only administrators can modify an object: it is owned by an
	// administrator, and grants nobody else more than reading it or, if
	// allowCreation, creating entries in it. ERROR_INVALID_SECURITY_DESCR if not.
	inline DWORD CheckAdministratorOnly (HANDLE handle, bool allowCreation)
	{
		SecurityDescriptor descriptor;
		PSID owner = NULL;
		PACL dacl = NULL;
		DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			&owner, NULL, &dacl, NULL, &descriptor.Value);
		if (error != ERROR_SUCCESS)
			return error;
		if (!dacl || !IsValidAcl (dacl) || !IsAdministratorSid (owner))
			return ERROR_INVALID_SECURITY_DESCR;

		DWORD allowed = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
		if (allowCreation)
			allowed |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
		GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
		for (DWORD i = 0; i < dacl->AceCount; ++i)
		{
			ACE_HEADER *header;
			if (!GetAce (dacl, i, reinterpret_cast<void **> (&header)))
				return GetLastError ();
			if ((header->AceFlags & INHERIT_ONLY_ACE) || header->AceType == ACCESS_DENIED_ACE_TYPE)
				continue;
			// Do not interpret conditional or object-specific grants.
			if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
				return ERROR_INVALID_SECURITY_DESCR;
			ACCESS_ALLOWED_ACE *ace = reinterpret_cast<ACCESS_ALLOWED_ACE *> (header);
			DWORD mask = ace->Mask;
			MapGenericMask (&mask, &mapping);
			PSID sid = reinterpret_cast<PSID> (&ace->SidStart);
			if ((mask & ~allowed) && !EqualSid (sid, owner) && !IsAdministratorSid (sid))
				return ERROR_INVALID_SECURITY_DESCR;
		}
		return ERROR_SUCCESS;
	}

	// A legacy object is used only if no standard user can have created,
	// modified or replaced it. Standard users can always create entries in the
	// legacy directory, but they must not be able to delete or rename them.
	inline DWORD CheckLegacyObject (HANDLE handle, bool directory)
	{
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (handle, &info))
			return GetLastError ();
		if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			|| ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
			|| (!directory && info.nNumberOfLinks != 1))
			return ERROR_INVALID_SECURITY_DESCR;
		return CheckAdministratorOnly (handle, directory);
	}

	// Create a directory with the given security in a location where only
	// administrators can create objects, or reset the DACL and the owner of the
	// existing directory. A reparse point is rejected, never followed. If its
	// security cannot be reset, e.g. because a security product prevents it, an
	// existing directory is still used if only administrators can modify it.
	inline DWORD PrepareDirectory (const std::wstring &path, PSECURITY_DESCRIPTOR descriptor, bool owner = true)
	{
		SECURITY_ATTRIBUTES attributes = { sizeof (attributes), descriptor, FALSE };
		if (CreateDirectoryW (path.c_str (), &attributes))
			return ERROR_SUCCESS;
		DWORD error = GetLastError ();
		if (error != ERROR_ALREADY_EXISTS)
			return error;

		const DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
		const DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
		Handle directory (CreateFileW (path.c_str (), READ_CONTROL | WRITE_DAC | (owner ? WRITE_OWNER : 0) | FILE_READ_ATTRIBUTES,
			sharing, NULL, OPEN_EXISTING, flags, NULL));
		const bool writable = directory.Value != INVALID_HANDLE_VALUE;
		if (!writable)
		{
			error = GetLastError ();
			if (error != ERROR_ACCESS_DENIED)
				return error;
			directory.Value = CreateFileW (path.c_str (), READ_CONTROL | FILE_READ_ATTRIBUTES, sharing, NULL, OPEN_EXISTING, flags, NULL);
			if (directory.Value == INVALID_HANDLE_VALUE)
				return GetLastError ();
		}
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (directory.Value, &info))
			return GetLastError ();
		if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			return ERROR_DIRECTORY;
		if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			return ERROR_REPARSE_POINT_ENCOUNTERED;
		if (HasSecurity (directory.Value, descriptor, owner))
			return ERROR_SUCCESS;
		// Unlike SetSecurityInfo, this does not rewrite the permissions of the
		// files that the directory contains.
		if (writable)
		{
			if (SetKernelObjectSecurity (directory.Value, (owner ? OWNER_SECURITY_INFORMATION : 0) | DACL_SECURITY_INFORMATION, descriptor))
				return ERROR_SUCCESS;
			error = GetLastError ();
		}
		return CheckAdministratorOnly (directory.Value, false) == ERROR_SUCCESS ? ERROR_SUCCESS : error;
	}

	inline DWORD NativeError (NTSTATUS status)
	{
		if (status >= 0)
			return ERROR_SUCCESS;
		typedef ULONG (NTAPI *ConvertStatus) (NTSTATUS);
		static ConvertStatus convert = reinterpret_cast<ConvertStatus> (GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlNtStatusToDosError"));
		return convert ? convert (status) : ERROR_GEN_FAILURE;
	}

	// Open a file of an open directory. The name is resolved in that directory,
	// even if its path now leads elsewhere, and a reparse point is not followed.
	// With backup intent, enabled backup and restore privileges grant access.
	inline DWORD OpenRelative (HANDLE directory, const wchar_t *name, DWORD access, DWORD sharing, Handle &file, bool backup = false)
	{
		static decltype (&NtCreateFile) createFile = reinterpret_cast<decltype (&NtCreateFile)>
			(GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "NtCreateFile"));
		if (!createFile)
			return ERROR_PROC_NOT_FOUND;
		size_t length = wcslen (name);
		if (!length || length > 255 || wcspbrk (name, L"\\/:"))
			return ERROR_BAD_PATHNAME;
		UNICODE_STRING objectName;
		objectName.Buffer = const_cast<wchar_t *> (name);
		objectName.Length = objectName.MaximumLength = static_cast<USHORT> (length * sizeof (wchar_t));
		OBJECT_ATTRIBUTES attributes;
		InitializeObjectAttributes (&attributes, &objectName, OBJ_CASE_INSENSITIVE, directory, NULL);
		IO_STATUS_BLOCK result = {};
		HANDLE opened = INVALID_HANDLE_VALUE;
		NTSTATUS status = createFile (&opened, access | SYNCHRONIZE, &attributes, &result, NULL, FILE_ATTRIBUTE_NORMAL,
			sharing, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE
			| (backup ? FILE_OPEN_FOR_BACKUP_INTENT : 0), NULL, 0);
		if (status < 0)
			return NativeError (status);
		file.Value = opened;
		return ERROR_SUCCESS;
	}

	inline DWORD OpenLegacyDirectory (const std::wstring &path, DWORD access, Handle &directory)
	{
		directory.Value = CreateFileW (path.c_str (), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
		if (directory.Value == INVALID_HANDLE_VALUE)
			return GetLastError ();
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (directory.Value, &info))
			return GetLastError ();
		if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			return ERROR_INVALID_SECURITY_DESCR;
		return ERROR_SUCCESS;
	}

	// Read a file of the legacy directory. ERROR_INVALID_SECURITY_DESCR means
	// that the file or the directory could have been modified by a standard user.
	inline DWORD ReadLegacy (const std::wstring &directory, const wchar_t *name, std::vector<unsigned char> &data, DWORD maxSize)
	{
		data.clear ();
		Handle folder, file;
		DWORD error = OpenLegacyDirectory (directory, READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE, folder);
		if (error == ERROR_SUCCESS)
			error = OpenRelative (folder.Value, name, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, file);
		if (error == ERROR_SUCCESS)
			error = CheckLegacyObject (folder.Value, true);
		if (error == ERROR_SUCCESS)
			error = CheckLegacyObject (file.Value, false);
		if (error == ERROR_SUCCESS)
			error = Read (file.Value, data, maxSize);
		return error;
	}

	// Delete a file of the legacy directory. A link is deleted, not its target.
	// The file is deleted whatever its permissions if the caller enabled the
	// privileges of AdministratorPrivileges.
	inline DWORD DeleteLegacy (const std::wstring &directory, const wchar_t *name)
	{
		Handle folder, file;
		DWORD error = OpenLegacyDirectory (directory, FILE_READ_ATTRIBUTES | FILE_TRAVERSE, folder);
		if (error == ERROR_SUCCESS)
			error = OpenRelative (folder.Value, name, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file, true);
		if (Missing (error))
			return ERROR_SUCCESS;
		if (error != ERROR_SUCCESS)
			return error;
		FILE_DISPOSITION_INFO disposition = { TRUE };
		return SetFileInformationByHandle (file.Value, FileDispositionInfo, &disposition, sizeof (disposition))
			? ERROR_SUCCESS : GetLastError ();
	}

	// Delete a link (reparse point), never its target, provided that it is still
	// the inspected object. ERROR_RETRY if it has been replaced meanwhile.
	inline DWORD DeleteLink (const std::wstring &path, const BY_HANDLE_FILE_INFORMATION &inspected)
	{
		Handle link (CreateFileW (path.c_str (), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL));
		if (link.Value == INVALID_HANDLE_VALUE)
			return GetLastError ();
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (link.Value, &info))
			return GetLastError ();
		if (!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			|| info.dwVolumeSerialNumber != inspected.dwVolumeSerialNumber
			|| info.nFileIndexHigh != inspected.nFileIndexHigh || info.nFileIndexLow != inspected.nFileIndexLow)
			return ERROR_RETRY;
		FILE_DISPOSITION_INFO disposition = { TRUE };
		return SetFileInformationByHandle (link.Value, FileDispositionInfo, &disposition, sizeof (disposition))
			? ERROR_SUCCESS : GetLastError ();
	}

	// Stop standard users from creating, deleting or renaming files in the
	// legacy directory, including a directory that a standard user created, so
	// that neither an old registration nor an older VeraCrypt executable can run
	// a script that they control. The owners and permissions of existing files
	// are not changed: a file that a standard user created is still not used.
	// A reparse point, through which the directory could lead elsewhere, is
	// deleted and replaced with a new directory, so that it cannot be created
	// again. Otherwise, a missing directory is not created: ERROR_FILE_NOT_FOUND
	// or ERROR_PATH_NOT_FOUND is returned.
	inline DWORD SecureLegacyDirectory (const std::wstring &path, PSECURITY_DESCRIPTOR descriptor, bool owner = true)
	{
		DWORD error = ERROR_RETRY;
		bool linkDeleted = false;
		for (int attempt = 0; attempt < 8; ++attempt)
		{
			Handle folder (CreateFileW (path.c_str (), READ_CONTROL | WRITE_DAC | (owner ? WRITE_OWNER : 0) | FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL));
			if (folder.Value == INVALID_HANDLE_VALUE)
			{
				error = GetLastError ();
				if (!linkDeleted)
					return error;
				// A virus scanner can briefly delay the deletion of the link.
				if (error == ERROR_ACCESS_DENIED)
				{
					Sleep (100);
					continue;
				}
				if (!Missing (error))
					return error;
				SECURITY_ATTRIBUTES attributes = { sizeof (attributes), descriptor, FALSE };
				if (CreateDirectoryW (path.c_str (), &attributes))
					return ERROR_SUCCESS;
				error = GetLastError ();
				if (error != ERROR_ALREADY_EXISTS)
					return error;
				continue;
			}

			BY_HANDLE_FILE_INFORMATION info;
			if (!GetFileInformationByHandle (folder.Value, &info))
				return GetLastError ();
			if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			{
				// The link disappears once this handle is closed too.
				error = DeleteLink (path, info);
				if (error != ERROR_SUCCESS && error != ERROR_RETRY)
					return error;
				linkDeleted = true;
				continue;
			}
			// A file prevents the creation of the directory.
			if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				return ERROR_SUCCESS;
			if (HasSecurity (folder.Value, descriptor, owner))
				return ERROR_SUCCESS;
			// SetSecurityInfo would also rewrite the permissions of the entries that
			// standard users may have created in this directory.
			return SetKernelObjectSecurity (folder.Value, (owner ? OWNER_SECURITY_INFORMATION : 0) | DACL_SECURITY_INFORMATION, descriptor)
				? ERROR_SUCCESS : GetLastError ();
		}
		return error;
	}

} }

#endif
