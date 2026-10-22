/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0; see License.txt.
*/

#ifndef TC_HEADER_Common_SystemEncryptionFiles
#define TC_HEADER_Common_SystemEncryptionFiles

#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

// These files become commands or boot code. Never repair an untrusted object's
// permissions and then accept its old contents as a trusted backup.
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

	inline bool TrustedSid (PSID sid)
	{
		if (!sid || !IsValidSid (sid))
			return false;
		if (IsWellKnownSid (sid, WinLocalSystemSid) || IsWellKnownSid (sid, WinBuiltinAdministratorsSid))
			return true;

		// Windows directories are commonly owned by TrustedInstaller.
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

	inline bool TrustedSecurity (PSECURITY_DESCRIPTOR descriptor, bool allowDirectoryCreation, bool volumeRoot = false,
		PSID installerOwner = NULL)
	{
		PSID owner = NULL;
		PACL dacl = NULL;
		BOOL present, defaulted;
		if (!GetSecurityDescriptorOwner (descriptor, &owner, &defaulted)
			|| (!TrustedSid (owner) && !(installerOwner && EqualSid (owner, installerOwner)))
			|| !GetSecurityDescriptorDacl (descriptor, &present, &dacl, &defaulted)
			|| !present || !dacl || !IsValidAcl (dacl))
			return false;

		DWORD allowed = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
		// Ancestors such as ProgramData can allow creation, but not removal or
		// replacement of an existing trusted child. Open children relative to
		// validated handles; sharing restrictions do not stop reparse changes.
		if (allowDirectoryCreation)
			allowed |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
		// The default system drive ACL grants DELETE on the volume root itself.
		// A volume root cannot be renamed or unlinked. DELETE_CHILD is still unsafe.
		if (volumeRoot) allowed |= DELETE;
		GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
		for (DWORD i = 0; i < dacl->AceCount; ++i)
		{
			ACE_HEADER *header;
			if (!GetAce (dacl, i, reinterpret_cast<void **> (&header)))
				return false;
			if (header->AceFlags & INHERIT_ONLY_ACE)
				continue;
			if (header->AceType == ACCESS_DENIED_ACE_TYPE)
				continue;
			// Do not try to interpret conditional or object-specific grants.
			if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
				return false;
			ACCESS_ALLOWED_ACE *ace = reinterpret_cast<ACCESS_ALLOWED_ACE *> (header);
			DWORD mask = ace->Mask;
			MapGenericMask (&mask, &mapping);
			if ((mask & ~allowed) && !TrustedSid (&ace->SidStart)
				&& !(installerOwner && EqualSid (&ace->SidStart, installerOwner)))
				return false;
		}
		return true;
	}

	inline DWORD CheckHandle (HANDLE handle, bool directory, bool allowDirectoryCreation = false, bool volumeRoot = false)
	{
		if (volumeRoot)
		{
			// Do not apply the root exception to a substituted drive's subdirectory.
			wchar_t path[2];
			DWORD length = GetFinalPathNameByHandleW (handle, path, ARRAYSIZE (path), VOLUME_NAME_NONE);
			if (!length) return GetLastError ();
			if (length != 1 || path[0] != L'\\') return ERROR_INVALID_SECURITY_DESCR;
		}
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (handle, &info))
			return GetLastError ();
		if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			|| ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
			|| (!directory && info.nNumberOfLinks != 1))
			return ERROR_INVALID_SECURITY_DESCR;

		SecurityDescriptor descriptor;
		DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			NULL, NULL, NULL, NULL, &descriptor.Value);
		if (error != ERROR_SUCCESS)
			return error;
		return TrustedSecurity (descriptor.Value, allowDirectoryCreation, volumeRoot) ? ERROR_SUCCESS : ERROR_INVALID_SECURITY_DESCR;
	}

	inline DWORD NewSecurity (SecurityDescriptor &descriptor, bool directory, bool executable = false)
	{
		// The explicit owner is important when a caller uses an elevated COM
		// server. Read access is needed by the unelevated rescue disk wizard.
		return ConvertStringSecurityDescriptorToSecurityDescriptorW (directory
			? L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
			: executable ? L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)"
			: L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)",
			SDDL_REVISION_1, &descriptor.Value, NULL) ? ERROR_SUCCESS : GetLastError ();
	}

	inline bool SimpleName (const std::wstring &name)
	{
		return !name.empty () && name.find_first_of (L"\\/:\0", 0, 4) == std::wstring::npos
			&& name.back () != L'.' && name.back () != L' ' && name.size () < 32768;
	}

	inline DWORD NativeError (NTSTATUS status)
	{
		if (status >= 0) return ERROR_SUCCESS;
		typedef ULONG (NTAPI *ConvertStatus) (NTSTATUS);
		static ConvertStatus convert = reinterpret_cast<ConvertStatus> (GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlNtStatusToDosError"));
		return convert ? convert (status) : ERROR_GEN_FAILURE;
	}

	inline DWORD OpenRelative (HANDLE parent, const std::wstring &name, DWORD access, DWORD sharing,
		ULONG disposition, bool directory, PSECURITY_DESCRIPTOR security, Handle &handle)
	{
		if (!SimpleName (name)) return ERROR_BAD_PATHNAME;
		// A single component is resolved against the already opened directory,
		// never against a pathname that may now lead through a different parent.
		static decltype (&NtCreateFile) createFile = reinterpret_cast<decltype (&NtCreateFile)>
			(GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "NtCreateFile"));
		if (!createFile) return ERROR_PROC_NOT_FOUND;
		UNICODE_STRING objectName = {};
		objectName.Buffer = const_cast<wchar_t *> (name.c_str ());
		objectName.Length = objectName.MaximumLength = static_cast<USHORT> (name.size () * sizeof (wchar_t));
		OBJECT_ATTRIBUTES attributes = { sizeof (attributes), parent, &objectName,
			OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, security, NULL };
		IO_STATUS_BLOCK result = {};
		HANDLE opened = INVALID_HANDLE_VALUE;
		NTSTATUS status = createFile (&opened, access | SYNCHRONIZE, &attributes, &result, NULL,
			FILE_ATTRIBUTE_NORMAL, sharing, disposition,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE), NULL, 0);
		if (status < 0) return NativeError (status);
		handle.Value = opened;
		return ERROR_SUCCESS;
	}

	class Directory
	{
	public:
		Directory () : Legacy (false) { }
		~Directory ()
		{
			for (size_t i = 0; i < Handles.size (); ++i)
				CloseHandle (Handles[i]);
		}

		DWORD Open (const std::wstring &path, bool create = false, bool legacy = false, bool pin = true)
		{
			// Only local absolute paths, with no alternate streams or ambiguous
			// components. Only the root is opened by an absolute pathname.
			if (!Handles.empty ()) return ERROR_INVALID_PARAMETER;
			if (path.size () < 3 || path[1] != L':' || path[2] != L'\\'
				|| !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))
				|| path.find_first_of (L"/:", 2) != std::wstring::npos)
				return ERROR_BAD_PATHNAME;

			Legacy = legacy;
			for (size_t start = 0, end = 3; ; )
			{
				bool last = end == path.size ();
				bool root = end == 3;
				std::wstring component = path.substr (start, end - start);
				SecurityDescriptor descriptor;
				if (last && create)
				{
					DWORD error = NewSecurity (descriptor, true);
					if (error != ERROR_SUCCESS) return error;
				}

				// Ancestor metadata handles neither exclude ordinary writers nor
				// conflict with their sharing modes. Pin only the final directory.
				// Metadata-only validation tolerates exclusive readers, but does
				// not pin a pathname. Pathname-based callers must keep pin enabled.
				DWORD access = last && pin ? GENERIC_READ : READ_CONTROL | FILE_READ_ATTRIBUTES;
				DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | (last ? 0 : FILE_SHARE_DELETE);
				Handle handle;
				DWORD error;
				if (root)
				{
					handle.Value = CreateFileW (component.c_str (), access, sharing, NULL, OPEN_EXISTING,
						FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
					error = handle.Value == INVALID_HANDLE_VALUE ? GetLastError () : ERROR_SUCCESS;
				}
				else
					error = OpenRelative (Handles.back (), component, access, sharing,
						last && create ? FILE_OPEN_IF : FILE_OPEN, true, descriptor.Value, handle);
				if (error != ERROR_SUCCESS) return error;
				error = CheckHandle (handle.Value, true, !last || legacy, root);
				if (error != ERROR_SUCCESS) return error;
				// Recheck the parent after opening its child. A trusted child cannot
				// be removed by an ordinary user, so the parent cannot then be emptied
				// and converted into a junction. This also protects callers of the
				// pathname-only Windows profile APIs in the strict final directory.
				if (!root)
				{
					error = CheckHandle (Handles.back (), true, true, Handles.size () == 1);
					if (error != ERROR_SUCCESS) return error;
				}
				Handles.push_back (handle.Value);
				handle.Value = INVALID_HANDLE_VALUE;
				if (last) return ERROR_SUCCESS;

				start = root ? end : end + 1;
				end = path.find (L'\\', start);
				if (end == std::wstring::npos) end = path.size ();
				if (start == end || path[end - 1] == L'.' || path[end - 1] == L' ')
					return ERROR_BAD_PATHNAME;
			}
		}

		DWORD OpenFile (const std::wstring &name, DWORD access, DWORD sharing, ULONG disposition,
			PSECURITY_DESCRIPTOR security, Handle &file) const
		{
			if (Handles.empty ()) return ERROR_INVALID_HANDLE;
			DWORD error = OpenRelative (Handles.back (), name, access, sharing, disposition, false, security, file);
			if (error != ERROR_SUCCESS) return error;
			// A legacy directory can allow creation and attribute writes. Do not
			// consume a file if that directory became a reparse point meanwhile.
			return CheckHandle (Handles.back (), true, Legacy, Handles.size () == 1);
		}

		HANDLE GetHandle () const { return Handles.empty () ? INVALID_HANDLE_VALUE : Handles.back (); }

	private:
		Directory (const Directory &);
		Directory &operator= (const Directory &);
		std::vector<HANDLE> Handles;
		bool Legacy;
	};

	inline bool Missing (DWORD error)
	{
		return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
	}

	// Provisioning of the installation package and Windows Setup settings only.
	// A full, unfiltered administrator can create individually owned objects.
	// Normalize those objects while that same principal is still privileged;
	// never apply this exception to other users or loader backups. Later reads
	// must still validate the resulting ownership and exclude existing writers.
	inline DWORD ProvisionInstallerObject (std::wstring path, bool directory, bool executable = false)
	{
		if (!path.empty () && path.back () == L'\\') path.pop_back ();
		size_t slash = path.find_last_of (L'\\');
		if (slash == std::wstring::npos || slash < 2 || slash + 1 == path.size ()) return ERROR_BAD_PATHNAME;
		Directory parent;
		// This is an ancestor, not the protected object itself. Standard roots
		// may allow child creation, but must not allow replacing an existing child.
		DWORD error = parent.Open (path.substr (0, slash == 2 ? 3 : slash), false, true, false);
		if (error != ERROR_SUCCESS) return error;
		Handle object;
		error = OpenRelative (parent.GetHandle (), path.substr (slash + 1), READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ, FILE_OPEN, directory, NULL, object);
		if (error != ERROR_SUCCESS) return error;
		error = CheckHandle (parent.GetHandle (), true, true, slash == 2);
		if (error != ERROR_SUCCESS) return error;
		error = CheckHandle (object.Value, directory);
		if (error != ERROR_INVALID_SECURITY_DESCR) return error;
		BY_HANDLE_FILE_INFORMATION info;
		if (!GetFileInformationByHandle (object.Value, &info)) return GetLastError ();
		if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || (!directory && info.nNumberOfLinks != 1)) return ERROR_INVALID_SECURITY_DESCR;
		Handle token;
		if (!OpenThreadToken (GetCurrentThread (), TOKEN_QUERY, TRUE, &token.Value))
		{
			if (GetLastError () != ERROR_NO_TOKEN) return GetLastError ();
			if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token.Value)) return GetLastError ();
		}
		TOKEN_ELEVATION_TYPE elevation; DWORD length;
		if (!GetTokenInformation (token.Value, TokenElevationType, &elevation, sizeof (elevation), &length)) return GetLastError ();
		if (elevation != TokenElevationTypeDefault) return ERROR_INVALID_SECURITY_DESCR;
		BYTE adminBuffer[SECURITY_MAX_SID_SIZE]; DWORD adminSize = sizeof (adminBuffer); BOOL administrator = FALSE;
		if (!CreateWellKnownSid (WinBuiltinAdministratorsSid, NULL, adminBuffer, &adminSize)
			|| !CheckTokenMembership (NULL, adminBuffer, &administrator)) return GetLastError ();
		if (!administrator) return ERROR_INVALID_SECURITY_DESCR;
		GetTokenInformation (token.Value, TokenUser, NULL, 0, &length);
		std::vector<unsigned char> user (length);
		if (!length || !GetTokenInformation (token.Value, TokenUser, user.data (), length, &length)) return GetLastError ();
		PSID caller = reinterpret_cast<TOKEN_USER *> (user.data ())->User.Sid;
		SecurityDescriptor oldSecurity, replacement;
		error = GetSecurityInfo (object.Value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			NULL, NULL, NULL, NULL, &oldSecurity.Value);
		if (error != ERROR_SUCCESS) return error;
		if (!TrustedSecurity (oldSecurity.Value, false, false, caller)) return ERROR_INVALID_SECURITY_DESCR;
		error = NewSecurity (replacement, directory, executable); if (error != ERROR_SUCCESS) return error;
		PSID owner; PACL acl; BOOL present, defaulted;
		if (!GetSecurityDescriptorOwner (replacement.Value, &owner, &defaulted)
			|| !GetSecurityDescriptorDacl (replacement.Value, &present, &acl, &defaulted)) return GetLastError ();
		error = SetSecurityInfo (object.Value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
			owner, NULL, acl, NULL);
		return error == ERROR_SUCCESS ? CheckHandle (object.Value, directory) : error;
	}

	// Keep both handles alive through any pathname-based copy of this source.
	// Provision only the same unfiltered administrator's objects, as elsewhere
	// in installer preparation; an ordinary-user owner or writer is rejected.
	inline DWORD OpenInstallerFile (const std::wstring &path, Directory &directory, Handle &file)
	{
		size_t slash = path.find_last_of (L'\\');
		if (slash == std::wstring::npos || slash < 3 || slash + 1 == path.size ()) return ERROR_BAD_PATHNAME;
		std::wstring parent = path.substr (0, slash);
		DWORD error = ProvisionInstallerObject (parent, true);
		if (error != ERROR_SUCCESS) return error;
		error = directory.Open (parent);
		if (error != ERROR_SUCCESS) return error;
		error = ProvisionInstallerObject (path, false, true);
		if (error != ERROR_SUCCESS) return error;
		error = directory.OpenFile (path.substr (slash + 1), GENERIC_READ | READ_CONTROL,
			FILE_SHARE_READ, FILE_OPEN, NULL, file);
		return error == ERROR_SUCCESS ? CheckHandle (file.Value, false) : error;
	}

	inline DWORD Read (HANDLE file, std::vector<unsigned char> &data)
	{
		DWORD error = CheckHandle (file, false);
		if (error != ERROR_SUCCESS) return error;
		LARGE_INTEGER size;
		if (!GetFileSizeEx (file, &size)) return GetLastError ();
		if (size.QuadPart < 0 || size.QuadPart > 64 * 1024 * 1024) return ERROR_FILE_TOO_LARGE;
		data.resize (static_cast<size_t> (size.QuadPart));
		DWORD count = 0;
		if (!data.empty () && !ReadFile (file, &data[0], static_cast<DWORD> (data.size ()), &count, NULL))
			return GetLastError ();
		return count == data.size () ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
	}

	inline DWORD Read (const Directory &directory, const wchar_t *name, std::vector<unsigned char> &data)
	{
		Handle file;
		DWORD error = directory.OpenFile (name, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, FILE_OPEN, NULL, file);
		return error == ERROR_SUCCESS ? Read (file.Value, data) : error;
	}

	inline DWORD Read (const std::wstring &directory, const wchar_t *name, std::vector<unsigned char> &data, bool legacy = false)
	{
		Directory locked;
		DWORD error = locked.Open (directory, false, legacy);
		return error == ERROR_SUCCESS ? Read (locked, name, data) : error;
	}

	inline DWORD Publish (HANDLE file, HANDLE directory, const std::wstring &name)
	{
		if (!SimpleName (name)) return ERROR_BAD_PATHNAME;
		// The native rename accepts a directory handle, avoiding another path
		// lookup for both the temporary file and its destination. It keeps the
		// new object's security; ReplaceFile would retain the old DACL.
		struct RenameInformation
		{
			BOOLEAN ReplaceIfExists;
			HANDLE RootDirectory;
			ULONG FileNameLength;
			wchar_t FileName[1];
		};
		typedef NTSTATUS (NTAPI *SetInformation) (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
		static SetInformation setInformation = reinterpret_cast<SetInformation>
			(GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "NtSetInformationFile"));
		if (!setInformation) return ERROR_PROC_NOT_FOUND;
		std::vector<unsigned char> buffer (sizeof (RenameInformation) + name.size () * sizeof (wchar_t));
		RenameInformation *rename = reinterpret_cast<RenameInformation *> (&buffer[0]);
		rename->ReplaceIfExists = TRUE;
		rename->RootDirectory = directory;
		rename->FileNameLength = static_cast<ULONG> (name.size () * sizeof (wchar_t));
		memcpy (rename->FileName, name.data (), rename->FileNameLength);
		IO_STATUS_BLOCK result = {};
		return NativeError (setInformation (file, &result, rename, static_cast<ULONG> (buffer.size ()), 10 /* FileRenameInformation */));
	}

	inline DWORD Write (const std::wstring &directory, const wchar_t *name, const unsigned char *data, DWORD size,
		const std::vector<unsigned char> *expected = NULL)
	{
		if (size > 64 * 1024 * 1024) return ERROR_FILE_TOO_LARGE;
		if (size && !data) return ERROR_INVALID_PARAMETER;
		Directory locked;
		DWORD error = locked.Open (directory, true);
		if (error != ERROR_SUCCESS) return error;
		if (!SimpleName (name)) return ERROR_BAD_PATHNAME;
		std::vector<unsigned char> previous;
		error = Read (locked, name, previous);
		// Detect another writer's edit since the caller read this shared file.
		// The setup lock serializes VeraCrypt callers; external writers do not
		// participate in it, so never knowingly publish a stale snapshot.
		if (expected && (error == ERROR_SUCCESS || Missing (error)) && previous != *expected)
			return ERROR_RETRY;
		if (error == ERROR_SUCCESS && previous.size () == size
			&& (size == 0 || memcmp (&previous[0], data, size) == 0))
			return ERROR_SUCCESS;
		if (error != ERROR_SUCCESS && !Missing (error)) return error;

		SecurityDescriptor descriptor;
		error = NewSecurity (descriptor, false);
		if (error != ERROR_SUCCESS) return error;
		// Only privileged callers can create files in this directory.
		// FILE_CREATE also prevents two privileged writers sharing a temporary file.
		std::wstring temporary;
		Handle file;
		for (unsigned int attempt = 0; attempt < 16; ++attempt)
		{
			wchar_t suffix[80];
			swprintf_s (suffix, ARRAYSIZE (suffix), L".%lu.%lu.%llu.%u.tmp",
				GetCurrentProcessId (), GetCurrentThreadId (), GetTickCount64 (), attempt);
			temporary = std::wstring (name) + suffix;
			error = locked.OpenFile (temporary, GENERIC_WRITE | DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, FILE_CREATE, descriptor.Value, file);
			if (error == ERROR_SUCCESS) break;
			if (file.Value != INVALID_HANDLE_VALUE)
			{
				FILE_DISPOSITION_INFO disposition = { TRUE };
				SetFileInformationByHandle (file.Value, FileDispositionInfo, &disposition, sizeof (disposition));
				return error;
			}
			if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) return error;
		}
		if (file.Value == INVALID_HANDLE_VALUE) return error;
		DWORD count = 0;
		error = CheckHandle (file.Value, false);
		if (error != ERROR_SUCCESS)
		{
			FILE_DISPOSITION_INFO disposition = { TRUE };
			SetFileInformationByHandle (file.Value, FileDispositionInfo, &disposition, sizeof (disposition));
			return error;
		}
		if (!WriteFile (file.Value, data, size, &count, NULL)) error = GetLastError ();
		else if (count != size) error = ERROR_WRITE_FAULT;
		else if (!FlushFileBuffers (file.Value)) error = GetLastError ();
		else error = ERROR_SUCCESS;
		// Never publish an incomplete write. Both publication and cleanup use
		// the original handle, even if a privileged process renames an ancestor.
		if (error == ERROR_SUCCESS)
		{
			if (expected)
			{
				std::vector<unsigned char> current;
				DWORD read = Read (locked, name, current);
				if (read != ERROR_SUCCESS && !Missing (read)) return read;
				if (current != *expected) return ERROR_RETRY;
			}
			return Publish (file.Value, locked.GetHandle (), name);
		}
		// Keep a complete temporary on publication failure for recovery. Delete
		// only incomplete data; never delete a handle after an uncertain rename.
		FILE_DISPOSITION_INFO disposition = { TRUE };
		SetFileInformationByHandle (file.Value, FileDispositionInfo, &disposition, sizeof (disposition));
		return error;
	}

	inline DWORD Remove (const std::wstring &directory, const wchar_t *name, const std::vector<unsigned char> *expected = NULL)
	{
		Directory locked;
		DWORD error = locked.Open (directory);
		if (Missing (error)) return expected && !expected->empty () ? ERROR_RETRY : ERROR_SUCCESS;
		if (error != ERROR_SUCCESS) return error;
		Handle file;
		error = locked.OpenFile (name, DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES | (expected ? GENERIC_READ : 0),
			FILE_SHARE_READ, FILE_OPEN, NULL, file);
		if (Missing (error)) return expected && !expected->empty () ? ERROR_RETRY : ERROR_SUCCESS;
		if (error != ERROR_SUCCESS) return error;
		error = CheckHandle (file.Value, false);
		if (error != ERROR_SUCCESS) return error;
		if (expected)
		{
			// Compare and delete through the same handle, excluding writers and
			// renames throughout. Never remove another product's intervening edit.
			std::vector<unsigned char> current;
			error = Read (file.Value, current);
			if (error != ERROR_SUCCESS) return error;
			if (current != *expected) return ERROR_RETRY;
		}
		FILE_DISPOSITION_INFO disposition = { TRUE };
		return SetFileInformationByHandle (file.Value, FileDispositionInfo, &disposition, sizeof (disposition))
			? ERROR_SUCCESS : GetLastError ();
	}

} }

#endif
