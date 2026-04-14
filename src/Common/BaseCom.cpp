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

#include <atlcomcli.h>
#include <atlconv.h>
#include <comutil.h>
#include <windows.h>
#include "BaseCom.h"
#include "BootEncryption.h"
#include "Dlgcode.h"
#include "Registry.h"

using namespace VeraCrypt;

// ========================================================================
// COM method input validation - whitelists and helper functions
// ========================================================================

// Helper: check if IOCTL code is in the allowed list
static BOOL IsIoctlInWhitelist (DWORD ioctl, const DWORD *whitelist, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		if (whitelist[i] == ioctl)
			return TRUE;
	}
	return FALSE;
}

// Allowed IOCTL codes for CallDriver (VeraCrypt kernel driver IOCTLs)
static const DWORD g_CallDriverIoctlWhitelist[] = {
	TC_IOCTL_GET_DRIVER_VERSION,
	TC_IOCTL_GET_BOOT_LOADER_VERSION,
	TC_IOCTL_MOUNT_VOLUME,
	TC_IOCTL_UNMOUNT_VOLUME,
	TC_IOCTL_UNMOUNT_ALL_VOLUMES,
	TC_IOCTL_GET_MOUNTED_VOLUMES,
	TC_IOCTL_GET_VOLUME_PROPERTIES,
	TC_IOCTL_GET_DEVICE_REFCOUNT,
	TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED,
	TC_IOCTL_IS_ANY_VOLUME_MOUNTED,
	TC_IOCTL_GET_PASSWORD_CACHE_STATUS,
	TC_IOCTL_WIPE_PASSWORD_CACHE,
	TC_IOCTL_OPEN_TEST,
	TC_IOCTL_GET_DRIVE_PARTITION_INFO,
	TC_IOCTL_GET_DRIVE_GEOMETRY,
	TC_IOCTL_PROBE_REAL_DRIVE_SIZE,
	TC_IOCTL_GET_RESOLVED_SYMLINK,
	TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS,
	TC_IOCTL_BOOT_ENCRYPTION_SETUP,
	TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP,
	TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT,
	TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES,
	TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER,
	TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME,
	TC_IOCTL_GET_PORTABLE_MODE_STATUS,
	TC_IOCTL_SET_PORTABLE_MODE_STATUS,
	TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING,
	TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG,
	TC_IOCTL_DISK_IS_WRITABLE,
	TC_IOCTL_START_DECOY_SYSTEM_WIPE,
	TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE,
	TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS,
	TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT,
	TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR,
	TC_IOCTL_GET_WARNING_FLAGS,
	TC_IOCTL_SET_SYSTEM_FAVORITE_VOLUME_DIRTY,
	TC_IOCTL_REREAD_DRIVER_CONFIG,
	TC_IOCTL_GET_SYSTEM_DRIVE_DUMP_CONFIG,
	VC_IOCTL_GET_BOOT_LOADER_FINGERPRINT,
	VC_IOCTL_GET_DRIVE_GEOMETRY_EX,
	VC_IOCTL_EMERGENCY_CLEAR_ALL_KEYS,
	VC_IOCTL_IS_RAM_ENCRYPTION_ENABLED,
	VC_IOCTL_ENCRYPTION_QUEUE_PARAMS,
};

// Allowed IOCTL codes for DeviceIoControl (standard disk/storage/filesystem IOCTLs)
static const DWORD g_DeviceIoControlWhitelist[] = {
	IOCTL_DISK_GET_DRIVE_GEOMETRY,
	IOCTL_DISK_GET_PARTITION_INFO,
	IOCTL_DISK_GET_PARTITION_INFO_EX,
	IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
	IOCTL_DISK_GET_LENGTH_INFO,
	IOCTL_DISK_PERFORMANCE,
	IOCTL_STORAGE_GET_DEVICE_NUMBER,
	IOCTL_STORAGE_READ_CAPACITY,
	IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
	FSCTL_LOCK_VOLUME,
	FSCTL_DISMOUNT_VOLUME,
	FSCTL_IS_VOLUME_MOUNTED,
	FSCTL_GET_NTFS_VOLUME_DATA,
	FSCTL_GET_VOLUME_BITMAP,
	FSCTL_GET_RETRIEVAL_POINTERS,
	FSCTL_MOVE_FILE,
	FSCTL_ALLOW_EXTENDED_DASD_IO,
	FSCTL_SET_SPARSE,
	FSCTL_EXTEND_VOLUME,
	FSCTL_SHRINK_VOLUME,
};

// Allowed HKLM registry key path prefixes (case-insensitive)
static const wchar_t* g_RegistryKeyPrefixWhitelist[] = {
	L"SYSTEM\\CurrentControlSet\\Services\\veracrypt",
	L"SYSTEM\\CurrentControlSet\\Services\\VeraCryptSystemFavorites",
	L"SYSTEM\\CurrentControlSet\\Control\\Power",
	L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
};

// Helper: check if registry key path matches an allowed prefix (exact or subkey)
static BOOL IsRegistryKeyPathAllowed (const wchar_t *keyPath)
{
	if (!keyPath)
		return FALSE;
	for (size_t i = 0; i < ARRAYSIZE (g_RegistryKeyPrefixWhitelist); i++)
	{
		size_t prefixLen = wcslen (g_RegistryKeyPrefixWhitelist[i]);
		if (_wcsnicmp (keyPath, g_RegistryKeyPrefixWhitelist[i], prefixLen) == 0)
		{
			wchar_t nextChar = keyPath[prefixLen];
			if (nextChar == L'\0' || nextChar == L'\\')
				return TRUE;
		}
	}
	return FALSE;
}

// Helper: reject paths containing ".." traversal components
static BOOL ValidatePathNoTraversal (const wchar_t *path)
{
	if (!path)
		return FALSE;
	if (wcsstr (path, L"..") != NULL)
		return FALSE;
	return TRUE;
}

// Helper: case-insensitive check if path contains "veracrypt" substring
static BOOL PathContainsVeraCrypt (const wchar_t *path)
{
	if (!path)
		return FALSE;
	size_t pathLen = wcslen (path);
	if (pathLen < 9)
		return FALSE;
	for (size_t i = 0; i <= pathLen - 9; i++)
	{
		if (_wcsnicmp (&path[i], L"veracrypt", 9) == 0)
			return TRUE;
	}
	return FALSE;
}

// Bare PhysicalDriveN is accepted because it is the form stored in
// SystemDriveConfiguration::DevicePath and reaches here via the elevated
// fallback in Device::Device.
static BOOL IsValidDevicePath (const wchar_t *path)
{
	if (!path)
		return FALSE;

	if (path[0] == L'\\' && path[1] == L'\\'
		&& (path[2] == L'.' || path[2] == L'?')
		&& path[3] == L'\\' && path[4] != L'\0')
	{
		return TRUE;
	}

	if (_wcsnicmp (path, L"PhysicalDrive", 13) == 0 && path[13] != L'\0')
	{
		for (const wchar_t *p = path + 13; *p; ++p)
		{
			if (*p < L'0' || *p > L'9')
				return FALSE;
		}
		return TRUE;
	}

	return FALSE;
}

// ========================================================================


HRESULT CreateElevatedComObject (HWND hwnd, REFGUID guid, REFIID iid, void **ppv)
{
    WCHAR monikerName[1024];
    WCHAR clsid[1024];
    BIND_OPTS3 bo;

    StringFromGUID2 (guid, clsid, sizeof (clsid) / 2);
	swprintf_s (monikerName, sizeof (monikerName) / 2, L"Elevation:Administrator!new:%s", clsid);

    memset (&bo, 0, sizeof (bo));
    bo.cbStruct = sizeof (bo);
    bo.hwnd = hwnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

	// Prevent the GUI from being half-rendered when the UAC prompt "freezes" it
	ProcessPaintMessages (hwnd, 5000);

    return CoGetObject (monikerName, &bo, iid, ppv);
}


BOOL ComGetInstanceBase (HWND hWnd, REFCLSID clsid, REFIID iid, void **tcServer)
{
	BOOL r;
	HRESULT hr;

	if (IsUacSupported ())
	{
		while (true)
		{
			r = (hr = CreateElevatedComObject (hWnd, clsid, iid, tcServer)) == S_OK;
			if (r)
				break;
			else
			{
				if (IDRETRY == ErrorRetryCancel ("UAC_INIT_ERROR", hWnd))
					continue;
				else
					break;
			}
		}
	}
	else
	{
		r = (hr = CoCreateInstance (clsid, NULL, CLSCTX_LOCAL_SERVER, iid, tcServer)) == S_OK;
		if (!r)
			Error ("UAC_INIT_ERROR", hWnd);
	}

	if (!r)
	{
		SetLastError((DWORD) hr);
	}

	return r;
}


DWORD BaseCom::CallDriver (DWORD ioctl, BSTR input, BSTR *output)
{
	if (!IsIoctlInWhitelist (ioctl, g_CallDriverIoctlWhitelist, ARRAYSIZE (g_CallDriverIoctlWhitelist)))
		return ERROR_ACCESS_DENIED;

	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.CallDriver (ioctl,
			(BYTE *) input, !(BYTE *) input ? 0 : ((DWORD *) ((BYTE *) input))[-1],
			(BYTE *) *output, !(BYTE *) *output ? 0 : ((DWORD *) ((BYTE *) *output))[-1]);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}


DWORD BaseCom::CopyFile (BSTR sourceFile, BSTR destinationFile)
{
	if (!ValidatePathNoTraversal (sourceFile) || !ValidatePathNoTraversal (destinationFile))
		return ERROR_ACCESS_DENIED;

	if (!PathContainsVeraCrypt (sourceFile) || !PathContainsVeraCrypt (destinationFile))
		return ERROR_ACCESS_DENIED;

	if (!::CopyFileW (sourceFile, destinationFile, FALSE))
		return GetLastError();

	return ERROR_SUCCESS;
}


DWORD BaseCom::DeleteFile (BSTR file)
{
	if (!ValidatePathNoTraversal (file))
		return ERROR_ACCESS_DENIED;

	if (!PathContainsVeraCrypt (file))
		return ERROR_ACCESS_DENIED;

	if (!::DeleteFileW (file))
		return GetLastError();

	return ERROR_SUCCESS;
}


BOOL BaseCom::IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
{
	return ::IsPagingFileActive (checkNonWindowsPartitionsOnly);
}


DWORD BaseCom::ReadWriteFile (BOOL write, BOOL device, BSTR filePath, BSTR *bufferBstr, unsigned __int64 offset, unsigned __int32 size, DWORD *sizeDone)
{
	if (device)
	{
		if (!IsValidDevicePath (filePath))
			return ERROR_ACCESS_DENIED;
	}
	else
	{
		if (!ValidatePathNoTraversal (filePath))
			return ERROR_ACCESS_DENIED;
	}

	try
	{
		unique_ptr <File> file (device ? new Device (filePath, !write) : new File (filePath, !write));
		file->CheckOpened (SRC_POS);
		file->SeekAt (offset);

		if (write)
		{
			file->Write ((BYTE *) *bufferBstr, size);
			*sizeDone = size;
		}
		else
		{
			*sizeDone = file->Read ((BYTE *) *bufferBstr, size);
		}
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::GetFileSize (BSTR filePath, unsigned __int64 *pSize)
{
	if (!pSize)
		return ERROR_INVALID_PARAMETER;

	if (!ValidatePathNoTraversal (filePath))
		return ERROR_ACCESS_DENIED;

	try
	{
		std::wstring path (filePath);
		File file(filePath, true);
		file.CheckOpened (SRC_POS);
		file.GetFileSize (*pSize);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::DeviceIoControl (BOOL readOnly, BOOL device, BSTR filePath, DWORD dwIoControlCode, BSTR input, BSTR *output)
{
	if (!IsIoctlInWhitelist (dwIoControlCode, g_DeviceIoControlWhitelist, ARRAYSIZE (g_DeviceIoControlWhitelist)))
		return ERROR_ACCESS_DENIED;

	if (device)
	{
		if (!IsValidDevicePath (filePath))
			return ERROR_ACCESS_DENIED;
	}
	else
	{
		if (!ValidatePathNoTraversal (filePath))
			return ERROR_ACCESS_DENIED;
	}

	try
	{
		unique_ptr <File> file (device ? new Device (filePath, readOnly == TRUE) : new File (filePath, readOnly == TRUE));
		file->CheckOpened (SRC_POS);
		if (!file->IoCtl (dwIoControlCode, (BYTE *) input, !(BYTE *) input ? 0 : ((DWORD *) ((BYTE *) input))[-1],
			(BYTE *) *output, !(BYTE *) *output ? 0 : ((DWORD *) ((BYTE *) *output))[-1]))
		{
			return GetLastError();
		}
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::RegisterFilterDriver (BOOL registerDriver, int filterType)
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.RegisterFilterDriver (registerDriver ? true : false, (BootEncryption::FilterType) filterType);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}


DWORD BaseCom::RegisterSystemFavoritesService (BOOL registerService)
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.RegisterSystemFavoritesService (registerService);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}


DWORD BaseCom::SetDriverServiceStartType (DWORD startType)
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.SetDriverServiceStartType (startType);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}


DWORD BaseCom::WriteLocalMachineRegistryDwordValue (BSTR keyPath, BSTR valueName, DWORD value)
{
	if (!IsRegistryKeyPathAllowed (keyPath))
		return ERROR_ACCESS_DENIED;

	if (!::WriteLocalMachineRegistryDword (keyPath, valueName, value))
		return GetLastError();

	return ERROR_SUCCESS;
}
DWORD BaseCom::InstallEfiBootLoader (BOOL preserveUserConfig, BOOL hiddenOSCreation, int pim, int hashAlg)
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.InstallBootLoader (preserveUserConfig? true : false, hiddenOSCreation? true : false, pim, hashAlg);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::BackupEfiSystemLoader ()
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.BackupSystemLoader ();
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (UserAbort&)
	{
		return ERROR_CANCELLED;
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::RestoreEfiSystemLoader ()
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.RestoreSystemLoader ();
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::GetEfiBootDeviceNumber (BSTR* pSdn)
{
	if (!pSdn || !(*pSdn) || ((((DWORD *) ((BYTE *) *pSdn))[-1]) < sizeof (STORAGE_DEVICE_NUMBER)))
		return ERROR_INVALID_PARAMETER;

	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.GetEfiBootDeviceNumber ((PSTORAGE_DEVICE_NUMBER) *pSdn);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded)
{
	if (!pSecureBootEnabled || !pVeraCryptKeysLoaded)
		return ERROR_INVALID_PARAMETER;

	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.GetSecureBootConfig (pSecureBootEnabled, pVeraCryptKeysLoaded);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::WriteEfiBootSectorUserConfig (DWORD userConfig, BSTR customUserMessage, int pim, int hashAlg)
{
	if (!customUserMessage)
		return ERROR_INVALID_PARAMETER;

	try
	{
		DWORD maxSize = ((DWORD *) ((BYTE *) customUserMessage))[-1];
		char* msg = (char*) *customUserMessage;
		if (maxSize > 0)
			msg [maxSize - 1] = 0;
		std::string msgStr = maxSize > 0 ? msg : "";
		BootEncryption bootEnc (NULL);
		bootEnc.WriteEfiBootSectorUserConfig ((uint8) userConfig,  msgStr, pim, hashAlg);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::UpdateSetupConfigFile (BOOL bForInstall)
{
	try
	{
		BootEncryption bootEnc (NULL);
		bootEnc.UpdateSetupConfigFile (bForInstall? true : false);
	}
	catch (SystemException &)
	{
		return GetLastError();
	}
	catch (Exception &e)
	{
		e.Show (NULL);
		return ERROR_EXCEPTION_IN_SERVICE;
	}
	catch (...)
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	return ERROR_SUCCESS;
}

DWORD BaseCom::NotifyService(DWORD dwNotifyCode)
{
	return SendServiceNotification(dwNotifyCode);
}

DWORD BaseCom::FastFileResize (BSTR filePath, __int64 fileSize)
{
	if (!ValidatePathNoTraversal (filePath))
		return ERROR_ACCESS_DENIED;

	return ::FastResizeFile (filePath, fileSize);
}
