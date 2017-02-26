/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
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

	if (IsUacSupported ())
	{
		while (true)
		{
			r = CreateElevatedComObject (hWnd, clsid, iid, tcServer) == S_OK;
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
		r = CoCreateInstance (clsid, NULL, CLSCTX_LOCAL_SERVER, iid, tcServer) == S_OK;
		if (!r)
			Error ("UAC_INIT_ERROR", hWnd);
	}

	return r;
}


DWORD BaseCom::CallDriver (DWORD ioctl, BSTR input, BSTR *output)
{
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

	if (!::CopyFileW (sourceFile, destinationFile, FALSE))
		return GetLastError();

	return ERROR_SUCCESS;
}


DWORD BaseCom::DeleteFile (BSTR file)
{

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
	try
	{
		auto_ptr <File> file (device ? new Device (filePath, !write) : new File (filePath, !write));
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
	try
	{
		auto_ptr <File> file (device ? new Device (filePath, readOnly == TRUE) : new File (filePath, readOnly == TRUE));
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

DWORD BaseCom::ReadEfiConfig (BSTR* pContent, DWORD *pcbRead)
{
	if (!pContent || !(*pContent))
		return ERROR_INVALID_PARAMETER;

	try
	{
		DWORD maxSize = ((DWORD *) ((BYTE *) *pContent))[-1];
		BootEncryption bootEnc (NULL);
		bootEnc.ReadEfiConfig ((byte*) *pContent, maxSize, pcbRead);
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
		bootEnc.WriteEfiBootSectorUserConfig ((byte) userConfig,  msgStr, pim, hashAlg);
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