/*
 Copyright (c) 2007-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
		r = CreateElevatedComObject (hWnd, clsid, iid, tcServer) == S_OK;
	else
		r = CoCreateInstance (clsid, NULL, CLSCTX_LOCAL_SERVER, iid, tcServer) == S_OK;

	if (!r)
		Error ("UAC_INIT_ERROR");

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
	USES_CONVERSION;

	if (!::CopyFile (CW2A (sourceFile), CW2A (destinationFile), FALSE))
		return GetLastError();

	return ERROR_SUCCESS;
}


DWORD BaseCom::DeleteFile (BSTR file)
{
	USES_CONVERSION;

	if (!::DeleteFile (CW2A (file)))
		return GetLastError();

	return ERROR_SUCCESS;
}


BOOL BaseCom::IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
{
	return ::IsPagingFileActive (checkNonWindowsPartitionsOnly);
}


DWORD BaseCom::ReadWriteFile (BOOL write, BOOL device, BSTR filePath, BSTR *bufferBstr, unsigned __int64 offset, unsigned __int32 size, DWORD *sizeDone)
{
	USES_CONVERSION;

	try
	{
		auto_ptr <File> file (device ? new Device (string (CW2A (filePath)), !write) : new File (string (CW2A (filePath)), !write));
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
	USES_CONVERSION;
	if (!::WriteLocalMachineRegistryDword (CW2A (keyPath), CW2A (valueName), value))
		return GetLastError();

	return ERROR_SUCCESS;
}
