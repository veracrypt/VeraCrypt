/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
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
#include "Format.h"
#include "Progress.h"
#include "TcFormat.h"
#include "FormatCom.h"
#include "FormatCom_h.h"
#include "FormatCom_i.c"

using namespace VeraCrypt;

static volatile LONG ObjectCount = 0;

class TrueCryptFormatCom : public ITrueCryptFormatCom
{

public:
	TrueCryptFormatCom (DWORD messageThreadId) : RefCount (0),
		MessageThreadId (messageThreadId),
		CallBack (NULL)
	{
		InterlockedIncrement (&ObjectCount);
	}

	virtual ~TrueCryptFormatCom ()
	{
		if (InterlockedDecrement (&ObjectCount) == 0)
			PostThreadMessage (MessageThreadId, WM_APP, 0, 0);
	}

	virtual ULONG STDMETHODCALLTYPE AddRef ()
	{
		return InterlockedIncrement (&RefCount);
	}

	virtual ULONG STDMETHODCALLTYPE Release ()
	{
		if (!InterlockedDecrement (&RefCount))
		{
			delete this;
			return 0;
		}

		return RefCount;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppvObject)
	{
		if (riid == IID_IUnknown || riid == IID_ITrueCryptFormatCom)
			*ppvObject = this;
		else
		{
			*ppvObject = NULL;
			return E_NOINTERFACE;
		}

		AddRef ();
		return S_OK;
	}
	
	virtual DWORD STDMETHODCALLTYPE CallDriver (DWORD ioctl, BSTR input, BSTR *output)
	{
		return BaseCom::CallDriver (ioctl, input, output);
	}

	virtual DWORD STDMETHODCALLTYPE CopyFile (BSTR sourceFile, BSTR destinationFile)
	{
		return BaseCom::CopyFile (sourceFile, destinationFile);
	}

	virtual DWORD STDMETHODCALLTYPE DeleteFile (BSTR file)
	{
		return BaseCom::DeleteFile (file);
	}

	virtual BOOL STDMETHODCALLTYPE FormatNtfs (int driveNo, int clusterSize)
	{
		return ::FormatNtfs (driveNo, clusterSize, TRUE);
	}

	virtual int STDMETHODCALLTYPE AnalyzeHiddenVolumeHost (
		__int64 hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters)
	{
		return ::AnalyzeHiddenVolumeHost (
			(HWND) hwndDlg, driveNo, hiddenVolHostSize, realClusterSize, nbrFreeClusters);
	}

	virtual DWORD STDMETHODCALLTYPE ReadWriteFile (BOOL write, BOOL device, BSTR filePath, BSTR *bufferBstr, unsigned __int64 offset, unsigned __int32 size, DWORD *sizeDone)
	{
		return BaseCom::ReadWriteFile (write, device, filePath, bufferBstr, offset, size, sizeDone);
	}

	virtual DWORD STDMETHODCALLTYPE RegisterFilterDriver (BOOL registerDriver, int filterType)
	{
		return BaseCom::RegisterFilterDriver (registerDriver, filterType);
	}

	virtual DWORD STDMETHODCALLTYPE RegisterSystemFavoritesService (BOOL registerService)
	{
		return BaseCom::RegisterSystemFavoritesService (registerService);
	}

	virtual DWORD STDMETHODCALLTYPE SetDriverServiceStartType (DWORD startType)
	{
		return BaseCom::SetDriverServiceStartType (startType);
	}

	virtual BOOL STDMETHODCALLTYPE IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
	{
		return BaseCom::IsPagingFileActive (checkNonWindowsPartitionsOnly);
	}

	virtual DWORD STDMETHODCALLTYPE WriteLocalMachineRegistryDwordValue (BSTR keyPath, BSTR valueName, DWORD value)
	{
		return BaseCom::WriteLocalMachineRegistryDwordValue (keyPath, valueName, value);
	}

	virtual BOOL STDMETHODCALLTYPE FormatFs (int driveNo, int clusterSize, int fsType)
	{
		return ::FormatFs (driveNo, clusterSize, fsType, TRUE);
	}

	virtual DWORD STDMETHODCALLTYPE GetFileSize (BSTR filePath, unsigned __int64 *pSize)
	{
		return BaseCom::GetFileSize (filePath, pSize);
	}

	virtual DWORD STDMETHODCALLTYPE DeviceIoControl (BOOL readOnly, BOOL device, BSTR filePath, DWORD dwIoControlCode, BSTR input, BSTR *output)
	{
		return BaseCom::DeviceIoControl (readOnly, device, filePath, dwIoControlCode, input, output);
	}

	virtual DWORD STDMETHODCALLTYPE InstallEfiBootLoader (BOOL preserveUserConfig, BOOL hiddenOSCreation, int pim, int hashAlg)
	{
		return BaseCom::InstallEfiBootLoader (preserveUserConfig, hiddenOSCreation, pim, hashAlg);
	}

	virtual DWORD STDMETHODCALLTYPE BackupEfiSystemLoader ()
	{
		return BaseCom::BackupEfiSystemLoader ();
	}

	virtual DWORD STDMETHODCALLTYPE RestoreEfiSystemLoader ()
	{
		return BaseCom::RestoreEfiSystemLoader ();
	}

	virtual DWORD STDMETHODCALLTYPE GetEfiBootDeviceNumber (BSTR* pSdn)
	{
		return BaseCom::GetEfiBootDeviceNumber (pSdn);
	}

	virtual DWORD STDMETHODCALLTYPE GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded)
	{
		return BaseCom::GetSecureBootConfig (pSecureBootEnabled, pVeraCryptKeysLoaded);
	}

	virtual DWORD STDMETHODCALLTYPE WriteEfiBootSectorUserConfig (DWORD userConfig, BSTR customUserMessage, int pim, int hashAlg)
	{
		return BaseCom::WriteEfiBootSectorUserConfig (userConfig, customUserMessage,pim, hashAlg);
	}

	virtual DWORD STDMETHODCALLTYPE UpdateSetupConfigFile (BOOL bForInstall)
	{
		return BaseCom::UpdateSetupConfigFile (bForInstall);
	}

	virtual DWORD STDMETHODCALLTYPE NotifyService (DWORD dwNotifyCode)
	{
		return BaseCom::NotifyService (dwNotifyCode);
	}

	virtual DWORD STDMETHODCALLTYPE FastFileResize (BSTR filePath, __int64 fileSize)
	{
		return BaseCom::FastFileResize (filePath, fileSize);
	}

protected:
	DWORD MessageThreadId;
	LONG RefCount;
	ITrueCryptFormatCom *CallBack;
};


extern "C" BOOL ComServerFormat ()
{
	SetProcessShutdownParameters (0x100, 0);

	TrueCryptFactory<TrueCryptFormatCom> factory (GetCurrentThreadId ());
	DWORD cookie;

	if (IsUacSupported ())
		UacElevated = TRUE;

	if (CoRegisterClassObject (CLSID_TrueCryptFormatCom, (LPUNKNOWN) &factory,
		CLSCTX_LOCAL_SERVER, REGCLS_SINGLEUSE, &cookie) != S_OK)
		return FALSE;

	MSG msg;
	while (int r = GetMessageW (&msg, NULL, 0, 0))
	{
		if (r == -1)
			return FALSE;

		TranslateMessage (&msg);
		DispatchMessageW (&msg);

		if (msg.message == WM_APP
			&& ObjectCount < 1
			&& !factory.IsServerLocked ())
			break;
	}
	CoRevokeClassObject (cookie);

	return TRUE;
}


static BOOL ComGetInstance (HWND hWnd, ITrueCryptFormatCom **tcServer)
{
	return ComGetInstanceBase (hWnd, CLSID_TrueCryptFormatCom, IID_ITrueCryptFormatCom, (void **) tcServer);
}


ITrueCryptFormatCom *GetElevatedInstance (HWND parent)
{
	ITrueCryptFormatCom *instance;

	if (!ComGetInstance (parent, &instance))
		throw UserAbort (SRC_POS);

	return instance;
}


extern "C" int UacFormatNtfs (HWND hWnd, int driveNo, int clusterSize)
{
	CComPtr<ITrueCryptFormatCom> tc;
	int r;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ComGetInstance (hWnd, &tc))
		r = tc->FormatNtfs (driveNo, clusterSize);
	else
		r = (int) GetLastError();

	CoUninitialize ();

	return r;
}

extern "C" int UacFormatFs (HWND hWnd, int driveNo, int clusterSize, int fsType)
{
	CComPtr<ITrueCryptFormatCom> tc;
	int r;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ComGetInstance (hWnd, &tc))
		r = tc->FormatFs (driveNo, clusterSize, fsType);
	else
		r = (int) GetLastError();

	CoUninitialize ();

	return r;
}


extern "C" int UacAnalyzeHiddenVolumeHost (HWND hwndDlg, int *driveNo, __int64 hiddenVolHostSize, int *realClusterSize, __int64 *nbrFreeClusters)
{
	CComPtr<ITrueCryptFormatCom> tc;
	int r;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ComGetInstance (hwndDlg, &tc))
		r = tc->AnalyzeHiddenVolumeHost ((__int64) hwndDlg, driveNo, hiddenVolHostSize, realClusterSize, nbrFreeClusters);
	else
		r = 0;

	CoUninitialize ();

	return r;
}

extern "C" BOOL UacWriteLocalMachineRegistryDword (HWND hwndDlg, wchar_t *keyPath, wchar_t *valueName, DWORD value)
{
	CComPtr<ITrueCryptFormatCom> tc;
	int r = 0;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ComGetInstance (hwndDlg, &tc))
	{
		CComBSTR keyPathBstr, valueNameBstr;
		BSTR bstr = W2BSTR(keyPath);
		if (bstr)
		{
			keyPathBstr.Attach (bstr);
			bstr = W2BSTR(valueName);
			if (bstr)
			{
				valueNameBstr.Attach (bstr);
				r = tc->WriteLocalMachineRegistryDwordValue (keyPathBstr, valueNameBstr, value);
			}
			else
				r = ERROR_OUTOFMEMORY;
		}
		else
			r = ERROR_OUTOFMEMORY;
	}

	CoUninitialize ();

	if (r == ERROR_SUCCESS)
		return TRUE;
	else
	{
		SetLastError (r);
		return FALSE;
	}
}

extern "C" DWORD UacFastFileCreation (HWND hWnd, wchar_t* filePath, __int64 fileSize)
{
	CComPtr<ITrueCryptFormatCom> tc;
	DWORD r;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	if (ComGetInstance (hWnd, &tc))
	{
		CComBSTR filePathBstr;
		BSTR bstr = W2BSTR(filePath);
		if (bstr)
		{
			filePathBstr.Attach (bstr);
			r = tc->FastFileResize (filePathBstr, fileSize);
		}
		else
			r = ERROR_OUTOFMEMORY;
	}
	else
		r = GetLastError();

	CoUninitialize ();

	return r;
}
