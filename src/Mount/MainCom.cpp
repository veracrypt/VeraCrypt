/*
 Copyright (c) 2007-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <atlcomcli.h>
#include <atlconv.h>
#include <windows.h>
#include "BaseCom.h"
#include "BootEncryption.h"
#include "Dlgcode.h"
#include "MainCom.h"
#include "MainCom_h.h"
#include "MainCom_i.c"
#include "Mount.h"
#include "Password.h"

using namespace VeraCrypt;

static volatile LONG ObjectCount = 0;

class TrueCryptMainCom : public ITrueCryptMainCom
{

public:
	TrueCryptMainCom (DWORD messageThreadId) : RefCount (0), MessageThreadId (messageThreadId)
	{
		InterlockedIncrement (&ObjectCount);
	}

	virtual ~TrueCryptMainCom ()
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
		if (riid == IID_IUnknown || riid == IID_ITrueCryptMainCom)
			*ppvObject = this;
		else
		{
			*ppvObject = NULL;
			return E_NOINTERFACE;
		}

		AddRef ();
		return S_OK;
	}

	virtual void STDMETHODCALLTYPE AnalyzeKernelMiniDump (LONG_PTR hwndDlg)
	{
		MainDlg = (HWND) hwndDlg;
		::AnalyzeKernelMiniDump ((HWND) hwndDlg);
	}

	virtual int STDMETHODCALLTYPE BackupVolumeHeader (LONG_PTR hwndDlg, BOOL bRequireConfirmation, BSTR lpszVolume)
	{
		USES_CONVERSION;
		MainDlg = (HWND) hwndDlg;
		return ::BackupVolumeHeader ((HWND) hwndDlg, bRequireConfirmation, CW2A (lpszVolume));
	}

	virtual int STDMETHODCALLTYPE RestoreVolumeHeader (LONG_PTR hwndDlg, BSTR lpszVolume)
	{
		USES_CONVERSION;
		MainDlg = (HWND) hwndDlg;
		return ::RestoreVolumeHeader ((HWND) hwndDlg, CW2A (lpszVolume));
	}

	virtual DWORD STDMETHODCALLTYPE CallDriver (DWORD ioctl, BSTR input, BSTR *output)
	{
		return BaseCom::CallDriver (ioctl, input, output);
	}

	virtual int STDMETHODCALLTYPE ChangePassword (BSTR volumePath, Password *oldPassword, Password *newPassword, int pkcs5, LONG_PTR hWnd)
	{
		USES_CONVERSION;
		MainDlg = (HWND) hWnd;
		return ::ChangePwd (CW2A (volumePath), oldPassword, newPassword, pkcs5, (HWND) hWnd);
	}

	virtual DWORD STDMETHODCALLTYPE CopyFile (BSTR sourceFile, BSTR destinationFile)
	{
		return BaseCom::CopyFile (sourceFile, destinationFile);
	}

	virtual DWORD STDMETHODCALLTYPE DeleteFile (BSTR file)
	{
		return BaseCom::DeleteFile (file);
	}

	virtual BOOL STDMETHODCALLTYPE IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
	{
		return BaseCom::IsPagingFileActive (checkNonWindowsPartitionsOnly);
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

	virtual DWORD STDMETHODCALLTYPE WriteLocalMachineRegistryDwordValue (BSTR keyPath, BSTR valueName, DWORD value)
	{
		return BaseCom::WriteLocalMachineRegistryDwordValue (keyPath, valueName, value);
	}

protected:
	DWORD MessageThreadId;
	LONG RefCount;
};


extern "C" BOOL ComServerMain ()
{
	SetProcessShutdownParameters (0x100, 0);

	TrueCryptFactory<TrueCryptMainCom> factory (GetCurrentThreadId ());
	DWORD cookie;

	if (IsUacSupported ())
		UacElevated = TRUE;

	if (CoRegisterClassObject (CLSID_TrueCryptMainCom, (LPUNKNOWN) &factory,
		CLSCTX_LOCAL_SERVER, REGCLS_SINGLEUSE, &cookie) != S_OK)
		return FALSE;

	MSG msg;
	while (int r = GetMessage (&msg, NULL, 0, 0))
	{
		if (r == -1)
			return FALSE;

		TranslateMessage (&msg);
		DispatchMessage (&msg);

		if (msg.message == WM_APP
			&& ObjectCount < 1
			&& !factory.IsServerLocked ())
			break;
	}
	CoRevokeClassObject (cookie);

	return TRUE;
}


static BOOL ComGetInstance (HWND hWnd, ITrueCryptMainCom **tcServer)
{
	return ComGetInstanceBase (hWnd, CLSID_TrueCryptMainCom, IID_ITrueCryptMainCom, (void **) tcServer);
}


ITrueCryptMainCom *GetElevatedInstance (HWND parent)
{
	ITrueCryptMainCom *instance;

	if (!ComGetInstance (parent, &instance))
		throw UserAbort (SRC_POS);

	return instance;
}


extern "C" void UacAnalyzeKernelMiniDump (HWND hwndDlg)
{
	CComPtr<ITrueCryptMainCom> tc;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
	{
		WaitCursor();
		tc->AnalyzeKernelMiniDump ((LONG_PTR) hwndDlg);
		NormalCursor();
	}

	CoUninitialize ();
}


extern "C" int UacBackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, char *lpszVolume)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
		r = tc->BackupVolumeHeader ((LONG_PTR) hwndDlg, bRequireConfirmation, CComBSTR (lpszVolume));
	else
		r = -1;

	CoUninitialize ();

	return r;
}


extern "C" int UacRestoreVolumeHeader (HWND hwndDlg, char *lpszVolume)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
		r = tc->RestoreVolumeHeader ((LONG_PTR) hwndDlg, CComBSTR (lpszVolume));
	else
		r = -1;

	CoUninitialize ();

	return r;
}


extern "C" int UacChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	if (ComGetInstance (hwndDlg, &tc))
	{
		WaitCursor ();
		r = tc->ChangePassword (CComBSTR (lpszVolume), oldPassword, newPassword, pkcs5, (LONG_PTR) hwndDlg);
		NormalCursor ();
	}
	else
		r = -1;

	return r;
}
