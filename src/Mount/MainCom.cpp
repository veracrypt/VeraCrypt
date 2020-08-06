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

	virtual void STDMETHODCALLTYPE AnalyzeKernelMiniDump (__int64 hwndDlg)
	{
		// Do nothing
		MainDlg = (HWND) hwndDlg;
	}

	virtual int STDMETHODCALLTYPE BackupVolumeHeader (__int64 hwndDlg, BOOL bRequireConfirmation, BSTR lpszVolume)
	{
		MainDlg = (HWND) hwndDlg;
		return ::BackupVolumeHeader ((HWND) hwndDlg, bRequireConfirmation, lpszVolume);
	}

	virtual int STDMETHODCALLTYPE RestoreVolumeHeader (__int64 hwndDlg, BSTR lpszVolume)
	{
		MainDlg = (HWND) hwndDlg;
		return ::RestoreVolumeHeader ((HWND) hwndDlg, lpszVolume);
	}

	virtual DWORD STDMETHODCALLTYPE CallDriver (DWORD ioctl, BSTR input, BSTR *output)
	{
		return BaseCom::CallDriver (ioctl, input, output);
	}

	virtual int STDMETHODCALLTYPE ChangePassword (BSTR volumePath, Password *oldPassword, Password *newPassword, int pkcs5, int wipePassCount, __int64 hWnd)
	{
		MainDlg = (HWND) hWnd;
		return ::ChangePwd (volumePath, oldPassword, 0, 0, FALSE, newPassword, pkcs5, 0, wipePassCount, (HWND) hWnd);
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

	virtual int STDMETHODCALLTYPE ChangePasswordEx (BSTR volumePath, Password *oldPassword, int old_pkcs5, Password *newPassword, int pkcs5, int wipePassCount, __int64 hWnd)
	{
		MainDlg = (HWND) hWnd;
		return ::ChangePwd (volumePath, oldPassword, old_pkcs5, 0, FALSE, newPassword, pkcs5, 0, wipePassCount, (HWND) hWnd);
	}

	virtual int STDMETHODCALLTYPE ChangePasswordEx2 (BSTR volumePath, Password *oldPassword, int old_pkcs5, BOOL truecryptMode, Password *newPassword, int pkcs5, int wipePassCount, __int64 hWnd)
	{
		MainDlg = (HWND) hWnd;
		return ::ChangePwd (volumePath, oldPassword, old_pkcs5, 0, truecryptMode, newPassword, pkcs5, 0, wipePassCount, (HWND) hWnd);
	}

	virtual int STDMETHODCALLTYPE ChangePasswordEx3 (BSTR volumePath, Password *oldPassword, int old_pkcs5, int old_pim, BOOL truecryptMode, Password *newPassword, int pkcs5, int pim, int wipePassCount, __int64 hWnd)
	{
		MainDlg = (HWND) hWnd;
		return ::ChangePwd (volumePath, oldPassword, old_pkcs5, old_pim, truecryptMode, newPassword, pkcs5, pim, wipePassCount, (HWND) hWnd);
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


extern "C" int UacBackupVolumeHeader (HWND hwndDlg, BOOL bRequireConfirmation, wchar_t *lpszVolume)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
	{
		CComBSTR volumeBstr;
		BSTR bstr = W2BSTR(lpszVolume);
		if (bstr)
		{
			volumeBstr.Attach (bstr);
			r = tc->BackupVolumeHeader ((__int64) hwndDlg, bRequireConfirmation, volumeBstr);
		}
		else
			r = ERR_OUTOFMEMORY;
	}
	else
		r = -1;

	CoUninitialize ();

	return r;
}


extern "C" int UacRestoreVolumeHeader (HWND hwndDlg, wchar_t *lpszVolume)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
	{
		CComBSTR volumeBstr;
		BSTR bstr = W2BSTR(lpszVolume);
		if (bstr)
		{
			volumeBstr.Attach (bstr);
			r = tc->RestoreVolumeHeader ((__int64) hwndDlg, volumeBstr);
		}
		else
			r = ERR_OUTOFMEMORY;
	}
	else
		r = -1;

	CoUninitialize ();

	return r;
}


extern "C" int UacChangePwd (wchar_t *lpszVolume, Password *oldPassword, int old_pkcs5, int old_pim, BOOL truecryptMode, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg)
{
	CComPtr<ITrueCryptMainCom> tc;
	int r;

	CoInitialize (NULL);

	if (ComGetInstance (hwndDlg, &tc))
	{
		CComBSTR bstrVolume (lpszVolume);
		WaitCursor ();
		r = tc->ChangePasswordEx3 (bstrVolume, oldPassword, old_pkcs5, old_pim, truecryptMode, newPassword, pkcs5, pim, wipePassCount, (__int64) hwndDlg);
		NormalCursor ();
	}
	else
		r = -1;

	CoUninitialize ();

	return r;
}
