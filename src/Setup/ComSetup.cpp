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

#define TC_MAIN_COM_VERSION_MAJOR 2
#define TC_MAIN_COM_VERSION_MINOR 13

#define TC_FORMAT_COM_VERSION_MAJOR 2
#define TC_FORMAT_COM_VERSION_MINOR 10

#include <atlbase.h>
#include <comdef.h>
#include <statreg.h>
#include <windows.h>
#include "ComSetup.h"
#include "Dlgcode.h"
#include "Resource.h"

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        EXTERN_C __declspec(selectany) const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

// Define GUIDs of "VeraCrypt.exe and" "VeraCrypt Format.exe" type libraries
MIDL_DEFINE_GUID(GUID, LIBID_TrueCryptMainCom, 0x9ACF6176, 0x5FC4, 0x4690, 0xA0, 0x25, 0xB3, 0x30, 0x6A, 0x50, 0xEB, 0x6A);
MIDL_DEFINE_GUID(GUID, LIBID_TrueCryptFormatCom, 0x56327DDA, 0xF1A7, 0x4e13, 0xB1, 0x28, 0x52, 0x0D, 0x12, 0x9B, 0xDE, 0xF6);


extern "C" BOOL RegisterComServers (wchar_t *modulePath)
{
	BOOL ret = TRUE;
	wchar_t mainModule[1024], formatModule[1024];
	CComPtr<ITypeLib> tl, tl2;

	wsprintfW (mainModule, L"%sVeraCrypt.exe", modulePath);
	wsprintfW (formatModule, L"%sVeraCrypt Format.exe", modulePath);

	UnRegisterTypeLib (LIBID_TrueCryptMainCom, TC_MAIN_COM_VERSION_MAJOR, TC_MAIN_COM_VERSION_MINOR, 0, SYS_WIN32);
	UnRegisterTypeLib (LIBID_TrueCryptFormatCom, TC_FORMAT_COM_VERSION_MAJOR, TC_FORMAT_COM_VERSION_MINOR, 0, SYS_WIN32);
	// unregister older versions that may still exist
	for (WORD i = 9; i >= 1; i--)
		UnRegisterTypeLib (LIBID_TrueCryptMainCom, TC_MAIN_COM_VERSION_MAJOR, TC_MAIN_COM_VERSION_MINOR-i, 0, SYS_WIN32);
	for (WORD i = 6; i >= 1; i--)
		UnRegisterTypeLib (LIBID_TrueCryptFormatCom, TC_FORMAT_COM_VERSION_MAJOR, TC_FORMAT_COM_VERSION_MINOR-i, 0, SYS_WIN32);

	wchar_t setupModule[MAX_PATH];
	GetModuleFileNameW (NULL, setupModule, sizeof (setupModule) / sizeof (setupModule[0]));

	CRegObject ro;
	HRESULT r;

	if (!SUCCEEDED (r = ro.FinalConstruct ())
		|| !SUCCEEDED (r = ro.AddReplacement (L"MAIN_MODULE", mainModule))
		|| !SUCCEEDED (r = ro.AddReplacement (L"FORMAT_MODULE", formatModule))
		|| !SUCCEEDED (r = ro.ResourceRegister (setupModule, IDR_COMREG, L"REGISTRY"))
		|| !SUCCEEDED (r = LoadTypeLib (mainModule, &tl))
		|| !SUCCEEDED (r = RegisterTypeLib (tl, mainModule, 0))
		|| !SUCCEEDED (r = LoadTypeLib (formatModule, &tl2))
		|| !SUCCEEDED (r = RegisterTypeLib (tl2, formatModule, 0)))
	{
		MessageBox (MainDlg, _com_error (r).ErrorMessage(), _T(TC_APP_NAME), MB_ICONERROR);
		ret = FALSE;
	}

	ro.FinalRelease ();
	return ret;
}


extern "C" BOOL UnregisterComServers (wchar_t *modulePath)
{
	BOOL ret;

	if (UnRegisterTypeLib (LIBID_TrueCryptMainCom, TC_MAIN_COM_VERSION_MAJOR, TC_MAIN_COM_VERSION_MINOR, 0, SYS_WIN32) != S_OK)
		return FALSE;
	if (UnRegisterTypeLib (LIBID_TrueCryptFormatCom, TC_FORMAT_COM_VERSION_MAJOR, TC_FORMAT_COM_VERSION_MINOR, 0, SYS_WIN32) != S_OK)
		return FALSE;

	// unregister older versions that may still exist
	for (WORD i = 9; i >= 1; i--)
		UnRegisterTypeLib (LIBID_TrueCryptMainCom, TC_MAIN_COM_VERSION_MAJOR, TC_MAIN_COM_VERSION_MINOR-i, 0, SYS_WIN32);
	for (WORD i = 6; i >= 1; i--)
		UnRegisterTypeLib (LIBID_TrueCryptFormatCom, TC_FORMAT_COM_VERSION_MAJOR, TC_FORMAT_COM_VERSION_MINOR-i, 0, SYS_WIN32);

	wchar_t module[1024];
	CRegObject ro;
	ro.FinalConstruct ();

	wsprintfW (module, L"%sVeraCrypt.exe", modulePath);
	ro.AddReplacement (L"MAIN_MODULE", module);

	wsprintfW (module, L"%sVeraCrypt Format.exe", modulePath);
	ro.AddReplacement (L"FORMAT_MODULE", module);

	wchar_t setupModule[MAX_PATH];
	GetModuleFileNameW (NULL, setupModule, sizeof (setupModule) / sizeof (setupModule[0]));

	ret = ro.ResourceUnregister (setupModule, IDR_COMREG, L"REGISTRY") == S_OK;

	ro.FinalRelease ();
	return ret;
}
