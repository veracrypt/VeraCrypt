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

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNKNOWN_STRING_ID L"[?]"

extern BOOL LocalizationActive;
extern int LocalizationSerialNo;
extern wchar_t UnknownString[1024];

typedef struct
{
	wchar_t *FaceName;
	int Size;
} Font;

BOOL CALLBACK LanguageDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
wchar_t *GetString (const char *stringId);
Font *GetFont (char *fontType);
BOOL LoadLanguageFile ();
BOOL LoadLanguageFromResource (int resourceid, BOOL bSetPreferredLanguage, BOOL bForceSilent);
char *GetPreferredLangId ();
void SetPreferredLangId (char *langId);
char *GetActiveLangPackVersion ();

#ifdef __cplusplus
}
#endif
