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

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	/* When adding/removing hot keys, update the following functions in Mount.c:
	DisplayHotkeyList()
	SaveSettings()
	LoadSettings()
	HandleHotKey()	*/

	HK_AUTOMOUNT_DEVICES = 0,
	HK_CLOSE_SECURITY_TOKEN_SESSIONS,
	HK_DISMOUNT_ALL,
	HK_DISMOUNT_ALL_AND_WIPE,
	HK_FORCE_DISMOUNT_ALL_AND_WIPE,
	HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT,
	HK_MOUNT_FAVORITE_VOLUMES,
	HK_SHOW_HIDE_MAIN_WINDOW,
	HK_WIPE_CACHE,
	NBR_HOTKEYS
};

typedef struct
{
	UINT vKeyCode;
	UINT vKeyModifiers;
} TCHOTKEY;

extern TCHOTKEY	Hotkeys [NBR_HOTKEYS];

BOOL CALLBACK HotkeysDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL GetKeyName (UINT vKey, wchar_t *keyName);
void UnregisterAllHotkeys (HWND hwndDlg, TCHOTKEY hotkeys[]);
BOOL RegisterAllHotkeys (HWND hwndDlg, TCHOTKEY hotkeys[]);

#ifdef __cplusplus
}
#endif
