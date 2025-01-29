/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <windows.h>
#include "Dlgcode.h"
#include "Hotkeys.h"
#include "Language.h"
#include "Mount.h"
#include "Resource.h"

#include <Strsafe.h>

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

#define MAX_KEY_COMB_NAME_LEN	260

TCHOTKEY	Hotkeys [NBR_HOTKEYS];
static TCHOTKEY	tmpHotkeys [NBR_HOTKEYS];

static int nSelectedHotkeyId;
static UINT currentVKeyCode;
static BYTE vkeysDown[256];


static void ScanAndProcessKey (UINT *vKeyCode, wchar_t *keyName)
{
	UINT vKey;
	*vKeyCode = 0;

	for (vKey = 0; vKey <= 0xFF; vKey++)
	{
		if (GetAsyncKeyState (vKey) < 0)
		{
			if (!vkeysDown [vKey])
			{
				vkeysDown [vKey] = 1;
				if (GetKeyName (vKey, keyName))	// If the key is allowed and its name has been resolved
					*vKeyCode = vKey;
			}
		}
		else
			vkeysDown [vKey] = 0;
	}
}


/* Returns TRUE if the key is allowed and its name is resolved. */
BOOL GetKeyName (UINT vKey, wchar_t *keyName)
{
	BOOL result = TRUE;

	if (vKey >= 0x30 && vKey <= 0x5a)
	{
		// ASCII characters
		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%hc", (char) vKey);
	}
	else if (vKey >= 0xE9 && vKey <= 0xF5)
	{
		// OEM-specific
		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM-%d", vKey);

		// mapping taken from:
		//	http://www.hotkeynet.com/ref/keynames.html
		//	https://mojoware.googlecode.com/svn-history/r3/trunk/mojo_engine/cKeyboard.cpp
		//	http://www.screenio.com/gui_screenio/gs_htmlhelp_subweb/download/SIMKEYS.cob
		//
		// These values seem to come from Nokia/Ericsson mobile device keys

		switch (vKey)
		{
		case 0xE9: // OEMReset = 0xE9
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMReset)");
			break;
		case 0xEA: // OEMJump = 0xEA
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMJump)");
			break;
		case 0xEB: // OEMPA1 = 0xEB
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMPA1)");
			break;
		case 0xEC: // OEMPA2 = 0xEC
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMPA2)");
			break;
		case 0xED: // OEMPA3 = 0xED
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMPA3)");
			break;
		case 0xEE: // OEMWSCtrl = 0xEE
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMWSCtrl)");
			break;
		case 0xEF: // OEMCUSel = 0xEF
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMCUSel)");
			break;
		case 0xF0: // OEMATTN = 0xF0
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMATTN)");
			break;
		case 0xF1: // OEMFinish = 0xF1
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMFinish)");
			break;
		case 0xF2: // OEMCopy = 0xF2
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMCopy)");
			break;
		case 0xF3: // OEMAuto = 0xF3
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMAuto)");
			break;
		case 0xF4: // OEMENLW = 0xF4
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMENLW)");
			break;
		case 0xF5: // OEMBackTab = 0xF5
			StringCbCatW (keyName, MAX_KEY_COMB_NAME_LEN, L" (OEMBackTab)");
			break;
		}
	}
	else if (vKey >= VK_F1 && vKey <= VK_F24)
	{
		// F1-F24
		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"F%d", vKey - VK_F1 + 1);
	}
	else if (vKey >= VK_NUMPAD0 && vKey <= VK_NUMPAD9)
	{
		// Numpad numbers
		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s %d", GetString ("VK_NUMPAD"), vKey - VK_NUMPAD0);
	}
	else
	{
		switch (vKey)
		{
		case VK_MULTIPLY:	StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s *", GetString ("VK_NUMPAD")); break;
		case VK_ADD:		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s +", GetString ("VK_NUMPAD")); break;
		case VK_SEPARATOR:	StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s Separator", GetString ("VK_NUMPAD")); break;
		case VK_SUBTRACT:	StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s -", GetString ("VK_NUMPAD")); break;
		case VK_DECIMAL:	StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s .", GetString ("VK_NUMPAD")); break;
		case VK_DIVIDE:		StringCbPrintfW (keyName, MAX_KEY_COMB_NAME_LEN, L"%s /", GetString ("VK_NUMPAD")); break;
		case VK_OEM_1:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 1 (';')"); break;
		case VK_OEM_PLUS:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"+"); break;
		case VK_OEM_COMMA:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L","); break;
		case VK_OEM_MINUS:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"-"); break;
		case VK_OEM_PERIOD:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L".");	break;
		case VK_OEM_2:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 2 ('/')"); break;
		case VK_OEM_3:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 3 (`)"); break;
		case VK_OEM_4:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 4 ('[')"); break;
		case VK_OEM_5:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 5 ('\\')"); break;
		case VK_OEM_6:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 6 (']')"); break;
		case VK_OEM_7:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 7 (')"); break;
		case VK_OEM_8:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 8"); break;
		case VK_OEM_AX:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM AX"); break;
		case VK_OEM_102:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM 102"); break;
		case VK_ICO_HELP:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"ICO_HELP"); break;
		case VK_ICO_00:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"ICO_00"); break;
		case VK_ICO_CLEAR:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"ICO_CLEAR"); break;
		case VK_ATTN:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"Attn"); break;
		case VK_CRSEL:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"CrSel"); break;
		case VK_EXSEL:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"ExSel"); break;
		case VK_EREOF:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"Erase EOF"); break;
		case VK_PA1:		StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"PA1"); break;
		case VK_OEM_CLEAR:	StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, L"OEM Clear"); break;

		case 0:
		case 1:
		case 0xFF:
			result = FALSE;
			break;

		default:
			{
				char key[16];
				wchar_t *desc;
				StringCbPrintfA (key, sizeof(key),"VKEY_%02X", vKey);
				desc = GetString (key);
				if (desc == UnknownString)
					result = FALSE;
				else
					StringCbCopyW (keyName, MAX_KEY_COMB_NAME_LEN, desc);
			}
		}
	}
	return result;
}


static BOOL ShortcutInUse (UINT vKeyCode, UINT modifiers, TCHOTKEY hotkeys[])
{
	int i;

	for (i = 0; i < NBR_HOTKEYS; i++)
	{
		if (hotkeys[i].vKeyCode == vKeyCode && hotkeys[i].vKeyModifiers == modifiers)
			return TRUE;
	}
	return FALSE;
}


void UnregisterAllHotkeys (HWND hwndDlg, TCHOTKEY hotkeys[])
{
	int i;

	for (i = 0; i < NBR_HOTKEYS; i++)
	{
		if (hotkeys[i].vKeyCode != 0)
			UnregisterHotKey (hwndDlg, i);

	}
}


BOOL RegisterAllHotkeys (HWND hwndDlg, TCHOTKEY hotkeys[])
{
	BOOL result = TRUE;
	int i;

	for (i = 0; i < NBR_HOTKEYS; i++)
	{
		if (hotkeys[i].vKeyCode != 0
		&& !RegisterHotKey (hwndDlg, i, hotkeys[i].vKeyModifiers, hotkeys[i].vKeyCode))
			result = FALSE;
	}

	return result;
}


static void DisplayHotkeyList (HWND hwndDlg)
{
	LVITEMW item;
	HWND hList = GetDlgItem (hwndDlg, IDC_HOTKEY_LIST);
	int i;
	wchar_t ShortcutMod [MAX_KEY_COMB_NAME_LEN];
	wchar_t ShortcutFinal [MAX_KEY_COMB_NAME_LEN*2];
	wchar_t Shortcut [MAX_KEY_COMB_NAME_LEN];

	SendMessage (hList, LVM_DELETEALLITEMS,0, (LPARAM)&item);

	for (i = 0; i < NBR_HOTKEYS; i++)
	{
		memset (&item,0,sizeof(item));
		item.mask = LVIF_TEXT;
		item.iItem = i;
		item.iSubItem = 0;

		switch (i)
		{

		case HK_AUTOMOUNT_DEVICES:
			item.pszText = GetString ("HK_AUTOMOUNT_DEVICES");
			break;

		case HK_UNMOUNT_ALL:
			item.pszText = GetString ("HK_UNMOUNT_ALL");
			break;

		case HK_WIPE_CACHE:
			item.pszText = GetString ("HK_WIPE_CACHE");
			break;

		case HK_UNMOUNT_ALL_AND_WIPE:
			item.pszText = GetString ("HK_UNMOUNT_ALL_AND_WIPE");
			break;

		case HK_FORCE_UNMOUNT_ALL_AND_WIPE:
			item.pszText = GetString ("HK_FORCE_UNMOUNT_ALL_AND_WIPE");
			break;

		case HK_FORCE_UNMOUNT_ALL_AND_WIPE_AND_EXIT:
			item.pszText = GetString ("HK_FORCE_UNMOUNT_ALL_AND_WIPE_AND_EXIT");
			break;

		case HK_MOUNT_FAVORITE_VOLUMES:
			item.pszText = GetString ("HK_MOUNT_FAVORITE_VOLUMES");
			break;

		case HK_SHOW_HIDE_MAIN_WINDOW:
			item.pszText = GetString ("HK_SHOW_HIDE_MAIN_WINDOW");
			break;

		case HK_CLOSE_SECURITY_TOKEN_SESSIONS:
			item.pszText = GetString ("IDM_CLOSE_ALL_TOKEN_SESSIONS");
			break;

		default:
			item.pszText = L"[?]";
		}

		SendMessageW (hList,LVM_INSERTITEMW,0,(LPARAM)&item);

		item.iSubItem = 1;
		Shortcut[0] = 0;
		ShortcutMod[0] = 0;

		if (GetKeyName (tmpHotkeys[i].vKeyCode, Shortcut))
		{
			if (tmpHotkeys[i].vKeyModifiers & MOD_CONTROL)
			{
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),GetString ("VK_CONTROL"));
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_SHIFT)
			{
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),GetString ("VK_SHIFT"));
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_ALT)
			{
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),GetString ("VK_ALT"));
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_WIN)
			{
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),GetString ("VK_WIN"));
				StringCbCatW (ShortcutMod, sizeof(ShortcutMod),L"+");
			}

			StringCbPrintfW (ShortcutFinal, sizeof(ShortcutFinal), L"%s%s", ShortcutMod, Shortcut);
			item.pszText = ShortcutFinal;
		}
		else
			item.pszText = L"";

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&item);
	}
}



BOOL CALLBACK HotkeysDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static BOOL bKeyScanOn;
	static BOOL bTPlaySoundOnSuccessfulHkDismount;
	static BOOL bTDisplayBalloonOnSuccessfulHkDismount;

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW col;
			HWND hList = GetDlgItem (hwndDlg, IDC_HOTKEY_LIST);

			bKeyScanOn = FALSE;
			nSelectedHotkeyId = -1;
			currentVKeyCode = 0;
			memcpy (tmpHotkeys, Hotkeys, sizeof(tmpHotkeys));
			memset (vkeysDown, 0, sizeof(vkeysDown));

			SendMessageW (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP
				);

			memset (&col,0,sizeof(col));
			col.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;
			col.pszText = GetString ("ACTION");
			col.cx = CompensateXDPI (341);
			col.fmt = LVCFMT_LEFT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,0,(LPARAM)&col);

			col.pszText = GetString ("SHORTCUT");
			col.cx = CompensateXDPI (190);
			col.fmt = LVCFMT_LEFT;
			SendMessageW (hList,LVM_INSERTCOLUMNW,1,(LPARAM)&col);

			LocalizeDialog (hwndDlg, "IDD_HOTKEYS_DLG");

			SetCheckBox (hwndDlg, IDC_HK_MOD_CTRL, TRUE);
			SetCheckBox (hwndDlg, IDC_HK_MOD_SHIFT, FALSE);
			SetCheckBox (hwndDlg, IDC_HK_MOD_ALT, TRUE);
			SetCheckBox (hwndDlg, IDC_HK_MOD_WIN, FALSE);

			SetCheckBox (hwndDlg, IDC_HK_UNMOUNT_PLAY_SOUND, bPlaySoundOnSuccessfulHkDismount);
			SetCheckBox (hwndDlg, IDC_HK_UNMOUNT_BALLOON_TOOLTIP, bDisplayBalloonOnSuccessfulHkDismount);

			bTPlaySoundOnSuccessfulHkDismount = bPlaySoundOnSuccessfulHkDismount;
			bTDisplayBalloonOnSuccessfulHkDismount = bDisplayBalloonOnSuccessfulHkDismount;

			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);

			DisplayHotkeyList(hwndDlg);

			if (SetTimer (hwndDlg, 0xfe, 10, NULL) == 0)
			{
				Error ("CANNOT_SET_TIMER", MainDlg);
				EndDialog (hwndDlg, IDCANCEL);
				return 1;
			}
			return 1;
		}

	case WM_TIMER:
		{
			if ((nSelectedHotkeyId > -1) && (GetFocus () == GetDlgItem (hwndDlg, IDC_HOTKEY_KEY)))
			{
				wchar_t keyName [MAX_KEY_COMB_NAME_LEN];
				UINT tmpVKeyCode;

				keyName[0] = 0;

				ScanAndProcessKey (&tmpVKeyCode, &keyName[0]);

				if (keyName[0] != 0)
				{
					currentVKeyCode = tmpVKeyCode;
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), keyName);
					EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), TRUE);
				}
				else if ((currentVKeyCode != 0) && GetKeyName (currentVKeyCode, keyName))
				{
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), keyName);
				}
			}
			return 1;
		}

	case WM_NOTIFY:
		if (wParam == IDC_HOTKEY_LIST)
		{
			if (((LPNMHDR) lParam)->code == LVN_ITEMACTIVATE
				|| ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED))
			{
				LVITEM item;
				memset(&item,0,sizeof(item));
				nSelectedHotkeyId = ((LPNMLISTVIEW) lParam)->iItem;
				currentVKeyCode = 0;
				memset (vkeysDown, 0, sizeof(vkeysDown));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), GetString ("PRESS_A_KEY_TO_ASSIGN"));

				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), (tmpHotkeys[nSelectedHotkeyId].vKeyCode > 0));

				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
				bKeyScanOn = TRUE;
				return 1;
			}
		}

		return 0;

	case WM_COMMAND:
		if (lw == IDC_HOTKEY_KEY && hw == EN_CHANGE)
		{
			if (!bKeyScanOn && nSelectedHotkeyId < 0 && GetWindowTextLengthW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY)))
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
		}

		if (lw == IDC_HOTKEY_ASSIGN)
		{
			BOOL bOwnActiveShortcut = FALSE;

			if (nSelectedHotkeyId >= 0 && currentVKeyCode != 0)
			{
				UINT modifiers = 0;
				if (GetCheckBox (hwndDlg, IDC_HK_MOD_CTRL))
					modifiers = MOD_CONTROL;

				if (GetCheckBox (hwndDlg, IDC_HK_MOD_ALT))
					modifiers |= MOD_ALT;

				if (GetCheckBox (hwndDlg, IDC_HK_MOD_SHIFT))
					modifiers |= MOD_SHIFT;

				if (GetCheckBox (hwndDlg, IDC_HK_MOD_WIN))
					modifiers |= MOD_WIN;

				// Check if it's not already assigned
				if (ShortcutInUse (currentVKeyCode, modifiers, tmpHotkeys))
				{
					Error ("SHORTCUT_ALREADY_IN_USE", hwndDlg);
					return 1;
				}

				// Check for reserved system keys
				switch (currentVKeyCode)
				{
				case VK_F1:
				case VK_F12:
					/* F1 is help and F12 is reserved for use by the debugger at all times */
					if (modifiers == 0)
					{
						Error ("CANNOT_USE_RESERVED_KEY", hwndDlg);
						return 1;
					}
					break;
				}

				bOwnActiveShortcut = ShortcutInUse (currentVKeyCode, modifiers, Hotkeys);

				// Test if the shortcut can be assigned without errors
				if (!bOwnActiveShortcut
					&& !RegisterHotKey (hwndDlg, nSelectedHotkeyId, modifiers, currentVKeyCode))
				{
					handleWin32Error(hwndDlg, SRC_POS);
					return 1;
				}
				else
				{
					if (!bOwnActiveShortcut && !UnregisterHotKey (hwndDlg, nSelectedHotkeyId))
						handleWin32Error(hwndDlg, SRC_POS);

					tmpHotkeys[nSelectedHotkeyId].vKeyCode = currentVKeyCode;
					tmpHotkeys[nSelectedHotkeyId].vKeyModifiers = modifiers;

					SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
					EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);
					nSelectedHotkeyId = -1;
					bKeyScanOn = FALSE;
					currentVKeyCode = 0;
					memset (vkeysDown, 0, sizeof(vkeysDown));
				}
			}
			DisplayHotkeyList(hwndDlg);
			return 1;
		}

		if (lw == IDC_HOTKEY_REMOVE)
		{
			if (nSelectedHotkeyId >= 0)
			{
				tmpHotkeys[nSelectedHotkeyId].vKeyCode = 0;
				tmpHotkeys[nSelectedHotkeyId].vKeyModifiers = 0;
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);
				nSelectedHotkeyId = -1;
				bKeyScanOn = FALSE;
				currentVKeyCode = 0;
				memset (vkeysDown, 0, sizeof(vkeysDown));
				DisplayHotkeyList(hwndDlg);
			}
			return 1;
		}

		if (lw == IDC_RESET_HOTKEYS)
		{
			int i;

			for (i = 0; i < NBR_HOTKEYS; i++)
			{
				tmpHotkeys[i].vKeyCode = 0;
				tmpHotkeys[i].vKeyModifiers = 0;
			}
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);
			nSelectedHotkeyId = -1;
			bKeyScanOn = FALSE;
			currentVKeyCode = 0;
			memset (vkeysDown, 0, sizeof(vkeysDown));
			DisplayHotkeyList(hwndDlg);
			return 1;
		}

		if (lw == IDC_HK_UNMOUNT_PLAY_SOUND)
		{
			bTPlaySoundOnSuccessfulHkDismount = GetCheckBox (hwndDlg, IDC_HK_UNMOUNT_PLAY_SOUND);
		}

		if (lw == IDC_HK_UNMOUNT_BALLOON_TOOLTIP)
		{
			bTDisplayBalloonOnSuccessfulHkDismount = GetCheckBox (hwndDlg, IDC_HK_UNMOUNT_BALLOON_TOOLTIP);
		}

		if (lw == IDCANCEL || lw == IDCLOSE)
		{
			KillTimer (hwndDlg, 0xfe);
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (lw == IDOK)
		{
			HWND hwndMainDlg = hwndDlg;

			while (GetParent (hwndMainDlg) != NULL)
			{
				hwndMainDlg = GetParent (hwndMainDlg);
			}
			UnregisterAllHotkeys (hwndMainDlg, Hotkeys);
			memcpy (Hotkeys, tmpHotkeys, sizeof(Hotkeys));
			RegisterAllHotkeys (hwndMainDlg, Hotkeys);
			KillTimer (hwndDlg, 0xfe);
			bPlaySoundOnSuccessfulHkDismount = bTPlaySoundOnSuccessfulHkDismount;
			bDisplayBalloonOnSuccessfulHkDismount = bTDisplayBalloonOnSuccessfulHkDismount;

			SaveSettings (hwndDlg);
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}
		return 0;

	case WM_CLOSE:

		KillTimer (hwndDlg, 0xfe);
		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}
	return 0;
}


