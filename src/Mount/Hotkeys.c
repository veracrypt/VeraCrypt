/*
 Copyright (c) 2005 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include "Dlgcode.h"
#include "Hotkeys.h"
#include "Language.h"
#include "Mount.h"
#include "Resource.h"

#define MAX_KEY_COMB_NAME_LEN	260

TCHOTKEY	Hotkeys [NBR_HOTKEYS];
static TCHOTKEY	tmpHotkeys [NBR_HOTKEYS];

static int nSelectedHotkeyId;
static UINT currentVKeyCode;


static void ScanAndProcessKey (UINT *vKeyCode, wchar_t *keyName)
{
	UINT vKey;
	*vKeyCode = 0;

	for (vKey = 0; vKey <= 0xFF; vKey++)
	{
		if (GetAsyncKeyState (vKey) < 0)
		{
			if (GetKeyName (vKey, keyName))	// If the key is allowed and its name has been resolved
				*vKeyCode = vKey;
		}
	}
}


/* Returns TRUE if the key is allowed and its name is resolved. */
BOOL GetKeyName (UINT vKey, wchar_t *keyName)
{
	BOOL result = TRUE;

	if (vKey >= 0x30 && vKey <= 0x5a)	
	{
		// ASCII characters
		wsprintfW (keyName, L"%hc", (char) vKey);
	}
	else if (vKey >= 0xE9 && vKey <= 0xF5)	
	{
		// OEM-specific
		wsprintfW (keyName, L"OEM-%d", vKey);
	}
	else if (vKey >= VK_F1 && vKey <= VK_F24)
	{
		// F1-F24
		wsprintfW (keyName, L"F%d", vKey - VK_F1 + 1);
	}
	else if (vKey >= VK_NUMPAD0 && vKey <= VK_NUMPAD9)
	{
		// Numpad numbers
		wsprintfW (keyName, L"%s %d", GetString ("VK_NUMPAD"), vKey - VK_NUMPAD0); 
	}
	else
	{
		switch (vKey)
		{
		case VK_MULTIPLY:	wsprintfW (keyName, L"%s *", GetString ("VK_NUMPAD")); break;
		case VK_ADD:		wsprintfW (keyName, L"%s +", GetString ("VK_NUMPAD")); break;
		case VK_SEPARATOR:	wsprintfW (keyName, L"%s Separator", GetString ("VK_NUMPAD")); break;
		case VK_SUBTRACT:	wsprintfW (keyName, L"%s -", GetString ("VK_NUMPAD")); break;
		case VK_DECIMAL:	wsprintfW (keyName, L"%s .", GetString ("VK_NUMPAD")); break;
		case VK_DIVIDE:		wsprintfW (keyName, L"%s /", GetString ("VK_NUMPAD")); break;
		case VK_OEM_1:		wcscpy (keyName, L"OEM 1 (';')"); break;
		case VK_OEM_PLUS:	wcscpy (keyName, L"+"); break;
		case VK_OEM_COMMA:	wcscpy (keyName, L","); break;
		case VK_OEM_MINUS:	wcscpy (keyName, L"-"); break;
		case VK_OEM_PERIOD:	wcscpy (keyName, L".");	break;
		case VK_OEM_2:		wcscpy (keyName, L"OEM 2 ('/')"); break;
		case VK_OEM_3:		wcscpy (keyName, L"OEM 3 (`)"); break;
		case VK_OEM_4:		wcscpy (keyName, L"OEM 4 ('[')"); break;
		case VK_OEM_5:		wcscpy (keyName, L"OEM 5 ('\\')"); break;
		case VK_OEM_6:		wcscpy (keyName, L"OEM 6 (']')"); break;
		case VK_OEM_7:		wcscpy (keyName, L"OEM 7 (')"); break;
		case VK_OEM_8:		wcscpy (keyName, L"OEM 8"); break;
		case VK_OEM_AX:		wcscpy (keyName, L"OEM AX"); break;
		case VK_OEM_102:	wcscpy (keyName, L"OEM 102"); break;
		case VK_ICO_HELP:	wcscpy (keyName, L"ICO_HELP"); break;
		case VK_ICO_00:		wcscpy (keyName, L"ICO_00"); break;
		case VK_ICO_CLEAR:	wcscpy (keyName, L"ICO_CLEAR"); break;
		case VK_ATTN:		wcscpy (keyName, L"Attn"); break;
		case VK_CRSEL:		wcscpy (keyName, L"CrSel"); break;
		case VK_EXSEL:		wcscpy (keyName, L"ExSel"); break;
		case VK_EREOF:		wcscpy (keyName, L"Erase EOF"); break;
		case VK_PA1:		wcscpy (keyName, L"PA1"); break;
		case VK_OEM_CLEAR:	wcscpy (keyName, L"OEM Clear"); break;

		case 0:
		case 1:
		case 0xFF:
			result = FALSE;
			break;

		default:
			{
				char key[16];
				wchar_t *desc;
				sprintf (key, "VKEY_%02X", vKey);
				desc = GetString (key);
				if (desc == UnknownString)
					result = FALSE;
				else
					wcsncpy (keyName, desc, MAX_KEY_COMB_NAME_LEN);
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

		case HK_DISMOUNT_ALL:	
			item.pszText = GetString ("HK_DISMOUNT_ALL");
			break;

		case HK_WIPE_CACHE:	
			item.pszText = GetString ("HK_WIPE_CACHE");
			break;

		case HK_DISMOUNT_ALL_AND_WIPE:	
			item.pszText = GetString ("HK_DISMOUNT_ALL_AND_WIPE");
			break;

		case HK_FORCE_DISMOUNT_ALL_AND_WIPE:	
			item.pszText = GetString ("HK_FORCE_DISMOUNT_ALL_AND_WIPE");
			break;

		case HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT:	
			item.pszText = GetString ("HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT");
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
		wcscpy (Shortcut, L"");
		wcscpy (ShortcutMod, L"");

		if (GetKeyName (tmpHotkeys[i].vKeyCode, Shortcut))
		{
			if (tmpHotkeys[i].vKeyModifiers & MOD_CONTROL)
			{
				wcscat (ShortcutMod, GetString ("VK_CONTROL"));
				wcscat (ShortcutMod, L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_SHIFT)
			{
				wcscat (ShortcutMod, GetString ("VK_SHIFT"));
				wcscat (ShortcutMod, L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_ALT)
			{
				wcscat (ShortcutMod, GetString ("VK_ALT"));
				wcscat (ShortcutMod, L"+");
			}

			if (tmpHotkeys[i].vKeyModifiers & MOD_WIN)
			{
				wcscat (ShortcutMod, GetString ("VK_WIN"));
				wcscat (ShortcutMod, L"+");
			}

			wsprintfW (ShortcutFinal, L"%s%s", ShortcutMod, Shortcut);
			item.pszText = ShortcutFinal;
		}
		else
			item.pszText = L"";

		SendMessageW (hList, LVM_SETITEMW, 0, (LPARAM)&item); 
	}
}



BOOL CALLBACK HotkeysDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HWND hList = GetDlgItem (hwndDlg, IDC_HOTKEY_LIST);
	HWND hwndMainDlg = hwndDlg;
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);
	static BOOL bKeyScanOn;
	static BOOL bTPlaySoundOnSuccessfulHkDismount;
	static BOOL bTDisplayBalloonOnSuccessfulHkDismount;

	while (GetParent (hwndMainDlg) != NULL)
	{
		hwndMainDlg = GetParent (hwndMainDlg);
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW col;

			bKeyScanOn = FALSE;
			nSelectedHotkeyId = -1;
			currentVKeyCode = 0;
			memcpy (tmpHotkeys, Hotkeys, sizeof(tmpHotkeys));

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

			SetCheckBox (hwndDlg, IDC_HK_DISMOUNT_PLAY_SOUND, bPlaySoundOnSuccessfulHkDismount);
			SetCheckBox (hwndDlg, IDC_HK_DISMOUNT_BALLOON_TOOLTIP, bDisplayBalloonOnSuccessfulHkDismount);

			bTPlaySoundOnSuccessfulHkDismount = bPlaySoundOnSuccessfulHkDismount;
			bTDisplayBalloonOnSuccessfulHkDismount = bDisplayBalloonOnSuccessfulHkDismount;

			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
			EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);

			DisplayHotkeyList(hwndDlg);
			
			SetTimer (hwndDlg, 0xfe, 10, NULL);
			return 1;
		}

	case WM_TIMER:
		{
			if (nSelectedHotkeyId > -1)
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
			}
			return 1;
		}

	case WM_COMMAND:
	case WM_NOTIFY:

		if (lw == IDC_HOTKEY_KEY && hw == EN_CHANGE)
		{
			if (!bKeyScanOn && nSelectedHotkeyId < 0 && GetWindowTextLengthW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY)))
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
		}

		if (msg == WM_NOTIFY && wParam == IDC_HOTKEY_LIST)
		{
			if (((LPNMHDR) lParam)->code == LVN_ITEMACTIVATE
				|| ((LPNMHDR) lParam)->code == LVN_ITEMCHANGED && (((LPNMLISTVIEW) lParam)->uNewState & LVIS_FOCUSED))
			{
				LVITEM item;
				memset(&item,0,sizeof(item));
				nSelectedHotkeyId = ((LPNMLISTVIEW) lParam)->iItem;
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), GetString ("PRESS_A_KEY_TO_ASSIGN"));

				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), (tmpHotkeys[nSelectedHotkeyId].vKeyCode > 0));

				EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
				bKeyScanOn = TRUE;
				return 1;
			}
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
					Error ("SHORTCUT_ALREADY_IN_USE");
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
						Error ("CANNOT_USE_RESERVED_KEY");
						return 1;
					}
					break;
				}

				bOwnActiveShortcut = ShortcutInUse (currentVKeyCode, modifiers, Hotkeys);

				// Test if the shortcut can be assigned without errors
				if (!bOwnActiveShortcut
					&& !RegisterHotKey (hwndDlg, nSelectedHotkeyId, modifiers, currentVKeyCode))
				{
					handleWin32Error(hwndDlg);
					return 1;
				}
				else
				{
					if (!bOwnActiveShortcut && !UnregisterHotKey (hwndDlg, nSelectedHotkeyId))
						handleWin32Error(hwndDlg);

					tmpHotkeys[nSelectedHotkeyId].vKeyCode = currentVKeyCode;
					tmpHotkeys[nSelectedHotkeyId].vKeyModifiers = modifiers;

					SetWindowTextW (GetDlgItem (hwndDlg, IDC_HOTKEY_KEY), L"");
					EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_ASSIGN), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_HOTKEY_REMOVE), FALSE);
					nSelectedHotkeyId = -1;
					bKeyScanOn = FALSE;
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
			DisplayHotkeyList(hwndDlg);
			return 1;
		}

		if (lw == IDC_HK_DISMOUNT_PLAY_SOUND)
		{
			bTPlaySoundOnSuccessfulHkDismount = GetCheckBox (hwndDlg, IDC_HK_DISMOUNT_PLAY_SOUND);
		}

		if (lw == IDC_HK_DISMOUNT_BALLOON_TOOLTIP)
		{
			bTDisplayBalloonOnSuccessfulHkDismount = GetCheckBox (hwndDlg, IDC_HK_DISMOUNT_BALLOON_TOOLTIP);
		}

		if (lw == IDCANCEL || lw == IDCLOSE)
		{
			KillTimer (hwndDlg, 0xfe);
			EndDialog (hwndDlg, IDCANCEL);
			return 1;
		}

		if (lw == IDOK)
		{
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


