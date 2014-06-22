/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Application.h"
#include "LanguageStrings.h"
#include "GraphicUserInterface.h"
#include "Hotkey.h"
#include "Xml.h"

namespace VeraCrypt
{
	HotkeyList Hotkey::GetAvailableHotkeys ()
	{
		HotkeyList hotkeys;
#ifdef TC_WINDOWS

#define TC_HOTKEY(ID,LANG) hotkeys.push_back (shared_ptr <Hotkey> (new Hotkey (Id::##ID, L###ID, LangString[LANG])))

		TC_HOTKEY (CloseAllSecurityTokenSessions, "IDM_CLOSE_ALL_TOKEN_SESSIONS");
		TC_HOTKEY (DismountAll, "HK_DISMOUNT_ALL");
		TC_HOTKEY (DismountAllWipeCache, "HK_DISMOUNT_ALL_AND_WIPE");
		TC_HOTKEY (ForceDismountAllWipeCache, "HK_FORCE_DISMOUNT_ALL_AND_WIPE");
		TC_HOTKEY (ForceDismountAllWipeCacheExit, "HK_FORCE_DISMOUNT_ALL_AND_WIPE_AND_EXIT");
		TC_HOTKEY (MountAllDevices, "HK_AUTOMOUNT_DEVICES");
		TC_HOTKEY (MountAllFavorites, "HK_MOUNT_FAVORITE_VOLUMES");
		TC_HOTKEY (ShowHideApplication, "HK_SHOW_HIDE_MAIN_WINDOW");
		TC_HOTKEY (WipeCache, "HK_WIPE_CACHE");

#endif
		return hotkeys;
	}

	wxString Hotkey::GetShortcutString () const
	{
		wxString keyStr = Hotkey::GetVirtualKeyCodeString (VirtualKeyCode);
		if (keyStr.empty())
			return L"";

		wxString str;

		if (VirtualKeyModifiers & wxMOD_SHIFT)
			str += LangString["VK_SHIFT"] + L"+";
		
		if (VirtualKeyModifiers & wxMOD_CONTROL)
			str += LangString["VK_CONTROL"] + L"+";
		
		if (VirtualKeyModifiers & wxMOD_ALT)
			str += LangString["VK_ALT"] + L"+";
		
		if (VirtualKeyModifiers & wxMOD_WIN )
			str += LangString["VK_WIN"] + L"+";

		return str + keyStr;
	}

	wxString Hotkey::GetVirtualKeyCodeString (int virtualKeyCode)
	{
#ifdef TC_WINDOWS
		// ASCII characters
		if (virtualKeyCode >= 0x30 && virtualKeyCode <= 0x5a)	
			return StringFormatter (L"{0}", char (virtualKeyCode));

		// OEM-specific
		if (virtualKeyCode >= 0xE9 && virtualKeyCode <= 0xF5)	
			return StringFormatter (L"OEM-{0}", virtualKeyCode);

		// F1-F24
		if (virtualKeyCode >= VK_F1 && virtualKeyCode <= VK_F24)
			return StringFormatter (L"F{0}", virtualKeyCode - VK_F1 + 1);

		// Numpad numbers
		if (virtualKeyCode >= VK_NUMPAD0 && virtualKeyCode <= VK_NUMPAD9)
			return StringFormatter (L"{0} {1}", LangString["VK_NUMPAD"], virtualKeyCode - VK_NUMPAD0);

		switch (virtualKeyCode)
		{
		case VK_MULTIPLY:	return LangString["VK_NUMPAD"] + L" *";
		case VK_ADD:		return LangString["VK_NUMPAD"] + L" +";
		case VK_SEPARATOR:	return LangString["VK_NUMPAD"] + L" Separator";
		case VK_SUBTRACT:	return LangString["VK_NUMPAD"] + L" -";
		case VK_DECIMAL:	return LangString["VK_NUMPAD"] + L" .";
		case VK_DIVIDE:		return LangString["VK_NUMPAD"] + L" /";
		case VK_OEM_1:		return L"OEM 1 (';')";
		case VK_OEM_PLUS:	return L"+";
		case VK_OEM_COMMA:	return L",";
		case VK_OEM_MINUS:	return L"-";
		case VK_OEM_PERIOD:	return L".";
		case VK_OEM_2:		return L"OEM 2 ('/')";
		case VK_OEM_3:		return L"OEM 3 (`)";
		case VK_OEM_4:		return L"OEM 4 ('[')";
		case VK_OEM_5:		return L"OEM 5 ('\\')";
		case VK_OEM_6:		return L"OEM 6 (']')";
		case VK_OEM_7:		return L"OEM 7 (')";
		case VK_OEM_8:		return L"OEM 8";
		case VK_OEM_AX:		return L"OEM AX";
		case VK_OEM_102:	return L"OEM 102";
		case VK_ICO_HELP:	return L"ICO_HELP";
		case VK_ICO_00:		return L"ICO_00";
		case VK_ICO_CLEAR:	return L"ICO_CLEAR";
		case VK_ATTN:		return L"Attn";
		case VK_CRSEL:		return L"CrSel";
		case VK_EXSEL:		return L"ExSel";
		case VK_EREOF:		return L"Erase EOF";
		case VK_PA1:		return L"PA1";
		case VK_OEM_CLEAR:	return L"OEM Clear";

		case 0:
		case 1:
		case 0xFF:
			break;

		default:
			{
				string langStrId = StringConverter::ToSingle (wstring (wxString::Format (L"VKEY_%02X", virtualKeyCode)));
				if (LangString.Exists (langStrId))
					return LangString[langStrId];
			}
		}
#endif // TC_WINDOWS
		return L"";
	}

	HotkeyList Hotkey::LoadList ()
	{
		HotkeyList hotkeys = GetAvailableHotkeys();

		FilePath path = Application::GetConfigFilePath (GetFileName());
		if (path.IsFile())
		{
			foreach (XmlNode node, XmlParser (path).GetNodes (L"hotkey"))
			{
				wstring keyName (node.Attributes[L"name"]);

				foreach (shared_ptr <Hotkey> hotkey, hotkeys)
				{
					if (hotkey->Name == keyName)
					{
						hotkey->VirtualKeyCode = StringConverter::ToUInt32 (wstring (node.Attributes[L"vkeycode"]));
						hotkey->VirtualKeyModifiers = 0;
						
						if (node.Attributes[L"modshift"] == L"1")
							hotkey->VirtualKeyModifiers |= wxMOD_SHIFT;

						if (node.Attributes[L"modcontrol"] == L"1")
							hotkey->VirtualKeyModifiers |= wxMOD_CONTROL;

						if (node.Attributes[L"modalt"] == L"1")
							hotkey->VirtualKeyModifiers |= wxMOD_ALT;

						if (node.Attributes[L"modwin"] == L"1")
							hotkey->VirtualKeyModifiers |= wxMOD_WIN;

						break;
					}
				}
			}
		}

		return hotkeys;
	}

	void Hotkey::RegisterList (wxWindow *handler, const HotkeyList &hotkeys)
	{
#ifdef TC_WINDOWS
		bool res = true;
		foreach (shared_ptr <Hotkey> hotkey, hotkeys)
		{
			if (hotkey->VirtualKeyCode != 0)
			{
				if (!handler->RegisterHotKey (hotkey->Id, hotkey->VirtualKeyModifiers, hotkey->VirtualKeyCode))
					res = false;
			}
		}

		if (!res)
			Gui->ShowWarning ("HOTKEY_REGISTRATION_ERROR");
#endif
	}

	void Hotkey::SaveList (const HotkeyList &hotkeys)
	{
		FilePath hotkeysCfgPath = Application::GetConfigFilePath (GetFileName(), true);

		bool noHotkey = true;
		XmlNode hotkeysXml (L"hotkeys");
		foreach_ref (const Hotkey &hotkey, hotkeys)
		{
			if (hotkey.VirtualKeyCode == 0)
				continue;

			noHotkey = false;
			XmlNode node (L"hotkey");
			node.Attributes[L"name"] = wstring (hotkey.Name);

			node.Attributes[L"vkeycode"] = StringConverter::FromNumber (hotkey.VirtualKeyCode);

			if (hotkey.VirtualKeyModifiers & wxMOD_SHIFT)
				node.Attributes[L"modshift"] = L"1";

			if (hotkey.VirtualKeyModifiers & wxMOD_CONTROL)
				node.Attributes[L"modcontrol"] = L"1";

			if (hotkey.VirtualKeyModifiers & wxMOD_ALT)
				node.Attributes[L"modalt"] = L"1";

			if (hotkey.VirtualKeyModifiers & wxMOD_WIN )
				node.Attributes[L"modwin"] = L"1";

			hotkeysXml.InnerNodes.push_back (node);
		}

		if (noHotkey)
		{
			if (hotkeysCfgPath.IsFile())
				hotkeysCfgPath.Delete();
		}
		else
		{
			XmlWriter hotkeysWriter (hotkeysCfgPath);
			hotkeysWriter.WriteNode (hotkeysXml);
			hotkeysWriter.Close();
		}
	}

	void Hotkey::UnregisterList (wxWindow *handler, const HotkeyList &hotkeys)
	{
#ifdef TC_WINDOWS
		foreach (shared_ptr <Hotkey> hotkey, hotkeys)
		{
			if (hotkey->VirtualKeyCode != 0)
				handler->UnregisterHotKey (hotkey->Id);
		}
#endif
	}
}
