/*
 Copyright (c) 2005-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Language.h"
#include "Dlgcode.h"
#include "Dictionary.h"
#include "Tcdefs.h"
#include "Xml.h"

#include "../Common/Resource.h"

#ifdef TCMOUNT
#include "../Mount/Resource.h"
#endif

#ifdef VOLFORMAT
#include "../Format/Resource.h"
#endif

#ifdef SETUP
#include "../Setup/Resource.h"
#endif

BOOL LocalizationActive;
int LocalizationSerialNo;

wchar_t UnknownString[1024];
static char *LanguageFileBuffer;
static HANDLE LanguageFileFindHandle = INVALID_HANDLE_VALUE;
static char PreferredLangId[6];
static char *LanguageResource;
static char *HeaderResource[2];
static char ActiveLangPackVersion[6];

static char *MapFirstLanguageFile ()
{
	if (LanguageFileFindHandle != INVALID_HANDLE_VALUE)
	{
		FindClose (LanguageFileFindHandle);
		LanguageFileFindHandle = INVALID_HANDLE_VALUE;
	}

	if (LanguageResource == NULL)
	{
		DWORD size;
		LanguageResource = MapResource ("Xml", IDR_LANGUAGE, &size);
		LanguageResource[size - 1] = 0;
	}

	return LanguageResource;
}


static char *MapNextLanguageFile ()
{
	wchar_t f[TC_MAX_PATH*2], *t;
	WIN32_FIND_DATAW find;
	HANDLE file;
	DWORD read;

	if (LanguageFileFindHandle == INVALID_HANDLE_VALUE)
	{
		GetModuleFileNameW (NULL, f, sizeof (f) / sizeof (f[0]));
		t = wcsrchr (f, L'\\');
		if (t == NULL) return NULL;

		wcscpy (t, L"\\Language*.xml");

		LanguageFileFindHandle = FindFirstFileW (f, &find);
	}
	else if (!FindNextFileW (LanguageFileFindHandle, &find))
	{
		FindClose (LanguageFileFindHandle);
		LanguageFileFindHandle = INVALID_HANDLE_VALUE;
		return NULL;
	}

	if (find.nFileSizeHigh != 0) return NULL;

	if (LanguageFileBuffer != NULL) free (LanguageFileBuffer);
	LanguageFileBuffer = malloc(find.nFileSizeLow);
	if (LanguageFileBuffer == NULL) return NULL;

	GetModuleFileNameW (NULL, f, sizeof (f) / sizeof(f[0]));
	t = wcsrchr (f, L'\\');
	wcscpy (t + 1, find.cFileName);

	file = CreateFileW (f, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) return NULL;

	ReadFile (file, LanguageFileBuffer, find.nFileSizeLow, &read, NULL);
	CloseHandle (file);
	if (read != find.nFileSizeLow) return NULL;

	return LanguageFileBuffer;
}


BOOL LoadLanguageFile ()
{
	DWORD size;
	BYTE *res;
	char *xml, *header;
	char langId[6] = "en", attr[32768], key[128];
	BOOL defaultLangParsed = FALSE, langFound = FALSE;
	WCHAR wattr[32768];
	int i, intKey, len;

	char *xmlElements[] = {"control", "string", 0};

#ifdef TCMOUNT
	int headers[] = { IDR_COMMON_RSRC_HEADER, IDR_MOUNT_RSRC_HEADER, 0 };
#endif

#ifdef VOLFORMAT
	int headers[] = { IDR_COMMON_RSRC_HEADER, IDR_FORMAT_RSRC_HEADER, 0 };
#endif

#ifdef SETUP
	int headers[] = { IDR_COMMON_RSRC_HEADER, IDR_SETUP_RSRC_HEADER, 0 };
#endif

	LocalizationActive = FALSE;
	ActiveLangPackVersion[0] = 0;
	ClearDictionaryPool ();

	if (PreferredLangId[0] != 0)
		strcpy (langId, PreferredLangId);

	// Parse all available language files until preferred language is found
	for (res = MapFirstLanguageFile (); res != NULL; res = MapNextLanguageFile ())
	{
		xml = (char *) res;
		xml = XmlFindElement (xml, "localization");
		if (!xml)
			continue;

		// Required TrueCrypt version
		XmlGetAttributeText (xml, "prog-version", attr, sizeof (attr));

		// Check version of external language file
		if (defaultLangParsed && strcmp (attr, VERSION_STRING) && strcmp (attr, "DEBUG"))
		{
			wchar_t m[2048];
			swprintf (m, L"The installed language pack is incompatible with this version of VeraCrypt (the language pack is for VeraCrypt %hs). A newer version may be available at www.idrix.fr.\n\nTo prevent this message from being displayed, do any of the following:\n\n- Select 'Settings' > 'Language'; then select 'English' and click 'OK'.\n\n- Remove or replace the language pack with a compatible version (the language pack may reside e.g. in 'C:\\Program Files\\VeraCrypt' or '%%LOCALAPPDATA%%\\VirtualStore\\Program Files\\VeraCrypt', etc.)", attr);
			MessageBoxW (NULL, m, L"VeraCrypt", MB_ICONERROR);
			continue;
		}

		// Search language id in language file
		if (defaultLangParsed)
		{
			while (xml = XmlFindElement (xml, "language"))
			{
				XmlGetAttributeText (xml, "langid", attr, sizeof (attr));
				if (strcmp (attr, langId) == 0)
				{
					XmlGetAttributeText (xml++, "version", ActiveLangPackVersion, sizeof (ActiveLangPackVersion));
					langFound = TRUE;
					break;
				}
				xml++;
			}

			if (!langFound) continue;
		}

		// Create font dictionary
		xml = (char *) res;
		while (xml = XmlFindElement (xml, "font"))
		{
			XmlGetAttributeText (xml, "lang", attr, sizeof (attr));
			if (!defaultLangParsed
				|| strcmp (attr, langId) == 0)
			{
				Font font;
				memset (&font, 0, sizeof (font));

				XmlGetAttributeText (xml, "face", attr, sizeof (attr));
			
				len = MultiByteToWideChar (CP_UTF8, 0, attr, -1, wattr, sizeof (wattr) / sizeof(wattr[0]));
				font.FaceName = AddPoolData ((void *) wattr, len * 2);
				
				XmlGetAttributeText (xml, "size", attr, sizeof (attr));
				sscanf (attr, "%d", &font.Size);

				strcpy (attr, "font_");
				XmlGetAttributeText (xml, "class", attr + 5, sizeof (attr) - 5);
				AddDictionaryEntry (
					AddPoolData ((void *) attr, strlen (attr) + 1), 0,
					AddPoolData ((void *) &font, sizeof(font)));
			}

			xml++;
		}

		// Create string and control dictionaries
		for (i = 0; xmlElements[i] != 0; i++)
		{
			xml = (char *) res;
			while (xml = XmlFindElement (xml, xmlElements[i]))
			{
				void *key;
				void *text;

				XmlGetAttributeText (xml, "lang", attr, sizeof (attr));
				if (!defaultLangParsed
					|| strcmp (attr, langId) == 0)
				{
					if (XmlGetAttributeText (xml, "key", attr, sizeof (attr)))
					{
						key = AddPoolData (attr, strlen (attr) + 1);
						if (key == NULL) return FALSE;

						XmlGetNodeText (xml, attr, sizeof (attr));

						// Parse \ escape sequences
						{
							char *in = attr, *out = attr;
							while (*in)
							{
								if (*in == '\\')
								{
									in++;
									switch (*in++)
									{
									case '\\': *out++ = '\\'; break;
									case 't': *out++ = '\t'; break;
									case 'n': *out++ = 13; *out++ = 10; break;
									default:
										MessageBox (0, key, "VeraCrypt: Unknown '\\' escape sequence in string", MB_ICONERROR);
										return FALSE;
									}
								}
								else
									*out++ = *in++;
							}
							*out = 0;
						}

						// UTF8 => wide char
						len = MultiByteToWideChar (CP_UTF8, 0, attr, -1, wattr, sizeof (wattr) / sizeof(wattr[0]));
						if (len == 0 || len == ERROR_NO_UNICODE_TRANSLATION)
						{
							MessageBox (0, key, "VeraCrypt: Error while decoding UTF-8 string", MB_ICONERROR);
							return FALSE;
						}

						// Add to dictionary
						text = AddPoolData ((void *) wattr, len * 2);
						if (text == NULL) return FALSE;

						AddDictionaryEntry ((char *) key, 0, text);
					}
				}

				xml++;
			}
		}

		if (langFound)
			break;

		if (!defaultLangParsed)
		{
			defaultLangParsed = TRUE;
			if (langId[0] == 0 || strcmp (langId, "en") == 0)
				break;
		}
	}

	LocalizationActive = langFound && strcmp (langId, "en") != 0;
	LocalizationSerialNo++;

	// Create control ID dictionary
	
	// Default controls
	AddDictionaryEntry (NULL, 1, GetString ("IDOK"));
	AddDictionaryEntry (NULL, 2, GetString ("IDCANCEL"));
	AddDictionaryEntry (NULL, 8, GetString ("IDCLOSE"));
	AddDictionaryEntry (NULL, 9, GetString ("IDHELP"));

	for (i = 0; headers[i] != 0; i++)
	{
		if (HeaderResource[i] == NULL)
		{
			HeaderResource[i] = MapResource ("Header", headers[i], &size);
			*(HeaderResource[i] + size - 1) = 0;
		}

		header = HeaderResource[i];
		if (header == NULL) return FALSE;

		do
		{
			if (sscanf (header, "#define %s %d", key, &intKey) == 2)
			{
				WCHAR *str = GetString (key);

				if (str != UnknownString)
					AddDictionaryEntry (NULL, intKey, str);
			}

		} while ((header = strchr (header, '\n') + 1) != (char *) 1);
	}

	return TRUE;
}


// lParam = 1: auto mode
BOOL CALLBACK LanguageDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			char *xml;
			char attr[2048], lastLangId[10];
			WCHAR wattr[2048];
			int len;
			int langCount = 0;
			BOOL defaultLangFound = FALSE;

			LocalizeDialog (hwndDlg, "IDD_LANGUAGE");
			ToHyperlink (hwndDlg, IDC_GET_LANG_PACKS);

			for (xml = MapFirstLanguageFile (); xml != NULL; xml = MapNextLanguageFile ())
			{
				while (xml = XmlFindElement (xml, "language"))
				{
					XmlGetAttributeText (xml, "name", attr, sizeof (attr));
					len = MultiByteToWideChar (CP_UTF8, 0, attr, -1, wattr, sizeof (wattr) / sizeof(wattr[0]));

					if (len != 0 && len != ERROR_NO_UNICODE_TRANSLATION
						&& (!defaultLangFound || wcscmp (wattr, L"English") != 0))
					{
						int i = SendDlgItemMessageW (hwndDlg, IDC_LANGLIST, LB_ADDSTRING, 0, (LPARAM)wattr);
						if (i >= 0)
						{
							int id;

							// Encode language id in LPARAM
							XmlGetAttributeText (xml, "langid", attr, sizeof (attr));
							switch (strlen (attr))
							{
							case 2: id = attr[0] | attr[1] << 8; break;
							case 5: id = attr[0] | attr[1] << 8 | attr[3] << 16 | attr[4] << 24; break;
							default: continue;
							}

							if (!defaultLangFound)
								defaultLangFound = TRUE;

							SendDlgItemMessage (hwndDlg, IDC_LANGLIST, LB_SETITEMDATA, i, (LPARAM) id);

							if (strcmp (attr, PreferredLangId) == 0)
							{
								char credits [10000];
								WCHAR wcredits [10000];
								WCHAR wversion [20];
								wchar_t szVers [200];
								int nLen;

								SendDlgItemMessage (hwndDlg, IDC_LANGLIST, LB_SETCURSEL, i, 0);

								// Language pack version 
								if (!ActiveLangPackVersion[0] || memcmp (ActiveLangPackVersion, "0.0.0", 5) == 0)
								{
									swprintf (szVers, GetString("LANG_PACK_VERSION"), L"--");
								}
								else
								{
									nLen = MultiByteToWideChar (CP_UTF8, 0, ActiveLangPackVersion, -1, wversion, sizeof (wversion) / sizeof(wversion[0]));
									if (nLen != 0 && nLen != ERROR_NO_UNICODE_TRANSLATION)
										swprintf (szVers, GetString("LANG_PACK_VERSION"), wversion);
								}
								SetWindowTextW (GetDlgItem (hwndDlg, IDC_LANGPACK_VERSION), szVers);

								// Translator credits
								XmlGetAttributeText (xml, "translators", credits, sizeof (credits));
								nLen = MultiByteToWideChar (CP_UTF8, 0, credits, -1, wcredits, sizeof (wcredits) / sizeof(wcredits[0]));
								if (nLen != 0 && nLen != ERROR_NO_UNICODE_TRANSLATION)
								{
									SetWindowTextW (GetDlgItem (hwndDlg, IDC_LANGPACK_CREDITS), wcredits);
								}
							}

							strcpy (lastLangId, attr);
							langCount++;
						}
					}

					xml++;
				}
			}

			if (lParam == 1)
			{
				// Auto mode
				if (langCount < 2) 
					EndDialog (hwndDlg, IDCANCEL);

				if (langCount == 2)
					strcpy (PreferredLangId, lastLangId);
				
				EndDialog (hwndDlg, IDOK);
			}

			return 1;
		}

	case WM_COMMAND:

		if (lw == IDOK || hw == LBN_DBLCLK)
		{
			int i = SendDlgItemMessage (hwndDlg, IDC_LANGLIST, LB_GETCURSEL, 0, 0);

			if (i >= 0)
			{
				int id = SendDlgItemMessage (hwndDlg, IDC_LANGLIST, LB_GETITEMDATA, i, 0);

				if (id != LB_ERR)
				{
					char l[6];

					// Decode language id from LPARAM
					l[0] = (char) id;
					l[1] = (char) (id >> 8);
					l[2] = 0;

					if ((id & 0xffff0000) != 0)
					{
						l[2] = '-';
						l[3] = (char) (id >> 16);
						l[4] = id >> 24;
						l[5] = 0;
					}	
		
					if (SendDlgItemMessage (hwndDlg, IDC_LANGLIST, LB_GETCOUNT, 0, 0) > 1)
						strcpy (PreferredLangId, l);
				}
			}

			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			EndDialog (hwndDlg, lw);
			return 1;
		}

		if (lw == IDC_GET_LANG_PACKS)
		{
			char tmpstr [256];

			if (strlen (ActiveLangPackVersion) > 0 && strlen (GetPreferredLangId()) > 0)
				sprintf (tmpstr, "&langpackversion=%s&lang=%s", ActiveLangPackVersion, GetPreferredLangId());
			else
				tmpstr[0] = 0;

			Applink ("localizations", TRUE, tmpstr);

			return 1;
		}
		return 0;
	}

	return 0;
}


char *GetPreferredLangId ()
{
	return PreferredLangId;
}


void SetPreferredLangId (char *langId)
{
	strncpy (PreferredLangId, langId, 5);
}


char *GetActiveLangPackVersion ()
{
	return ActiveLangPackVersion;
}


wchar_t *GetString (const char *stringId)
{
	WCHAR *str = (WCHAR *) GetDictionaryValue (stringId);
	if (str != NULL) return str;

	wsprintfW (UnknownString, UNKNOWN_STRING_ID L"%hs" UNKNOWN_STRING_ID, stringId);
	return UnknownString;
}


Font *GetFont (char *fontType)
{
	return (Font *) GetDictionaryValue (fontType);

}
