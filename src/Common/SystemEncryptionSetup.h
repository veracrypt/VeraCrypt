/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0; see License.txt.
*/
#ifndef TC_HEADER_Common_SystemEncryptionSetup
#define TC_HEADER_Common_SystemEncryptionSetup
#include <windows.h>
#include <string>
#include <vector>
namespace VeraCrypt { namespace SystemEncryptionSetup
{
	class Ini
	{
	public:
		Ini () : Unicode (false), Utf8Bom (false) { }
		DWORD Load (const std::vector<unsigned char> &bytes)
		{
			Text.clear (); Unicode = false; Utf8Bom = false;
			if (bytes.size () >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe)
			{
				if (bytes.size () % 2) return ERROR_NO_UNICODE_TRANSLATION;
				Unicode = true;
				for (size_t i = 2; i < bytes.size (); i += 2) Text += wchar_t (bytes[i] | (bytes[i + 1] << 8));
			}
			else if (bytes.size () >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf)
			{
				Unicode = true; Utf8Bom = true;
				DWORD error = Decode (std::string (bytes.begin () + 3, bytes.end ()), CP_UTF8, Text);
				if (error != ERROR_SUCCESS) return error;
			}
			else
			{
				if (bytes.size () >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) return ERROR_NO_UNICODE_TRANSLATION;
				for (size_t i = 0; i < bytes.size (); ++i) Text += wchar_t (bytes[i]);
			}
			for (size_t i = 0; i < Text.size (); ++i)
				if (Text[i] < L' ' && Text[i] != L'\t' && Text[i] != L'\r' && Text[i] != L'\n') return ERROR_INVALID_DATA;
			return ERROR_SUCCESS;
		}

		DWORD Set (const wchar_t *key, const std::wstring *value)
		{
			std::wstring encoded;
			if (value)
			{
				if (value->find_first_of (L"\r\n") != std::wstring::npos || value->find (L'\0') != std::wstring::npos) return ERROR_INVALID_DATA;
				encoded = *value;
				if (!Unicode)
				{
					BOOL substituted = FALSE;
					UINT cp = GetACP ();
					DWORD flags = cp == CP_UTF8 ? WC_ERR_INVALID_CHARS : WC_NO_BEST_FIT_CHARS;
					BOOL *usedDefault = cp == CP_UTF8 ? NULL : &substituted;
					int size = WideCharToMultiByte (cp, flags, value->c_str (), (int) value->size (), NULL, 0, NULL, usedDefault);
					std::string bytes (size > 0 ? size : 0, '\0');
					if (size > 0 && !WideCharToMultiByte (cp, flags, value->c_str (), (int) value->size (), &bytes[0], size, NULL, usedDefault)) return GetLastError ();
					if ((size <= 0 && !value->empty ()) || substituted)
					{
						// A non-ASCII BOMless UTF-8 file is indistinguishable from
						// some ANSI files. Do not silently reinterpret its other values.
						std::string original = ByteString (Text); std::wstring utf8, decoded;
						if (cp != CP_UTF8 && Decode (original, CP_UTF8, utf8) == ERROR_SUCCESS && utf8 != Text) return ERROR_NO_UNICODE_TRANSLATION;
						DWORD error = Decode (original, cp, decoded); if (error != ERROR_SUCCESS) return error;
						Text.swap (decoded); Unicode = true;
					}
					else { encoded.clear (); for (size_t i = 0; i < bytes.size (); ++i) encoded += wchar_t ((unsigned char) bytes[i]); }
				}
			}
			std::wstring result; bool section = false, inserted = false;
			for (size_t start = 0; start < Text.size (); )
			{
				size_t end = LineEnd (Text, start);
				std::wstring original = Text.substr (start, end - start), line = Trim (original);
				if (!line.empty () && line[0] == L'[')
				{
					if (section && !inserted && value) { Append (result, key, encoded); inserted = true; }
					section = IsSection (line);
				}
				// Replace the first occurrence in place and remove duplicates.
				// Keeping its position avoids two rewrites on every maintenance run.
				if (section && IsKey (line, key))
				{
					if (value && !inserted) { Append (result, key, encoded); inserted = true; }
				}
				else result += original;
				start = end;
			}
			if (value && !inserted)
			{
				if (!section) { EndLine (result); result += L"[SetupConfig]\r\n"; }
				Append (result, key, encoded);
			}
			Text.swap (result); return ERROR_SUCCESS;
		}

		// Inspect every occurrence, including duplicate sections. Cleanup must
		// remove only registrations whose ownership the caller recognizes.
		template <class Predicate> DWORD RemoveMatching (const wchar_t *key, Predicate remove)
		{
			std::wstring result; bool section = false;
			for (size_t start = 0; start < Text.size (); )
			{
				size_t end = LineEnd (Text, start);
				std::wstring original = Text.substr (start, end - start), line = Trim (original);
				bool discard = false;
				if (!line.empty () && line[0] == L'[') section = IsSection (line);
				else if (section && IsKey (line, key))
				{
					size_t equals = line.find (L'=');
					std::wstring value = equals == std::wstring::npos ? L"" : Trim (line.substr (equals + 1));
					if (value.size () >= 2 && (value[0] == L'\"' || value[0] == L'\'') && value.back () == value[0])
						value = value.substr (1, value.size () - 2);
					if (!Unicode)
					{
						DWORD error = Decode (ByteString (value), CP_ACP, value);
						if (error != ERROR_SUCCESS) return error;
					}
					discard = remove (value);
				}
				if (!discard) result += original;
				start = end;
			}
			Text.swap (result); return ERROR_SUCCESS;
		}

		bool IsEmpty () const
		{
			// Empty SetupConfig headers are left by removing our last options.
			// Preserve comments, other sections and every other nonblank line.
			for (size_t start = 0; start < Text.size (); )
			{
				size_t end = LineEnd (Text, start);
				std::wstring line = Trim (Text.substr (start, end - start));
				if (!line.empty () && _wcsicmp (line.c_str (), L"[SetupConfig]") != 0) return false;
				start = end;
			}
			return true;
		}

		DWORD PreservedBytes (std::vector<unsigned char> &bytes) const
		{
			if (!Utf8Bom) { bytes = Bytes (); return ERROR_SUCCESS; }
			// Do not activate another product's hidden UTF-8-BOM section by
			// converting its encoding while removing our own registrations.
			bytes.assign ({ 0xef, 0xbb, 0xbf });
			if (Text.empty ()) return ERROR_SUCCESS;
			int size = WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, Text.data (), (int) Text.size (), NULL, 0, NULL, NULL);
			if (!size) return GetLastError ();
			bytes.resize (3 + size);
			return WideCharToMultiByte (CP_UTF8, WC_ERR_INVALID_CHARS, Text.data (), (int) Text.size (),
				reinterpret_cast<char *> (bytes.data () + 3), size, NULL, NULL) ? ERROR_SUCCESS : GetLastError ();
		}

		std::vector<unsigned char> Bytes () const
		{
			std::vector<unsigned char> bytes;
			if (Unicode) { bytes.push_back (0xff); bytes.push_back (0xfe); }
			for (size_t i = 0; i < Text.size (); ++i)
			{
				bytes.push_back (static_cast<unsigned char> (Text[i] & 255));
				if (Unicode) bytes.push_back (static_cast<unsigned char> (Text[i] >> 8));
			}
			return bytes;
		}
	private:
		static size_t LineEnd (const std::wstring &text, size_t start)
		{
			size_t end = text.find_first_of (L"\r\n", start);
			if (end == std::wstring::npos) return text.size ();
			if (text[end] == L'\r' && end + 1 < text.size () && text[end + 1] == L'\n') ++end;
			return end + 1;
		}
		static std::string ByteString (const std::wstring &text)
		{
			std::string bytes; bytes.reserve (text.size ());
			for (size_t i = 0; i < text.size (); ++i) bytes += static_cast<char> (text[i]);
			return bytes;
		}
		static DWORD Decode (const std::string &bytes, UINT cp, std::wstring &text)
		{
			text.clear (); if (bytes.empty ()) return ERROR_SUCCESS;
			int size = MultiByteToWideChar (cp, MB_ERR_INVALID_CHARS, bytes.data (), (int) bytes.size (), NULL, 0);
			if (!size) return GetLastError ();
			text.resize (size);
			return MultiByteToWideChar (cp, MB_ERR_INVALID_CHARS, bytes.data (), (int) bytes.size (), &text[0], size) ? ERROR_SUCCESS : GetLastError ();
		}
		static std::wstring Trim (const std::wstring &text)
		{
			size_t start = text.find_first_not_of (L" \t\r\n"), end = text.find_last_not_of (L" \t\r\n");
			return start == std::wstring::npos ? L"" : text.substr (start, end - start + 1);
		}
		static bool IsSection (const std::wstring &line)
		{
			size_t end = line.find (L']');
			// Windows profile APIs also accept a section terminated by the end
			// of the line without a closing bracket. Recognize it before editing
			// so a consumer-visible value cannot survive replacement/removal.
			return _wcsicmp (Trim (line.substr (1, end == std::wstring::npos ? end : end - 1)).c_str (), L"SetupConfig") == 0;
		}
		static bool IsKey (const std::wstring &line, const wchar_t *key)
		{
			return _wcsicmp (Trim (line.substr (0, line.find (L'='))).c_str (), key) == 0;
		}
		static void EndLine (std::wstring &text) { if (!text.empty () && text.back () != L'\n' && text.back () != L'\r') text += L"\r\n"; }
		static void Append (std::wstring &text, const wchar_t *key, const std::wstring &value)
		{
			EndLine (text); text += key; text += L"="; text += value; text += L"\r\n";
		}
		std::wstring Text;
		bool Unicode, Utf8Bom;
	};
} }
#endif
