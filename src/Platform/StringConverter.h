/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_StringConverter
#define TC_HEADER_Platform_StringConverter

#include <stdlib.h>
#include "PlatformBase.h"

namespace VeraCrypt
{
	class StringConverter
	{
	public:
		static void Erase (string &str);
		static void Erase (wstring &str);
		static wstring FromNumber (double number);
		static wstring FromNumber (int32 number);
		static wstring FromNumber (uint32 number);
		static wstring FromNumber (int64 number);
		static wstring FromNumber (uint64 number);
		static string GetTrailingNumber (const string &str);
		static string GetTypeName (const type_info &typeInfo);
		static wstring QuoteSpaces (const wstring &str);
		static vector <string> Split (const string &str, const string &separators = " \t\r\n", bool returnEmptyFields = false);
		static string StripTrailingNumber (const string &str);
		static wstring ToExceptionString (const exception &ex);
		static string ToLower (const string &str);
		static uint32 ToUInt32 (const string &str);
		static uint32 ToUInt32 (const wstring &str);
		static uint64 ToUInt64 (const string &str);
		static uint64 ToUInt64 (const wstring &str);
		static string ToSingle (double number) { return ToSingle (FromNumber (number)); }
		static string ToSingle (int32 number) { return ToSingle (FromNumber (number)); }
		static string ToSingle (uint32 number) { return ToSingle (FromNumber (number)); }
		static string ToSingle (int64 number) { return ToSingle (FromNumber (number)); }
		static string ToSingle (uint64 number) { return ToSingle (FromNumber (number)); }
		static string ToSingle (const wstring &wstr, bool noThrow = false);
		static void ToSingle (const wstring &wstr, string &str, bool noThrow = false);
		static string ToUpper (const string &str);
		static wstring ToWide (double number) { return FromNumber (number); }
		static wstring ToWide (int32 number) { return FromNumber (number); }
		static wstring ToWide (uint32 number) { return FromNumber (number); }
		static wstring ToWide (int64 number) { return FromNumber (number); }
		static wstring ToWide (uint64 number) { return FromNumber (number); }
		static wstring ToWide (const string &str, bool noThrow = false);
		static void ToWideBuffer (const wstring &str, wchar_t *buffer, size_t bufferSize);
		static string Trim (const string &str);

	private:
		StringConverter ();
	};
}

#endif // TC_HEADER_Platform_StringConverter
