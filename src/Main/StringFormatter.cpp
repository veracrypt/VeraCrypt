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

#include "System.h"
#include "StringFormatter.h"
#include "UserInterfaceException.h"

namespace VeraCrypt
{
	StringFormatter::StringFormatter (const wxString &format, StringFormatterArg arg0, StringFormatterArg arg1, StringFormatterArg arg2, StringFormatterArg arg3, StringFormatterArg arg4, StringFormatterArg arg5, StringFormatterArg arg6, StringFormatterArg arg7, StringFormatterArg arg8, StringFormatterArg arg9)
	{
		bool numberExpected = false;
		bool endTagExpected = false;

		//TODO replace this workaround for %s, %d, %c for printf
		wxString text(format);
		text.Replace (L"%s", L"{}",true);
		text.Replace (L"%d", L"{}",true);
		text.Replace (L"%c", L"{}",true);
		int i=0;
		while (text.find(L"{}") != (size_t) wxNOT_FOUND){
			text.Replace(L"{}",L"{"+wxString::Format(wxT("%i"),i++)+L"}",false);
		}

		foreach (wchar_t c, wstring (text))
		{
			if (numberExpected)
			{
				endTagExpected = true;
				bool err = false;

				switch (c)
				{
				case L'{': FormattedString += L'{'; endTagExpected = false; break; // Escaped {

				case L'0': FormattedString += arg0; err = arg0.IsEmpty(); break;
				case L'1': FormattedString += arg1; err = arg1.IsEmpty(); break;
				case L'2': FormattedString += arg2; err = arg2.IsEmpty(); break;
				case L'3': FormattedString += arg3; err = arg3.IsEmpty(); break;
				case L'4': FormattedString += arg4; err = arg4.IsEmpty(); break;
				case L'5': FormattedString += arg5; err = arg5.IsEmpty(); break;
				case L'6': FormattedString += arg6; err = arg6.IsEmpty(); break;
				case L'7': FormattedString += arg7; err = arg7.IsEmpty(); break;
				case L'8': FormattedString += arg8; err = arg8.IsEmpty(); break;
				case L'9': FormattedString += arg9; err = arg9.IsEmpty(); break;

				default: err = true; break;
				}

				if (err)
					throw StringFormatterException (SRC_POS, wstring (format));

				numberExpected = false;
			}
			else if (endTagExpected)
			{
				if (c != L'}')
					throw StringFormatterException (SRC_POS, wstring (format));

				endTagExpected = false;
			}
			else if (c == L'{')
			{
				numberExpected = true;
			}
			else if (c == L'}')
			{
				FormattedString += c;
				endTagExpected = true;
			}
			else
				FormattedString += c;
		}

		if (numberExpected
			|| endTagExpected
			|| (!arg0.WasReferenced() && !arg0.IsEmpty())
			|| (!arg1.WasReferenced() && !arg1.IsEmpty())
			|| (!arg2.WasReferenced() && !arg2.IsEmpty())
			|| (!arg3.WasReferenced() && !arg3.IsEmpty())
			|| (!arg4.WasReferenced() && !arg4.IsEmpty())
			|| (!arg5.WasReferenced() && !arg5.IsEmpty())
			|| (!arg6.WasReferenced() && !arg6.IsEmpty())
			|| (!arg7.WasReferenced() && !arg7.IsEmpty())
			|| (!arg8.WasReferenced() && !arg8.IsEmpty())
			|| (!arg9.WasReferenced() && !arg9.IsEmpty())
			)
			throw StringFormatterException (SRC_POS, wstring (format));
	}

	StringFormatter::~StringFormatter ()
	{
	}
}
