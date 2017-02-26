/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_StringFormatter
#define TC_HEADER_Main_StringFormatter

#include "System.h"
#include "Main.h"

namespace VeraCrypt
{
	class StringFormatterArg
	{
	public:
		StringFormatterArg () : Empty (true) { }

		StringFormatterArg (const char c) :			Empty (false) { string s; s += c; StringArg = StringConverter::ToWide (s); }
		StringFormatterArg (const wchar_t c) :		Empty (false), Referenced (false), StringArg (c) { }
		StringFormatterArg (const char *str) :		Empty (false), Referenced (false), StringArg (StringConverter::ToWide (str)) { }
		StringFormatterArg (const wchar_t *str) :	Empty (false), Referenced (false), StringArg (str) { }
		StringFormatterArg (const string &str) :	Empty (false), Referenced (false), StringArg (StringConverter::ToWide (str)) { }
		StringFormatterArg (const wstring &str) :	Empty (false), Referenced (false), StringArg (str) { }
		StringFormatterArg (const wxString &str) :	Empty (false), Referenced (false), StringArg (str) { }
		StringFormatterArg (int32 number) :			Empty (false), Referenced (false), StringArg (StringConverter::FromNumber (number)) { }
		StringFormatterArg (uint32 number) :		Empty (false), Referenced (false), StringArg (StringConverter::FromNumber (number)) { }
		StringFormatterArg (int64 number) :			Empty (false), Referenced (false), StringArg (StringConverter::FromNumber (number)) { }
		StringFormatterArg (uint64 number) :		Empty (false), Referenced (false), StringArg (StringConverter::FromNumber (number)) { }

		operator wxString () { Referenced = true; return StringArg; }

		bool IsEmpty () const { return Empty; }
		bool WasReferenced() const { return Referenced; }

	protected:
		bool Empty;
		bool Referenced;
		wxString StringArg;
	};

	class StringFormatter
	{
	public:
		StringFormatter (const wxString &format, StringFormatterArg arg0 = StringFormatterArg(), StringFormatterArg arg1 = StringFormatterArg(), StringFormatterArg arg2 = StringFormatterArg(), StringFormatterArg arg3 = StringFormatterArg(), StringFormatterArg arg4 = StringFormatterArg(), StringFormatterArg arg5 = StringFormatterArg(), StringFormatterArg arg6 = StringFormatterArg(), StringFormatterArg arg7 = StringFormatterArg(), StringFormatterArg arg8 = StringFormatterArg(), StringFormatterArg arg9 = StringFormatterArg());
		virtual ~StringFormatter ();

		operator wstring () const { return wstring (FormattedString); }
		operator wxString () const { return FormattedString; }
		operator StringFormatterArg () const { return FormattedString; }

	protected:
		wxString FormattedString;

	private:
		StringFormatter (const StringFormatter &);
		StringFormatter &operator= (const StringFormatter &);
	};
}

#endif // TC_HEADER_Main_StringFormatter
