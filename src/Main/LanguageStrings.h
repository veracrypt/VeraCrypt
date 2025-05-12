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

#ifndef TC_HEADER_Main_LanguageStrings
#define TC_HEADER_Main_LanguageStrings

#include "System.h"
#include "Main.h"

namespace VeraCrypt
{
	class LanguageStrings
	{
	public:
		LanguageStrings ();
		virtual ~LanguageStrings ();

		wxString operator[] (const string &key) const;

		bool Exists (const string &key) const { return Map.find (key) != Map.end(); }
		wstring Get (const string &key) const;
		string GetPreferredLang () const { return PreferredLang; }
		void Init ();

	protected:
		map <string, wstring> Map;
		string PreferredLang;

	private:
		LanguageStrings (const LanguageStrings &);
		LanguageStrings &operator= (const LanguageStrings &);
	};

	extern LanguageStrings LangString;
}

#endif // TC_HEADER_Main_LanguageStrings
