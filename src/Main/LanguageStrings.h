/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_LanguageStrings
#define TC_HEADER_Main_LanguageStrings

#include "System.h"
#include "Main.h"

namespace TrueCrypt
{
	class LanguageStrings
	{
	public:
		LanguageStrings ();
		virtual ~LanguageStrings ();

		wxString operator[] (const string &key) const;

		bool Exists (const string &key) const { return Map.find (key) != Map.end(); }
		wstring Get (const string &key) const;
		void Init ();

	protected:
		map <string, wstring> Map;

	private:
		LanguageStrings (const LanguageStrings &);
		LanguageStrings &operator= (const LanguageStrings &);
	};

	extern LanguageStrings LangString;
}

#endif // TC_HEADER_Main_LanguageStrings
