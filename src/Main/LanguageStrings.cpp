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
#include "Resources.h"
#include "LanguageStrings.h"
#include "Xml.h"

namespace VeraCrypt
{
	LanguageStrings::LanguageStrings ()
	{
	}

	LanguageStrings::~LanguageStrings ()
	{
	}

	wxString LanguageStrings::operator[] (const string &key) const
	{
		if (Map.count (key) > 0)
			return wxString (Map.find (key)->second);
		// return "VeraCrypt" as it is
		if (key == "VeraCrypt")
			return L"VeraCrypt";

		return wxString (L"?") + StringConverter::ToWide (key) + L"?";
	}

	wstring LanguageStrings::Get (const string &key) const
	{
		return wstring (LangString[key]);
	}

	void LanguageStrings::Init ()
	{
		static byte LanguageXml[] =
        {
#           include "Common/Language.xml.h"
            , 0
        };
		string def = string ((const char*) LanguageXml);
		foreach (XmlNode node, XmlParser (def).GetNodes (L"entry"))
		{
			wxString text = node.InnerText;
			text.Replace (L"\\n", L"\n");
			Map[StringConverter::ToSingle (wstring (node.Attributes[L"key"]))] = text;
		}

		foreach (XmlNode node, XmlParser (Resources::GetLanguageXml()).GetNodes (L"entry"))
		{
			wxString text = node.InnerText;
			text.Replace (L"\\n", L"\n");
			Map[StringConverter::ToSingle (wstring (node.Attributes[L"key"]))] = text;
		}
	}

	LanguageStrings LangString;
}
