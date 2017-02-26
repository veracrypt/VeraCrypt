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

#ifndef TC_HEADER_Main_Xml
#define TC_HEADER_Main_Xml

#include "System.h"
#include "Main.h"

namespace VeraCrypt
{
	struct XmlNode;
	typedef list <XmlNode> XmlNodeList;

	struct XmlNode
	{
		XmlNode () { }
		XmlNode (const wxString &name) : Name (name) { }
		XmlNode (const wxString &name, const wxString &innerText) : InnerText (innerText), Name (name) { }
		XmlNode (const wxString &name, const XmlNodeList &innerNodes) : InnerNodes (innerNodes), Name (name) { }

		map <wxString, wxString> Attributes;
		XmlNodeList InnerNodes;
		wxString InnerText;
		wxString Name;
	};

	class XmlParser
	{
	public:
		XmlParser (const FilePath &fileName);
		XmlParser (const string &xmlTextUtf8) : XmlText (wxString::FromUTF8 (xmlTextUtf8.c_str())) { }
		XmlParser (const wxString &xmlText) : XmlText (xmlText) { }
		virtual ~XmlParser () { }

		wxString ConvertEscapedChars (wxString xmlString) const;
		XmlNodeList GetNodes (const wxString &nodeName) const;

	protected:
		wxString XmlText;

	private:
		XmlParser (const XmlParser &);
		XmlParser &operator= (const XmlParser &);
	};

	class XmlWriter
	{
	public:
		XmlWriter (const FilePath &fileName);
		virtual ~XmlWriter ();

		void Close();
		wxString EscapeChars (wxString rawString) const;
		void WriteNode (const XmlNode &xmlNode);
		void WriteNodes (const XmlNodeList &xmlNodes);

	protected:
		int CurrentIndentLevel;
		auto_ptr <wxMemoryOutputStream> MemOutStream;
		auto_ptr <wxTextOutputStream> TextOutStream;
		File OutFile;

	private:
		XmlWriter (const XmlWriter &);
		XmlWriter &operator= (const XmlWriter &);
	};
}

#endif // TC_HEADER_Main_Xml
