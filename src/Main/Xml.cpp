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

#include "System.h"
#include <wx/tokenzr.h>
#include "Platform/FileStream.h"
#include "Xml.h"

namespace VeraCrypt
{
	XmlParser::XmlParser (const FilePath &fileName)
	{
		make_shared_auto (File, file);
		file->Open (fileName);
		FileStream stream (file);

		XmlText = wxString::FromUTF8 (stream.ReadToEnd().c_str());
	}

	wxString XmlParser::ConvertEscapedChars (wxString xmlString) const
	{
		xmlString.Replace (L"&lt;", L"<");
		xmlString.Replace (L"&gt;", L">");
		xmlString.Replace (L"&amp;", L"&");
		xmlString.Replace (L"&quot;", L"\"");
		return xmlString;
	}

	size_t XmlParser::FindTagEnd(size_t startPos) const
	{
		bool inQuote = false;
		wchar_t quoteChar = L'\0';
		size_t pos = startPos;
		while (pos < XmlText.length())
		{
			wchar_t c = XmlText[pos];
			if (!inQuote && (c == L'\'' || c == L'"'))
			{
				inQuote = true;
				quoteChar = c;
			}
			else if (inQuote && c == quoteChar)
			{
				inQuote = false;
			}
			else if (!inQuote && c == L'>')
			{
				return pos;
			}
			pos++;
		}
		return wxString::npos;
	}

	XmlNodeList XmlParser::GetNodes(const wxString &nodeName) const
	{
		XmlNodeList nodeList;
	
		size_t nodePos = 0;
		while ((nodePos = XmlText.find (L"<" + nodeName, nodePos)) != wxString::npos)
		{
			XmlNode xmlNode;
			xmlNode.Name = nodeName;
	
			// Use the helper method to correctly locate the end of the start tag
			size_t nodeEnd = FindTagEnd (nodePos);
			if (nodeEnd == wxString::npos)
				throw ParameterIncorrect (SRC_POS);
	
			// Extract the tag text (excluding the initial '<')
			wxString nodeTagText = XmlText.substr (nodePos + 1, nodeEnd - nodePos - 1);
			nodePos = nodeEnd;
	
			if (nodeTagText.size() > nodeName.size() && nodeTagText[nodeName.size()] != L' ' && nodeTagText[nodeName.size()] != L'/')
				continue;
	
			// Remove the node name from the tag text
			nodeTagText = nodeTagText.substr (nodeName.size());
	
			size_t attrPos = 0;
			while (attrPos < nodeTagText.length()) {
				// Skip any leading whitespace
				while (attrPos < nodeTagText.length() && nodeTagText[attrPos] == L' ')
					attrPos++;
					
				// If we've reached the end or a self-closing marker, exit the loop.
				if (attrPos >= nodeTagText.length() || nodeTagText[attrPos] == L'/')
					break;
					
				// Look for the equals sign to determine the attribute assignment.
				size_t equalsPos = nodeTagText.find (L'=', attrPos);
				if (equalsPos == wxString::npos)
					throw ParameterIncorrect (SRC_POS);
					
				// Extract and trim the attribute name.
				wxString attributeName = nodeTagText.substr (attrPos, equalsPos - attrPos);
				attributeName.Trim(true).Trim(false);
				if (attributeName.empty())
					throw ParameterIncorrect (SRC_POS);
				
				// Find the opening quote for the attribute value.
				size_t quoteStart = nodeTagText.find (L'"', equalsPos);
				if (quoteStart == wxString::npos)
					throw ParameterIncorrect (SRC_POS);
					
				// Search for the matching closing quote.
				size_t quoteEnd = quoteStart + 1;
				bool inEscape = false;
				while (quoteEnd < nodeTagText.length()) {
					if (nodeTagText[quoteEnd] == L'"' && !inEscape)
						break;
					inEscape = (nodeTagText[quoteEnd] == L'\\' && !inEscape);
					quoteEnd++;
				}
					
				if (quoteEnd >= nodeTagText.length())
					throw ParameterIncorrect (SRC_POS);
					
				// Extract the attribute value and convert any escaped characters.
				wxString attributeText = nodeTagText.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
				xmlNode.Attributes[attributeName] = ConvertEscapedChars(attributeText);
					
				attrPos = quoteEnd + 1;
			}
	
			// If not a self-closing tag, extract the inner text.
			if (!nodeTagText.EndsWith(L"/"))
			{
				size_t innerTextPos = nodeEnd + 1;
				size_t innerTextEnd = XmlText.find(L"</" + nodeName + L">", innerTextPos);
				if (innerTextEnd == wxString::npos)
					throw ParameterIncorrect (SRC_POS);
	
				xmlNode.InnerText = ConvertEscapedChars(XmlText.substr(innerTextPos, innerTextEnd - innerTextPos));
				nodePos = innerTextEnd;
			}
	
			nodeList.push_back(xmlNode);
		}
	
		return nodeList;
	}	

	XmlWriter::XmlWriter (const FilePath &fileName)
	{
		MemOutStream.reset (new wxMemoryOutputStream);
		TextOutStream.reset (new wxTextOutputStream (*MemOutStream));
		OutFile.Open (fileName, File::CreateWrite);

		*TextOutStream << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>" << endl << L"<VeraCrypt>" << endl;
		CurrentIndentLevel = 0;
	}

	void XmlWriter::Close()
	{
		if (MemOutStream.get())
		{
			*TextOutStream << L"</VeraCrypt>" << endl;

			wxStreamBuffer *buf = MemOutStream->GetOutputStreamBuffer();
			OutFile.Write (ConstBufferPtr (reinterpret_cast <uint8 *> (buf->GetBufferStart()), buf->GetBufferSize()));
			OutFile.Close();

			TextOutStream.reset();
			MemOutStream.reset();
		}
	}

	wxString XmlWriter::EscapeChars (wxString rawString) const
	{
		rawString.Replace (L"<", L"&lt;");
		rawString.Replace (L">", L"&gt;");
		rawString.Replace (L"&", L"&amp;");
		rawString.Replace (L"\"", L"&quot;");
		return rawString;
	}

	void XmlWriter::WriteNode (const XmlNode &xmlNode)
	{
		XmlNodeList nodes;
		nodes.push_back (xmlNode);
		WriteNodes (nodes);
	}

	void XmlWriter::WriteNodes (const XmlNodeList &xmlNodes)
	{
		CurrentIndentLevel++;
		wxString indent;
		for (int i = 0; i < CurrentIndentLevel; ++i)
			indent += L"\t";

		foreach (const XmlNode &node, xmlNodes)
		{
			*TextOutStream << indent << L"<" << node.Name;

			typedef pair <wxString, wxString> AttribPair;
			foreach (AttribPair attrib, node.Attributes)
			{
				*TextOutStream << L" " << attrib.first << L"=\"" << EscapeChars (attrib.second) << L"\"";
			}

			if (!node.InnerNodes.empty())
			{
				*TextOutStream << L">" << endl;
				WriteNodes (node.InnerNodes);
				*TextOutStream << indent;
			}
			else if (!node.InnerText.empty())
			{
				*TextOutStream << L">" << EscapeChars (node.InnerText);
			}
			else
			{
				*TextOutStream << L"/>" << endl;
				continue;
			}

			*TextOutStream << L"</" << node.Name << L">" << endl;
		}

		CurrentIndentLevel--;
	}

	XmlWriter::~XmlWriter ()
	{
		try
		{
			Close();
		}
		catch (...) { }
	}
}
