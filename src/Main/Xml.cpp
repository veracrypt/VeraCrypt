/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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

	XmlNodeList XmlParser::GetNodes (const wxString &nodeName) const
	{
		XmlNodeList nodeList;

		size_t nodePos = 0;
		while ((nodePos = XmlText.find (L"<" + nodeName, nodePos)) != string::npos)
		{
			XmlNode xmlNode;
			xmlNode.Name = nodeName;

			size_t nodeEnd = XmlText.find (L">", nodePos);
			if (nodeEnd == string::npos)
				throw ParameterIncorrect (SRC_POS);

			wxString nodeTagText = XmlText.substr (nodePos + 1, nodeEnd - nodePos - 1);
			nodePos = nodeEnd;

			if (nodeTagText.size() > nodeName.size() && nodeTagText[nodeName.size()] != L' ' && nodeTagText[nodeName.size()] != L'/')
				continue;

			nodeTagText = nodeTagText.substr (nodeName.size());


			// Attributes
			wxStringTokenizer tokenizer (nodeTagText, L"\"", wxTOKEN_RET_EMPTY);
			while (tokenizer.HasMoreTokens())
			{
				wxString attributeName = tokenizer.GetNextToken();
				attributeName.Replace (L" ", L"", true);
				attributeName.Replace (L"=", L"");

				if (!attributeName.empty() && tokenizer.HasMoreTokens())
				{
					wxString attributeText = tokenizer.GetNextToken();
					xmlNode.Attributes[attributeName] = ConvertEscapedChars (attributeText);
				}
			}

			// Inner text
			if (!nodeTagText.EndsWith (L"/"))
			{
				size_t innerTextPos = nodeEnd + 1;
				size_t innerTextEnd = XmlText.find (L"</" + nodeName + L">", innerTextPos);
				if (innerTextEnd == string::npos)
					throw ParameterIncorrect (SRC_POS);

				xmlNode.InnerText = ConvertEscapedChars (XmlText.substr (innerTextPos, innerTextEnd - innerTextPos));
				nodePos = innerTextEnd;
			}

			nodeList.push_back (xmlNode);
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
			OutFile.Write (ConstBufferPtr (reinterpret_cast <byte *> (buf->GetBufferStart()), buf->GetBufferSize()));
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
