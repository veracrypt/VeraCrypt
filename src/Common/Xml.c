/*
 Copyright (c) 2005-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include <stdio.h>
#include "Xml.h"


static BOOL BeginsWith (char *string, char *subString)
{
	while (*string++ == *subString++)
	{
		if (*subString == 0) return TRUE;
		if (*string == 0) return FALSE;
	}

	return FALSE;
}


char *XmlNextNode (char *xmlNode)
{
	char *t = xmlNode + 1;
	while ((t = strchr (t, '<')) != NULL)
	{
		if (t[1] != '/')
			return t;

		t++;
	}

	return NULL;
}


char *XmlFindElement (char *xmlNode, char *nodeName)
{
	char *t = xmlNode;
	size_t nameLen = strlen (nodeName);

	do
	{
		if (BeginsWith (t + 1, nodeName)
			&& (t[nameLen + 1] == '>'
			|| t[nameLen + 1] == ' ')) return t;

	} while (t = XmlNextNode (t));

	return NULL;
}


char *XmlFindElementByAttributeValue (char *xml, char *nodeName, char *attrName, char *attrValue)
{
	char attr[2048];

	while (xml = XmlFindElement (xml, nodeName))
	{
		XmlGetAttributeText (xml, attrName, attr, sizeof (attr));
		if (strcmp (attr, attrValue) == 0)
			return xml;

		xml++;
	}

	return NULL;
}


char *XmlGetAttributeText (char *xmlNode, char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize)
{
	char *t = xmlNode;
	char *e = xmlNode;
	int l = 0;

	xmlAttrValue[0] = 0;
	if (t[0] != '<') return NULL;

	e = strchr (e, '>');
	if (e == NULL) return NULL;

	while ((t = strstr (t, xmlAttrName)) && t < e)
	{
		char *o = t + strlen (xmlAttrName);
		if (t[-1] == ' '
			&&
			(BeginsWith (o, "=\"")
			|| BeginsWith (o, "= \"")
			|| BeginsWith (o, " =\"")
			|| BeginsWith (o, " = \""))
			)
			break;

		t++;
	}

	if (t == NULL || t > e) return NULL;

	t = strchr (t, '"') + 1;
	e = strchr (t, '"');
	l = (int)(e - t);
	if (e == NULL || l > xmlAttrValueSize) return NULL;

	memcpy (xmlAttrValue, t, l);
	xmlAttrValue[l] = 0;

	return xmlAttrValue;
}


char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize)
{
	char *t = xmlNode;
	char *e = xmlNode + 1;
	int l = 0, i = 0, j = 0;

	xmlText[0] = 0;

	if (t[0] != '<')
		return NULL;

	t = strchr (t, '>') + 1;
	if (t == (char *)1) return NULL;

	e = strchr (e, '<');
	if (e == NULL) return NULL;

	l = (int)(e - t);
	if (e == NULL || l > xmlTextSize) return NULL;

	while (i < l)
	{
		if (BeginsWith (&t[i], "&lt;"))
		{
			xmlText[j++] = '<';
			i += 4;
			continue;
		}
		if (BeginsWith (&t[i], "&gt;"))
		{
			xmlText[j++] = '>';
			i += 4;
			continue;
		}
		if (BeginsWith (&t[i], "&amp;"))
		{
			xmlText[j++] = '&';
			i += 5;
			continue;
		}
		xmlText[j++] = t[i++];
	}
	xmlText[j] = 0;

	return t;
}


char *XmlQuoteText (const char *textSrc, char *textDst, int textDstMaxSize)
{
	char *textDstLast = textDst + textDstMaxSize - 1;

	if (textDstMaxSize == 0)
		return NULL;

	while (*textSrc != 0 && textDst <= textDstLast) 
	{
		char c = *textSrc++;
		switch (c)
		{
		case '&':
			if (textDst + 6 > textDstLast)
				return NULL;
			strcpy (textDst, "&amp;");
			textDst += 5;
			continue;

		case '>':
			if (textDst + 5 > textDstLast)
				return NULL;
			strcpy (textDst, "&gt;");
			textDst += 4;
			continue;

		case '<':
			if (textDst + 5 > textDstLast)
				return NULL;
			strcpy (textDst, "&lt;");
			textDst += 4;
			continue;

		default:
			*textDst++ = c;
		}
	}

	if (textDst > textDstLast)
		return NULL;

	*textDst = 0;
	return textDst;
}


int XmlWriteHeader (FILE *file)
{
	return fputs ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<TrueCrypt>", file);
}


int XmlWriteHeaderW (FILE *file)
{
	return fputws (L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<TrueCrypt>", file);
}


int XmlWriteFooter (FILE *file)
{
	return fputs ("\n</TrueCrypt>", file);
}


int XmlWriteFooterW (FILE *file)
{
	return fputws (L"\n</TrueCrypt>", file);
}
