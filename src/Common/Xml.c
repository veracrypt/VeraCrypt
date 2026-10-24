/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/
#if !defined(_UEFI)
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#else
#include "Tcdefs.h"
#pragma warning( disable : 4706 )  //  assignment within conditional expression
#endif
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


static BOOL XmlIsSpace (char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}


static BOOL XmlIsNameChar (char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		|| (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':';
}


/* Read the complete start tag before accepting an attribute. VeraCrypt writes
   double quoted values. Raw '<' and '>' inside them are kept for old favorites.
   Checking the syntax after each value also rejects a missing closing quote
   that would otherwise consume the opening quote of a later element. */
static char *XmlParseStartTag (char *xmlNode, const char *xmlAttrName, char **value, size_t *valueLen)
{
	char *t = xmlNode;
	size_t wantedLen = xmlAttrName ? strlen (xmlAttrName) : 0;

	if (!t || *t != '<') return NULL;
	++t;
	if (!XmlIsNameChar (*t)) return NULL;
	while (XmlIsNameChar (*t)) ++t;

	for (;;)
	{
		char *name, *text;
		size_t nameLen;

		if (*t == '>') return t;
		if (*t == '/' && t[1] == '>') return t + 1;
		if (!XmlIsSpace (*t)) return NULL;
		while (XmlIsSpace (*t)) ++t;
		if (*t == '>') return t;
		if (*t == '/' && t[1] == '>') return t + 1;

		name = t;
		while (XmlIsNameChar (*t)) ++t;
		nameLen = (size_t) (t - name);
		if (nameLen == 0) return NULL;
		while (XmlIsSpace (*t)) ++t;
		if (*t != '=') return NULL;
		++t;
		while (XmlIsSpace (*t)) ++t;
		if (*t != '"') return NULL;
		text = ++t;
		t = strchr (text, '"');
		if (!t) return NULL;

		if (xmlAttrName && !*value && nameLen == wantedLen && memcmp (name, xmlAttrName, nameLen) == 0)
		{
			*value = text;
			*valueLen = (size_t) (t - text);
		}
		++t;
	}
}


/* Returns the '>' ending a valid start tag, ignoring angle brackets in values. */
char *XmlFindTagEnd (char *xmlNode)
{
	return XmlParseStartTag (xmlNode, NULL, NULL, NULL);
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

	if (!t || !*t || nameLen == 0) return NULL;

	do
	{
		if (*t == '<' && BeginsWith (t + 1, nodeName)
			&& (t[nameLen + 1] == '>'
			|| XmlIsSpace (t[nameLen + 1]))) return t;

	} while (t = XmlNextNode (t));

	return NULL;
}


char *XmlFindElementByAttributeValue (char *xml, char *nodeName, const char *attrName, const char *attrValue)
{
	char attr[2048];

	while (xml = XmlFindElement (xml, nodeName))
	{
		char *tagEnd = XmlFindTagEnd (xml);
		if (XmlGetAttributeText (xml, attrName, attr, sizeof (attr)) && strcmp (attr, attrValue) == 0)
			return xml;

		xml = tagEnd ? tagEnd : xml + 1;
	}

	return NULL;
}


char *XmlGetAttributeText (char *xmlNode, const char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize)
{
	char *value = NULL;
	size_t valueLen = 0;

	if (xmlAttrValueSize <= 0)
		return NULL;

	xmlAttrValue[0] = 0;
	if (!XmlParseStartTag (xmlNode, xmlAttrName, &value, &valueLen)
		|| !value || valueLen >= (size_t) xmlAttrValueSize)
		return NULL;

	memcpy (xmlAttrValue, value, valueLen);
	xmlAttrValue[valueLen] = 0;

	return xmlAttrValue;
}


char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize)
{
	char *t = xmlNode;
	char *e = xmlNode + 1;
	int l = 0, i = 0, j = 0;

	if (xmlTextSize <= 0)
		return NULL;

	xmlText[0] = 0;

	if (t[0] != '<')
		return NULL;

	t = XmlFindTagEnd (t);
	if (t == NULL) return NULL;

	t++;
	e = strchr (t, '<');
	if (e == NULL) return NULL;

	l = (int)(e - t);
	if (l < 0) return NULL;

	while (i < l)
	{
		if (j >= xmlTextSize - 1)
		{
			xmlText[0] = 0;
			return NULL;
		}

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
			StringCchCopyA (textDst, textDstMaxSize, "&amp;");
			textDst += 5;
			textDstMaxSize -= 5;
			continue;

		case '>':
			if (textDst + 5 > textDstLast)
				return NULL;
			StringCchCopyA (textDst, textDstMaxSize, "&gt;");
			textDst += 4;
			textDstMaxSize -= 4;
			continue;

		case '<':
			if (textDst + 5 > textDstLast)
				return NULL;
			StringCchCopyA (textDst, textDstMaxSize, "&lt;");
			textDst += 4;
			textDstMaxSize -= 4;
			continue;

		default:
			*textDst++ = c;
			textDstMaxSize--;
		}
	}

	if (textDst > textDstLast)
		return NULL;

	*textDst = 0;
	return textDst;
}

wchar_t *XmlQuoteTextW (const wchar_t *textSrc, wchar_t *textDst, int textDstMaxSize)
{
	wchar_t *textDstLast = textDst + textDstMaxSize - 1;

	if (textDstMaxSize == 0)
		return NULL;

	while (*textSrc != 0 && textDst <= textDstLast)
	{
		wchar_t c = *textSrc++;
		switch (c)
		{
		case L'&':
			if (textDst + 6 > textDstLast)
				return NULL;
			StringCchCopyW (textDst, textDstMaxSize, L"&amp;");
			textDst += 5;
			textDstMaxSize -= 5;
			continue;

		case L'>':
			if (textDst + 5 > textDstLast)
				return NULL;
			StringCchCopyW (textDst, textDstMaxSize, L"&gt;");
			textDst += 4;
			textDstMaxSize -= 4;
			continue;

		case L'<':
			if (textDst + 5 > textDstLast)
				return NULL;
			StringCchCopyW (textDst, textDstMaxSize, L"&lt;");
			textDst += 4;
			textDstMaxSize -= 4;
			continue;

		default:
			*textDst++ = c;
			textDstMaxSize--;
		}
	}

	if (textDst > textDstLast)
		return NULL;

	*textDst = 0;
	return textDst;
}

#if !defined(_UEFI)
#pragma warning( default : 4706 )
#define TC_XML_HEADER "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<VeraCrypt>"
#define TC_XML_FOOTER "\n</VeraCrypt>"

int XmlWriteHeader (FILE *file)
{
	return fputws (L"" TC_XML_HEADER, file);
}


int XmlWriteFooter (FILE *file)
{
	return fputws (L"" TC_XML_FOOTER, file);
}


int XmlWriteHeaderUtf8 (FILE *file)
{
	return fputs ("\xEF\xBB\xBF" TC_XML_HEADER, file);
}


int XmlWriteFooterUtf8 (FILE *file)
{
	return fputs (TC_XML_FOOTER, file);
}
#endif !defined(_UEFI)

#if !defined(TC_WINDOWS_DRIVER) && !defined(_UEFI)
BOOL XmlTest (void)
{
	char buffer[10];

	/* XmlGetAttributeText tests */

	/* 1. length size - 1 accepted */
	char xmlAttrValid[] = "<Node attr=\"123456789\"></Node>";
	if (XmlGetAttributeText (xmlAttrValid, "attr", buffer, sizeof (buffer)) == NULL
		|| strcmp (buffer, "123456789") != 0)
		return FALSE;

	/* 2. length size rejected (off-by-one: would write NUL past buffer end) */
	char xmlAttrOverflow[] = "<Node attr=\"1234567890\"></Node>";
	if (XmlGetAttributeText (xmlAttrOverflow, "attr", buffer, sizeof (buffer)) != NULL)
		return FALSE;

	/* 3. malformed: closing quote absent returns NULL */
	char xmlAttrMissingQuote[] = "<Node attr=\"123456789></Node>";
	if (XmlGetAttributeText (xmlAttrMissingQuote, "attr", buffer, sizeof (buffer)) != NULL)
		return FALSE;

	/* 4. closing quote belongs to a later tag, not the current one */
	char xmlAttrCrossTag[] = "<Node attr=\"123456789></Node><Other attr=\"test\"></Other>";
	if (XmlGetAttributeText (xmlAttrCrossTag, "attr", buffer, sizeof (buffer)) != NULL)
		return FALSE;


	/* XmlGetNodeText tests */

	/* 5. length size - 1 accepted */
	char xmlNodeValid[] = "<Node>123456789</Node>";
	if (XmlGetNodeText (xmlNodeValid, buffer, sizeof (buffer)) == NULL
		|| strcmp (buffer, "123456789") != 0)
		return FALSE;

	/* 6. length size rejected (off-by-one: would write NUL past buffer end) */
	char xmlNodeOverflow[] = "<Node>1234567890</Node>";
	if (XmlGetNodeText (xmlNodeOverflow, buffer, sizeof (buffer)) != NULL)
		return FALSE;

	/* 7. escaped text accepted: raw input is larger than buffer but decoded
	   output fits. Decoded: "<>&456789" (9 chars), buffer is 10 bytes. */
	char xmlNodeEscaped[] = "<Node>&lt;&gt;&amp;456789</Node>";
	if (XmlGetNodeText (xmlNodeEscaped, buffer, sizeof (buffer)) == NULL
		|| strcmp (buffer, "<>&456789") != 0)
		return FALSE;

	/* 8. escaped text rejected: decoded output is exactly size (10 chars),
	   leaving no room for the NUL terminator. Decoded: "<>&4567890" (10 chars). */
	char xmlNodeEscapedOverflow[] = "<Node>&lt;&gt;&amp;4567890</Node>";
	if (XmlGetNodeText (xmlNodeEscapedOverflow, buffer, sizeof (buffer)) != NULL)
		return FALSE;

	/* 9. seed the buffer and verify overflow failure leaves it empty */
	char xmlNodeOverflowSeed[] = "<Node>1234567890</Node>";
	buffer[0] = 's';
	buffer[1] = 0;
	if (XmlGetNodeText (xmlNodeOverflowSeed, buffer, sizeof (buffer)) != NULL || buffer[0] != 0)
		return FALSE;

	return TRUE;
}
#endif
