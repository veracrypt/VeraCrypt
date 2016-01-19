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

#ifdef __cplusplus
extern "C" {
#endif

char *XmlNextNode (char *xmlNode);
char *XmlFindElement (char *xmlNode, char *nodeName);
char *XmlGetAttributeText (char *xmlNode, char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize);
char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize);
int XmlWriteHeader (FILE *file);
int XmlWriteFooter (FILE *file);
char *XmlFindElementByAttributeValue (char *xml, char *nodeName, char *attrName, char *attrValue);
char *XmlQuoteText (const char *textSrc, char *textDst, int textDstMaxSize);
wchar_t *XmlQuoteTextW (const wchar_t *textSrc, wchar_t *textDst, int textDstMaxSize);

#ifdef __cplusplus
}
#endif
