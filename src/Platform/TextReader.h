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

#ifndef TC_HEADER_Platform_TextReader
#define TC_HEADER_Platform_TextReader

#include "PlatformBase.h"
#include "FileStream.h"
#include "FilesystemPath.h"
#include "SharedPtr.h"
#include "Stream.h"

namespace VeraCrypt
{
	class TextReader
	{
	public:
		TextReader (const FilePath &path);
		TextReader (shared_ptr <Stream> stream) : InputStream (stream) { }
		virtual ~TextReader () { }

		virtual bool ReadLine (string &outputString);

	protected:
		shared_ptr <File> InputFile;
		shared_ptr <Stream> InputStream;
	};
}

#endif // TC_HEADER_Platform_TextReader
