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

#include "TextReader.h"

namespace VeraCrypt
{
	TextReader::TextReader (const FilePath &path)
	{
		InputFile.reset (new File);
		InputFile->Open (path);
		InputStream = shared_ptr <Stream> (new FileStream (InputFile));
	}

	bool TextReader::ReadLine (string &outputString)
	{
		outputString.erase();

		char c;
		while (InputStream->Read (BufferPtr ((byte *) &c, sizeof (c))) == sizeof (c))
		{
			if (c == '\r')
				continue;

			if (c == '\n')
				return true;

			outputString += c;
		}
		return !outputString.empty();
	}
}
