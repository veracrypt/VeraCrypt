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

#ifndef TC_HEADER_Platform_FileStream
#define TC_HEADER_Platform_FileStream

#include "PlatformBase.h"
#include "File.h"
#include "SharedPtr.h"
#include "Stream.h"

namespace VeraCrypt
{
	class FileStream : public Stream
	{
	public:
		FileStream (shared_ptr <File> file) : DataFile (file) { }
		FileStream (File::SystemFileHandleType openFileHandle) { DataFile.reset (new File ()); DataFile->AssignSystemHandle (openFileHandle); }
		virtual ~FileStream () { }

		virtual uint64 Read (const BufferPtr &buffer)
		{
			return DataFile->Read (buffer);
		}

		virtual void ReadCompleteBuffer (const BufferPtr &buffer)
		{
			DataFile->ReadCompleteBuffer (buffer);
		}

		virtual string ReadToEnd ()
		{
			string str;
			vector <char> buffer (4096);
			uint64 len;

			while ((len = DataFile->Read (BufferPtr (reinterpret_cast <byte *> (&buffer[0]), buffer.size()))) > 0)
				str.insert (str.end(), buffer.begin(), buffer.begin() + static_cast <int> (len));

			return str;
		}

		virtual void Write (const ConstBufferPtr &data)
		{
			DataFile->Write (data);
		}

	protected:
		shared_ptr <File> DataFile;
	};
}

#endif // TC_HEADER_Platform_FileStream
