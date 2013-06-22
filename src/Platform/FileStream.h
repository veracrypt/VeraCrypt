/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_FileStream
#define TC_HEADER_Platform_FileStream

#include "PlatformBase.h"
#include "File.h"
#include "SharedPtr.h"
#include "Stream.h"

namespace TrueCrypt
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
