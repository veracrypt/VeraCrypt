/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_File
#define TC_HEADER_Platform_File

#include "PlatformBase.h"
#include "Buffer.h"
#include "FilesystemPath.h"
#include "SystemException.h"

namespace TrueCrypt
{
	class File
	{
	public:
		enum FileOpenMode
		{
			CreateReadWrite,
			CreateWrite,
			OpenRead,
			OpenWrite,
			OpenReadWrite
		};

		enum FileShareMode
		{
			ShareNone,
			ShareRead,
			ShareReadWrite,
			ShareReadWriteIgnoreLock
		};

		enum FileOpenFlags
		{
			// Bitmap
			FlagsNone = 0,
			PreserveTimestamps = 1 << 0,
			DisableWriteCaching = 1 << 1
		};

#ifdef TC_WINDOWS
		typedef FILE* SystemFileHandleType;
#else
		typedef int SystemFileHandleType;
#endif

		File () : FileIsOpen (false), SharedHandle (false) { }
		virtual ~File ();
			
		void AssignSystemHandle (SystemFileHandleType openFileHandle, bool sharedHandle = true)
		{
			if (FileIsOpen)
				Close();
			FileHandle = openFileHandle;
			FileIsOpen = true;
			SharedHandle = sharedHandle;
		}

		void Close ();
		static void Copy (const FilePath &sourcePath, const FilePath &destinationPath, bool preserveTimestamps = true);
		void Delete ();
		void Flush () const;
		uint32 GetDeviceSectorSize () const;
		static size_t GetOptimalReadSize () { return OptimalReadSize; }
		static size_t GetOptimalWriteSize ()  { return OptimalWriteSize; }
		uint64 GetPartitionDeviceStartOffset () const;
		bool IsOpen () const { return FileIsOpen; }
		FilePath GetPath () const;
		uint64 Length () const;
		void Open (const FilePath &path, FileOpenMode mode = OpenRead, FileShareMode shareMode = ShareReadWrite, FileOpenFlags flags = FlagsNone);
		uint64 Read (const BufferPtr &buffer) const;
		void ReadCompleteBuffer (const BufferPtr &buffer) const;
		uint64 ReadAt (const BufferPtr &buffer, uint64 position) const;
		void SeekAt (uint64 position) const;
		void SeekEnd (int ofset) const;
		void Write (const ConstBufferPtr &buffer) const;
		void Write (const ConstBufferPtr &buffer, size_t length) const { Write (buffer.GetRange (0, length)); }
		void WriteAt (const ConstBufferPtr &buffer, uint64 position) const;
		
	protected:
		void ValidateState () const;

		static const size_t OptimalReadSize = 256 * 1024;
		static const size_t OptimalWriteSize = 256 * 1024;

		bool FileIsOpen;
		FileOpenFlags mFileOpenFlags;
		bool SharedHandle;
		FilePath Path;
		SystemFileHandleType FileHandle;

#ifdef TC_WINDOWS
#else
		time_t AccTime;
		time_t ModTime;
#endif

	private:
		File (const File &);
		File &operator= (const File &);
	};
}

#endif // TC_HEADER_Platform_File
