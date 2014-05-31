/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>

#ifdef TC_LINUX
#include <sys/mount.h>
#endif

#ifdef TC_BSD
#include <sys/disk.h>
#endif

#ifdef TC_SOLARIS
#include <stropts.h>
#include <sys/dkio.h>
#endif

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "Platform/File.h"
#include "Platform/TextReader.h"

namespace TrueCrypt
{
#if 0
#	define TC_TRACE_FILE_OPERATIONS

	static void TraceFileOperation (int fileHandle, FilePath filePath, bool write, uint64 length, int64 position = -1)
	{
		string path = filePath;
		if (path.empty() || path.find ("truecrypt_aux_mnt") != string::npos)
			return;

		stringstream s;
		s << path << ": " << (write ? "W " : "R ") << (position == -1 ? lseek (fileHandle, 0, SEEK_CUR) : position) << " (" << length << ")";
		SystemLog::WriteError (s.str());
	}
#endif

	void File::Close ()
	{
		if_debug (ValidateState());

		if (!SharedHandle)
		{
			close (FileHandle);
			FileIsOpen = false;

			if ((mFileOpenFlags & File::PreserveTimestamps) && Path.IsFile())
			{
				struct utimbuf u;
				u.actime = AccTime;
				u.modtime = ModTime;

				try
				{
					throw_sys_sub_if (utime (string (Path).c_str(), &u) == -1, wstring (Path));
				}
				catch (...) // Suppress errors to allow using read-only files
				{
#ifdef DEBUG 
					throw;
#endif
				}
			}
		}
	}

	void File::Delete ()
	{
		Close();
		Path.Delete();
	}


	void File::Flush () const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (fsync (FileHandle) != 0, wstring (Path));
	}

	uint32 File::GetDeviceSectorSize () const
	{
		if (Path.IsDevice())
		{
#ifdef TC_LINUX
			int blockSize;
			throw_sys_sub_if (ioctl (FileHandle, BLKSSZGET, &blockSize) == -1, wstring (Path));
			return blockSize;

#elif defined (TC_MACOSX)
			uint32 blockSize;
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKSIZE, &blockSize) == -1, wstring (Path));
			return blockSize;

#elif defined (TC_FREEBSD)
			u_int sectorSize;
			throw_sys_sub_if (ioctl (FileHandle, DIOCGSECTORSIZE, &sectorSize) == -1, wstring (Path));
			return (uint32) sectorSize;

#elif defined (TC_SOLARIS)
			struct dk_minfo mediaInfo;
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGMEDIAINFO, &mediaInfo) == -1, wstring (Path));
			return mediaInfo.dki_lbsize;

#else
#	error GetDeviceSectorSize()
#endif
		}
		else
			throw ParameterIncorrect (SRC_POS);
	}

	uint64 File::GetPartitionDeviceStartOffset () const
	{
#ifdef TC_LINUX

		// HDIO_GETGEO ioctl is limited by the size of long
		TextReader tr ("/sys/block/" + string (Path.ToHostDriveOfPartition().ToBaseName()) + "/" + string (Path.ToBaseName()) + "/start");
		
		string line;
		tr.ReadLine (line);
		return StringConverter::ToUInt64 (line) * GetDeviceSectorSize();

#elif defined (TC_MACOSX)

#ifndef DKIOCGETBASE
#	define DKIOCGETBASE _IOR('d', 73, uint64)
#endif
		uint64 offset;
		throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBASE, &offset) == -1, wstring (Path));
		return offset;

#elif defined (TC_SOLARIS)

		struct extpart_info partInfo;
		throw_sys_sub_if (ioctl (FileHandle, DKIOCEXTPARTINFO, &partInfo) == -1, wstring (Path));
		return partInfo.p_start * GetDeviceSectorSize();

#else
		throw NotImplemented (SRC_POS);
#endif
	}

	uint64 File::Length () const
	{
		if_debug (ValidateState());

		// BSD does not support seeking to the end of a device
#ifdef TC_BSD
		if (Path.IsBlockDevice() || Path.IsCharacterDevice())
		{
#	ifdef TC_MACOSX
			uint32 blockSize;
			uint64 blockCount;
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKSIZE, &blockSize) == -1, wstring (Path));
			throw_sys_sub_if (ioctl (FileHandle, DKIOCGETBLOCKCOUNT, &blockCount) == -1, wstring (Path));
			return blockCount * blockSize;
#	else
			uint64 mediaSize;
			throw_sys_sub_if (ioctl (FileHandle, DIOCGMEDIASIZE, &mediaSize) == -1, wstring (Path));
			return mediaSize;
#	endif
		}
#endif
		off_t current = lseek (FileHandle, 0, SEEK_CUR);
		throw_sys_sub_if (current == -1, wstring (Path));
		SeekEnd (0);
		uint64 length = lseek (FileHandle, 0, SEEK_CUR);
		SeekAt (current);
		return length;
	}

	void File::Open (const FilePath &path, FileOpenMode mode, FileShareMode shareMode, FileOpenFlags flags)
	{
#ifdef TC_LINUX
		int sysFlags = O_LARGEFILE;
#else
		int sysFlags = 0;
#endif

		switch (mode)
		{
		case CreateReadWrite:
			sysFlags |= O_CREAT | O_TRUNC | O_RDWR;
			break;
				
		case CreateWrite:
			sysFlags |= O_CREAT | O_TRUNC | O_WRONLY;
			break;

		case OpenRead:
			sysFlags |= O_RDONLY;
			break;

		case OpenWrite:
			sysFlags |= O_WRONLY;
			break;

		case OpenReadWrite:
			sysFlags |= O_RDWR;
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		if ((flags & File::PreserveTimestamps) && path.IsFile())
		{
			struct stat statData;
			throw_sys_sub_if (stat (string (path).c_str(), &statData) == -1, wstring (path));
			AccTime = statData.st_atime;
			ModTime = statData.st_mtime;
		}

		FileHandle = open (string (path).c_str(), sysFlags, S_IRUSR | S_IWUSR);
		throw_sys_sub_if (FileHandle == -1, wstring (path));

#if 0 // File locking is disabled to avoid remote filesystem locking issues
		try
		{
			struct flock fl;
			memset (&fl, 0, sizeof (fl));
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 0;

			switch (shareMode)
			{
			case ShareNone:
				fl.l_type = F_WRLCK;
				if (fcntl (FileHandle, F_SETLK, &fl) == -1)
					throw_sys_sub_if (errno == EAGAIN || errno == EACCES, wstring (path));
				break;

			case ShareRead:
				fl.l_type = F_RDLCK;
				if (fcntl (FileHandle, F_SETLK, &fl) == -1)
					throw_sys_sub_if (errno == EAGAIN || errno == EACCES, wstring (path));
				break;

			case ShareReadWrite:
				fl.l_type = (mode == OpenRead ? F_RDLCK : F_WRLCK);
				if (fcntl (FileHandle, F_GETLK, &fl) != -1 && fl.l_type != F_UNLCK)
				{
					errno = EAGAIN;
					throw SystemException (SRC_POS, wstring (path));
				}
				break;
			
			case ShareReadWriteIgnoreLock:
				break;

			default:
				throw ParameterIncorrect (SRC_POS);
			}
		}
		catch (...)
		{
			close (FileHandle);
			throw;
		}
#endif // 0

		Path = path;
		mFileOpenFlags = flags;
		FileIsOpen = true;
	}

	uint64 File::Read (const BufferPtr &buffer) const
	{
		if_debug (ValidateState());

#ifdef TC_TRACE_FILE_OPERATIONS
		TraceFileOperation (FileHandle, Path, false, buffer.Size());
#endif
		ssize_t bytesRead = read (FileHandle, buffer, buffer.Size());
		throw_sys_sub_if (bytesRead == -1, wstring (Path));

		return bytesRead;
	}

	uint64 File::ReadAt (const BufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());

#ifdef TC_TRACE_FILE_OPERATIONS
		TraceFileOperation (FileHandle, Path, false, buffer.Size(), position);
#endif
		ssize_t bytesRead = pread (FileHandle, buffer, buffer.Size(), position);
		throw_sys_sub_if (bytesRead == -1, wstring (Path));

		return bytesRead;
	}

	void File::SeekAt (uint64 position) const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (lseek (FileHandle, position, SEEK_SET) == -1, wstring (Path));
	}

	void File::SeekEnd (int offset) const
	{
		if_debug (ValidateState());

		// BSD does not support seeking to the end of a device
#ifdef TC_BSD
		if (Path.IsBlockDevice() || Path.IsCharacterDevice())
		{
			SeekAt (Length() + offset);
			return;
		}
#endif

		throw_sys_sub_if (lseek (FileHandle, offset, SEEK_END) == -1, wstring (Path));
	}

	void File::Write (const ConstBufferPtr &buffer) const
	{
		if_debug (ValidateState());

#ifdef TC_TRACE_FILE_OPERATIONS
		TraceFileOperation (FileHandle, Path, true, buffer.Size());
#endif
		throw_sys_sub_if (write (FileHandle, buffer, buffer.Size()) != (ssize_t) buffer.Size(), wstring (Path));
	}
	
	void File::WriteAt (const ConstBufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());

#ifdef TC_TRACE_FILE_OPERATIONS
		TraceFileOperation (FileHandle, Path, true, buffer.Size(), position);
#endif
		throw_sys_sub_if (pwrite (FileHandle, buffer, buffer.Size(), position) != (ssize_t) buffer.Size(), wstring (Path));
	}
}
