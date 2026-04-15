/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifdef TC_OPENBSD
# define FUSE_USE_VERSION 26
#else
# ifndef VC_FUSE_VERSION
#  define VC_FUSE_VERSION 2
# endif
# if VC_FUSE_VERSION < 3
#  define FUSE_USE_VERSION 25
# else
#  define FUSE_USE_VERSION 301
#  define VC_FUSE3 1
# endif
#endif


#ifdef VC_FUSE3
#define VC_FUSE_FILL_DIR(filler, buf, name, st, off) filler(buf, name, st, off, (enum fuse_fill_dir_flags)0)
#else
#define VC_FUSE_FILL_DIR(filler, buf, name, st, off) filler(buf, name, st, off)
#endif

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "FuseService.h"
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"
#include "Platform/Unix/Pipe.h"
#include "Platform/Unix/Poller.h"
#include "Volume/EncryptionThreadPool.h"
#include "Core/Core.h"

namespace VeraCrypt
{
	static const ino_t VC_FUSE_INODE_ROOT = 1;
	static const ino_t VC_FUSE_INODE_VOLUME = 2;
	static const ino_t VC_FUSE_INODE_CONTROL = 3;

	static int fuse_service_fill_dir_entry (void *buf, fuse_fill_dir_t filler, const char *name, mode_t mode, ino_t ino, off_t nextOff)
	{
		struct stat st;
		Memory::Zero (&st, sizeof (st));
		st.st_mode = mode;
		st.st_nlink = S_ISDIR (mode) ? 2 : 1;
		st.st_uid = FuseService::GetUserId();
		st.st_gid = FuseService::GetGroupId();
		st.st_ino = ino;

		return VC_FUSE_FILL_DIR (filler, buf, name, &st, nextOff);
	}

	static int fuse_service_access (const char *path, int mask)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static void *fuse_service_init_common ()
	{
		try
		{
			// Termination signals are handled by a separate process to allow clean dismount on shutdown
			struct sigaction action;
			Memory::Zero (&action, sizeof (action));
			action.sa_handler = SIG_IGN;

			sigaction (SIGINT, &action, nullptr);
			sigaction (SIGQUIT, &action, nullptr);
			sigaction (SIGTERM, &action, nullptr);

			if (!EncryptionThreadPool::IsRunning())
				EncryptionThreadPool::Start();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}

		return nullptr;
	}

#if defined(VC_FUSE3)
	static void *fuse_service_init (struct fuse_conn_info *conn, struct fuse_config *cfg)
	{
		if (cfg)
		{
			cfg->set_uid = 1;
			cfg->set_gid = 1;
			cfg->uid = FuseService::GetUserId();
			cfg->gid = FuseService::GetGroupId();
		}

		return fuse_service_init_common ();
	}
#elif defined(TC_OPENBSD) || (FUSE_USE_VERSION >= 26)
	static void *fuse_service_init (struct fuse_conn_info *conn)
	{
		(void) conn;
		return fuse_service_init_common ();
	}
#else
	static void *fuse_service_init ()
	{
		return fuse_service_init_common ();
	}
#endif

	static void fuse_service_destroy (void *userdata)
	{
		try
		{
			FuseService::Dismount();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}
	}

	static int fuse_service_getattr_impl (const char *path, struct stat *statData)
	{
		try
		{
			Memory::Zero (statData, sizeof(*statData));

			statData->st_uid = FuseService::GetUserId();
			statData->st_gid = FuseService::GetGroupId();
			statData->st_atime = time (NULL);
			statData->st_ctime = time (NULL);
			statData->st_mtime = time (NULL);

			if (strcmp (path, "/") == 0)
			{
				statData->st_mode = S_IFDIR | 0500;
				statData->st_nlink = 2;
				statData->st_ino = VC_FUSE_INODE_ROOT;
			}
			else
			{
				if (!FuseService::CheckAccessRights())
					return -EACCES;

				if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = FuseService::GetVolumeSize();
					statData->st_ino = VC_FUSE_INODE_VOLUME;
				}
				else if (strcmp (path, FuseService::GetControlPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = FuseService::GetVolumeInfo()->Size();
					statData->st_ino = VC_FUSE_INODE_CONTROL;
				}
				else
				{
					return -ENOENT;
				}
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

#if defined(VC_FUSE3)
	static int fuse_service_getattr (const char *path, struct stat *statData, struct fuse_file_info *fi)
	{
		(void) fi;
		return fuse_service_getattr_impl (path, statData);
	}
#else
	static int fuse_service_getattr (const char *path, struct stat *statData)
	{
		return fuse_service_getattr_impl (path, statData);
	}
#endif

	static int fuse_service_opendir (const char *path, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, "/") != 0)
				return -ENOENT;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static int fuse_service_open (const char *path, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				return 0;

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				fi->direct_io = 1;
				return 0;
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}
		return -ENOENT;
	}

	static int fuse_service_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				try
				{
					// Test for read beyond the end of the volume
					if ((uint64) offset + size > FuseService::GetVolumeSize())
						size = FuseService::GetVolumeSize() - offset;

					size_t sectorSize = FuseService::GetVolumeSectorSize();
					if (size % sectorSize != 0 || offset % sectorSize != 0)
					{
						// Support for non-sector-aligned read operations is required by some loop device tools
						// which may analyze the volume image before attaching it as a device

						uint64 alignedOffset = offset - (offset % sectorSize);
						uint64 alignedSize = size + (offset % sectorSize);

						if (alignedSize % sectorSize != 0)
							alignedSize += sectorSize - (alignedSize % sectorSize);

						SecureBuffer alignedBuffer (alignedSize);

						FuseService::ReadVolumeSectors (alignedBuffer, alignedOffset);
						BufferPtr ((uint8 *) buf, size).CopyFrom (alignedBuffer.GetRange (offset % sectorSize, size));
					}
					else
					{
						FuseService::ReadVolumeSectors (BufferPtr ((uint8 *) buf, size), offset);
					}
				}
				catch (MissingVolumeData&)
				{
					return 0;
				}

				return size;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				shared_ptr <Buffer> infoBuf = FuseService::GetVolumeInfo();
				BufferPtr outBuf ((uint8 *)buf, size);

				if (offset >= (off_t) infoBuf->Size())
					return 0;

				if (offset + size > infoBuf->Size())
					size = infoBuf->Size () - offset;

				outBuf.CopyFrom (infoBuf->GetRange (offset, size));
				return size;
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

	static int fuse_service_readdir_impl (const char *path, void *buf, fuse_fill_dir_t filler, struct fuse_file_info *fi)
	{
		(void) fi;

		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, "/") != 0)
				return -ENOENT;

			if (fuse_service_fill_dir_entry (buf, filler, ".", S_IFDIR | 0500, VC_FUSE_INODE_ROOT, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, "..", S_IFDIR | 0500, VC_FUSE_INODE_ROOT, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetVolumeImagePath() + 1, S_IFREG | 0600, VC_FUSE_INODE_VOLUME, 0) != 0)
				return 0;
			if (fuse_service_fill_dir_entry (buf, filler, FuseService::GetControlPath() + 1, S_IFREG | 0600, VC_FUSE_INODE_CONTROL, 0) != 0)
				return 0;
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

#if defined(VC_FUSE3)
	static int fuse_service_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
	{
		(void) offset;
		(void) flags;
		return fuse_service_readdir_impl (path, buf, filler, fi);
	}
#else
	static int fuse_service_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
	{
		(void) offset;
		return fuse_service_readdir_impl (path, buf, filler, fi);
	}
#endif

	static int fuse_service_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (!FuseService::CheckAccessRights())
				return -EACCES;

			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				FuseService::WriteVolumeSectors (BufferPtr ((uint8 *) buf, size), offset);
				return size;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				if (FuseService::AuxDeviceInfoReceived())
					return -EACCES;

				FuseService::ReceiveAuxDeviceInfo (ConstBufferPtr ((const uint8 *)buf, size));
				return size;
			}
		}
#ifdef TC_FREEBSD
		// FreeBSD apparently retries failed write operations forever, which may lead to a system crash.
		catch (VolumeReadOnly&)
		{
			return size;
		}
		catch (VolumeProtected&)
		{
			return size;
		}
#endif
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

	bool FuseService::CheckAccessRights ()
	{
		return fuse_get_context()->uid == 0 || fuse_get_context()->uid == UserId;
	}

	void FuseService::CloseMountedVolume ()
	{
		if (MountedVolume)
		{
			// This process will exit before the use count of MountedVolume reaches zero
			if (MountedVolume->GetFile().use_count() > 1)
				MountedVolume->GetFile()->Close();

			if (MountedVolume.use_count() > 1)
				delete MountedVolume.get();

			MountedVolume.reset();
		}
	}

	void FuseService::Dismount ()
	{
		CloseMountedVolume();

		if (EncryptionThreadPool::IsRunning())
			EncryptionThreadPool::Stop();
	}

	int FuseService::ExceptionToErrorCode ()
	{
		try
		{
			throw;
		}
		catch (std::bad_alloc&)
		{
			return -ENOMEM;
		}
		catch (ParameterIncorrect &e)
		{
			SystemLog::WriteException (e);
			return -EINVAL;
		}
		catch (VolumeProtected&)
		{
			return -EPERM;
		}
		catch (VolumeReadOnly&)
		{
			return -EPERM;
		}
		catch (SystemException &e)
		{
			SystemLog::WriteException (e);
			return -static_cast <int> (e.GetErrorCode());
		}
		catch (std::exception &e)
		{
			SystemLog::WriteException (e);
			return -EINTR;
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
			return -EINTR;
		}
	}

	shared_ptr <Buffer> FuseService::GetVolumeInfo ()
	{
		shared_ptr <Stream> stream (new MemoryStream);

		{
			ScopeLock lock (OpenVolumeInfoMutex);

			OpenVolumeInfo.Set (*MountedVolume);
			OpenVolumeInfo.SlotNumber = SlotNumber;

			OpenVolumeInfo.Serialize (stream);
		}

		ConstBufferPtr infoBuf = dynamic_cast <MemoryStream&> (*stream);
		shared_ptr <Buffer> outBuf (new Buffer (infoBuf.Size()));
		outBuf->CopyFrom (infoBuf);

		return outBuf;
	}

	const char *FuseService::GetVolumeImagePath ()
	{
#ifdef TC_MACOSX
		return "/volume.dmg";
#else
		return "/volume";
#endif
	}

	uint64 FuseService::GetVolumeSize ()
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		return MountedVolume->GetSize();
	}

	void FuseService::Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint)
	{
		list <string> args;
		args.push_back (FuseService::GetDeviceType());
		args.push_back (fuseMountPoint);

#ifdef TC_MACOSX
		args.push_back ("-o");
		args.push_back ("noping_diskarb");
		args.push_back ("-o");
		args.push_back ("nobrowse");

#ifdef VC_MACOSX_FUSET
		// Use FUSE-T's SMB backend for the auxiliary mount. The default NFS
		// backend can be affected by macOS Network Volumes privacy state.
		args.push_back ("-o");
		args.push_back ("backend=smb");
		args.push_back ("-o");
		args.push_back ("nonamedattr");
		args.push_back ("-o");
		args.push_back ("rwsize=262144");
#endif

		if (getuid() == 0 || geteuid() == 0)
#endif
		{
			args.push_back ("-o");
			args.push_back ("allow_other");
		}

		ExecFunctor execFunctor (openVolume, slotNumber);
		Process::Execute ("fuse", args, -1, &execFunctor);

		for (int t = 0; true; t++)
		{
			try
			{
				if (FilesystemPath (fuseMountPoint + FuseService::GetControlPath()).GetType() == FilesystemPathType::File)
					break;
			}
			catch (...)
			{
				// Ignore exceptions since we will retry
			}

			if (t > 50)
				throw TimeOut (SRC_POS);

			Thread::Sleep (100);
		}
	}

	void FuseService::ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->ReadSectors (buffer, byteOffset);
	}

	void FuseService::ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer)
	{
		shared_ptr <Stream> stream (new MemoryStream (buffer));
		Serializer sr (stream);

		ScopeLock lock (OpenVolumeInfoMutex);
		OpenVolumeInfo.VirtualDevice = sr.DeserializeString ("VirtualDevice");
		OpenVolumeInfo.LoopDevice = sr.DeserializeString ("LoopDevice");
	}

	void FuseService::SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice)
	{
		File fuseServiceControl;
		fuseServiceControl.Open (string (fuseMountPoint) + GetControlPath(), File::OpenWrite);

		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);

		sr.Serialize ("VirtualDevice", string (virtualDevice));
		sr.Serialize ("LoopDevice", string (loopDevice));
		fuseServiceControl.Write (dynamic_cast <MemoryStream&> (*stream));
	}

	void FuseService::WriteVolumeSectors (const ConstBufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->WriteSectors (buffer, byteOffset);
	}

	void FuseService::OnSignal (int signal)
	{
		try
		{
			shared_ptr <VolumeInfo> volume = Core->GetMountedVolume (SlotNumber);

			if (volume)
				Core->DismountVolume (volume, true);
		}
		catch (...) { }

		_exit (0);
	}

	void FuseService::ExecFunctor::operator() (int argc, char *argv[])
	{
		struct timeval tv;
		gettimeofday (&tv, NULL);
		FuseService::OpenVolumeInfo.SerialInstanceNumber = (uint64)tv.tv_sec * 1000000ULL + tv.tv_usec;

		FuseService::MountedVolume = MountedVolume;
		FuseService::SlotNumber = SlotNumber;

		FuseService::UserId = getuid();
		FuseService::GroupId = getgid();

		if (getenv ("SUDO_UID"))
		{
			try
			{
				string s (getenv ("SUDO_UID"));
				FuseService::UserId = static_cast <uid_t> (StringConverter::ToUInt64 (s));

				if (getenv ("SUDO_GID"))
				{
					s = getenv ("SUDO_GID");
					FuseService::GroupId = static_cast <gid_t> (StringConverter::ToUInt64 (s));
				}
			}
			catch (...) { }
		}

		static fuse_operations fuse_service_oper;

		fuse_service_oper.access = fuse_service_access;
		fuse_service_oper.destroy = fuse_service_destroy;
		fuse_service_oper.getattr = fuse_service_getattr;
		fuse_service_oper.init = fuse_service_init;
		fuse_service_oper.open = fuse_service_open;
		fuse_service_oper.opendir = fuse_service_opendir;
		fuse_service_oper.read = fuse_service_read;
		fuse_service_oper.readdir = fuse_service_readdir;
		fuse_service_oper.write = fuse_service_write;

		// Create a new session
		setsid ();

		// Fork handler of termination signals
		SignalHandlerPipe.reset (new Pipe);

		int forkedPid = fork();
		throw_sys_if (forkedPid == -1);

		if (forkedPid == 0)
		{
			CloseMountedVolume();

			struct sigaction action;
			Memory::Zero (&action, sizeof (action));
			action.sa_handler = OnSignal;

			sigaction (SIGINT, &action, nullptr);
			sigaction (SIGQUIT, &action, nullptr);
			sigaction (SIGTERM, &action, nullptr);

			// Wait for the exit of the main service
			uint8 buf[1];
			if (read (SignalHandlerPipe->GetReadFD(), buf, sizeof (buf))) { } // Errors ignored

			_exit (0);
		}

		SignalHandlerPipe->GetWriteFD();

#ifdef VC_FUSE3
		_exit (fuse_main (argc, argv, &fuse_service_oper, nullptr));
#elif defined(TC_OPENBSD)
		_exit (fuse_main (argc, argv, &fuse_service_oper, NULL));
#else
		_exit (fuse_main (argc, argv, &fuse_service_oper));
#endif
	}

	VolumeInfo FuseService::OpenVolumeInfo;
	Mutex FuseService::OpenVolumeInfoMutex;
	shared_ptr <Volume> FuseService::MountedVolume;
	VolumeSlotNumber FuseService::SlotNumber;
	uid_t FuseService::UserId;
	gid_t FuseService::GroupId;
	unique_ptr <Pipe> FuseService::SignalHandlerPipe;
}
