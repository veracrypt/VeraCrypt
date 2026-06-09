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

#include "CoreUnix.h"
#include "Common/Tcdefs.h"
#include <errno.h>
#include <iostream>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef TC_LINUX
#include <sys/utsname.h>
#endif
#ifdef TC_OPENBSD
#include <pwd.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/SystemLog.h"
#include "Driver/Fuse/FuseService.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
#ifdef TC_LINUX
	static string GetTmpUser ();
	static bool GetLinuxKernelVersion (int &kernelMajor, int &kernelMinor);
	static bool IsLinuxKernelModuleLoaded (const string &moduleName);
	static bool IsLinuxKernelVersionAtLeast (int major, int minor);
	static bool IsNtfsReadWriteKernelModuleAvailable ();
	static bool SamePath (const string& path1, const string& path2);
#endif

#ifdef TC_OPENBSD
	static bool GetDoasUserIds (uid_t *uid, gid_t *gid)
	{
		const char *env = getenv ("DOAS_USER");
		if (!env || !env[0])
			return false;

		struct passwd *pw = getpwnam (env);
		if (!pw)
			return false;

		if (uid)
			*uid = pw->pw_uid;
		if (gid)
			*gid = pw->pw_gid;

		return true;
	}
#endif

	// Struct to hold terminal emulator information
	struct TerminalInfo {
		const char* name;
		const char** args;
		const char** dependency_path;
	};

	// Popular terminal emulators data and arguments
	static const char* xterm_args[] = {"-T", "fsck", "-e", NULL};

	static const char* gnome_args[] = {"--title", "fsck", "--", "sh", "-c", NULL};
	static const char* gnome_deps[] = {"dbus-launch", NULL};

	static const char* konsole_args[] = {"--hold", "-p", "tabtitle=fsck", "-e", "sh", "-c", NULL};
	static const char* xfce4_args[] = {"--title=fsck", "-x", "sh", "-c", NULL};
	static const char* mate_args[] = {"--title", "fsck", "--", "sh", "-c", NULL};
	static const char* lxterminal_args[] = {"--title=fsck", "-e", "sh", "-c", NULL};
	static const char* terminator_args[] = {"-T", "fsck", "-x", "sh", "-c", NULL};
	static const char* urxvt_args[] = {"-title", "fsck", "-e", "sh", "-c", NULL};
	static const char* st_args[] = {"-t", "fsck", "-e", "sh", "-c", NULL};

	// List of popular terminal emulators
	static const TerminalInfo TERMINALS[] = {
		{"xterm", xterm_args, NULL},
		{"gnome-terminal", gnome_args, gnome_deps},
		{"konsole", konsole_args, NULL},
		{"xfce4-terminal", xfce4_args, NULL},
		{"mate-terminal", mate_args, NULL},
		{"lxterminal", lxterminal_args, NULL},
		{"terminator", terminator_args, NULL},
		{"urxvt", urxvt_args, NULL},
		{"st", st_args, NULL},
		{NULL, NULL, NULL}
	};

	CoreUnix::CoreUnix ()
	{
		signal (SIGPIPE, SIG_IGN);

		char *loc = setlocale (LC_ALL, "");
		if (!loc || string (loc) == "C")
			setlocale (LC_ALL, "en_US.UTF-8");
	}

	CoreUnix::~CoreUnix ()
	{
	}

	void CoreUnix::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		if (!mountedVolume->MountPoint.IsEmpty())
			DismountFilesystem (mountedVolume->MountPoint, false);

		// Find system fsck first
		std::string errorMsg;
		std::string fsckPath = Process::FindSystemBinary("fsck", errorMsg);
		if (fsckPath.empty()) {
			throw SystemException(SRC_POS, errorMsg);
		}

		list <string> args;

		string xargs = fsckPath + " ";  // Use absolute fsck path

#ifdef TC_LINUX
		if (!repair)
			xargs += "-n ";
		else
			xargs += "-r ";
#endif

		xargs += string (mountedVolume->VirtualDevice) + "; echo '[Done]'; read W";
		// Try each terminal
		for (const TerminalInfo* term = TERMINALS; term->name != NULL; ++term) {
			errno = 0;
			std::string termPath = Process::FindSystemBinary(term->name, errorMsg);
			if (termPath.length() > 0) {
				// check dependencies
				if (term->dependency_path) {
					bool depFound = true;
					for (const char** dep = term->dependency_path; *dep != NULL; ++dep) {
						string depPath = Process::FindSystemBinary(*dep, errorMsg);
						if (depPath.empty()) {
							depFound = false;
							break;
						}
					}

					if (!depFound) {
						continue; // dependency not found, skip 
					}
				}

				// Build args
				std::list<std::string> args;
				for (const char** arg = term->args; *arg != NULL; ++arg) {
					args.push_back(*arg);
				}
				args.push_back(xargs);

				try {
					Process::Execute (termPath, args, 1000);
					return;
				}
				catch (TimeOut&) {
					return;
				}
				catch (SystemException&) {
					// Continue to next terminal
				}
			}
		}

		throw TerminalNotFound();
	}

	void CoreUnix::DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
	{
		list <string> args;

#ifdef TC_MACOSX
		if (force)
			args.push_back ("-f");
#endif
		args.push_back ("--");
		args.push_back (mountPoint);

		Process::Execute ("umount", args);
	}

#ifdef TC_LINUX
	void CoreUnix::DismountFilesystemLazy (const DirectoryPath &mountPoint) const
	{
		list <string> args;
		args.push_back ("-l");
		args.push_back ("--");
		args.push_back (mountPoint);

		Process::Execute ("umount", args);
	}
#endif

	shared_ptr <VolumeInfo> CoreUnix::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		if (!mountedVolume->MountPoint.IsEmpty())
		{
#ifdef TC_LINUX
			try
			{
				DismountFilesystem (mountedVolume->MountPoint, ignoreOpenFiles);
			}
			catch (ExecutedProcessFailed &e)
			{
				throw FilesystemDismountFailed (e);
			}
#else
			DismountFilesystem (mountedVolume->MountPoint, ignoreOpenFiles);
#endif

			// Delete mount directory if a default path has been used
			if (string (mountedVolume->MountPoint).find (GetDefaultMountPointPrefix()) == 0)
				mountedVolume->MountPoint.Delete();
		}

		try
		{
			DismountNativeVolume (mountedVolume);
		}
#ifdef TC_LINUX
		catch (ExecutedProcessFailed &e)
		{
			throw FilesystemDismountFailed (e);
		}
#endif
		catch (NotApplicable &) { }

		if (!mountedVolume->LoopDevice.IsEmpty())
		{
			try
			{
				DetachLoopDevice (mountedVolume->LoopDevice);
			}
			catch (ExecutedProcessFailed&) { }
		}

		if (syncVolumeInfo || mountedVolume->Protection == VolumeProtection::HiddenVolumeReadOnly)
		{
			sync();
			VolumeInfoList ml = GetMountedVolumes (mountedVolume->Path);

			if (ml.size() > 0)
				mountedVolume = ml.front();
		}

		list <string> args;
		args.push_back ("--");
		args.push_back (mountedVolume->AuxMountPoint);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("umount", args);
				break;
			}
			catch (ExecutedProcessFailed &e)
			{
				if (t > 10)
#ifdef TC_LINUX
					throw FilesystemDismountFailed (e);
#else
					throw;
#endif
				Thread::Sleep (200);
			}
		}

		try
		{
			mountedVolume->AuxMountPoint.Delete();
		}
		catch (...)	{ }

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeDismountedEvent.Raise (eventArgs);

		return mountedVolume;
	}

#ifdef TC_LINUX
	shared_ptr <VolumeInfo> CoreUnix::EmergencyDismountVolume (shared_ptr <VolumeInfo> mountedVolume)
	{
		unique_ptr <Exception> firstException;

		if (!mountedVolume->MountPoint.IsEmpty())
		{
			bool mountPointMounted = true;
			bool mountPointDetached = false;

			try
			{
				mountPointMounted = !GetMountedFilesystems (DevicePath(), mountedVolume->MountPoint).empty();
			}
			catch (...) { }

			if (mountPointMounted)
			{
				try
				{
					DismountFilesystemLazy (mountedVolume->MountPoint);
					mountPointDetached = true;
				}
				catch (Exception &e)
				{
					if (!firstException.get())
						firstException.reset (e.CloneNew());
				}
			}

			if ((!mountPointMounted || mountPointDetached) && string (mountedVolume->MountPoint).find (GetDefaultMountPointPrefix()) == 0)
			{
				try
				{
					mountedVolume->MountPoint.Delete();
				}
				catch (...) { }
			}
		}

		try
		{
			DismountNativeVolumeDeferred (mountedVolume);
		}
		catch (NotApplicable&) { }
		catch (Exception &e)
		{
			if (!firstException.get())
				firstException.reset (e.CloneNew());
		}

		if (!mountedVolume->LoopDevice.IsEmpty())
		{
			try
			{
				DetachLoopDevice (mountedVolume->LoopDevice);
			}
			catch (ExecutedProcessFailed &e)
			{
				if (IsLoopDeviceAttached (mountedVolume->LoopDevice) && !firstException.get())
					firstException.reset (e.CloneNew());
			}
			catch (Exception &e)
			{
				if (!firstException.get())
					firstException.reset (e.CloneNew());
			}
		}

		if (!mountedVolume->AuxMountPoint.IsEmpty())
		{
			bool auxMountPointMounted = true;
			bool auxMountPointDetached = false;

			try
			{
				auxMountPointMounted = !GetMountedFilesystems (DevicePath(), mountedVolume->AuxMountPoint).empty();
			}
			catch (...) { }

			if (auxMountPointMounted)
			{
				list <string> args;
				args.push_back ("--");
				args.push_back (mountedVolume->AuxMountPoint);

				try
				{
					for (int t = 0; true; t++)
					{
						try
						{
							Process::Execute ("umount", args);
							auxMountPointDetached = true;
							break;
						}
						catch (ExecutedProcessFailed&)
						{
							if (t > 10)
								throw;
							Thread::Sleep (200);
						}
					}
				}
				catch (ExecutedProcessFailed&)
				{
					try
					{
						DismountFilesystemLazy (mountedVolume->AuxMountPoint);
						auxMountPointDetached = true;
					}
					catch (Exception &e)
					{
						if (!firstException.get())
							firstException.reset (e.CloneNew());
					}
				}
				catch (Exception &e)
				{
					if (!firstException.get())
						firstException.reset (e.CloneNew());
				}
			}

			if (!auxMountPointMounted || auxMountPointDetached)
			{
				try
				{
					mountedVolume->AuxMountPoint.Delete();
				}
				catch (...) { }
			}
		}

		if (firstException.get())
			firstException->Throw();

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeDismountedEvent.Raise (eventArgs);

		return mountedVolume;
	}
#endif

	bool CoreUnix::FilesystemSupportsLargeFiles (const FilePath &filePath) const
	{
		string path = filePath;
		size_t pos;

		while ((pos = path.find_last_of ('/')) != string::npos)
		{
			path = path.substr (0, pos);

			if (path.empty())
				break;

			try
			{
				MountedFilesystemList filesystems = GetMountedFilesystems (DevicePath(), path);
				if (!filesystems.empty())
				{
					const MountedFilesystem &fs = *filesystems.front();

					if (fs.Type == "fat"
						|| fs.Type == "fat32"
						|| fs.Type == "vfat"
						|| fs.Type == "fatfs"
						|| fs.Type == "msdos"
						|| fs.Type == "msdosfs"
						|| fs.Type == "umsdos"
						|| fs.Type == "dos"
						|| fs.Type == "dosfs"
						|| fs.Type == "pcfs"
						)
					{
						return false;
					}

					return true;
				}
			}
			catch (...) { }
		}

		return true;	// Prevent errors if the filesystem cannot be identified
	}

	bool CoreUnix::FilesystemSupportsUnixPermissions (const DevicePath &devicePath) const
	{
		File device;
		device.Open (devicePath);

		Buffer bootSector (device.GetDeviceSectorSize());
		device.SeekAt (0);
		device.ReadCompleteBuffer (bootSector);

		uint8 *b = bootSector.Ptr();

		return memcmp (b + 3,  "NTFS", 4) != 0
			&& memcmp (b + 54, "FAT", 3) != 0
			&& memcmp (b + 82, "FAT32", 5) != 0
			&& memcmp (b + 3,  "EXFAT", 5) != 0;
	}

	string CoreUnix::GetDefaultMountPointPrefix () const
	{
		const char *envPrefix = getenv ("VERACRYPT_MOUNT_PREFIX");
		if (envPrefix && !string (envPrefix).empty())
			return envPrefix;

		if (FilesystemPath ("/media").IsDirectory())
			return "/media/veracrypt";
#ifdef TC_LINUX
		if (FilesystemPath ("/run/media").IsDirectory())
			return "/run/media/veracrypt";
#endif
		if (FilesystemPath ("/mnt").IsDirectory())
			return "/mnt/veracrypt";

		return GetTempDirectory() + "/veracrypt_mnt";
	}

	uint32 CoreUnix::GetDeviceSectorSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.GetDeviceSectorSize();
	}

	uint64 CoreUnix::GetDeviceSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.Length();
	}

	DirectoryPath CoreUnix::GetDeviceMountPoint (const DevicePath &devicePath) const
	{
		DevicePath devPath = devicePath;
#ifdef TC_MACOSX
		if (string (devPath).find ("/dev/rdisk") != string::npos)
			devPath = string ("/dev/") + string (devicePath).substr (6);
#endif
		MountedFilesystemList mountedFilesystems = GetMountedFilesystems (devPath);

		if (mountedFilesystems.size() < 1)
			return DirectoryPath();

		return mountedFilesystems.front()->MountPoint;
	}

	VolumeInfoList CoreUnix::GetMountedVolumes (const VolumePath &volumePath) const
	{
		VolumeInfoList volumes;

		foreach_ref (const MountedFilesystem &mf, GetMountedFilesystems ())
		{
			if (string (mf.MountPoint).find (GetFuseMountDirPrefix()) == string::npos)
				continue;

			shared_ptr <VolumeInfo> mountedVol;
			// Introduce a retry mechanism with a timeout for control file access.
			// The list is already filtered to VeraCrypt auxiliary mounts; in
			// FUSE-T builds, the mount table device name varies by backend.
#ifdef VC_MACOSX_FUSET
			int controlFileRetries = volumePath.IsEmpty() ? 1 : 10; // Up to 10 attempts with 500ms sleeps for specific volume lookups
			string controlFileError;
			while (!mountedVol && (controlFileRetries-- > 0))
#endif
			{
				try 
				{
					shared_ptr <File> controlFile (new File);
					controlFile->Open (string (mf.MountPoint) + FuseService::GetControlPath());

					FileStream controlFileReader (controlFile);
					string controlFileData = controlFileReader.ReadToEnd();
					if (controlFileData.empty() || controlFileData.size() > 1024 * 1024)
						throw ParameterIncorrect (SRC_POS);

					shared_ptr <Stream> controlFileStream (new MemoryStream (ConstBufferPtr ((const uint8 *) controlFileData.data(), controlFileData.size())));
					mountedVol = Serializable::DeserializeNew <VolumeInfo> (controlFileStream);
				}
				catch (const std::exception& e)
				{
#ifdef VC_MACOSX_FUSET
					controlFileError = StringConverter::ToSingle (StringConverter::ToExceptionString (e));
					if (controlFileRetries > 0)
					{
						// FUSE-T's SMB backend can briefly expose the auxiliary mount
						// before the control file is readable and deserializable.
						Thread::Sleep (500);
					}
#else
					(void) e;
#endif
				}
#ifdef VC_MACOSX_FUSET
				catch (...)
				{
					controlFileError = "unknown exception";
					if (controlFileRetries > 0)
					{
						// FUSE-T's SMB backend can briefly expose the auxiliary mount
						// before the control file is readable and deserializable.
						Thread::Sleep (500);
					}
				}
#endif
			}

			if (!mountedVol) 
			{
#ifdef VC_MACOSX_FUSET
				if (!volumePath.IsEmpty())
				{
					stringstream logMessage;
					logMessage << "Failed to read VeraCrypt auxiliary mount control file after retries: "
						<< string (mf.MountPoint) << FuseService::GetControlPath();
					if (!controlFileError.empty())
						logMessage << ": " << controlFileError;
					SystemLog::WriteError (logMessage.str());
				}
#endif
				continue; // Skip to the next mounted filesystem
			}

			if (!volumePath.IsEmpty() && wstring (mountedVol->Path).compare (volumePath) != 0)
				continue;

			mountedVol->AuxMountPoint = mf.MountPoint;

			if (mountedVol->MountPoint.IsEmpty() && !mountedVol->VirtualDevice.IsEmpty())
			{
				MountedFilesystemList mpl = GetMountedFilesystems (mountedVol->VirtualDevice);

				if (mpl.size() > 0)
					mountedVol->MountPoint = mpl.front()->MountPoint;
			}

			if (mountedVol->MountPoint.IsEmpty() || mountedVol->VirtualDevice.IsEmpty())
				UpdateMountedVolumeInfo (mountedVol);

			volumes.push_back (mountedVol);

			if (!volumePath.IsEmpty())
				break;
		}

		return volumes;
	}

	gid_t CoreUnix::GetRealGroupId () const
	{
		const char *env = getenv ("SUDO_GID");
		if (env)
		{
			try
			{
				string s (env);
				return static_cast <gid_t> (StringConverter::ToUInt64 (s));
			}
			catch (...) { }
		}

#ifdef TC_OPENBSD
		gid_t doasGid;
		if (GetDoasUserIds (nullptr, &doasGid))
			return doasGid;
#endif

		return getgid();
	}

	uid_t CoreUnix::GetRealUserId () const
	{
		const char *env = getenv ("SUDO_UID");
		if (env)
		{
			try
			{
				string s (env);
				return static_cast <uid_t> (StringConverter::ToUInt64 (s));
			}
			catch (...) { }
		}

#ifdef TC_OPENBSD
		uid_t doasUid;
		if (GetDoasUserIds (&doasUid, nullptr))
			return doasUid;
#endif

		return getuid();
	}

	string CoreUnix::GetTempDirectory () const
	{
		const char *tmpdir = getenv ("TMPDIR");
		string envDir = tmpdir ? tmpdir : "/tmp";

#ifdef TC_LINUX
		/*
		 * If pam_tmpdir.so is in use, a different temporary directory is
		 * allocated for each user ID. We need to mount to the directory used
		 * by the non-root user.
		 */
		if (getuid () == 0 && envDir.size () >= 2
			&& envDir.substr (envDir.size () - 2) == "/0") {
			string tmpuser = GetTmpUser ();
			if (SamePath (envDir, tmpuser + "/0")) {
				/* Substitute the sudo'ing user for 0 */
				char uid[40];
				FILE *fp = fopen ("/proc/self/loginuid", "r");
				if (fp != NULL) {
					if (fgets (uid, sizeof (uid), fp) != nullptr) {
						envDir = tmpuser + "/" + uid;
					}
					fclose (fp);
				}
			}
		}
#endif

		return envDir;
	}

#ifdef TC_LINUX
	static string GetTmpUser ()
	{
		string tmpuser = "/tmp/user";
		FILE *fp = fopen ("/etc/security/tmpdir.conf", "r");
		if (fp == NULL) {
			return tmpuser;
		}
		while (true) {
			/* Parses the same way as pam_tmpdir */
			char line[1024];
			if (fgets (line, sizeof (line), fp) == nullptr) {
				break;
			}
			if (line[0] == '#') {
				continue;
			}
			size_t len = strlen (line);
			if (len > 0 && line[len-1] == '\n') {
				line[len-1] = '\0';
			}
			char *eq = strchr (line, '=');
			if (eq == nullptr) {
				continue;
			}
			*eq = '\0';
			const char *key = line;
			const char *value = eq + 1;
			if (strcmp (key, "tmpdir") == 0) {
				tmpuser = value;
				break;
			}
		}
		fclose (fp);
		return tmpuser;
	}

	static bool SamePath (const string& path1, const string& path2)
	{
		size_t i1 = 0;
		size_t i2 = 0;
		while (i1 < path1.size () && i2 < path2.size ()) {
			if (path1[i1] != path2[i2]) {
				return false;
			}
			/* Any two substrings consisting entirely of slashes compare equal */
			if (path1[i1] == '/') {
				while (i1 < path1.size () && path1[i1] == '/') {
					++i1;
				}
				while (i2 < path2.size () && path2[i2] == '/') {
					++i2;
				}
			}
			else
			{
				++i1;
				++i2;
			}
		}
		return (i1 == path1.size () && i2 == path2.size ());
	}
#endif

	bool CoreUnix::IsMountPointAvailable (const DirectoryPath &mountPoint) const
	{
		return GetMountedFilesystems (DevicePath(), mountPoint).size() == 0;
	}

#ifdef TC_LINUX
	static bool GetLinuxKernelVersion (int &kernelMajor, int &kernelMinor)
	{
		struct utsname kernelInfo;
		if (uname (&kernelInfo) != 0)
			return false;

		kernelMajor = 0;
		kernelMinor = 0;
		int versionFields = sscanf (kernelInfo.release, "%d.%d", &kernelMajor, &kernelMinor);

		if (versionFields < 1)
			return false;

		return true;
	}

	static bool IsLinuxKernelVersionAtLeast (int major, int minor)
	{
		int kernelMajor = 0;
		int kernelMinor = 0;
		if (!GetLinuxKernelVersion (kernelMajor, kernelMinor))
			return false;

		return kernelMajor > major || (kernelMajor == major && kernelMinor >= minor);
	}

	static bool IsLinuxKernelModuleLoaded (const string &moduleName)
	{
		string modulePath = "/sys/module/" + moduleName;
		struct stat moduleStat;
		return stat (modulePath.c_str(), &moduleStat) == 0 && S_ISDIR (moduleStat.st_mode);
	}

	static bool IsNtfsReadWriteKernelModuleAvailable ()
	{
		list <string> args;
		args.push_back ("-F");
		args.push_back ("description");
		args.push_back ("ntfs");

		try
		{
			string description = StringConverter::ToLower (StringConverter::Trim (Process::Execute ("modinfo", args, 2000)));
			// The upstream fs/ntfs module reports "NTFS read-write filesystem driver".
			// ntfs3 compatibility aliases report different wording, such as read/write.
			return description.find ("ntfs") != string::npos
				&& description.find ("read-write") != string::npos
				&& description.find ("filesystem driver") != string::npos;
		}
		catch (...) { }

		return false;
	}

	bool CoreUnix::IsNtfsReadWriteKernelFilesystemTypeAvailable () const
	{
		if (!IsNtfsReadWriteKernelModuleAvailable ())
			return false;

		if (!IsLinuxKernelModuleLoaded ("ntfs"))
		{
			list <string> args;
			args.push_back ("-q");
			args.push_back ("-b");
			args.push_back ("ntfs");

			try
			{
				Process::Execute ("modprobe", args, 5000);
			}
			catch (...) { }
		}

		return IsLinuxKernelModuleLoaded ("ntfs") && IsFilesystemTypeRegistered ("ntfs");
	}

	string CoreUnix::DetectFilesystemType (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-p");
		args.push_back ("-o");
		args.push_back ("value");
		args.push_back ("-s");
		args.push_back ("TYPE");
		args.push_back ("--");
		args.push_back (devicePath);

		try
		{
			return StringConverter::ToLower (StringConverter::Trim (Process::Execute ("blkid", args, 2000)));
		}
		catch (...)
		{
			return string();
		}
	}

	bool CoreUnix::IsFilesystemTypeRegistered (const string &filesystemType) const
	{
		FILE *procFilesystems = fopen ("/proc/filesystems", "r");
		if (!procFilesystems)
			return false;

		bool registered = false;
		char line[256];
		finally_do_arg (FILE *, procFilesystems, fclose (finally_arg););

		while (fgets (line, sizeof (line), procFilesystems))
		{
			string entry = StringConverter::Trim (line);
			size_t separator = entry.find_last_of (" \t");

			if (separator != string::npos)
				entry = entry.substr (separator + 1);

			if (entry == filesystemType)
			{
				registered = true;
				break;
			}
		}

		return registered;
	}

	bool CoreUnix::IsKernelFilesystemTypeAvailable (const string &filesystemType) const
	{
		if (IsFilesystemTypeRegistered (filesystemType))
			return true;

		// This is only used from mount-time paths that run with root-equivalent privileges.
		// If a future unprivileged caller uses it, modprobe is expected to fail silently here.
		list <string> moduleNames;
		moduleNames.push_back (filesystemType);
		moduleNames.push_back ("fs-" + filesystemType);

		foreach (const string &moduleName, moduleNames)
		{
			list <string> args;
			args.push_back ("-q");
			args.push_back ("-b");
			args.push_back (moduleName);

			try
			{
				Process::Execute ("modprobe", args, 5000);
			}
			catch (...) { }

			if (IsFilesystemTypeRegistered (filesystemType))
				return true;
		}

		return false;
	}

	string CoreUnix::SelectNtfsKernelFilesystemType () const
	{
		bool kernelHasStandaloneNtfs = IsLinuxKernelVersionAtLeast (7, 1);

		// Linux 6.9-7.0 may expose an "ntfs" compatibility alias from ntfs3,
		// but that legacy mount path is forced read-only. Only use "ntfs" where
		// the standalone read/write in-kernel driver is expected upstream, or when
		// module metadata and /sys/module positively identify a loaded backport as
		// the modern driver. Do not trust a pre-existing "ntfs" registration on
		// pre-7.1 kernels; it may belong to ntfs3's read-only compatibility path.
		if (!kernelHasStandaloneNtfs && IsNtfsReadWriteKernelFilesystemTypeAvailable ())
			return "ntfs";

		if (kernelHasStandaloneNtfs && IsKernelFilesystemTypeAvailable ("ntfs"))
			return "ntfs";

		if (IsKernelFilesystemTypeAvailable ("ntfs3"))
			return "ntfs3";

		throw KernelNtfsDriverUnavailable (SRC_POS);
	}

	void CoreUnix::ResolveNtfsKernelMountOptions (const DevicePath &devicePath, bool mountNtfsWithKernelDriver,
		wstring &filesystemType, bool &internalMountOnly) const
	{
		string requestedFilesystemType = StringConverter::ToLower (StringConverter::ToSingle (filesystemType));
		bool explicitKernelNtfsRequest = requestedFilesystemType == "kernel-ntfs" || requestedFilesystemType == "ntfs-kernel";

		if (requestedFilesystemType == "ntfs3")
		{
			// mount.ntfs3 helpers are not required; -i keeps mount(8) on the kernel path.
			internalMountOnly = true;
			return;
		}

		if (!explicitKernelNtfsRequest
			&& !(mountNtfsWithKernelDriver
				&& filesystemType.empty()
				&& DetectFilesystemType (devicePath) == "ntfs"))
			return;

		filesystemType = StringConverter::ToWide (SelectNtfsKernelFilesystemType());
		internalMountOnly = true;
	}
#endif

	void CoreUnix::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions, bool internalMountOnly) const
	{
		if (GetMountedFilesystems (DevicePath(), mountPoint).size() > 0)
			throw MountPointUnavailable (SRC_POS);

		list <string> args;
		string options;

		if (internalMountOnly)
			args.push_back ("-i");

		if (!filesystemType.empty())
		{
#ifdef TC_SOLARIS
			args.push_back ("-F");
#else
			args.push_back ("-t");
#endif
			args.push_back (filesystemType);
		}

		if (readOnly)
			options = "-oro";

		if (!systemMountOptions.empty())
		{
			if (options.empty())
				options = "-o";
			else
				options += ",";

			options += systemMountOptions;
		}

		if (!options.empty())
			args.push_back (options);

		args.push_back ("--");
		args.push_back (devicePath);
		args.push_back (mountPoint);

		Process::Execute ("mount", args);
	}

	VolumeSlotNumber CoreUnix::MountPointToSlotNumber (const DirectoryPath &mountPoint) const
	{
		string mountPointStr (mountPoint);
		if (mountPointStr.find (GetDefaultMountPointPrefix()) == 0)
		{
			try
			{
				return StringConverter::ToUInt32 (StringConverter::GetTrailingNumber (mountPointStr));
			}
			catch (...) { }
		}
		return GetFirstFreeSlotNumber();
	}

	shared_ptr <VolumeInfo> CoreUnix::MountVolume (MountOptions &options)
	{
		CoalesceSlotNumberAndMountPoint (options);

		if (IsVolumeMounted (*options.Path))
			throw VolumeAlreadyMounted (SRC_POS);

		if (options.MountPoint && !options.MountPoint->IsEmpty())
		{
			// Reject if the mount point is a system directory
			if (IsProtectedSystemDirectory(*options.MountPoint))
				throw MountPointBlocked (SRC_POS);

			// Reject if the mount point is in the user's PATH and the user has not explicitly allowed insecure mount points
			if (!GetAllowInsecureMount() && IsDirectoryOnUserPath(*options.MountPoint))
				throw MountPointNotAllowed (SRC_POS);
		}

		Cipher::EnableHwSupport (!options.NoHardwareCrypto);

		shared_ptr <Volume> volume;

		while (true)
		{
			try
			{
				volume = OpenVolume (
					options.Path,
					options.PreserveTimestamps,
					options.Password,
					options.Pim,
					options.Kdf,
					options.Keyfiles,
					options.EMVSupportEnabled,
					options.Protection,
					options.ProtectionPassword,
					options.ProtectionPim,
					options.ProtectionKdf,
					options.ProtectionKeyfiles,
					options.SharedAccessAllowed,
					VolumeType::Unknown,
					options.UseBackupHeaders,
					options.PartitionInSystemEncryptionScope
					);

				options.Password.reset();
			}
			catch (SystemException &e)
			{
				if (options.Protection != VolumeProtection::ReadOnly
					&& (e.GetErrorCode() == EROFS || e.GetErrorCode() == EACCES || e.GetErrorCode() == EPERM))
				{
					// Read-only filesystem
					options.Protection = VolumeProtection::ReadOnly;
					continue;
				}

				options.Password.reset();
				throw;
			}

			break;
		}

		if (options.Path->IsDevice())
		{
			const uint32 devSectorSize = volume->GetFile()->GetDeviceSectorSize();
			const size_t volSectorSize = volume->GetSectorSize();
			if (devSectorSize != volSectorSize)
				throw DeviceSectorSizeMismatch (SRC_POS, StringConverter::ToWide(devSectorSize) + L" != " + StringConverter::ToWide((uint32) volSectorSize));
		}

		// Find a free mount point for FUSE service
		MountedFilesystemList mountedFilesystems = GetMountedFilesystems ();
		string fuseMountPoint;
		for (int i = 1; true; i++)
		{
			stringstream path;
			path << GetTempDirectory() << "/" << GetFuseMountDirPrefix() << i;
			FilesystemPath fsPath (path.str());

			bool inUse = false;

			foreach_ref (const MountedFilesystem &mf, mountedFilesystems)
			{
				if (mf.MountPoint == path.str())
				{
					inUse = true;
					break;
				}
			}

			if (!inUse)
			{
				try
				{
					if (fsPath.IsDirectory())
						fsPath.Delete();

					throw_sys_sub_if (mkdir (path.str().c_str(), S_IRUSR | S_IXUSR) == -1, path.str());

					fuseMountPoint = fsPath;
					break;
				}
				catch (...)
				{
					if (i > 255)
						throw TemporaryDirectoryFailure (SRC_POS, StringConverter::ToWide (path.str()));
				}
			}
		}

		try
		{
			FuseService::Mount (volume, options.SlotNumber, fuseMountPoint);
		}
		catch (...)
		{
			try
			{
				DirectoryPath (fuseMountPoint).Delete();
			}
			catch (...) { }
			throw;
		}

		DevicePath mountedVirtualDevice;

		try
		{
			// Create a mount directory if a default path has been specified
			bool mountDirCreated = false;
			string mountPoint;
			if (!options.NoFilesystem && options.MountPoint)
			{
				mountPoint = *options.MountPoint;

#ifndef TC_MACOSX
				if (mountPoint.find (GetDefaultMountPointPrefix()) == 0 && !options.MountPoint->IsDirectory())
				{
					Directory::Create (*options.MountPoint);
					try
					{
						throw_sys_sub_if (chown (mountPoint.c_str(), GetRealUserId(), GetRealGroupId()) == -1, mountPoint);
					} catch (ParameterIncorrect&) { }

					mountDirCreated = true;
				}
#endif
			}

			try
			{
				try
				{
					MountVolumeNative (volume, options, fuseMountPoint);
				}
				catch (NotApplicable&)
				{
					mountedVirtualDevice = MountAuxVolumeImage (fuseMountPoint, options);
				}
			}
			catch (...)
			{
				if (mountDirCreated)
					remove (mountPoint.c_str());
				throw;
			}

#ifndef TC_MACOSX
			// set again correct ownership of the mount point to avoid any issues
			if (!options.NoFilesystem && options.MountPoint)
			{
				mountPoint = *options.MountPoint;

				if (mountPoint.find (GetDefaultMountPointPrefix()) == 0)
				{
					try
					{
						throw_sys_sub_if (chown (mountPoint.c_str(), GetRealUserId(), GetRealGroupId()) == -1, mountPoint);
					} catch (...) { }
				}
			}
#endif

		}
		catch (...)
		{
			try
			{
				VolumeInfoList mountedVolumes = GetMountedVolumes (*options.Path);
				if (mountedVolumes.size() > 0)
				{
					shared_ptr <VolumeInfo> mountedVolume (mountedVolumes.front());
					DismountVolume (mountedVolume);
				}
			}
			catch (...) { }
			throw;
		}

#ifdef VC_MACOSX_FUSET
		VolumeInfoList mountedVolumes = GetMountedVolumes (*options.Path);
		shared_ptr <VolumeInfo> mountedVolume;
		if (mountedVolumes.size() == 1)
		{
			mountedVolume = mountedVolumes.front();
			if (!mountedVirtualDevice.IsEmpty())
			{
				if (mountedVolume->VirtualDevice.IsEmpty())
					mountedVolume->VirtualDevice = mountedVirtualDevice;

				if (!options.NoFilesystem && mountedVolume->MountPoint.IsEmpty())
				{
					for (int mountPointRetries = 20; mountPointRetries > 0; --mountPointRetries)
					{
						try
						{
							mountedVolume->MountPoint = GetDeviceMountPoint (mountedVirtualDevice);
							if (!mountedVolume->MountPoint.IsEmpty())
								break;
						}
						catch (...) { }

						Thread::Sleep (500);
					}
				}
			}
		}
		else if (!mountedVirtualDevice.IsEmpty())
		{
			mountedVolume.reset (new VolumeInfo);
			mountedVolume->Set (*volume);
			mountedVolume->ProgramVersion = VERSION_NUM;
			mountedVolume->SlotNumber = options.SlotNumber;
			mountedVolume->AuxMountPoint = fuseMountPoint;
			mountedVolume->VirtualDevice = mountedVirtualDevice;

			struct timeval tv;
			gettimeofday (&tv, NULL);
			mountedVolume->SerialInstanceNumber = (uint64) tv.tv_sec * 1000000ULL + tv.tv_usec;

			if (!options.NoFilesystem)
			{
				for (int mountPointRetries = 20; mountPointRetries > 0; --mountPointRetries)
				{
					try
					{
						mountedVolume->MountPoint = GetDeviceMountPoint (mountedVirtualDevice);
						if (!mountedVolume->MountPoint.IsEmpty())
							break;
					}
					catch (...) { }

					Thread::Sleep (500);
				}
			}
		}
#else
		VolumeInfoList mountedVolumes = GetMountedVolumes (*options.Path);
		shared_ptr <VolumeInfo> mountedVolume;
		if (mountedVolumes.size() == 1)
			mountedVolume = mountedVolumes.front();
#endif
		if (!mountedVolume)
			throw ParameterIncorrect (SRC_POS);

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeMountedEvent.Raise (eventArgs);

		return mountedVolume;
	}

	DevicePath CoreUnix::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
		DevicePath loopDev = AttachFileToLoopDevice (string (auxMountPoint) + FuseService::GetVolumeImagePath(), options.Protection == VolumeProtection::ReadOnly);

		try
		{
			FuseService::SendAuxDeviceInfo (auxMountPoint, loopDev, loopDev);
		}
		catch (...)
		{
			try
			{
				DetachLoopDevice (loopDev);
			}
			catch (...) { }
			throw;
		}

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			wstring filesystemType = options.FilesystemType;
			bool internalMountOnly = false;

#ifdef TC_LINUX
			ResolveNtfsKernelMountOptions (loopDev, options.MountNtfsWithKernelDriver, filesystemType, internalMountOnly);
#endif

			MountFilesystem (loopDev, *options.MountPoint,
				StringConverter::ToSingle (filesystemType),
				options.Protection == VolumeProtection::ReadOnly,
				StringConverter::ToSingle (options.FilesystemOptions),
				internalMountOnly);
		}

		return loopDev;
	}

	void CoreUnix::SetFileOwner (const FilesystemPath &path, const UserId &owner) const
	{
		throw_sys_if (chown (string (path).c_str(), owner.SystemId, (gid_t) -1) == -1);
	}

	DirectoryPath CoreUnix::SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const
	{
		if (slotNumber < GetFirstSlotNumber() || slotNumber > GetLastSlotNumber())
			throw ParameterIncorrect (SRC_POS);

		stringstream s;
		s << GetDefaultMountPointPrefix() << slotNumber;
		return s.str();
	}

	bool CoreUnix::IsProtectedSystemDirectory (const DirectoryPath &directory) const
	{
		static const char* systemDirs[] = {
			"/usr",
			"/bin",
			"/sbin",
			"/lib",
#ifdef TC_LINUX
			"/lib32",
			"/lib64",
			"/libx32",
#endif
			"/etc",
			"/boot",
			"/root",
			"/proc",
			"/sys",
			"/dev",
			NULL
		};

		// Resolve any symlinks in the path
		string path(directory);
		char* resolvedPathCStr = realpath(path.c_str(), NULL);
		if (resolvedPathCStr)
		{
			path = resolvedPathCStr;
			free(resolvedPathCStr); // Free the allocated memory
		}

		// reject of the path is the root directory "/"
		if (path == "/")
			return true;

		// Check if resolved path matches any system directory
		for (int i = 0; systemDirs[i] != NULL; ++i)
		{
			if (path == systemDirs[i] || path.find(string(systemDirs[i]) + "/") == 0)
				return true;
		}

		return false;
	}

	bool CoreUnix::IsDirectoryOnUserPath(const DirectoryPath &directory) const
	{
		// Obtain the PATH environment variable
		const char* pathEnv = UserEnvPATH.c_str();
		if (!pathEnv[0])
			return false;

		// Resolve the given directory
		string dirPath(directory);
		char* resolvedDir = realpath(dirPath.c_str(), NULL);
		if (resolvedDir)
		{
			dirPath = resolvedDir;
			free(resolvedDir);
		}

		// Split PATH and compare each entry
		stringstream ss(pathEnv);
		string token;
		while (getline(ss, token, ':'))
		{
			// remove any trailing slashes from the token
			while (!token.empty() && token[token.length() - 1] == '/')
				token.erase(token.length() - 1);

			if (token.empty())
				continue;

			// check if the directory is the same as the entry or a subdirectory
			if (dirPath == token || dirPath.find(token + "/") == 0)
				return true;

			// handle the case where the PATH entry is a symlink
			char* resolvedEntry = realpath(token.c_str(), NULL);
			if (!resolvedEntry)
				continue; // skip to the next entry since the path does not exist

			string entryPath(resolvedEntry);
			free(resolvedEntry);

			// remove any trailing slashes from the token
			while (!entryPath.empty() && entryPath[entryPath.length() - 1] == '/')
				entryPath.erase(entryPath.length() - 1);

			// perform check again if the resolved path is different from the original (symlink)
			if (dirPath == entryPath || dirPath.find(entryPath + "/") == 0)
				return true;
		}

		return false;
	}
}
