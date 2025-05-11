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

#include "CoreUnix.h"
#include <errno.h>
#include <iostream>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include "Platform/FileStream.h"
#include "Driver/Fuse/FuseService.h"
#include "Volume/VolumePasswordCache.h"

namespace VeraCrypt
{
#ifdef TC_LINUX
	static string GetTmpUser ();
	static bool SamePath (const string& path1, const string& path2);
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

	shared_ptr <VolumeInfo> CoreUnix::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		if (!mountedVolume->MountPoint.IsEmpty())
		{
			DismountFilesystem (mountedVolume->MountPoint, ignoreOpenFiles);

			// Delete mount directory if a default path has been used
			if (string (mountedVolume->MountPoint).find (GetDefaultMountPointPrefix()) == 0)
				mountedVolume->MountPoint.Delete();
		}

		try
		{
			DismountNativeVolume (mountedVolume);
		}
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
			catch (ExecutedProcessFailed&)
			{
				if (t > 10)
					throw;
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
			// Introduce a retry mechanism with a timeout for control file access
			// This workaround is limited to FUSE-T mounted volume under macOS for
			// which md.Device starts with "fuse-t:"
#ifdef VC_MACOSX_FUSET
			bool isFuseT = wstring(mf.Device).find(L"fuse-t:") == 0;
			int controlFileRetries = 10; // 10 retries with 500ms sleep each, total 5 seconds
			while (!mountedVol && (controlFileRetries-- > 0))
#endif
			{
				try 
				{
					shared_ptr <File> controlFile (new File);
					controlFile->Open (string (mf.MountPoint) + FuseService::GetControlPath());

					shared_ptr <Stream> controlFileStream (new FileStream (controlFile));
					mountedVol = Serializable::DeserializeNew <VolumeInfo> (controlFileStream);
				}
				catch (const std::exception& e)
				{
#ifdef VC_MACOSX_FUSET
					// if exception starts with "VeraCrypt::Serializer::ValidateName", then 
					// serialization is not ready yet and we need to wait before retrying
					// this happens when FUSE-T is used under macOS and if it is the first time
					// the volume is mounted
					if (isFuseT && string (e.what()).find ("VeraCrypt::Serializer::ValidateName") != string::npos)
					{
						Thread::Sleep(500); // Wait before retrying
					}
					else
					{
						break; // Control file not found or other error
					}
#endif
				}
			}

			if (!mountedVol) 
			{
				continue; // Skip to the next mounted filesystem
			}

			if (!volumePath.IsEmpty() && wstring (mountedVol->Path).compare (volumePath) != 0)
				continue;

			mountedVol->AuxMountPoint = mf.MountPoint;

			if (!mountedVol->VirtualDevice.IsEmpty())
			{
				MountedFilesystemList mpl = GetMountedFilesystems (mountedVol->VirtualDevice);

				if (mpl.size() > 0)
					mountedVol->MountPoint = mpl.front()->MountPoint;
			}

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

	void CoreUnix::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
	{
		if (GetMountedFilesystems (DevicePath(), mountPoint).size() > 0)
			throw MountPointUnavailable (SRC_POS);

		list <string> args;
		string options;

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
					MountAuxVolumeImage (fuseMountPoint, options);
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

		VolumeInfoList mountedVolumes = GetMountedVolumes (*options.Path);
		if (mountedVolumes.size() != 1)
			throw ParameterIncorrect (SRC_POS);

		VolumeEventArgs eventArgs (mountedVolumes.front());
		VolumeMountedEvent.Raise (eventArgs);

		return mountedVolumes.front();
	}

	void CoreUnix::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
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
			MountFilesystem (loopDev, *options.MountPoint,
				StringConverter::ToSingle (options.FilesystemType),
				options.Protection == VolumeProtection::ReadOnly,
				StringConverter::ToSingle (options.FilesystemOptions));
		}
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
			while (!token.empty() && token.back() == '/')
				token.pop_back();

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
			while (!entryPath.empty() && entryPath.back() == '/')
				entryPath.pop_back();

			// perform check again if the resolved path is different from the original (symlink)
			if (dirPath == entryPath || dirPath.find(entryPath + "/") == 0)
				return true;
		}

		return false;
	}
}
