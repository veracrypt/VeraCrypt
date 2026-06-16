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

#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "CoreMacOSX.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"

namespace VeraCrypt
{
	// RAII wrapper so CFRelease is never forgotten on early returns / exceptions.
	class CFHolder
	{
	public:
		explicit CFHolder (CFTypeRef ref = nullptr) : Ref (ref) { }
		~CFHolder () { if (Ref) CFRelease (Ref); }
		CFTypeRef Get () const { return Ref; }
	private:
		CFHolder (const CFHolder &);
		CFHolder &operator= (const CFHolder &);
		CFTypeRef Ref;
	};

	static string CFStringToStdString (CFStringRef cfStr)
	{
		if (!cfStr)
			return string();

		CFIndex length = CFStringGetLength (cfStr);
		CFIndex maxSize = CFStringGetMaximumSizeForEncoding (length, kCFStringEncodingUTF8) + 1;
		if (maxSize <= 0)
			return string();

		vector <char> buffer ((size_t) maxSize);
		if (!CFStringGetCString (cfStr, &buffer[0], maxSize, kCFStringEncodingUTF8))
			return string();

		return string (&buffer[0]);
	}

	// Fetch a string value from a CFDictionary by (C-string) key; empty if absent
	// or not a string.
	static string CFDictionaryGetStdString (CFDictionaryRef dict, const char *key)
	{
		if (!dict)
			return string();

		CFHolder cfKey (CFStringCreateWithCString (kCFAllocatorDefault, key, kCFStringEncodingUTF8));
		if (!cfKey.Get())
			return string();

		CFTypeRef value = CFDictionaryGetValue (dict, cfKey.Get());	// borrowed reference
		if (!value || CFGetTypeID (value) != CFStringGetTypeID())
			return string();

		return CFStringToStdString ((CFStringRef) value);
	}

	// Parse an hdiutil -plist (XML) document into a CFPropertyList. Returns nullptr
	// on failure; the caller owns the result and must CFRelease it.
	static CFPropertyListRef ParsePropertyList (const string &xml)
	{
		if (xml.empty())
			return nullptr;

		CFHolder data (CFDataCreate (kCFAllocatorDefault, (const UInt8 *) xml.data(), (CFIndex) xml.size()));
		if (!data.Get())
			return nullptr;

		return CFPropertyListCreateWithData (kCFAllocatorDefault, (CFDataRef) data.Get(), kCFPropertyListImmutable, nullptr, nullptr);
	}

	static string NormalizeDiskImagePath (const string &path)
	{
		string normalized;
		bool previousSlash = false;

		for (string::const_iterator i = path.begin(); i != path.end(); ++i)
		{
			if (*i == '/')
			{
				if (previousSlash)
					continue;

				previousSlash = true;
			}
			else
				previousSlash = false;

			normalized += *i;
		}

		if (normalized.find ("/private/") == 0)
			normalized.erase (0, 8);

		return normalized;
	}

	// Walk a "system-entities" array (from hdiutil attach/info). Prefer the entity
	// that carries a mount-point; otherwise fall back to the first dev-entry.
	static bool ExtractDeviceAndMountPointFromEntities (CFArrayRef entities, DevicePath &device, DirectoryPath &mountPoint)
	{
		if (!entities || CFGetTypeID (entities) != CFArrayGetTypeID())
			return false;

		string firstDevice;
		string mountedDevice;
		string mountedPath;

		CFIndex count = CFArrayGetCount (entities);
		for (CFIndex i = 0; i < count; ++i)
		{
			CFTypeRef entry = CFArrayGetValueAtIndex (entities, i);	// borrowed reference
			if (!entry || CFGetTypeID (entry) != CFDictionaryGetTypeID())
				continue;

			CFDictionaryRef entryDict = (CFDictionaryRef) entry;

			string devEntry = StringConverter::Trim (CFDictionaryGetStdString (entryDict, "dev-entry"));
			if (devEntry.empty())
				continue;

			if (firstDevice.empty())
				firstDevice = devEntry;

			string currentMountPoint = CFDictionaryGetStdString (entryDict, "mount-point");
			if (!currentMountPoint.empty())
			{
				mountedDevice = devEntry;
				mountedPath = currentMountPoint;
				break;
			}
		}

		if (!mountedDevice.empty())
		{
			device = mountedDevice;
			mountPoint = mountedPath;
			return true;
		}

		if (!firstDevice.empty())
		{
			device = firstDevice;
			return true;
		}

		return false;
	}

	// Parse "hdiutil attach -plist" output (top-level dict with "system-entities").
	static bool ExtractDiskImageDeviceAndMountPoint (const string &attachXml, DevicePath &device, DirectoryPath &mountPoint)
	{
		CFHolder plist (ParsePropertyList (attachXml));
		if (!plist.Get() || CFGetTypeID (plist.Get()) != CFDictionaryGetTypeID())
			return false;

		CFTypeRef entities = CFDictionaryGetValue ((CFDictionaryRef) plist.Get(), CFSTR ("system-entities"));	// borrowed
		if (!entities || CFGetTypeID (entities) != CFArrayGetTypeID())
			return false;

		return ExtractDeviceAndMountPointFromEntities ((CFArrayRef) entities, device, mountPoint);
	}

	static bool FindDiskImageInfoByImagePath (const string &imagePath, DevicePath &device, DirectoryPath &mountPoint)
	{
		list <string> args;
		args.push_back ("info");
		args.push_back ("-plist");

		string xml = Process::Execute ("/usr/bin/hdiutil", args);
		string normalizedImagePath = NormalizeDiskImagePath (imagePath);

		CFHolder plist (ParsePropertyList (xml));
		if (!plist.Get() || CFGetTypeID (plist.Get()) != CFDictionaryGetTypeID())
			return false;

		CFTypeRef images = CFDictionaryGetValue ((CFDictionaryRef) plist.Get(), CFSTR ("images"));	// borrowed
		if (!images || CFGetTypeID (images) != CFArrayGetTypeID())
			return false;

		CFArrayRef imageArray = (CFArrayRef) images;
		CFIndex count = CFArrayGetCount (imageArray);
		for (CFIndex i = 0; i < count; ++i)
		{
			CFTypeRef image = CFArrayGetValueAtIndex (imageArray, i);	// borrowed
			if (!image || CFGetTypeID (image) != CFDictionaryGetTypeID())
				continue;

			CFDictionaryRef imageDict = (CFDictionaryRef) image;

			string currentImagePath = CFDictionaryGetStdString (imageDict, "image-path");
			if (NormalizeDiskImagePath (currentImagePath) != normalizedImagePath)
				continue;

			// Matching image found: extract from its system-entities (mirrors the
			// previous behavior of returning the result for the first match).
			CFTypeRef entities = CFDictionaryGetValue (imageDict, CFSTR ("system-entities"));	// borrowed
			if (!entities || CFGetTypeID (entities) != CFArrayGetTypeID())
				return false;

			return ExtractDeviceAndMountPointFromEntities ((CFArrayRef) entities, device, mountPoint);
		}

		return false;
	}

	static bool AuxiliaryControlFileHasVirtualDevice (const DirectoryPath &auxMountPoint, const DevicePath &virtualDev, int retryCount = 50)
	{
		for (int t = 0; t < retryCount; ++t)
		{
			try
			{
				shared_ptr <File> controlFile (new File);
				controlFile->Open (string (auxMountPoint) + FuseService::GetControlPath());

				FileStream controlFileReader (controlFile);
				string controlFileData = controlFileReader.ReadToEnd();
				if (controlFileData.empty() || controlFileData.size() > 1024 * 1024)
					throw ParameterIncorrect (SRC_POS);

				shared_ptr <Stream> controlFileStream (new MemoryStream (ConstBufferPtr ((const uint8 *) controlFileData.data(), controlFileData.size())));
				shared_ptr <VolumeInfo> mountedVol = Serializable::DeserializeNew <VolumeInfo> (controlFileStream);
				if (mountedVol && string (mountedVol->VirtualDevice) == string (virtualDev))
					return true;
			}
			catch (...) { }

			Thread::Sleep (100);
		}

		return false;
	}

	CoreMacOSX::CoreMacOSX ()
	{
	}

	CoreMacOSX::~CoreMacOSX ()
	{
	}

	shared_ptr <VolumeInfo> CoreMacOSX::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		if (!mountedVolume->AuxMountPoint.IsEmpty())
		{
			try
			{
				UpdateMountedVolumeInfo (mountedVolume);
			}
			catch (...) { }
		}

		if (!mountedVolume->VirtualDevice.IsEmpty() && mountedVolume->VirtualDevice.IsBlockDevice())
		{
			list <string> args;
			args.push_back ("detach");
			args.push_back (mountedVolume->VirtualDevice);

			if (ignoreOpenFiles)
				args.push_back ("-force");

			try
			{
				Process::Execute ("/usr/bin/hdiutil", args);
			}
			catch (ExecutedProcessFailed &e)
			{
				if (!ignoreOpenFiles)
				{
					string err = e.GetErrorOutput();

					if (err.find ("couldn't unmount") != string::npos
						|| err.find ("busy") != string::npos
						|| err.find ("49153") != string::npos)
					{
						throw MountedVolumeInUse (SRC_POS);
					}
				}

				throw;
			}
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
				Process::Execute ("/sbin/umount", args);
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

		return mountedVolume;
	}

	void CoreMacOSX::UpdateMountedVolumeInfo (shared_ptr <VolumeInfo> mountedVolume) const
	{
		if (!mountedVolume || mountedVolume->AuxMountPoint.IsEmpty())
			return;

		try
		{
			DevicePath recoveredVirtualDevice;
			DirectoryPath recoveredMountPoint;

			if (FindDiskImageInfoByImagePath (string (mountedVolume->AuxMountPoint) + FuseService::GetVolumeImagePath(), recoveredVirtualDevice, recoveredMountPoint))
			{
				if (!recoveredVirtualDevice.IsEmpty())
				{
					if (mountedVolume->VirtualDevice != recoveredVirtualDevice && recoveredMountPoint.IsEmpty())
						mountedVolume->MountPoint = DirectoryPath();

					mountedVolume->VirtualDevice = recoveredVirtualDevice;
				}

				if (!recoveredMountPoint.IsEmpty())
					mountedVolume->MountPoint = recoveredMountPoint;
			}
		}
		catch (...) { }

		if (mountedVolume->MountPoint.IsEmpty() && !mountedVolume->VirtualDevice.IsEmpty())
		{
			try
			{
				MountedFilesystemList mountedFilesystems = GetMountedFilesystems (mountedVolume->VirtualDevice);

				if (mountedFilesystems.size() > 0)
					mountedVolume->MountPoint = mountedFilesystems.front()->MountPoint;
			}
			catch (...) { }
		}
	}

	void CoreMacOSX::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		list <string> args;
		struct stat sb;

		if (stat("/Applications/Utilities/Disk Utility.app", &sb) == 0)
			args.push_back ("/Applications/Utilities/Disk Utility.app");
		else
			args.push_back ("/System/Applications/Utilities/Disk Utility.app");

		Process::Execute ("/usr/bin/open", args);
	}

	DevicePath CoreMacOSX::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
#ifndef VC_MACOSX_FUSET
		// Check FUSE version
		char fuseVersionString[MAXHOSTNAMELEN + 1] = { 0 };
		size_t fuseVersionStringLength = MAXHOSTNAMELEN;
		int status;

		if ((status = sysctlbyname ("osxfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
		{
			fuseVersionStringLength = MAXHOSTNAMELEN;
			if ((status = sysctlbyname ("vfs.generic.osxfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
			{
				fuseVersionStringLength = MAXHOSTNAMELEN;
				if ((status = sysctlbyname ("vfs.generic.macfuse.version.number", fuseVersionString, &fuseVersionStringLength, NULL, 0)) != 0)
				{
					throw HigherFuseVersionRequired (SRC_POS);
				}
			}
		}

		// look for OSXFuse dynamic library
		struct stat sb;
		if (0 != stat("/usr/local/lib/libosxfuse_i64.2.dylib", &sb) && 0 != stat("/usr/local/lib/libfuse.dylib", &sb))
		{
			throw HigherFuseVersionRequired (SRC_POS);
		}

		vector <string> fuseVersion = StringConverter::Split (string (fuseVersionString), ".");
		if (fuseVersion.size() < 2)
			throw HigherFuseVersionRequired (SRC_POS);

		uint32 fuseVersionMajor = StringConverter::ToUInt32 (fuseVersion[0]);
		uint32 fuseVersionMinor = StringConverter::ToUInt32 (fuseVersion[1]);

		if (fuseVersionMajor < 2 || (fuseVersionMajor == 2 && fuseVersionMinor < 5))
			throw HigherFuseVersionRequired (SRC_POS);
#endif
		// Mount volume image
		string volImage = string (auxMountPoint) + FuseService::GetVolumeImagePath();

		list <string> args;
		args.push_back ("attach");
		args.push_back (volImage);
		args.push_back ("-plist");
		args.push_back ("-noautofsck");
		args.push_back ("-imagekey");
		args.push_back ("diskimage-class=CRawDiskImage");

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			args.push_back ("-mount");
			args.push_back ("required");

			// Let the system specify mount point except when the user specified a non-default one
			if (string (*options.MountPoint).find (GetDefaultMountPointPrefix()) != 0)
			{
				args.push_back ("-mountpoint");
				args.push_back (*options.MountPoint);
			}
		}
		else
			args.push_back ("-nomount");

		if (options.Protection == VolumeProtection::ReadOnly)
			args.push_back ("-readonly");

		string xml;

		while (true)
		{
			try
			{
				xml = Process::Execute ("/usr/bin/hdiutil", args);
				break;
			}
			catch (ExecutedProcessFailed &e)
			{
				if (e.GetErrorOutput().find ("noautofsck") != string::npos)
				{
					args.remove ("-noautofsck");
					continue;
				}

				throw;
			}
		}

		DevicePath virtualDev;
		DirectoryPath mountPoint;
		if (!ExtractDiskImageDeviceAndMountPoint (xml, virtualDev, mountPoint)
			|| virtualDev.IsEmpty())
			throw ParameterIncorrect (SRC_POS);
		(void) mountPoint;

		try
		{
			FuseService::SendAuxDeviceInfo (auxMountPoint, virtualDev);
#ifndef VC_MACOSX_FUSET
			if (!AuxiliaryControlFileHasVirtualDevice (auxMountPoint, virtualDev))
			{
				stringstream logMessage;
				logMessage << "VeraCrypt auxiliary mount did not report hdiutil device after mount: "
					<< string (auxMountPoint) << FuseService::GetControlPath()
					<< ", expected " << string (virtualDev);
				SystemLog::WriteError (logMessage.str());

				throw TimeOut (SRC_POS);
			}
#endif
		}
		catch (...)
		{
			try
			{
				list <string> args;
				args.push_back ("detach");
				args.push_back (virtualDev);
				args.push_back ("-force");

				Process::Execute ("/usr/bin/hdiutil", args);
			}
			catch (ExecutedProcessFailed&) { }
			throw;
		}

#ifdef VC_MACOSX_FUSET
		if (!AuxiliaryControlFileHasVirtualDevice (auxMountPoint, virtualDev, 10))
		{
			stringstream logMessage;
			logMessage << "VeraCrypt auxiliary mount did not report hdiutil device after mount: "
				<< string (auxMountPoint) << FuseService::GetControlPath()
				<< ", expected " << string (virtualDev)
				<< "; continuing with hdiutil device";
			SystemLog::WriteError (logMessage.str());
		}
#endif

		return virtualDev;
	}

	unique_ptr <CoreBase> Core (new CoreServiceProxy <CoreMacOSX>);
	unique_ptr <CoreBase> CoreDirect (new CoreMacOSX);
}
