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

#ifndef TC_HEADER_Platform_FilesystemPath
#define TC_HEADER_Platform_FilesystemPath

#include "PlatformBase.h"
#include "Platform/User.h"
#include "SharedPtr.h"
#include "StringConverter.h"

namespace VeraCrypt
{
	struct FilesystemPathType
	{
		enum Enum
		{
			Unknown,
			File,
			Directory,
			SymbolickLink,
			BlockDevice,
			CharacterDevice
		};
	};

	class FilesystemPath
	{
	public:
		FilesystemPath () { }
		FilesystemPath (const char *path) : Path (StringConverter::ToWide (path)) { }
		FilesystemPath (string path) : Path (StringConverter::ToWide (path)) { }
		FilesystemPath (const wchar_t *path) : Path (path) { }
		FilesystemPath (wstring path) : Path (path) { }
		virtual ~FilesystemPath () { }

		bool operator== (const FilesystemPath &other) const { return Path == other.Path; }
		bool operator!= (const FilesystemPath &other) const { return Path != other.Path; }
		operator string () const { return StringConverter::ToSingle (Path); }
		operator wstring () const { return Path; }

		void Delete () const;
		UserId GetOwner () const;
		FilesystemPathType::Enum GetType () const;
		bool IsBlockDevice () const throw () { try { return GetType() == FilesystemPathType::BlockDevice; } catch (...) { return false; }; }
		bool IsCharacterDevice () const throw () { try { return GetType() == FilesystemPathType::CharacterDevice; } catch (...) { return false; }; }
		bool IsDevice () const throw () { return IsBlockDevice() || IsCharacterDevice(); }
		bool IsDirectory () const throw () { try { return GetType() == FilesystemPathType::Directory; } catch (...) { return false; } }
		bool IsEmpty () const throw () { try { return Path.empty(); } catch (...) { return false; } }
		bool IsFile () const throw () { try { return GetType() == FilesystemPathType::File; } catch (...) { return false; } }
		FilesystemPath ToBaseName () const;
		FilesystemPath ToHostDriveOfPartition () const;

		static const int MaxSize = 260;

	protected:
		wstring Path;
	};

	typedef FilesystemPath DevicePath;
	typedef FilesystemPath DirectoryPath;
	typedef FilesystemPath FilePath;

	typedef list < shared_ptr <DirectoryPath> > DirectoryPathList;
	typedef list < shared_ptr <FilePath> > FilePathList;
}

#endif // TC_HEADER_Platform_FilesystemPath
