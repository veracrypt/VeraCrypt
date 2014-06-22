/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_Keyfile
#define TC_HEADER_Encryption_Keyfile

#include "Platform/Platform.h"
#include "Platform/Stream.h"
#include "VolumePassword.h"

namespace VeraCrypt
{
	class Keyfile;
	typedef list < shared_ptr <Keyfile> > KeyfileList;

	class Keyfile
	{
	public:
		Keyfile (const FilesystemPath &path) : Path (path) { }
		virtual ~Keyfile () { };

		operator FilesystemPath () const { return Path; }
		static shared_ptr <VolumePassword> ApplyListToPassword (shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> password);
		static shared_ptr <KeyfileList> DeserializeList (shared_ptr <Stream> stream, const string &name);
		static void SerializeList (shared_ptr <Stream> stream, const string &name, shared_ptr <KeyfileList> keyfiles);
		static bool WasHiddenFilePresentInKeyfilePath() { bool r = HiddenFileWasPresentInKeyfilePath; HiddenFileWasPresentInKeyfilePath = false; return r; }

		static const size_t MinProcessedLength = 1;
		static const size_t MaxProcessedLength = 1024 * 1024;

	protected:
		void Apply (const BufferPtr &pool) const;

		static bool HiddenFileWasPresentInKeyfilePath;

		FilesystemPath Path;

	private:
		Keyfile (const Keyfile &);
		Keyfile &operator= (const Keyfile &);
	};
}

#endif // TC_HEADER_Encryption_Keyfile
