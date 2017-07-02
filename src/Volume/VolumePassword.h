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

#ifndef TC_HEADER_Encryption_Password
#define TC_HEADER_Encryption_Password

#include "Platform/Platform.h"
#include "Platform/Serializable.h"

namespace VeraCrypt
{
	class VolumePassword : public Serializable
	{
	public:
		VolumePassword ();
		VolumePassword (const byte *password, size_t size) { Set (password, size); }
		VolumePassword (const SecureBuffer &password) { Set (password.Ptr (), password.Size ()); }
		VolumePassword (const VolumePassword &password) { Set (password); }
		virtual ~VolumePassword ();

		bool operator== (const VolumePassword &other) const { return ConstBufferPtr (DataPtr(), Size()).IsDataEqual (ConstBufferPtr (other.DataPtr(), other.Size())); }
		bool operator!= (const VolumePassword &other) const { return !(*this == other); }
		VolumePassword &operator= (const VolumePassword &password) { Set (password); return *this; }

		operator BufferPtr () const { return BufferPtr (PasswordBuffer); }

		byte *DataPtr () const { return PasswordBuffer; }
		bool IsEmpty () const { return PasswordSize == 0; }
		size_t Size () const { return PasswordSize; }
		void Set (const byte *password, size_t size);
		void Set (const VolumePassword &password);

		TC_SERIALIZABLE (VolumePassword);

		static const size_t MaxSize = 64;
		static const size_t WarningSizeThreshold = 12;

	protected:
		void AllocateBuffer ();

		SecureBuffer PasswordBuffer;

		size_t PasswordSize;
	};

	struct PasswordException : public Exception
	{
	protected:
		PasswordException () { }
		PasswordException (const string &message) : Exception (message) { }
		PasswordException (const string &message, const wstring &subject) : Exception (message, subject) { }
	};

	TC_EXCEPTION_DECL (PasswordIncorrect, PasswordException);
	TC_EXCEPTION_DECL (PasswordKeyfilesIncorrect, PasswordIncorrect);
	TC_EXCEPTION_DECL (PasswordOrKeyboardLayoutIncorrect, PasswordException);
	TC_EXCEPTION_DECL (PasswordOrMountOptionsIncorrect, PasswordException);
	TC_EXCEPTION_DECL (ProtectionPasswordIncorrect, PasswordIncorrect);
	TC_EXCEPTION_DECL (ProtectionPasswordKeyfilesIncorrect, PasswordIncorrect);

#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,PasswordException)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (PasswordIncorrect); \
	TC_EXCEPTION_NODECL (PasswordKeyfilesIncorrect); \
	TC_EXCEPTION_NODECL (PasswordOrKeyboardLayoutIncorrect); \
	TC_EXCEPTION_NODECL (PasswordOrMountOptionsIncorrect); \
	TC_EXCEPTION_NODECL (ProtectionPasswordIncorrect); \
	TC_EXCEPTION_NODECL (ProtectionPasswordKeyfilesIncorrect); \
	TC_EXCEPTION (PasswordEmpty); \
	TC_EXCEPTION (PasswordTooLong); \
	TC_EXCEPTION (PasswordUTF8TooLong); \
	TC_EXCEPTION (PasswordUTF8Invalid); \
	TC_EXCEPTION (UnportablePassword);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION
}

#endif // TC_HEADER_Encryption_Password
