/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_Ciphers
#define TC_HEADER_Encryption_Ciphers

#include "Platform/Platform.h"


namespace TrueCrypt
{
	class Cipher;
	typedef vector < shared_ptr <Cipher> > CipherList;

	class Cipher
	{
	public:
		virtual ~Cipher ();

		virtual void DecryptBlock (byte *data) const;
		virtual void DecryptBlocks (byte *data, size_t blockCount) const;
		static void EnableHwSupport (bool enable) { HwSupportEnabled = enable; }
		virtual void EncryptBlock (byte *data) const;
		virtual void EncryptBlocks (byte *data, size_t blockCount) const;
		static CipherList GetAvailableCiphers ();
		virtual size_t GetBlockSize () const = 0;
		virtual const SecureBuffer &GetKey () const { return Key; }
		virtual size_t GetKeySize () const = 0;
		virtual wstring GetName () const = 0;
		virtual shared_ptr <Cipher> GetNew () const = 0;
		virtual bool IsHwSupportAvailable () const { return false; }
		static bool IsHwSupportEnabled () { return HwSupportEnabled; }
		virtual void SetKey (const ConstBufferPtr &key);

		static const int MaxBlockSize = 16;

	protected:
		Cipher ();

		virtual void Decrypt (byte *data) const = 0;
		virtual void Encrypt (byte *data) const = 0;
		virtual size_t GetScheduledKeySize () const = 0;
		virtual void SetCipherKey (const byte *key) = 0;

		static bool HwSupportEnabled;
		bool Initialized;
		SecureBuffer Key;
		SecureBuffer ScheduledKey;

	private:
		Cipher (const Cipher &);
		Cipher &operator= (const Cipher &);
	};

	struct CipherException : public Exception
	{
	protected:
		CipherException () { }
		CipherException (const string &message) : Exception (message) { }
		CipherException (const string &message, const wstring &subject) : Exception (message, subject) { }
	};


#define TC_CIPHER(NAME, BLOCK_SIZE, KEY_SIZE) \
	class TC_JOIN (Cipher,NAME) : public Cipher \
	{ \
	public: \
		TC_JOIN (Cipher,NAME) () { } \
		virtual ~TC_JOIN (Cipher,NAME) () { } \
\
		virtual size_t GetBlockSize () const { return BLOCK_SIZE; }; \
		virtual size_t GetKeySize () const { return KEY_SIZE; }; \
		virtual wstring GetName () const { return L###NAME; }; \
		virtual shared_ptr <Cipher> GetNew () const { return shared_ptr <Cipher> (new TC_JOIN (Cipher,NAME)()); } \
		TC_CIPHER_ADD_METHODS \
\
	protected: \
		virtual void Decrypt (byte *data) const; \
		virtual void Encrypt (byte *data) const; \
		virtual size_t GetScheduledKeySize () const; \
		virtual void SetCipherKey (const byte *key); \
\
	private: \
		TC_JOIN (Cipher,NAME) (const TC_JOIN (Cipher,NAME) &); \
		TC_JOIN (Cipher,NAME) &operator= (const TC_JOIN (Cipher,NAME) &); \
	}
	
#define TC_CIPHER_ADD_METHODS \
	virtual void DecryptBlocks (byte *data, size_t blockCount) const; \
	virtual void EncryptBlocks (byte *data, size_t blockCount) const; \
	virtual bool IsHwSupportAvailable () const;

	TC_CIPHER (AES, 16, 32);

#undef TC_CIPHER_ADD_METHODS
#define TC_CIPHER_ADD_METHODS

	TC_CIPHER (Blowfish, 8, 56);
	TC_CIPHER (Cast5, 8, 16);
	TC_CIPHER (Serpent, 16, 32);
	TC_CIPHER (TripleDES, 8, 24);
	TC_CIPHER (Twofish, 16, 32);

#undef TC_CIPHER

	
#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,CipherException)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION (CipherInitError); \
	TC_EXCEPTION (WeakKeyDetected);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION

#if (defined (TC_ARCH_X86) || defined (TC_ARCH_X64)) && !defined (__ppc__)
#	define TC_AES_HW_CPU
#endif

}

#endif // TC_HEADER_Encryption_Ciphers
