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

#ifndef TC_HEADER_Encryption_Ciphers
#define TC_HEADER_Encryption_Ciphers

#include "Platform/Platform.h"
#include "Crypto/cpu.h"

namespace VeraCrypt
{
	class Cipher;
	typedef vector < shared_ptr <Cipher> > CipherList;

	class Cipher
	{
	public:
		virtual ~Cipher ();

		virtual void DecryptBlock (uint8 *data) const;
		virtual void DecryptBlocks (uint8 *data, size_t blockCount) const;
            #ifndef WOLFCRYPT_BACKEND
                static void EnableHwSupport (bool enable) { HwSupportEnabled = enable; }
	    #else
                static void EnableHwSupport (bool enable) { HwSupportEnabled = false; }
                virtual void EncryptBlockXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const;
                virtual void DecryptBlockXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const;
                virtual void SetKeyXTS (const ConstBufferPtr &key);
          #endif        
                virtual void EncryptBlock (uint8 *data) const;
		virtual void EncryptBlocks (uint8 *data, size_t blockCount) const;
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

		virtual void Decrypt (uint8 *data) const = 0;
		virtual void Encrypt (uint8 *data) const = 0;
		virtual size_t GetScheduledKeySize () const = 0;
		virtual void SetCipherKey (const uint8 *key) = 0;
            #ifdef WOLFCRYPT_BACKEND
                virtual void DecryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const = 0;
		virtual void EncryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const = 0;
                virtual void SetCipherKeyXTS (const uint8 *key) = 0;
            #endif

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

#ifdef WOLFCRYPT_BACKEND

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
		virtual void Decrypt (uint8 *data) const; \
		virtual void Encrypt (uint8 *data) const; \
		virtual size_t GetScheduledKeySize () const; \
		virtual void SetCipherKey (const uint8 *key); \
                virtual void DecryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const; \
		virtual void SetCipherKeyXTS (const uint8 *key); \
                virtual void EncryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const; \
\
	private: \
		TC_JOIN (Cipher,NAME) (const TC_JOIN (Cipher,NAME) &); \
		TC_JOIN (Cipher,NAME) &operator= (const TC_JOIN (Cipher,NAME) &); \
	}

#else

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
		virtual void Decrypt (uint8 *data) const; \
		virtual void Encrypt (uint8 *data) const; \
		virtual size_t GetScheduledKeySize () const; \
		virtual void SetCipherKey (const uint8 *key); \
\
	private: \
		TC_JOIN (Cipher,NAME) (const TC_JOIN (Cipher,NAME) &); \
		TC_JOIN (Cipher,NAME) &operator= (const TC_JOIN (Cipher,NAME) &); \
	}

#endif

#define TC_CIPHER_ADD_METHODS \
	virtual void DecryptBlocks (uint8 *data, size_t blockCount) const; \
	virtual void EncryptBlocks (uint8 *data, size_t blockCount) const; \
	virtual bool IsHwSupportAvailable () const;

	TC_CIPHER (AES, 16, 32);
	TC_CIPHER (Serpent, 16, 32);
	TC_CIPHER (Twofish, 16, 32);
	TC_CIPHER (Camellia, 16, 32);
	TC_CIPHER (Kuznyechik, 16, 32);

#undef TC_CIPHER_ADD_METHODS
#define TC_CIPHER_ADD_METHODS

#undef TC_CIPHER


#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,CipherException)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION (CipherInitError); \
	TC_EXCEPTION (WeakKeyDetected);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION

}

#endif // TC_HEADER_Encryption_Ciphers
