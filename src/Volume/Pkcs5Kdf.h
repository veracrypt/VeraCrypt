/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_Pkcs5
#define TC_HEADER_Encryption_Pkcs5

#include "Platform/Platform.h"
#include "Hash.h"
#include "VolumePassword.h"

namespace VeraCrypt
{
	class Pkcs5Kdf;
	typedef list < shared_ptr <Pkcs5Kdf> > Pkcs5KdfList;

	class Pkcs5Kdf
	{
	public:
		virtual ~Pkcs5Kdf ();

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, BOOL bNotTest = TRUE) const;
		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const = 0;
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const wstring &name);
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const Hash &hash);
		static Pkcs5KdfList GetAvailableAlgorithms ();
		virtual shared_ptr <Hash> GetHash () const = 0;
		virtual int GetIterationCount () const = 0;
		virtual wstring GetName () const = 0;
		virtual bool IsDeprecated () const { return GetHash()->IsDeprecated(); }

	protected:
		Pkcs5Kdf ();

		void ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;

	private:
		Pkcs5Kdf (const Pkcs5Kdf &);
		Pkcs5Kdf &operator= (const Pkcs5Kdf &);
	};

	class Pkcs5HmacRipemd160 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160 () { }
		virtual ~Pkcs5HmacRipemd160 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount () const { return 32767; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }

	private:
		Pkcs5HmacRipemd160 (const Pkcs5HmacRipemd160 &);
		Pkcs5HmacRipemd160 &operator= (const Pkcs5HmacRipemd160 &);
	};

	class Pkcs5HmacRipemd160_1000 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160_1000 () { }
		virtual ~Pkcs5HmacRipemd160_1000 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount () const { return 16384; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }

	private:
		Pkcs5HmacRipemd160_1000 (const Pkcs5HmacRipemd160_1000 &);
		Pkcs5HmacRipemd160_1000 &operator= (const Pkcs5HmacRipemd160_1000 &);
	};

	class Pkcs5HmacSha1 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha1 () { }
		virtual ~Pkcs5HmacSha1 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha1); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-SHA-1"; }

	private:
		Pkcs5HmacSha1 (const Pkcs5HmacSha1 &);
		Pkcs5HmacSha1 &operator= (const Pkcs5HmacSha1 &);
	};

	class Pkcs5HmacSha512 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha512 () { }
		virtual ~Pkcs5HmacSha512 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha512); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-SHA-512"; }

	private:
		Pkcs5HmacSha512 (const Pkcs5HmacSha512 &);
		Pkcs5HmacSha512 &operator= (const Pkcs5HmacSha512 &);
	};

	class Pkcs5HmacWhirlpool : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacWhirlpool () { }
		virtual ~Pkcs5HmacWhirlpool () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest = TRUE) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-Whirlpool"; }

	private:
		Pkcs5HmacWhirlpool (const Pkcs5HmacWhirlpool &);
		Pkcs5HmacWhirlpool &operator= (const Pkcs5HmacWhirlpool &);
	};
}

#endif // TC_HEADER_Encryption_Pkcs5
