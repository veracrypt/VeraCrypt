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

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt) const;
		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const = 0;
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const wstring &name);
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const Hash &hash);
		static Pkcs5KdfList GetAvailableAlgorithms ();
		virtual shared_ptr <Hash> GetHash () const = 0;
		virtual int GetIterationCount (int pim) const = 0;
		virtual wstring GetName () const = 0;
		virtual Pkcs5Kdf* Clone () const = 0;
		virtual bool IsDeprecated () const { return GetHash()->IsDeprecated(); }

	protected:
		Pkcs5Kdf ();

		void ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;

	private:
		Pkcs5Kdf (const Pkcs5Kdf &);
		Pkcs5Kdf &operator= (const Pkcs5Kdf &);
	};

	class Pkcs5HmacBlake2s_Boot : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacBlake2s_Boot () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacBlake2s_Boot () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Blake2s); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 200000 : (pim * 2048); }
		virtual wstring GetName () const { return L"HMAC-BLAKE2s-256"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacBlake2s_Boot(); }

	private:
		Pkcs5HmacBlake2s_Boot (const Pkcs5HmacBlake2s_Boot &);
		Pkcs5HmacBlake2s_Boot &operator= (const Pkcs5HmacBlake2s_Boot &);
	};

	class Pkcs5HmacBlake2s : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacBlake2s () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacBlake2s () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Blake2s); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 500000 : (15000 + (pim * 1000)); }
		virtual wstring GetName () const { return L"HMAC-BLAKE2s-256"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacBlake2s(); }

	private:
		Pkcs5HmacBlake2s (const Pkcs5HmacBlake2s &);
		Pkcs5HmacBlake2s &operator= (const Pkcs5HmacBlake2s &);
	};

	class Pkcs5HmacSha256_Boot : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha256_Boot () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacSha256_Boot () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha256); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 200000 : (pim * 2048); }
		virtual wstring GetName () const { return L"HMAC-SHA-256"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacSha256_Boot(); }

	private:
		Pkcs5HmacSha256_Boot (const Pkcs5HmacSha256_Boot &);
		Pkcs5HmacSha256_Boot &operator= (const Pkcs5HmacSha256_Boot &);
	};

	class Pkcs5HmacSha256 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha256 () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacSha256 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha256); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 500000 : (15000 + (pim * 1000)); }
		virtual wstring GetName () const { return L"HMAC-SHA-256"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacSha256(); }

	private:
		Pkcs5HmacSha256 (const Pkcs5HmacSha256 &);
		Pkcs5HmacSha256 &operator= (const Pkcs5HmacSha256 &);
	};

	class Pkcs5HmacSha512 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha512 () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacSha512 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha512); }
		virtual int GetIterationCount (int pim) const { return (pim <= 0 ? 500000 : (15000 + (pim * 1000))); }
		virtual wstring GetName () const { return L"HMAC-SHA-512"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacSha512(); }

	private:
		Pkcs5HmacSha512 (const Pkcs5HmacSha512 &);
		Pkcs5HmacSha512 &operator= (const Pkcs5HmacSha512 &);
	};

	class Pkcs5HmacWhirlpool : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacWhirlpool () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacWhirlpool () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual int GetIterationCount (int pim) const { return (pim <= 0 ? 500000 : (15000 + (pim * 1000))); }
		virtual wstring GetName () const { return L"HMAC-Whirlpool"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacWhirlpool(); }

	private:
		Pkcs5HmacWhirlpool (const Pkcs5HmacWhirlpool &);
		Pkcs5HmacWhirlpool &operator= (const Pkcs5HmacWhirlpool &);
	};
	
	class Pkcs5HmacStreebog : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacStreebog () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacStreebog () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Streebog); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 500000 : (15000 + (pim * 1000)); }
		virtual wstring GetName () const { return L"HMAC-Streebog"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacStreebog(); }

	private:
		Pkcs5HmacStreebog (const Pkcs5HmacStreebog &);
		Pkcs5HmacStreebog &operator= (const Pkcs5HmacStreebog &);
	};
	
	class Pkcs5HmacStreebog_Boot : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacStreebog_Boot () : Pkcs5Kdf() { }
		virtual ~Pkcs5HmacStreebog_Boot () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Streebog); }
		virtual int GetIterationCount (int pim) const { return pim <= 0 ? 200000 : pim * 2048; }
		virtual wstring GetName () const { return L"HMAC-Streebog"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacStreebog_Boot(); }

	private:
		Pkcs5HmacStreebog_Boot (const Pkcs5HmacStreebog_Boot &);
		Pkcs5HmacStreebog_Boot &operator= (const Pkcs5HmacStreebog_Boot &);
	};
}

#endif // TC_HEADER_Encryption_Pkcs5
