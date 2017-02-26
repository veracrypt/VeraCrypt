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
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const wstring &name, bool truecryptMode);
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const Hash &hash, bool truecryptMode);
		static Pkcs5KdfList GetAvailableAlgorithms (bool truecryptMode);
		virtual shared_ptr <Hash> GetHash () const = 0;
		virtual int GetIterationCount (int pim) const = 0;
		virtual wstring GetName () const = 0;
		virtual Pkcs5Kdf* Clone () const = 0;
		virtual bool IsDeprecated () const { return GetHash()->IsDeprecated(); }
		bool GetTrueCryptMode () const { return m_truecryptMode;}
		void SetTrueCryptMode (bool truecryptMode) { m_truecryptMode = truecryptMode;}

	protected:
		bool m_truecryptMode;
		Pkcs5Kdf (bool truecryptMode);

		void ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;

	private:
		Pkcs5Kdf (const Pkcs5Kdf &);
		Pkcs5Kdf &operator= (const Pkcs5Kdf &);
	};

	class Pkcs5HmacRipemd160 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160 (bool truecryptMode) : Pkcs5Kdf (truecryptMode) { }
		virtual ~Pkcs5HmacRipemd160 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount (int pim) const { return m_truecryptMode? 2000 : (pim <= 0 ? 655331 : (15000 + (pim * 1000))) ; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacRipemd160(m_truecryptMode); }

	private:
		Pkcs5HmacRipemd160 (const Pkcs5HmacRipemd160 &);
		Pkcs5HmacRipemd160 &operator= (const Pkcs5HmacRipemd160 &);
	};

	class Pkcs5HmacRipemd160_1000 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160_1000 (bool truecryptMode) : Pkcs5Kdf(truecryptMode) { }
		virtual ~Pkcs5HmacRipemd160_1000 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount (int pim) const { return m_truecryptMode? 1000 : (pim <= 0 ? 327661 : (pim * 2048)); }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacRipemd160_1000(m_truecryptMode); }

	private:
		Pkcs5HmacRipemd160_1000 (const Pkcs5HmacRipemd160_1000 &);
		Pkcs5HmacRipemd160_1000 &operator= (const Pkcs5HmacRipemd160_1000 &);
	};

	class Pkcs5HmacSha256_Boot : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha256_Boot () : Pkcs5Kdf(false) { }
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
		Pkcs5HmacSha256 () : Pkcs5Kdf(false) { }
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
		Pkcs5HmacSha512 (bool truecryptMode) : Pkcs5Kdf(truecryptMode) { }
		virtual ~Pkcs5HmacSha512 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha512); }
		virtual int GetIterationCount (int pim) const { return m_truecryptMode? 1000 : (pim <= 0 ? 500000 : (15000 + (pim * 1000))); }
		virtual wstring GetName () const { return L"HMAC-SHA-512"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacSha512(m_truecryptMode); }

	private:
		Pkcs5HmacSha512 (const Pkcs5HmacSha512 &);
		Pkcs5HmacSha512 &operator= (const Pkcs5HmacSha512 &);
	};

	class Pkcs5HmacWhirlpool : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacWhirlpool (bool truecryptMode) : Pkcs5Kdf(truecryptMode) { }
		virtual ~Pkcs5HmacWhirlpool () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual int GetIterationCount (int pim) const { return m_truecryptMode? 1000 : (pim <= 0 ? 500000 : (15000 + (pim * 1000))); }
		virtual wstring GetName () const { return L"HMAC-Whirlpool"; }
		virtual Pkcs5Kdf* Clone () const { return new Pkcs5HmacWhirlpool(m_truecryptMode); }

	private:
		Pkcs5HmacWhirlpool (const Pkcs5HmacWhirlpool &);
		Pkcs5HmacWhirlpool &operator= (const Pkcs5HmacWhirlpool &);
	};
	
	class Pkcs5HmacStreebog : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacStreebog () : Pkcs5Kdf(false) { }
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
		Pkcs5HmacStreebog_Boot () : Pkcs5Kdf(false) { }
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
