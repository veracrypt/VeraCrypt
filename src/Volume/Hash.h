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

#ifndef TC_HEADER_Encryption_Hash
#define TC_HEADER_Encryption_Hash

#include "Platform/Platform.h"

namespace VeraCrypt
{
	class Hash;
	typedef list < shared_ptr <Hash> > HashList;

	class Hash
	{
	public:
		Hash () : Deprecated (false) { }
		virtual ~Hash () { }

		static HashList GetAvailableAlgorithms ();
		virtual void GetDigest (const BufferPtr &buffer) = 0;
		virtual size_t GetBlockSize () const = 0;
		virtual size_t GetDigestSize () const = 0;
		virtual wstring GetName () const = 0;
		virtual wstring GetAltName () const = 0;
		virtual shared_ptr <Hash> GetNew () const = 0;
		virtual void Init () = 0;
		bool IsDeprecated () const { return Deprecated; }
		virtual void ProcessData (const ConstBufferPtr &data) = 0;
		virtual void ValidateDataParameters (const ConstBufferPtr &data) const;
		virtual void ValidateDigestParameters (const BufferPtr &buffer) const;

	protected:
		SecureBuffer Context;
		bool Deprecated;

	private:
		Hash (const Hash &);
		Hash &operator= (const Hash &);
	};

	// Blake2s
	class Blake2s : public Hash
	{
	public:
		Blake2s ();
		virtual ~Blake2s () { }

		virtual void GetDigest (const BufferPtr &buffer);
		virtual size_t GetBlockSize () const { return 64; }
		virtual size_t GetDigestSize () const { return 32; }
		virtual wstring GetName () const { return L"BLAKE2s-256"; }
		virtual wstring GetAltName () const { return L"BLAKE2s"; }
		virtual shared_ptr <Hash> GetNew () const { return shared_ptr <Hash> (new Blake2s); }
		virtual void Init ();
		virtual void ProcessData (const ConstBufferPtr &data);

	protected:

	private:
		Blake2s (const Blake2s &);
		Blake2s &operator= (const Blake2s &);
	};

	// SHA-256
	class Sha256 : public Hash
	{
	public:
		Sha256 ();
		virtual ~Sha256 () { }

		virtual void GetDigest (const BufferPtr &buffer);
		virtual size_t GetBlockSize () const { return 64; }
		virtual size_t GetDigestSize () const { return 256 / 8; }
		virtual wstring GetName () const { return L"SHA-256"; }
		virtual wstring GetAltName () const { return L"SHA256"; }
		virtual shared_ptr <Hash> GetNew () const { return shared_ptr <Hash> (new Sha256); }
		virtual void Init ();
		virtual void ProcessData (const ConstBufferPtr &data);

	protected:

	private:
		Sha256 (const Sha256 &);
		Sha256 &operator= (const Sha256 &);
	};

	// SHA-512
	class Sha512 : public Hash
	{
	public:
		Sha512 ();
		virtual ~Sha512 () { }

		virtual void GetDigest (const BufferPtr &buffer);
		virtual size_t GetBlockSize () const { return 128; }
		virtual size_t GetDigestSize () const { return 512 / 8; }
		virtual wstring GetName () const { return L"SHA-512"; }
		virtual wstring GetAltName () const { return L"SHA512"; }
		virtual shared_ptr <Hash> GetNew () const { return shared_ptr <Hash> (new Sha512); }
		virtual void Init ();
		virtual void ProcessData (const ConstBufferPtr &data);

	protected:

	private:
		Sha512 (const Sha512 &);
		Sha512 &operator= (const Sha512 &);
	};

	// Whirlpool
	class Whirlpool : public Hash
	{
	public:
		Whirlpool ();
		virtual ~Whirlpool () { }

		virtual void GetDigest (const BufferPtr &buffer);
		virtual size_t GetBlockSize () const { return 64; }
		virtual size_t GetDigestSize () const { return 512 / 8; }
		virtual wstring GetName () const { return L"Whirlpool"; }
		virtual wstring GetAltName () const { return L"Whirlpool"; }
		virtual shared_ptr <Hash> GetNew () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual void Init ();
		virtual void ProcessData (const ConstBufferPtr &data);

	protected:

	private:
		Whirlpool (const Whirlpool &);
		Whirlpool &operator= (const Whirlpool &);
	};
	
	// Streebog
	class Streebog : public Hash
	{
	public:
		Streebog ();
		virtual ~Streebog () { }

		virtual void GetDigest (const BufferPtr &buffer);
		virtual size_t GetBlockSize () const { return 64; }
		virtual size_t GetDigestSize () const { return 512 / 8; }
		virtual wstring GetName () const { return L"Streebog"; }
		virtual wstring GetAltName () const { return L"Streebog"; }
		virtual shared_ptr <Hash> GetNew () const { return shared_ptr <Hash> (new Streebog); }
		virtual void Init ();
		virtual void ProcessData (const ConstBufferPtr &data);

	protected:

	private:
		Streebog (const Streebog &);
		Streebog &operator= (const Streebog &);
	};
}

#endif // TC_HEADER_Encryption_Hash
