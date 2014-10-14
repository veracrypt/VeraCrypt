/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Hash.h"

#include "Crypto/Rmd160.h"
#include "Crypto/Sha2.h"
#include "Crypto/Whirlpool.h"

namespace VeraCrypt
{
	HashList Hash::GetAvailableAlgorithms ()
	{
		HashList l;
		
		l.push_back (shared_ptr <Hash> (new Sha512 ()));
		l.push_back (shared_ptr <Hash> (new Whirlpool ()));
		l.push_back (shared_ptr <Hash> (new Sha256 ()));
		l.push_back (shared_ptr <Hash> (new Ripemd160 ()));

		return l;
	}

	void Hash::ValidateDataParameters (const ConstBufferPtr &data) const
	{
		if (data.Size() < 1)
			throw ParameterIncorrect (SRC_POS);
	}

	void Hash::ValidateDigestParameters (const BufferPtr &buffer) const
	{
		if (buffer.Size() != GetDigestSize ())
			throw ParameterIncorrect (SRC_POS);
	}

	// RIPEMD-160
	Ripemd160::Ripemd160 ()
	{
		Context.Allocate (sizeof (RMD160_CTX));
		Init();
	}

	void Ripemd160::GetDigest (const BufferPtr &buffer)
	{
		if_debug (ValidateDigestParameters (buffer));
		RMD160Final (buffer, (RMD160_CTX *) Context.Ptr());
	}

	void Ripemd160::Init ()
	{
		RMD160Init ((RMD160_CTX *) Context.Ptr());
	}

	void Ripemd160::ProcessData (const ConstBufferPtr &data)
	{
		if_debug (ValidateDataParameters (data));
		RMD160Update ((RMD160_CTX *) Context.Ptr(), data.Get(), (int) data.Size());
	}
	
	// SHA-256
	Sha256::Sha256 ()
	{
		Context.Allocate (sizeof (sha256_ctx));
		Init();
	}

	void Sha256::GetDigest (const BufferPtr &buffer)
	{
		if_debug (ValidateDigestParameters (buffer));
		sha256_end (buffer, (sha256_ctx *) Context.Ptr());
	}

	void Sha256::Init ()
	{
		sha256_begin ((sha256_ctx *) Context.Ptr());
	}

	void Sha256::ProcessData (const ConstBufferPtr &data)
	{
		if_debug (ValidateDataParameters (data));
		sha256_hash (data.Get(), (int) data.Size(), (sha256_ctx *) Context.Ptr());
	}

	// SHA-512
	Sha512::Sha512 ()
	{
		Context.Allocate (sizeof (sha512_ctx));
		Init();
	}

	void Sha512::GetDigest (const BufferPtr &buffer)
	{
		if_debug (ValidateDigestParameters (buffer));
		sha512_end (buffer, (sha512_ctx *) Context.Ptr());
	}

	void Sha512::Init ()
	{
		sha512_begin ((sha512_ctx *) Context.Ptr());
	}

	void Sha512::ProcessData (const ConstBufferPtr &data)
	{
		if_debug (ValidateDataParameters (data));
		sha512_hash (data.Get(), (int) data.Size(), (sha512_ctx *) Context.Ptr());
	}

	// Whirlpool
	Whirlpool::Whirlpool ()
	{
		Context.Allocate (sizeof (WHIRLPOOL_CTX));
		Init();
	}

	void Whirlpool::GetDigest (const BufferPtr &buffer)
	{
		if_debug (ValidateDigestParameters (buffer));
		WHIRLPOOL_finalize ((WHIRLPOOL_CTX *) Context.Ptr(), buffer);
	}

	void Whirlpool::Init ()
	{
		WHIRLPOOL_init ((WHIRLPOOL_CTX *) Context.Ptr());
	}

	void Whirlpool::ProcessData (const ConstBufferPtr &data)
	{
		if_debug (ValidateDataParameters (data));
		WHIRLPOOL_add (data.Get(), (int) data.Size() * 8, (WHIRLPOOL_CTX *) Context.Ptr());
	}
}
