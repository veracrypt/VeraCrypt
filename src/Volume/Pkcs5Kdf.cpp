/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Common/Pkcs5.h"
#include "Pkcs5Kdf.h"
#include "VolumePassword.h"

namespace TrueCrypt
{
	Pkcs5Kdf::Pkcs5Kdf ()
	{
	}

	Pkcs5Kdf::~Pkcs5Kdf ()
	{
	}

	void Pkcs5Kdf::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, BOOL bNotTest) const
	{
		DeriveKey (key, password, salt, GetIterationCount(), bNoTest);
	}
	
	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const wstring &name)
	{
		foreach (shared_ptr <Pkcs5Kdf> kdf, GetAvailableAlgorithms())
		{
			if (kdf->GetName() == name)
				return kdf;
		}
		throw ParameterIncorrect (SRC_POS);
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const Hash &hash)
	{
		foreach (shared_ptr <Pkcs5Kdf> kdf, GetAvailableAlgorithms())
		{
			if (typeid (*kdf->GetHash()) == typeid (hash))
				return kdf;
		}

		throw ParameterIncorrect (SRC_POS);
	}

	Pkcs5KdfList Pkcs5Kdf::GetAvailableAlgorithms ()
	{
		Pkcs5KdfList l;
		
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1 ()));

		return l;
	}

	void Pkcs5Kdf::ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		if (key.Size() < 1 || password.Size() < 1 || salt.Size() < 1 || iterationCount < 1)
			throw ParameterIncorrect (SRC_POS);
	}

	void Pkcs5HmacRipemd160::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_ripemd160 (bNoTest, (char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacRipemd160_1000::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_ripemd160 (bNoTest, (char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha1::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha1 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha512 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacWhirlpool::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, BOOL bNotTest) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_whirlpool ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}
}
