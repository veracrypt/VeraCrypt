/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/Platform.h"
#include "Cipher.h"
#include "Crypto/Aes.h"
#include "Crypto/Blowfish.h"
#include "Crypto/Des.h"
#include "Crypto/Cast.h"
#include "Crypto/Serpent.h"
#include "Crypto/Twofish.h"

#ifdef TC_AES_HW_CPU
#	include "Crypto/Aes_hw_cpu.h"
#endif

namespace TrueCrypt
{
	Cipher::Cipher () : Initialized (false)
	{
	}

	Cipher::~Cipher ()
	{
	}

	void Cipher::DecryptBlock (byte *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Decrypt (data);
	}

	void Cipher::DecryptBlocks (byte *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		while (blockCount-- > 0)
		{
			Decrypt (data);
			data += GetBlockSize();
		}
	}

	void Cipher::EncryptBlock (byte *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Encrypt (data);
	}

	void Cipher::EncryptBlocks (byte *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		while (blockCount-- > 0)
		{
			Encrypt (data);
			data += GetBlockSize();
		}
	}

	CipherList Cipher::GetAvailableCiphers ()
	{
		CipherList l;

		l.push_back (shared_ptr <Cipher> (new CipherAES ()));
		l.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		l.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		l.push_back (shared_ptr <Cipher> (new CipherBlowfish ()));
		l.push_back (shared_ptr <Cipher> (new CipherCast5 ()));
		l.push_back (shared_ptr <Cipher> (new CipherTripleDES ()));

		return l;
	}

	void Cipher::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != GetKeySize ())
			throw ParameterIncorrect (SRC_POS);

		if (!Initialized)
			ScheduledKey.Allocate (GetScheduledKeySize ());

		SetCipherKey (key);
		Key.CopyFrom (key);
		Initialized = true;
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (CipherException);


	// AES
	void CipherAES::Decrypt (byte *data) const
	{
#ifdef TC_AES_HW_CPU
		if (IsHwSupportAvailable())
			aes_hw_cpu_decrypt (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx), data);
		else
#endif
			aes_decrypt (data, data, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx)));
	}

	void CipherAES::DecryptBlocks (byte *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#ifdef TC_AES_HW_CPU
		if ((blockCount & (32 - 1)) == 0
			&& IsHwSupportAvailable())
		{
			while (blockCount > 0)
			{
				aes_hw_cpu_decrypt_32_blocks (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx), data);

				data += 32 * GetBlockSize();
				blockCount -= 32;
			}
		}
		else
#endif
			Cipher::DecryptBlocks (data, blockCount);
	}

	void CipherAES::Encrypt (byte *data) const
	{
#ifdef TC_AES_HW_CPU
		if (IsHwSupportAvailable())
			aes_hw_cpu_encrypt (ScheduledKey.Ptr(), data);
		else
#endif
			aes_encrypt (data, data, (aes_encrypt_ctx *) ScheduledKey.Ptr());
	}

	void CipherAES::EncryptBlocks (byte *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#ifdef TC_AES_HW_CPU
		if ((blockCount & (32 - 1)) == 0
			&& IsHwSupportAvailable())
		{
			while (blockCount > 0)
			{
				aes_hw_cpu_encrypt_32_blocks (ScheduledKey.Ptr(), data);

				data += 32 * GetBlockSize();
				blockCount -= 32;
			}
		}
		else
#endif
			Cipher::EncryptBlocks (data, blockCount);
	}

	size_t CipherAES::GetScheduledKeySize () const
	{
		return sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx);
	}

	bool CipherAES::IsHwSupportAvailable () const
	{
#ifdef TC_AES_HW_CPU
		static bool state = false;
		static bool stateValid = false;

		if (!stateValid)
		{
			state = is_aes_hw_cpu_supported() ? true : false;
			stateValid = true;
		}
		return state && HwSupportEnabled;
#else
		return false;
#endif
	}

	void CipherAES::SetCipherKey (const byte *key)
	{
		if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ScheduledKey.Ptr()) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);

		if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx))) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);
	}

	
	// Blowfish
	void CipherBlowfish::Decrypt (byte *data) const
	{
		BlowfishEncryptLE (data, data, (BF_KEY *) ScheduledKey.Ptr(), 0);
	}

	void CipherBlowfish::Encrypt (byte *data) const
	{
		BlowfishEncryptLE (data, data, (BF_KEY *) ScheduledKey.Ptr(), 1);
	}

	size_t CipherBlowfish::GetScheduledKeySize () const
	{
		return sizeof (BF_KEY);
	}

	void CipherBlowfish::SetCipherKey (const byte *key)
	{
		BlowfishSetKey ((BF_KEY *) ScheduledKey.Ptr(), static_cast<int> (GetKeySize ()), (unsigned char *) key);
	}


	// CAST5
	void CipherCast5::Decrypt (byte *data) const
	{
		Cast5Decrypt (data, data, (CAST_KEY *) ScheduledKey.Ptr());
	}

	void CipherCast5::Encrypt (byte *data) const
	{
		Cast5Encrypt (data, data, (CAST_KEY *) ScheduledKey.Ptr());
	}

	size_t CipherCast5::GetScheduledKeySize () const
	{
		return sizeof (CAST_KEY);
	}

	void CipherCast5::SetCipherKey (const byte *key)
	{
		Cast5SetKey ((CAST_KEY *) ScheduledKey.Ptr(), static_cast<int> (GetKeySize ()), (unsigned char *) key);
	}


	// Serpent
	void CipherSerpent::Decrypt (byte *data) const
	{
		serpent_decrypt (data, data, ScheduledKey);
	}

	void CipherSerpent::Encrypt (byte *data) const
	{
		serpent_encrypt (data, data, ScheduledKey);
	}
	
	size_t CipherSerpent::GetScheduledKeySize () const
	{
		return 140*4;
	}

	void CipherSerpent::SetCipherKey (const byte *key)
	{
		serpent_set_key (key, static_cast<int> (GetKeySize ()), ScheduledKey);
	}


	// Triple-DES
	void CipherTripleDES::Decrypt (byte *data) const
	{
		TripleDesEncrypt (data, data, (TDES_KEY *) ScheduledKey.Ptr(), 0);
	}

	void CipherTripleDES::Encrypt (byte *data) const
	{
		TripleDesEncrypt (data, data, (TDES_KEY *) ScheduledKey.Ptr(), 1);
	}

	size_t CipherTripleDES::GetScheduledKeySize () const
	{
		return sizeof (TDES_KEY);
	}

	void CipherTripleDES::SetCipherKey (const byte *key)
	{
		TripleDesSetKey (key, GetKeySize(), (TDES_KEY *) ScheduledKey.Ptr());
	}


	// Twofish
	void CipherTwofish::Decrypt (byte *data) const
	{
		twofish_decrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	void CipherTwofish::Encrypt (byte *data) const
	{
		twofish_encrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	size_t CipherTwofish::GetScheduledKeySize () const
	{
		return TWOFISH_KS;
	}

	void CipherTwofish::SetCipherKey (const byte *key)
	{
		twofish_set_key ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *) key, static_cast<int> (GetKeySize ()) * 8);
	}


	bool Cipher::HwSupportEnabled = true;
}
