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

#include "Platform/Platform.h"
#include "Cipher.h"
#include "Crypto/Aes.h"
#include "Crypto/SerpentFast.h"
#include "Crypto/Twofish.h"
#include "Crypto/Camellia.h"
#include "Crypto/kuznyechik.h"

#ifdef TC_AES_HW_CPU
#	include "Crypto/Aes_hw_cpu.h"
#endif

extern "C" int IsAesHwCpuSupported ()
{
#ifdef TC_AES_HW_CPU
	static bool state = false;
	static bool stateValid = false;

	if (!stateValid)
	{
		state = HasAESNI() ? true : false;
		stateValid = true;
	}
	return state && VeraCrypt::Cipher::IsHwSupportEnabled();
#else
	return false;
#endif
}

namespace VeraCrypt
{
	Cipher::Cipher () : Initialized (false)
	{
	}

	Cipher::~Cipher ()
	{
	}

	void Cipher::DecryptBlock (uint8 *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Decrypt (data);
	}

	void Cipher::DecryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		while (blockCount-- > 0)
		{
			Decrypt (data);
			data += GetBlockSize();
		}
	}

	void Cipher::EncryptBlock (uint8 *data) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		Encrypt (data);
	}

	void Cipher::EncryptBlocks (uint8 *data, size_t blockCount) const
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
        #ifndef WOLFCRYPT_BACKEND
		l.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		l.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		l.push_back (shared_ptr <Cipher> (new CipherCamellia ()));
		l.push_back (shared_ptr <Cipher> (new CipherKuznyechik ()));
        #endif
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

    #ifdef WOLFCRYPT_BACKEND
        void Cipher::SetKeyXTS (const ConstBufferPtr &key)
	{
		if (key.Size() != GetKeySize ())
			throw ParameterIncorrect (SRC_POS);

		if (!Initialized)
			ScheduledKey.Allocate (GetScheduledKeySize ());

		SetCipherKeyXTS (key);
		Key.CopyFrom (key);
		Initialized = true;
	}

         void Cipher::EncryptBlockXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		EncryptXTS (data, length, startDataUnitNo);
	}

        void Cipher::DecryptBlockXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

		DecryptXTS (data, length, startDataUnitNo);
	}
    #endif

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (CipherException);


	// AES
	void CipherAES::Decrypt (uint8 *data) const
	{
#ifdef TC_AES_HW_CPU
		if (IsHwSupportAvailable())
			aes_hw_cpu_decrypt (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx), data);
		else
#endif
			aes_decrypt (data, data, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx)));
	}

	void CipherAES::DecryptBlocks (uint8 *data, size_t blockCount) const
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

	void CipherAES::Encrypt (uint8 *data) const
	{
#ifdef TC_AES_HW_CPU
		if (IsHwSupportAvailable())
			aes_hw_cpu_encrypt (ScheduledKey.Ptr(), data);
		else
#endif
			aes_encrypt (data, data, (aes_encrypt_ctx *) ScheduledKey.Ptr());
	}

	void CipherAES::EncryptBlocks (uint8 *data, size_t blockCount) const
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
    #ifdef WOLFCRYPT_BACKEND
        void CipherAES::EncryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
	    xts_encrypt (data, data, length, startDataUnitNo, (aes_encrypt_ctx *) ScheduledKey.Ptr());
	}

        void CipherAES::DecryptXTS (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
	    xts_decrypt (data, data, length, startDataUnitNo, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx)));
	}

        void CipherAES::SetCipherKeyXTS (const uint8 *key)
	{
		if (xts_encrypt_key256 (key, (aes_encrypt_ctx *) ScheduledKey.Ptr()) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);

		if (xts_decrypt_key256 (key, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx))) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);
	}
    #endif

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
			state = HasAESNI() ? true : false;
			stateValid = true;
		}
		return state && HwSupportEnabled;
#else
		return false;
#endif
	}

	void CipherAES::SetCipherKey (const uint8 *key)
	{
		if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ScheduledKey.Ptr()) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);

		if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ScheduledKey.Ptr() + sizeof (aes_encrypt_ctx))) != EXIT_SUCCESS)
			throw CipherInitError (SRC_POS);
	}

    #ifndef WOLFCRYPT_BACKEND
	// Serpent
	void CipherSerpent::Decrypt (uint8 *data) const
	{
		serpent_decrypt (data, data, ScheduledKey);
	}

	void CipherSerpent::Encrypt (uint8 *data) const
	{
		serpent_encrypt (data, data, ScheduledKey);
	}

	size_t CipherSerpent::GetScheduledKeySize () const
	{
		return 140*4;
	}

	void CipherSerpent::SetCipherKey (const uint8 *key)
	{
		serpent_set_key (key, ScheduledKey);
	}
	
	void CipherSerpent::EncryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(CRYPTOPP_DISABLE_ASM)
		if ((blockCount >= 4)
			&& IsHwSupportAvailable())
		{
			serpent_encrypt_blocks (data, data, blockCount, ScheduledKey.Ptr());
		}
		else
#endif
			Cipher::EncryptBlocks (data, blockCount);
	}
	
	void CipherSerpent::DecryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(CRYPTOPP_DISABLE_ASM)
		if ((blockCount >= 4)
			&& IsHwSupportAvailable())
		{
			serpent_decrypt_blocks (data, data, blockCount, ScheduledKey.Ptr());
		}
		else
#endif
			Cipher::DecryptBlocks (data, blockCount);
	}
	
	bool CipherSerpent::IsHwSupportAvailable () const
	{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		static bool state = false;
		static bool stateValid = false;

		if (!stateValid)
		{
			state = HasSSE2() ? true : false;
			stateValid = true;
		}
		return state;
#else
		return false;
#endif
	}


	// Twofish
	void CipherTwofish::Decrypt (uint8 *data) const
	{
		twofish_decrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	void CipherTwofish::Encrypt (uint8 *data) const
	{
		twofish_encrypt ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *)data, (unsigned int *)data);
	}

	size_t CipherTwofish::GetScheduledKeySize () const
	{
		return TWOFISH_KS;
	}

	void CipherTwofish::SetCipherKey (const uint8 *key)
	{
		twofish_set_key ((TwofishInstance *) ScheduledKey.Ptr(), (unsigned int *) key);
	}
	
	void CipherTwofish::EncryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		twofish_encrypt_blocks ( (TwofishInstance *) ScheduledKey.Ptr(), data, data, blockCount);
#else
		Cipher::EncryptBlocks (data, blockCount);
#endif
	}
	
	void CipherTwofish::DecryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		twofish_decrypt_blocks ( (TwofishInstance *) ScheduledKey.Ptr(), data, data, blockCount);
#else
		Cipher::DecryptBlocks (data, blockCount);
#endif
	}
	
	bool CipherTwofish::IsHwSupportAvailable () const
	{
#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		return true;
#else
		return false;
#endif
	}
	
	// Camellia
	void CipherCamellia::Decrypt (uint8 *data) const
	{
		camellia_decrypt (data, data, ScheduledKey.Ptr());
	}

	void CipherCamellia::Encrypt (uint8 *data) const
	{
		camellia_encrypt (data, data, ScheduledKey.Ptr());
	}

	size_t CipherCamellia::GetScheduledKeySize () const
	{
		return CAMELLIA_KS;
	}

	void CipherCamellia::SetCipherKey (const uint8 *key)
	{
		camellia_set_key (key, ScheduledKey.Ptr());
	}
	
	void CipherCamellia::EncryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		camellia_encrypt_blocks ( ScheduledKey.Ptr(), data, data, blockCount);
#else
		Cipher::EncryptBlocks (data, blockCount);
#endif
	}
	
	void CipherCamellia::DecryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		camellia_decrypt_blocks ( ScheduledKey.Ptr(), data, data, blockCount);
#else
		Cipher::DecryptBlocks (data, blockCount);
#endif
	}
	
	bool CipherCamellia::IsHwSupportAvailable () const
	{
#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
		return true;
#else
		return false;
#endif
	}

	// Kuznyechik
	void CipherKuznyechik::Decrypt (uint8 *data) const
	{
		kuznyechik_decrypt_block (data, data, (kuznyechik_kds *) ScheduledKey.Ptr());
	}

	void CipherKuznyechik::Encrypt (uint8 *data) const
	{
		kuznyechik_encrypt_block (data, data, (kuznyechik_kds *) ScheduledKey.Ptr());
	}

	size_t CipherKuznyechik::GetScheduledKeySize () const
	{
		return KUZNYECHIK_KS;
	}

	void CipherKuznyechik::SetCipherKey (const uint8 *key)
	{
		kuznyechik_set_key (key, (kuznyechik_kds *) ScheduledKey.Ptr());
	}
	void CipherKuznyechik::EncryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		if ((blockCount >= 4)
			&& IsHwSupportAvailable())
		{
			kuznyechik_encrypt_blocks (data, data, blockCount, (kuznyechik_kds *) ScheduledKey.Ptr());
		}
		else
#endif
			Cipher::EncryptBlocks (data, blockCount);
	}
	
	void CipherKuznyechik::DecryptBlocks (uint8 *data, size_t blockCount) const
	{
		if (!Initialized)
			throw NotInitialized (SRC_POS);

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		if ((blockCount >= 4)
			&& IsHwSupportAvailable())
		{
			kuznyechik_decrypt_blocks (data, data, blockCount, (kuznyechik_kds *) ScheduledKey.Ptr());
		}
		else
#endif
			Cipher::DecryptBlocks (data, blockCount);
	}
	
	bool CipherKuznyechik::IsHwSupportAvailable () const
	{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
		static bool state = false;
		static bool stateValid = false;

		if (!stateValid)
		{
			state = HasSSE2() ? true : false;
			stateValid = true;
		}
		return state;
#else
		return false;
#endif
	}
    #endif	
        bool Cipher::HwSupportEnabled = true;
}
