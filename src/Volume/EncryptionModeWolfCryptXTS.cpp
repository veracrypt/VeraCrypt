
#include "Crypto/cpu.h"
#include "Crypto/misc.h"
#include "EncryptionModeWolfCryptXTS.h"
#include "Common/Crypto.h"

namespace VeraCrypt
{
	void EncryptionModeWolfCryptXTS::Encrypt (uint8 *data, uint64 length) const
	{
		EncryptBuffer (data, length, 0);
	}

	void EncryptionModeWolfCryptXTS::EncryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
		if_debug (ValidateState());

		CipherList::const_iterator iSecondaryCipher = SecondaryCiphers.begin();

		for (CipherList::const_iterator iCipher = Ciphers.begin(); iCipher != Ciphers.end(); ++iCipher)
		{
			EncryptBufferXTS (**iCipher, **iSecondaryCipher, data, length, startDataUnitNo, 0);
			++iSecondaryCipher;
		}

		assert (iSecondaryCipher == SecondaryCiphers.end());
	}

	void EncryptionModeWolfCryptXTS::EncryptBufferXTS (Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
                cipher.EncryptBlockXTS(buffer, length, startDataUnitNo);
	}

	void EncryptionModeWolfCryptXTS::EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}

	size_t EncryptionModeWolfCryptXTS::GetKeySize () const
	{
		if (Ciphers.empty())
			throw NotInitialized (SRC_POS);

		size_t keySize = 0;
		foreach_ref (const Cipher &cipher, SecondaryCiphers)
		{
			keySize += cipher.GetKeySize();
		}

		return keySize;
	}

	void EncryptionModeWolfCryptXTS::Decrypt (uint8 *data, uint64 length) const
	{
		DecryptBuffer (data, length, 0);
	}

	void EncryptionModeWolfCryptXTS::DecryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const
	{
		if_debug (ValidateState());

		CipherList::const_iterator iSecondaryCipher = SecondaryCiphers.end();

		for (CipherList::const_reverse_iterator iCipher = Ciphers.rbegin(); iCipher != Ciphers.rend(); ++iCipher)
		{
			--iSecondaryCipher;
			DecryptBufferXTS (**iCipher, **iSecondaryCipher, data, length, startDataUnitNo, 0);
		}

		assert (iSecondaryCipher == SecondaryCiphers.begin());
	}

	void EncryptionModeWolfCryptXTS::DecryptBufferXTS (Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
                cipher.DecryptBlockXTS(buffer, length, startDataUnitNo);
        }

	void EncryptionModeWolfCryptXTS::DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		DecryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}

	void EncryptionModeWolfCryptXTS::SetCiphers (const CipherList &ciphers)
	{
		EncryptionMode::SetCiphers (ciphers);

		SecondaryCiphers.clear();

		foreach_ref (const Cipher &cipher, ciphers)
		{
			SecondaryCiphers.push_back (cipher.GetNew());
		}

		if (SecondaryKey.Size() > 0)
			SetSecondaryCipherKeys();
	}

	void EncryptionModeWolfCryptXTS::SetKey (const ConstBufferPtr &key)
	{
		SecondaryKey.Allocate (key.Size());
		SecondaryKey.CopyFrom (key);

		if (!SecondaryCiphers.empty())
			SetSecondaryCipherKeys();

        }

	void EncryptionModeWolfCryptXTS::SetSecondaryCipherKeys ()
	{
		size_t keyOffset = 0;
		foreach_ref (Cipher &cipher, SecondaryCiphers)
		{
                        cipher.SetKeyXTS (SecondaryKey.GetRange (keyOffset, cipher.GetKeySize()));
                        keyOffset += cipher.GetKeySize();
		}

		KeySet = true;
	}
}
