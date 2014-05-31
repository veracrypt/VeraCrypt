/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/Memory.h"
#include "Common/Crc.h"
#include "Common/Endian.h"
#include "EncryptionModeCBC.h"

namespace TrueCrypt
{
	void EncryptionModeCBC::Decrypt (byte *data, uint64 length) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, length));

		if (IsOuterCBC (Ciphers))
		{
			DecryptBuffer (data, length, Ciphers, (uint32 *) IV.Ptr(), (uint32 *) (IV.Ptr() + WhiteningIVOffset));
		}
		else
		{
			for (CipherList::const_reverse_iterator iCipherList = Ciphers.rbegin();
				iCipherList != Ciphers.rend();
				++iCipherList)
			{
				CipherList cl;
				cl.push_back (*iCipherList);

				DecryptBuffer (data, length, cl, (uint32 *) IV.Ptr(), (uint32 *) (IV.Ptr() + WhiteningIVOffset));
			}
		}
	}

	void EncryptionModeCBC::DecryptBuffer (byte *data, uint64 length, const CipherList &ciphers, const uint32 *iv, const uint32 *whitening) const
	{
		size_t blockSize = ciphers.front()->GetBlockSize();
		if (blockSize != 8 && blockSize != 16)
			throw ParameterIncorrect (SRC_POS);

		uint32 *data32 = (uint32 *) data;
		uint32 bufIV[4];
		uint32 ct[4];
		uint64 i;

		bufIV[0] = iv[0];
		bufIV[1] = iv[1];
		if (blockSize == 16)
		{
			bufIV[2] = iv[2];
			bufIV[3] = iv[3];
		}

		for (i = 0; i < length / blockSize; i++)
		{
			// Dewhitening
			data32[0] ^= whitening[0];
			data32[1] ^= whitening[1];
			if (blockSize == 16)
			{
				data32[2] ^= whitening[0];
				data32[3] ^= whitening[1];
			}

			// CBC
			ct[0] = data32[0];
			ct[1] = data32[1];
			if (blockSize == 16)
			{
				ct[2] = data32[2];
				ct[3] = data32[3];
			}

			for (CipherList::const_reverse_iterator iCipherList = ciphers.rbegin();
				iCipherList != ciphers.rend();
				++iCipherList)
			{
				const Cipher &c = **iCipherList;

				if (c.GetBlockSize () != blockSize)
					throw ParameterIncorrect (SRC_POS);

				c.DecryptBlock ((byte *) data32);
			}

			// CBC
			data32[0] ^= bufIV[0];
			data32[1] ^= bufIV[1];
			bufIV[0] = ct[0];
			bufIV[1] = ct[1];
			if (blockSize == 16)
			{
				data32[2] ^= bufIV[2];
				data32[3] ^= bufIV[3];
				bufIV[2] = ct[2];
				bufIV[3] = ct[3];
			}

			data32 += blockSize / sizeof(*data32);
		}

		Memory::Erase (bufIV, sizeof (bufIV));
		Memory::Erase (ct, sizeof (ct));
	}

	void EncryptionModeCBC::DecryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, sectorCount, sectorSize));

		uint32 sectorIV[4];
		uint32 sectorWhitening[2];

		while (sectorCount--)
		{
			if (IsOuterCBC (Ciphers))
			{
				InitSectorIVAndWhitening (sectorIndex, Ciphers.front()->GetBlockSize(), (uint64 *) IV.Ptr(), sectorIV, sectorWhitening);
				DecryptBuffer (data, sectorSize, Ciphers, sectorIV, sectorWhitening);
			}
			else
			{
				for (CipherList::const_reverse_iterator iCipherList = Ciphers.rbegin();
					iCipherList != Ciphers.rend();
					++iCipherList)
				{
					const Cipher &c = **iCipherList;
					CipherList cl;
					cl.push_back (*iCipherList);

					InitSectorIVAndWhitening (sectorIndex, c.GetBlockSize(), (uint64 *) IV.Ptr(), sectorIV, sectorWhitening);
					DecryptBuffer (data, sectorSize, cl, sectorIV, sectorWhitening);
				}
			}

			data += sectorSize;
			sectorIndex++;
		}

		Memory::Erase (sectorIV, sizeof (sectorIV));
		Memory::Erase (sectorWhitening, sizeof (sectorWhitening));
	}

	void EncryptionModeCBC::Encrypt (byte *data, uint64 length) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, length));

		if (IsOuterCBC (Ciphers))
		{
			EncryptBuffer (data, length, Ciphers, (uint32 *) IV.Ptr(), (uint32 *) (IV.Ptr() + WhiteningIVOffset));
		}
		else
		{
			for (CipherList::const_iterator iCipherList = Ciphers.begin();
				iCipherList != Ciphers.end();
				++iCipherList)
			{
				CipherList cl;
				cl.push_back (*iCipherList);

				EncryptBuffer (data, length, cl, (uint32 *) IV.Ptr(), (uint32 *) (IV.Ptr() + WhiteningIVOffset));
			}
		}
	}

	void EncryptionModeCBC::EncryptBuffer (byte *data, uint64 length, const CipherList &ciphers, const uint32 *iv, const uint32 *whitening) const
	{
		size_t blockSize = ciphers.front()->GetBlockSize();
		if (blockSize != 8 && blockSize != 16)
			throw ParameterIncorrect (SRC_POS);

		uint32 *data32 = (uint32 *) data;
		uint32 bufIV[4];
		uint64 i;

		bufIV[0] = iv[0];
		bufIV[1] = iv[1];
		if (blockSize == 16)
		{
			bufIV[2] = iv[2];
			bufIV[3] = iv[3];
		}

		for (i = 0; i < length / blockSize; i++)
		{
			data32[0] ^= bufIV[0];
			data32[1] ^= bufIV[1];
			if (blockSize == 16)
			{
				data32[2] ^= bufIV[2];
				data32[3] ^= bufIV[3];
			}

			for (CipherList::const_iterator iCipherList = ciphers.begin();
				iCipherList != ciphers.end();
				++iCipherList)
			{
				const Cipher &c = **iCipherList;

				if (c.GetBlockSize () != blockSize)
					throw ParameterIncorrect (SRC_POS);

				c.EncryptBlock ((byte *) data32);
			}

			bufIV[0] = data32[0];
			bufIV[1] = data32[1];
			if (blockSize == 16)
			{
				bufIV[2] = data32[2];
				bufIV[3] = data32[3];
			}

			data32[0] ^= whitening[0];
			data32[1] ^= whitening[1];
			if (blockSize == 16)
			{
				data32[2] ^= whitening[0];
				data32[3] ^= whitening[1];
			}

			data32 += blockSize / sizeof(*data32);
		}

		Memory::Erase (bufIV, sizeof (bufIV));
	}

	void EncryptionModeCBC::EncryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, sectorCount, sectorSize));

		uint32 sectorIV[4];
		uint32 sectorWhitening[2];

		while (sectorCount--)
		{
			if (IsOuterCBC (Ciphers))
			{
				InitSectorIVAndWhitening (sectorIndex, Ciphers.front()->GetBlockSize(), (uint64 *) IV.Ptr(), sectorIV, sectorWhitening);
				EncryptBuffer (data, sectorSize, Ciphers, sectorIV, sectorWhitening);
			}
			else
			{
				for (CipherList::const_iterator iCipherList = Ciphers.begin();
					iCipherList != Ciphers.end();
					++iCipherList)
				{
					const Cipher &c = **iCipherList;
					CipherList cl;
					cl.push_back (*iCipherList);

					InitSectorIVAndWhitening (sectorIndex, c.GetBlockSize(), (uint64 *) IV.Ptr(), sectorIV, sectorWhitening);
					EncryptBuffer (data, sectorSize, cl, sectorIV, sectorWhitening);
				}
			}

			data += sectorSize;
			sectorIndex++;
		}

		Memory::Erase (sectorIV, sizeof (sectorIV));
		Memory::Erase (sectorWhitening, sizeof (sectorWhitening));
	}

	void EncryptionModeCBC::InitSectorIVAndWhitening (uint64 sectorIndex, size_t blockSize, const uint64 *ivSeed, uint32 *iv, uint32 *whitening) const
	{
		if (blockSize != 8 && blockSize != 16)
			throw ParameterIncorrect (SRC_POS);

		uint64 iv64[4];
		uint32 *iv32 = (uint32 *) iv64;

		iv64[0] = ivSeed[0] ^ Endian::Little (sectorIndex);
		iv64[1] = ivSeed[1] ^ Endian::Little (sectorIndex);
		iv64[2] = ivSeed[2] ^ Endian::Little (sectorIndex);
		if (blockSize == 16)
		{
			iv64[3] = ivSeed[3] ^ Endian::Little (sectorIndex);
		}

		iv[0] = iv32[0];
		iv[1] = iv32[1];

		if (blockSize == 8)
		{
			whitening[0] = Endian::Little ( crc32int ( &iv32[2] ) ^ crc32int ( &iv32[5] ) );
			whitening[1] = Endian::Little ( crc32int ( &iv32[3] ) ^ crc32int ( &iv32[4] ) );
		}
		else
		{
			iv[2] = iv32[2];
			iv[3] = iv32[3];

			whitening[0] = Endian::Little ( crc32int ( &iv32[4] ) ^ crc32int ( &iv32[7] ) );
			whitening[1] = Endian::Little ( crc32int ( &iv32[5] ) ^ crc32int ( &iv32[6] ) );
		}
	}

	bool EncryptionModeCBC::IsOuterCBC (const CipherList &ciphers) const
	{
		if (ciphers.size() < 2)
			return false;

		size_t blockSize = ciphers.front()->GetBlockSize();

		for (CipherList::const_iterator iCipherList = ciphers.begin();
			iCipherList != ciphers.end();
			++iCipherList)
		{
			const Cipher &c = **iCipherList;
			if (c.GetBlockSize() != blockSize)
				return false;
		}

		return true;
	}

	void EncryptionModeCBC::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != GetKeySize ())
			throw ParameterIncorrect (SRC_POS);

		if (!KeySet)
			IV.Allocate (GetKeySize ());
		
		IV.CopyFrom (key);
		KeySet = true;
	}
}
