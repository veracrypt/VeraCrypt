/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "EncryptionModeLRW.h"
#include "Common/GfMul.h"

namespace VeraCrypt
{
	void EncryptionModeLRW::Decrypt (byte *data, uint64 length) const
	{
		if_debug (ValidateState ());
		DecryptBuffer (data, length, 1);
	}

	void EncryptionModeLRW::DecryptBuffer (byte *data, uint64 length, uint64 blockIndex) const
	{
		size_t blockSize = Ciphers.front()->GetBlockSize();
		if (blockSize != 8 && blockSize != 16)
			throw ParameterIncorrect (SRC_POS);

		byte i[8];
		*(uint64 *)i = Endian::Big (blockIndex);

		byte t[Cipher::MaxBlockSize];

		for (unsigned int b = 0; b < length / blockSize; b++)
		{
			if (blockSize == 8)
			{
				Gf64MulTab (i, t, (GfCtx *) (GfContext.Ptr()));
				Xor64 ((uint64 *)data, (uint64 *)t);
			}
			else
			{
				Gf128MulBy64Tab (i, t, (GfCtx *) (GfContext.Ptr()));
				Xor128 ((uint64 *)data, (uint64 *)t);
			}

			for (CipherList::const_reverse_iterator iCipherList = Ciphers.rbegin();
				iCipherList != Ciphers.rend();
				++iCipherList)
			{
				const Cipher &c = **iCipherList;

				if (c.GetBlockSize () != blockSize)
					throw ParameterIncorrect (SRC_POS);

				c.DecryptBlock (data);
			}

			if (blockSize == 8)
				Xor64 ((uint64 *)data, (uint64 *)t);
			else
				Xor128 ((uint64 *)data, (uint64 *)t);

			data += blockSize;
			IncrementBlockIndex (i);
		}

		Memory::Erase (t, sizeof (t));
	}

	void EncryptionModeLRW::DecryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, sectorCount, sectorSize));

		DecryptBuffer (data,
			sectorCount * sectorSize,
			SectorToBlockIndex (sectorIndex));
	}

	void EncryptionModeLRW::Encrypt (byte *data, uint64 length) const
	{
		ValidateState ();
		EncryptBuffer (data, length, 1);
	}

	void EncryptionModeLRW::EncryptBuffer (byte *data, uint64 length, uint64 blockIndex) const
	{
		size_t blockSize = Ciphers.front()->GetBlockSize();
		if (blockSize != 8 && blockSize != 16)
			throw ParameterIncorrect (SRC_POS);

		byte i[8];
		*(uint64 *)i = Endian::Big (blockIndex);

		byte t[Cipher::MaxBlockSize];

		for (unsigned int b = 0; b < length / blockSize; b++)
		{
			if (blockSize == 8)
			{
				Gf64MulTab (i, t, (GfCtx *) (GfContext.Ptr()));
				Xor64 ((uint64 *)data, (uint64 *)t);
			}
			else
			{
				Gf128MulBy64Tab (i, t, (GfCtx *) (GfContext.Ptr()));
				Xor128 ((uint64 *)data, (uint64 *)t);
			}

			for (CipherList::const_iterator iCipherList = Ciphers.begin();
				iCipherList != Ciphers.end();
				++iCipherList)
			{
				const Cipher &c = **iCipherList;

				if (c.GetBlockSize () != blockSize)
					throw ParameterIncorrect (SRC_POS);

				c.EncryptBlock (data);
			}

			if (blockSize == 8)
				Xor64 ((uint64 *)data, (uint64 *)t);
			else
				Xor128 ((uint64 *)data, (uint64 *)t);

			data += blockSize;
			IncrementBlockIndex (i);
		}

		Memory::Erase (t, sizeof (t));
	}

	void EncryptionModeLRW::EncryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState ());
		if_debug (ValidateParameters (data, sectorCount, sectorSize));

		EncryptBuffer (data,
			sectorCount * sectorSize,
			SectorToBlockIndex (sectorIndex));
	}

	void EncryptionModeLRW::IncrementBlockIndex (byte *index) const
	{
		if (index[7] != 0xff)
			index[7]++;
		else
			*(uint64 *)index = Endian::Big ( Endian::Big (*(uint64 *)index) + 1 );
	}

	uint64 EncryptionModeLRW::SectorToBlockIndex (uint64 sectorIndex) const
	{
		sectorIndex -= SectorOffset;

		switch (Ciphers.front()->GetBlockSize())
		{
		case 8:
			return (sectorIndex << 6) | 1;

		case 16:
			return (sectorIndex << 5) | 1;
		
		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void EncryptionModeLRW::SetKey (const ConstBufferPtr &key)
	{
		if (key.Size() != 16)
			throw ParameterIncorrect (SRC_POS);

		if (!KeySet)
			GfContext.Allocate (sizeof (GfCtx));

		if (!Gf64TabInit ((unsigned char *) key.Get(), (GfCtx *) (GfContext.Ptr())))
			throw bad_alloc();

		if (!Gf128Tab64Init ((unsigned char *) key.Get(), (GfCtx *) (GfContext.Ptr())))
			throw bad_alloc();

		Key.CopyFrom (key);
		KeySet = true;
	}

	void EncryptionModeLRW::Xor64 (uint64 *a, const uint64 *b) const
	{
		*a ^= *b;
	}

	void EncryptionModeLRW::Xor128 (uint64 *a, const uint64 *b) const
	{
		*a++ ^= *b++;
		*a ^= *b;
	}
}
