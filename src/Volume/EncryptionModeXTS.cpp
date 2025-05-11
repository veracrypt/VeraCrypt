/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Crypto/cpu.h"
#include "Crypto/misc.h"
#include "EncryptionModeXTS.h"
#include "Common/Crypto.h"

#if (CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_X64)

#define XorBlocks(result,ptr,len,start,end) \
	while (len >= 2) \
	{ \
		__m128i xmm1 = _mm_loadu_si128((const __m128i*) ptr); \
		__m128i xmm2 = _mm_loadu_si128((__m128i*)result); \
		__m128i xmm3 = _mm_loadu_si128((const __m128i*) (ptr + 2)); \
		__m128i xmm4 = _mm_loadu_si128((__m128i*)(result + 2)); \
		\
		_mm_storeu_si128((__m128i*)result, _mm_xor_si128(xmm1, xmm2)); \
		_mm_storeu_si128((__m128i*)(result + 2), _mm_xor_si128(xmm3, xmm4)); \
		ptr+= 4; \
		result+= 4; \
		len -= 2; \
	} \
	\
	if (len) \
	{ \
		__m128i xmm1 = _mm_loadu_si128((const __m128i*)ptr); \
		__m128i xmm2 = _mm_loadu_si128((__m128i*)result); \
		\
		_mm_storeu_si128((__m128i*)result, _mm_xor_si128(xmm1, xmm2)); \
		ptr+= 2; \
		result+= 2; \
	} \
	len = end - start;

#endif

namespace VeraCrypt
{
	void EncryptionModeXTS::Encrypt (uint8 *data, uint64 length) const
	{
		EncryptBuffer (data, length, 0);
	}

	void EncryptionModeXTS::EncryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const
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

	void EncryptionModeXTS::EncryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
                uint8 finalCarry;
		uint8 whiteningValues [ENCRYPTION_DATA_UNIT_SIZE];
		uint8 whiteningValue [BYTES_PER_XTS_BLOCK];
		uint8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
		uint64 *whiteningValuesPtr64 = (uint64 *) whiteningValues;
		uint64 *whiteningValuePtr64 = (uint64 *) whiteningValue;
		uint64 *bufPtr = (uint64 *) buffer;
		uint64 *dataUnitBufPtr;
		unsigned int startBlock = startCipherBlockNo, endBlock, block, countBlock;
		uint64 remainingBlocks, dataUnitNo;

		startDataUnitNo += SectorOffset;

		/* The encrypted data unit number (i.e. the resultant ciphertext block) is to be multiplied in the
		finite field GF(2^128) by j-th power of n, where j is the sequential plaintext/ciphertext block
		number and n is 2, a primitive element of GF(2^128). This can be (and is) simplified and implemented
		as a left shift of the preceding whitening value by one bit (with carry propagating). In addition, if
		the shift of the highest byte results in a carry, 135 is XORed into the lowest byte. The value 135 is
		derived from the modulus of the Galois Field (x^128+x^7+x^2+x+1). */

		// Convert the 64-bit data unit number into a little-endian 16-byte array.
		// Note that as we are converting a 64-bit number into a 16-byte array we can always zero the last 8 bytes.
		dataUnitNo = startDataUnitNo;
		*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		*((uint64 *) byteBufUnitNo + 1) = 0;

		if (length % BYTES_PER_XTS_BLOCK)
			TC_THROW_FATAL_EXCEPTION;

		remainingBlocks = length / BYTES_PER_XTS_BLOCK;

		// Process all blocks in the buffer
		while (remainingBlocks > 0)
		{
			if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
				endBlock = startBlock + (unsigned int) remainingBlocks;
			else
				endBlock = BLOCKS_PER_XTS_DATA_UNIT;
			countBlock = endBlock - startBlock;

			whiteningValuesPtr64 = (uint64 *) whiteningValues;
			whiteningValuePtr64 = (uint64 *) whiteningValue;

			// Encrypt the data unit number using the secondary key (in order to generate the first
			// whitening value for this data unit)
			*whiteningValuePtr64 = *((uint64 *) byteBufUnitNo);
			*(whiteningValuePtr64 + 1) = 0;
			secondaryCipher.EncryptBlock (whiteningValue);

			// Generate subsequent whitening values for blocks in this data unit. Note that all generated 128-bit
			// whitening values are stored in memory as a sequence of 64-bit integers.
			for (block = 0; block < endBlock; block++)
			{
				if (block >= startBlock)
				{
					*whiteningValuesPtr64++ = *whiteningValuePtr64++;
					*whiteningValuesPtr64++ = *whiteningValuePtr64;
				}
				else
					whiteningValuePtr64++;

				// Derive the next whitening value

#if BYTE_ORDER == LITTLE_ENDIAN

				// Little-endian platforms

				finalCarry =
					(*whiteningValuePtr64 & 0x8000000000000000ULL) ?
					135 : 0;

				*whiteningValuePtr64-- <<= 1;

				if (*whiteningValuePtr64 & 0x8000000000000000ULL)
					*(whiteningValuePtr64 + 1) |= 1;

				*whiteningValuePtr64 <<= 1;
#else

				// Big-endian platforms

				finalCarry =
					(*whiteningValuePtr64 & 0x80) ?
					135 : 0;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);

				whiteningValuePtr64--;

				if (*whiteningValuePtr64 & 0x80)
					*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
#endif

				whiteningValue[0] ^= finalCarry;
			}

			dataUnitBufPtr = bufPtr;
			whiteningValuesPtr64 = (uint64 *) whiteningValues;

			// Encrypt all blocks in this data unit
#if (CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_X64)
			XorBlocks (bufPtr, whiteningValuesPtr64, countBlock, startBlock, endBlock);
#else
			for (block = 0; block < countBlock; block++)
			{
				// Pre-whitening
				*bufPtr++ ^= *whiteningValuesPtr64++;
				*bufPtr++ ^= *whiteningValuesPtr64++;
			}
#endif
			// Actual encryption
			cipher.EncryptBlocks ((uint8 *) dataUnitBufPtr, countBlock);

			bufPtr = dataUnitBufPtr;
			whiteningValuesPtr64 = (uint64 *) whiteningValues;

#if (CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_X64)
			XorBlocks (bufPtr, whiteningValuesPtr64, countBlock, startBlock, endBlock);
#else
			for (block = 0; block < countBlock; block++)
			{
				// Post-whitening
				*bufPtr++ ^= *whiteningValuesPtr64++;
				*bufPtr++ ^= *whiteningValuesPtr64++;
			}
#endif
			remainingBlocks -= countBlock;
			startBlock = 0;
			dataUnitNo++;
			*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		}

		FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
		FAST_ERASE64 (whiteningValues, sizeof (whiteningValues));
	}

	void EncryptionModeXTS::EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}

	size_t EncryptionModeXTS::GetKeySize () const
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

	void EncryptionModeXTS::Decrypt (uint8 *data, uint64 length) const
	{
		DecryptBuffer (data, length, 0);
	}

	void EncryptionModeXTS::DecryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const
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

	void EncryptionModeXTS::DecryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const
	{
		uint8 finalCarry;
		uint8 whiteningValues [ENCRYPTION_DATA_UNIT_SIZE];
		uint8 whiteningValue [BYTES_PER_XTS_BLOCK];
		uint8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
		uint64 *whiteningValuesPtr64 = (uint64 *) whiteningValues;
		uint64 *whiteningValuePtr64 = (uint64 *) whiteningValue;
		uint64 *bufPtr = (uint64 *) buffer;
		uint64 *dataUnitBufPtr;
		unsigned int startBlock = startCipherBlockNo, endBlock, block, countBlock;
		uint64 remainingBlocks, dataUnitNo;

		startDataUnitNo += SectorOffset;

		// Convert the 64-bit data unit number into a little-endian 16-byte array.
		// Note that as we are converting a 64-bit number into a 16-byte array we can always zero the last 8 bytes.
		dataUnitNo = startDataUnitNo;
		*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		*((uint64 *) byteBufUnitNo + 1) = 0;

		if (length % BYTES_PER_XTS_BLOCK)
			TC_THROW_FATAL_EXCEPTION;

		remainingBlocks = length / BYTES_PER_XTS_BLOCK;

		// Process all blocks in the buffer
		while (remainingBlocks > 0)
		{
			if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
				endBlock = startBlock + (unsigned int) remainingBlocks;
			else
				endBlock = BLOCKS_PER_XTS_DATA_UNIT;
			countBlock = endBlock - startBlock;

			whiteningValuesPtr64 = (uint64 *) whiteningValues;
			whiteningValuePtr64 = (uint64 *) whiteningValue;

			// Encrypt the data unit number using the secondary key (in order to generate the first
			// whitening value for this data unit)
			*whiteningValuePtr64 = *((uint64 *) byteBufUnitNo);
			*(whiteningValuePtr64 + 1) = 0;
			secondaryCipher.EncryptBlock (whiteningValue);

			// Generate subsequent whitening values for blocks in this data unit. Note that all generated 128-bit
			// whitening values are stored in memory as a sequence of 64-bit integers.
			for (block = 0; block < endBlock; block++)
			{
				if (block >= startBlock)
				{
					*whiteningValuesPtr64++ = *whiteningValuePtr64++;
					*whiteningValuesPtr64++ = *whiteningValuePtr64;
				}
				else
					whiteningValuePtr64++;

				// Derive the next whitening value

#if BYTE_ORDER == LITTLE_ENDIAN

				// Little-endian platforms

				finalCarry =
					(*whiteningValuePtr64 & 0x8000000000000000ULL) ?
					135 : 0;

				*whiteningValuePtr64-- <<= 1;

				if (*whiteningValuePtr64 & 0x8000000000000000ULL)
					*(whiteningValuePtr64 + 1) |= 1;

				*whiteningValuePtr64 <<= 1;

#else
				// Big-endian platforms

				finalCarry =
					(*whiteningValuePtr64 & 0x80) ?
					135 : 0;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);

				whiteningValuePtr64--;

				if (*whiteningValuePtr64 & 0x80)
					*(whiteningValuePtr64 + 1) |= 0x0100000000000000ULL;

				*whiteningValuePtr64 = Endian::Little (Endian::Little (*whiteningValuePtr64) << 1);
#endif

				whiteningValue[0] ^= finalCarry;
			}

			dataUnitBufPtr = bufPtr;
			whiteningValuesPtr64 = (uint64 *) whiteningValues;

			// Decrypt blocks in this data unit
#if (CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_X64)
			XorBlocks (bufPtr, whiteningValuesPtr64, countBlock, startBlock, endBlock);
#else
			for (block = 0; block < countBlock; block++)
			{
				*bufPtr++ ^= *whiteningValuesPtr64++;
				*bufPtr++ ^= *whiteningValuesPtr64++;
			}
#endif
			cipher.DecryptBlocks ((uint8 *) dataUnitBufPtr, countBlock);

			bufPtr = dataUnitBufPtr;
			whiteningValuesPtr64 = (uint64 *) whiteningValues;
#if (CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && CRYPTOPP_BOOL_X64)
			XorBlocks (bufPtr, whiteningValuesPtr64, countBlock, startBlock, endBlock);
#else
			for (block = 0; block < countBlock; block++)
			{
				*bufPtr++ ^= *whiteningValuesPtr64++;
				*bufPtr++ ^= *whiteningValuesPtr64++;
			}
#endif
			remainingBlocks -= countBlock;
			startBlock = 0;
			dataUnitNo++;

			*((uint64 *) byteBufUnitNo) = Endian::Little (dataUnitNo);
		}

		FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
		FAST_ERASE64 (whiteningValues, sizeof (whiteningValues));
        }

	void EncryptionModeXTS::DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		DecryptBuffer (data, sectorCount * sectorSize, sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE);
	}

	void EncryptionModeXTS::SetCiphers (const CipherList &ciphers)
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

	void EncryptionModeXTS::SetKey (const ConstBufferPtr &key)
	{
		SecondaryKey.Allocate (key.Size());
		SecondaryKey.CopyFrom (key);

		if (!SecondaryCiphers.empty())
			SetSecondaryCipherKeys();
	}

	void EncryptionModeXTS::SetSecondaryCipherKeys ()
	{
		size_t keyOffset = 0;
		foreach_ref (Cipher &cipher, SecondaryCiphers)
		{
			cipher.SetKey (SecondaryKey.GetRange (keyOffset, cipher.GetKeySize()));
                        keyOffset += cipher.GetKeySize();
		}

		KeySet = true;
	}
}
