/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "EncryptionMode.h"
#include "EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "EncryptionModeWolfCryptXTS.h"
#endif
#include "EncryptionThreadPool.h"

namespace VeraCrypt
{
	EncryptionMode::EncryptionMode () : KeySet (false), SectorOffset (0)
	{
	}

	EncryptionMode::~EncryptionMode ()
	{
	}

	void EncryptionMode::DecryptSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptionThreadPool::DoWork (EncryptionThreadPool::WorkType::DecryptDataUnits, this, data, sectorIndex, sectorCount, sectorSize);
	}

	void EncryptionMode::EncryptSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptionThreadPool::DoWork (EncryptionThreadPool::WorkType::EncryptDataUnits, this, data, sectorIndex, sectorCount, sectorSize);
	}

	EncryptionModeList EncryptionMode::GetAvailableModes ()
	{
		EncryptionModeList l;

            #ifdef WOLFCRYPT_BACKEND
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeWolfCryptXTS ()));
            #else
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
            #endif

		return l;
	}

	void EncryptionMode::ValidateState () const
	{
		if (!KeySet || Ciphers.size() < 1)
			throw NotInitialized (SRC_POS);
	}

	void EncryptionMode::ValidateParameters (uint8 *data, uint64 length) const
	{
		if ((Ciphers.size() > 0 && (length % Ciphers.front()->GetBlockSize()) != 0))
			throw ParameterIncorrect (SRC_POS);
	}

	void EncryptionMode::ValidateParameters (uint8 *data, uint64 sectorCount, size_t sectorSize) const
	{
		if (sectorCount == 0 || sectorSize == 0 || (sectorSize % EncryptionDataUnitSize) != 0)
			throw ParameterIncorrect (SRC_POS);
	}
}
