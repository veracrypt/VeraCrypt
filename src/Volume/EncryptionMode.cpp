/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "EncryptionMode.h"
#include "EncryptionModeCBC.h"
#include "EncryptionModeLRW.h"
#include "EncryptionModeXTS.h"
#include "EncryptionThreadPool.h"

namespace TrueCrypt
{
	EncryptionMode::EncryptionMode () : KeySet (false), SectorOffset (0)
	{
	}

	EncryptionMode::~EncryptionMode ()
	{
	}

	void EncryptionMode::DecryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptionThreadPool::DoWork (EncryptionThreadPool::WorkType::DecryptDataUnits, this, data, sectorIndex, sectorCount, sectorSize);
	}

	void EncryptionMode::EncryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptionThreadPool::DoWork (EncryptionThreadPool::WorkType::EncryptDataUnits, this, data, sectorIndex, sectorCount, sectorSize);
	}

	EncryptionModeList EncryptionMode::GetAvailableModes ()
	{
		EncryptionModeList l;

		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));

		return l;
	}

	void EncryptionMode::ValidateState () const
	{
		if (!KeySet || Ciphers.size() < 1)
			throw NotInitialized (SRC_POS);
	}

	void EncryptionMode::ValidateParameters (byte *data, uint64 length) const
	{
		if ((Ciphers.size() > 0 && (length % Ciphers.front()->GetBlockSize()) != 0))
			throw ParameterIncorrect (SRC_POS);
	}

	void EncryptionMode::ValidateParameters (byte *data, uint64 sectorCount, size_t sectorSize) const
	{
		if (sectorCount == 0 || sectorSize == 0 || (sectorSize % EncryptionDataUnitSize) != 0)
			throw ParameterIncorrect (SRC_POS);
	}
}
