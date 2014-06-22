/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_EncryptionMode
#define TC_HEADER_Encryption_EncryptionMode

#include "Platform/Platform.h"
#include "Common/Crypto.h"
#include "Cipher.h"

namespace VeraCrypt
{
	class EncryptionMode;
	typedef list < shared_ptr <EncryptionMode> > EncryptionModeList;

	class EncryptionMode
	{
	public:
		virtual ~EncryptionMode ();

		virtual void Decrypt (byte *data, uint64 length) const = 0;
		virtual void DecryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void DecryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const = 0;
		virtual void Encrypt (byte *data, uint64 length) const = 0;
		virtual void EncryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void EncryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const = 0;
		static EncryptionModeList GetAvailableModes ();
		virtual const SecureBuffer &GetKey () const { throw NotApplicable (SRC_POS); }
		virtual size_t GetKeySize () const = 0;
		virtual wstring GetName () const = 0;
		virtual shared_ptr <EncryptionMode> GetNew () const = 0;
		virtual uint64 GetSectorOffset () const { return SectorOffset; }
		virtual bool IsKeySet () const { return KeySet; }
		virtual void SetKey (const ConstBufferPtr &key) = 0;
		virtual void SetCiphers (const CipherList &ciphers) { Ciphers = ciphers; }
		virtual void SetSectorOffset (int64 offset) { SectorOffset = offset; }

	protected:
		EncryptionMode ();

		virtual void ValidateState () const;
		void ValidateParameters (byte *data, uint64 length) const;
		virtual void ValidateParameters (byte *data, uint64 sectorCount, size_t sectorSize) const;

		static const size_t EncryptionDataUnitSize = ENCRYPTION_DATA_UNIT_SIZE;

		CipherList Ciphers;
		bool KeySet;
		uint64 SectorOffset;

	private:
		EncryptionMode (const EncryptionMode &);
		EncryptionMode &operator= (const EncryptionMode &);
	};
}

#endif // TC_HEADER_Encryption_EncryptionMode
