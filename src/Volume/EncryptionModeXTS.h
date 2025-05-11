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

#ifndef TC_HEADER_Volume_EncryptionModeXTS
#define TC_HEADER_Volume_EncryptionModeXTS

#include "Platform/Platform.h"
#include "EncryptionMode.h"

namespace VeraCrypt
{
	class EncryptionModeXTS : public EncryptionMode
	{
	public:
		EncryptionModeXTS () { }
		virtual ~EncryptionModeXTS () { }

		virtual void Decrypt (uint8 *data, uint64 length) const;
		virtual void DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void Encrypt (uint8 *data, uint64 length) const;
		virtual void EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual const SecureBuffer &GetKey () const { return SecondaryKey; }
		virtual size_t GetKeySize () const;
		virtual wstring GetName () const { return L"XTS"; };
		virtual shared_ptr <EncryptionMode> GetNew () const { return shared_ptr <EncryptionMode> (new EncryptionModeXTS); }
		virtual void SetCiphers (const CipherList &ciphers);
		virtual void SetKey (const ConstBufferPtr &key);

	protected:
		void DecryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const;
		void DecryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const;
		void EncryptBuffer (uint8 *data, uint64 length, uint64 startDataUnitNo) const;
		void EncryptBufferXTS (const Cipher &cipher, const Cipher &secondaryCipher, uint8 *buffer, uint64 length, uint64 startDataUnitNo, unsigned int startCipherBlockNo) const;
		void SetSecondaryCipherKeys ();

		SecureBuffer SecondaryKey;
		CipherList SecondaryCiphers;

	private:
		EncryptionModeXTS (const EncryptionModeXTS &);
		EncryptionModeXTS &operator= (const EncryptionModeXTS &);
	};
}

#endif // TC_HEADER_Volume_EncryptionModeXTS
