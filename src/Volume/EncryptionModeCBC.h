/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_EncryptionModeCBC
#define TC_HEADER_Encryption_EncryptionModeCBC

#include "Platform/Platform.h"
#include "EncryptionMode.h"

namespace TrueCrypt
{
	class EncryptionModeCBC : public EncryptionMode
	{
	public:
		EncryptionModeCBC () { }
		virtual ~EncryptionModeCBC () { }

		virtual void Decrypt (byte *data, uint64 length) const;
		virtual void DecryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void Encrypt (byte *data, uint64 length) const;
		virtual void EncryptSectorsCurrentThread (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual size_t GetKeySize () const { return 32; };
		virtual wstring GetName () const { return L"CBC"; };
		virtual shared_ptr <EncryptionMode> GetNew () const { return shared_ptr <EncryptionMode> (new EncryptionModeCBC); }
		virtual void SetKey (const ConstBufferPtr &key);

	protected:
		void DecryptBuffer (byte *data, uint64 length, const CipherList &ciphers, const uint32 *iv, const uint32 *whitening) const;
		void EncryptBuffer (byte *data, uint64 length, const CipherList &ciphers, const uint32 *iv, const uint32 *whitening) const;
		void InitSectorIVAndWhitening (uint64 sectorIndex, size_t blockSize, const uint64 *ivSeed, uint32 *iv, uint32 *whitening) const;
		bool IsOuterCBC (const CipherList &ciphers) const;

		SecureBuffer IV;
		static const int WhiteningIVOffset = 8;

	private:
		EncryptionModeCBC (const EncryptionModeCBC &);
		EncryptionModeCBC &operator= (const EncryptionModeCBC &);
	};
}

#endif // TC_HEADER_Encryption_EncryptionModeCBC
