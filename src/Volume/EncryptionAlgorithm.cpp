/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "EncryptionAlgorithm.h"
#include "EncryptionModeCBC.h"
#include "EncryptionModeLRW.h"
#include "EncryptionModeXTS.h"

namespace TrueCrypt
{
	EncryptionAlgorithm::EncryptionAlgorithm () : Deprecated (false)
	{
	}

	EncryptionAlgorithm::~EncryptionAlgorithm ()
	{
	}

	void EncryptionAlgorithm::Decrypt (byte *data, uint64 length) const
	{
		if_debug (ValidateState ());
		Mode->Decrypt (data, length);
	}

	void EncryptionAlgorithm::Decrypt (const BufferPtr &data) const
	{
		Decrypt (data, data.Size());
	}

	void EncryptionAlgorithm::DecryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState());
		Mode->DecryptSectors (data, sectorIndex, sectorCount, sectorSize);
	}

	void EncryptionAlgorithm::Encrypt (byte *data, uint64 length) const
	{
		if_debug (ValidateState());
		Mode->Encrypt (data, length);
	}

	void EncryptionAlgorithm::Encrypt (const BufferPtr &data) const
	{
		Encrypt (data, data.Size());
	}

	void EncryptionAlgorithm::EncryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		if_debug (ValidateState ());
		Mode->EncryptSectors (data, sectorIndex, sectorCount, sectorSize);
	}

	EncryptionAlgorithmList EncryptionAlgorithm::GetAvailableAlgorithms ()
	{
		EncryptionAlgorithmList l;
		
		l.push_back (shared_ptr <EncryptionAlgorithm> (new AES ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new Serpent ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new Twofish ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new AESTwofish ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new AESTwofishSerpent ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new SerpentAES ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new SerpentTwofishAES ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new TwofishSerpent ()));

		l.push_back (shared_ptr <EncryptionAlgorithm> (new AESBlowfish ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new AESBlowfishSerpent ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new Blowfish ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new Cast5 ()));
		l.push_back (shared_ptr <EncryptionAlgorithm> (new TripleDES ()));
		return l;
	}

	size_t EncryptionAlgorithm::GetLargestKeySize (const EncryptionAlgorithmList &algorithms)
	{
		size_t largestKeySize = 0;

		foreach_ref (const EncryptionAlgorithm &ea, algorithms)
		{
			if (ea.GetKeySize() > largestKeySize)
				largestKeySize = ea.GetKeySize();
		}

		return largestKeySize;
	}

	size_t EncryptionAlgorithm::GetKeySize () const
	{
		if (Ciphers.size() < 1)
			throw NotInitialized (SRC_POS);

		size_t keySize = 0;

		foreach_ref (const Cipher &c, Ciphers)
			keySize += c.GetKeySize();

		return keySize;
	}
	
	size_t EncryptionAlgorithm::GetMaxBlockSize () const
	{
		size_t blockSize = 0;

		foreach_ref (const Cipher &c, Ciphers)
			if (c.GetBlockSize() > blockSize)
				blockSize = c.GetBlockSize();

		return blockSize;
	}

	size_t EncryptionAlgorithm::GetMinBlockSize () const
	{
		size_t blockSize = 0;

		foreach_ref (const Cipher &c, Ciphers)
			if (blockSize == 0 || c.GetBlockSize() < blockSize)
				blockSize = c.GetBlockSize();

		return blockSize;
	}

	shared_ptr <EncryptionMode> EncryptionAlgorithm::GetMode () const
	{
		if (Mode.get() == nullptr)
			throw NotInitialized (SRC_POS);

		return Mode;
	}

	wstring EncryptionAlgorithm::GetName () const
	{
		if (Ciphers.size() < 1)
			throw NotInitialized (SRC_POS);

		wstring name;

		foreach_reverse_ref (const Cipher &c, Ciphers)
		{
			if (name.empty())
				name = c.GetName();
			else
				name += wstring (L"-") + c.GetName();
		}

		return name;
	}

	bool EncryptionAlgorithm::IsModeSupported (const EncryptionMode &mode) const
	{
		bool supported = false;

		foreach_ref (const EncryptionMode &em, SupportedModes)
		{
			if (typeid (mode) == typeid (em))
			{
				supported = true;
				break;
			}
		}

		return supported;
	}

	
	bool EncryptionAlgorithm::IsModeSupported (const shared_ptr <EncryptionMode> mode) const
	{
		return IsModeSupported (*mode);
	}

	void EncryptionAlgorithm::SetMode (shared_ptr <EncryptionMode> mode)
	{
		if (!IsModeSupported (*mode))
			throw ParameterIncorrect (SRC_POS);

		mode->SetCiphers (Ciphers);
		Mode = mode;
	}
	
	void EncryptionAlgorithm::SetKey (const ConstBufferPtr &key)
	{
		if (Ciphers.size() < 1)
			throw NotInitialized (SRC_POS);

		if (GetKeySize() != key.Size())
			throw ParameterIncorrect (SRC_POS);

		size_t keyOffset = 0;
		foreach_ref (Cipher &c, Ciphers)
		{
			c.SetKey (key.GetRange (keyOffset, c.GetKeySize()));
			keyOffset += c.GetKeySize();
		}
	}

	void EncryptionAlgorithm::ValidateState () const
	{
		if (Ciphers.size() < 1 || Mode.get() == nullptr)
			throw NotInitialized (SRC_POS);
	}

	// AES
	AES::AES ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// AES-Blowfish
	AESBlowfish::AESBlowfish ()
	{
		Deprecated = true;

		Ciphers.push_back (shared_ptr <Cipher> (new CipherBlowfish ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// AES-Blowfish-Serpent
	AESBlowfishSerpent::AESBlowfishSerpent ()
	{
		Deprecated = true;

		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherBlowfish ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// AES-Twofish
	AESTwofish::AESTwofish ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// AES-Twofish-Serpent
	AESTwofishSerpent::AESTwofishSerpent ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Blowfish
	Blowfish::Blowfish ()
	{
		Deprecated = true;
		Ciphers.push_back (shared_ptr <Cipher> (new CipherBlowfish()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// CAST5
	Cast5::Cast5 ()
	{
		Deprecated = true;
		Ciphers.push_back (shared_ptr <Cipher> (new CipherCast5()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Serpent
	Serpent::Serpent ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Serpent-AES
	SerpentAES::SerpentAES ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Triple-DES
	TripleDES::TripleDES ()
	{
		Deprecated = true;
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTripleDES()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Twofish
	Twofish::Twofish ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTwofish()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Twofish-Serpent
	TwofishSerpent::TwofishSerpent ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTwofish ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	// Serpent-Twofish-AES
	SerpentTwofishAES::SerpentTwofishAES ()
	{
		Ciphers.push_back (shared_ptr <Cipher> (new CipherAES ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherTwofish ()));
		Ciphers.push_back (shared_ptr <Cipher> (new CipherSerpent ()));

		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}
}
