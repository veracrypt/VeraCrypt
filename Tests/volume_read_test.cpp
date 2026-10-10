// Decrypt the data area of a volume through the volume layer, without
// mounting. Usage: volume_read_test VOLUME PASSWORD KDF OUTPUT
//
// The volume is opened read-only with PIM 0 and the given KDF (as with
// --hash). CPU features are detected as in the application, so the
// accelerated cipher code is used where available. The data area is read in
// one call, again in one call with the encryption thread pool running, and
// one sector at a time; all three must match. The plaintext is written to
// OUTPUT, where Tests/test_volume_read.py checks it.
#include "Platform/Platform.h"
#include "Platform/Finally.h"
#include "Volume/EncryptionThreadPool.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/Volume.h"
#include "Crypto/cpu.h"
#include <cstring>
#include <fstream>
#include <iostream>

using namespace VeraCrypt;

// Same matching as --hash on the command line: the KDF name, the hash name
// or its alternative name, or "argon2"/"argon2id".
static shared_ptr <Pkcs5Kdf> FindKdf (const string &name)
{
	string lowerName = StringConverter::ToLower (name);
	foreach (shared_ptr <Pkcs5Kdf> kdf, Pkcs5Kdf::GetAvailableAlgorithms())
	{
		if (StringConverter::ToLower (StringConverter::ToSingle (kdf->GetName())) == lowerName)
			return kdf;
		if (kdf->IsArgon2())
		{
			if (lowerName == "argon2" || lowerName == "argon2id")
				return kdf;
			continue;
		}
		if (StringConverter::ToLower (StringConverter::ToSingle (kdf->GetHash()->GetName())) == lowerName
			|| StringConverter::ToLower (StringConverter::ToSingle (kdf->GetHash()->GetAltName())) == lowerName)
			return kdf;
	}
	throw ParameterIncorrect (SRC_POS);
}

static void Require (bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error (message);
}

int main (int argc, char **argv)
{
	if (argc != 5)
	{
		std::cerr << "usage: volume_read_test VOLUME PASSWORD KDF OUTPUT\n";
		return 2;
	}

	try
	{
#ifdef CRYPTOPP_CPUID_AVAILABLE
		DetectX86Features ();
#endif
#if CRYPTOPP_BOOL_ARMV8
		DetectArmFeatures ();
#endif
		shared_ptr <VolumePassword> password (new VolumePassword ((const uint8 *) argv[2], strlen (argv[2])));
		Volume volume;
		volume.Open (VolumePath (string (argv[1])), false, password, 0, FindKdf (argv[3]),
			shared_ptr <KeyfileList> (), false, VolumeProtection::ReadOnly);

		const uint64 size = volume.GetSize();
		const size_t sectorSize = volume.GetSectorSize();
		Require (size != 0 && size % sectorSize == 0, "unexpected data area size");

		SecureBuffer data ((size_t) size);
		volume.ReadSectors (data, 0);

		EncryptionThreadPool::Start();
		finally_do ({ EncryptionThreadPool::Stop(); });

		SecureBuffer threaded ((size_t) size);
		volume.ReadSectors (threaded, 0);
		Require (memcmp (threaded.Ptr(), data.Ptr(), (size_t) size) == 0, "read with the thread pool differs");

		SecureBuffer sector (sectorSize);
		for (uint64 offset = 0; offset < size; offset += sectorSize)
		{
			volume.ReadSectors (sector, offset);
			Require (memcmp (sector.Ptr(), data.Ptr() + offset, sectorSize) == 0, "read one sector at a time differs");
		}

		std::ofstream output (argv[4], std::ios::binary);
		output.write ((const char *) data.Ptr(), (std::streamsize) data.Size());
		output.close();
		Require (!output.fail(), "cannot write the output file");

		std::cout << StringConverter::ToSingle (volume.GetEncryptionAlgorithm()->GetName())
			<< " " << size << " bytes\n";
		volume.Close();
	}
	catch (std::exception &e)
	{
		std::cerr << "error: " << StringConverter::ToSingle (StringConverter::ToExceptionString (e)) << "\n";
		return 1;
	}
	catch (...)
	{
		std::cerr << "error: unknown exception\n";
		return 1;
	}
	return 0;
}
