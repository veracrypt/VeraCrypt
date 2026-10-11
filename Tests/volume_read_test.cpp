// Decrypt the data area of a volume through the volume layer, without
// mounting. Usage:
//   volume_read_test VOLUME PASSWORD KDF OUTPUT [--require-thread-pool]
//
// The volume is opened read-only with PIM 0 and the given KDF (as with
// --hash). CPU features are detected as in the application, so the
// accelerated cipher code is used where available. The data area is read in
// one call, then as ranges of several sectors at nonzero offsets (odd sector
// counts, so the work is split unevenly), again with the encryption thread
// pool running, and one sector at a time; every read must match the first.
// The pool does not start with fewer than two processors: that part is then
// reported as skipped, or fails with --require-thread-pool. The plaintext is
// written to OUTPUT, where Tests/test_volume_read.py checks it.
#include "Platform/Platform.h"
#include "Platform/Finally.h"
#include "Volume/EncryptionThreadPool.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/Volume.h"
#include "Crypto/cpu.h"
#include <clocale>
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

// Read several multi-sector ranges at nonzero offsets and compare them with
// the data area read in one call.
static void CheckRanges (Volume &volume, const SecureBuffer &data, const char *message)
{
	const size_t sectorSize = volume.GetSectorSize();
	const uint64 sectors = data.Size() / sectorSize;
	Require (sectors >= 34, "data area too small for the range checks");
	const uint64 ranges[][2] = {
		{ 1, 3 }, { 7, 5 }, { sectors / 2 - 4, 9 }, { sectors - 17, 17 }
	};

	for (size_t i = 0; i < sizeof (ranges) / sizeof (ranges[0]); i++)
	{
		const uint64 offset = ranges[i][0] * sectorSize;
		const size_t length = (size_t) (ranges[i][1] * sectorSize);
		Require (ranges[i][0] > 0 && ranges[i][0] + ranges[i][1] <= sectors, "data area too small for the range checks");

		SecureBuffer buffer (length);
		volume.ReadSectors (buffer, offset);
		Require (memcmp (buffer.Ptr(), data.Ptr() + offset, length) == 0, message);
	}
}

int main (int argc, char **argv)
{
	const bool requireThreadPool = (argc == 6 && strcmp (argv[5], "--require-thread-pool") == 0);
	if (argc != 5 && !requireThreadPool)
	{
		std::cerr << "usage: volume_read_test VOLUME PASSWORD KDF OUTPUT [--require-thread-pool]\n";
		return 2;
	}

	// The volume path is converted to a wide string with mbsrtowcs, which
	// needs the character set of the environment (e.g. for "répertoire").
	// Without it (e.g. the locale is not installed) only ASCII paths work.
	const bool localeSet = setlocale (LC_CTYPE, "") != nullptr;

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
		CheckRanges (volume, data, "read of several sectors differs");

		EncryptionThreadPool::Start();
		finally_do ({ EncryptionThreadPool::Stop(); });

		const bool threaded = EncryptionThreadPool::IsRunning();
		if (threaded)
		{
			SecureBuffer all ((size_t) size);
			volume.ReadSectors (all, 0);
			Require (memcmp (all.Ptr(), data.Ptr(), (size_t) size) == 0, "read with the thread pool differs");
			CheckRanges (volume, data, "read of several sectors with the thread pool differs");
		}
		else
			Require (!requireThreadPool, "the encryption thread pool did not start (fewer than two processors?)");

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
			<< " " << size << " bytes" << (threaded ? "" : ", thread pool reads skipped (pool not started)")
			<< (localeSet ? "" : ", locale from the environment unavailable, using C") << "\n";
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
