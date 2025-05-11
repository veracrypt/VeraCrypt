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

#ifndef TC_HEADER_Core_CoreException
#define TC_HEADER_Core_CoreException

#include "Platform/Platform.h"

namespace VeraCrypt
{
	struct ElevationFailed : public ExecutedProcessFailed
	{
		ElevationFailed () { }
		ElevationFailed (const string &message, const string &command, int exitCode, const string &errorOutput)
			: ExecutedProcessFailed (message, command, exitCode, errorOutput) { }
		TC_SERIALIZABLE_EXCEPTION (ElevationFailed);
	};

	TC_EXCEPTION_DECL (RootDeviceUnavailable, SystemException);

#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,Exception)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (ElevationFailed); \
	TC_EXCEPTION_NODECL (RootDeviceUnavailable); \
	TC_EXCEPTION (DriveLetterUnavailable); \
	TC_EXCEPTION (DriverError); \
	TC_EXCEPTION (EncryptedSystemRequired); \
	TC_EXCEPTION (HigherFuseVersionRequired); \
	TC_EXCEPTION (KernelCryptoServiceTestFailed); \
	TC_EXCEPTION (LoopDeviceSetupFailed); \
	TC_EXCEPTION (MountPointRequired); \
	TC_EXCEPTION (MountPointUnavailable); \
	TC_EXCEPTION (NoDriveLetterAvailable); \
	TC_EXCEPTION (TemporaryDirectoryFailure); \
	TC_EXCEPTION (UnsupportedSectorSizeHiddenVolumeProtection); \
	TC_EXCEPTION (UnsupportedSectorSizeNoKernelCrypto); \
	TC_EXCEPTION (VolumeAlreadyMounted); \
	TC_EXCEPTION (VolumeSlotUnavailable);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION
}

#endif // TC_HEADER_Core_CoreException
