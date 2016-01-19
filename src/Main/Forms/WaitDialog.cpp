/*
 Copyright (c) 2013-2016 IDRIX. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include "Volume/EncryptionModeXTS.h"
#include "Main/GraphicUserInterface.h"
#include "Common/SecurityToken.h"
#include "WaitDialog.h"

namespace VeraCrypt
{
	DEFINE_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED)
	DEFINE_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_ADMIN_PASSWORD)
	DEFINE_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_PIN)
	DEFINE_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_SHOW_MSG)

	wxThread::ExitCode WaitThread::Entry()
	{	
		m_pRoutine->Execute();
		wxQueueEvent (m_pHandler, new wxCommandEvent( wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED,0));
		return (wxThread::ExitCode)0; // success
	}

	void WaitDialog::ThrowException(Exception* ex)
	{
	#define VC_CONVERT_EXCEPTION(NAME) if (dynamic_cast<NAME*> (ex)) throw (NAME&) *ex;
		VC_CONVERT_EXCEPTION (PasswordIncorrect);
		VC_CONVERT_EXCEPTION (PasswordKeyfilesIncorrect);
		VC_CONVERT_EXCEPTION (PasswordOrKeyboardLayoutIncorrect);
		VC_CONVERT_EXCEPTION (PasswordOrMountOptionsIncorrect);
		VC_CONVERT_EXCEPTION (ProtectionPasswordIncorrect);
		VC_CONVERT_EXCEPTION (ProtectionPasswordKeyfilesIncorrect);
		VC_CONVERT_EXCEPTION (PasswordEmpty);
		VC_CONVERT_EXCEPTION (PasswordTooLong);
		VC_CONVERT_EXCEPTION (PasswordUTF8TooLong);
		VC_CONVERT_EXCEPTION (PasswordUTF8Invalid);
		VC_CONVERT_EXCEPTION (UnportablePassword);
		VC_CONVERT_EXCEPTION (ElevationFailed);
		VC_CONVERT_EXCEPTION (RootDeviceUnavailable);
		VC_CONVERT_EXCEPTION (DriveLetterUnavailable);
		VC_CONVERT_EXCEPTION (DriverError);
		VC_CONVERT_EXCEPTION (EncryptedSystemRequired);
		VC_CONVERT_EXCEPTION (HigherFuseVersionRequired);
		VC_CONVERT_EXCEPTION (KernelCryptoServiceTestFailed);
		VC_CONVERT_EXCEPTION (LoopDeviceSetupFailed);
		VC_CONVERT_EXCEPTION (MountPointRequired);
		VC_CONVERT_EXCEPTION (MountPointUnavailable);
		VC_CONVERT_EXCEPTION (NoDriveLetterAvailable);
		VC_CONVERT_EXCEPTION (TemporaryDirectoryFailure);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSizeHiddenVolumeProtection);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSizeNoKernelCrypto);
		VC_CONVERT_EXCEPTION (VolumeAlreadyMounted);
		VC_CONVERT_EXCEPTION (VolumeSlotUnavailable);
		VC_CONVERT_EXCEPTION (UserInterfaceException);
		VC_CONVERT_EXCEPTION (MissingArgument);
		VC_CONVERT_EXCEPTION (NoItemSelected);
		VC_CONVERT_EXCEPTION (StringFormatterException);	
		VC_CONVERT_EXCEPTION (ExecutedProcessFailed);
		VC_CONVERT_EXCEPTION (AlreadyInitialized);
		VC_CONVERT_EXCEPTION (AssertionFailed);
		VC_CONVERT_EXCEPTION (ExternalException);
		VC_CONVERT_EXCEPTION (InsufficientData);
		VC_CONVERT_EXCEPTION (NotApplicable);
		VC_CONVERT_EXCEPTION (NotImplemented);
		VC_CONVERT_EXCEPTION (NotInitialized);
		VC_CONVERT_EXCEPTION (ParameterIncorrect);
		VC_CONVERT_EXCEPTION (ParameterTooLarge);
		VC_CONVERT_EXCEPTION (PartitionDeviceRequired);
		VC_CONVERT_EXCEPTION (StringConversionFailed);
		VC_CONVERT_EXCEPTION (TestFailed);
		VC_CONVERT_EXCEPTION (TimeOut);
		VC_CONVERT_EXCEPTION (UnknownException);
		VC_CONVERT_EXCEPTION (UserAbort)
		VC_CONVERT_EXCEPTION (CipherInitError);
		VC_CONVERT_EXCEPTION (WeakKeyDetected);	
		VC_CONVERT_EXCEPTION (HigherVersionRequired);
		VC_CONVERT_EXCEPTION (KeyfilePathEmpty);
		VC_CONVERT_EXCEPTION (MissingVolumeData);
		VC_CONVERT_EXCEPTION (MountedVolumeInUse);
		VC_CONVERT_EXCEPTION (UnsupportedSectorSize);
		VC_CONVERT_EXCEPTION (VolumeEncryptionNotCompleted);
		VC_CONVERT_EXCEPTION (VolumeHostInUse);
		VC_CONVERT_EXCEPTION (VolumeProtected);
		VC_CONVERT_EXCEPTION (VolumeReadOnly);
		VC_CONVERT_EXCEPTION (Pkcs11Exception);
		VC_CONVERT_EXCEPTION (InvalidSecurityTokenKeyfilePath);
		VC_CONVERT_EXCEPTION (SecurityTokenLibraryNotInitialized);
		VC_CONVERT_EXCEPTION (SecurityTokenKeyfileAlreadyExists);
		VC_CONVERT_EXCEPTION (SecurityTokenKeyfileNotFound);
		VC_CONVERT_EXCEPTION (UnsupportedAlgoInTrueCryptMode);	
		VC_CONVERT_EXCEPTION (UnsupportedTrueCryptFormat);
		VC_CONVERT_EXCEPTION (SystemException);
		VC_CONVERT_EXCEPTION (CipherException);
		VC_CONVERT_EXCEPTION (VolumeException);
		VC_CONVERT_EXCEPTION (PasswordException);
		throw *ex;
	}
}
