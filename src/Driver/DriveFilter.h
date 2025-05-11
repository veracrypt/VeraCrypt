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

#ifndef TC_HEADER_DRIVER_DRIVE_FILTER
#define TC_HEADER_DRIVER_DRIVE_FILTER

#include "TCdefs.h"
#include "Boot/Windows/BootCommon.h"
#include "EncryptedIoQueue.h"

typedef struct _DriveFilterExtension
{
	BOOL bRootDevice;
	BOOL IsVolumeDevice;
	BOOL IsDriveFilterDevice;
	BOOL IsVolumeFilterDevice;
	uint64 MagicNumber;

	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT LowerDeviceObject;
	PDEVICE_OBJECT Pdo;

	ULONG SystemStorageDeviceNumber;
	BOOL SystemStorageDeviceNumberValid;

	int64 ConfiguredEncryptedAreaStart;
	int64 ConfiguredEncryptedAreaEnd;

	uint32 VolumeHeaderSaltCrc32;
	EncryptedIoQueue Queue;

	BOOL BootDrive;
	BOOL VolumeHeaderPresent;
	BOOL DriveMounted;

	KEVENT MountWorkItemCompletedEvent;

	CRYPTO_INFO *HeaderCryptoInfo;
	BOOL HiddenSystem;

} DriveFilterExtension;

extern BOOL BootArgsValid;
extern BootArguments BootArgs;
extern PKTHREAD EncryptionSetupThread;
extern PKTHREAD DecoySystemWipeThread;

NTSTATUS AbortBootEncryptionSetup ();
NTSTATUS DriveFilterAddDevice (PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo);
NTSTATUS DriveFilterDispatchIrp (PDEVICE_OBJECT DeviceObject, PIRP Irp);
void GetBootDriveVolumeProperties (PIRP irp);
void GetBootEncryptionAlgorithmName (PIRP irp);
void GetBootEncryptionStatus (PIRP irp);
void GetBootLoaderVersion (PIRP irp);
void GetBootLoaderFingerprint (PIRP irp);
NTSTATUS GetSetupResult ();
DriveFilterExtension *GetBootDriveFilterExtension ();
CRYPTO_INFO *GetSystemDriveCryptoInfo ();
BOOL IsBootDriveMounted ();
BOOL IsBootEncryptionSetupInProgress ();
BOOL IsHiddenSystemRunning ();
NTSTATUS LoadBootArguments (BOOL bIsEfi);
static NTSTATUS SaveDriveVolumeHeader (DriveFilterExtension *Extension);
NTSTATUS StartBootEncryptionSetup (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp);
void EmergencyClearAllKeys (PIRP irp);
void ReopenBootVolumeHeader (PIRP irp);
NTSTATUS StartDecoySystemWipe (PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp);
NTSTATUS AbortDecoySystemWipe ();
BOOL IsDecoySystemWipeInProgress();
NTSTATUS GetDecoySystemWipeResult();
void GetDecoySystemWipeStatus (PIRP irp);
uint64 GetBootDriveLength ();
NTSTATUS WriteBootDriveSector (PIRP irp, PIO_STACK_LOCATION irpSp);

#define TC_ENCRYPTION_SETUP_IO_BLOCK_SIZE (1536 * 1024)
#define TC_ENCRYPTION_SETUP_HEADER_UPDATE_THRESHOLD (64 * 1024 * 1024)
#define TC_HIBERNATION_WRITE_BUFFER_SIZE (128 * 1024)

#endif // TC_HEADER_DRIVER_DRIVE_FILTER
