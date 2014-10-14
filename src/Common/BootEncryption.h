/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Common_BootEncryption
#define TC_HEADER_Common_BootEncryption

#include "Tcdefs.h"
#include "Dlgcode.h"
#include "Exception.h"
#include "Platform/PlatformBase.h"
#include "Volumes.h"

using namespace std;

namespace VeraCrypt
{
	class File
	{
	public:
		File () : Elevated (false), FileOpen (false), FilePointerPosition(0), Handle(NULL), IsDevice(false) { }
		File (string path, bool readOnly = false, bool create = false);
		~File () { Close(); }

		void Close ();
		DWORD Read (byte *buffer, DWORD size);
		void Write (byte *buffer, DWORD size);
		void SeekAt (int64 position);

	protected:
		bool Elevated;
		bool FileOpen;
		uint64 FilePointerPosition;
		HANDLE Handle;
		bool IsDevice;
		string Path;
	};


	class Device : public File
	{
	public:
		Device (string path, bool readOnly = false);
	};


	class Buffer
	{
	public:
		Buffer (size_t size) : DataSize (size)
		{
			DataPtr = new byte[size];
			if (!DataPtr)
				throw bad_alloc();
		}

		~Buffer () { delete[] DataPtr; }
		byte *Ptr () const { return DataPtr; }
		size_t Size () const { return DataSize; }

	protected:
		byte *DataPtr;
		size_t DataSize;
	};


	struct Partition
	{
		string DevicePath;
		PARTITION_INFORMATION Info;
		string MountPoint;
		size_t Number;
		BOOL IsGPT;
		wstring VolumeNameId;
	};

	typedef list <Partition> PartitionList;

#pragma pack (push)
#pragma pack(1)

	struct PartitionEntryMBR
	{
		byte BootIndicator;

		byte StartHead;
		byte StartCylSector;
		byte StartCylinder;

		byte Type;

		byte EndHead;
		byte EndSector;
		byte EndCylinder;

		uint32 StartLBA;
		uint32 SectorCountLBA;
	};

	struct MBR
	{
		byte Code[446];
		PartitionEntryMBR Partitions[4];
		uint16 Signature;
	};

#pragma pack (pop)

	struct SystemDriveConfiguration
	{
		string DeviceKernelPath;
		string DevicePath;
		int DriveNumber;
		Partition DrivePartition;
		bool ExtraBootPartitionPresent;
		int64 InitialUnallocatedSpace;
		PartitionList Partitions;
		Partition SystemPartition;
		int64 TotalUnallocatedSpace;
		bool SystemLoaderPresent;
	};

	class BootEncryption
	{
	public:
		BootEncryption (HWND parent);
		~BootEncryption ();

		enum FilterType
		{
			DriveFilter,
			VolumeFilter,
			DumpFilter
		};

		void AbortDecoyOSWipe ();
		void AbortSetup ();
		void AbortSetupWait ();
		void CallDriver (DWORD ioctl, void *input = nullptr, DWORD inputSize = 0, void *output = nullptr, DWORD outputSize = 0);
		int ChangePassword (Password *oldPassword, Password *newPassword, int pkcs5, int wipePassCount);
		void CheckDecoyOSWipeResult ();
		void CheckEncryptionSetupResult ();
		void CheckRequirements ();
		void CheckRequirementsHiddenOS ();
		void CopyFileAdmin (const string &sourceFile, const string &destinationFile);
		void CreateRescueIsoImage (bool initialSetup, const string &isoImagePath);
		void Deinstall (bool displayWaitDialog = false);
		void DeleteFileAdmin (const string &file);
		DecoySystemWipeStatus GetDecoyOSWipeStatus ();
		DWORD GetDriverServiceStartType ();
		unsigned int GetHiddenOSCreationPhase ();
		uint16 GetInstalledBootLoaderVersion ();
		Partition GetPartitionForHiddenOS ();
		bool IsBootLoaderOnDrive (char *devicePath);
		BootEncryptionStatus GetStatus ();
		string GetTempPath ();
		void GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties);
		SystemDriveConfiguration GetSystemDriveConfiguration ();
		void Install (bool hiddenSystem);
		void InstallBootLoader (bool preserveUserConfig = false, bool hiddenOSCreation = false);
		void InvalidateCachedSysDriveProperties ();
		bool IsCDDrivePresent ();
		bool IsHiddenSystemRunning ();
		bool IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
		void PrepareHiddenOSCreation (int ea, int mode, int pkcs5);
		void PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, const string &rescueIsoImagePath);
		void ProbeRealSystemDriveSize ();
		void ReadBootSectorConfig (byte *config, size_t bufLength, byte *userConfig = nullptr, string *customUserMessage = nullptr, uint16 *bootLoaderVersion = nullptr);
		uint32 ReadDriverConfigurationFlags ();
		void RegisterBootDriver (bool hiddenSystem);
		void RegisterFilterDriver (bool registerDriver, FilterType filterType);
		void RegisterSystemFavoritesService (BOOL registerService);
		void RenameDeprecatedSystemLoaderBackup ();
		bool RestartComputer (void);
		void InitialSecurityChecksForHiddenOS ();
		void RestrictPagingFilesToSystemPartition ();
		void SetDriverConfigurationFlag (uint32 flag, bool state);
		void SetDriverServiceStartType (DWORD startType);
		void SetHiddenOSCreationPhase (unsigned int newPhase);
		void StartDecryption (BOOL discardUnreadableEncryptedSectors);
		void StartDecoyOSWipe (WipeAlgorithmId wipeAlgorithm);
		void StartEncryption (WipeAlgorithmId wipeAlgorithm, bool zeroUnreadableSectors);
		bool SystemDriveContainsPartitionType (byte type);
		bool SystemDriveContainsExtendedPartition ();
		bool SystemDriveContainsNonStandardPartitions ();
		bool SystemPartitionCoversWholeDrive ();
		bool SystemDriveIsDynamic ();
		bool VerifyRescueDisk ();
		void WipeHiddenOSCreationConfig ();
		void WriteBootDriveSector (uint64 offset, byte *data);
		void WriteBootSectorConfig (const byte newConfig[]);
		void WriteBootSectorUserConfig (byte userConfig, const string &customUserMessage);
		void WriteLocalMachineRegistryDwordValue (char *keyPath, char *valueName, DWORD value);

	protected:
		static const uint32 RescueIsoImageSize = 1835008; // Size of ISO9660 image with bootable emulated 1.44MB floppy disk image

		void BackupSystemLoader ();
		void CreateBootLoaderInMemory (byte *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation = false);
		void CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5);
		string GetSystemLoaderBackupPath ();
		uint32 GetChecksum (byte *data, size_t size);
		DISK_GEOMETRY GetDriveGeometry (int driveNumber);
		PartitionList GetDrivePartitions (int driveNumber);
		wstring GetRemarksOnHiddenOS ();
		string GetWindowsDirectory ();
		void RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid = nullptr);
		void RestoreSystemLoader ();
		void InstallVolumeHeader ();

		HWND ParentWindow;
		SystemDriveConfiguration DriveConfig;
		int SelectedEncryptionAlgorithmId;
		int SelectedPrfAlgorithmId;
		Partition HiddenOSCandidatePartition;
		byte *RescueIsoImage;
		byte RescueVolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		byte VolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		bool DriveConfigValid;
		bool RealSystemDriveSizeValid;
		bool RescueVolumeHeaderValid;
		bool VolumeHeaderValid;
	};
}

#define TC_ABORT_TRANSFORM_WAIT_INTERVAL	10

#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS	2.1
#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT		1.05

#define TC_SYS_BOOT_LOADER_BACKUP_NAME			"Original System Loader"
#define TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY	"Original System Loader.bak"	// Deprecated to prevent removal by some "cleaners"

#define TC_SYSTEM_FAVORITES_SERVICE_NAME				TC_APP_NAME "SystemFavorites"
#define	TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP	"Event Log"
#define TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION		"/systemFavoritesService"

#endif // TC_HEADER_Common_BootEncryption
