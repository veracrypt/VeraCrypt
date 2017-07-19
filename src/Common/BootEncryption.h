/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Common_BootEncryption
#define TC_HEADER_Common_BootEncryption

#include "Tcdefs.h"
#include "Dlgcode.h"
#include "Exception.h"
#include "Platform/PlatformBase.h"
#include "Volumes.h"
#include <Winternl.h>

#define SYSPARTITIONINFORMATION 0x62

typedef NTSTATUS (WINAPI *NtQuerySystemInformationFn)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
      ULONG                    SystemInformationLength,
		PULONG                   ReturnLength
);

using namespace std;

namespace VeraCrypt
{
	class File
	{
	public:
		File () : Elevated (false), FileOpen (false), ReadOnly (false), FilePointerPosition(0), Handle(INVALID_HANDLE_VALUE), IsDevice(false), LastError(0) { }
		File (wstring path,bool readOnly = false, bool create = false);
		virtual ~File () { Close(); }

		void CheckOpened (const char* srcPos) { if (!FileOpen) { SetLastError (LastError); throw SystemException (srcPos);} }
		void Close ();
		DWORD Read (byte *buffer, DWORD size);
		void Write (byte *buffer, DWORD size);
		void SeekAt (int64 position);
		void GetFileSize (unsigned __int64& size);
		void GetFileSize (DWORD& dwSize);
      bool IoCtl(DWORD code, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize);

	protected:
		bool Elevated;
		bool FileOpen;
		bool ReadOnly;
		uint64 FilePointerPosition;
		HANDLE Handle;
		bool IsDevice;
		wstring Path;
		DWORD LastError;
		BYTE ReadBuffer[4096];
	};


	class Device : public File
	{
	public:
		Device (wstring path,bool readOnly = false);
		virtual ~Device () {}
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
		void Resize (size_t newSize)
		{ 
			if (newSize > DataSize)
			{
				byte *tmp = new byte[newSize];
				if (!tmp)
					throw bad_alloc();
				memcpy (tmp, DataPtr, DataSize);
				delete [] DataPtr;			
				DataPtr = tmp;
			}
			DataSize = newSize;
		}

	protected:
		byte *DataPtr;
		size_t DataSize;
	};


	struct Partition
	{
		wstring DevicePath;
		PARTITION_INFORMATION Info;
		wstring MountPoint;
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
		wstring DeviceKernelPath;
		wstring DevicePath;
		int DriveNumber;
		Partition DrivePartition;
		bool ExtraBootPartitionPresent;
		int64 InitialUnallocatedSpace;
		PartitionList Partitions;
		Partition SystemPartition;
		int64 TotalUnallocatedSpace;
		bool SystemLoaderPresent;
	};

	class EfiBootConf
	{
	public:

		int passwordType;
		string passwordMsg;
		string passwordPicture;
		string hashMsg;
		int hashAlgo;
		int requestHash;
		string pimMsg;
		int pim;
		int requestPim;
		int authorizeVisible;
		int authorizeRetry;
		int bmlLockFlags;
		int bmlDriverEnabled;

		EfiBootConf();

		static BOOL ReadConfigValue (char* configContent, const char *configKey, char *configValue, int maxValueSize);
		static int ReadConfigInteger (char* configContent, const char *configKey, int defaultValue);
		static char *ReadConfigString (char* configContent, const char *configKey, char *defaultValue, char *str, int maxLen);
		static BOOL WriteConfigString (FILE* configFile, char* configContent, const char *configKey, const char *configValue);
		static BOOL WriteConfigInteger (FILE* configFile, char* configContent, const char *configKey, int configValue);
		BOOL Load (const wchar_t* fileName);
		void Load (char* configContent);
		BOOL Save (const wchar_t* fileName, HWND hwnd);
	};

	void GetVolumeESP(wstring& path);
	std::string ReadESPFile (LPCWSTR szFilePath, bool bSkipUTF8BOM);
	void WriteESPFile (LPCWSTR szFilePath, LPBYTE pbData, DWORD dwDataLen, bool bAddUTF8BOM);

	class EfiBoot {
	public:
		EfiBoot();

		void MountBootPartition(WCHAR letter);
		void DismountBootPartition();
		bool IsEfiBoot();

		void DeleteStartExec(uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL);
		void SetStartExec(wstring description, wstring execPath, uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL, uint32 attr = 1);
		void SaveFile(const wchar_t* name, byte* data, DWORD size);
		void GetFileSize(const wchar_t* name, unsigned __int64& size);
		void ReadFile(const wchar_t* name, byte* data, DWORD size);
		void CopyFile(const wchar_t* name, const wchar_t* targetName);

		BOOL RenameFile(const wchar_t* name, wchar_t* nameNew, BOOL bForce);
		BOOL DelFile(const wchar_t* name);
		BOOL MkDir(const wchar_t* name, bool& bAlreadyExists);
		BOOL ReadConfig (const wchar_t* name, EfiBootConf& conf);
		BOOL UpdateConfig (const wchar_t* name, int pim, int hashAlgo, HWND hwndDlg);
		BOOL WriteConfig (const wchar_t* name, bool preserveUserConfig, int pim, int hashAlgo, const char* passPromptMsg, HWND hwndDlg);
		BOOL DelDir(const wchar_t* name);
		void SelectBootVolumeESP();
		void SelectBootVolume(WCHAR* bootVolumePath);
		PSTORAGE_DEVICE_NUMBER GetStorageDeviceNumber () { return &sdn;}

	protected:
		bool m_bMounted;
		WCHAR	EfiBootPartPath[3];
		STORAGE_DEVICE_NUMBER sdn;
		PARTITION_INFORMATION_EX partInfo;
		WCHAR     tempBuf[1024];
		bool  bBootVolumePathSelected;
		WCHAR BootVolumePath[MAX_PATH];
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

		void SetParentWindow (HWND parent) { ParentWindow = parent; }
		void AbortDecoyOSWipe ();
		void AbortSetup ();
		void AbortSetupWait ();
		void CallDriver (DWORD ioctl, void *input = nullptr, DWORD inputSize = 0, void *output = nullptr, DWORD outputSize = 0);
		int ChangePassword (Password *oldPassword, int old_pkcs5, int old_pim, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg);
		void CheckDecoyOSWipeResult ();
		void CheckEncryptionSetupResult ();
		void CheckRequirements ();
		void CheckRequirementsHiddenOS ();
		void CopyFileAdmin (const wstring &sourceFile, const wstring &destinationFile);
		void CreateRescueIsoImage (bool initialSetup, const wstring &isoImagePath);
		void Deinstall (bool displayWaitDialog = false);
		void DeleteFileAdmin (const wstring &file);
		DecoySystemWipeStatus GetDecoyOSWipeStatus ();
		DWORD GetDriverServiceStartType ();
		unsigned int GetHiddenOSCreationPhase ();
		uint16 GetInstalledBootLoaderVersion ();
		void GetInstalledBootLoaderFingerprint (byte fingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE]);
		Partition GetPartitionForHiddenOS ();
		bool IsBootLoaderOnDrive (wchar_t *devicePath);
		BootEncryptionStatus GetStatus ();
		void GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties);
		SystemDriveConfiguration GetSystemDriveConfiguration ();
		void Install (bool hiddenSystem, int hashAlgo);
		void InstallBootLoader (Device& device, bool preserveUserConfig = false, bool hiddenOSCreation = false, int pim = -1, int hashAlg = -1);
		void InstallBootLoader (bool preserveUserConfig = false, bool hiddenOSCreation = false, int pim = -1, int hashAlg = -1);
		bool CheckBootloaderFingerprint (bool bSilent = false);
		void InvalidateCachedSysDriveProperties ();
		bool IsCDRecorderPresent ();
		bool IsHiddenSystemRunning ();
		bool IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
		void PrepareHiddenOSCreation (int ea, int mode, int pkcs5);
		void PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, int pim, const wstring &rescueIsoImagePath);
		void ProbeRealSystemDriveSize ();
		bool ReadBootSectorConfig (byte *config, size_t bufLength, byte *userConfig = nullptr, string *customUserMessage = nullptr, uint16 *bootLoaderVersion = nullptr);
		uint32 ReadDriverConfigurationFlags ();
		void RegisterBootDriver (bool hiddenSystem);
		void RegisterFilterDriver (bool registerDriver, FilterType filterType);
		void RegisterSystemFavoritesService (BOOL registerService);
		void RegisterSystemFavoritesService (BOOL registerService, BOOL noFileHandling);
		void UpdateSystemFavoritesService ();
		void RenameDeprecatedSystemLoaderBackup ();
		bool RestartComputer (BOOL bShutdown = FALSE);
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
		bool VerifyRescueDiskImage (const wchar_t* imageFile);
		void WipeHiddenOSCreationConfig ();
		void WriteBootDriveSector (uint64 offset, byte *data);
		void WriteBootSectorConfig (const byte newConfig[]);
		void WriteBootSectorUserConfig (byte userConfig, const string &customUserMessage, int pim, int hashAlg);
		void WriteEfiBootSectorUserConfig (byte userConfig, const string &customUserMessage, int pim, int hashAlg);
		void WriteLocalMachineRegistryDwordValue (wchar_t *keyPath, wchar_t *valueName, DWORD value);
		void GetEfiBootDeviceNumber (PSTORAGE_DEVICE_NUMBER pSdn);
		void BackupSystemLoader ();
		void RestoreSystemLoader ();

	protected:
		static const uint32 RescueIsoImageSize = 1835008; // Size of ISO9660 image with bootable emulated 1.44MB floppy disk image

		void CreateBootLoaderInMemory (byte *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation = false);
		void CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5, int pim);
		wstring GetSystemLoaderBackupPath ();
		uint32 GetChecksum (byte *data, size_t size);
		DISK_GEOMETRY_EX GetDriveGeometry (int driveNumber);
		PartitionList GetDrivePartitions (int driveNumber);
		wstring GetRemarksOnHiddenOS ();
		wstring GetWindowsDirectory ();
		void RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid = nullptr);		
		void InstallVolumeHeader ();

		HWND ParentWindow;
		SystemDriveConfiguration DriveConfig;
		int SelectedEncryptionAlgorithmId;
		int SelectedPrfAlgorithmId;
		Partition HiddenOSCandidatePartition;
		byte *RescueIsoImage;
		byte *RescueZipData;
		unsigned long RescueZipSize;
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

#define TC_SYS_BOOT_LOADER_BACKUP_NAME			L"Original System Loader"
#define TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY	L"Original System Loader.bak"	// Deprecated to prevent removal by some "cleaners"

#define TC_SYSTEM_FAVORITES_SERVICE_NAME				_T(TC_APP_NAME) L"SystemFavorites"
#define	TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP	L"Event Log"
#define TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION		L"/systemFavoritesService"

#endif // TC_HEADER_Common_BootEncryption
