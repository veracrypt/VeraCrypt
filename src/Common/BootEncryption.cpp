/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Tcdefs.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <Setupapi.h>
#include <devguid.h>
#include <io.h>
#include <shlobj.h>
#include <atlbase.h>
#include "BootEncryption.h"
#include "Boot/Windows/BootCommon.h"
#include "Common/Resource.h"
#include "Crc.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Endian.h"
#include "Language.h"
#include "Random.h"
#include "Registry.h"
#include "Volumes.h"

#ifdef VOLFORMAT
#include "Format/FormatCom.h"
#elif defined (TCMOUNT)
#include "Mount/MainCom.h"
#endif

namespace VeraCrypt
{
#if !defined (SETUP)

	class Elevator
	{
	public:
		
		static void AddReference ()
		{
			++ReferenceCount;
		}


		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
		{
			Elevate();

			CComBSTR inputBstr;
			if (input && inputBstr.AppendBytes ((const char *) input, inputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			CComBSTR outputBstr;
			if (output && outputBstr.AppendBytes ((const char *) output, outputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			DWORD result = ElevatedComInstance->CallDriver (ioctl, inputBstr, &outputBstr);

			if (output)
				memcpy (output, *(void **) &outputBstr, outputSize);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void CopyFile (const string &sourceFile, const string &destinationFile)
		{
			Elevate();

			DWORD result = ElevatedComInstance->CopyFile (CComBSTR (sourceFile.c_str()), CComBSTR (destinationFile.c_str()));

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void DeleteFile (const string &file)
		{
			Elevate();

			DWORD result = ElevatedComInstance->DeleteFile (CComBSTR (file.c_str()));

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void ReadWriteFile (BOOL write, BOOL device, const string &filePath, byte *buffer, uint64 offset, uint32 size, DWORD *sizeDone)
		{
			Elevate();

			CComBSTR bufferBstr;
			if (bufferBstr.AppendBytes ((const char *) buffer, size) != S_OK)
				throw ParameterIncorrect (SRC_POS);
			DWORD result = ElevatedComInstance->ReadWriteFile (write, device, CComBSTR (filePath.c_str()), &bufferBstr, offset, size, sizeDone);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}

			if (!write)
				memcpy (buffer, (BYTE *) bufferBstr.m_str, size);
		}

		static BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
		{
			Elevate();

			return ElevatedComInstance->IsPagingFileActive (checkNonWindowsPartitionsOnly);
		}

		static void WriteLocalMachineRegistryDwordValue (char *keyPath, char *valueName, DWORD value)
		{
			Elevate();

			DWORD result = ElevatedComInstance->WriteLocalMachineRegistryDwordValue (CComBSTR (keyPath), CComBSTR (valueName), value);
		
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void RegisterFilterDriver (bool registerDriver, BootEncryption::FilterType filterType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterFilterDriver (registerDriver ? TRUE : FALSE, filterType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void RegisterSystemFavoritesService (BOOL registerService)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterSystemFavoritesService (registerService);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void Release ()
		{
			if (--ReferenceCount == 0 && ElevatedComInstance)
			{
				ElevatedComInstance->Release();
				ElevatedComInstance = nullptr;
				CoUninitialize ();
			}
		}

		static void SetDriverServiceStartType (DWORD startType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->SetDriverServiceStartType (startType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

	protected:
		static void Elevate ()
		{
			if (IsAdmin())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException();
			}

			if (!ElevatedComInstance || ElevatedComInstanceThreadId != GetCurrentThreadId())
			{
				CoInitialize (NULL);
				ElevatedComInstance = GetElevatedInstance (GetActiveWindow() ? GetActiveWindow() : MainDlg);
				ElevatedComInstanceThreadId = GetCurrentThreadId();
			}
		}
		
#if defined (TCMOUNT)
		static ITrueCryptMainCom *ElevatedComInstance;
#elif defined (VOLFORMAT)
		static ITrueCryptFormatCom *ElevatedComInstance;
#endif
		static DWORD ElevatedComInstanceThreadId;
		static int ReferenceCount;
	};

#if defined (TCMOUNT)
	ITrueCryptMainCom *Elevator::ElevatedComInstance;
#elif defined (VOLFORMAT)
	ITrueCryptFormatCom *Elevator::ElevatedComInstance;
#endif
	DWORD Elevator::ElevatedComInstanceThreadId;
	int Elevator::ReferenceCount = 0;

#else // SETUP
	
	class Elevator
	{
	public:
		static void AddReference () { }
		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize) { throw ParameterIncorrect (SRC_POS); }
		static void ReadWriteFile (BOOL write, BOOL device, const string &filePath, byte *buffer, uint64 offset, uint32 size, DWORD *sizeDone) { throw ParameterIncorrect (SRC_POS); }
		static void RegisterFilterDriver (bool registerDriver, BootEncryption::FilterType filterType) { throw ParameterIncorrect (SRC_POS); }
		static void Release () { }
		static void SetDriverServiceStartType (DWORD startType) { throw ParameterIncorrect (SRC_POS); }
	};

#endif // SETUP


	File::File (string path, bool readOnly, bool create) : Elevated (false), FileOpen (false)
	{
		Handle = CreateFile (path.c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		try
		{
			throw_sys_if (Handle == INVALID_HANDLE_VALUE);
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevated = true;
			else
				throw;
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = false;
		Path = path;
	}

	void File::Close ()
	{
		if (FileOpen)
		{
			if (!Elevated)
				CloseHandle (Handle);

			FileOpen = false;
		}
	}

	DWORD File::Read (byte *buffer, DWORD size)
	{
		DWORD bytesRead;

		if (Elevated)
		{
			DWORD bytesRead;

			Elevator::ReadWriteFile (false, IsDevice, Path, buffer, FilePointerPosition, size, &bytesRead);
			FilePointerPosition += bytesRead;
			return bytesRead;
		}

		throw_sys_if (!ReadFile (Handle, buffer, size, &bytesRead, NULL));
		return bytesRead;
	}

	void File::SeekAt (int64 position)
	{
		FilePointerPosition = position;

		if (!Elevated)
		{
			LARGE_INTEGER pos;
			pos.QuadPart = position;
			throw_sys_if (!SetFilePointerEx (Handle, pos, NULL, FILE_BEGIN));
		}
	}

	void File::Write (byte *buffer, DWORD size)
	{
		DWORD bytesWritten;

		try
		{
			if (Elevated)
			{
				Elevator::ReadWriteFile (true, IsDevice, Path, buffer, FilePointerPosition, size, &bytesWritten);
				FilePointerPosition += bytesWritten;
				throw_sys_if (bytesWritten != size);
			}
			else
			{
				throw_sys_if (!WriteFile (Handle, buffer, size, &bytesWritten, NULL) || bytesWritten != size);
			}
		}
		catch (SystemException &e)
		{
			if (!IsDevice || e.ErrorCode != ERROR_WRITE_PROTECT)
				throw;

			BootEncryption bootEnc (NULL);

			while (size >= TC_SECTOR_SIZE_BIOS)
			{
				bootEnc.WriteBootDriveSector (FilePointerPosition, buffer);

				FilePointerPosition += TC_SECTOR_SIZE_BIOS;
				buffer += TC_SECTOR_SIZE_BIOS;
				size -= TC_SECTOR_SIZE_BIOS;
			}
		}
	}

	void Show (HWND parent, const string &str)
	{
		MessageBox (parent, str.c_str(), NULL, 0);
	}


	Device::Device (string path, bool readOnly)
	{
		 FileOpen = false;
		 Elevated = false;

		Handle = CreateFile ((string ("\\\\.\\") + path).c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		try
		{
			throw_sys_if (Handle == INVALID_HANDLE_VALUE);
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevated = true;
			else
				throw;
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = true;
		Path = path;
	}


	BootEncryption::BootEncryption (HWND parent)
		: DriveConfigValid (false),
		ParentWindow (parent),
		RealSystemDriveSizeValid (false),
		RescueIsoImage (nullptr),
		RescueVolumeHeaderValid (false),
		SelectedEncryptionAlgorithmId (0),
		VolumeHeaderValid (false)
	{
      HiddenOSCandidatePartition.IsGPT = FALSE;
      HiddenOSCandidatePartition.Number = (size_t) -1;
      DriveConfig.DriveNumber = -1;
      DriveConfig.ExtraBootPartitionPresent = false;
      DriveConfig.SystemLoaderPresent = false;
      DriveConfig.InitialUnallocatedSpace = 0;
      DriveConfig.TotalUnallocatedSpace = 0;
		Elevator::AddReference();
	}


	BootEncryption::~BootEncryption ()
	{
		if (RescueIsoImage)
			delete[] RescueIsoImage;

		Elevator::Release();
	}


	void BootEncryption::CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
	{
		try
		{
			DWORD bytesReturned;
			throw_sys_if (!DeviceIoControl (hDriver, ioctl, input, inputSize, output, outputSize, &bytesReturned, NULL));
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevator::CallDriver (ioctl, input, inputSize, output, outputSize);
			else
				throw;
		}
	}


	// Finds the first partition physically located behind the active one and returns its properties
	Partition BootEncryption::GetPartitionForHiddenOS ()
	{
		Partition candidatePartition;

		memset (&candidatePartition, 0, sizeof(candidatePartition));

		// The user may have modified/added/deleted partitions since the time the partition table was last scanned
		InvalidateCachedSysDriveProperties();

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();
		bool activePartitionFound = false;
		bool candidateForHiddenOSFound = false;

		if (config.SystemPartition.IsGPT)
			throw ParameterIncorrect (SRC_POS);	// It is assumed that CheckRequirements() had been called

		// Find the first active partition on the system drive 
		foreach (const Partition &partition, config.Partitions)
		{
			if (partition.Info.BootIndicator)
			{
				if (partition.Info.PartitionNumber != config.SystemPartition.Number)
				{
					// If there is an extra boot partition, the system partition must be located right behind it
					if (IsOSAtLeast (WIN_7) && config.ExtraBootPartitionPresent)
					{
						int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;
						Partition bootPartition = partition;
						Partition partitionBehindBoot;

						foreach (const Partition &partition, config.Partitions)
						{
							if (partition.Info.StartingOffset.QuadPart > bootPartition.Info.StartingOffset.QuadPart
								&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
							{
								minOffsetFound = partition.Info.StartingOffset.QuadPart;
								partitionBehindBoot = partition;
							}
						}

						if (minOffsetFound != config.DrivePartition.Info.PartitionLength.QuadPart
							&& partitionBehindBoot.Number == config.SystemPartition.Number)
						{
							activePartitionFound = true;
							break;
						}
					}

					throw ErrorException (wstring (GetString ("SYSTEM_PARTITION_NOT_ACTIVE"))
						+ GetRemarksOnHiddenOS());
				}

				activePartitionFound = true;
				break;
			}
		}

		/* WARNING: Note that the partition number at the end of a device path (\Device\HarddiskY\PartitionX) must
		NOT be used to find the first partition physically located behind the active one. The reason is that the 
		user may have deleted and created partitions during this session and e.g. the second partition could have 
		a higer number than the third one. */

		
		// Find the first partition physically located behind the active partition
		if (activePartitionFound)
		{
			int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;

			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.StartingOffset.QuadPart > config.SystemPartition.Info.StartingOffset.QuadPart
					&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
				{
					minOffsetFound = partition.Info.StartingOffset.QuadPart;

					candidatePartition = partition;

					candidateForHiddenOSFound = true;
				}
			}

			if (!candidateForHiddenOSFound)
			{
				throw ErrorException (wstring (GetString ("NO_PARTITION_FOLLOWS_BOOT_PARTITION"))
					+ GetRemarksOnHiddenOS());
			}

			if (config.SystemPartition.Info.PartitionLength.QuadPart > TC_MAX_FAT_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			{
				if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS)
				{
					throw ErrorException (wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS_NTFS"))
						+ GetRemarksOnHiddenOS());
				}
			}
			else if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT)
			{
				throw ErrorException (wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS"))
					+ GetRemarksOnHiddenOS());
			}
		}
		else
		{
			// No active partition on the system drive
			throw ErrorException ("SYSTEM_PARTITION_NOT_ACTIVE");
		}

		HiddenOSCandidatePartition = candidatePartition;
		return candidatePartition;
	}


	DWORD BootEncryption::GetDriverServiceStartType ()
	{
		DWORD startType;
		throw_sys_if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", "Start", &startType));
		return startType;
	}


	wstring BootEncryption::GetRemarksOnHiddenOS ()
	{
		return (wstring (L"\n\n")
				+ GetString ("TWO_SYSTEMS_IN_ONE_PARTITION_REMARK")
				+ L"\n\n"
				+ GetString ("FOR_MORE_INFO_ON_PARTITIONS"));
	}


	void BootEncryption::SetDriverServiceStartType (DWORD startType)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::SetDriverServiceStartType (startType);
			return;
		}

		BOOL startOnBoot = (startType == SERVICE_BOOT_START);

		SC_HANDLE serviceManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!serviceManager);

		finally_do_arg (SC_HANDLE, serviceManager, { CloseServiceHandle (finally_arg); });

		SC_HANDLE service = OpenService (serviceManager, "veracrypt", SERVICE_CHANGE_CONFIG);
		throw_sys_if (!service);

		finally_do_arg (SC_HANDLE, service, { CloseServiceHandle (finally_arg); });

		// Windows versions preceding Vista can be installed on FAT filesystem which does not
		// support long filenames during boot. Convert the driver path to short form if required.
		string driverPath;
		if (startOnBoot && !IsOSAtLeast (WIN_VISTA))
		{
			char pathBuf[MAX_PATH];
			char filesystem[128];

			string path (GetWindowsDirectory());
			path += "\\drivers\\veracrypt.sys";

			if (GetVolumePathName (path.c_str(), pathBuf, sizeof (pathBuf))
				&& GetVolumeInformation (pathBuf, NULL, 0, NULL, NULL, NULL, filesystem, sizeof(filesystem))
				&& memcmp (filesystem, "FAT", 3) == 0)
			{
				throw_sys_if (GetShortPathName (path.c_str(), pathBuf, sizeof (pathBuf)) == 0);

				// Convert absolute path to relative to the Windows directory
				driverPath = pathBuf;
				driverPath = driverPath.substr (driverPath.rfind ("\\", driverPath.rfind ("\\", driverPath.rfind ("\\") - 1) - 1) + 1);
			}
		}

		throw_sys_if (!ChangeServiceConfig (service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
			startOnBoot ? SERVICE_ERROR_SEVERE : SERVICE_ERROR_NORMAL,
			driverPath.empty() ? NULL : driverPath.c_str(),
			startOnBoot ? "Filter" : NULL,
			NULL, NULL, NULL, NULL, NULL));

		// ChangeServiceConfig() rejects SERVICE_BOOT_START with ERROR_INVALID_PARAMETER
		throw_sys_if (!WriteLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", "Start", startType));
	}


	void BootEncryption::ProbeRealSystemDriveSize ()
	{
		if (RealSystemDriveSizeValid)
			return;

		GetSystemDriveConfiguration();

		ProbeRealDriveSizeRequest request;
		_snwprintf (request.DeviceName, array_capacity (request.DeviceName), L"%hs", DriveConfig.DrivePartition.DevicePath.c_str());
		
		CallDriver (TC_IOCTL_PROBE_REAL_DRIVE_SIZE, &request, sizeof (request), &request, sizeof (request));
		DriveConfig.DrivePartition.Info.PartitionLength = request.RealDriveSize;

		RealSystemDriveSizeValid = true;

		if (request.TimeOut)
			throw TimeOut (SRC_POS);
	}


	void BootEncryption::InvalidateCachedSysDriveProperties ()
	{
		DriveConfigValid = false;
		RealSystemDriveSizeValid = false;
	}


	PartitionList BootEncryption::GetDrivePartitions (int driveNumber)
	{
		PartitionList partList;

		for (int partNumber = 0; partNumber < 64; ++partNumber)
		{
			stringstream partPath;
			partPath << "\\Device\\Harddisk" << driveNumber << "\\Partition" << partNumber;

			DISK_PARTITION_INFO_STRUCT diskPartInfo;
			_snwprintf (diskPartInfo.deviceName, array_capacity (diskPartInfo.deviceName), L"%hs", partPath.str().c_str());

			try
			{
				CallDriver (TC_IOCTL_GET_DRIVE_PARTITION_INFO, &diskPartInfo, sizeof (diskPartInfo), &diskPartInfo, sizeof (diskPartInfo));
			}
			catch (...)
			{
				continue;
			}

			Partition part;
			part.DevicePath = partPath.str();
			part.Number = partNumber;
			part.Info = diskPartInfo.partInfo;
			part.IsGPT = diskPartInfo.IsGPT;

			// Mount point
			wstringstream ws;
			ws << partPath.str().c_str();
			int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

			if (driveNumber >= 0)
			{
				part.MountPoint += (char) (driveNumber + 'A');
				part.MountPoint += ":";
			}

			// Volume ID
			wchar_t volumePath[TC_MAX_PATH];
			if (ResolveSymbolicLink ((wchar_t *) ws.str().c_str(), volumePath))
			{
				wchar_t volumeName[TC_MAX_PATH];
				HANDLE fh = FindFirstVolumeW (volumeName, array_capacity (volumeName));
				if (fh != INVALID_HANDLE_VALUE)
				{
					do
					{
						wstring volumeNameStr = volumeName;
						wchar_t devicePath[TC_MAX_PATH];

						if (QueryDosDeviceW (volumeNameStr.substr (4, volumeNameStr.size() - 1 - 4).c_str(), devicePath, array_capacity (devicePath)) != 0
							&& wcscmp (volumePath, devicePath) == 0)
						{
							part.VolumeNameId = volumeName;
							break;
						}

					} while (FindNextVolumeW (fh, volumeName, array_capacity (volumeName)));

					FindVolumeClose (fh);
				}
			}

			partList.push_back (part);
		}

		return partList;
	}
	

	DISK_GEOMETRY BootEncryption::GetDriveGeometry (int driveNumber)
	{
		stringstream devName;
		devName << "\\Device\\Harddisk" << driveNumber << "\\Partition0";

		DISK_GEOMETRY geometry;
		throw_sys_if (!::GetDriveGeometry ((char *) devName.str().c_str(), &geometry));
		return geometry;
	}

	
	string BootEncryption::GetWindowsDirectory ()
	{
		char buf[MAX_PATH];
		throw_sys_if (GetSystemDirectory (buf, sizeof (buf)) == 0);
		
		return string (buf);
	}


	string BootEncryption::GetTempPath ()
	{
		char tempPath[MAX_PATH];
		DWORD tempLen = ::GetTempPath (sizeof (tempPath), tempPath);
		if (tempLen == 0 || tempLen > sizeof (tempPath))
			throw ParameterIncorrect (SRC_POS);

		return string (tempPath);
	}


	uint16 BootEncryption::GetInstalledBootLoaderVersion ()
	{
		uint16 version;
		CallDriver (TC_IOCTL_GET_BOOT_LOADER_VERSION, NULL, 0, &version, sizeof (version));
		return version;
	}


	// Note that this does not require admin rights (it just requires the driver to be running)
	bool BootEncryption::IsBootLoaderOnDrive (char *devicePath)
	{
		try 
		{
			OPEN_TEST_STRUCT openTestStruct;
			memset (&openTestStruct, 0, sizeof (openTestStruct));
			DWORD dwResult;

			strcpy ((char *) &openTestStruct.wszFileName[0], devicePath);
			ToUNICODE ((char *) &openTestStruct.wszFileName[0]);

			openTestStruct.bDetectTCBootLoader = TRUE;

			return (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
				   &openTestStruct, sizeof (OPEN_TEST_STRUCT),
				   &openTestStruct, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL) && openTestStruct.TCBootLoaderDetected);
		}
		catch (...)
		{
			return false;
		}
	}


	BootEncryptionStatus BootEncryption::GetStatus ()
	{
		/* IMPORTANT: Do NOT add any potentially time-consuming operations to this function. */

		BootEncryptionStatus status;
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS, NULL, 0, &status, sizeof (status));
		return status;
	}


	void BootEncryption::GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties)
	{
		if (properties == NULL)
			throw ParameterIncorrect (SRC_POS);

		CallDriver (TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES, NULL, 0, properties, sizeof (*properties));
	}


	bool BootEncryption::IsHiddenSystemRunning ()
	{
		int hiddenSystemStatus;
		
		CallDriver (TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING, nullptr, 0, &hiddenSystemStatus, sizeof (hiddenSystemStatus));
		return hiddenSystemStatus != 0;
	}


	bool BootEncryption::SystemDriveContainsPartitionType (byte type)
	{
		Device device (GetSystemDriveConfiguration().DevicePath, true);

		byte mbrBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrBuf, sizeof (mbrBuf));

		MBR *mbr = reinterpret_cast <MBR *> (mbrBuf);
		if (mbr->Signature != 0xaa55)
			throw ParameterIncorrect (SRC_POS);

		for (size_t i = 0; i < array_capacity (mbr->Partitions); ++i)
		{
			if (mbr->Partitions[i].Type == type)
				return true;
		}

		return false;
	}


	bool BootEncryption::SystemDriveContainsExtendedPartition ()
	{
		return SystemDriveContainsPartitionType (PARTITION_EXTENDED) || SystemDriveContainsPartitionType (PARTITION_XINT13_EXTENDED);
	}


	bool BootEncryption::SystemDriveContainsNonStandardPartitions ()
	{
		for (int partitionType = 1; partitionType <= 0xff; ++partitionType)
		{
			switch (partitionType)
			{
			case PARTITION_FAT_12:
			case PARTITION_FAT_16:
			case PARTITION_EXTENDED:
			case PARTITION_HUGE:
			case PARTITION_IFS:
			case PARTITION_FAT32:
			case PARTITION_FAT32_XINT13:
			case PARTITION_XINT13:
			case PARTITION_XINT13_EXTENDED:
				continue;
			}

			if (SystemDriveContainsPartitionType ((byte) partitionType))
				return true;
		}

		return false;
	}


	bool BootEncryption::SystemDriveIsDynamic ()
	{
		GetSystemDriveConfigurationRequest request;
		_snwprintf (request.DevicePath, array_capacity (request.DevicePath), L"%hs", GetSystemDriveConfiguration().DeviceKernelPath.c_str());

		CallDriver (TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG, &request, sizeof (request), &request, sizeof (request));
		return request.DriveIsDynamic ? true : false;
	}


	SystemDriveConfiguration BootEncryption::GetSystemDriveConfiguration ()
	{
		if (DriveConfigValid)
			return DriveConfig;

		SystemDriveConfiguration config;

		string winDir = GetWindowsDirectory();

		// Scan all drives
		for (int driveNumber = 0; driveNumber < 32; ++driveNumber)
		{
			bool windowsFound = false;
			bool activePartitionFound = false;
			config.ExtraBootPartitionPresent = false;
			config.SystemLoaderPresent = false;

			PartitionList partitions = GetDrivePartitions (driveNumber);
			foreach (const Partition &part, partitions)
			{
				if (!part.MountPoint.empty()
					&& (_access ((part.MountPoint + "\\bootmgr").c_str(), 0) == 0 || _access ((part.MountPoint + "\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}
				else if (!part.VolumeNameId.empty()
					&& (_waccess ((part.VolumeNameId + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.VolumeNameId + L"\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}

				if (!windowsFound && !part.MountPoint.empty() && ToUpperCase (winDir).find (ToUpperCase (part.MountPoint)) == 0)
				{
					config.SystemPartition = part;
					windowsFound = true;
				}

				if (!activePartitionFound && part.Info.BootIndicator)
				{
					activePartitionFound = true;

					if (part.Info.PartitionLength.QuadPart > 0 && part.Info.PartitionLength.QuadPart <= TC_MAX_EXTRA_BOOT_PARTITION_SIZE)
						config.ExtraBootPartitionPresent = true;
				}
			}

			if (windowsFound)
			{
				config.DriveNumber = driveNumber;

				stringstream ss;
				ss << "PhysicalDrive" << driveNumber;
				config.DevicePath = ss.str();

				stringstream kernelPath;
				kernelPath << "\\Device\\Harddisk" << driveNumber << "\\Partition0";
				config.DeviceKernelPath = kernelPath.str();

				config.DrivePartition = partitions.front();
				partitions.pop_front();
				config.Partitions = partitions;

				config.InitialUnallocatedSpace = 0x7fffFFFFffffFFFFull;
				config.TotalUnallocatedSpace = config.DrivePartition.Info.PartitionLength.QuadPart;

				foreach (const Partition &part, config.Partitions)
				{
					if (part.Info.StartingOffset.QuadPart < config.InitialUnallocatedSpace)
						config.InitialUnallocatedSpace = part.Info.StartingOffset.QuadPart;

					config.TotalUnallocatedSpace -= part.Info.PartitionLength.QuadPart;
				}

				DriveConfig = config;
				DriveConfigValid = true;
				return DriveConfig;
			}
		}

		throw ParameterIncorrect (SRC_POS);
	}


	bool BootEncryption::SystemPartitionCoversWholeDrive ()
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		if (IsOSAtLeast (WIN_7)
			&& config.Partitions.size() == 2
			&& config.ExtraBootPartitionPresent
			&& config.DrivePartition.Info.PartitionLength.QuadPart - config.SystemPartition.Info.PartitionLength.QuadPart < 164 * BYTES_PER_MB)
		{
			return true;
		}

		return config.Partitions.size() == 1
			&& config.DrivePartition.Info.PartitionLength.QuadPart - config.SystemPartition.Info.PartitionLength.QuadPart < 64 * BYTES_PER_MB;
	}


	uint32 BootEncryption::GetChecksum (byte *data, size_t size)
	{
		uint32 sum = 0;

		while (size-- > 0)
		{
			sum += *data++;
			sum = _rotl (sum, 1);
		}

		return sum;
	}


	void BootEncryption::CreateBootLoaderInMemory (byte *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation)
	{
		if (bufferSize < TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE)
			throw ParameterIncorrect (SRC_POS);

		ZeroMemory (buffer, bufferSize);

		int ea = 0;
		if (GetStatus().DriveMounted)
		{
			try
			{
				GetBootEncryptionAlgorithmNameRequest request;
				CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME, NULL, 0, &request, sizeof (request));

				if (_stricmp (request.BootEncryptionAlgorithmName, "AES") == 0)
					ea = AES;
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Serpent") == 0)
					ea = SERPENT;
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Twofish") == 0)
					ea = TWOFISH;
			}
			catch (...)
			{
				try
				{
					VOLUME_PROPERTIES_STRUCT properties;
					GetVolumeProperties (&properties);
					ea = properties.ea;
				}
				catch (...) { }
			}
		}
		else
		{
			if (SelectedEncryptionAlgorithmId == 0)
				throw ParameterIncorrect (SRC_POS);

			ea = SelectedEncryptionAlgorithmId;
		}

		int bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR : IDR_BOOT_SECTOR;
		int bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER : IDR_BOOT_LOADER;

		switch (ea)
		{
		case AES:
			bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_AES : IDR_BOOT_SECTOR_AES;
			bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_AES : IDR_BOOT_LOADER_AES;
			break;

		case SERPENT:
			bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_SERPENT : IDR_BOOT_SECTOR_SERPENT;
			bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_SERPENT : IDR_BOOT_LOADER_SERPENT;
			break;

		case TWOFISH:
			bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_TWOFISH : IDR_BOOT_SECTOR_TWOFISH;
			bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_TWOFISH : IDR_BOOT_LOADER_TWOFISH;
			break;
		}

		// Boot sector
		DWORD size;
		byte *bootSecResourceImg = MapResource ("BIN", bootSectorId, &size);
		if (!bootSecResourceImg || size != TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer, bootSecResourceImg, size);

		*(uint16 *) (buffer + TC_BOOT_SECTOR_VERSION_OFFSET) = BE16 (VERSION_NUM);

		if (IsOSAtLeast (WIN_VISTA))
			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_WINDOWS_VISTA_OR_LATER;

		if (rescueDisk && (ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION))
			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISABLE_HW_ENCRYPTION;

		// Checksum of the backup header of the outer volume for the hidden system
		if (hiddenOSCreation)
		{
			Device device (GetSystemDriveConfiguration().DevicePath);
			byte headerSector[TC_SECTOR_SIZE_BIOS];

			device.SeekAt (HiddenOSCandidatePartition.Info.StartingOffset.QuadPart + HiddenOSCandidatePartition.Info.PartitionLength.QuadPart - TC_VOLUME_HEADER_GROUP_SIZE + TC_VOLUME_HEADER_EFFECTIVE_SIZE);
			device.Read (headerSector, sizeof (headerSector));

			*(uint32 *) (buffer + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET) = GetCrc32 (headerSector, sizeof (headerSector));
		}

		// Decompressor
		byte *decompressor = MapResource ("BIN", IDR_BOOT_LOADER_DECOMPRESSOR, &size);
		if (!decompressor || size > TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + TC_SECTOR_SIZE_BIOS, decompressor, size);

		// Compressed boot loader
		byte *bootLoader = MapResource ("BIN", bootLoaderId, &size);
		if (!bootLoader || size > TC_MAX_BOOT_LOADER_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + TC_SECTOR_SIZE_BIOS + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS, bootLoader, size);

		// Boot loader and decompressor checksum
		*(uint16 *) (buffer + TC_BOOT_SECTOR_LOADER_LENGTH_OFFSET) = static_cast <uint16> (size);
		*(uint32 *) (buffer + TC_BOOT_SECTOR_LOADER_CHECKSUM_OFFSET) = GetChecksum (buffer + TC_SECTOR_SIZE_BIOS,
			TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS + size);

		// Backup of decompressor and boot loader
		if (size + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS <= TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
		{
			memcpy (buffer + TC_SECTOR_SIZE_BIOS + TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS,
				buffer + TC_SECTOR_SIZE_BIOS, TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS);

			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_BACKUP_LOADER_AVAILABLE;
		}
		else if (!rescueDisk && bootLoaderId != IDR_BOOT_LOADER)
		{
			throw ParameterIncorrect (SRC_POS);
		}
	}


	void BootEncryption::ReadBootSectorConfig (byte *config, size_t bufLength, byte *userConfig, string *customUserMessage, uint16 *bootLoaderVersion)
	{
		if (config && bufLength < TC_BOOT_CFG_FLAG_AREA_SIZE)
			throw ParameterIncorrect (SRC_POS);

		GetSystemDriveConfigurationRequest request;
		_snwprintf (request.DevicePath, array_capacity (request.DevicePath), L"%hs", GetSystemDriveConfiguration().DeviceKernelPath.c_str());

		try
		{
			CallDriver (TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG, &request, sizeof (request), &request, sizeof (request));
			if (config)
				*config = request.Configuration;

			if (userConfig)
				*userConfig = request.UserConfiguration;
			
			if (customUserMessage)
			{
				request.CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH] = 0;
				*customUserMessage = request.CustomUserMessage;
			}

			if (bootLoaderVersion)
				*bootLoaderVersion = request.BootLoaderVersion;
		}
		catch (...)
		{
			if (config)
				*config = 0;

			if (userConfig)
				*userConfig = 0;
			
			if (customUserMessage)
				customUserMessage->clear();

			if (bootLoaderVersion)
				*bootLoaderVersion = 0;
		}
	}


	void BootEncryption::WriteBootSectorConfig (const byte newConfig[])
	{
		Device device (GetSystemDriveConfiguration().DevicePath);
		byte mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));

		memcpy (mbr + TC_BOOT_SECTOR_CONFIG_OFFSET, newConfig, TC_BOOT_CFG_FLAG_AREA_SIZE);

		device.SeekAt (0);
		device.Write (mbr, sizeof (mbr));

		byte mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrVerificationBuf, sizeof (mbr));

		if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
			throw ErrorException ("ERROR_MBR_PROTECTED");
	}


	void BootEncryption::WriteBootSectorUserConfig (byte userConfig, const string &customUserMessage)
	{
		Device device (GetSystemDriveConfiguration().DevicePath);
		byte mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));

		if (!BufferContainsString (mbr, sizeof (mbr), TC_APP_NAME)
			|| BE16 (*(uint16 *) (mbr + TC_BOOT_SECTOR_VERSION_OFFSET)) != VERSION_NUM)
		{
			return;
		}

		mbr[TC_BOOT_SECTOR_USER_CONFIG_OFFSET] = userConfig;

		memset (mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, 0, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);

		if (!customUserMessage.empty())
		{
			if (customUserMessage.size() > TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)
				throw ParameterIncorrect (SRC_POS);

			memcpy (mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, customUserMessage.c_str(), customUserMessage.size());
		}

		device.SeekAt (0);
		device.Write (mbr, sizeof (mbr));

		byte mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrVerificationBuf, sizeof (mbr));

		if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
			throw ErrorException ("ERROR_MBR_PROTECTED");
	}


	unsigned int BootEncryption::GetHiddenOSCreationPhase ()
	{
		byte configFlags [TC_BOOT_CFG_FLAG_AREA_SIZE];

		ReadBootSectorConfig (configFlags, sizeof(configFlags));

		return (configFlags[0] & TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE);
	}


	void BootEncryption::SetHiddenOSCreationPhase (unsigned int newPhase)
	{
#if TC_BOOT_CFG_FLAG_AREA_SIZE != 1
#	error TC_BOOT_CFG_FLAG_AREA_SIZE != 1; revise GetHiddenOSCreationPhase() and SetHiddenOSCreationPhase()
#endif
		byte configFlags [TC_BOOT_CFG_FLAG_AREA_SIZE];

		ReadBootSectorConfig (configFlags, sizeof(configFlags));

		configFlags[0] &= (byte) ~TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;

		configFlags[0] |= newPhase;

		WriteBootSectorConfig (configFlags);
	}


#ifndef SETUP

	void BootEncryption::StartDecoyOSWipe (WipeAlgorithmId wipeAlgorithm)
	{
		if (!IsHiddenOSRunning())
			throw ParameterIncorrect (SRC_POS);

		WipeDecoySystemRequest request;
		ZeroMemory (&request, sizeof (request));

		request.WipeAlgorithm = wipeAlgorithm;
		
		if (Randinit() != ERR_SUCCESS)
			throw ParameterIncorrect (SRC_POS);

		UserEnrichRandomPool (ParentWindow);

		if (!RandgetBytes (request.WipeKey, sizeof (request.WipeKey), TRUE))
			throw ParameterIncorrect (SRC_POS);

		CallDriver (TC_IOCTL_START_DECOY_SYSTEM_WIPE, &request, sizeof (request), NULL, 0);

		burn (&request, sizeof (request));
	}


	void BootEncryption::AbortDecoyOSWipe ()
	{
		CallDriver (TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE);
	}

	
	DecoySystemWipeStatus BootEncryption::GetDecoyOSWipeStatus ()
	{
		DecoySystemWipeStatus status;
		CallDriver (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS, NULL, 0, &status, sizeof (status));
		return status;
	}


	void BootEncryption::CheckDecoyOSWipeResult ()
	{
		CallDriver (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT);
	}


	void BootEncryption::WipeHiddenOSCreationConfig ()
	{
		if (IsHiddenOSRunning() || Randinit() != ERR_SUCCESS)
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);
		byte mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));
		
		finally_do_arg (BootEncryption *, this,
		{
			try
			{
				finally_arg->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
			} catch (...) { }
		});

#if PRAND_DISK_WIPE_PASSES > RNG_POOL_SIZE
#	error PRAND_DISK_WIPE_PASSES > RNG_POOL_SIZE
#endif

		byte randData[PRAND_DISK_WIPE_PASSES];
		if (!RandgetBytes (randData, sizeof (randData), FALSE))
			throw ParameterIncorrect (SRC_POS);

		for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES; wipePass++)
		{
			for (int i = 0; i < TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE; ++i)
			{
				mbr[TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET + i] = randData[wipePass];
			}

			mbr[TC_BOOT_SECTOR_CONFIG_OFFSET] &= (byte) ~TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;
			mbr[TC_BOOT_SECTOR_CONFIG_OFFSET] |= randData[wipePass] & TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;

			if (wipePass == PRAND_DISK_WIPE_PASSES - 1)
				memset (mbr + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET, 0, TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE);

			device.SeekAt (0);
			device.Write (mbr, sizeof (mbr));
		}

		for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES/4 + 1; wipePass++)
		{
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_CLONING);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_WIPING);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_WIPED);
		}
		SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
	}

#endif // !SETUP


	void BootEncryption::InstallBootLoader (bool preserveUserConfig, bool hiddenOSCreation)
	{
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		CreateBootLoaderInMemory (bootLoaderBuf, sizeof (bootLoaderBuf), false, hiddenOSCreation);

		// Write MBR
		Device device (GetSystemDriveConfiguration().DevicePath);
		byte mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));

		if (preserveUserConfig && BufferContainsString (mbr, sizeof (mbr), TC_APP_NAME))
		{
			uint16 version = BE16 (*(uint16 *) (mbr + TC_BOOT_SECTOR_VERSION_OFFSET));
			if (version != 0)
			{
				bootLoaderBuf[TC_BOOT_SECTOR_USER_CONFIG_OFFSET] = mbr[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
				memcpy (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
			}
		}

		memcpy (mbr, bootLoaderBuf, TC_MAX_MBR_BOOT_CODE_SIZE);

		device.SeekAt (0);
		device.Write (mbr, sizeof (mbr));

		byte mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrVerificationBuf, sizeof (mbr));

		if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
			throw ErrorException ("ERROR_MBR_PROTECTED");

		// Write boot loader
		device.SeekAt (TC_SECTOR_SIZE_BIOS);
		device.Write (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, sizeof (bootLoaderBuf) - TC_SECTOR_SIZE_BIOS);
	}


	string BootEncryption::GetSystemLoaderBackupPath ()
	{
		char pathBuf[MAX_PATH];

		throw_sys_if (!SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, pathBuf)));
		
		string path = string (pathBuf) + "\\" TC_APP_NAME;
		CreateDirectory (path.c_str(), NULL);

		return path + '\\' + TC_SYS_BOOT_LOADER_BACKUP_NAME;
	}


	void BootEncryption::RenameDeprecatedSystemLoaderBackup ()
	{
		char pathBuf[MAX_PATH];

		if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA, NULL, 0, pathBuf)))
		{
			string path = string (pathBuf) + "\\" TC_APP_NAME + '\\' + TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY;

			if (FileExists (path.c_str()) && !FileExists (GetSystemLoaderBackupPath().c_str()))
				throw_sys_if (rename (path.c_str(), GetSystemLoaderBackupPath().c_str()) != 0);
		}
	}


#ifndef SETUP
	void BootEncryption::CreateRescueIsoImage (bool initialSetup, const string &isoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		Buffer imageBuf (RescueIsoImageSize);
		
		byte *image = imageBuf.Ptr();
		memset (image, 0, RescueIsoImageSize);

		// Primary volume descriptor
		strcpy ((char *)image + 0x8000, "\001CD001\001");
		strcpy ((char *)image + 0x7fff + 41, "VeraCrypt Rescue Disk           ");
		*(uint32 *) (image + 0x7fff + 81) = RescueIsoImageSize / 2048;
		*(uint32 *) (image + 0x7fff + 85) = BE32 (RescueIsoImageSize / 2048);
		image[0x7fff + 121] = 1;
		image[0x7fff + 124] = 1;
		image[0x7fff + 125] = 1;
		image[0x7fff + 128] = 1;
		image[0x7fff + 130] = 8;
		image[0x7fff + 131] = 8;

		image[0x7fff + 133] = 10;
		image[0x7fff + 140] = 10;
		image[0x7fff + 141] = 0x14;
		image[0x7fff + 157] = 0x22;
		image[0x7fff + 159] = 0x18;

		// Boot record volume descriptor
		strcpy ((char *)image + 0x8801, "CD001\001EL TORITO SPECIFICATION");
		image[0x8800 + 0x47] = 0x19;

		// Volume descriptor set terminator
		strcpy ((char *)image + 0x9000, "\377CD001\001");

		// Path table
		image[0xA000 + 0] = 1;
		image[0xA000 + 2] = 0x18;
		image[0xA000 + 6] = 1;

		// Root directory
		image[0xc000 + 0] = 0x22;
		image[0xc000 + 2] = 0x18;
		image[0xc000 + 9] = 0x18;
		image[0xc000 + 11] = 0x08;
		image[0xc000 + 16] = 0x08;
		image[0xc000 + 25] = 0x02;
		image[0xc000 + 28] = 0x01;
		image[0xc000 + 31] = 0x01;
		image[0xc000 + 32] = 0x01;
		image[0xc000 + 34] = 0x22;
		image[0xc000 + 36] = 0x18;
		image[0xc000 + 43] = 0x18;
		image[0xc000 + 45] = 0x08;
		image[0xc000 + 50] = 0x08;
		image[0xc000 + 59] = 0x02;
		image[0xc000 + 62] = 0x01;
		*(uint32 *) (image + 0xc000 + 65) = 0x010101;

		// Validation entry
		image[0xc800] = 1;
		int offset = 0xc800 + 0x1c;
		image[offset++] = 0xaa;
		image[offset++] = 0x55;
		image[offset++] = 0x55;
		image[offset] = 0xaa;

		// Initial entry
		offset = 0xc820;
		image[offset++] = 0x88;
		image[offset++] = 2;
		image[0xc820 + 6] = 1;
		image[0xc820 + 8] = TC_CD_BOOT_LOADER_SECTOR;

		// TrueCrypt Boot Loader
		CreateBootLoaderInMemory (image + TC_CD_BOOTSECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE, true);

		// Volume header
		if (initialSetup)
		{
			if (!RescueVolumeHeaderValid)
				throw ParameterIncorrect (SRC_POS);

			memcpy (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, RescueVolumeHeader, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
		}
		else
		{
			Device bootDevice (GetSystemDriveConfiguration().DevicePath, true);
			bootDevice.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
			bootDevice.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
		}

		// Original system loader
		try
		{
			File sysBakFile (GetSystemLoaderBackupPath(), true);
			sysBakFile.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE);
			
			image[TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISK_ORIG_SYS_LOADER;
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			Warning ("SYS_LOADER_UNAVAILABLE_FOR_RESCUE_DISK");
		}
		
		// Boot loader backup
		CreateBootLoaderInMemory (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE, false);

		RescueIsoImage = new byte[RescueIsoImageSize];
		if (!RescueIsoImage)
			throw bad_alloc();
		memcpy (RescueIsoImage, image, RescueIsoImageSize);

		if (!isoImagePath.empty())
		{
			File isoFile (isoImagePath, false, true);
			isoFile.Write (image, RescueIsoImageSize);
		}
	}
#endif


	bool BootEncryption::IsCDDrivePresent ()
	{
		for (char drive = 'Z'; drive >= 'C'; --drive)
		{
			string path = "X:\\";
			path[0] = drive;

			if (GetDriveType (path.c_str()) == DRIVE_CDROM)
				return true;
		}

		return false;
	}


	bool BootEncryption::VerifyRescueDisk ()
	{
		if (!RescueIsoImage)
			throw ParameterIncorrect (SRC_POS);

		for (char drive = 'Z'; drive >= 'C'; --drive)
		{
			try
			{
				string path = "X:";
				path[0] = drive;

				Device driveDevice (path, true);
				size_t verifiedSectorCount = (TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET + TC_BOOT_LOADER_AREA_SIZE) / 2048;
				Buffer buffer ((verifiedSectorCount + 1) * 2048);

				DWORD bytesRead = driveDevice.Read (buffer.Ptr(), buffer.Size());
				if (bytesRead != buffer.Size())
					continue;

				if (memcmp (buffer.Ptr(), RescueIsoImage, buffer.Size()) == 0)
					return true;
			}
			catch (...) { }
		}

		return false;
	}


#ifndef SETUP

	void BootEncryption::CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5)
	{
		PCRYPTO_INFO cryptoInfo = NULL;

		if (!IsRandomNumberGeneratorStarted())
			throw ParameterIncorrect (SRC_POS);

		throw_sys_if (CreateVolumeHeaderInMemory (TRUE, (char *) VolumeHeader, ea, mode, password, pkcs5, NULL, &cryptoInfo,
			volumeSize, 0, encryptedAreaStart, 0, TC_SYSENC_KEYSCOPE_MIN_REQ_PROG_VERSION, TC_HEADER_FLAG_ENCRYPTED_SYSTEM, TC_SECTOR_SIZE_BIOS, FALSE) != 0);

		finally_do_arg (PCRYPTO_INFO*, &cryptoInfo, { crypto_close (*finally_arg); });

		// Initial rescue disk assumes encryption of the drive has been completed (EncryptedAreaLength == volumeSize)
		memcpy (RescueVolumeHeader, VolumeHeader, sizeof (RescueVolumeHeader));
		ReadVolumeHeader (TRUE, (char *) RescueVolumeHeader, password, NULL, cryptoInfo);

		DecryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		if (GetHeaderField32 (RescueVolumeHeader, TC_HEADER_OFFSET_MAGIC) != 0x56455241)
			throw ParameterIncorrect (SRC_POS);

		byte *fieldPos = RescueVolumeHeader + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
		mputInt64 (fieldPos, volumeSize);

		// CRC of the header fields
		uint32 crc = GetCrc32 (RescueVolumeHeader + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
		fieldPos = RescueVolumeHeader + TC_HEADER_OFFSET_HEADER_CRC;
		mputLong (fieldPos, crc);

		EncryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		VolumeHeaderValid = true;
		RescueVolumeHeaderValid = true;
	}


	void BootEncryption::InstallVolumeHeader ()
	{
		if (!VolumeHeaderValid)
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);

		device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
		device.Write ((byte *) VolumeHeader, sizeof (VolumeHeader));
	}


	// For synchronous operations use AbortSetupWait()
	void BootEncryption::AbortSetup ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);
	}


	// For asynchronous operations use AbortSetup()
	void BootEncryption::AbortSetupWait ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);

		BootEncryptionStatus encStatus = GetStatus();

		while (encStatus.SetupInProgress)
		{
			Sleep (TC_ABORT_TRANSFORM_WAIT_INTERVAL);
			encStatus = GetStatus();
		}
	}


	void BootEncryption::BackupSystemLoader ()
	{
		Device device (GetSystemDriveConfiguration().DevicePath, true);
	
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (bootLoaderBuf, sizeof (bootLoaderBuf));

		// Prevent TrueCrypt loader from being backed up
		for (size_t i = 0; i < sizeof (bootLoaderBuf) - strlen (TC_APP_NAME); ++i)
		{
			if (memcmp (bootLoaderBuf + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
			{
				if (AskWarnNoYes ("TC_BOOT_LOADER_ALREADY_INSTALLED") == IDNO)
					throw UserAbort (SRC_POS);
				return;
			}
		}

		File backupFile (GetSystemLoaderBackupPath(), false, true);
		backupFile.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
	}


	void BootEncryption::RestoreSystemLoader ()
	{
		byte bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS];

		File backupFile (GetSystemLoaderBackupPath(), true);
		
		if (backupFile.Read (bootLoaderBuf, sizeof (bootLoaderBuf)) != sizeof (bootLoaderBuf))
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);

		// Preserve current partition table
		byte mbr[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));
		memcpy (bootLoaderBuf + TC_MAX_MBR_BOOT_CODE_SIZE, mbr + TC_MAX_MBR_BOOT_CODE_SIZE, sizeof (mbr) - TC_MAX_MBR_BOOT_CODE_SIZE);

		device.SeekAt (0);
		device.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
	}

#endif // SETUP

	void BootEncryption::RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid)
	{
		string filter;
		string filterReg;
		HKEY regKey;

		switch (filterType)
		{
		case DriveFilter:
		case VolumeFilter:
			filter = "veracrypt";
			filterReg = "UpperFilters";
			regKey = SetupDiOpenClassRegKey (deviceClassGuid, KEY_READ | KEY_WRITE);
			throw_sys_if (regKey == INVALID_HANDLE_VALUE);

			break;

		case DumpFilter:
			if (!IsOSAtLeast (WIN_VISTA))
				return;

			filter = "veracrypt.sys";
			filterReg = "DumpFilters";
			SetLastError (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CrashControl", 0, KEY_READ | KEY_WRITE, &regKey));
			throw_sys_if (GetLastError() != ERROR_SUCCESS);

			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		finally_do_arg (HKEY, regKey, { RegCloseKey (finally_arg); });

		if (registerFilter && filterType != DumpFilter)
		{
			// Register class filter below all other filters in the stack

			size_t strSize = filter.size() + 1;
			byte regKeyBuf[65536];
			DWORD size = sizeof (regKeyBuf) - strSize;

			// SetupInstallFromInfSection() does not support prepending of values so we have to modify the registry directly
			strncpy ((char *) regKeyBuf, filter.c_str(), sizeof (regKeyBuf));

			if (RegQueryValueEx (regKey, filterReg.c_str(), NULL, NULL, regKeyBuf + strSize, &size) != ERROR_SUCCESS)
				size = 1;

			SetLastError (RegSetValueEx (regKey, filterReg.c_str(), 0, REG_MULTI_SZ, regKeyBuf, strSize + size));
			throw_sys_if (GetLastError() != ERROR_SUCCESS);
		}
		else
		{
			string infFileName = GetTempPath() + "\\veracrypt_driver_setup.inf";

			File infFile (infFileName, false, true);
			finally_do_arg (string, infFileName, { DeleteFile (finally_arg.c_str()); });

			string infTxt = "[veracrypt]\r\n"
							+ string (registerFilter ? "Add" : "Del") + "Reg=veracrypt_reg\r\n\r\n"
							"[veracrypt_reg]\r\n"
							"HKR,,\"" + filterReg + "\",0x0001" + string (registerFilter ? "0008" : "8002") + ",\"" + filter + "\"\r\n";

			infFile.Write ((byte *) infTxt.c_str(), infTxt.size());
			infFile.Close();

			HINF hInf = SetupOpenInfFile (infFileName.c_str(), NULL, INF_STYLE_OLDNT | INF_STYLE_WIN4, NULL);
			throw_sys_if (hInf == INVALID_HANDLE_VALUE);
			finally_do_arg (HINF, hInf, { SetupCloseInfFile (finally_arg); });

			throw_sys_if (!SetupInstallFromInfSection (ParentWindow, hInf, "veracrypt", SPINST_REGISTRY, regKey, NULL, 0, NULL, NULL, NULL, NULL));
		}
	}

	void BootEncryption::RegisterFilterDriver (bool registerDriver, FilterType filterType)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::RegisterFilterDriver (registerDriver, filterType);
			return;
		}

		switch (filterType)
		{
		case DriveFilter:
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_DISKDRIVE);
			break;

		case VolumeFilter:
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_VOLUME);
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_FLOPPYDISK);
			break;

		case DumpFilter:
			RegisterFilter (registerDriver, filterType);
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

#ifndef SETUP

	void BootEncryption::RegisterSystemFavoritesService (BOOL registerService)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::RegisterSystemFavoritesService (registerService);
			return;
		}

		SC_HANDLE scm = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!scm);

		string servicePath = GetServiceConfigPath (TC_APP_NAME ".exe");

		if (registerService)
		{
			try
			{
				RegisterSystemFavoritesService (FALSE);
			}
			catch (...) { }

			char appPath[TC_MAX_PATH];
			throw_sys_if (!GetModuleFileName (NULL, appPath, sizeof (appPath)));

			throw_sys_if (!CopyFile (appPath, servicePath.c_str(), FALSE));

			SC_HANDLE service = CreateService (scm,
				TC_SYSTEM_FAVORITES_SERVICE_NAME,
				TC_APP_NAME " System Favorites",
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_NORMAL,
				(string ("\"") + servicePath + "\" " TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION).c_str(),
				TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP,
				NULL,
				NULL,
				NULL,
				NULL);

			throw_sys_if (!service);

			SERVICE_DESCRIPTION description;
			description.lpDescription = "Mounts VeraCrypt system favorite volumes.";
			ChangeServiceConfig2 (service, SERVICE_CONFIG_DESCRIPTION, &description);

			CloseServiceHandle (service);

			try
			{
				WriteLocalMachineRegistryString ("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, NULL, "Service", FALSE);
				WriteLocalMachineRegistryString ("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, NULL, "Service", FALSE);

				SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES, true);
			}
			catch (...)
			{
				try
				{
					RegisterSystemFavoritesService (false);
				}
				catch (...) { }

				throw;
			}
		}
		else
		{
			SetDriverConfigurationFlag (TC_DRIVER_CONFIG_CACHE_BOOT_PASSWORD_FOR_SYS_FAVORITES, false);

			DeleteLocalMachineRegistryKey ("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal", TC_SYSTEM_FAVORITES_SERVICE_NAME);
			DeleteLocalMachineRegistryKey ("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network", TC_SYSTEM_FAVORITES_SERVICE_NAME);

			SC_HANDLE service = OpenService (scm, TC_SYSTEM_FAVORITES_SERVICE_NAME, SERVICE_ALL_ACCESS);
			throw_sys_if (!service);

			throw_sys_if (!DeleteService (service));
			CloseServiceHandle (service);

			DeleteFile (servicePath.c_str());
		}
	}

	void BootEncryption::CheckRequirements ()
	{
		if (nCurrentOS == WIN_2000)
			throw ErrorException ("SYS_ENCRYPTION_UNSUPPORTED_ON_CURRENT_OS");
 
		if (CurrentOSMajor == 6 && CurrentOSMinor == 0 && CurrentOSServicePack < 1)
			throw ErrorException ("SYS_ENCRYPTION_UNSUPPORTED_ON_VISTA_SP0");

		if (IsNonInstallMode())
			throw ErrorException ("FEATURE_REQUIRES_INSTALLATION");

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		if (config.SystemPartition.IsGPT)
			throw ErrorException ("GPT_BOOT_DRIVE_UNSUPPORTED");

		if (SystemDriveIsDynamic())
			throw ErrorException ("SYSENC_UNSUPPORTED_FOR_DYNAMIC_DISK");

		if (config.InitialUnallocatedSpace < TC_BOOT_LOADER_AREA_SIZE)
			throw ErrorException ("NO_SPACE_FOR_BOOT_LOADER");

		DISK_GEOMETRY geometry = GetDriveGeometry (config.DriveNumber);

		if (geometry.BytesPerSector != TC_SECTOR_SIZE_BIOS)
			throw ErrorException ("SYSENC_UNSUPPORTED_SECTOR_SIZE_BIOS");

		bool activePartitionFound = false;
		if (!config.SystemPartition.IsGPT)
		{
			// Determine whether there is an Active partition on the system drive
			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.BootIndicator)
				{
					activePartitionFound = true;
					break;
				}
			}
		}

		if (!config.SystemLoaderPresent || !activePartitionFound)
		{
			static bool confirmed = false;

			if (!confirmed && AskWarnNoYes ("WINDOWS_NOT_ON_BOOT_DRIVE_ERROR") == IDNO)
				throw UserAbort (SRC_POS);

			confirmed = true;
		}
	}


	void BootEncryption::CheckRequirementsHiddenOS ()
	{
		// It is assumed that CheckRequirements() had been called (so we don't check e.g. whether it's GPT).

		// The user may have modified/added/deleted partitions since the partition table was last scanned.
		InvalidateCachedSysDriveProperties ();

		GetPartitionForHiddenOS ();
	}


	void BootEncryption::InitialSecurityChecksForHiddenOS ()
	{
		char windowsDrive = (char) toupper (GetWindowsDirectory()[0]);

		// Paging files
		bool pagingFilesOk = !IsPagingFileActive (TRUE);

		char pagingFileRegData[65536];
		DWORD pagingFileRegDataSize = sizeof (pagingFileRegData);

		if (ReadLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", pagingFileRegData, &pagingFileRegDataSize)
			&& pagingFileRegDataSize > 4)
		{
			for (size_t i = 1; i < pagingFileRegDataSize - 2; ++i)
			{
				if (memcmp (pagingFileRegData + i, ":\\", 2) == 0 && toupper (pagingFileRegData[i - 1]) != windowsDrive)
				{
					pagingFilesOk = false;
					break;
				}
			}
		}

		if (!pagingFilesOk)
		{
			if (AskWarnYesNoString ((wchar_t *) (wstring (GetString ("PAGING_FILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION")
				+ L"\n\n\n"
				+ GetString ("RESTRICT_PAGING_FILES_TO_SYS_PARTITION")
				).c_str()) == IDYES)
			{
				RestrictPagingFilesToSystemPartition();
				RestartComputer();
				AbortProcessSilent();
			}

			throw ErrorException (wstring (GetString ("PAGING_FILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"));
		}

		// User profile
		char *configPath = GetConfigPath ("dummy");
		if (configPath && toupper (configPath[0]) != windowsDrive)
		{
			throw ErrorException (wstring (GetString ("USER_PROFILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"));
		}

		// Temporary files
		if (toupper (GetTempPath()[0]) != windowsDrive)
		{
			throw ErrorException (wstring (GetString ("TEMP_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"));
		}
	}


	// This operation may take a long time when an antivirus is installed and its real-time protection enabled.
	// Therefore, if calling it without the wizard displayed, it should be called with displayWaitDialog set to true.
	void BootEncryption::Deinstall (bool displayWaitDialog)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (encStatus.DriveEncrypted || encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		if (encStatus.VolumeHeaderPresent)
		{
			// Verify CRC of header salt
			Device device (config.DevicePath, true);
			byte header[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];

			device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
			device.Read (header, sizeof (header));

			if (encStatus.VolumeHeaderSaltCrc32 != GetCrc32 ((byte *) header, PKCS5_SALT_SIZE))
				throw ParameterIncorrect (SRC_POS);
		}

		try
		{
			RegisterFilterDriver (false, DriveFilter);
			RegisterFilterDriver (false, VolumeFilter);
			RegisterFilterDriver (false, DumpFilter);
			SetDriverServiceStartType (SERVICE_SYSTEM_START);
		}
		catch (...)
		{
			try
			{
				RegisterBootDriver (IsHiddenSystemRunning());
			}
			catch (...) { }

			throw;
		}

		SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);	// In case RestoreSystemLoader() fails

		try
		{
			RegisterSystemFavoritesService (false);
		}
		catch (...) { }

		try
		{
			if (displayWaitDialog)
				DisplayStaticModelessWaitDlg (ParentWindow);

			finally_do_arg (bool, displayWaitDialog, { if (finally_arg) CloseStaticModelessWaitDlg(); });

			RestoreSystemLoader ();
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			throw ErrorException ("SYS_LOADER_RESTORE_FAILED");
		}
	}


	int BootEncryption::ChangePassword (Password *oldPassword, Password *newPassword, int pkcs5)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		char header[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		Device device (config.DevicePath);

		// Only one algorithm is currently supported
		if (pkcs5 != 0)
			throw ParameterIncorrect (SRC_POS);

		int64 headerOffset = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;
		int64 backupHeaderOffset = -1;

		if (encStatus.HiddenSystem)
		{
			headerOffset = encStatus.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;

			// Find hidden system partition
			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.StartingOffset.QuadPart == encStatus.HiddenSystemPartitionStart)
				{
					backupHeaderOffset = partition.Info.StartingOffset.QuadPart + partition.Info.PartitionLength.QuadPart - TC_VOLUME_HEADER_SIZE;
					break;
				}
			}

			if (backupHeaderOffset == -1)
				throw ParameterIncorrect (SRC_POS);
		}

		device.SeekAt (headerOffset);
		device.Read ((byte *) header, sizeof (header));

		PCRYPTO_INFO cryptoInfo = NULL;
		
		int status = ReadVolumeHeader (!encStatus.HiddenSystem, header, oldPassword, &cryptoInfo, NULL);
		finally_do_arg (PCRYPTO_INFO, cryptoInfo, { if (finally_arg) crypto_close (finally_arg); });

		if (status != 0)
		{
			handleError (ParentWindow, status);
			return status;
		}

		// Change the PKCS-5 PRF if requested by user
		if (pkcs5 != 0)
		{
			cryptoInfo->pkcs5 = pkcs5;
			RandSetHashFunction (pkcs5);
		}

		throw_sys_if (Randinit () != 0);
		finally_do ({ RandStop (FALSE); });

		NormalCursor();
		UserEnrichRandomPool (ParentWindow);
		WaitCursor();

		/* The header will be re-encrypted PRAND_DISK_WIPE_PASSES times to prevent adversaries from using 
		techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
		to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
		times (ideally, 35 times) using non-random patterns and pseudorandom data. However, as users might
		impatiently interupt the process (etc.) we will not use the Gutmann's patterns but will write the
		valid re-encrypted header, i.e. pseudorandom data, and there will be many more passes than Guttman
		recommends. During each pass we will write a valid working header. Each pass will use the same master
		key, and also the same header key, secondary key (XTS), etc., derived from the new password. The only
		item that will be different for each pass will be the salt. This is sufficient to cause each "version"
		of the header to differ substantially and in a random manner from the versions written during the
		other passes. */

		bool headerUpdated = false;
		int result = ERR_SUCCESS;

		try
		{
			BOOL backupHeader = FALSE;
			while (TRUE)
			{
				for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES; wipePass++)
				{
					PCRYPTO_INFO tmpCryptoInfo = NULL;

					status = CreateVolumeHeaderInMemory (!encStatus.HiddenSystem,
						header,
						cryptoInfo->ea,
						cryptoInfo->mode,
						newPassword,
						cryptoInfo->pkcs5,
						(char *) cryptoInfo->master_keydata,
						&tmpCryptoInfo,
						cryptoInfo->VolumeSize.Value,
						cryptoInfo->hiddenVolumeSize,
						cryptoInfo->EncryptedAreaStart.Value,
						cryptoInfo->EncryptedAreaLength.Value,
						cryptoInfo->RequiredProgramVersion,
						cryptoInfo->HeaderFlags | TC_HEADER_FLAG_ENCRYPTED_SYSTEM,
						cryptoInfo->SectorSize,
						wipePass < PRAND_DISK_WIPE_PASSES - 1);

					if (tmpCryptoInfo)
						crypto_close (tmpCryptoInfo);

					if (status != 0)
					{
						handleError (ParentWindow, status);
						return status;
					}

					device.SeekAt (headerOffset);
					device.Write ((byte *) header, sizeof (header));
					headerUpdated = true;
				}

				if (!encStatus.HiddenSystem || backupHeader)
					break;

				backupHeader = TRUE;
				headerOffset = backupHeaderOffset;
			}
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			result = ERR_OS_ERROR;
		}

		if (headerUpdated)
		{
			ReopenBootVolumeHeaderRequest reopenRequest;
			reopenRequest.VolumePassword = *newPassword;
			finally_do_arg (ReopenBootVolumeHeaderRequest*, &reopenRequest, { burn (finally_arg, sizeof (*finally_arg)); });

			CallDriver (TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER, &reopenRequest, sizeof (reopenRequest));
		}

		return result;
	}


	void BootEncryption::CheckEncryptionSetupResult ()
	{
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT);
	}


	void BootEncryption::Install (bool hiddenSystem)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		try
		{
			InstallBootLoader (false, hiddenSystem);

			if (!hiddenSystem)
				InstallVolumeHeader ();

			RegisterBootDriver (hiddenSystem);
		}
		catch (Exception &)
		{
			try
			{
				RestoreSystemLoader ();
			}
			catch (Exception &e)
			{
				e.Show (ParentWindow);
			}

			throw;
		}
	}


	void BootEncryption::PrepareHiddenOSCreation (int ea, int mode, int pkcs5)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		CheckRequirements();
		BackupSystemLoader();

		SelectedEncryptionAlgorithmId = ea;
	}


	void BootEncryption::PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, const string &rescueIsoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		CheckRequirements ();

		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		// Some chipset drivers may prevent access to the last sector of the drive
		if (!systemPartitionOnly)
		{
			DISK_GEOMETRY geometry = GetDriveGeometry (config.DriveNumber);
			Buffer sector (geometry.BytesPerSector);

			Device device (config.DevicePath);

			try
			{
				device.SeekAt (config.DrivePartition.Info.PartitionLength.QuadPart - geometry.BytesPerSector);
				device.Read (sector.Ptr(), sector.Size());
			}
			catch (SystemException &e)
			{
				if (e.ErrorCode != ERROR_CRC)
				{
					e.Show (ParentWindow);
					Error ("WHOLE_DRIVE_ENCRYPTION_PREVENTED_BY_DRIVERS");
					throw UserAbort (SRC_POS);
				}
			}
		}

		BackupSystemLoader ();

		uint64 volumeSize;
		uint64 encryptedAreaStart;

		if (systemPartitionOnly)
		{
			volumeSize = config.SystemPartition.Info.PartitionLength.QuadPart;
			encryptedAreaStart = config.SystemPartition.Info.StartingOffset.QuadPart;
		}
		else
		{
			volumeSize = config.DrivePartition.Info.PartitionLength.QuadPart - TC_BOOT_LOADER_AREA_SIZE;
			encryptedAreaStart = config.DrivePartition.Info.StartingOffset.QuadPart + TC_BOOT_LOADER_AREA_SIZE;
		}

		SelectedEncryptionAlgorithmId = ea;
		CreateVolumeHeader (volumeSize, encryptedAreaStart, &password, ea, mode, pkcs5);
		
		if (!rescueIsoImagePath.empty())
			CreateRescueIsoImage (true, rescueIsoImagePath);
	}

	bool BootEncryption::IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
	{
		if (!IsAdmin() && IsUacSupported())
			return Elevator::IsPagingFileActive (checkNonWindowsPartitionsOnly) ? true : false;

		return ::IsPagingFileActive (checkNonWindowsPartitionsOnly) ? true : false;
	}

	void BootEncryption::RestrictPagingFilesToSystemPartition ()
	{
		char pagingFiles[128];
		strncpy (pagingFiles, "X:\\pagefile.sys 0 0", sizeof (pagingFiles));
		pagingFiles[0] = GetWindowsDirectory()[0];

		throw_sys_if (!WriteLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", pagingFiles, strlen (pagingFiles) + 2));
	}

	void BootEncryption::WriteLocalMachineRegistryDwordValue (char *keyPath, char *valueName, DWORD value)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::WriteLocalMachineRegistryDwordValue (keyPath, valueName, value);
			return;
		}

		throw_sys_if (!WriteLocalMachineRegistryDword (keyPath, valueName, value));
	}

	void BootEncryption::SetDriverConfigurationFlag (uint32 flag, bool state)
	{
		DWORD configMap = ReadDriverConfigurationFlags();

		if (state)
			configMap |= flag;
		else
			configMap &= ~flag;

		WriteLocalMachineRegistryDwordValue ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, configMap);
	}

	void BootEncryption::StartDecryption (BOOL discardUnreadableEncryptedSectors)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupDecryption;
		request.DiscardUnreadableEncryptedSectors = discardUnreadableEncryptedSectors;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::StartEncryption (WipeAlgorithmId wipeAlgorithm, bool zeroUnreadableSectors)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupEncryption;
		request.WipeAlgorithm = wipeAlgorithm;
		request.ZeroUnreadableSectors = zeroUnreadableSectors;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::CopyFileAdmin (const string &sourceFile, const string &destinationFile)
	{
		if (!IsAdmin())
		{
			if (!IsUacSupported())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException();
			}
			else
				Elevator::CopyFile (sourceFile, destinationFile);
		}
		else
			throw_sys_if (!::CopyFile (sourceFile.c_str(), destinationFile.c_str(), FALSE));
	}

	void BootEncryption::DeleteFileAdmin (const string &file)
	{
		if (!IsAdmin() && IsUacSupported())
			Elevator::DeleteFile (file);
		else
			throw_sys_if (!::DeleteFile (file.c_str()));
	}

#endif // !SETUP

	uint32 BootEncryption::ReadDriverConfigurationFlags ()
	{
		DWORD configMap;

		if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, &configMap))
			configMap = 0;

		return configMap;
	}

	void BootEncryption::WriteBootDriveSector (uint64 offset, byte *data)
	{
		WriteBootDriveSectorRequest request;
		request.Offset.QuadPart = offset;
		memcpy (request.Data, data, sizeof (request.Data));

		CallDriver (TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::RegisterBootDriver (bool hiddenSystem)
	{
		SetDriverServiceStartType (SERVICE_BOOT_START);

		try
		{
			RegisterFilterDriver (false, DriveFilter);
			RegisterFilterDriver (false, VolumeFilter);
			RegisterFilterDriver (false, DumpFilter);
		}
		catch (...) { }

		try
		{
			RegisterFilterDriver (true, DriveFilter);

			if (hiddenSystem)
				RegisterFilterDriver (true, VolumeFilter);

			RegisterFilterDriver (true, DumpFilter);
		}
		catch (...)
		{
			try { RegisterFilterDriver (false, DriveFilter); } catch (...) { }
			try { RegisterFilterDriver (false, VolumeFilter); } catch (...) { }
			try { RegisterFilterDriver (false, DumpFilter); } catch (...) { }
			try { SetDriverServiceStartType (SERVICE_SYSTEM_START); } catch (...) { }

			throw;
		}
	}

	bool BootEncryption::RestartComputer (void)
	{
		return (::RestartComputer() != FALSE);
	}
}
