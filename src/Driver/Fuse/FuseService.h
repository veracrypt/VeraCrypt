/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Driver_Fuse_FuseService
#define TC_HEADER_Driver_Fuse_FuseService

#include "Platform/Platform.h"
#include "Platform/Unix/Pipe.h"
#include "Platform/Unix/Process.h"
#include "Volume/VolumeInfo.h"
#include "Volume/Volume.h"

namespace VeraCrypt
{

	class FuseService
	{
	protected:
		struct ExecFunctor : public ProcessExecFunctor
		{
			ExecFunctor (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, uint64 serialInstanceNumber)
				:
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
				StartupFd (-1), StartupPeerFd (-1),
#endif
				MountedVolume (openVolume), SlotNumber (slotNumber), SerialInstanceNumber (serialInstanceNumber)
			{
			}
			virtual void operator() (int argc, char *argv[]);

#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
			int StartupFd;
			int StartupPeerFd;
#endif

		protected:
			shared_ptr <Volume> MountedVolume;
			VolumeSlotNumber SlotNumber;
			uint64 SerialInstanceNumber;
		};

		friend struct ExecFunctor;

	public:
		static bool AuxDeviceInfoReceived () { return !OpenVolumeInfo.VirtualDevice.IsEmpty(); }
		static bool CheckAccessRights ();
		static void Dismount ();
		static int ExceptionToErrorCode ();
		static const char *GetAuxDeviceInfoPath () { return "/aux-device-info"; }
		static const char *GetControlPath () { return "/control"; }
		static const char *GetVolumeImagePath ();
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		static const char *GetShutdownPath () { return "/shutdown"; }
		static const char *GetShutdownSocketPath () { return "/shutdown-socket"; }
#endif
		static string GetDeviceType () { return "veracrypt"; }
		static gid_t GetGroupId () { return GroupId; }
		static uid_t GetUserId () { return UserId; }
		static uint64 GetSerialInstanceNumber () { return OpenVolumeInfo.SerialInstanceNumber; }
		static VolumeSlotNumber GetSlotNumber () { return SlotNumber; }
		static shared_ptr <Buffer> GetAuxDeviceInfo ();
		static shared_ptr <Buffer> GetVolumeInfo ();
		static uint64 GetVolumeSize ();
		static uint64 GetVolumeSectorSize () { return MountedVolume->GetSectorSize(); }
		static uint64 Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint);
		static void ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset);
		static void ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer);
		static void SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice = DevicePath());
#if defined(TC_MACOSX) && defined(VC_MACOSX_FUSET)
		struct DismountRequest
		{
			pid_t ProcessId;
			uint64 ProcessStartTime;
			uint64 SerialInstanceNumber;
			VolumeSlotNumber SlotNumber;
			bool IgnoreOpenFiles;
			bool LegacyService;
			string SocketDirectory;
			string AuxMountPoint;
			int32 MountId[2];
		};

		static DismountRequest PrepareDismount (const DirectoryPath &fuseMountPoint, uint64 serialInstanceNumber, VolumeSlotNumber slotNumber, bool ignoreOpenFiles);
		static pid_t RequestDismount (const DismountRequest &request);
		static bool IsDismountMountPresent (const DismountRequest &request);
		static void DismountLegacy (const DismountRequest &request);
		static void WaitForDismount (pid_t processId, const DirectoryPath &fuseMountPoint, VolumeSlotNumber slotNumber, int timeOut = 10000, uint64 processStartTime = 0);
#endif
		static void WriteVolumeSectors (const ConstBufferPtr &buffer, uint64 byteOffset);

	protected:
		FuseService ();
		static void CloseMountedVolume ();
		static void OnSignal (int signal);

		static VolumeInfo OpenVolumeInfo;
		static Mutex OpenVolumeInfoMutex;
		static shared_ptr <Volume> MountedVolume;
		static VolumeSlotNumber SlotNumber;
		static uid_t UserId;
		static gid_t GroupId;
		static unique_ptr <Pipe> SignalHandlerPipe;
	};
}

#endif // TC_HEADER_Driver_Fuse_FuseService
