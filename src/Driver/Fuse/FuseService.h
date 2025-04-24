/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
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
		class ExecFunctor : public ProcessExecFunctor
		{
		public:
			ExecFunctor (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber)
				: MountedVolume (openVolume), SlotNumber (slotNumber)
			{
			}
			virtual void operator() (int argc, char *argv[]);

		protected:
			shared_ptr <Volume> MountedVolume;
			VolumeSlotNumber SlotNumber;
		};

		friend class ExecFunctor;

	public:
		static bool AuxDeviceInfoReceived () { return !OpenVolumeInfo.VirtualDevice.IsEmpty(); }
		static bool CheckAccessRights ();
		static void Dismount ();
		static int ExceptionToErrorCode ();
		static const char *GetControlPath () { return "/control"; }
		static const char *GetVolumeImagePath ();
		static string GetDeviceType () { return "veracrypt"; }
		static uid_t GetGroupId () { return GroupId; }
		static uid_t GetUserId () { return UserId; }
		static shared_ptr <Buffer> GetVolumeInfo ();
		static uint64 GetVolumeSize ();
		static uint64 GetVolumeSectorSize () { return MountedVolume->GetSectorSize(); }
		static void Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint);
		static void ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset);
		static void ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer);
		static void SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice = DevicePath());
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
