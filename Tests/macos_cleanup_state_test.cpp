// Exercise cleanup-failure IPC and preserve the released /control wire format.
#include "Volume/VolumeInfo.h"
#include "Core/CoreException.h"
#include "Platform/MemoryStream.h"
#include "Platform/StringConverter.h"
#include <cstring>
#include <iostream>
#include <unistd.h>

using namespace VeraCrypt;

static void Require (bool condition, const char *message)
{
	if (!condition) throw std::runtime_error (message);
}

int main ()
{
	try
	{
		shared_ptr <VolumeInfo> volume (new VolumeInfo);
		volume->EncryptionAlgorithmBlockSize = volume->EncryptionAlgorithmKeySize = volume->EncryptionAlgorithmMinBlockSize = 0;
		volume->HeaderCreationTime = volume->VolumeCreationTime = 0;
		volume->HiddenVolumeProtectionTriggered = volume->SystemEncryption = volume->MasterKeyVulnerable = false;
		volume->MinRequiredProgramVersion = volume->Pkcs5IterationCount = volume->ProgramVersion = 0;
		volume->Protection = VolumeProtection::None;
		volume->SerialInstanceNumber = 123456789;
		volume->Size = volume->TopWriteOffset = volume->TotalDataRead = volume->TotalDataWritten = 0;
		volume->SlotNumber = 7;
		volume->Type = VolumeType::Normal;
		volume->Pim = 0;
		volume->AuxMountPoint = "/private/tmp/unit-aux";
		volume->Path = VolumePath (wstring (L"/private/tmp/unit-container"));
		volume->VirtualDevice = "/dev/disk42";

		shared_ptr <MemoryStream> controlBefore (new MemoryStream), controlAfter (new MemoryStream);
		volume->Serialize (controlBefore);
		volume->Discovery = VolumeInfo::ControlUnavailable;
		volume->Serialize (controlAfter);
		ConstBufferPtr before = *controlBefore, after = *controlAfter;
		Require (before.Size() == after.Size() && memcmp (before.Get(), after.Get(), before.Size()) == 0, "local status changed the legacy control format");
		shared_ptr <Stream> control (new MemoryStream (before));
		Require (Serializable::DeserializeNew <VolumeInfo> (control)->Discovery == VolumeInfo::DiscoveryUnknown, "local hint unexpectedly serialized");

		shared_ptr <VolumeInfo> clone = volume->Clone();
		clone->VirtualDevice = DevicePath();
		clone->Discovery = VolumeInfo::ImageAbsent;
		Require (!volume->VirtualDevice.IsEmpty() && volume->Discovery == VolumeInfo::ControlUnavailable, "clone shared mutable fields");

		// A core helper reports an unconfirmed service exit through the regular exception serializer.
		DismountServiceCleanupFailed failure ("unit", L"pid=1234, auxiliary mount=/private/tmp/unit-aux");
		shared_ptr <Stream> stream (new MemoryStream);
		failure.Serialize (stream);
		shared_ptr <DismountServiceCleanupFailed> restored = Serializable::DeserializeNew <DismountServiceCleanupFailed> (stream);
		Require (restored->GetSubject() == failure.GetSubject() && string (restored->what()) == "unit", "lost cleanup failure details");

		// Wrappers and background logs format errors with ToExceptionString.
		Require (StringConverter::ToExceptionString (*restored).find (failure.GetSubject()) != wstring::npos, "formatting dropped cleanup failure details");
		ExecutedProcessFailed inventory ("unit", "/usr/bin/hdiutil", 7, "inventory-error-detail\n");
		wstring formatted = StringConverter::ToExceptionString (inventory);
		Require (formatted.find (L"/usr/bin/hdiutil (7): inventory-error-detail") != wstring::npos, "formatting dropped subprocess failure details");
		std::cout << "PASS: cleanup failure IPC and formatting, subprocess failure formatting, snapshot independence, unchanged control format\n";
	}
	catch (std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
	return 0;
}
