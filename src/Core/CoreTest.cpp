/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0, the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source distributions.
*/

#include "CoreTest.h"
#include "HostDevice.h"
#include "Platform/MemoryStream.h"
#include "Unix/CoreServiceRequest.h"
#include "Volume/VolumePassword.h"

namespace VeraCrypt
{
	void CoreTest::HostDeviceTest ()
	{
		HostDevice device;
		device.Name = L"Device";
		device.SystemNumber = 0;
		shared_ptr <HostDevice> partition (new HostDevice);
		partition->Name = L"Partition";
		partition->SystemNumber = 1;
		device.Partitions.push_back (partition);

		// Exercise real parent/child serialization at the nesting boundary using a
		// shallow tree and reserved scopes, without constructing a deep input tree.
		for (int attempt = 0; attempt < 2; ++attempt)
		{
			shared_ptr <Stream> stream (new MemoryStream);
			vector < shared_ptr <SerializationScope> > scopes;
			if (attempt != 0)
			{
				for (unsigned int i = 0; i < Serializer::MaxNestingDepth - 2; ++i)
					scopes.push_back (shared_ptr <SerializationScope> (new SerializationScope (stream)));
			}
			device.Serialize (stream);
			shared_ptr <HostDevice> result = Serializable::DeserializeNew <HostDevice> (stream);
			if (result->Name != device.Name || result->Partitions.size() != 1
				|| result->Partitions.front()->Name != partition->Name
				|| result->Partitions.front()->SystemNumber != partition->SystemNumber)
				throw TestFailed (SRC_POS);
		}

		for (int direction = 0; direction < 2; ++direction)
		{
			shared_ptr <Stream> stream (new MemoryStream);
			device.Serialize (stream);
			vector < shared_ptr <SerializationScope> > scopes;
			for (unsigned int i = 0; i < Serializer::MaxNestingDepth - 1; ++i)
				scopes.push_back (shared_ptr <SerializationScope> (new SerializationScope (stream)));
			try
			{
				if (direction == 0)
					Serializable::DeserializeNew <HostDevice> (stream);
				else
					device.Serialize (stream);
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }
			scopes.clear();
			SerializationScope reusable (stream);
		}

		device.Partitions.assign ((size_t) Serializer::MaxCollectionSize + 1, partition);
		try
		{
			shared_ptr <Stream> stream (new MemoryStream);
			device.Serialize (stream);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
	}

	void CoreTest::VolumePasswordTest ()
	{
		SecureBuffer password (VolumePassword::MaxSize);
		for (size_t i = 0; i < password.Size(); ++i)
			password[i] = (uint8) i;
		const size_t sizes[] = { 0, VolumePassword::MaxLegacySize, VolumePassword::MaxSize };
		for (size_t i = 0; i < array_capacity (sizes); ++i)
		{
			shared_ptr <Stream> stream (new MemoryStream);
			VolumePassword original (password.Ptr(), sizes[i]);
			original.Serialize (stream);
			shared_ptr <VolumePassword> result = Serializable::DeserializeNew <VolumePassword> (stream);
			if (*result != original)
				throw TestFailed (SRC_POS);
		}

		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);
		Serializable::SerializeHeader (sr, "VolumePassword");
		sr.Serialize ("PasswordSize", (uint64) VolumePassword::MaxSize + 1);
		try
		{
			Serializable::DeserializeNew <VolumePassword> (stream);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		try
		{
			VolumePassword invalid (password.Ptr(), VolumePassword::MaxSize + 1);
			throw TestFailed (SRC_POS);
		}
		catch (PasswordTooLong &) { }
	}

	void CoreTest::ServiceRequestTest ()
	{
		shared_ptr <Stream> stream (new MemoryStream);
		GetDeviceSizeRequest request (DevicePath (L"/dev/test"));
		request.Serialize (stream);
		shared_ptr <CoreServiceRequest> result = Serializable::DeserializeNew <CoreServiceRequest> (stream);
		GetDeviceSizeRequest *deviceRequest = dynamic_cast <GetDeviceSizeRequest *> (result.get());
		if (!deviceRequest || deviceRequest->Path != request.Path)
			throw TestFailed (SRC_POS);
	}

	void CoreTest::TestAll ()
	{
		HostDeviceTest();
		VolumePasswordTest();
		ServiceRequestTest();
	}
}
