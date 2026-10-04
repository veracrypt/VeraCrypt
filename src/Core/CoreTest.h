/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0, the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source distributions.
*/

#ifndef TC_HEADER_Core_CoreTest
#define TC_HEADER_Core_CoreTest

namespace VeraCrypt
{
	class CoreTest
	{
	public:
		static void TestAll ();

	private:
		CoreTest ();
		static void HostDeviceTest ();
		static void VolumePasswordTest ();
		static void ServiceRequestTest ();
	};
}

#endif // TC_HEADER_Core_CoreTest
