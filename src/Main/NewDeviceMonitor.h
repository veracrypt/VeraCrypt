/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_NewDeviceMonitor
#define TC_HEADER_Main_NewDeviceMonitor

#include "System.h"

namespace VeraCrypt
{
	// Reports USB and Thunderbolt devices that are connected while it runs and were not connected when it started.
	// A device that is disconnected and connected again is not reported, unless it has no serial number and is
	// connected to another port.
	class NewDeviceMonitor
	{
	public:
		typedef void (*Handler) (const wstring &device);

		NewDeviceMonitor ();
		~NewDeviceMonitor ();

		static bool IsSupported ();
		bool IsRunning () const;
		// The handler can be called on another thread. Throws if the monitor cannot be started.
		void Start (Handler handler);
		void Stop ();

	private:
		struct Impl;
		unique_ptr <Impl> mImpl;

		NewDeviceMonitor (const NewDeviceMonitor &);
		NewDeviceMonitor &operator= (const NewDeviceMonitor &);
	};
}

#endif // TC_HEADER_Main_NewDeviceMonitor
