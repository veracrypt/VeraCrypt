/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include <set>
#include <string.h>
#include "Platform/Platform.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include "NewDeviceMonitor.h"

#ifdef TC_LINUX
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
// GCC 4.4 (CentOS 6) provides the atomic types under the old header name.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 4 && __GNUC_MINOR__ < 5
#include <cstdatomic>
#else
#include <atomic>
#endif
#include <map>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#endif

#ifdef TC_MACOSX
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#endif

namespace VeraCrypt
{
#if defined (TC_LINUX) || defined (TC_MACOSX)
	namespace
	{
		// A device's name must not prevent reporting it: a serial number may not decode in the current locale
		wstring GetDeviceLabel (const string &device)
		{
			try
			{
				return StringConverter::ToWide (device);
			}
			catch (...) { }

			wstring label;
			for (size_t i = 0; i < device.size(); i++)
				label += (device[i] > 0 && device[i] < 0x7f) ? (wchar_t) device[i] : L'?';
			return label;
		}

		void ReportNewDevice (NewDeviceMonitor::Handler handler, const string &device)
		{
			try
			{
				handler (GetDeviceLabel (device));
			}
			catch (...) { }
		}
	}
#endif

#ifdef TC_LINUX
	namespace
	{
		string ReadSysfsAttribute (const string &directory, const char *name)
		{
			ifstream file ((directory + "/" + name).c_str());
			string value;
			getline (file, value);
			return value;
		}

		string GetLastPathComponent (const string &path)
		{
			size_t pos = path.find_last_of ('/');
			return pos == string::npos ? path : path.substr (pos + 1);
		}

		// The vendor, product and serial number of a USB device, or its port if it has no serial number.
		// Returns an empty string if the attributes cannot be read.
		string GetUsbDeviceId (const string &directory)
		{
			string vendor = ReadSysfsAttribute (directory, "idVendor");
			string product = ReadSysfsAttribute (directory, "idProduct");
			if (vendor.empty() || product.empty())
				return string();

			string id = "usb:" + vendor + ":" + product + ":";
			string serial = ReadSysfsAttribute (directory, "serial");
			if (!serial.empty())
				id += serial;
			else
				id += "@" + GetLastPathComponent (directory);

			return id;
		}

		string GetThunderboltDeviceId (const string &directory)
		{
			string uniqueId = ReadSysfsAttribute (directory, "unique_id");
			return uniqueId.empty() ? string() : "thunderbolt:" + uniqueId;
		}

		void AddConnectedDevices (const string &busDirectory, string (*getId) (const string &), std::set <string> &devices)
		{
			DIR *dir = opendir (busDirectory.c_str());
			if (!dir)
				return;

			struct dirent *entry;
			while ((entry = readdir (dir)) != nullptr)
			{
				if (entry->d_name[0] == '.')
					continue;

				// Interfaces and other objects without the attributes are not devices
				string id = getId (busDirectory + "/" + entry->d_name);
				if (!id.empty())
					devices.insert (id);
			}

			closedir (dir);
		}
	}

	struct NewDeviceMonitor::Impl
	{
		Impl () : Socket (-1), Stopped (false)
		{
			StopPipe[0] = StopPipe[1] = -1;
		}

		bool IsAlive () const { return !Stopped; }

		static TC_THREAD_PROC RunWorker (void *impl)
		{
			static_cast <Impl *> (impl)->Run();
			return 0;
		}

		~Impl ()
		{
			if (Socket != -1)
				close (Socket);
			if (StopPipe[0] != -1)
				close (StopPipe[0]);
			if (StopPipe[1] != -1)
				close (StopPipe[1]);
		}

		void Run ()
		{
			vector <char> buffer (64 * 1024);

			while (true)
			{
				struct pollfd fds[2];
				fds[0].fd = Socket;
				fds[0].events = POLLIN;
				fds[0].revents = 0;
				fds[1].fd = StopPipe[0];
				fds[1].events = POLLIN;
				fds[1].revents = 0;

				if (poll (fds, 2, -1) == -1)
				{
					if (errno == EINTR)
						continue;
					Fail();
					return;
				}

				if (fds[1].revents)
				{
					Stopped = true;
					return;
				}

				struct sockaddr_nl sender;
				socklen_t senderSize = sizeof (sender);
				ssize_t size = recvfrom (Socket, &buffer[0], buffer.size() - 1, 0, (struct sockaddr *) &sender, &senderSize);
				if (size < 0)
				{
					if (errno == EINTR || errno == EAGAIN)
						continue;

					// Events were lost: compare the devices connected now with those connected at start
					if (errno == ENOBUFS)
					{
						std::set <string> connected;
						AddConnectedDevices ("/sys/bus/usb/devices", GetUsbDeviceId, connected);
						AddConnectedDevices ("/sys/bus/thunderbolt/devices", GetThunderboltDeviceId, connected);
						foreach (const string &id, connected)
						{
							if (Known.find (id) == Known.end())
								ReportNewDevice (OnNewDevice, id);
						}
						continue;
					}

					Fail();
					return;
				}

				// Only the kernel reports devices on this group
				if (senderSize != sizeof (sender) || sender.nl_pid != 0)
					continue;

				buffer[size] = 0;

				// "<action>@<devpath>" followed by NUL-terminated KEY=VALUE pairs
				map <string, string> event;
				for (size_t pos = strlen (&buffer[0]) + 1; pos < (size_t) size; pos += strlen (&buffer[pos]) + 1)
				{
					const char *pair = &buffer[pos];
					const char *equal = strchr (pair, '=');
					if (equal)
						event[string (pair, equal - pair)] = equal + 1;
				}

				if (event["ACTION"] != "add" || event["DEVPATH"].empty())
					continue;

				const string directory = "/sys" + event["DEVPATH"];
				string id;

				if (event["SUBSYSTEM"] == "usb" && event["DEVTYPE"] == "usb_device")
				{
					id = GetUsbDeviceId (directory);
					if (id.empty())
						id = "usb:" + event["DEVPATH"];
				}
				else if (event["SUBSYSTEM"] == "thunderbolt" && event["DEVTYPE"] == "thunderbolt_device")
				{
					id = GetThunderboltDeviceId (directory);
					if (id.empty())
						id = "thunderbolt:" + event["DEVPATH"];
				}
				else
					continue;

				if (Known.find (id) == Known.end())
					ReportNewDevice (OnNewDevice, id);
			}
		}

		// Not monitoring from here on, which the handler can already see: it starts the monitor again
		void Fail ()
		{
			Stopped = true;
			ReportNewDevice (OnNewDevice, "(device monitoring failed)");
		}

		int Socket;
		int StopPipe[2];
		std::atomic <bool> Stopped;
		Thread Worker;
		std::set <string> Known;
		Handler OnNewDevice;
	};

	bool NewDeviceMonitor::IsSupported ()
	{
		return true;
	}

	void NewDeviceMonitor::Start (Handler handler)
	{
		if (IsRunning())
			return;

		// A worker that stopped after a failure
		Stop();

		unique_ptr <Impl> impl (new Impl);
		impl->OnNewDevice = handler;

		// Listen before taking the list of connected devices, so that no device can be connected in between unseen
		impl->Socket = socket (AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
		throw_sys_if (impl->Socket == -1);

		int bufferSize = 1024 * 1024;
		setsockopt (impl->Socket, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof (bufferSize));

		struct sockaddr_nl address;
		memset (&address, 0, sizeof (address));
		address.nl_family = AF_NETLINK;
		address.nl_groups = 1; // Kernel events
		throw_sys_if (bind (impl->Socket, (struct sockaddr *) &address, sizeof (address)) == -1);

		throw_sys_if (pipe2 (impl->StopPipe, O_CLOEXEC) == -1);

		AddConnectedDevices ("/sys/bus/usb/devices", GetUsbDeviceId, impl->Known);
		AddConnectedDevices ("/sys/bus/thunderbolt/devices", GetThunderboltDeviceId, impl->Known);

		impl->Worker.Start (Impl::RunWorker, impl.get());
		mImpl.reset (impl.release());
	}

	void NewDeviceMonitor::Stop ()
	{
		if (!mImpl.get())
			return;

		while (write (mImpl->StopPipe[1], "", 1) == -1 && errno == EINTR)
			continue;

		mImpl->Worker.Join();
		mImpl.reset();
	}

#elif defined (TC_MACOSX)

	namespace
	{
		bool GetNumberProperty (io_service_t service, CFStringRef name, uint64 &value)
		{
			CFTypeRef property = IORegistryEntryCreateCFProperty (service, name, kCFAllocatorDefault, 0);
			if (!property)
				return false;

			bool result = false;
			long long number;
			if (CFGetTypeID (property) == CFNumberGetTypeID() && CFNumberGetValue ((CFNumberRef) property, kCFNumberLongLongType, &number))
			{
				value = (uint64) number;
				result = true;
			}

			CFRelease (property);
			return result;
		}

		string GetStringProperty (io_service_t service, CFStringRef name)
		{
			CFTypeRef property = IORegistryEntryCreateCFProperty (service, name, kCFAllocatorDefault, 0);
			if (!property)
				return string();

			string result;
			char value[512];
			if (CFGetTypeID (property) == CFStringGetTypeID() && CFStringGetCString ((CFStringRef) property, value, sizeof (value), kCFStringEncodingUTF8))
				result = value;

			CFRelease (property);
			return result;
		}

		// The vendor, product and serial number of a USB device, or its location if it has no serial number.
		// A Thunderbolt device by its UID. Otherwise, the registry entry, which changes when the device is connected again.
		string GetDeviceId (io_service_t service)
		{
			uint64 vendor, product, location, uid;
			if (GetNumberProperty (service, CFSTR ("idVendor"), vendor) && GetNumberProperty (service, CFSTR ("idProduct"), product))
			{
				string id = "usb:" + StringConverter::ToSingle (vendor) + ":" + StringConverter::ToSingle (product) + ":";

				string serial = GetStringProperty (service, CFSTR ("USB Serial Number"));
				if (serial.empty())
					serial = GetStringProperty (service, CFSTR ("kUSBSerialNumberString"));

				if (!serial.empty())
					id += serial;
				else if (GetNumberProperty (service, CFSTR ("locationID"), location))
					id += "@" + StringConverter::ToSingle (location);

				return id;
			}

			if (GetNumberProperty (service, CFSTR ("UID"), uid))
				return "thunderbolt:" + StringConverter::ToSingle (uid);

			uint64 entryId = 0;
			IORegistryEntryGetRegistryEntryID (service, &entryId);
			return "registry:" + StringConverter::ToSingle (entryId);
		}
	}

	struct NewDeviceMonitor::Impl
	{
		Impl () : Port (nullptr), Reporting (false) { }

		bool IsAlive () const { return true; }

		~Impl ()
		{
			foreach (io_iterator_t iterator, Iterators)
				IOObjectRelease (iterator);

			if (Port)
			{
				CFRunLoopRemoveSource (CFRunLoopGetMain(), IONotificationPortGetRunLoopSource (Port), kCFRunLoopCommonModes);
				IONotificationPortDestroy (Port);
			}
		}

		// Called on the main thread by the run loop. The notification is armed again only once the iterator is emptied.
		static void OnMatched (void *context, io_iterator_t iterator)
		{
			static_cast <Impl *> (context)->Drain (iterator);
		}

		void Drain (io_iterator_t iterator)
		{
			io_service_t service;
			while ((service = IOIteratorNext (iterator)) != 0)
			{
				string id = GetDeviceId (service);
				IOObjectRelease (service);

				if (!Reporting)
					Known.insert (id);
				else if (Known.find (id) == Known.end())
					ReportNewDevice (OnNewDevice, id);
			}
		}

		IONotificationPortRef Port;
		list <io_iterator_t> Iterators;
		std::set <string> Known;
		Handler OnNewDevice;
		bool Reporting;
	};

	bool NewDeviceMonitor::IsSupported ()
	{
		return true;
	}

	void NewDeviceMonitor::Start (Handler handler)
	{
		if (IsRunning())
			return;

		unique_ptr <Impl> impl (new Impl);
		impl->OnNewDevice = handler;

		impl->Port = IONotificationPortCreate (MACH_PORT_NULL);
		if (!impl->Port)
			throw SystemException (SRC_POS, "IONotificationPortCreate");

		CFRunLoopAddSource (CFRunLoopGetMain(), IONotificationPortGetRunLoopSource (impl->Port), kCFRunLoopCommonModes);

		// The first notifications list the devices connected now. Thunderbolt devices can access memory directly.
		const char *classes[] = { "IOUSBHostDevice", "IOUSBDevice", "IOThunderboltSwitch" };
		for (size_t i = 0; i < array_capacity (classes); i++)
		{
			const char *className = classes[i];
			io_iterator_t iterator = 0;
			// IOServiceMatching's dictionary is consumed by the call
			kern_return_t result = IOServiceAddMatchingNotification (impl->Port, kIOFirstMatchNotification,
				IOServiceMatching (className), Impl::OnMatched, impl.get(), &iterator);

			if (result != KERN_SUCCESS)
				throw SystemException (SRC_POS, string ("IOServiceAddMatchingNotification: ") + className);

			impl->Iterators.push_back (iterator);
			impl->Drain (iterator);
		}

		impl->Reporting = true;
		mImpl.reset (impl.release());
	}

	void NewDeviceMonitor::Stop ()
	{
		mImpl.reset();
	}

#else

	struct NewDeviceMonitor::Impl
	{
		bool IsAlive () const { return false; }
	};

	bool NewDeviceMonitor::IsSupported ()
	{
		return false;
	}

	void NewDeviceMonitor::Start (Handler handler)
	{
		throw NotApplicable (SRC_POS);
	}

	void NewDeviceMonitor::Stop ()
	{
	}

#endif

	NewDeviceMonitor::NewDeviceMonitor ()
	{
	}

	NewDeviceMonitor::~NewDeviceMonitor ()
	{
		Stop();
	}

	bool NewDeviceMonitor::IsRunning () const
	{
		return mImpl.get() != nullptr && mImpl->IsAlive();
	}
}
