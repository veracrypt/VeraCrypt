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

#ifndef TC_HEADER_Platform_Unix_Poller
#define TC_HEADER_Platform_Unix_Poller

#include "Platform/PlatformBase.h"

namespace VeraCrypt
{
	class Poller
	{
	public:
		Poller (int fileDescriptor1, int fileDescriptor2 = -1, int fileDescriptor3 = -1, int fileDescriptor4 = -1);
		virtual ~Poller () { }

		list <int> WaitForData (int timeOut = -1) const;

	protected:
		vector <int> FileDescriptors;

	private:
		Poller (const Poller &);
		Poller &operator= (const Poller &);
	};
}

#endif // TC_HEADER_Platform_Unix_Poller
