/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <poll.h>
#include <unistd.h>
#include "Poller.h"
#include "Platform/SystemException.h"

namespace VeraCrypt
{
	Poller::Poller (int fileDescriptor1, int fileDescriptor2, int fileDescriptor3, int fileDescriptor4)
	{
		FileDescriptors.push_back (fileDescriptor1);

		if (fileDescriptor2 != -1)
			FileDescriptors.push_back (fileDescriptor2);

		if (fileDescriptor3 != -1)
			FileDescriptors.push_back (fileDescriptor3);

		if (fileDescriptor4 != -1)
			FileDescriptors.push_back (fileDescriptor4);
	}

	list <int> Poller::WaitForData (int timeOut) const
	{
		vector <pollfd> pfd (FileDescriptors.size());
		for (size_t i = 0; i < FileDescriptors.size(); i++)
		{
			pfd[i].fd = FileDescriptors[i];
			pfd[i].events = POLLIN;
		}

		list <int> descList;

		int pollRes = poll (&pfd[0], pfd.size(), timeOut);

		if (pollRes == 0 && timeOut != -1)
			throw TimeOut (SRC_POS);

		if (pollRes > 0)
		{
			for (size_t i = 0; i < pfd.size(); i++)
			{
				if (pfd[i].revents & POLLIN)
					descList.push_back (pfd[i].fd);
			}
		}

		return descList;
	}
}
