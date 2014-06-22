/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <unistd.h>
#include "Pipe.h"
#include "Platform/SystemException.h"

namespace VeraCrypt
{
	Pipe::Pipe ()
	{
		int fd[2];
		throw_sys_if (pipe (fd) == -1);
		ReadFileDescriptor = fd[0];
		WriteFileDescriptor = fd[1];
	}

	Pipe::~Pipe ()
	{
		try
		{
			Close();
		}
		catch (...) { }
	}

	void Pipe::Close ()
	{
		if (ReadFileDescriptor != -1)
			close (ReadFileDescriptor);
		if (WriteFileDescriptor != -1)
			close (WriteFileDescriptor);
	}

	int Pipe::GetReadFD ()
	{
		assert (ReadFileDescriptor != -1);
		
		if (WriteFileDescriptor != -1)
		{
			close (WriteFileDescriptor);
			WriteFileDescriptor = -1;
		}

		return ReadFileDescriptor;
	}

	int Pipe::GetWriteFD ()
	{
		assert (WriteFileDescriptor != -1);

		if (ReadFileDescriptor != -1)
		{
			close (ReadFileDescriptor);
			ReadFileDescriptor = -1;
		}

		return WriteFileDescriptor;
	}
}
