/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_Unix_Pipe
#define TC_HEADER_Platform_Unix_Pipe

#include "Platform/PlatformBase.h"

namespace VeraCrypt
{
	class Pipe
	{
	public:
		Pipe ();
		virtual ~Pipe ();

		void Close ();
		int GetReadFD ();
		int GetWriteFD ();
		int PeekReadFD () const { return ReadFileDescriptor; }
		int PeekWriteFD () const { return WriteFileDescriptor; }

	protected:
		int ReadFileDescriptor;
		int WriteFileDescriptor;

	private:
		Pipe (const Pipe &);
		Pipe &operator= (const Pipe &);
	};
}

#endif // TC_HEADER_Platform_Unix_Pipe
