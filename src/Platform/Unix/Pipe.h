/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Unix_Pipe
#define TC_HEADER_Platform_Unix_Pipe

#include "Platform/PlatformBase.h"

namespace TrueCrypt
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
