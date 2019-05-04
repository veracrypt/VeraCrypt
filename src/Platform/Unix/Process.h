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

#ifndef TC_HEADER_Platform_Unix_Process
#define TC_HEADER_Platform_Unix_Process

#include "Platform/PlatformBase.h"
#include "Platform/Buffer.h"
#include "Platform/Functor.h"

namespace VeraCrypt
{
	struct ProcessExecFunctor
	{
		virtual ~ProcessExecFunctor () { }
		virtual void operator() (int argc, char *argv[]) = 0;
	};

	class Process
	{
	public:
		Process ();
		virtual ~Process ();

		static string Execute (const string &processName, const list <string> &arguments, int timeOut = -1, ProcessExecFunctor *execFunctor = nullptr, const Buffer *inputData = nullptr);

	protected:

	private:
		Process (const Process &);
		Process &operator= (const Process &);
	};
}

#endif // TC_HEADER_Platform_Unix_Process
