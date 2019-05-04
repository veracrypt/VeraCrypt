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

#ifndef TC_HEADER_Platform_SystemLog
#define TC_HEADER_Platform_SystemLog

#include "Platform/PlatformBase.h"
#include "Platform/StringConverter.h"

namespace VeraCrypt
{
	class SystemLog
	{
	public:
		static void WriteDebug (const string &debugMessage);
		static void WriteError (const string &errorMessage);

		static void WriteException (const exception &ex)
		{
			WriteError (string ("exception: ") + StringConverter::ToSingle (StringConverter::ToExceptionString (ex)));
		}

	protected:
		SystemLog ();
	};

#ifdef DEBUG
#	define tracelog_point do { stringstream s; s << (SRC_POS); SystemLog::WriteError (s.str()); } while (false)
#	define tracelog_msg(stream_args) do { stringstream s; s << (SRC_POS) << ": " << stream_args; SystemLog::WriteError (s.str()); } while (false)
#else
#	define tracelog_point
#	define tracelog_msg(stream_args) while (false) { stringstream s; s << stream_args; }
#endif

}

#endif // TC_HEADER_Platform_SystemLog
