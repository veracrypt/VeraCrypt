/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <syslog.h>
#include "Platform/SystemLog.h"

namespace VeraCrypt
{
	void SystemLog::WriteDebug (const string &debugMessage)
	{
		openlog ("veracrypt", LOG_PID, LOG_USER);
		syslog (LOG_DEBUG, "%s", debugMessage.c_str());
		closelog();
	}

	void SystemLog::WriteError (const string &errorMessage)
	{
		openlog ("veracrypt", LOG_PID, LOG_USER);
		syslog (LOG_ERR, "%s", errorMessage.c_str());
		closelog();
	}
}
