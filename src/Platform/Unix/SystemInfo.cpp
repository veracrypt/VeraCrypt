/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/SystemException.h"
#include "Platform/SystemInfo.h"
#include <sys/utsname.h>

namespace VeraCrypt
{
	wstring SystemInfo::GetPlatformName ()
	{
#ifdef TC_LINUX
		return L"Linux";
#elif defined (TC_MACOSX)
		return L"Mac OS X";
#elif defined (TC_FREEBSD)
		return L"FreeBSD";
#elif defined (TC_SOLARIS)
		return L"Solaris";
#else
#	error GetPlatformName() undefined
#endif

	}

	vector <int> SystemInfo::GetVersion ()
	{
		struct utsname unameData;
		throw_sys_if (uname (&unameData) == -1);

		vector <string> versionStrings = StringConverter::Split (unameData.release, ".");
		vector <int> version;

		for (size_t i = 0; i < versionStrings.size(); ++i)
		{
			string s = versionStrings[i];

			size_t p = s.find_first_not_of ("0123456789");
			if (p != string::npos)
				s = s.substr (0, p);

			if (s.empty())
				break;

			version.push_back (StringConverter::ToUInt32 (s));
		}

		return version;
	}

	bool SystemInfo::IsVersionAtLeast (int versionNumber1, int versionNumber2, int versionNumber3)
	{
		vector <int> osVersionNumbers = GetVersion();

		if (osVersionNumbers.size() < 2)
			throw ParameterIncorrect (SRC_POS);

		if (osVersionNumbers.size() < 3)
			osVersionNumbers[2] = 0;

		return (osVersionNumbers[0] * 10000000 +  osVersionNumbers[1] * 10000 + osVersionNumbers[2]) >=
			(versionNumber1 * 10000000 +  versionNumber2 * 10000 + versionNumber3);
	}
}
