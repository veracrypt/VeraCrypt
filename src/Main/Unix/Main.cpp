/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include <sys/mman.h>

#include "Platform/Platform.h"
#include "Platform/SystemLog.h"
#include "Volume/EncryptionThreadPool.h"
#include "Core/Unix/CoreService.h"
#include "Main/Application.h"
#include "Main/Main.h"
#include "Main/UserInterface.h"

#if defined (TC_MACOSX) && !defined (TC_NO_GUI)
#include <ApplicationServices/ApplicationServices.h>
#endif

using namespace TrueCrypt;

int main (int argc, char **argv)
{
	try
	{
		// Make sure all required commands can be executed via default search path
		string sysPathStr = "/usr/sbin:/sbin:/usr/bin:/bin";
		
		char *sysPath = getenv ("PATH");
		if (sysPath)
		{
			sysPathStr += ":";
			sysPathStr += sysPath;
		}

		setenv ("PATH", sysPathStr.c_str(), 1);

		if (argc > 1 && strcmp (argv[1], TC_CORE_SERVICE_CMDLINE_OPTION) == 0)
		{
			// Process elevated requests
			try
			{
				CoreService::ProcessElevatedRequests();
				return 0;
			}
			catch (exception &e)
			{
#ifdef DEBUG
				SystemLog::WriteException (e);
#endif
			}
			catch (...)	{ }
			return 1;
		}

		// Start core service
		CoreService::Start();
		finally_do ({ CoreService::Stop(); });

		// Start encryption thread pool
		EncryptionThreadPool::Start();
		finally_do ({ EncryptionThreadPool::Stop(); });

#ifdef TC_NO_GUI
		bool forceTextUI = true;
#else
		bool forceTextUI = false;
#endif

#ifdef __WXGTK__
		if (!getenv ("DISPLAY"))
			forceTextUI = true;
#endif

		// Initialize application
		if (forceTextUI || (argc > 1 && (strcmp (argv[1], "-t") == 0 || strcmp (argv[1], "--text") == 0)))
		{
			Application::Initialize (UserInterfaceType::Text);
		}
		else
		{
#if defined (TC_MACOSX) && !defined (TC_NO_GUI)
			if (argc > 1 && !(argc == 2 && strstr (argv[1], "-psn_") == argv[1]))
			{
				ProcessSerialNumber p;
				if (GetCurrentProcess (&p) == noErr)
				{
					TransformProcessType (&p, kProcessTransformToForegroundApplication);
					SetFrontProcess (&p);
				}
			}
#endif
			Application::Initialize (UserInterfaceType::Graphic);
		}

		Application::SetExitCode (1);

		// Start application
		if (::wxEntry (argc, argv) == 0)
			Application::SetExitCode (0);
	}
	catch (ErrorMessage &e)
	{
		wcerr << wstring (e) << endl;
	}
	catch (SystemException &e)
	{
		wstringstream s;
		if (e.GetSubject().empty())
			s << e.what() << endl << e.SystemText();
		else
			s << e.what() << endl << e.SystemText() << endl << e.GetSubject();
		wcerr << s.str() << endl;
	}
	catch (exception &e)
	{
		stringstream s;
		s << StringConverter::GetTypeName (typeid (e)) << endl << e.what();
		cerr << s.str() << endl;
	}

	return Application::GetExitCode();
}
