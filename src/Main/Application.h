/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_AppMain
#define TC_HEADER_Main_AppMain

#include "Main.h"
#include "UserInterface.h"
#include "UserInterfaceType.h"

namespace VeraCrypt
{
	class Application
	{
	public:
		static wxApp* CreateConsoleApp ();
		static wxApp* CreateGuiApp ();
		static FilePath GetConfigFilePath (const wxString &configFileName, bool createConfigDir = false);
		static DirectoryPath GetExecutableDirectory ();
		static FilePath GetExecutablePath ();
		static int GetExitCode () { return ExitCode; }
		static wstring GetName () { return L"VeraCrypt"; }
		static UserInterface *GetUserInterface () { return mUserInterface; }
		static UserInterfaceType::Enum GetUserInterfaceType () { return mUserInterfaceType; }
		static void Initialize (UserInterfaceType::Enum type);
		static void SetExitCode (int code) { ExitCode = code; }

	protected:
		static int ExitCode;
		static UserInterface *mUserInterface;
		static UserInterfaceType::Enum mUserInterfaceType;
	};
}

#endif // TC_HEADER_Main_AppMain
