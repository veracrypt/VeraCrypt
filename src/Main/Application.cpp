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

#include "System.h"
#include <wx/stdpaths.h>
#include "Main.h"
#include "Application.h"
#include "CommandLineInterface.h"
#ifndef TC_NO_GUI
#include "GraphicUserInterface.h"
#endif
#include "TextUserInterface.h"

namespace VeraCrypt
{
	namespace
	{
		void EnsureEndsWithPathSeparator( wxString &s )
		{
			const wxUniChar pathSeparator = wxFileName::GetPathSeparator();
			if (s[s.size() - 1] != pathSeparator)
				s.append(pathSeparator);
		}

		wxString *GetXdgConfigPath ()
		{
			const wxChar *xdgConfig = wxGetenv(wxT("XDG_CONFIG_HOME"));
			wxString *configDir;

			if (!wxIsEmpty(xdgConfig))
			{
				configDir = new wxString (xdgConfig);
				//wcerr << L"XDG_CONFIG_HOME=" << *configDir << endl;
				EnsureEndsWithPathSeparator(*configDir);
				configDir->append(Application::GetName());
			}
			else
			{
				#if !defined(TC_UNIX) || defined(TC_MACOSX) // Windows, OS X:
					configDir =
						new wxString (wxStandardPaths::Get().GetUserDataDir());
				#else // Linux, FreeBSD, Solaris:
					configDir = new wxString (wxFileName::GetHomeDir());
					configDir->append(wxT("/.config/"));
					configDir->append(Application::GetName());

					if (!wxDirExists(*configDir))
					{
						wxString legacyConfigDir = wxStandardPaths::Get().GetUserDataDir();
						//wcerr << L"Legacy config dir: " << legacyConfigDir << endl;
						if (wxDirExists(legacyConfigDir))
						{
							configDir->swap(legacyConfigDir);
						}
					}
				#endif
			}

			//wcerr << L"Config dir: " << *configDir << endl;
			return configDir;
		}
	}

	wxApp* Application::CreateConsoleApp ()
	{
		mUserInterface = new TextUserInterface;
		mUserInterfaceType = UserInterfaceType::Text;
		return mUserInterface;
	}

#ifndef TC_NO_GUI
	wxApp* Application::CreateGuiApp ()
	{
		mUserInterface = new GraphicUserInterface;
		mUserInterfaceType = UserInterfaceType::Graphic;
		wxSetEnv("WXSUPPRESS_SIZER_FLAGS_CHECK", "1");
		return mUserInterface;
	}
#endif

	FilePath Application::GetConfigFilePath (const wxString &configFileName, bool createConfigDir)
	{
		static std::unique_ptr<const wxString> configDirC;
		static bool configDirExists = false;

		if (!configDirExists)
		{
			if (!configDirC)
			{
				wxString *configDir;

				if (Core->IsInPortableMode())
				{
					configDir = new wxString (
						wxPathOnly(wxStandardPaths::Get().GetExecutablePath()));
				}
				else
				{
					configDir = GetXdgConfigPath();
				}

				EnsureEndsWithPathSeparator(*configDir);
				configDirC.reset(configDir);
			}

			if (createConfigDir)
			{
				if (!wxDirExists(*configDirC))
				{
					//wcerr << L"Creating config dir »" << *configDirC << L"« ..." << endl;
					throw_sys_sub_if(
						!wxMkdir(*configDirC, wxS_IRUSR | wxS_IWUSR | wxS_IXUSR),
						configDirC->ToStdWstring());
				}
				configDirExists = true;
				//wcerr << L"Config directory »" << *configDirC << L"« exists now" << endl;
			}
		}

		return FilePath((*configDirC + configFileName).ToStdWstring());
	}

	DirectoryPath Application::GetExecutableDirectory ()
	{
		return wstring (wxFileName (wxStandardPaths::Get().GetExecutablePath()).GetPath());
	}

	FilePath Application::GetExecutablePath ()
	{
		return wstring (wxStandardPaths::Get().GetExecutablePath());
	}

	void Application::Initialize (UserInterfaceType::Enum type)
	{
		switch (type)
		{
		case UserInterfaceType::Text:
			{
				wxAppInitializer wxTheAppInitializer((wxAppInitializerFunction) CreateConsoleApp);
				break;
			}

#ifndef TC_NO_GUI
		case UserInterfaceType::Graphic:
			{
				wxAppInitializer wxTheAppInitializer((wxAppInitializerFunction) CreateGuiApp);
				break;
			}
#endif

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	int Application::ExitCode = 0;
	UserInterface *Application::mUserInterface = nullptr;
	UserInterfaceType::Enum Application::mUserInterfaceType;
}
