/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include <wx/stackwalk.h>

#include "Main.h"
#include "Application.h"
#include "UserInterface.h"
#include "GraphicUserInterface.h"
#include "Volume/Crc32.h"

#ifdef TC_UNIX
#include <signal.h>
#endif

#ifdef TC_MACOSX
#	ifdef __ppc__
#		include <ppc/ucontext.h>
#	else
#		include <i386/ucontext.h>
#	endif
#elif defined (TC_BSD)
#	include <ucontext.h>
#endif

#include "FatalErrorHandler.h"

namespace VeraCrypt
{
	static terminate_handler DefaultTerminateHandler;

	struct FatalErrorReport
	{
		bool UnhandledException;
	};

#ifdef TC_UNIX
	static void OnFatalProgramErrorSignal (int, siginfo_t *signalInfo, void *contextArg)
	{
		TC_UNUSED_VAR ucontext_t *context = (ucontext_t *) contextArg;
		uint64 faultingInstructionAddress = 0;

#ifdef TC_LINUX
#	ifdef REG_EIP
		faultingInstructionAddress = context->uc_mcontext.gregs[REG_EIP];
#	elif defined (REG_RIP)
		faultingInstructionAddress = context->uc_mcontext.gregs[REG_RIP];
#	endif

#elif defined (TC_MACOSX)
#	ifdef __ppc__
		faultingInstructionAddress = context->uc_mcontext->ss.srr0;
#	elif defined (__x86_64__)
		faultingInstructionAddress = context->uc_mcontext->ss.rip;
#	else
		faultingInstructionAddress = context->uc_mcontext->ss.eip;
#	endif

#endif
		wstringstream vars;

		vars << L"cpus=" << wxThread::GetCPUCount();
		vars << L"&cksum=" << hex << FatalErrorHandler::GetAppChecksum() << dec;
		vars << L"&err=" << signalInfo->si_signo;
		vars << L"&addr=" << hex << faultingInstructionAddress << dec;
		vars << FatalErrorHandler::GetCallStack (16);

		wxString url = Gui->GetHomepageLinkURL (L"err-report", true, vars.str());
		url.Replace (L"=0x", L"=");
		url.Replace (L"=0X0x", L"=0x");
		url.Replace (L"=0X", L"=0x");

		wxString msg = L"A critical error has occurred and VeraCrypt must be terminated. If this is caused by a bug in VeraCrypt, we would like to fix it. To help us, you can send us an automatically generated error report containing the following items:\n\n- Program version\n- Operating system version\n- Hardware architecture\n- Checksum of VeraCrypt executable\n- Error category\n- Error address\n";
#if wxUSE_STACKWALKER == 1
		msg += L"- VeraCrypt call stack\n";
#endif
		msg += L"\nIf you select 'Yes', the following URL (which contains the entire error report) will be opened in your default Internet browser.\n\n";

#ifdef __WXGTK__
		wxString fUrl = url;
		fUrl.Replace (L"&st", L" &st");
		msg += fUrl;
#else
		msg += url;
#endif

		msg += L"\n\nDo you want to send us the error report?";

		if (Gui->AskYesNo (msg, true))
			wxLaunchDefaultBrowser (url, wxBROWSER_NEW_WINDOW);

		_exit (1);
	}
#endif // TC_UNIX

	void FatalErrorHandler::Deregister()
	{
#ifdef TC_UNIX
		signal (SIGILL, SIG_DFL);
		signal (SIGFPE, SIG_DFL);
		signal (SIGSEGV, SIG_DFL);
		signal (SIGBUS, SIG_DFL);
		signal (SIGSYS, SIG_DFL);
#endif

#ifndef TC_WINDOWS
		std::set_terminate (DefaultTerminateHandler);
#endif
	}
	
	uint32 FatalErrorHandler::GetAppChecksum ()
	{
		uint32 checkSum = 0;
		try
		{
			File executable;
			executable.Open (Application::GetExecutablePath());

			Buffer executableData (executable.Length());
			executable.ReadCompleteBuffer (executableData);
			checkSum = Crc32::ProcessBuffer (executableData);
		}
		catch (...) { }

		return checkSum;
	}

	wstring FatalErrorHandler::GetCallStack (int depth)
	{	
#if wxUSE_STACKWALKER == 1

		class StackWalker : public wxStackWalker
		{
		public:
			StackWalker () : FrameCount (0) { }

			void OnStackFrame (const wxStackFrame &frame)
			{
				if (FrameCount >= 32)
					return;

				StackVars << L"&st" << FrameCount++ << L"=";

				wxString functionName = frame.GetName();
				if (!functionName.empty() && !frame.GetModule().empty())
				{
					int p = functionName.Find (L"(");
					if (p != wxNOT_FOUND)
						functionName = functionName.Mid (0, p);

					for (size_t i = 0; i < functionName.size(); ++i)
					{
						if (!isalnum (functionName[i]))
							functionName[i] = L'_';
					}

					while (functionName.Replace (L"__", L"_"));

					StackVars << wstring (functionName);
				}
				else
					StackVars << "0X" << hex << frame.GetAddress() << dec;
			}

			int FrameCount;
			wstringstream StackVars;
		};

		StackWalker stackWalker;
		stackWalker.Walk (2);

		return stackWalker.StackVars.str();

#else // wxUSE_STACKWALKER
		
		return wstring();

#endif // wxUSE_STACKWALKER
	}

	void FatalErrorHandler::OnTerminate ()
	{
		try
		{
			throw;
		}
		catch (UserAbort&)
		{
		}
		catch (Exception &e)
		{
			wxString vars;

			wxString exName = StringConverter::ToWide (StringConverter::GetTypeName (typeid (e)));
			if (exName.find (L"VeraCrypt::") != string::npos)
				exName = exName.Mid (11);

			wxString exPos = StringConverter::ToWide (e.what());
			if (exPos.find (L"VeraCrypt::") != string::npos)
				exPos = exPos.Mid (11);

			vars << L"cpus=" << wxThread::GetCPUCount();
			vars << wxString::Format (L"&cksum=%x", GetAppChecksum());
			vars << L"&exception=" << exName;
			vars << L"&exlocation=" << exPos;
			vars << FatalErrorHandler::GetCallStack (16);

			vars.Replace (L"::", L".");
			vars.Replace (L":", L".");

			wxString url = Gui->GetHomepageLinkURL (L"err-report", true, vars);
			url.Replace (L"=0x", L"=");
			url.Replace (L"=0X0x", L"=0x");
			url.Replace (L"=0X", L"=0x");

			wxString msg = L"An unhandled exception has occurred and VeraCrypt must be terminated. If this is caused by a bug in VeraCrypt, we would like to fix it. To help us, you can send us an automatically generated error report containing the following items:\n\n- Program version\n- Operating system version\n- Hardware architecture\n- Checksum of VeraCrypt executable\n- Error description\n- Error location\n";
#if wxUSE_STACKWALKER == 1
			msg += L"- VeraCrypt call stack\n";
#endif
			msg += L"\nIf you select 'Yes', the following URL (which contains the entire error report) will be opened in your default Internet browser.\n\n";

#ifdef __WXGTK__
			wxString fUrl = url;
			fUrl.Replace (L"&st", L" &st");
			msg += fUrl;
#else
			msg += url;
#endif

			msg += L"\n\nDo you want to send us the error report?";

			if (Gui->AskYesNo (msg, true))
				wxLaunchDefaultBrowser (url, wxBROWSER_NEW_WINDOW);

		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
		catch (...)
		{
			Gui->ShowError (_("Unknown exception occurred."));
		}

		_exit (1);
	}

	void FatalErrorHandler::Register ()
	{
#ifndef TC_WINDOWS
		 // OnUnhandledException() seems to be called only on Windows
		DefaultTerminateHandler = std::set_terminate (OnTerminate);
#endif

#ifdef TC_UNIX
		struct sigaction action;
		Memory::Zero (&action, sizeof (action));
		action.sa_flags = SA_SIGINFO;
		action.sa_sigaction = OnFatalProgramErrorSignal;

		throw_sys_if (sigaction (SIGILL, &action, nullptr) == -1);
		throw_sys_if (sigaction (SIGFPE, &action, nullptr) == -1);
		throw_sys_if (sigaction (SIGSEGV, &action, nullptr) == -1);
		throw_sys_if (sigaction (SIGBUS, &action, nullptr) == -1);
		throw_sys_if (sigaction (SIGSYS, &action, nullptr) == -1);
#endif
	}
}
