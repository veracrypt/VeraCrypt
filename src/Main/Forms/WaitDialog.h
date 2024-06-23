/*
 Copyright (c) 2013-2018 IDRIX. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_WaitDialog
#define TC_HEADER_Main_Forms_WaitDialog

#include "Forms.h"
#include "Main/Main.h"
#include "Main/Application.h"
#include <wx/msgqueue.h>
#include <wx/msgdlg.h>

namespace VeraCrypt
{

	DECLARE_LOCAL_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, -1);
	DECLARE_LOCAL_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_ADMIN_PASSWORD, -1);
	DECLARE_LOCAL_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_PIN, -1);
	DECLARE_LOCAL_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOG_SHOW_MSG, -1);

	class WaitDialog;



	class WaitThread : public wxThread
	{
	public:
		WaitThread(WaitDialog *handler, WaitThreadRoutine* pRoutine) : wxThread(wxTHREAD_DETACHED), m_pRoutine(pRoutine)
		{
			m_pHandler = handler;
		}
		~WaitThread()
		{
		}

	protected:
		virtual ExitCode Entry();
		WaitDialog *m_pHandler;
		WaitThreadRoutine* m_pRoutine;
	};

	class WaitDialog : public WaitDialogBase, public WaitThreadUI
	{
	public:
		WaitDialog (wxWindow *parent, const wxString& label, WaitThreadRoutine* pRoutine)
			: WaitDialogBase(parent), WaitThreadUI(pRoutine), m_bThreadRunning (false), m_timer (this)
		{
			WaitStaticText->SetLabel (label);
			WaitProgessBar->Pulse();
			Layout();
			GetSizer()->Fit( this );
			Centre( wxBOTH );
			Connect( wxID_ANY, wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, wxCommandEventHandler( WaitDialog::OnThreadCompletion ) );
			Connect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_ADMIN_PASSWORD, wxCommandEventHandler( WaitDialog::OnAdminPasswordRequest ) );
			Connect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_PIN, wxCommandEventHandler( WaitDialog::OnPinRequest ) );
			Connect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_SHOW_MSG, wxCommandEventHandler( WaitDialog::OnShowMsg ) );

			Connect( wxEVT_TIMER, wxTimerEventHandler( WaitDialog::OnProgressTimer ), NULL, this );
			m_thread = new WaitThread(this, pRoutine);
		}

		~WaitDialog()
		{
			Disconnect( wxEVT_TIMER, wxTimerEventHandler( WaitDialog::OnProgressTimer ));
			Disconnect( wxID_ANY, wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, wxCommandEventHandler( WaitDialog::OnThreadCompletion ) );
			Disconnect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_ADMIN_PASSWORD, wxCommandEventHandler( WaitDialog::OnAdminPasswordRequest ) );
			Disconnect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_PIN, wxCommandEventHandler( WaitDialog::OnPinRequest ) );
			Disconnect( wxID_ANY, wxEVT_COMMAND_WAITDIALOG_SHOW_MSG, wxCommandEventHandler( WaitDialog::OnShowMsg ) );
		}

		virtual void OnWaitDialogInit( wxInitDialogEvent& event )
		{
			m_thread->Run();
			m_timer.Start(100);
			m_bThreadRunning = true;
		}

		static int ComputeCharWidth (wxWindow *window)
		{
			int width;
			int height;
			window->GetTextExtent (L"a", &width, &height);

			if (width < 1)
				return 7;

			return width;
		}

		class ShowMessageParam
		{
		public:
			wxString m_message;
			wxString m_caption;
			long m_style;
			bool m_topMost;
			ShowMessageParam(const wxString &message, const wxString &caption,long style, bool topMost)
				: m_message(message), m_caption(caption), m_style(style), m_topMost(topMost)
			{}
		};

		int RequestShowMessage (const wxString &message, const wxString &caption,long style, bool topMost)
		{
			long lResult = -1;
			if (m_queue.IsOk())
			{
				wxString sResult;
				ShowMessageParam* pParam = new ShowMessageParam(message, caption, style, topMost);
				wxCommandEvent* pEvent = new wxCommandEvent( wxEVT_COMMAND_WAITDIALOG_SHOW_MSG,0);
				pEvent->SetClientData (pParam);
				wxQueueEvent (this, pEvent);
				m_queue.Receive (sResult);
				sResult.ToLong(&lResult);
			}
			return (int) lResult;
		}

		void RequestAdminPassword (wxString& adminPassword)
		{
			if (m_queue.IsOk())
			{
				wxQueueEvent (this, new wxCommandEvent( wxEVT_COMMAND_WAITDIALOG_ADMIN_PASSWORD,0));
				if (wxMSGQUEUE_NO_ERROR != m_queue.Receive (adminPassword))
					adminPassword = wxT("");
			}
			else
				adminPassword = wxT("");
		}

		void RequestPin (wxString& pin)
		{
			if (m_queue.IsOk())
			{
				wxCommandEvent* pEvent = new wxCommandEvent( wxEVT_COMMAND_WAITDIALOG_PIN,0);
				pEvent->SetString (pin);
				wxQueueEvent (this, pEvent);
				if (wxMSGQUEUE_NO_ERROR != m_queue.Receive (pin))
					pin = wxT("");
			}
			else
				pin = wxT("");
		}

		virtual void OnWaitDialogClose( wxCloseEvent& event ) 
		{ 
			if (event.CanVeto () && m_bThreadRunning)
			{
				event.Veto ();
			}
			else
				event.Skip ();
		}
 
		void OnThreadCompletion(wxCommandEvent &)
		{
			m_bThreadRunning = false;
			m_queue.Clear();
			EndModal(0);
		}

		void OnAdminPasswordRequest(wxCommandEvent &)
		{

			wxPasswordEntryDialog dialog (this, LangString["LINUX_ADMIN_PW_QUERY"], LangString["LINUX_ADMIN_PW_QUERY_TITLE"]);
			if (dialog.ShowModal() != wxID_OK)
				m_queue.Post(wxT(""));
			else
				m_queue.Post(dialog.GetValue());
		}



		void OnPinRequest(wxCommandEvent &e)
		{

			wxPasswordEntryDialog dialog (this, wxString::Format (LangString["ENTER_TOKEN_PASSWORD"], e.GetString()), LangString["IDD_TOKEN_PASSWORD"]);
			dialog.SetSize (wxSize (ComputeCharWidth (&dialog) * 50, -1));

			if (dialog.ShowModal() != wxID_OK)
				m_queue.Post(wxT(""));
			else
				m_queue.Post(dialog.GetValue());
		}

		void OnShowMsg(wxCommandEvent &e)
		{
			ShowMessageParam* pParam = (ShowMessageParam*) e.GetClientData();
			if (pParam->m_topMost)
			{
				if (!IsActive())
					RequestUserAttention (wxUSER_ATTENTION_ERROR);

				pParam->m_style |= wxSTAY_ON_TOP;
			}
			wxMessageDialog cur(this, pParam->m_message, pParam->m_caption, pParam->m_style);
			cur.SetYesNoLabels(LangString["UISTR_YES"], LangString["UISTR_NO"]);
			int iResult =  (cur.ShowModal() == wxID_YES ? wxYES : wxNO);
			delete pParam;
			m_queue.Post(wxString::Format(wxT("%d"), iResult));
		}

		void OnProgressTimer(wxTimerEvent& event)
		{
			WaitProgessBar->Pulse();
		}

		virtual void Run(void) { ShowModal(); if (m_pRoutine->HasException()) ThrowException(m_pRoutine->m_pException); }

		void ThrowException(Exception* ex);

	protected:
		WaitThread* m_thread;
		bool m_bThreadRunning;
		wxTimer m_timer;
		wxMessageQueue<wxString> m_queue;
	};
}

#endif // TC_HEADER_Main_Forms_WaitDialog
