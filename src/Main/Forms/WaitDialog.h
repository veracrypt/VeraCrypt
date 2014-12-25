/*
 Copyright (c) 2014 IDRIX. All rights reserved.

 Governed by the VeraCrypt License the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_WaitDialog
#define TC_HEADER_Main_Forms_WaitDialog

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{

	DECLARE_LOCAL_EVENT_TYPE(wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, -1);
	
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
			: WaitDialogBase(parent), WaitThreadUI(pRoutine), m_timer (this)
		{
			WaitStaticText->SetLabel (label);
			WaitProgessBar->Pulse();
			Layout();
			GetSizer()->Fit( this );
			Centre( wxBOTH );
			Connect( wxID_ANY, wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, wxCommandEventHandler( WaitDialog::OnThreadCompletion ) );
			Connect( wxEVT_TIMER, wxTimerEventHandler( WaitDialog::OnProgressTimer ), NULL, this );
			m_thread = new WaitThread(this, pRoutine);
		}
		
		~WaitDialog()
		{
			Disconnect( wxEVT_TIMER, wxTimerEventHandler( WaitDialog::OnProgressTimer ));
			Disconnect( wxID_ANY, wxEVT_COMMAND_WAITDIALOGTHREAD_COMPLETED, wxCommandEventHandler( WaitDialog::OnThreadCompletion ) );
		}

		virtual void OnWaitDialogInit( wxInitDialogEvent& event )
		{	
			m_thread->Run();
			m_timer.Start(100);
		}
		
		// virtual void OnWaitDialogClose( wxCloseEvent& event ) { }
		void OnThreadCompletion(wxCommandEvent &)
		{
			EndModal(0);
		}
		
		void OnProgressTimer(wxTimerEvent& event)
		{
			WaitProgessBar->Pulse();
		}

		virtual void Run(void) { ShowModal(); if (m_pRoutine->HasException()) ThrowException(m_pRoutine->m_pException); }

		void ThrowException(Exception* ex);

	protected:
		WaitThread* m_thread;
		wxTimer m_timer;	
	};
}

#endif // TC_HEADER_Main_Forms_WaitDialog
