/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_WizardFrame
#define TC_HEADER_Main_Forms_WizardFrame

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class WizardFrame : public WizardFrameBase
	{
	public:
		WizardFrame (wxWindow* parent);
		virtual ~WizardFrame ();

	protected:
		typedef int WizardStep;

		void ClearHistory ();
		virtual WizardPage *GetPage (WizardStep step) = 0;
		WizardPage *GetCurrentPage () const { return CurrentPage; }
		WizardStep GetCurrentStep () const { return CurrentStep; }
		wxPanel *GetPageParent () const { return MainPanel; }
		bool IsWorkInProgress() const { return WorkInProgress; }
		virtual void OnCancelButtonClick (wxCommandEvent& event) { Close(); }
		virtual void OnClose (wxCloseEvent& event);
		virtual void OnHelpButtonClick (wxCommandEvent& event);
		virtual WizardStep ProcessPageChangeRequest (bool forward) = 0;
		void SetCancelButtonText (const wxString &text);
		void SetImage (const wxBitmap &bitmap);
		void SetMaxStaticTextWidth (size_t charCount);
		void SetStep (WizardStep newStep);
		void SetWorkInProgress (bool state);

	private:
		void OnActivate (wxActivateEvent& event);
		void OnNextButtonClick (wxCommandEvent& event);
		void OnPageUpdated (EventArgs &args) { UpdateControls(); }
		void OnPreviousButtonClick (wxCommandEvent& event);
		void SetStep (WizardStep newStep, bool forward);
		void UpdateControls ();

		WizardPage *CurrentPage;
		WizardStep CurrentStep;
		int MaxStaticTextWidth;
		list <WizardStep> StepHistory;
		bool WorkInProgress;
	};
}

#endif // TC_HEADER_Main_Forms_WizardFrame
