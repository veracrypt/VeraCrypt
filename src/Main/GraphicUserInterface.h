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

#ifndef TC_HEADER_Main_GraphicUserInterface
#define TC_HEADER_Main_GraphicUserInterface

#include "System.h"
#include <utility>
#include "Main.h"
#include "UserInterface.h"
#include "Forms/WaitDialog.h"

namespace VeraCrypt
{
	class GraphicUserInterface : public UserInterface
	{
	public:
		GraphicUserInterface ();
		virtual ~GraphicUserInterface ();

		virtual void AppendToListCtrl (wxListCtrl *listCtrl, const vector <wstring> &itemFields, int imageIndex = -1, void *itemDataPtr = nullptr) const;
		virtual wxMenuItem *AppendToMenu (wxMenu &menu, const wxString &label, wxEvtHandler *handler = nullptr, wxObjectEventFunction handlerFunction = nullptr, int itemId = wxID_ANY) const;
		virtual bool AskYesNo (const wxString &message, bool defaultYes = false, bool warning = false) const;
		virtual void AutoDismountVolumes (VolumeInfoList mountedVolumes, bool alwaysForce = true);
		virtual void BackupVolumeHeaders (shared_ptr <VolumePath> volumePath) const;
		virtual void RevealRedkey (shared_ptr <VolumePath> volumePath) const;
		virtual void BeginBusyState () const { wxBeginBusyCursor(); }
		virtual void BeginInteractiveBusyState (wxWindow *window);
		virtual void ChangePassword (shared_ptr <VolumePath> volumePath = shared_ptr <VolumePath>(), shared_ptr <VolumePassword> password = shared_ptr <VolumePassword>(), int pim = 0, shared_ptr <Hash> currentHash = shared_ptr <Hash>(), shared_ptr <KeyfileList> keyfiles = shared_ptr <KeyfileList>(), wstring securityTokenKeySpec = wstring(), shared_ptr <VolumePassword> newPassword = shared_ptr <VolumePassword>(), int newPim = 0, shared_ptr <KeyfileList> newKeyfiles = shared_ptr <KeyfileList>(), shared_ptr <Hash> newHash = shared_ptr <Hash>()) const { ThrowTextModeRequired(); }
		wxHyperlinkCtrl *CreateHyperlink (wxWindow *parent, const wxString &linkUrl, const wxString &linkText) const;
		virtual void CreateKeyfile (shared_ptr <FilePath> keyfilePath = shared_ptr <FilePath>()) const;
		virtual void CreateVolume (shared_ptr <VolumeCreationOptions> options) const { ThrowTextModeRequired(); }
		virtual void ClearListCtrlSelection (wxListCtrl *listCtrl) const;
		virtual void DeleteSecurityTokenKeyfiles () const { ThrowTextModeRequired(); }
		virtual void DoShowError (const wxString &message) const;
		virtual void DoShowInfo (const wxString &message) const;
		virtual void DoShowString (const wxString &str) const;
		virtual void DoShowWarning (const wxString &message) const;
		virtual void EndBusyState () const { wxEndBusyCursor(); }
		virtual void EndInteractiveBusyState (wxWindow *window) const;
		virtual void ExportTokenKeyfile () const { ThrowTextModeRequired(); }
		virtual wxTopLevelWindow *GetActiveWindow () const;
		virtual shared_ptr <GetStringFunctor> GetAdminPasswordRequestHandler ();
		virtual int GetCharHeight (wxWindow *window) const;
		virtual int GetCharWidth (wxWindow *window) const;
		virtual int GetDefaultBorderSize () const { return 5; }
		virtual wxFont GetDefaultBoldFont (wxWindow *window) const;
		virtual wxString GetHomepageLinkURL (const wxString &linkId, const wxString &extraVars = wxEmptyString) const;
		virtual wxFrame *GetMainFrame () const { return mMainFrame; }
		virtual int GetScrollbarWidth (wxWindow *window, bool noScrollBar = false) const;
		virtual list <long> GetListCtrlSelectedItems (wxListCtrl *listCtrl) const;
		virtual wxString GetListCtrlSubItemText (wxListCtrl *listCtrl, long itemIndex, int columnIndex) const;
		virtual void ImportTokenKeyfiles () const { ThrowTextModeRequired(); }
		virtual void InitSecurityTokenLibrary () const;
		virtual void InsertToListCtrl (wxListCtrl *listCtrl, long itemIndex, const vector <wstring> &itemFields, int imageIndex = -1, void *itemDataPtr = nullptr) const;
		virtual bool IsInBackgroundMode () const { return BackgroundMode; }
		virtual bool IsTheOnlyTopLevelWindow (const wxWindow *window) const;
        virtual void ListTokenKeyfiles () const;
        virtual void ListSecurityTokenKeyfiles () const;
        virtual void ListEMVTokenKeyfiles () const;
		virtual VolumeInfoList MountAllDeviceHostedVolumes (MountOptions &options) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options) const;
		virtual void MoveListCtrlItem (wxListCtrl *listCtrl, long itemIndex, long newItemIndex) const;
		virtual void OnAutoDismountAllEvent ();
		virtual bool OnInit ();
		virtual void OnLogOff ();
		virtual void OpenDocument (wxWindow *parent, const wxFileName &document);
		virtual void OpenHomepageLink (wxWindow *parent, const wxString &linkId, const wxString &extraVars = wxEmptyString);
		virtual void OpenOnlineHelp (wxWindow *parent);
		virtual void OpenUserGuide (wxWindow *parent);
		virtual void RestoreVolumeHeaders (shared_ptr <VolumePath> volumePath) const;
		virtual DevicePath SelectDevice (wxWindow *parent) const;
		virtual DirectoryPath SelectDirectory (wxWindow *parent, const wxString &message = wxEmptyString, bool existingOnly = true) const;
		virtual FilePathList SelectFiles (wxWindow *parent, const wxString &caption, bool saveMode = false, bool allowMultiple = false, const list < pair <wstring, wstring> > &fileExtensions = (list < pair <wstring, wstring> > ()), const DirectoryPath &directory = DirectoryPath()) const;
		virtual FilePath SelectVolumeFile (wxWindow *parent, bool saveMode = false, const DirectoryPath &directory = DirectoryPath()) const;
		virtual void SetActiveFrame (wxFrame *frame) { ActiveFrame = frame; }
		virtual void SetBackgroundMode (bool state);
		virtual void SetListCtrlColumnWidths (wxListCtrl *listCtrl, list <int> columnWidthPermilles, bool hasVerticalScrollbar = true) const;
		virtual void SetListCtrlHeight (wxListCtrl *listCtrl, size_t rowCount) const;
		virtual void SetListCtrlWidth (wxListCtrl *listCtrl, size_t charCount, bool hasVerticalScrollbar = true) const;
		virtual void SetContentProtection(bool enable) const;
		virtual void ShowErrorTopMost (char *langStringId) const { ShowErrorTopMost (LangString[langStringId]); }
		virtual void ShowErrorTopMost (const wxString &message) const;
		virtual void ShowInfoTopMost (char *langStringId) const { ShowInfoTopMost (LangString[langStringId]); }
		virtual void ShowInfoTopMost (const wxString &message) const;
		virtual void ShowWarningTopMost (char *langStringId) const { ShowWarningTopMost (LangString[langStringId]); }
		virtual void ShowWarningTopMost (const wxString &message) const;
		virtual bool UpdateListCtrlItem (wxListCtrl *listCtrl, long itemIndex, const vector <wstring> &itemFields) const;
		virtual void UserEnrichRandomPool (wxWindow *parent, shared_ptr <Hash> hash = shared_ptr <Hash>()) const;
		virtual void Yield () const;
		virtual shared_ptr <VolumeInfo> MountVolumeThread (MountOptions &options) const;
		WaitDialog* GetWaitDialog () { return mWaitDialog; }
		void ExecuteWaitThreadRoutine (wxWindow *parent, WaitThreadRoutine *pRoutine) const;

#ifdef TC_MACOSX
		virtual void MacOpenFiles (const wxArrayString &fileNames);
		virtual void MacReopenApp ();
		static bool HandlePasswordEntryCustomEvent (wxEvent& event);
		static void InstallPasswordEntryCustomKeyboardShortcuts (wxWindow* window);
#endif

		template <class T>
		T *GetSelectedData (wxControlWithItems *control) const
		{
			int sel = control->GetSelection();
			if (sel == wxNOT_FOUND)
				return nullptr;

			return reinterpret_cast <T *> (control->GetClientData (sel));
		}

		Event OpenVolumeSystemRequestEvent;

	protected:
		virtual void OnEndSession (wxCloseEvent& event) { OnLogOff(); }
#ifdef wxHAS_POWER_EVENTS
		virtual void OnPowerSuspending (wxPowerEvent& event);
#endif
		static void OnSignal (int signal);
		virtual void OnVolumesAutoDismounted ();
		virtual int ShowMessage (const wxString &message, long style, bool topMost = false) const;
		void ThrowTextModeRequired () const;

		wxFrame *ActiveFrame;
		bool BackgroundMode;
#ifdef TC_WINDOWS
		unique_ptr <wxDDEServer> DDEServer;
#endif
		wxFrame *mMainFrame;
		unique_ptr <wxSingleInstanceChecker> SingleInstanceChecker;

		mutable WaitDialog* mWaitDialog;
public:	
#ifdef TC_MACOSX
		static int g_customIdCmdV;
		static int g_customIdCmdA;
#endif

	private:
		GraphicUserInterface (const GraphicUserInterface &);
		GraphicUserInterface &operator= (const GraphicUserInterface &);
	};


	struct OpenVolumeSystemRequestEventArgs : public EventArgs
	{
		OpenVolumeSystemRequestEventArgs (const wxString &volumePath) : mVolumePath (volumePath) { }
		wxString mVolumePath;
	};


	class FreezeScope
	{
	public:
		FreezeScope (wxWindow *window) : Window (window)
		{
			Window->Freeze();
		}

		~FreezeScope ()
		{
			Window->Thaw();
		}

		wxWindow *Window;
	};

	DECLARE_EVENT_TYPE (TC_EVENT_THREAD_EXITING, -1);

	extern GraphicUserInterface *Gui;
}

#endif // TC_HEADER_Main_GraphicUserInterface
