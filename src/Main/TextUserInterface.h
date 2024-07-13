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

#ifndef TC_HEADER_Main_TextUserInterface
#define TC_HEADER_Main_TextUserInterface

#include "System.h"
#include "Main.h"
#include "UserInterface.h"

namespace VeraCrypt
{
	class AdminPasswordTextRequestHandler;
	class TextUserInterface : public UserInterface
	{
	public:
		friend class AdminPasswordTextRequestHandler;
		TextUserInterface ();
		virtual ~TextUserInterface ();

		virtual FilePath AskFilePath (const wxString &message = wxEmptyString) const;
		virtual shared_ptr <KeyfileList> AskKeyfiles (const wxString &message = L"") const;
		virtual shared_ptr <VolumePassword> AskPassword (const wxString &message = L"", bool verify = false) const;
		virtual int AskPim (const wxString &message = L"") const;
		virtual ssize_t AskSelection (ssize_t optionCount, ssize_t defaultOption = -1) const;
		virtual wstring AskString (const wxString &message = wxEmptyString) const;
		virtual shared_ptr <VolumePath> AskVolumePath (const wxString &message = L"") const;
		virtual bool AskYesNo (const wxString &message, bool defaultYes = false, bool warning = false) const;
		virtual void BackupVolumeHeaders (shared_ptr <VolumePath> volumePath) const;
		virtual void BeginBusyState () const { }
		virtual void ChangePassword (shared_ptr <VolumePath> volumePath = shared_ptr <VolumePath>(), shared_ptr <VolumePassword> password = shared_ptr <VolumePassword>(), int pim = 0, shared_ptr <Hash> currentHash = shared_ptr <Hash>(), shared_ptr <KeyfileList> keyfiles = shared_ptr <KeyfileList>(), shared_ptr <VolumePassword> newPassword = shared_ptr <VolumePassword>(), int newPim = 0, shared_ptr <KeyfileList> newKeyfiles = shared_ptr <KeyfileList>(), shared_ptr <Hash> newHash = shared_ptr <Hash>()) const;
		virtual void CreateKeyfile (shared_ptr <FilePath> keyfilePath = shared_ptr <FilePath>()) const;
		virtual void CreateVolume (shared_ptr <VolumeCreationOptions> options) const;
		virtual void DeleteSecurityTokenKeyfiles () const;
		virtual void DoShowError (const wxString &message) const;
		virtual void DoShowInfo (const wxString &message) const;
		virtual void DoShowString (const wxString &str) const;
		virtual void DoShowWarning (const wxString &message) const;
		virtual void EndBusyState () const { }
		virtual void ExportTokenKeyfile () const;
		virtual shared_ptr <GetStringFunctor> GetAdminPasswordRequestHandler ();
		virtual void ImportTokenKeyfiles () const;
#ifndef TC_NO_GUI
		virtual bool Initialize (int &argc, wxChar **argv) { return wxAppBase::Initialize(argc, argv); }
#endif
		virtual void InitSecurityTokenLibrary () const;
		virtual void ListTokenKeyfiles () const;
        virtual void ListSecurityTokenKeyfiles () const;
        virtual void ListEMVTokenKeyfiles () const;
		virtual VolumeInfoList MountAllDeviceHostedVolumes (MountOptions &options) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options) const;
		virtual bool OnInit ();
#ifndef TC_NO_GUI
		virtual bool OnInitGui () { return true; }
#endif
		virtual int OnRun();
		virtual void RestoreVolumeHeaders (shared_ptr <VolumePath> volumePath) const;
		static void SetTerminalEcho (bool enable);
		virtual void UserEnrichRandomPool () const;
		virtual void Yield () const { }

	protected:
		static void OnSignal (int signal);
		virtual void ReadInputStreamLine (wxString &line) const;
		virtual wxString ReadInputStreamLine () const;

		unique_ptr <wxFFileInputStream> FInputStream;
		unique_ptr <wxTextInputStream> TextInputStream;

	private:
		TextUserInterface (const TextUserInterface &);
		TextUserInterface &operator= (const TextUserInterface &);
	};

	extern wxMessageOutput *DefaultMessageOutput;
}

#endif // TC_HEADER_Main_TextUserInterface
