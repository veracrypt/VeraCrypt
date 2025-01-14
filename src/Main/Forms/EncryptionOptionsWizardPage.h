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

#ifndef TC_HEADER_Main_Forms_EncryptionOptionsWizardPage
#define TC_HEADER_Main_Forms_EncryptionOptionsWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	class EncryptionOptionsWizardPage : public EncryptionOptionsWizardPageBase
	{
	public:
		EncryptionOptionsWizardPage (wxPanel* parent);

#ifdef TC_MACOSX
		~EncryptionOptionsWizardPage ();
#endif
		shared_ptr <EncryptionAlgorithm> GetEncryptionAlgorithm () const;
		shared_ptr <Hash> GetHash () const;
		bool IsValid () { return true; }
		void SetPageText (const wxString &text) { }
		void SetEncryptionAlgorithm (shared_ptr <EncryptionAlgorithm> algorithm);
		void SetHash (shared_ptr <Hash> hash);

	protected:
		void OnBenchmarkButtonClick (wxCommandEvent& event);
		void OnEncryptionAlgorithmHyperlinkClick (wxHyperlinkEvent& event);
		void OnEncryptionAlgorithmSelected ();
		void OnEncryptionAlgorithmSelected (wxCommandEvent& event) { OnEncryptionAlgorithmSelected(); }
		void OnHashHyperlinkClick (wxHyperlinkEvent& event);
		void OnTestButtonClick (wxCommandEvent& event);

#ifdef TC_MACOSX
		void HandleOnSize( wxSizeEvent& event );
#endif
		EncryptionAlgorithmList EncryptionAlgorithms;
		HashList Hashes;
	};
}

#endif // TC_HEADER_Main_Forms_EncryptionOptionsWizardPage
