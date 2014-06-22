/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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

		EncryptionAlgorithmList EncryptionAlgorithms;
		HashList Hashes;
	};
}

#endif // TC_HEADER_Main_Forms_EncryptionOptionsWizardPage
