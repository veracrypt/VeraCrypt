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

#ifndef TC_HEADER_Main_Forms_KeyfileGeneratorDialog
#define TC_HEADER_Main_Forms_KeyfileGeneratorDialog

#include "Forms.h"
#include "Main/Main.h"

namespace VeraCrypt
{
	class KeyfileGeneratorDialog : public KeyfileGeneratorDialogBase
	{
	public:
		KeyfileGeneratorDialog (wxWindow* parent);
		~KeyfileGeneratorDialog ();

	protected:
		void OnGenerateButtonClick (wxCommandEvent& event);
		void OnHashSelected (wxCommandEvent& event);
		void OnMouseMotion (wxMouseEvent& event);
		void OnShowRandomPoolCheckBoxClicked (wxCommandEvent& event);
		void OnRandomSizeCheckBoxClicked( wxCommandEvent& event );
		void ShowBytes (wxStaticText *textCtrl, const ConstBufferPtr &buffer, bool appendDots = true);
		void HideBytes (wxStaticText *textCtrl, size_t len);

		HashList Hashes;
		int	MouseEventsCounter;
		Mutex AccessMutex;
	};
}

#endif // TC_HEADER_Main_Forms_KeyfileGeneratorDialog
