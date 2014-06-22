/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Main_Forms_SingleChoiceWizardPage
#define TC_HEADER_Main_Forms_SingleChoiceWizardPage

#include "Forms.h"

namespace VeraCrypt
{
	template <class ChoiceType>
	class SingleChoiceWizardPage : public SingleChoiceWizardPageBase
	{
	public:
		SingleChoiceWizardPage (wxPanel* parent, const wxString &groupBoxText = wxEmptyString, bool choiceTextBold = false)
			: SingleChoiceWizardPageBase (parent),
			ChoiceTextBold (choiceTextBold)
		{
			if (!groupBoxText.empty())
			{
				OuterChoicesSizer->Remove (ChoicesSizer);
				ChoicesSizer = new wxStaticBoxSizer (wxVERTICAL, this, groupBoxText);
				OuterChoicesSizer->Add (ChoicesSizer, 0, wxEXPAND, 5);
			}
		}

		void AddChoice (ChoiceType choice, const wxString &choiceText, const wxString &infoText = wxEmptyString, const wchar_t *infoLinkId = nullptr, const wxString &infoLinkText = wxEmptyString)
		{
			assert (RadioButtonMap.find (choice) == RadioButtonMap.end());

			wxRadioButton *radioButton = new wxRadioButton (this, wxID_ANY, choiceText);
			if (RadioButtonMap.empty())
				radioButton->SetValue (true);

			RadioButtonMap[choice] = radioButton;

			if (ChoiceTextBold)
			{
				wxFont buttonFont = radioButton->GetFont();
				buttonFont.SetWeight (wxFONTWEIGHT_BOLD);
				radioButton->SetFont (buttonFont);
			}

			ChoicesSizer->Add (radioButton, 0, wxALL, 5);

			wxBoxSizer *infoSizer = new wxBoxSizer (wxVERTICAL);

			wxStaticText *infoStaticText = new wxStaticText (this, wxID_ANY, infoText, wxDefaultPosition, wxDefaultSize, 0);
			ChoiceInfoTexts.push_back (infoStaticText);

			infoSizer->Add (infoStaticText, 0, wxALL, 5);
			ChoicesSizer->Add (infoSizer, 0, wxEXPAND | wxLEFT, Gui->GetCharWidth (this) * 3);

			if (infoLinkId)
			{
				wxHyperlinkCtrl *hyperlink = Gui->CreateHyperlink (this, infoLinkId, infoLinkText);
				infoSizer->Add (hyperlink, 0, wxALL, 5);
				hyperlink->Connect (wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler (SingleChoiceWizardPage::OnChoiceHyperlinkClick), nullptr, this);
			}

			ChoicesSizer->Add (1, Gui->GetCharHeight (this) * 1, 0, wxEXPAND, 5);
		}

		ChoiceType GetSelection () const
		{
			typedef pair <ChoiceType, wxRadioButton*> MapPair;
			foreach (MapPair p, RadioButtonMap)
			{
				if (p.second->GetValue())
					return p.first;
			}

			throw NoItemSelected (SRC_POS);
		}

		bool IsValid ()
		{
			return true;
		}

		void SetMaxStaticTextWidth (int width)
		{
			InfoStaticText->Wrap (width);

			foreach (wxStaticText *infoText, ChoiceInfoTexts)
				infoText->Wrap (width - Gui->GetCharWidth (this) * 3);
		}

		void SetPageText (const wxString &text)
		{
			InfoStaticText->SetLabel (text);
		}

		void SetSelection (ChoiceType choice)
		{
			RadioButtonMap[choice]->SetValue (true);
		}

	protected:
		void OnChoiceHyperlinkClick (wxHyperlinkEvent &event)
		{
			Gui->OpenHomepageLink (this, event.GetURL());
		}

		bool ChoiceTextBold;
		list <wxStaticText*> ChoiceInfoTexts;
		map <ChoiceType, wxRadioButton*> RadioButtonMap;
	};
}

#endif // TC_HEADER_Main_Forms_SingleChoiceWizardPage
