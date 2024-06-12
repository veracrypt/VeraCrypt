#ifndef TC_HEADER_Common_EMVToken
#define TC_HEADER_Common_EMVToken

#define TC_EMV_TOKEN_KEYFILE_URL_PREFIX L"emv://"
#define TC_EMV_TOKEN_KEYFILE_URL_SLOT L"slot"

#define EMV_CARDS_LABEL L"EMV Certificates"

#include "EMVCard.h"

namespace VeraCrypt
{
	struct EMVTokenInfo: TokenInfo
	{
		virtual ~EMVTokenInfo();
		virtual BOOL isEditable() const { return false; }
	};

	struct EMVTokenKeyfile: TokenKeyfile
	{
		EMVTokenKeyfile();
		EMVTokenKeyfile(const TokenKeyfilePath& path);
		virtual ~EMVTokenKeyfile() {};

		virtual operator TokenKeyfilePath () const;
		virtual void GetKeyfileData(vector <uint8>& keyfileData) const;
	};

	class EMVToken
	{
	public:
		static bool IsKeyfilePathValid(const wstring& emvTokenKeyfilePath);
		static vector<EMVTokenKeyfile> GetAvailableKeyfiles(unsigned long int* slotIdFilter = nullptr, const wstring& keyfileIdFilter = wstring());
		static EMVTokenInfo GetTokenInfo(unsigned long int slotId);

		friend void EMVTokenKeyfile::GetKeyfileData(vector <uint8>& keyfileData) const;

		static map <unsigned long int, shared_ptr<EMVCard>> EMVCards;
	};
}

#endif
