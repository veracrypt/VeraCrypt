#ifndef TC_HEADER_Common_EMVToken
#define TC_HEADER_Common_EMVToken

#define TC_EMV_TOKEN_KEYFILE_URL_PREFIX L"emv://"
#define TC_EMV_TOKEN_KEYFILE_URL_SLOT L"slot"

#define EMV_CARDS_LABEL L"EMV Certificates"

#include "EMVCard.h"
#include <mutex>

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
		static void CloseAllSessions() throw ();

		friend void EMVTokenKeyfile::GetKeyfileData(vector <uint8>& keyfileData) const;

	private:
		// Hold this mutex throughout card operations, including reader enumeration,
		// so closing sessions cannot race with use or insertion of a cached card.
		static std::mutex EMVCardsMutex;
		static map <unsigned long int, shared_ptr<EMVCard>> EMVCards;
		static EMVTokenInfo GetTokenInfoLocked(unsigned long int slotId);
	};
}

#endif
