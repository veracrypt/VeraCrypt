

#ifndef TC_HEADER_Common_EMVToken
#define TC_HEADER_Common_EMVToken

#define TC_EMV_TOKEN_KEYFILE_URL_PREFIX L"emv://"
#define TC_EMV_TOKEN_KEYFILE_URL_SLOT L"slot"

#define EMV_CARDS_LABEL L"EMV Certificates"

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

#include "Token.h"

namespace VeraCrypt {

	struct EMVTokenKeyfileInfo: TokenInfo
	{
	};

	struct EMVTokenKeyfile: TokenKeyfile
	{
        EMVTokenKeyfile(){Id = EMV_CARDS_LABEL;};
		EMVTokenKeyfile(const TokenKeyfilePath& path);

		virtual operator TokenKeyfilePath () const;

	};

	class EMVToken {
	public:
		static void GetKeyfileData(const TokenKeyfile& keyfile, vector <byte>& keyfileData);
		static bool IsKeyfilePathValid(const wstring& emvTokenKeyfilePath);
		static vector<EMVTokenKeyfile> GetAvailableKeyfiles(unsigned long int* slotIdFilter = nullptr, const wstring keyfileIdFilter = wstring());
        static EMVTokenKeyfileInfo GetTokenInfo(unsigned long int slotId);

	};
}

#endif
