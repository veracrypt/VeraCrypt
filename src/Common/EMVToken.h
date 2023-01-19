

#ifndef TC_HEADER_Common_EMVToken
#define TC_HEADER_Common_EMVToken

#define TC_EMV_TOKEN_KEYFILE_URL_PREFIX L"emv://"
#define TC_EMV_TOKEN_KEYFILE_URL_SLOT L"slot"

#define EMV_CARDS_LABEL L"emv"

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
        EMVTokenKeyfile(){Id = L"emv";};
		EMVTokenKeyfile(const TokenKeyfilePath& path);

		virtual operator TokenKeyfilePath () const;

	};

	class EMVToken {
	public:
		static void GetKeyfileData(const TokenKeyfile& keyfile, vector <byte>& keyfileData);
		static bool IsKeyfilePathValid(const wstring& emvTokenKeyfilePath);
		static vector<EMVTokenKeyfile> GetAvailableKeyfiles();
        static EMVTokenInfo EMVToken::GetTokenInfo(unsigned long int slotId);

	};
}

#endif
