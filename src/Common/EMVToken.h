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
#include "IccDataExtractor.h"

namespace VeraCrypt {

	struct EMVTokenInfo: TokenInfo
	{
		virtual ~EMVTokenInfo();
		virtual BOOL isEditable() const {return false;}
	};

	struct EMVTokenKeyfile: TokenKeyfile
	{
		EMVTokenKeyfile(){Id = EMV_CARDS_LABEL; Token = shared_ptr<EMVTokenInfo>(new EMVTokenInfo());};
		EMVTokenKeyfile(const TokenKeyfilePath& path);

		virtual operator TokenKeyfilePath () const;
		virtual void GetKeyfileData(vector <byte>& keyfileData) const;

	};

	class EMVToken {
	private:
		static IccDataExtractor extractor;
	public:
		static bool IsKeyfilePathValid(const wstring& emvTokenKeyfilePath);
		static vector<EMVTokenKeyfile> GetAvailableKeyfiles(unsigned long int* slotIdFilter = nullptr, const wstring keyfileIdFilter = wstring());
		static EMVTokenInfo GetTokenInfo(unsigned long int slotId);

		friend void EMVTokenKeyfile::GetKeyfileData(vector <byte>& keyfileData) const;

	};
}

#endif
