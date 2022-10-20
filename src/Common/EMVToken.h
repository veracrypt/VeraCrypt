#ifndef TC_HEADER_Common_EMVToken
#define TC_HEADER_Common_EMVToken

#define TC_EMV_TOKEN_KEYFILE_URL_PREFIX L"emv://"
#define TC_EMV_TOKEN_KEYFILE_URL_SLOT L"slot"

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

namespace VeraCrypt {

    struct EMVTokenPath
	{
		EMVTokenPath () { }
		EMVTokenPath (const wstring &path) : Path (path) { }
		operator wstring () const { return Path; }
		wstring Path;
	};

	struct EMVTokenInfo
	{
		EMVTokenInfo () : SlotId(~0UL) {}
		EMVTokenInfo (const EMVTokenPath &path);

		operator EMVTokenPath () const;

		unsigned long SlotId;
	};

    class EMVToken {
        public:
            static void GetKeyfileData (const EMVTokenInfo &keyfile, vector <byte> &keyfileData);
            static bool IsKeyfilePathValid (const wstring &securityTokenKeyfilePath);

    };
}

#endif