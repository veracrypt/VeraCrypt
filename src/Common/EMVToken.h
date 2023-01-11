

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

    struct EMVTokenKeyfilePath
	{
		EMVTokenKeyfilePath () { }
		EMVTokenKeyfilePath (const wstring &path) : Path (path) { }
		operator wstring () const { return Path; }
		wstring Path;	//Complete path
	};

	struct EMVTokenKeyfileInfo
	{
		unsigned long SlotId;	//Card reader slotId
		wstring Label ;	//Card name
	};

	struct EMVTokenKeyfile
	{
		EMVTokenKeyfile () : SlotId(~0UL) {}
		EMVTokenKeyfile (const EMVTokenKeyfilePath &path);

		operator EMVTokenKeyfilePath () const;

		static const wstring Id;	//File name = "emv" for every EMV keyfile
		string IdUtf8;	// ??
		unsigned long SlotId;	//Card reader slotId
		EMVTokenKeyfileInfo Token;	//Token infos
	};

    class EMVToken {
        public:
            static void GetKeyfileData (const EMVTokenKeyfile &keyfile, vector <byte> &keyfileData);
            static bool IsKeyfilePathValid (const wstring &securityTokenKeyfilePath);

    };
}

#endif