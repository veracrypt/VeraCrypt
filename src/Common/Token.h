#ifndef TC_HEADER_Common_Token
#define TC_HEADER_Common_Token

#include "Platform/PlatformBase.h"

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else

#	include "Platform/Exception.h"

#endif

#include <string>


namespace VeraCrypt {

    struct TokenKeyfilePath {

        TokenKeyfilePath () { }
        TokenKeyfilePath (const wstring &path) : Path (path) { }

        operator wstring () const { return Path; }
        wstring Path;	//Complete path

    };
    struct TokenInfo {

    };

    struct TokenKeyfile {
        virtual operator TokenKeyfilePath () const = 0;
    };

    class Token {
    public:
        static vector<unique_ptr<TokenKeyfile>> GetAvailableKeyfiles();
        static bool isValidPath(TokenKeyfilePath p);

    };
}


#endif //TC_HEADER_Common_Token
