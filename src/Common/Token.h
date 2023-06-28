#ifndef TC_HEADER_Common_Token
#define TC_HEADER_Common_Token

#include "Platform/PlatformBase.h"

#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else

#	include "Platform/Exception.h"

#endif

#include <string>

#define UNAVAILABLE_SLOT ~0UL

namespace VeraCrypt {

	struct TokenKeyfilePath {
		TokenKeyfilePath(const wstring& path): Path(path) { }
		operator wstring () const { return Path; }

		wstring Path;	//Complete path

	};
	struct TokenInfo {
		TokenInfo() {}
		virtual ~TokenInfo() {}

		virtual BOOL isEditable() const=0;

		unsigned long int SlotId;
		wstring Label;	//Card name
	};

	struct TokenKeyfile {
		virtual operator TokenKeyfilePath () const = 0;
		virtual void GetKeyfileData(vector <byte>& keyfileData) const = 0;

		string IdUtf8;	                // Was used in SecurityToken to compare with the file name from a PKCS11 card, remove from token ?
		shared_ptr<TokenInfo> Token;
		wstring Id;
	};

	class Token {
	public:
		static vector<shared_ptr<TokenKeyfile>> GetAvailableKeyfiles(bool EMVOption);
		static bool IsKeyfilePathValid(const wstring& tokenKeyfilePath, bool EMVOption);
		static list <shared_ptr<TokenInfo>> GetAvailableTokens();	// List available token to write 
		static shared_ptr<TokenKeyfile> getTokenKeyfile(const TokenKeyfilePath path);
	};

};


#endif //TC_HEADER_Common_Token
