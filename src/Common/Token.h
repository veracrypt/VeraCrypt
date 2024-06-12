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

namespace VeraCrypt
{
	struct TokenKeyfilePath
	{
		virtual ~TokenKeyfilePath() {};
		TokenKeyfilePath(const wstring& path): Path(path) { }
		operator wstring () const { return Path; }

		wstring Path;	// Complete path
	};

	struct TokenInfo
	{
		TokenInfo(): SlotId(0), Label(L"") {}
		virtual ~TokenInfo() {}

		virtual BOOL isEditable() const = 0;

		unsigned long int SlotId;
		wstring Label;	// Card name
	};

	struct TokenKeyfile
	{
		virtual ~TokenKeyfile() {}
		virtual operator TokenKeyfilePath () const = 0;
		virtual void GetKeyfileData(vector <uint8>& keyfileData) const = 0;

		shared_ptr<TokenInfo> Token;
		wstring Id;
	};

	class Token
	{
	public:
		static vector< shared_ptr<TokenKeyfile> > GetAvailableKeyfiles(bool isEMVSupportEnabled);
		static bool IsKeyfilePathValid(const wstring& tokenKeyfilePath, bool isEMVSupportEnabled);
		static list < shared_ptr<TokenInfo> > GetAvailableTokens();
		static shared_ptr<TokenKeyfile> getTokenKeyfile(const TokenKeyfilePath& path);
	};
};


#endif //TC_HEADER_Common_Token
