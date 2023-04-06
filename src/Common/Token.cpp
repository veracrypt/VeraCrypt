#include "Token.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"

#if !defined(TC_WINDOWS) || defined(TC_PROTOTYPE)
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"
#include "Platform/SystemException.h"
#else
#include "Dictionary.h"
#include "Language.h"
#endif

#include <vector>
#include <algorithm>
#include <memory>

#include "SecurityToken.h"
#include "EMVToken.h"
#include "iostream"

using namespace std;

namespace VeraCrypt
{
	vector<shared_ptr<TokenKeyfile>> Token::GetAvailableKeyfiles(bool EMVOption) {
		vector<shared_ptr<TokenKeyfile>> availableKeyfiles;
		bool securityTokenLibraryInitialized = true;

		try{
			foreach (SecurityTokenKeyfile k, SecurityToken::GetAvailableKeyfiles()) {
				availableKeyfiles.push_back(shared_ptr<TokenKeyfile>(new SecurityTokenKeyfile(k)));
			}
		} catch (SecurityTokenLibraryNotInitialized){
			securityTokenLibraryInitialized = false;
		}

        if(EMVOption){
            foreach (EMVTokenKeyfile k, EMVToken::GetAvailableKeyfiles()) {
                availableKeyfiles.push_back(shared_ptr<TokenKeyfile>(new EMVTokenKeyfile(k)));
            }
        }

		if(availableKeyfiles.size() == 0 && ! securityTokenLibraryInitialized){
			throw SecurityTokenLibraryNotInitialized();
		}

		return availableKeyfiles;
	}

	bool Token::IsKeyfilePathValid(const wstring& tokenKeyfilePath, bool EMVOption)
	{
        if(EMVOption){
            return SecurityToken::IsKeyfilePathValid(tokenKeyfilePath) || EMVToken::IsKeyfilePathValid(tokenKeyfilePath);
        }
		return SecurityToken::IsKeyfilePathValid(tokenKeyfilePath);
	}

	list <shared_ptr<TokenInfo>> Token::GetAvailableTokens()
	{
		list <shared_ptr<TokenInfo>> availableTokens;
		foreach(SecurityTokenInfo securityToken, SecurityToken::GetAvailableTokens()){
			availableTokens.push_back(shared_ptr<TokenInfo>(new SecurityTokenInfo(std::move(securityToken))));
		}

		return availableTokens ;
	}

	shared_ptr<TokenKeyfile> Token::getTokenKeyfile(const TokenKeyfilePath path){
		shared_ptr<TokenKeyfile> tokenKeyfile;

		if(SecurityToken::IsKeyfilePathValid(path)){
			tokenKeyfile = shared_ptr<TokenKeyfile>(new SecurityTokenKeyfile(path));
		} else {
			if(EMVToken::IsKeyfilePathValid(path)){
				tokenKeyfile = shared_ptr<TokenKeyfile>(new EMVTokenKeyfile(path));
			}		
		}

		return tokenKeyfile;
	}
}