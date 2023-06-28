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
#include "PCSCException.h"
#include "iostream"

using namespace std;

namespace VeraCrypt
{
	vector<shared_ptr<TokenKeyfile>> Token::GetAvailableKeyfiles(bool isEMVSupportEnabled)
	{
		vector<shared_ptr<TokenKeyfile>> availableKeyfiles;
		bool securityTokenLibraryInitialized = true;
		bool scardLibraryInitialized = true;

		try
		{
			foreach (SecurityTokenKeyfile k, SecurityToken::GetAvailableKeyfiles())
			{
				availableKeyfiles.push_back(shared_ptr<TokenKeyfile>(new SecurityTokenKeyfile(k)));
			}
		}
		catch (SecurityTokenLibraryNotInitialized&)
		{
			securityTokenLibraryInitialized = false;
		}
		
		if (isEMVSupportEnabled)
		{
			try
			{
				foreach (EMVTokenKeyfile k, EMVToken::GetAvailableKeyfiles())
				{
					availableKeyfiles.push_back(shared_ptr<TokenKeyfile>(new EMVTokenKeyfile(k)));
				}
			}
			catch (ScardLibraryInitializationFailed&)
			{
				scardLibraryInitialized = false;
			}
		}

		if (availableKeyfiles.size() == 0)
		{
			if (!securityTokenLibraryInitialized)
			{
				throw SecurityTokenLibraryNotInitialized();
			}
			else if (!scardLibraryInitialized)
			{
				throw ScardLibraryInitializationFailed();
			}
		}

		return availableKeyfiles;
	}

	bool Token::IsKeyfilePathValid(const wstring& tokenKeyfilePath, bool isEMVSupportEnabled)
	{
		if (isEMVSupportEnabled)
		{
			return SecurityToken::IsKeyfilePathValid(tokenKeyfilePath) || EMVToken::IsKeyfilePathValid(tokenKeyfilePath);
		}
		return SecurityToken::IsKeyfilePathValid(tokenKeyfilePath);
	}

	list <shared_ptr<TokenInfo>> Token::GetAvailableTokens()
	{
		list <shared_ptr<TokenInfo>> availableTokens;

		foreach(SecurityTokenInfo securityToken, SecurityToken::GetAvailableTokens())
		{
			availableTokens.push_back(shared_ptr<TokenInfo>(new SecurityTokenInfo(std::move(securityToken))));
		}

		return availableTokens ;
	}

	shared_ptr<TokenKeyfile> Token::getTokenKeyfile(const TokenKeyfilePath& path)
	{
		shared_ptr<TokenKeyfile> tokenKeyfile;

		if (SecurityToken::IsKeyfilePathValid(path))
		{
			tokenKeyfile = shared_ptr<TokenKeyfile>(new SecurityTokenKeyfile(path));
		}
		else 
		{
			if (EMVToken::IsKeyfilePathValid(path))
			{
				tokenKeyfile = shared_ptr<TokenKeyfile>(new EMVTokenKeyfile(path));
			}		
		}

		return tokenKeyfile;
	}
}