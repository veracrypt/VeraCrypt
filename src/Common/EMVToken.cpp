#include "EMVToken.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <vector>
#include <iostream>



#if !defined(TC_WINDOWS) || defined(TC_PROTOTYPE)
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"
#include "Platform/SystemException.h"
#else
#include "Dictionary.h"
#include "Language.h"
#endif


using namespace std;

namespace VeraCrypt
{

	IccDataExtractor EMVToken::extractor;

	EMVTokenInfo::~EMVTokenInfo()
	{
		burn(&Label,Label.size());
	}

	EMVTokenKeyfile::EMVTokenKeyfile(const TokenKeyfilePath& path)
	{
		Id = EMV_CARDS_LABEL;
		Token = shared_ptr<EMVTokenInfo>(new EMVTokenInfo());
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf(pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw InvalidEMVPath();

		Token->SlotId = slotId;
	}

	EMVTokenKeyfile::operator TokenKeyfilePath () const
	{
		wstringstream path;
		path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << Token->SlotId;
		return path.str();
	}

	void EMVTokenKeyfile::GetKeyfileData(vector <byte>& keyfileData) const
	{
		#ifdef TC_WINDOWS
		EMVToken::extractor.InitLibrary();
		#endif

		EMVToken::extractor.GetReaders();
		EMVToken::extractor.GettingAllCerts(Token->SlotId, keyfileData);
	}

	bool EMVToken::IsKeyfilePathValid(const wstring& emvTokenKeyfilePath)
	{
		return emvTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	vector<EMVTokenKeyfile> EMVToken::GetAvailableKeyfiles(unsigned long int* slotIdFilter, const wstring keyfileIdFilter) {
		#ifdef TC_WINDOWS
		EMVToken::extractor.InitLibrary();
		#endif

		vector <EMVTokenKeyfile> keyfiles;
		unsigned long int nb = 0;

		nb = EMVToken::extractor.GetReaders();
	

		for(unsigned long int slotId = 0; slotId<nb; slotId++)
		{
			EMVTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try{
				token = GetTokenInfo(slotId);
			} catch(EMVUnknownCardType) {
				continue;
			}catch(PCSCException){

					continue;
			}

			EMVTokenKeyfile keyfile;
			keyfile.Token->SlotId = slotId;
			keyfile.Token = shared_ptr<TokenInfo>(new EMVTokenInfo(token));

			keyfiles.push_back(keyfile);

			if (!keyfileIdFilter.empty())
				break;
		}

		return keyfiles;

	}


	EMVTokenInfo EMVToken::GetTokenInfo(unsigned long int slotId) {
		EMVTokenInfo token;
		token.SlotId = slotId;
		//card numbers extraction
		std::string pan;
		EMVToken::extractor.GettingPAN(slotId, pan);
		token.Label = L"EMV card **** ";
		token.Label += wstring (pan.begin(), pan.end());
		burn(&pan[0],pan.size());
		return token;
	}

}
