#include "EMVToken.h"

#include "IccDataExtractor.h"

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

	EMVTokenKeyfile::EMVTokenKeyfile(const TokenKeyfilePath& path)
	{
		Id = EMV_CARDS_LABEL;
		Token = shared_ptr<EMVTokenInfo>(new EMVTokenInfo());
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf(pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw nullptr; //InvalidSecurityTokenKeyfilePath(); TODO Create similar error

		Token->SlotId = slotId;
		/* TODO : Make a similar thing to get an EMVTokenKeyfile token.Label filled with the card number
		Need : EMVToken::GetAvailableKeyfiles(unsined long *slotIdFilter = nullptr, const wstring keyfileIdFilter = EMV_CARDS_LABEL)
		returning a vector of EMVTokenKeyfile matching the filters

		vector <SecurityTokenKeyfile> keyfiles = SecurityToken::GetAvailableKeyfiles (&SlotId, Id);

		if (keyfiles.empty())
		throw SecurityTokenKeyfileNotFound();

		*this = keyfiles.front();*/
	}

	EMVTokenKeyfile::operator TokenKeyfilePath () const
	{
		wstringstream path;
		path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << Token->SlotId;
		return path.str();
	}

	void EMVTokenKeyfile::GetKeyfileData(vector <byte>& keyfileData) const
	{
		EMVToken::extractor.GettingAllCerts(Token->SlotId, keyfileData);
	}

	bool EMVToken::IsKeyfilePathValid(const wstring& emvTokenKeyfilePath)
	{
		return emvTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	vector<EMVTokenKeyfile> EMVToken::GetAvailableKeyfiles(unsigned long int* slotIdFilter, const wstring keyfileIdFilter) {
		vector <EMVTokenKeyfile> keyfiles;
		unsigned long int nb = 0;

		try{
			nb = EMVToken::extractor.GetReaders();
		}catch(ICCExtractionException){
			cout << "PB pour lister les lecteurs" << endl;
		}

		for(unsigned long int slotId = 0; slotId<nb; slotId++)
		{
			EMVTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try{
				token = GetTokenInfo(slotId);
			} catch(ICCExtractionException) {
				cout << "Not EMV Type" << endl;
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
		std::string w = EMVToken::extractor.GettingPAN(slotId);
		token.Label = L"EMV card ****-" + (wstring (w.begin(), w.end())).substr(w.size()-4);

		return token;
	}

}
