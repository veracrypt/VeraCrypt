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
		Id = L"emv";
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf(pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw nullptr; //InvalidSecurityTokenKeyfilePath(); TODO Create similar error

		SlotId = slotId;
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
		path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << SlotId;
		return path.str();
	}

	void EMVTokenKeyfile::GetKeyfileData(vector <byte>& keyfileData) const
	{
		keyfileData = EMVToken::extractor.GettingAllCerts(SlotId);
		return;
	}

	bool EMVToken::IsKeyfilePathValid(const wstring& emvTokenKeyfilePath)
	{
		return emvTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	vector<EMVTokenKeyfile> EMVToken::GetAvailableKeyfiles(unsigned long int* slotIdFilter, const wstring keyfileIdFilter) {
		vector <EMVTokenKeyfile> keyfiles;

		for(unsigned long int slotId = 0; slotId<EMVToken::extractor.GetReaders(); slotId++)
		{
			EMVTokenKeyfileInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try{
				token = GetTokenInfo(slotId);
			} catch(ICCExtractionException) {
				cout << "Not EMV Type" << endl;
				continue;
			}


			EMVTokenKeyfile keyfile;
			keyfile.SlotId = slotId;
			keyfile.Token = shared_ptr<EMVTokenKeyfileInfo>(new EMVTokenKeyfileInfo(token));

			keyfiles.push_back(keyfile);

			if (!keyfileIdFilter.empty())
				break;
		}

		return keyfiles;

	}


	EMVTokenKeyfileInfo EMVToken::GetTokenInfo(unsigned long int slotId) {
		EMVTokenKeyfileInfo token;
		token.SlotId = slotId;
		//card numbers recuperation
		std::string w = EMVToken::extractor.GettingPAN(slotId);

		token.Label = L"****-" + (wstring (w.begin(), w.end())).substr(w.size()-4);

		return token;
	}

}
