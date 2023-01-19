#include "EMVToken.h"

#include "IccExtractor.h"

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

	void EMVToken::GetKeyfileData(const TokenKeyfile& keyfile, vector<byte>& keyfileData)
	{
		// Add EMV card data inside the vector of bytes keyfileData
		// (note: the vector already exists, so we can simply do keyfileData.push_back(a_byte) )
		// The variable keyfile contains the card id, accessible by reading keyfile.SlotID

		std::cerr << "EstablishRSContext" << std::endl;
		EstablishRSContext();
		std::cerr << "GetReaders" << std::endl;
		GetReaders();
		int reader_nb = keyfile.SlotId;
		std::cerr << "ConnectCard" << std::endl;
		ConnectCard(reader_nb);
		std::cerr << "StatusCard" << std::endl;
		StatusCard();

		// we create a unsigned char array to store the data and then convert it to a vector to pass it to the keyfileData
		unsigned char ICC_DATA[1024]; // 1024 bytes should be enough to store the issuer and icc pk certificate of one app + CPCL
		for (int i = 0; i < 1024; i++) {
			ICC_DATA[i] = 0;
		}

		int ICC_DATA_SIZE = 0;
		fprintf(stderr, "GettingAllCerts");
		GettingAllCerts(ICC_DATA, &ICC_DATA_SIZE);

		// we push the datas into the keyfileData vector
		for (int i = 0; i < ICC_DATA_SIZE; i++)
		{
			keyfileData.push_back(ICC_DATA[i]);
		}

		std::cerr << "FinishClean" << std::endl;
		FinishClean();
		std::cerr << "EMV Part DONE!!!" << std::endl;
	}

	bool EMVToken::IsKeyfilePathValid(const wstring& emvTokenKeyfilePath)
	{
		return emvTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	//todo
	vector<EMVTokenKeyfile> EMVToken::GetAvailableKeyfiles() {
        EMVTokenKeyfile k;
        shared_ptr<EMVTokenKeyfileInfo> i = shared_ptr<EMVTokenKeyfileInfo>(new EMVTokenKeyfileInfo);
        k.SlotId = 0;
        i->Label = L"EMV card **** **** **** 1456";
        k.Token = i;
        vector<EMVTokenKeyfile> res;
        res.push_back(k);
        return res;
	}

}
