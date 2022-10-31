#include "EMVToken.h"

extern "C" {
    #include "IccExtractor.h"
}

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
    EMVTokenInfo::EMVTokenInfo(const EMVTokenPath &path)
    {
        wstring pathStr = path;
        unsigned long slotId;

        if (swscanf(pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
            throw nullptr; // InvalidSecurityTokenKeyfilePath();

        SlotId = slotId;
    }

    EMVTokenInfo::operator EMVTokenPath() const
    {
        wstringstream path;
        path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << SlotId;
        return path.str();
    }

    void EMVToken::GetKeyfileData(const EMVTokenInfo &keyfile, vector<byte> &keyfileData)
    {
        // TODO: Add EMV card data inside the vector of bytes keyfileData
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
        fprintf(stderr,"GettingAllCerts");
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

    bool EMVToken::IsKeyfilePathValid(const wstring &securityTokenKeyfilePath)
    {
        return securityTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
    }

}