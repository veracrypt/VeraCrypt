#include "EMVToken.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <vector>

#if !defined (TC_WINDOWS) || defined (TC_PROTOTYPE)
#	include "Platform/SerializerFactory.h"
#	include "Platform/StringConverter.h"
#	include "Platform/SystemException.h"
#else
#	include "Dictionary.h"
#	include "Language.h"
#endif

using namespace std;

namespace VeraCrypt {
    EMVTokenInfo::EMVTokenInfo (const EMVTokenPath &path)
	{
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf (pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw nullptr; //InvalidSecurityTokenKeyfilePath();

		SlotId = slotId;
	}

	EMVTokenInfo::operator EMVTokenPath () const
	{
		wstringstream path;
		path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << SlotId;
		return path.str();
	}

    void EMVToken::GetKeyfileData (const EMVTokenInfo &keyfile, vector <byte> &keyfileData) {
        // TODO: Add EMV card data inside the vector of bytes keyfileData
        // (note: the vector already exists, so we can simply do keyfileData.push_back(a_byte) )
        // The variable keyfile contains the card id, accessible by reading keyfile.SlotID

        // Placeholder
        for (byte b = 0x00; b <= 0xFF; b++)
            keyfileData.push_back(b);
    }

    bool EMVToken::IsKeyfilePathValid (const wstring &securityTokenKeyfilePath) {
        return securityTokenKeyfilePath.find (TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
    }


}