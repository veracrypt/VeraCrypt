#ifndef TC_HEADER_Common_EMVCard
#define TC_HEADER_Common_EMVCard

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

#include "Token.h"
#include "SCard.h"

namespace VeraCrypt
{
    typedef enum EMVCardType
	{
		NONE = 0,
		AMEX,
		MASTERCARD,
		VISA
	} EMVCardType;

	class EMVCard : public SCard
	{
    protected:

        // The following fields will only be empty if the card has not been read yet.
        // After the card has been read, and if some or all fields cannot be read, the EMVCard
        // object will be considered invalid and will not be included in the list of available cards
        // of EMVToken.
        vector<byte> m_aid;
        vector<vector<byte>> m_supportedAids;
        vector<byte> m_iccCert;
        vector<byte> m_issuerCert;
        vector<byte> m_cplcData;
        wstring m_lastPANDigits;

	public:

        // Add other AIDS
		// https://gist.github.com/pvieito/6224eed92c99b069f6401996c548d0e4
		// https://ambimat.com/developer-resources/list-of-application-identifiers-aid/
		const static byte AMEX_AID[7];
		const static byte MASTERCARD_AID[7];
		const static byte VISA_AID[7];
		const static map<EMVCardType, vector<byte>> SUPPORTED_AIDS;

        EMVCard();
		EMVCard(size_t slotId);
        EMVCard(const EMVCard& other);
		EMVCard(EMVCard&& other);
		EMVCard& operator = (const EMVCard& other);
		EMVCard& operator = (EMVCard&& other);
        virtual ~EMVCard();

        void Clear(void);

		// Retrieves the card's AID.
		// It first checks the card against a list of supported AIDs.
		// If that fails, it tries getting the AID from the card using PSE
		vector<byte> GetCardAID(bool forceContactless = false);

		void GetCardContent(vector<byte>& iccCert, vector<byte>& issuerCert, vector<byte>& cplcData);
		void GetCardPAN(wstring& lastPANDigits);
	};
}

#endif // TC_HEADER_Common_EMVCard
