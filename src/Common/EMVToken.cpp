#include "EMVToken.h"
#include "TLVParser.h"
#include "SCardReader.h"
#include "PCSCException.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <vector>
#include <iostream>
#include <algorithm>

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
	void AppendData(vector<byte>& buffer, const unsigned char* pbData, size_t cbData, size_t from, size_t length, bool bEncodeLength = false)
	{
		if (cbData > 0 && from <= cbData - 2 && length > 0 && length <= cbData - from)
		{
			size_t offset = (bEncodeLength ? 4 : 0);
			size_t orgSize = buffer.size();
			buffer.resize(orgSize + length + offset);
			if (bEncodeLength)
			{
				unsigned int dwLength = (unsigned int)(length);
				memcpy(buffer.data() + orgSize, &dwLength, 4);
			}
			memcpy(buffer.data() + orgSize + offset, pbData + from, length);
		}
	}

	/* ****************************************************************************************************************************************** */

	map <unsigned long int, shared_ptr<EMVCard>> EMVToken::EMVCards;

	EMVTokenInfo::~EMVTokenInfo()
	{
		if (Label.size() > 0)
			burn(&Label[0], Label.size() * sizeof(wchar_t));
	}

	EMVTokenKeyfile::EMVTokenKeyfile()
	{
		Id = EMV_CARDS_LABEL;
		Token = shared_ptr<EMVTokenInfo>(new EMVTokenInfo());
	}

	EMVTokenKeyfile::EMVTokenKeyfile(const TokenKeyfilePath& path)
	{
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf(pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw InvalidEMVPath();

		Id = EMV_CARDS_LABEL;
		Token = shared_ptr<EMVTokenInfo>(new EMVTokenInfo());
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
		map <unsigned long int, shared_ptr<EMVCard>>::iterator emvCardsIt;
		shared_ptr<EMVCard> card;
		vector<byte> iccCert;
		vector<byte> issuerCert;
		vector<byte> cplcData;
		bool addNewCard = true;

		keyfileData.clear();
		
		emvCardsIt = EMVToken::EMVCards.find(Token->SlotId);
		if (emvCardsIt != EMVToken::EMVCards.end())
		{
			// An EMVCard object has already been created for this slotId.
			// We check that it's SCard handle is still valid.
			// If it is, we use the existing EMVCard to get the card's content.
			// If it is not, we remove the EMVCard from EMVCards and create a new one.
			
			if (emvCardsIt->second->IsCardHandleValid())
			{
				emvCardsIt->second->GetCardContent(iccCert, issuerCert, cplcData);
				addNewCard = false;
			}
			else
			{
				EMVToken::EMVCards.erase(emvCardsIt);
			}
		}

		if (addNewCard)
		{
			// An EMVCard object does not exist for this slotId, or exists but its handle is not valid anymore.
			// We create a new one and then add it to EMVCards.
			card = make_shared<EMVCard>(Token->SlotId);
			card->GetCardContent(iccCert, issuerCert, cplcData);
			EMVToken::EMVCards.insert(make_pair(Token->SlotId, card));
		}

		AppendData(keyfileData, iccCert.data(), iccCert.size(), 0, iccCert.size());
		AppendData(keyfileData, issuerCert.data(), issuerCert.size(), 0, issuerCert.size());
		AppendData(keyfileData, cplcData.data(), cplcData.size(), 0, cplcData.size());
	}

	bool EMVToken::IsKeyfilePathValid(const wstring& emvTokenKeyfilePath)
	{
		return emvTokenKeyfilePath.find(TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
	}

	vector<EMVTokenKeyfile> EMVToken::GetAvailableKeyfiles(unsigned long int* slotIdFilter, const wstring& keyfileIdFilter)
	{
		vector <EMVTokenKeyfile> keyfiles;
		vector<wstring> readers;

		readers = EMVCard::manager.GetReaders();
		for (unsigned long int slotId = 0; slotId < readers.size(); slotId++)
		{
			EMVTokenInfo token;

			if (slotIdFilter && *slotIdFilter != slotId)
				continue;

			try
			{
				token = GetTokenInfo(slotId);
			}
			catch(ParameterIncorrect&)
			{
				continue;
			}
			catch(EMVUnknownCardType&)
			{
				continue;
			}
			catch(EMVSelectAIDFailed&)
			{
				continue;
			}
			catch(EMVPANNotFound&)
			{
				continue;
			}
			catch(PCSCException&)
			{
				continue;
			}

			EMVTokenKeyfile keyfile;
			keyfile.Token = shared_ptr<TokenInfo>(new EMVTokenInfo(token));
			keyfile.Token->SlotId = slotId;

			// keyfileIdFilter is of no use for EMV tokens as the Id is always set to EMV_CARDS_LABEL.
			// Nonetheless, we keep the following code that is also used in SecurityToken::GetAvailableKeyfiles.
			if (keyfile.Id.empty() || (!keyfileIdFilter.empty() && keyfileIdFilter != keyfile.Id))
				continue;

			keyfiles.push_back(keyfile);

			if (!keyfileIdFilter.empty())
				break;
		}

		return keyfiles;
	}

	EMVTokenInfo EMVToken::GetTokenInfo(unsigned long int slotId)
	{
		EMVTokenInfo token;
		wstring lastPANDigits;
		map <unsigned long int, shared_ptr<EMVCard>>::iterator emvCardsIt;
		shared_ptr<EMVCard> card;
		bool addNewCard = true;

		emvCardsIt = EMVCards.find(slotId);
		if (emvCardsIt != EMVCards.end())
		{
			// An EMVCard object has already been created for this slotId.
			// We check that it's SCard handle is still valid.
			// If it is, we use the existing EMVCard to get the card's PAN.
			// If it is not, we remove the EMVCard from EMVCards and create a new one.
			
			if (emvCardsIt->second->IsCardHandleValid())
			{
				emvCardsIt->second->GetCardPAN(lastPANDigits);
				addNewCard = false;
			}
			else
			{
				EMVCards.erase(emvCardsIt);
			}
		}

		if (addNewCard)
		{
			// An EMVCard object does not exist for this slotId, or exists but its handle is not valid anymore.
			// We create a new one and then add it to EMVCards.
			card = make_shared<EMVCard>(slotId);
			card->GetCardPAN(lastPANDigits);
			EMVCards.insert(make_pair(slotId, card));
		}

		token.SlotId = slotId;
		token.Label = L"EMV card **** ";
		token.Label += lastPANDigits;
		burn(&lastPANDigits[0], lastPANDigits.size() * sizeof(wchar_t));

		return token;
	}
}
