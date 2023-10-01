#include "EMVCard.h"
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
#ifndef TC_WINDOWS
	wstring ArrayToHexWideString(const unsigned char * pbData, size_t cbData)
	{
		static wchar_t* hexChar = L"0123456789ABCDEF";
		wstring result;
		if (pbData)
		{
			for (int i = 0; i < cbData; i++)
			{
				result += hexChar[pbData[i] >> 4];
				result += hexChar[pbData[i] & 0x0F];
			}
		}

		return result;
	}
#endif

	map<EMVCardType, vector<byte>> InitializeSupportedAIDs()
	{
		map<EMVCardType, vector<byte>> supportedAIDs;
		supportedAIDs.insert(std::make_pair(EMVCardType::AMEX, vector<byte>(EMVCard::AMEX_AID, EMVCard::AMEX_AID + sizeof(EMVCard::AMEX_AID))));
		supportedAIDs.insert(std::make_pair(EMVCardType::MASTERCARD, vector<byte>(EMVCard::MASTERCARD_AID, EMVCard::MASTERCARD_AID + sizeof(EMVCard::MASTERCARD_AID))));
		supportedAIDs.insert(std::make_pair(EMVCardType::VISA, vector<byte>(EMVCard::VISA_AID, EMVCard::VISA_AID + sizeof(EMVCard::VISA_AID))));
		return supportedAIDs;
	}

	const byte EMVCard::AMEX_AID[7]										= {0xA0, 0x00, 0x00, 0x00, 0x00, 0x25, 0x10};
	const byte EMVCard::MASTERCARD_AID[7]								= {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};
	const byte EMVCard::VISA_AID[7]										= {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
	const map<EMVCardType, vector<byte>> EMVCard::SUPPORTED_AIDS		= InitializeSupportedAIDs();

	EMVCard::EMVCard() : SCard(), m_lastPANDigits(L"")
	{
	}
	
	EMVCard::EMVCard(size_t slotId) : SCard(slotId), m_lastPANDigits(L"")
    {
    }

    EMVCard::~EMVCard()
    {
		Clear();
    }

	EMVCard::EMVCard(const EMVCard& other) :
			SCard(other),
			m_aid(other.m_aid),
			m_supportedAids(other.m_supportedAids),
			m_iccCert(other.m_iccCert),
			m_issuerCert(other.m_issuerCert),
			m_cplcData(other.m_cplcData),
			m_lastPANDigits(other.m_lastPANDigits)
	{
	}

	EMVCard::EMVCard(EMVCard&& other) :
			SCard(other),
			m_aid(std::move(other.m_aid)),
			m_supportedAids(std::move(other.m_supportedAids)),
			m_iccCert(std::move(other.m_iccCert)),
			m_issuerCert(std::move(other.m_issuerCert)),
			m_cplcData(std::move(other.m_cplcData)),
			m_lastPANDigits(std::move(other.m_lastPANDigits))
	{
	}
	
	EMVCard& EMVCard::operator = (const EMVCard& other)
	{
		if (this != &other)
		{
			SCard::operator=(other);
			m_aid = other.m_aid;
			m_supportedAids = other.m_supportedAids;
			m_iccCert = other.m_iccCert;
			m_issuerCert = other.m_issuerCert;
			m_cplcData = other.m_cplcData;
			m_lastPANDigits = other.m_lastPANDigits;
		}
		return *this;
	}
	
	EMVCard& EMVCard::operator = (EMVCard&& other)
	{
		if (this != &other)
		{
			SCard::operator=(other);
			m_reader = std::move(other.m_reader);
			m_aid = std::move(other.m_aid);
			m_supportedAids = std::move(other.m_supportedAids);
			m_iccCert = std::move(other.m_iccCert);
			m_issuerCert = std::move(other.m_issuerCert);
			m_cplcData = std::move(other.m_cplcData);
			m_lastPANDigits = std::move(other.m_lastPANDigits);
		}
		return *this;
	}

	void EMVCard::Clear(void)
	{
		m_aid.clear();
		m_supportedAids.clear();
		m_iccCert.clear();
		m_issuerCert.clear();
		m_cplcData.clear();
		m_lastPANDigits.clear();
	}

	vector<byte> EMVCard::GetCardAID(bool forceContactless)
	{
		vector<vector<byte>> 				supportedAIDs;
		vector<byte> 						supportedAIDsPriorities;
		vector<pair<byte, vector<byte>>> 	supportedAIDsSorted;
		bool 								hasBeenReset = false;
		CommandAPDU 						command;
		ResponseAPDU 						response;
		vector<byte> 						responseData;
		shared_ptr<TLVNode> 				rootNode;
		shared_ptr<TLVNode> 				fciNode;
		shared_ptr<TLVNode> 				dfNameNode;
		shared_ptr<TLVNode> 				sfiNode;
		shared_ptr<TLVNode> 				fciIssuerNode;
		shared_ptr<TLVNode> 				fciIssuerDiscretionaryDataNode;
		shared_ptr<TLVNode> 				templateNode;
		vector<shared_ptr<TLVNode>> 		pseDirectoryNodes;
		unsigned char 						sfi;
		bool 								usingContactless = false;
		vector<byte>						tokenAID;

		if (m_aid.size())
			return m_aid;

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				try
				{
					for (auto it = EMVCard::SUPPORTED_AIDS.begin(); it != EMVCard::SUPPORTED_AIDS.end(); it++)
					{
						command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, it->second, SCardReader::shortAPDUMaxTransSize);
						m_reader->ApduProcessData(command, response);
						if (response.getSW() == SW_NO_ERROR)
						{
							tokenAID = it->second;
							break;
						}
					}

					if (tokenAID.size())
					{
						m_supportedAids.push_back(tokenAID);
						m_aid = tokenAID;
					}
					else
					{
						// The following code retrieves the supported AIDs from the card using PSE.
						// If the card supports more than one AID, the returned list is sorted using the AIDs priorities,
						// the first AID being the one with more priority.
						if (forceContactless)
						{
							usingContactless = true;
							command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE2, 0, sizeof(EMV_PSE2), SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
						}
						else 
						{
							command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE1, 0, sizeof(EMV_PSE1), SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
							if (response.getSW() != SW_NO_ERROR)
							{
								// EMV_PSE2 not found, try EMV_PSE1
								usingContactless = true;
								command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMV_PSE2, 0, sizeof(EMV_PSE2), SCardReader::shortAPDUMaxTransSize);
								m_reader->ApduProcessData(command, response);
							}
						}
						if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
						{
							responseData = response.getData();
							rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
							fciNode = TLVParser::TLV_Find(rootNode, EMV_FCI_TAG);
							if (fciNode && fciNode->Subs->size() >= 2)
							{
								if (usingContactless)
								{
									fciIssuerNode = TLVParser::TLV_Find(fciNode, EMV_FCI_ISSUER_TAG);
									if (fciIssuerNode && fciIssuerNode->Subs->size() >= 1)
									{
										fciIssuerDiscretionaryDataNode = TLVParser::TLV_Find(fciIssuerNode, EMV_FCI_ISSUER_DISCRETIONARY_DATA_TAG);
										if (fciIssuerDiscretionaryDataNode && fciIssuerDiscretionaryDataNode->Subs->size() >= 1)
										{
											for (size_t i = 0; i < fciIssuerDiscretionaryDataNode->Subs->size(); i++)
											{
												if (fciIssuerDiscretionaryDataNode->Subs->at(i)->Tag == EMV_DIRECTORY_ENTRY_TAG)
												{
													pseDirectoryNodes.push_back(fciIssuerDiscretionaryDataNode->Subs->at(i));
												}
											}
										}
									}
								}
								else
								{
									dfNameNode = TLVParser::TLV_Find(fciNode, EMV_DFNAME_TAG);
									if (dfNameNode)
									{
										fciIssuerNode = TLVParser::TLV_Find(fciNode, EMV_FCI_ISSUER_TAG);
										if (fciIssuerNode)
										{
											sfiNode = TLVParser::TLV_Find(fciIssuerNode, EMV_SFI_TAG);
											if (sfiNode && sfiNode->Value->size() == 1)
											{
												sfi = sfiNode->Value->at(0);

												byte rec = 1;
												do
												{
													command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec++, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
													m_reader->ApduProcessData(command, response);
													if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
													{
														responseData = response.getData();

														try
														{
															templateNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
															if (templateNode && templateNode->Tag == EMV_TEMPLATE_TAG && templateNode->Subs->size() >= 1)
															{
																for (size_t i = 0; i < templateNode->Subs->size(); i++)
																{
																	if (templateNode->Subs->at(i)->Tag == EMV_DIRECTORY_ENTRY_TAG)
																	{
																		pseDirectoryNodes.push_back(templateNode->Subs->at(i));
																	}
																}
															}
														}
														catch(TLVException)
														{
															continue;
														}
													}
												} while (response.getData().size() > 0);
											}
										}
									}
								}
							}
						}

						for (size_t i = 0; i < pseDirectoryNodes.size(); i++)
						{
							shared_ptr<TLVNode> aidNode;
							shared_ptr<TLVNode> aidPriorityNode;
							aidNode = TLVParser::TLV_Find(pseDirectoryNodes[i], EMV_AID_TAG);
							aidPriorityNode = TLVParser::TLV_Find(pseDirectoryNodes[i], EMV_PRIORITY_TAG);
							if (aidNode && aidNode->Value->size() > 0 && aidPriorityNode && aidPriorityNode->Value->size() == 1)
							{
								supportedAIDs.push_back(*aidNode->Value.get());
								supportedAIDsPriorities.push_back(aidNode->Value->at(0));
							}
						}
						for(size_t i = 0; i < supportedAIDs.size(); i++)
						{
							supportedAIDsSorted.push_back(make_pair(supportedAIDsPriorities[i], supportedAIDs[i]));
						}
						std::sort(supportedAIDsSorted.begin(), supportedAIDsSorted.end());
						for(size_t i = 0; i < supportedAIDs.size(); i++)
						{
							supportedAIDs[i] = supportedAIDsSorted[i].second;
						}

						if (supportedAIDs.size())
						{
							m_supportedAids = supportedAIDs;
							tokenAID = supportedAIDs[0];
							m_aid = tokenAID;
						}
					}
				}
				catch (...)
				{
				}
			}
		}

		return tokenAID;
	}

	void EMVCard::GetCardContent(vector<byte>& iccCert, vector<byte>& issuerCert, vector<byte>& cplcData)
	{
		bool						hasBeenReset	= false;
		bool						aidSelected		= false;
		bool						iccFound		= false;
		bool						issuerFound		= false;
		bool						cplcFound		= false;
		vector<byte>				emvCardAid;
		shared_ptr<TLVNode>			rootNode;
		shared_ptr<TLVNode>			iccPublicKeyCertNode;
		shared_ptr<TLVNode>			issuerPublicKeyCertNode;
		CommandAPDU					command;
		ResponseAPDU				response;
		vector<byte>				responseData;

		iccCert.clear();
		issuerCert.clear();
		cplcData.clear();

		if (m_iccCert.size() && m_issuerCert.size() && m_cplcData.size())
		{
			iccCert = m_iccCert;
			issuerCert = m_issuerCert;
			cplcData = m_cplcData;
			return;
		}

		emvCardAid = GetCardAID();
		if (emvCardAid.size() == 0)
		{
			throw EMVUnknownCardType();
		}

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				// First get CPLC before selecting the AID of the card.
				command = CommandAPDU(0x80, INS_GET_DATA, (EMV_CPLC_TAG >> 8) & 0xFF, EMV_CPLC_TAG & 0xFF, SCardReader::shortAPDUMaxTransSize);
				m_reader->ApduProcessData(command, response);
				if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
				{
					cplcFound = true;
					cplcData = response.getData();

					// Then get the certs.
					command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, emvCardAid, SCardReader::shortAPDUMaxTransSize);
					m_reader->ApduProcessData(command, response);
					if (response.getSW() == SW_NO_ERROR)
					{
						aidSelected = true;

						// TODO: Send GET PROCESSING OPTIONS to get the AIL and AFL,
						//		 which will then be used to get the actual start and end of sfi and rec.
						for (byte sfi = 1; sfi < 32 && (!iccFound || !issuerFound); sfi++)
						{
							for (byte rec = 1; rec < 17 && (!iccFound || !issuerFound); rec++)
							{
								command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
								m_reader->ApduProcessData(command, response);
								if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
								{
									responseData = response.getData();

									try
									{
										rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
									}
									catch(TLVException)
									{
										continue;
									}

									iccPublicKeyCertNode = TLVParser::TLV_Find(rootNode, EMV_ICC_PK_CERT_TAG);
									if (iccPublicKeyCertNode && iccPublicKeyCertNode->Value->size() > 0)
									{
										iccFound = true;
										iccCert = *iccPublicKeyCertNode->Value.get();
									}

									issuerPublicKeyCertNode = TLVParser::TLV_Find(rootNode, EMV_ISS_PK_CERT_TAG);
									if (issuerPublicKeyCertNode && issuerPublicKeyCertNode->Value->size() > 0)
									{
										issuerFound = true;
										issuerCert = *issuerPublicKeyCertNode->Value.get();
									}
								}
							}
						}
					}
				}
			}
		}

		if (!cplcFound)
			throw EMVCPLCNotFound();

		if (!aidSelected)
			throw EMVSelectAIDFailed();

		if (!iccFound)
			throw EMVIccCertNotFound();

		if (!issuerFound)
			throw EMVIssuerCertNotFound();

		m_iccCert = iccCert;
		m_issuerCert = issuerCert;
		m_cplcData = cplcData;
	}

	void EMVCard::GetCardPAN(wstring& lastPANDigits)
	{
		bool						hasBeenReset	= false;
		bool						panFound		= false;
		bool						aidSelected		= false;
		vector<byte>				EMVCardAid;
		vector<byte>				panData;
		shared_ptr<TLVNode>			rootNode;
		shared_ptr<TLVNode>			panNode;
		CommandAPDU					command;
		ResponseAPDU				response;
		vector<byte>				responseData;

		lastPANDigits = L"";

		if (m_lastPANDigits != L"")
		{
			lastPANDigits = m_lastPANDigits;
			return;
		}

		EMVCardAid = GetCardAID();
		if (EMVCardAid.size() == 0)
		{
			throw EMVUnknownCardType();
		}

		if (m_reader)
		{
			if (m_reader->IsCardPresent())
			{
				m_reader->Connect(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hasBeenReset, true);
				m_reader->BeginTransaction();
				finally_do_arg (shared_ptr<SCardReader>, m_reader, { finally_arg->EndTransaction(); });

				command = CommandAPDU(CLA_ISO7816, INS_SELECT_FILE, 0x04, 0x00, EMVCardAid, SCardReader::shortAPDUMaxTransSize);
				m_reader->ApduProcessData(command, response);
				if (response.getSW() == SW_NO_ERROR)
				{
					aidSelected = true;

					// TODO: Send GET PROCESSING OPTIONS to get the AIL and AFL,
					//		 which will then be used to get the actual start and end of sfi and rec.
					for (byte sfi = 1; sfi < 32 && !panFound; sfi++)
					{
						for (byte rec = 1; rec < 17 && !panFound; rec++)
						{
							command = CommandAPDU(CLA_ISO7816, INS_READ_RECORD, rec, (sfi << 3) | 4, SCardReader::shortAPDUMaxTransSize);
							m_reader->ApduProcessData(command, response);
							if (response.getSW() == SW_NO_ERROR && response.getData().size() > 0)
							{
								responseData = response.getData();

								try
								{
									rootNode = TLVParser::TLV_Parse(responseData.data(), responseData.size());
								}
								catch(TLVException)
								{
									continue;
								}

								panNode = TLVParser::TLV_Find(rootNode, EMV_PAN_TAG);
								if (panNode && panNode->Value->size() >= 8)
								{
									panFound = true;
									panData = *panNode->Value.get();
									panData = vector<byte>(panData.rbegin(), panData.rbegin() + 2); // only interested in last digits
									std::swap(panData[0], panData[1]);
									lastPANDigits = ArrayToHexWideString(panData.data(), (int) panData.size());
								}
							}
						}
					}
				}
			}
		}
		
		if (panData.size())
			burn(panData.data(), panData.size());

		if (!aidSelected)
			throw EMVSelectAIDFailed();

		if (!panFound)
			throw EMVPANNotFound();

		m_lastPANDigits = lastPANDigits;
	}
}
