#include "SCardReader.h"
#include "PCSCException.h"

#include <locale>

using namespace std;

namespace VeraCrypt
{
	void SCardReader::Init(const wstring& szSCReaderName, const shared_ptr<SCardLoader> scardLoader, const SCARDHANDLE& hCard, const DWORD& dwProtocol, LPCSCARD_IO_REQUEST pIO_Protocol)
	{
		m_szSCReaderName = szSCReaderName;
		if (scardLoader)
		{
			m_scardLoader = scardLoader;
			m_hSCReaderContext = m_scardLoader->GetSCardContext();
		}
		else 
		{
			m_scardLoader.reset();
			m_hSCReaderContext = 0;
		}
		m_hCard = hCard;
		m_dwProtocol = dwProtocol;
		m_pIO_Protocol = pIO_Protocol;
	}

	SCardReader::SCardReader(const wstring &szName, const shared_ptr<SCardLoader> scardLoader)
	{
		Init(szName, scardLoader, 0, 0, NULL);
	}

	SCardReader::SCardReader(const SCardReader& other)
		:	m_szSCReaderName(other.m_szSCReaderName),
			m_scardLoader(other.m_scardLoader),
			m_hSCReaderContext(other.m_hSCReaderContext),
			m_hCard(other.m_hCard),
			m_dwProtocol(other.m_dwProtocol),
			m_pIO_Protocol(other.m_pIO_Protocol)
	{
	}

	SCardReader::SCardReader(SCardReader&& other)
		:	m_szSCReaderName(other.m_szSCReaderName),
			m_scardLoader(other.m_scardLoader),
			m_hSCReaderContext(other.m_hSCReaderContext),
			m_hCard(other.m_hCard),
			m_dwProtocol(other.m_dwProtocol),
			m_pIO_Protocol(other.m_pIO_Protocol)
	{
		other.Clear();
	}

	SCardReader& SCardReader::operator=(const SCardReader& other)
	{
		if (this != &other)
		{
			m_szSCReaderName = other.m_szSCReaderName;
			m_scardLoader = other.m_scardLoader;
			m_hSCReaderContext = other.m_hSCReaderContext;
			m_hCard = other.m_hCard;
			m_dwProtocol = other.m_dwProtocol;
			m_pIO_Protocol = other.m_pIO_Protocol;
		}
		return *this;
	}

	SCardReader& SCardReader::operator=(SCardReader&& other)
	{
		if (this != &other)
		{
			m_szSCReaderName = other.m_szSCReaderName;
			m_scardLoader = other.m_scardLoader;
			m_hSCReaderContext = other.m_hSCReaderContext;
			m_hCard = other.m_hCard;
			m_dwProtocol = other.m_dwProtocol;
			m_pIO_Protocol = other.m_pIO_Protocol;

			other.Clear();
		}
		return *this;
	}

	void SCardReader::Clear(void)
	{
		m_szSCReaderName = L"";
		m_scardLoader.reset();
		m_hSCReaderContext = 0;
		m_hCard = 0;
		m_dwProtocol = 0;
		m_pIO_Protocol = NULL;
	}	

	SCardReader::~SCardReader()
	{
		Clear();
	}

	const wstring SCardReader::GetNameWide() const
	{
		return m_szSCReaderName;
	}

	const string SCardReader::GetName() const
	{
		string name = "";
		size_t size = wcstombs(NULL, m_szSCReaderName.c_str(), 0) + 1;
		if (size)
		{
			name.resize(size);
			size = wcstombs(&name[0], m_szSCReaderName.c_str(), size);
			if (size)
			{
				name.resize(size);
			}
		}
		return name;
	}

	bool SCardReader::IsCardPresent(vector<uint8>& cardAtr)
	{
		LONG				lRet = SCARD_S_SUCCESS;
		SCARD_READERSTATE	state;
		bool				bIsCardPresent = false;
#ifdef TC_WINDOWS
		wstring				readerName = GetNameWide();
#else
		string				readerName = GetName();
#endif

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		cardAtr.clear();
		burn(&state, sizeof(SCARD_READERSTATE));
		state.szReader = readerName.c_str();

		lRet = m_scardLoader->SCardIsValidContext(m_hSCReaderContext);
		if (SCARD_S_SUCCESS != lRet)
		{
			m_scardLoader->SCardReleaseContext(m_hSCReaderContext);
			lRet = m_scardLoader->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hSCReaderContext);
			if (lRet != SCARD_S_SUCCESS)
				throw PCSCException(lRet);
		}

		lRet = m_scardLoader->SCardGetStatusChange(m_hSCReaderContext, 0, &state, 1);
		if (lRet == SCARD_S_SUCCESS)
		{
			if ((state.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT && (state.dwEventState & SCARD_STATE_MUTE) == 0)
			{
				cardAtr.resize(state.cbAtr, 0);
				memcpy(cardAtr.data(), state.rgbAtr, state.cbAtr);
				bIsCardPresent = true;
				burn(&state, sizeof(SCARD_READERSTATE));
			}
		}
		else 
		{
			throw PCSCException(lRet);
		}

		return bIsCardPresent;
	}

	bool SCardReader::IsCardPresent()
	{
		vector<uint8> dummy;
		return IsCardPresent(dummy);
	}

	LONG SCardReader::CardHandleStatus()
	{
		LONG lRet = SCARD_E_INVALID_HANDLE;

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		if (m_hCard != 0)
		{
#ifdef TC_WINDOWS
			wchar_t
#else
			char
#endif
				szName[TC_MAX_PATH] = {};
			BYTE pbAtr[36] = {};
			DWORD dwState, dwProtocol, dwNameLen = TC_MAX_PATH, dwAtrLen = 36;
			lRet = m_scardLoader->SCardStatus(m_hCard, szName, &dwNameLen, &dwState, &dwProtocol, pbAtr, &dwAtrLen);
		}

		return lRet;
	}

	void SCardReader::Connect(DWORD dwProtocolToUse, bool& bHasBeenReset, bool resetAfterConnect)
	{
		LONG lRet = SCARD_S_SUCCESS;
		bHasBeenReset = false;
#ifdef TC_WINDOWS
		wstring	readerName = GetNameWide();
#else
		string readerName = GetName();
#endif

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		lRet = m_scardLoader->SCardIsValidContext(m_hSCReaderContext);
		if (SCARD_S_SUCCESS != lRet)
		{
			m_scardLoader->SCardReleaseContext(m_hSCReaderContext);
			lRet = m_scardLoader->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hSCReaderContext);
			if (lRet != SCARD_S_SUCCESS)
				throw PCSCException(lRet);
		}

		if (m_hCard != 0)
		{
			lRet = CardHandleStatus();
			if (lRet == SCARD_W_RESET_CARD)
			{
				bHasBeenReset = true;
				lRet = m_scardLoader->SCardReconnect(
					m_hCard,
					SCARD_SHARE_SHARED,
					dwProtocolToUse,
					SCARD_LEAVE_CARD,
					&m_dwProtocol);
				if (lRet != SCARD_S_SUCCESS)
				{
					throw PCSCException(lRet);
				}
			}
			else if (lRet != SCARD_S_SUCCESS)
			{
				// Card handle is invalid, disconnect and reconnect.
				Disconnect();
			}
		}

		if (m_hCard == 0)
		{
			lRet = m_scardLoader->SCardConnect(
				m_hSCReaderContext,
				readerName.c_str(),
				SCARD_SHARE_SHARED,
				dwProtocolToUse,
				&m_hCard,
				&m_dwProtocol);
			if (lRet != SCARD_S_SUCCESS)
			{
				throw PCSCException(lRet);
			}
		}

		if (m_pIO_Protocol == NULL)
		{
			if (m_dwProtocol == SCARD_PROTOCOL_T0)
			{
				m_pIO_Protocol = m_scardLoader->scardT0Pci;
			}
			else if (m_dwProtocol == SCARD_PROTOCOL_T1)
			{
				m_pIO_Protocol = m_scardLoader->scardT1Pci;
			}
			else if (m_dwProtocol == SCARD_PROTOCOL_RAW)
			{
				m_pIO_Protocol = m_scardLoader->scardRawPci;
			}
			else
			{
				lRet = SCARD_E_INVALID_PARAMETER;
				Disconnect();
				throw PCSCException(lRet);
			}
		}

		if (resetAfterConnect)
		{
			lRet = m_scardLoader->SCardReconnect(
				m_hCard,
				SCARD_SHARE_SHARED,
				m_dwProtocol,
				SCARD_RESET_CARD,
				&m_dwProtocol);

			if (lRet != SCARD_S_SUCCESS)
			{
				Disconnect();
				throw PCSCException(lRet);
			}
		}
	}

	bool SCardReader::IsConnected()
	{
		return m_hCard != 0;
	}

	void SCardReader::Disconnect() const
	{
		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		if (m_hCard != 0)
		{
			m_scardLoader->SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
			m_dwProtocol = 0;
			m_hCard = 0;
			m_pIO_Protocol = NULL;
		}
	}

	LONG SCardReader::SendAPDU(LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength, uint16& SW) const
	{
		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		LONG lRet = m_scardLoader->SCardTransmit(m_hCard, m_pIO_Protocol, pbSendBuffer, cbSendLength, NULL, pbRecvBuffer, pcbRecvLength);

		if (SCARD_S_SUCCESS == lRet)
		{
			if (*pcbRecvLength < 2)			//	must be at least = 2 (SW)
			{
				lRet = SCARD_E_UNEXPECTED;
			}
			else
			{
				SW = (pbRecvBuffer[*pcbRecvLength - 2] << 8) | pbRecvBuffer[*pcbRecvLength - 1];
				*pcbRecvLength -= 2;
			}
		}

		return lRet;
	}

	void SCardReader::BeginTransaction()
	{
		LONG lRet = 0;

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		if (m_hCard != 0)
		{
#ifndef _DEBUG
			lRet = m_scardLoader->SCardBeginTransaction(m_hCard);
			if (lRet != SCARD_S_SUCCESS)
			{
				throw PCSCException(lRet);
			}
#else
			lRet = SCARD_S_SUCCESS;
#endif
		}
		else
		{
			lRet = SCARD_E_INVALID_HANDLE;
			throw PCSCException(lRet);
		}
	}

	void SCardReader::EndTransaction()
	{
		LONG lRet = 0;

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		if (m_hCard != 0)
		{
#ifndef _DEBUG
			lRet = m_scardLoader->SCardEndTransaction(m_hCard, SCARD_LEAVE_CARD);
			if (lRet != SCARD_S_SUCCESS)
			{
				throw PCSCException(lRet);
			}
#endif
			lRet = SCARD_S_SUCCESS;
		}
		else
		{
			lRet = SCARD_E_INVALID_HANDLE;
			throw PCSCException(lRet);
		}
	}

	void SCardReader::ApduProcessData(CommandAPDU commandAPDU, ResponseAPDU& responseAPDU) const
	{
		LONG lRet = 0;
		uint16 SW = 0;

		uint32 nc = 0, ne = 0;

		bool expectingResponse = false;
		bool useExtendedAPDU = false;

		size_t indexOfLe = 0;
		size_t indexOfLcData = 0;

		vector<uint8> pbSendBuffer;
		vector<uint8> pbRecvBuffer;
		DWORD cbSendLength = 0;
		DWORD cbRecvLength = 0;
	
		responseAPDU.clear();

		if (!commandAPDU.isValid())
		{
			throw CommandAPDUNotValid(SRC_POS, commandAPDU.getErrorStr());
		}

		//	See whether the CommandAPDU is extended or not
		useExtendedAPDU = commandAPDU.isExtended();

		//	If T != 1, cannot use Extended-APDU
		if (m_dwProtocol != SCARD_PROTOCOL_T1 && useExtendedAPDU)
		{
			throw ExtendedAPDUNotSupported();
		}

		//	Set some needed vars
		nc = commandAPDU.getNc();
		ne = commandAPDU.getNe();
		pbSendBuffer.resize(useExtendedAPDU ? extendedAPDUMaxSendSize : shortAPDUMaxSendSize, 0);
		pbRecvBuffer.resize(useExtendedAPDU ? extendedAPDUMaxRecvSize : shortAPDUMaxRecvSize, 0);
		cbRecvLength = (DWORD)pbRecvBuffer.size();
	
		if (nc > (useExtendedAPDU ? extendedAPDUMaxTransSize : shortAPDUMaxTransSize) - 1)	//	Max = 255 or 65535
		{
			std::string errStr = vformat("Nc > %d", (useExtendedAPDU ? extendedAPDUMaxTransSize : shortAPDUMaxTransSize) - 1);
			throw CommandAPDUNotValid(SRC_POS, commandAPDU.getErrorStr());
		}
		if (ne > (useExtendedAPDU ? extendedAPDUMaxTransSize : shortAPDUMaxTransSize))		//	Max = 256 or 65536
		{
			std::string errStr = vformat("Ne > %d", (useExtendedAPDU ? extendedAPDUMaxTransSize : shortAPDUMaxTransSize) - 1);
			throw CommandAPDUNotValid(SRC_POS, commandAPDU.getErrorStr());
		}
	
		//	Create and populate buffer to send to card
		pbSendBuffer[0] = commandAPDU.getCLA();
		pbSendBuffer[1] = commandAPDU.getINS();
		pbSendBuffer[2] = commandAPDU.getP1();
		pbSendBuffer[3] = commandAPDU.getP2();
		if (nc == 0)
		{
			if (ne == 0)
			{
				//	case 1
				cbSendLength = 4;
			}
			else
			{
				expectingResponse = true;

				//	case 2s or 2e
				if (ne <= 256)
				{
					//	case 2s
					//	256 is encoded as 0x00
					pbSendBuffer[4] = (BYTE)ne;
					indexOfLe = 4;
					cbSendLength = 4 + 1;	//	header || Le (1 uint8)
				}
				else
				{
					//	case 2e
					//	65536 is encoded as 0x00 0x00 0x00
					BYTE l1, l2;
					if (ne == 65536)
					{
						l1 = 0;
						l2 = 0;
					}
					else
					{
						l1 = (BYTE)(ne >> 8);
						l2 = (BYTE)ne;
					}
					pbSendBuffer[4] = 0x00;
					pbSendBuffer[5] = l1;
					pbSendBuffer[6] = l2;
					cbSendLength = 4 + 3;	//	header || Le (3 bytes)
				}
			}
		}
		else
		{
			if (ne == 0)
			{
				//	case 3s or 3e
				if (nc <= 255)
				{
					//	case 3s
					pbSendBuffer[4] = (BYTE)nc;
					indexOfLcData = 5;
					cbSendLength = 4 + 1 + nc;	//	header || Lc (1 uint8) || Data
					memcpy(&pbSendBuffer[indexOfLcData], commandAPDU.getData().data(), nc);
				}
				else
				{
					//	case 3e
					pbSendBuffer[4] = 0;
					pbSendBuffer[5] = (BYTE)(nc >> 8);
					pbSendBuffer[6] = (BYTE)nc;
					indexOfLcData = 7;
					cbSendLength = 4 + 3 + nc;	//	header || Lc (3 bytes) || Data
					memcpy(&pbSendBuffer[indexOfLcData], commandAPDU.getData().data(), nc);
				}
			}
			else
			{
				expectingResponse = true;

				//	case 4s or 4e
				if ((nc <= 255) && (ne <= 256))
				{
					//	case 4s
					pbSendBuffer[4] = (BYTE)nc;
					indexOfLcData = 5;
					cbSendLength = 4 + 1 + nc + 1;	//	header || Lc (1 uint8) || Data || Le (1 uint8)
					memcpy(&pbSendBuffer[indexOfLcData], commandAPDU.getData().data(), nc);
					pbSendBuffer[indexOfLcData + nc] = (ne != 256) ? (BYTE)ne : 0;
					indexOfLe = indexOfLcData + nc;
				}
				else
				{
					//	case 4e
					pbSendBuffer[4] = 0;
					pbSendBuffer[5] = (BYTE)(nc >> 8);
					pbSendBuffer[6] = (BYTE)nc;
					indexOfLcData = 7;
					cbSendLength = 4 + 3 + nc + 2;	//	header || Lc (3 bytes) || Data || Le (2 bytes)
					memcpy(&pbSendBuffer[indexOfLcData], commandAPDU.getData().data(), nc);
					if (ne != 65536)
					{
						size_t leOfs = cbSendLength - 2;
						pbSendBuffer[leOfs] = (BYTE)(ne >> 8);
						pbSendBuffer[leOfs + 1] = (BYTE)ne;
					}//	65536 is 0x00 0x00 and the buffer has already been initialized with 0s
				}
			}
		}
		cbRecvLength = (DWORD)pbRecvBuffer.size();
		lRet = SendAPDU(pbSendBuffer.data(), cbSendLength, pbRecvBuffer.data(), &cbRecvLength, SW);
		if (lRet != SCARD_S_SUCCESS)
		{
			responseAPDU.setSW(SW);
			goto end;
		}

		//	If Expecting Response
		if (expectingResponse)
		{
			//	If Short-APDU
			if (!useExtendedAPDU)
			{
				//	If SW != 0x9000
				if (SW != SW_NO_ERROR)
				{
					//  If SW == 0x6CXX => Le larger than actual available data on ICC, SW2 contains the appropriate value
					if ((BYTE)(SW >> 8) == (BYTE)(SW_CORRECT_LENGTH_00 >> 8))								// 0x6C
					{
						pbSendBuffer[indexOfLe] = (BYTE)(SW & 0x00FF);
						cbRecvLength = (DWORD)pbRecvBuffer.size();
						lRet = SendAPDU(pbSendBuffer.data(), cbSendLength, pbRecvBuffer.data(), &cbRecvLength, SW);

						if (lRet != SCARD_S_SUCCESS)
						{
							responseAPDU.setSW(SW);
							goto end;
						}
					}

					//	If SW != 0x61XX (GET RESPONSE REMAINING BYTES) => there was an unexpected error
					if (SW != SW_NO_ERROR && ((BYTE)(SW >> 8) != (BYTE)(SW_BYTES_REMAINING_00 >> 8)))		// 0x61
					{
						responseAPDU.setSW(SW);
						goto end;
					}
				}

				// 	Get response data from APDU Response
				//	Response might be complete (1 APDU, <= 256 bytes : SW = 0x9000) or needs a Get Response to get the rest (1st APDU, == 256 bytes, SW = 0x61XX)
				if (cbRecvLength)
					responseAPDU.appendData(pbRecvBuffer.data(), cbRecvLength);

				//	Send get response to get the rest as long as we receive SW == 0x61XX
				//	In case of PACE, this is never the case
				while ((lRet == SCARD_S_SUCCESS) && ((BYTE)(SW >> 8) == (BYTE)(SW_BYTES_REMAINING_00 >> 8))) // 0x61
				{
					//	GET RESPONSE APDU
					pbSendBuffer[0] = commandAPDU.getCLA();
					pbSendBuffer[1] = INS_GET_RESPONSE;
					pbSendBuffer[2] = 0x00;
					pbSendBuffer[3] = 0x00;
					pbSendBuffer[4] = (BYTE)(SW & 0x00FF);
					cbSendLength = 5;

					cbRecvLength = (DWORD)pbRecvBuffer.size();
					lRet = SendAPDU(pbSendBuffer.data(), cbSendLength, pbRecvBuffer.data(), &cbRecvLength, SW);

					if (lRet == SCARD_S_SUCCESS)
					{
						if ((SW != SW_NO_ERROR) && ((SW >> 8) != (BYTE)(SW_BYTES_REMAINING_00 >> 8))) // 0x61
						{
							responseAPDU.clear();
							responseAPDU.setSW(SW);
						}
						else
							responseAPDU.appendData(pbRecvBuffer.data(), cbRecvLength);
					}
				}
			}
			//	If Extended-APDU (SW = 0x6CXX and SW = 0x61XX are handled by the low-level driver + smart card reader)
			else
			{
				//	If SW != 0x9000 => there was an unexpected error
				if (SW != SW_NO_ERROR)
				{
					responseAPDU.setSW(SW);
					goto end;
				}

				//	Response is complete in 1 ResponseAPDU
				if (cbRecvLength)
					responseAPDU.appendData(pbRecvBuffer.data(), cbRecvLength);
			}

			if (lRet == SCARD_S_SUCCESS)
			{
				responseAPDU.setSW(SW);
			}
		}
		else
		{
			responseAPDU.setSW(SW);
		}

	end:

		burn(pbSendBuffer.data(), pbSendBuffer.size());
		burn(pbRecvBuffer.data(), pbRecvBuffer.size());

		if (lRet != SCARD_S_SUCCESS)
			throw PCSCException(lRet);
	}

	void SCardReader::GetATRFromHandle(vector<uint8>& atrValue)
	{
		vector<uint8> pbATR;
		DWORD cByte = 0;
		LONG  lRet = 0;

		atrValue.clear();

		if (!m_scardLoader)
			throw ScardLibraryInitializationFailed();

		lRet = m_scardLoader->SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, NULL, &cByte);
		if (lRet == SCARD_S_SUCCESS)
		{
			pbATR.resize(cByte, 0);
			lRet = m_scardLoader->SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, pbATR.data(), &cByte);

			if (lRet == SCARD_S_SUCCESS)
			{
				atrValue = pbATR;
			}
			else
			{
				throw PCSCException(lRet);
			}
		}
		else
		{
			throw PCSCException(lRet);
		}
	}
}

