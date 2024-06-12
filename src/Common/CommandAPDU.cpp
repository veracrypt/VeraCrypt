#include "CommandAPDU.h"
#include <string.h>

using namespace std;

namespace VeraCrypt
{
	CommandAPDU::CommandAPDU()
		: m_nc(0), m_ne(0), m_dataOffset(0), m_isExtendedAPDU(false), m_parsingErrorStr(""), m_parsedSuccessfully(false)
	{
	}

	void CommandAPDU::parse()
	{
		uint32 l1 = 0;
		uint32 l2 = 0;
		size_t leOfs = 0;
		uint32 l3 = 0;
		m_parsingErrorStr = "";
		m_parsedSuccessfully = false;

		if (m_apdu.size() < 4)
		{
			m_parsingErrorStr = vformat("APDU must be at least 4 bytes long - Length = %zu", m_apdu.size());
			goto failure;
		}

		if (m_apdu.size() == 4)
		{
			//	case 1
			goto success;
		}

		/***	SHORT APDUs		***/
		l1 = m_apdu[4] & 0xff;
		if (m_apdu.size() == 5)
		{
			//	case 2s
			m_ne = (l1 == 0) ? 256 : l1;
			goto success;
		}
		if (l1 != 0)
		{
			if (m_apdu.size() == 4 + 1 + l1)
			{
				//	case 3s
				m_nc = l1;
				m_dataOffset = 5;
				goto success;
			}
			else if (m_apdu.size() == 4 + 2 + l1)
			{
				//	case 4s
				m_nc = l1;
				m_dataOffset = 5;
				l2 = m_apdu[m_apdu.size() - 1] & 0xff;
				m_ne = (l2 == 0) ? 256 : l2;
				goto success;
			}
			else
			{
				m_parsingErrorStr = vformat("Invalid APDU : b1 = %u, expected length to be %u or %u, got %zu", l1, 4 + 1 + l1, 4 + 2 + l1, m_apdu.size());
				goto failure;
			}
		}

		if (m_apdu.size() < 7)
		{
			m_parsingErrorStr = vformat("Invalid APDU : b1 = %u, expected length to be >= 7 , got %zu", l1, m_apdu.size());
			goto failure;
		}

		/***	EXTENDED APDUs	***/
		l2 = ((m_apdu[5] & 0xff) << 8) | (m_apdu[6] & 0xff);
		if (m_apdu.size() == 7)
		{
			//	case 2e
			m_ne = (l2 == 0) ? 65536 : l2;
			m_isExtendedAPDU = true;
			goto success;
		}
		if (l2 == 0)
		{
			m_parsingErrorStr = vformat("Invalid APDU: b1 = %u, b2||b3 = %u, length = %zu", l1, l2, m_apdu.size());
			goto failure;
		}
		if (m_apdu.size() == 4 + 3 + l2)
		{
			//	case 3e
			m_nc = l2;
			m_dataOffset = 7;
			m_isExtendedAPDU = true;
			goto success;
		}
		if (m_apdu.size() == 4 + 5 + l2)
		{
			//	case 4e
			m_nc = l2;
			m_dataOffset = 7;
			leOfs = m_apdu.size() - 2;
			l3 = ((m_apdu[leOfs] & 0xff) << 8) | (m_apdu[leOfs + 1] & 0xff);
			m_ne = (l3 == 0) ? 65536 : l3;
			m_isExtendedAPDU = true;
			goto success;
		}
		else
		{
			m_parsingErrorStr = vformat("Invalid APDU : b1 = %u, b2||b3 = %u, expected length to be %u or %u, got %zu", l1, l2, 4 + 3 + l2, 4 + 5 + l2, m_apdu.size());
			goto failure;
		}

	success:
		m_parsedSuccessfully = true;

	failure:
		clear();
	}

	void CommandAPDU::init(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength, uint32 ne)
	{
		m_nc = 0;
		m_ne = 0;
		m_dataOffset = 0;
		m_isExtendedAPDU = false;
		m_parsingErrorStr = "";
		m_parsedSuccessfully = false;

		if (dataLength > 65535) 
		{
			m_parsingErrorStr = vformat("dataLength is too large (> 65535) - dataLength = %u", dataLength);
			clear();
			return;
		}
		if (ne > 65536) 
		{
			m_parsingErrorStr = vformat("ne is too large (> 65536) - ne = %u", ne);
			clear();
			return;
		}

		m_ne = ne;
		m_nc = dataLength;

		if (dataLength == 0)
		{
			if (m_ne == 0)
			{
				//	case 1
				m_apdu.resize(4, 0);
				setHeader(cla, ins, p1, p2);
			}
			else
			{
				//	case 2s or 2e
				if (ne <= 256)
				{
					//	case 2s
					//	256 is encoded as 0x00
					uint8 len = (m_ne != 256) ? (uint8)m_ne : 0;
					m_apdu.resize(5, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[4] = len;
				}
				else
				{
					//	case 2e
					uint8 l1, l2;
					//	65536 is encoded as 0x00 0x00
					if (m_ne == 65536)
					{
						l1 = 0;
						l2 = 0;
					}
					else
					{
						l1 = (uint8)(m_ne >> 8);
						l2 = (uint8)m_ne;
					}
					m_apdu.resize(7, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[5] = l1;
					m_apdu[6] = l2;
					m_isExtendedAPDU = true;
				}
			}
		}
		else
		{
			if (m_ne == 0)
			{
				//	case 3s or 3e
				if (dataLength <= 255)
				{
					//	case 3s
					m_apdu.resize(4 + 1 + dataLength, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[4] = (uint8)dataLength;
					m_dataOffset = 5;
					memcpy(m_apdu.data() + 5, data + dataOffset, dataLength);
				}
				else
				{
					//	case 3e
					m_apdu.resize(4 + 3 + dataLength, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[4] = 0;
					m_apdu[5] = (uint8)(dataLength >> 8);
					m_apdu[6] = (uint8)dataLength;
					m_dataOffset = 7;
					memcpy(m_apdu.data() + 7, data + dataOffset, dataLength);
					m_isExtendedAPDU = true;
				}
			}
			else
			{
				//	case 4s or 4e
				if ((dataLength <= 255) && (m_ne <= 256))
				{
					//	case 4s
					m_apdu.resize(4 + 2 + dataLength, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[4] = (uint8)dataLength;
					m_dataOffset = 5;
					memcpy(m_apdu.data() + 5, data + dataOffset, dataLength);
					m_apdu[m_apdu.size() - 1] = (m_ne != 256) ? (uint8)m_ne : 0;
				}
				else
				{
					//	case 4e
					m_apdu.resize(4 + 5 + dataLength, 0);
					setHeader(cla, ins, p1, p2);
					m_apdu[4] = 0;
					m_apdu[5] = (uint8)(dataLength >> 8);
					m_apdu[6] = (uint8)dataLength;
					m_dataOffset = 7;
					memcpy(m_apdu.data() + 7, data + dataOffset, dataLength);
					if (ne != 65536)
					{
						size_t leOfs = m_apdu.size() - 2;
						m_apdu[leOfs] = (uint8)(m_ne >> 8);
						m_apdu[leOfs + 1] = (uint8)m_ne;
					} // else le == 65536: no need to fill in, encoded as 0
					m_isExtendedAPDU = true;
				}
			}
		}

		m_parsedSuccessfully = true;
	}

	void CommandAPDU::setHeader(uint8 cla, uint8 ins, uint8 p1, uint8 p2)
	{
		m_apdu[0] = (uint8)cla;
		m_apdu[1] = (uint8)ins;
		m_apdu[2] = (uint8)p1;
		m_apdu[3] = (uint8)p2;
	}

	void CommandAPDU::clear()
	{
		m_apdu.clear();
		m_nc = 0;
		m_ne = 0;
		m_dataOffset = 0;
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength, uint32 ne)
	{
		init(cla, ins, p1, p2, data, dataOffset, dataLength, ne);
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2)
	{
		init(cla, ins, p1, p2, NULL, 0, 0, 0);
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, uint32 ne)
	{
		init(cla, ins, p1, p2, NULL, 0, 0, ne);
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const vector<uint8>& data)
	{
		init(cla, ins, p1, p2, data.data(), 0, (uint32)data.size(), 0);
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength)
	{
		init(cla, ins, p1, p2, data, dataOffset, dataLength, 0);
	}

	CommandAPDU::CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const vector<uint8>& data, uint32 ne)
	{
		init(cla, ins, p1, p2, data.data(), 0, (uint32)data.size(), ne);
	}

	CommandAPDU::CommandAPDU(const vector<uint8>& apdu) : m_nc(0), m_ne(0), m_dataOffset(0), m_isExtendedAPDU(false)
	{
		m_apdu = apdu;
		parse();
	}

	uint8 CommandAPDU::getCLA()
	{
		return m_apdu[0] & 0xff;
	}

	uint8 CommandAPDU::getINS()
	{
		return m_apdu[1] & 0xff;
	}

	uint8 CommandAPDU::getP1()
	{
		return m_apdu[2] & 0xff;
	}

	uint8 CommandAPDU::getP2()
	{
		return m_apdu[3] & 0xff;
	}

	uint32 CommandAPDU::getNc()
	{
		return m_nc;
	}

	const vector<uint8> CommandAPDU::getData()
	{
		vector<uint8> data;

		if (m_nc > 0)
		{
			data.resize(m_nc, 0);
			memcpy(data.data(), m_apdu.data() + m_dataOffset, data.size());
		}

		return data;
	}

	uint32 CommandAPDU::getNe()
	{
		return m_ne;
	}

	const vector<uint8> CommandAPDU::getAPDU()
	{
		return m_apdu;
	}

	bool CommandAPDU::isExtended()
	{
		return m_isExtendedAPDU;
	}

	bool CommandAPDU::isValid()
	{
		return m_parsedSuccessfully;
	}

	std::string CommandAPDU::getErrorStr()
	{
		return m_parsingErrorStr;
	}
}

