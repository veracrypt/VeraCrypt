#include "ResponseAPDU.h"
#include <string.h>

using namespace std;

namespace VeraCrypt
{
	uint16 BytesToUInt16(const vector<uint8>& buff)
	{
		uint16 value = 0;
		for (uint16 i = 0; i < buff.size(); i++)
		{
			value <<= 8;
			value |= (uint16)buff.at(i);
		}

		return value;
	}

	void AppendData (vector<uint8>& buffer, const uint8* pbData, size_t cbData)
	{
		size_t orgSize = buffer.size ();
		buffer.resize (orgSize + cbData);
		memcpy (buffer.data () + orgSize, pbData, cbData);
	}

	/*********************************************************************************/

	void ResponseAPDU::clear()
	{
		m_data.clear();
		m_SW = 0;
	}

	ResponseAPDU::ResponseAPDU() : m_SW(0)
	{
	}

	ResponseAPDU::ResponseAPDU(const vector<uint8>& data, uint16 SW)
	{
		m_data = data;
		m_SW = SW;
	}

	uint32 ResponseAPDU::getNr()
	{
		return (uint32)m_data.size();
	}

	const vector<uint8> ResponseAPDU::getData()
	{
		return m_data;
	}

	uint8 ResponseAPDU::getSW1()
	{
		return (uint8)((0xFF00 & m_SW) >> 8);
	}

	uint8 ResponseAPDU::getSW2()
	{
		return (uint8)(0x00FF & m_SW);
	}

	uint16 ResponseAPDU::getSW()
	{
		return m_SW;
	}

	const vector<uint8> ResponseAPDU::getBytes()
	{
		vector<uint8> apdu;

		AppendData(apdu, m_data.data(), m_data.size());
		apdu.push_back((uint8)getSW1());
		apdu.push_back((uint8)getSW2());

		return apdu;
	}

	void ResponseAPDU::appendData(const vector<uint8>& data)
	{
		appendData(data.data(), data.size());
	}

	void ResponseAPDU::appendData(const uint8* data, size_t dataLen)
	{
		AppendData(m_data, data, dataLen);
	}

	void ResponseAPDU::setSW(uint16 SW)
	{
		m_SW = SW;
	}

	void ResponseAPDU::setBytes(const vector<uint8>& bytes)
	{
		clear();
		if (bytes.size() >= 2)
		{
			vector<uint8> SWBytes;
			m_data.resize(bytes.size() - 2);
			SWBytes.resize(2);

			memcpy(m_data.data(), bytes.data(), bytes.size() - 2);
			memcpy(SWBytes.data(), bytes.data() + bytes.size() - 2, 2);
			m_SW = BytesToUInt16(SWBytes);
		}
	}
}

