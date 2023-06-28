#include "ResponseAPDU.h"
#include <string.h>

using namespace std;

namespace VeraCrypt
{
	uint16 BytesToUInt16(const vector<byte>& buff)
	{
		uint16 value = 0;
		for (uint16 i = 0; i < buff.size(); i++)
		{
			value <<= 8;
			value |= (uint16)buff.at(i);
		}

		return value;
	}

	void AppendData (vector<byte>& buffer, const byte* pbData, size_t cbData)
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

	ResponseAPDU::ResponseAPDU(const vector<byte>& data, uint16 SW)
	{
		m_data = data;
		m_SW = SW;
	}

	uint32 ResponseAPDU::getNr()
	{
		return (uint32)m_data.size();
	}

	const vector<byte> ResponseAPDU::getData()
	{
		return m_data;
	}

	byte ResponseAPDU::getSW1()
	{
		return (byte)((0xFF00 & m_SW) >> 8);
	}

	byte ResponseAPDU::getSW2()
	{
		return (byte)(0x00FF & m_SW);
	}

	uint16 ResponseAPDU::getSW()
	{
		return m_SW;
	}

	const vector<byte> ResponseAPDU::getBytes()
	{
		vector<byte> apdu;

		AppendData(apdu, m_data.data(), m_data.size());
		apdu.push_back((byte)getSW1());
		apdu.push_back((byte)getSW2());

		return apdu;
	}

	void ResponseAPDU::appendData(const vector<byte>& data)
	{
		appendData(data.data(), data.size());
	}

	void ResponseAPDU::appendData(const byte* data, size_t dataLen)
	{
		AppendData(m_data, data, dataLen);
	}

	void ResponseAPDU::setSW(uint16 SW)
	{
		m_SW = SW;
	}

	void ResponseAPDU::setBytes(const vector<byte>& bytes)
	{
		clear();
		if (bytes.size() >= 2)
		{
			vector<byte> SWBytes;
			m_data.resize(bytes.size() - 2);
			SWBytes.resize(2);

			memcpy(m_data.data(), bytes.data(), bytes.size() - 2);
			memcpy(SWBytes.data(), bytes.data() + bytes.size() - 2, 2);
			m_SW = BytesToUInt16(SWBytes);
		}
	}
}

