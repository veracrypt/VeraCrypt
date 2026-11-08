#include "ResponseAPDU.h"
#include "Tcdefs.h"
#include <stdexcept>
#include <string.h>

using namespace std;

namespace VeraCrypt
{
	/*********************************************************************************/

	void ResponseAPDU::clear()
	{
		if (!m_data.empty())
			burn(m_data.data(), m_data.size());
		m_data.clear();
		m_SW = 0;
	}

	ResponseAPDU::ResponseAPDU() : m_SW(0)
	{
	}

	ResponseAPDU::ResponseAPDU(const vector<uint8>& data, uint16 SW) : m_data(data), m_SW(SW)
	{
	}

	ResponseAPDU::ResponseAPDU(const ResponseAPDU& other) : m_data(other.m_data), m_SW(other.m_SW)
	{
	}

	ResponseAPDU& ResponseAPDU::operator=(const ResponseAPDU& other)
	{
		if (this != &other)
		{
			ResponseAPDU replacement(other);
			m_data.swap(replacement.m_data);
			m_SW = other.m_SW;
		}
		return *this;
	}

	ResponseAPDU::~ResponseAPDU()
	{
		clear();
	}

	uint32 ResponseAPDU::getNr()
	{
		return (uint32)m_data.size();
	}

	const vector<uint8>& ResponseAPDU::getData() const
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

	vector<uint8> ResponseAPDU::getBytes()
	{
		vector<uint8> apdu;
		if (m_data.size() > apdu.max_size() - 2)
			throw length_error("APDU response too large");
		// Allocate the complete output before copying sensitive data.
		apdu.resize(m_data.size() + 2);
		if (!m_data.empty())
			memcpy(apdu.data(), m_data.data(), m_data.size());
		apdu[m_data.size()] = (uint8)getSW1();
		apdu[m_data.size() + 1] = (uint8)getSW2();

		return apdu;
	}

	void ResponseAPDU::appendData(const vector<uint8>& data)
	{
		appendData(data.data(), data.size());
	}

	void ResponseAPDU::appendData(const uint8* data, size_t dataLen)
	{
		if (dataLen == 0)
			return;
		if (dataLen > m_data.max_size() - m_data.size())
			throw length_error("APDU response too large");

		size_t oldSize = m_data.size();
		size_t newSize = oldSize + dataLen;
		if (newSize > m_data.capacity())
		{
			// vector growth would otherwise release the previous contents without wiping.
			vector<uint8> replacement;
			size_t capacity = m_data.capacity();
			if (capacity <= m_data.max_size() / 2 && capacity * 2 > newSize)
				replacement.reserve(capacity * 2);
			replacement.resize(newSize);
			if (oldSize > 0)
				memcpy(replacement.data(), m_data.data(), oldSize);
			memcpy(replacement.data() + oldSize, data, dataLen);
			// Copy the appended bytes before erasing, as data may refer to m_data.
			if (oldSize > 0)
				burn(m_data.data(), oldSize);
			m_data.swap(replacement);
		}
		else
		{
			m_data.resize(newSize);
			memcpy(m_data.data() + oldSize, data, dataLen);
		}
	}

	void ResponseAPDU::setSW(uint16 SW)
	{
		m_SW = SW;
	}

	void ResponseAPDU::setBytes(const vector<uint8>& bytes)
	{
		ResponseAPDU replacement;
		if (bytes.size() >= 2)
		{
			replacement.appendData(bytes.data(), bytes.size() - 2);
			replacement.m_SW = (static_cast<uint16>(bytes[bytes.size() - 2]) << 8) | bytes.back();
		}
		m_data.swap(replacement.m_data);
		m_SW = replacement.m_SW;
	}
}

