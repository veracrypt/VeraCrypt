#include "SCard.h"

using namespace std;

namespace VeraCrypt
{
	SCardManager SCard::manager;

	SCard::SCard()
	{
	}

	SCard::SCard(size_t slotId)
    {
        m_reader = SCard::manager.GetReader(slotId);
    }

	SCard::~SCard()
    {
        if (m_reader)
        {
            m_reader->Disconnect();
        }
    }

	SCard::SCard(const SCard& other) : m_reader(other.m_reader)
	{
	}

	SCard::SCard(SCard&& other) : m_reader(std::move(other.m_reader))
	{
	}
	
	SCard& SCard::operator = (const SCard& other)
	{
		if (this != &other)
		{
			m_reader = other.m_reader;
		}
		return *this;
	}
	
	SCard& SCard::operator = (SCard&& other)
	{
		if (this != &other)
		{
			m_reader = std::move(other.m_reader);
		}
		return *this;
	}

	bool SCard::IsCardHandleValid() const
	{
		bool isValid = false;
		if (m_reader)
        {
			isValid = m_reader->CardHandleStatus() == SCARD_S_SUCCESS;
		}

		return isValid;
	}
}
