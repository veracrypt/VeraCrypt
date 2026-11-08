#ifndef TC_HEADER_Common_SCard
#define TC_HEADER_Common_SCard

#include "Platform/PlatformBase.h"

#include "SCardManager.h"

namespace VeraCrypt
{
	class SCard
	{
    protected:
        shared_ptr<SCardReader> m_reader;
	public:
		static SCardManager manager;
		SCard();
		SCard(size_t slotId);
		SCard(const SCard& other);
		SCard(SCard&& other);
		SCard& operator = (const SCard& other);
		SCard& operator = (SCard&& other);
		virtual ~SCard();
        bool IsCardHandleValid() const;
	};
}

#endif // TC_HEADER_Common_SCard
