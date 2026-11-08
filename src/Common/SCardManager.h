#ifndef TC_HEADER_Common_SCardManager
#define TC_HEADER_Common_SCardManager

#include "Platform/PlatformBase.h"
#include "SCardReader.h"

namespace VeraCrypt
{
	class SCardManager
	{
	protected:
		static shared_ptr<SCardLoader> loader;
	public:
		SCardManager();
		virtual ~SCardManager();
		static vector<wstring> GetReaders();
		static shared_ptr<SCardReader> GetReader(size_t readerNumber);
	};
};

#endif // TC_HEADER_Common_SCardManager