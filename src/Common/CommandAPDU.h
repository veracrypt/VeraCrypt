#ifndef TC_HEADER_Common_CommandAPDU
#define TC_HEADER_Common_CommandAPDU

#include "Platform/PlatformBase.h"
#include <stdarg.h>

namespace VeraCrypt
{
	inline const std::string vformat(const char* zcFormat, ...)
	{
		if (zcFormat)
		{
			va_list vaArgs;
			va_start(vaArgs, zcFormat);

			const int iLen = vsnprintf(NULL, 0, zcFormat, vaArgs);
			va_end(vaArgs);

			if (iLen)
			{
				std::vector<char> zc((size_t)iLen + 1);
				va_start(vaArgs, zcFormat);
				vsnprintf(zc.data(), zc.size(), zcFormat, vaArgs);
				va_end(vaArgs);

				return std::string(zc.data(), iLen);
			}
		}
	
		return "";
	}

	class CommandAPDU 
	{
	protected:

		vector<uint8> m_apdu;
		uint32 m_nc;
		uint32 m_ne;
		uint32 m_dataOffset;
		bool m_isExtendedAPDU;
		std::string m_parsingErrorStr;
		bool m_parsedSuccessfully;

		void parse();
		void init(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength, uint32 ne);
		void setHeader(uint8 cla, uint8 ins, uint8 p1, uint8 p2);

	public:

		void clear();

		CommandAPDU();

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength, uint32 ne);

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2);

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, uint32 ne);

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const vector<uint8>& data);

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const uint8* data, uint32 dataOffset, uint32 dataLength);

		CommandAPDU(uint8 cla, uint8 ins, uint8 p1, uint8 p2, const vector<uint8>& data, uint32 ne);

		CommandAPDU(const vector<uint8>& apdu);

		uint8 getCLA();

		uint8 getINS();

		uint8 getP1();

		uint8 getP2();

		uint32 getNc();

		const vector<uint8> getData();

		uint32 getNe();

		const vector<uint8> getAPDU();

		bool isValid();

		std::string getErrorStr();

		bool isExtended();
	};
};

#endif // TC_HEADER_Common_CommandAPDU