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

		vector<byte> m_apdu;
		uint32 m_nc;
		uint32 m_ne;
		uint32 m_dataOffset;
		bool m_isExtendedAPDU;
		std::string m_parsingErrorStr;
		bool m_parsedSuccessfully;

		void parse();
		void init(byte cla, byte ins, byte p1, byte p2, const byte* data, uint32 dataOffset, uint32 dataLength, uint32 ne);
		void setHeader(byte cla, byte ins, byte p1, byte p2);

	public:

		void clear();

		CommandAPDU();

		CommandAPDU(byte cla, byte ins, byte p1, byte p2, const byte* data, uint32 dataOffset, uint32 dataLength, uint32 ne);

		CommandAPDU(byte cla, byte ins, byte p1, byte p2);

		CommandAPDU(byte cla, byte ins, byte p1, byte p2, uint32 ne);

		CommandAPDU(byte cla, byte ins, byte p1, byte p2, const vector<byte>& data);

		CommandAPDU(byte cla, byte ins, byte p1, byte p2, const byte* data, uint32 dataOffset, uint32 dataLength);

		CommandAPDU(byte cla, byte ins, byte p1, byte p2, const vector<byte>& data, uint32 ne);

		CommandAPDU(const vector<byte>& apdu);

		byte getCLA();

		byte getINS();

		byte getP1();

		byte getP2();

		uint32 getNc();

		const vector<byte> getData();

		uint32 getNe();

		const vector<byte> getAPDU();

		bool isValid();

		std::string getErrorStr();

		bool isExtended();
	};
};

#endif // TC_HEADER_Common_CommandAPDU