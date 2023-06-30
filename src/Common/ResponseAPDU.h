#ifndef TC_HEADER_Common_ResponseAPDU
#define TC_HEADER_Common_ResponseAPDU

#include "Platform/PlatformBase.h"

namespace VeraCrypt
{
	class ResponseAPDU
	{
	protected:

		vector<byte> m_data;

		uint16 m_SW;

	public:

		void clear();

		ResponseAPDU();

		ResponseAPDU(const vector<byte>& data, uint16 SW);

		uint32 getNr();

		const vector<byte> getData();

		byte getSW1();

		byte getSW2();

		uint16 getSW();

		const vector<byte> getBytes();

		void setSW(uint16 SW);
		void setBytes(const vector<byte>& bytes);

		void appendData(const vector<byte>& data);
		void appendData(const byte* data, size_t dataLen);
	};
};

#endif // TC_HEADER_Common_ResponseAPDU