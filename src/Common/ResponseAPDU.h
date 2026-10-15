#ifndef TC_HEADER_Common_ResponseAPDU
#define TC_HEADER_Common_ResponseAPDU

#include "Platform/PlatformBase.h"

namespace VeraCrypt
{
	class ResponseAPDU
	{
	protected:

		vector<uint8> m_data;

		uint16 m_SW;

	public:

		void clear();

		ResponseAPDU();

		ResponseAPDU(const vector<uint8>& data, uint16 SW);
		ResponseAPDU(const ResponseAPDU& other);
		ResponseAPDU& operator=(const ResponseAPDU& other);
		~ResponseAPDU();

		uint32 getNr();

		// The returned data remains owned by this response and is invalidated by mutation.
		const vector<uint8>& getData() const;

		uint8 getSW1();

		uint8 getSW2();

		uint16 getSW();

		// The caller owns this serialized copy and is responsible for erasing it.
		vector<uint8> getBytes();

		void setSW(uint16 SW);
		void setBytes(const vector<uint8>& bytes);

		void appendData(const vector<uint8>& data);
		void appendData(const uint8* data, size_t dataLen);
	};
};

#endif // TC_HEADER_Common_ResponseAPDU
