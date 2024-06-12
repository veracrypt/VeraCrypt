#ifndef TC_HEADER_Common_SCardReader
#define TC_HEADER_Common_SCardReader

#include "Platform/PlatformBase.h"
#include "CommandAPDU.h"
#include "ResponseAPDU.h"
#include "SCardLoader.h"

namespace VeraCrypt
{
	/* ================================================================================================ */
	/* SW values																						*/
	/* ================================================================================================ */
	const uint16 SW_BYTES_REMAINING_00 = (uint16)0x6100;
	const uint16 SW_STATE_NON_VOLATILE_MEMORY_UNCHANGED_NO_INFORMATION_GIVEN = (uint16)0x6200;
	const uint16 SW_END_OF_FILE = (uint16)0x6282;
	const uint16 SW_LESS_DATA_RESPONDED_THAN_REQUESTED = (uint16)0x6287;
	const uint16 SW_NON_VOLATILE_MEMORY_CHANGED_NO_INFORMATION_GIVEN = (uint16)0x6300;
	const uint16 SW_NON_VOLATILE_MEMORY_CHANGED_FILE_FILLED_UP_BY_LAST_WRITE = (uint16)0x6381;
	const uint16 SW_NON_VOLATILE_MEMORY_CHANGED_COUNTER_0 = (uint16)0x63C0;
	const uint16 SW_WRONG_LENGTH = (uint16)0x6700;
	const uint16 SW_LOGICAL_CHANNEL_NOT_SUPPORTED = (uint16)0x6881;
	const uint16 SW_SECURE_MESSAGING_NOT_SUPPORTED = (uint16)0x6882;
	const uint16 SW_LAST_COMMAND_EXPECTED = (uint16)0x6883;
	const uint16 SW_SECURITY_STATUS_NOT_SATISFIED = (uint16)0x6982;
	const uint16 SW_FILE_INVALID = (uint16)0x6983;
	const uint16 SW_DATA_INVALID = (uint16)0x6984;
	const uint16 SW_CONDITIONS_NOT_SATISFIED = (uint16)0x6985;
	const uint16 SW_COMMAND_NOT_ALLOWED = (uint16)0x6986;
	const uint16 SW_EXPECTED_SM_DATA_OBJECTS_MISSING = (uint16)0x6987;
	const uint16 SW_SM_DATA_OBJECTS_INCORRECT = (uint16)0x6988;
	const uint16 SW_APPLET_SELECT_FAILED = (uint16)0x6999;
	const uint16 SW_KEY_USAGE_ERROR = (uint16)0x69C1;
	const uint16 SW_WRONG_DATA = (uint16)0x6A80;
	const uint16 SW_FILEHEADER_INCONSISTENT = (uint16)0x6A80;
	const uint16 SW_FUNC_NOT_SUPPORTED = (uint16)0x6A81;
	const uint16 SW_FILE_NOT_FOUND = (uint16)0x6A82;
	const uint16 SW_RECORD_NOT_FOUND = (uint16)0x6A83;
	const uint16 SW_FILE_FULL = (uint16)0x6A84;
	const uint16 SW_OUT_OF_MEMORY = (uint16)0x6A84;
	const uint16 SW_INCORRECT_P1P2 = (uint16)0x6A86;
	const uint16 SW_KEY_NOT_FOUND = (uint16)0x6A88;
	const uint16 SW_WRONG_P1P2 = (uint16)0x6B00;
	const uint16 SW_CORRECT_LENGTH_00 = (uint16)0x6C00;
	const uint16 SW_INS_NOT_SUPPORTED = (uint16)0x6D00;
	const uint16 SW_CLA_NOT_SUPPORTED = (uint16)0x6E00;
	const uint16 SW_UNKNOWN = (uint16)0x6F00;
	const uint16 SW_CARD_TERMINATED = (uint16)0x6FFF;
	const uint16 SW_NO_ERROR = (uint16)0x9000;

	/* ================================================================================================ */
	/* CLA values																						*/
	/* ================================================================================================ */
	const uint8 CLA_ISO7816 = (uint8)0x00;
	const uint8 CLA_COMMAND_CHAINING = (uint8)0x10;

	/* ================================================================================================ */
	/* INS values																						*/
	/* ================================================================================================ */
	const uint8 INS_ERASE_BINARY = 0x0E;
	const uint8 INS_VERIFY = 0x20;
	const uint8 INS_CHANGE_CHV = 0x24;
	const uint8 INS_UNBLOCK_CHV = 0x2C;
	const uint8 INS_DECREASE = 0x30;
	const uint8 INS_INCREASE = 0x32;
	const uint8 INS_DECREASE_STAMPED = 0x34;
	const uint8 INS_REHABILITATE_CHV = 0x44;
	const uint8 INS_MANAGE_CHANNEL = 0x70;
	const uint8 INS_EXTERNAL_AUTHENTICATE = (uint8)0x82;
	const uint8 INS_MUTUAL_AUTHENTICATE = (uint8)0x82;
	const uint8 INS_GET_CHALLENGE = (uint8)0x84;
	const uint8 INS_ASK_RANDOM = (uint8)0x84;
	const uint8 INS_GIVE_RANDOM = (uint8)0x86;
	const uint8 INS_INTERNAL_AUTHENTICATE = (uint8)0x88;
	const uint8 INS_SEEK = (uint8)0xA2;
	const uint8 INS_SELECT = (uint8)0xA4;
	const uint8 INS_SELECT_FILE = (uint8)0xA4;
	const uint8 INS_CLOSE_APPLICATION = (uint8)0xAC;
	const uint8 INS_READ_BINARY = (uint8)0xB0;
	const uint8 INS_READ_BINARY2 = (uint8)0xB1;
	const uint8 INS_READ_RECORD = (uint8)0xB2;
	const uint8 INS_READ_RECORD2 = (uint8)0xB3;
	const uint8 INS_READ_RECORDS = (uint8)0xB2;
	const uint8 INS_READ_BINARY_STAMPED = (uint8)0xB4;
	const uint8 INS_READ_RECORD_STAMPED = (uint8)0xB6;
	const uint8 INS_GET_RESPONSE = (uint8)0xC0;
	const uint8 INS_ENVELOPE = (uint8)0xC2;
	const uint8 INS_GET_DATA = (uint8)0xCA;
	const uint8 INS_WRITE_BINARY = (uint8)0xD0;
	const uint8 INS_WRITE_RECORD = (uint8)0xD2;
	const uint8 INS_UPDATE_BINARY = (uint8)0xD6;
	const uint8 INS_LOAD_KEY_FILE = (uint8)0xD8;
	const uint8 INS_PUT_DATA = (uint8)0xDA;
	const uint8 INS_UPDATE_RECORD = (uint8)0xDC;
	const uint8 INS_CREATE_FILE = (uint8)0xE0;
	const uint8 INS_APPEND_RECORD = (uint8)0xE2;
	const uint8 INS_DELETE_FILE = (uint8)0xE4;
	const uint8 INS_PSO = (uint8)0x2A;
	const uint8 INS_MSE = (uint8)0x22;

	/* ================================================================================================ */
	/* EMV values																						*/
	/* ================================================================================================ */
	const uint16 EMV_CPLC_TAG = (uint16)0x9F7F;
	const uint16 EMV_ICC_PK_CERT_TAG = (uint16)0x9F46;
	const uint16 EMV_FCI_ISSUER_DISCRETIONARY_DATA_TAG = (uint16)0xBF0C;
	const uint8 EMV_ISS_PK_CERT_TAG = (uint8)0x90;
	const uint8 EMV_PAN_TAG = (uint8)0x5A;
	const uint8 EMV_FCI_TAG = (uint8)0x6F;
	const uint8 EMV_DFNAME_TAG = (uint8)0x84;
	const uint8 EMV_FCI_ISSUER_TAG = (uint8)0xA5;
	const uint8 EMV_DIRECTORY_ENTRY_TAG = (uint8)0x61;
	const uint8 EMV_SFI_TAG = (uint8)0x88;
	const uint8 EMV_TEMPLATE_TAG = (uint8)0x70;
	const uint8 EMV_AID_TAG = (uint8)0x4F;
	const uint8 EMV_LABEL_TAG = (uint8)0x50;
	const uint8 EMV_PRIORITY_TAG = (uint8)0x87;
	const uint8 EMV_PSE1[] = { 0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 }; // "1PAY.SYS.DDF01" (contact)
	const uint8 EMV_PSE2[] = { 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 }; // "2PAY.SYS.DDF01" (contactless)

	/* ================================================================================================ */

	class SCardReader
	{
	protected:

		wstring m_szSCReaderName;

		shared_ptr<SCardLoader>		m_scardLoader;
		mutable SCARDCONTEXT		m_hSCReaderContext;
		mutable SCARDHANDLE			m_hCard;
		mutable DWORD				m_dwProtocol;
		mutable LPCSCARD_IO_REQUEST m_pIO_Protocol;

		void Init(const wstring& szSCReaderName, const shared_ptr<SCardLoader> scardLoader, const SCARDHANDLE& hCard, const DWORD& dwProtocol, LPCSCARD_IO_REQUEST pIO_Protocol);

	public:

		/*  Card variables */
		//	Max Command APDU total size  ; Typically either 261 (short) or 65544 (extended)
		//	Max Response APDU total size ; Typically either 258 (short) or 65538 (extended)
		//	Max Response APDU data size  ; Ne ; Typically either 256 (short : 0x00) of 65536 (extended : 0x0000)
		const static uint32 shortAPDUMaxSendSize = 261;
		const static uint32 shortAPDUMaxRecvSize = 258;
		const static uint32 shortAPDUMaxTransSize = 256;
		const static uint32 extendedAPDUMaxSendSize = 65544;
		const static uint32 extendedAPDUMaxRecvSize = 65538;
		const static uint32 extendedAPDUMaxTransSize = 65536;

		// ------------------------------------------------------------------------------------------------------------------------------------- //
		//	Ctors, dtors																												
		// ------------------------------------------------------------------------------------------------------------------------------------- //

		SCardReader(const wstring &szName, const shared_ptr<SCardLoader> scardLoader);

		SCardReader(const SCardReader& other);
		SCardReader(SCardReader&& other);
		SCardReader& operator = (const SCardReader& other);
		SCardReader& operator = (SCardReader&& other);

		void Clear(void);

		~SCardReader();

		// ------------------------------------------------------------------------------------------------------------------------------------- //
		//	Getters & Setters																												
		// ------------------------------------------------------------------------------------------------------------------------------------- //

		const wstring GetNameWide() const;
		const string GetName() const;

		// ------------------------------------------------------------------------------------------------------------------------------------- //
		//	Card Connection management methods																									
		// ------------------------------------------------------------------------------------------------------------------------------------- //

		bool IsCardPresent(vector<uint8>& cardAtr);
		bool IsCardPresent();

		LONG CardHandleStatus();

		void Connect(DWORD dwProtocolToUse, bool& bHasBeenReset, bool resetAfterConnect = false);
		bool IsConnected();
		void Disconnect() const;

		LONG SendAPDU(LPCBYTE pbSendBuffer,
			DWORD cbSendLength,
			LPBYTE pbRecvBuffer,
			LPDWORD pcbRecvLength,
			uint16& SW) const;

		void BeginTransaction();
		void EndTransaction();

		void ApduProcessData(CommandAPDU commandAPDU, ResponseAPDU& responseAPDU) const;

		void GetATRFromHandle(vector<uint8>& atrValue);
	};
};

#endif // TC_HEADER_Common_SCardReader