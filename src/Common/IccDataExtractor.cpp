//
// Created by bshp on 1/14/23.
//

#include "IccDataExtractor.h"

#if !defined (TC_WINDOWS) || defined (TC_PROTOTYPE)
#	include "Platform/SerializerFactory.h"
#	include "Platform/StringConverter.h"
#	include "Platform/SystemException.h"
#else
#	include "Dictionary.h"
#	include "Language.h"
#endif

#include "Tcdefs.h"

namespace VeraCrypt
{


	#ifdef TC_WINDOWS
	bool VeraCrypt::IccDataExtractor::Initialized;
	#endif
	//using namespace std;
	const BYTE IccDataExtractor::SELECT_MASTERCARD[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x04, 0x10, 0x10};
	const BYTE IccDataExtractor::SELECT_VISA[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x03, 0x10, 0x10};
	const BYTE IccDataExtractor::SELECT_AMEX[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 00, 0x25, 0x10};
	const BYTE * IccDataExtractor::SELECT_TYPES[]={SELECT_MASTERCARD,  SELECT_VISA, SELECT_AMEX};

	IccDataExtractor::IccDataExtractor(){}

	IccDataExtractor::~IccDataExtractor(){
		/* Disconnect card if connected */
		if(hCard){
			#ifdef TC_WINDOWS
			WSCardDisconnect(hContext,hCard);
			#else
			SCardDisconnect(hContext,hCard);
			#endif
		}
		/* Release memory that has been returned from the resource manager using the SCARD_AUTOALLOCATE length
		* designator*/
		if (mszReaders){
			#ifdef TC_WINDOWS
			WSCardFreeMemory(hContext, mszReaders);
			#else
			SCardFreeMemory(hContext, mszReaders);
			#endif
		}

		/* Closing the established resource manager context freeing any resources allocated under that context
		* including SCARDHANDLE objects and memory allocated using the SCARD_AUTOALLOCATE length designator*/
		if(hContext){
			#ifdef TC_WINDOWS
			WSCardReleaseContext(hContext);
			#else
			SCardReleaseContext(hContext);
			#endif
		}

		/* Freeing winscard library */
		#ifdef TC_WINDOWS
		FreeLibrary(WinscardLibraryHandle);
		#endif
	}

	#ifdef TC_WINDOWS
	void IccDataExtractor::InitLibrary(){

		if(Initialized) return;

		/* Getting the System32 directory */
		char sysDir[MAX_PATH-20];
		GetSystemDirectoryA(sysDir, MAX_PATH);
		
		/* Getting the winscard dll path directory */
		char winscardPath[MAX_PATH];
		sprintf_s(winscardPath, "%s\\Winscard.dll", sysDir);

		/* Loading the winscard dll from System32 */
		WinscardLibraryHandle = LoadLibraryA(winscardPath);
		throw_sys_if(!WinscardLibraryHandle);

		/* Fetching the functions pointers from the dll */
		WSCardEstablishContext = (SCardEstablishContextPtr) GetProcAddress(WinscardLibraryHandle,"SCardEstablishContext");
		if(!WSCardEstablishContext) throw WinscardLibraryNotInitialized();

		WSCardReleaseContext= (SCardReleaseContextPtr) GetProcAddress(WinscardLibraryHandle,"SCardReleaseContext");
		if(!WSCardReleaseContext) throw WinscardLibraryNotInitialized();

		WSCardConnectA = (SCardConnectAPtr) GetProcAddress(WinscardLibraryHandle,"SCardConnectA");
		if(!WSCardConnectA) throw WinscardLibraryNotInitialized();

		WSCardDisconnect = (SCardDisconnectPtr) GetProcAddress(WinscardLibraryHandle,"SCardDisconnect");
		if(!WSCardDisconnect) throw WinscardLibraryNotInitialized();

		WSCardFreeMemory = ( SCardFreeMemoryPtr) GetProcAddress(WinscardLibraryHandle,"SCardFreeMemory");
		if(!WSCardFreeMemory) throw WinscardLibraryNotInitialized();

		WSCardListReadersA =  (SCardListReadersAPtr) GetProcAddress(WinscardLibraryHandle,"SCardListReadersA");
		if(!WSCardListReadersA) throw WinscardLibraryNotInitialized();

		WSCardTransmit = ( SCardTransmitPtr) GetProcAddress(WinscardLibraryHandle,"SCardTransmit");
		if(!WSCardTransmit) throw WinscardLibraryNotInitialized();

		Initialized = true;
		
	}
	#endif

	/* Establishing the resource manager context (the scope) within which database operations are performed.
	* The module of the smart card subsystem that manages access to multiple readers and smart cards. The
	* resource manager identifies and tracks resources, allocates readers and resources across multiple
	* applications,and supports transaction primitives for accessing services available on a given card.*/
	int IccDataExtractor::EstablishRSContext(){
		
		#ifdef TC_WINDOWS
		LONG returnValue = WSCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
		#else
		LONG returnValue = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
		#endif

		/* Check if the establishment of the context was unsuccessful  */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		return EXIT_SUCCESS;
	}

	/* Detecting available readers and filling the reader table */
	unsigned long IccDataExtractor::GetReaders(){

		#ifdef TC_WINDOWS
		if(!Initialized) 
			throw WinscardLibraryNotInitialized();
		#endif 

		EstablishRSContext();

		/* Length of the mszReaders buffer in characters. If the buffer length is specified as
		* SCARD_AUTOALLOCATE, then mszReaders is converted to a pointer to a byte pointer, and
		* receives the address of a block of memory containing the multi-string structure */
		DWORD dwReaders = SCARD_AUTOALLOCATE;

		/* Retrieving the available readers list and putting it in mszReaders*/ // Use LPSTR on linux
		#ifdef TC_WINDOWS
		LONG returnValue = WSCardListReadersA(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
		#else
		LONG returnValue = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
		#endif

		/* If the is no readers, return */
		if(returnValue == SCARD_E_NO_READERS_AVAILABLE) return 0;

		/* Check if the listing of the connected readers was unsuccessful  */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);
 
		nbReaders = 0;
		LPSTR ReaderPtr = mszReaders;
		
		/* Getting the total number of readers */
		while (*ReaderPtr != '\0')
		{
			readers.push_back(ReaderPtr);
			ReaderPtr += strlen((char*)ReaderPtr) + 1;
			nbReaders++;
		}

		return nbReaders;
	}

	/* Connecting to the card in the given reader*/
	int IccDataExtractor::ConnectCard(unsigned long int reader_nb){

		/* Check if the given reader slot number is possible */
		if (reader_nb < 0 || reader_nb >= nbReaders)
			throw InvalidEMVPath();

		dwActiveProtocol = SCARD_PROTOCOL_UNDEFINED;
	
		#ifdef TC_WINDOWS
		LONG returnValue = WSCardConnectA(hContext, readers[reader_nb], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		#else
		LONG returnValue = SCardConnect(hContext, readers[reader_nb], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		#endif

		/* Check is the card connection was unsuccessful */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		return EXIT_SUCCESS;
	}

	/* Disconnect the card currently connected*/
	int IccDataExtractor::DisconnectCard(){
		#ifdef TC_WINDOWS
		LONG returnValue = WSCardDisconnect(hCard, SCARD_UNPOWER_CARD);
		#else
		LONG returnValue = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
		#endif

		/* Check is the card deconnection was unsuccessful */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		return EXIT_SUCCESS;
	}

	/* Testing if the card contains the application of the given EMV type (0:Mastercard, 1:Visa, 2:Amex) */
	bool IccDataExtractor::TestingCardType(const int SELECT_TYPE_NUMBER){

		const BYTE * SELECTED_TYPE = SELECT_TYPES[SELECT_TYPE_NUMBER];

		BYTE pbRecvBuffer[64];      /* Buffer to receive the card response */

		DWORD dwSendLength = SELECT_TYPE_SIZE;     /* Set the size of the send buffer */
		DWORD dwRecvLength = sizeof(pbRecvBuffer); /* Set the size of the reception buffer */

		/* Set up the io request */
		SCARD_IO_REQUEST ioRequest;
		ioRequest.dwProtocol = dwActiveProtocol;
		ioRequest.cbPciLength = sizeof(ioRequest);

		#ifdef TC_WINDOWS
		LONG returnValue = WSCardTransmit(hCard, &ioRequest, SELECTED_TYPE, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);
		#else
		LONG returnValue = SCardTransmit(hCard, &ioRequest, SELECTED_TYPE, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);
		#endif

		/* Check if the transmission was unsuccessful  */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		/* It received a response. Check if it didn't get a recognisable response */
		if (dwRecvLength < 2)
			return false;

		/* Check if the command successfully executed (the card is the type passed in the parameter) */
		if (pbRecvBuffer[0] == 0x61)
			return true;

		return false;
	}

	/* Getting the ICC Public Key Certificates and the Issuer Public Key Certificates by parsing the application
	* (!NEED TO TEST CARD TYPE TO SELECT APPLICATION FIRST!)*/
	void IccDataExtractor::GetCerts(vector<byte> &CERTS){

		CERTS.clear();

		bool iccFound= false;
		bool issuerFound= false;

		shared_ptr<TLVNode> node;
		shared_ptr<TLVNode> ICC_Public_Key_Certificate;
		shared_ptr<TLVNode> Issuer_PK_Certificate;

		BYTE pbRecvBuffer[64];      /* Buffer to receive the card response */
		BYTE pbRecvBufferFat[256];  /* Bigger buffer to receive the card response */

		DWORD dwSendLength; /* Size of the send buffer */
		DWORD dwRecvLength; /* Size of the reception buffer */

		/* Set up the io request */
		SCARD_IO_REQUEST ioRequest;
		ioRequest.dwProtocol = dwActiveProtocol;
		ioRequest.cbPciLength = sizeof(ioRequest);

		LONG returnValue;

		/* Parsing root folders */
		for (int sfi = 0; sfi < 32; sfi++)
		{
			/* Parsing sub folders */
			for (int rec = 0; rec < 17; rec++)
			{
				BYTE SELECT_APDU_FILE[] = {00, 0xB2, static_cast<unsigned char>(rec), static_cast<unsigned char>((sfi << 3) | 4), 0x00};

				dwSendLength = sizeof(SELECT_APDU_FILE);
				dwRecvLength = sizeof(pbRecvBuffer);

				/* Check if there is data in the folder */
				#ifdef TC_WINDOWS
				returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);
				#else
				returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);
				#endif

				/* Check if the transmission was unsuccessful  */
				if (returnValue != SCARD_S_SUCCESS)
					throw PCSCException(returnValue);

				/* There is no data in the folder */
				if (pbRecvBuffer[0] != 0x6C)
					continue;

				/* It set the proper expected length of the data in the APDU */
				SELECT_APDU_FILE[4] = pbRecvBuffer[1];

				dwRecvLength = sizeof(pbRecvBufferFat);

				/* Get the data from the folder */
				#ifdef TC_WINDOWS
				returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength, NULL, pbRecvBufferFat, &dwRecvLength);
				#else
				returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength, NULL, pbRecvBufferFat, &dwRecvLength);
				#endif

				/* Check if the transmission was unsuccessful */
				if (returnValue != SCARD_S_SUCCESS)
					throw PCSCException(returnValue);

				/* It received a response. Check if it didn't get a recognisable response */
				if (dwRecvLength < 2)
					continue;

				/* Parsing the TLV */
				try{
					node = TLVParser::TLV_Parse(pbRecvBufferFat,sizeof(pbRecvBufferFat));
				}catch(TLVException){
					continue;
				}

				/* Finding the ICC_Public_Key_Certificate */
				try{
					ICC_Public_Key_Certificate = TLVParser::TLV_Find(node, 0x9F46);
				}catch(TLVException){
					continue;
				}
				if(ICC_Public_Key_Certificate) {
					iccFound=true;
					for (int i = 0; i < ICC_Public_Key_Certificate->Length;i++) {
						CERTS.push_back(static_cast<byte>(ICC_Public_Key_Certificate->Value[i]));
					}
				}

				/* Finding the Issuer_Public_Key_Certificate */
				try{
					Issuer_PK_Certificate = TLVParser::TLV_Find(node, 0x90);
				}catch(TLVException){
					continue;
				}

				if(Issuer_PK_Certificate) {
					issuerFound=true;
					for (int i = 0; i < Issuer_PK_Certificate->Length;i++) {
						CERTS.push_back(static_cast<byte>(Issuer_PK_Certificate->Value[i]));
					}
				}

				/* Limiting the search to at least one occurrence of both PKs to speed up the process.
				* There might be more certificates tho */
				if(iccFound && issuerFound){
                    burn(pbRecvBuffer, sizeof(pbRecvBuffer));
                    burn(pbRecvBufferFat, sizeof(pbRecvBufferFat));
                    return;
                }
			}
		}
        burn(pbRecvBuffer, sizeof(pbRecvBuffer));
        burn(pbRecvBufferFat, sizeof(pbRecvBufferFat));
		throw EMVKeyfileDataNotFound();
	}

	/* Getting CPCL data from the card*/
	void IccDataExtractor::GetCPCL(vector<byte> &v){

		BYTE SELECT_APDU_CPCL[] = {0x80,0xCA, 0x9F, 0x7F, 0x00};

		BYTE pbRecvBuffer[64];                              /* Buffer to receive the card response */
		BYTE pbRecvBufferFat[256];                          /* Bigger buffer to receive the card response */

		DWORD dwSendLength = sizeof (SELECT_APDU_CPCL);     /* Set the size of the send buffer */
		DWORD dwRecvLength = sizeof(pbRecvBuffer);          /* Set the size of the reception buffer */

		/* Set up the io request */
		SCARD_IO_REQUEST ioRequest;
		ioRequest.dwProtocol = dwActiveProtocol;
		ioRequest.cbPciLength = sizeof(ioRequest);

		/* Check if there is the TAG for CPCL Data in the card */
		#ifdef TC_WINDOWS
		LONG returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);
		#else
		LONG returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);
		#endif

		/* Check if the transmission was unsuccessful  */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		/* Not the correct APDU response code */
		if (pbRecvBuffer[0] != 0x6C)
			throw EMVKeyfileDataNotFound();

		/* It set the proper expected length of the data in the APDU */
		SELECT_APDU_CPCL[4] = pbRecvBuffer[1];

		dwRecvLength = sizeof(pbRecvBufferFat);

		/* Get the CPCL data */
		#ifdef TC_WINDOWS
		returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength,NULL, pbRecvBufferFat, &dwRecvLength);
		#else
		returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength,NULL, pbRecvBufferFat, &dwRecvLength);
		#endif

		/* Check if the transmission was unsuccessful  */
		if (returnValue != SCARD_S_SUCCESS)
			throw PCSCException(returnValue);

		/* It received a response. Check if it didn't get a recognisable response */
		if (dwRecvLength < 2)
			throw EMVKeyfileDataNotFound();

		/* We add CPCL data and crop the TAG and the data length at the start and the trailer at the end */
		for (unsigned long i = 3; i < dwRecvLength-2; i++) {
			v.push_back(static_cast<byte>(pbRecvBufferFat[i]));
		}
        burn(pbRecvBuffer, sizeof(pbRecvBuffer));
        burn(pbRecvBufferFat, sizeof(pbRecvBufferFat));

	}

	/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates for the first application with the cpcl
	* data present on the card and finally merge it into one byte array */
	void IccDataExtractor::GettingAllCerts(int readerNumber, vector<byte> &v){

		#ifdef TC_WINDOWS
		if(!Initialized) 
			throw WinscardLibraryNotInitialized();
		#endif 

		bool isEMV= false;

		ConnectCard(readerNumber);

		/* Test all the type of applications and get the certificates from the first one found */
		for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){

			/* The card does not contain this application (0:Mastercard, 1:Visa, 2:Amex) */
			if(!TestingCardType(i)) continue;
			isEMV= true;
			GetCerts(v);
			break;
		}

		/* Need to disconnect reconnect the card to access CPLC data (not located in any application) */
		DisconnectCard();

		/* Check if the card is not an EMV one */
		if(!isEMV)
			throw EMVUnknownCardType();

		ConnectCard(readerNumber);

		GetCPCL(v);

		DisconnectCard();
	}

	/* Getting the PAN  by parsing the application
	* (!NEED TO TEST CARD TYPE TO SELECT APPLICATION FIRST!)*/
	void IccDataExtractor::GetPAN(vector<byte> &v) {

		bool PANFound= false;
		shared_ptr<TLVNode> node;
		shared_ptr<TLVNode> PAN;

		BYTE pbRecvBuffer[64];      /* Buffer to receive the card response */
		BYTE pbRecvBufferFat[256];  /* Bigger buffer to receive the card response */

		DWORD dwSendLength; /* Size of the send buffer */
		DWORD dwRecvLength; /* Size of the reception buffer */

		/* Set up the io request */
		SCARD_IO_REQUEST ioRequest;
		ioRequest.dwProtocol = dwActiveProtocol;
		ioRequest.cbPciLength = sizeof(ioRequest);

		LONG returnValue;

		/* Parsing root folders */
		for (int sfi = 0; sfi < 32; sfi++)
		{
			/* Parsing sub folders */
			for (int rec = 0; rec < 17; rec++)
			{
				BYTE SELECT_APDU_FILE[] = {00, 0xB2, static_cast<unsigned char>(rec), static_cast<unsigned char>((sfi << 3) | 4), 0x00};

				dwSendLength = sizeof(SELECT_APDU_FILE);
				dwRecvLength = sizeof(pbRecvBuffer);

				/* Check if there is data in the folder */
				#ifdef TC_WINDOWS
				returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);
				#else
				returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);
				#endif

				/* Check if the transmission was unsuccessful  */
				if (returnValue != SCARD_S_SUCCESS)
					throw PCSCException(returnValue);

				/* There is no data in the folder */
				if (pbRecvBuffer[0] != 0x6C)
					continue;

				/* It set the proper expected length of the data in the APDU */
				SELECT_APDU_FILE[4] = pbRecvBuffer[1];

				dwRecvLength = sizeof(pbRecvBufferFat);

				/* Get the data from the folder */
				#ifdef TC_WINDOWS
				returnValue = WSCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBufferFat, &dwRecvLength);
				#else
				returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBufferFat, &dwRecvLength);
				#endif

				/* Check if the transmission was unsuccessful */
				if (returnValue != SCARD_S_SUCCESS)
					throw PCSCException(returnValue);

				/* It received a response. Check if it didn't get a recognisable response */
				if (dwRecvLength < 2)
					continue;

				/* Parsing the TLV */
				try{
					node = TLVParser::TLV_Parse(pbRecvBufferFat,sizeof(pbRecvBufferFat));
				}catch(TLVException){
					continue;
				}

				/* Finding the PAN */
				try{
					PAN = TLVParser::TLV_Find(node, 0x5A);
				}catch(TLVException){
					continue;
				}
				if(PAN) {
					PANFound=true;
					if (PAN->Length >= 8){
						for (int i = 6; i < 8;i++) {
							v.push_back(static_cast<byte>(PAN->Value[i]));
						}
					}
				}

				if(PANFound){
                    burn(pbRecvBuffer, sizeof(pbRecvBuffer));
                    burn(pbRecvBufferFat, sizeof(pbRecvBufferFat));
                    return ;
                }
			}
		}
        burn(pbRecvBuffer, sizeof(pbRecvBuffer));
        burn(pbRecvBufferFat, sizeof(pbRecvBufferFat));
		throw EMVPANNotFound();
	}

	/* Helper function to transform the PAN received (vector of byte) to a string */
	template<typename TInputIter>
	void IccDataExtractor::make_hex_string(TInputIter first, TInputIter last, string& returnValue, bool use_uppercase, bool insert_spaces) {
		ostringstream ss;
		ss << hex << std::setfill('0');
		if (use_uppercase)
			ss << uppercase;
		while (first != last)
		{
			ss << setw(2) << static_cast<int>(*first++);
			if (insert_spaces && first != last)
				ss << " ";
		}

		returnValue = ss.str();
	}

	/* Wrapper function to get the PAN of the card*/
	void IccDataExtractor::GettingPAN(int readerNumber, string& panString) {

		#ifdef TC_WINDOWS
		if(!Initialized) 
			throw WinscardLibraryNotInitialized();
		#endif 

		vector<byte> PAN;

		bool isEMV= false;

		ConnectCard(readerNumber);

		/* Test all the type of applications and get the PAN from the first one found */
		for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){

			/* The card does not contain this application (0:Mastercard, 1:Visa, 2:Amex) */
			if(!TestingCardType(i)) continue;
			isEMV=true;
			GetPAN(PAN);
			break;
		}

		DisconnectCard();

		/* Check if the card is not an EMV one */
		if(!isEMV)
			throw EMVUnknownCardType();

		make_hex_string(PAN.begin(),PAN.end(),panString);

		burn(&PAN.front(),PAN.size());
	}

	PCSCException::operator string() const{
		if (ErrorCode == SCARD_S_SUCCESS)
			return string();

		static const struct{
			LONG ErrorCode;
			const char* ErrorString;
		} ErrorStrings[] = {
			#define SC_ERR(CODE) { CODE, #CODE },
#ifdef TC_WINDOWS
                SC_ERR(ERROR_BROKEN_PIPE)
            SC_ERR(SCARD_E_NO_PIN_CACHE)
            SC_ERR(SCARD_E_PIN_CACHE_EXPIRED)
            SC_ERR(SCARD_E_READ_ONLY_CARD)
            SC_ERR(SCARD_W_CACHE_ITEM_NOT_FOUND)
            SC_ERR(SCARD_W_CACHE_ITEM_STALE)
            SC_ERR(SCARD_W_CACHE_ITEM_TOO_BIG)
#endif
                SC_ERR(SCARD_E_BAD_SEEK)
                SC_ERR(SCARD_E_CANCELLED)
                SC_ERR(SCARD_E_CANT_DISPOSE)
                SC_ERR(SCARD_E_CARD_UNSUPPORTED)
                SC_ERR(SCARD_E_CERTIFICATE_UNAVAILABLE)
                SC_ERR(SCARD_E_COMM_DATA_LOST)
                SC_ERR(SCARD_E_COMM_DATA_LOST)
                SC_ERR(SCARD_E_DIR_NOT_FOUND)
                SC_ERR(SCARD_E_DUPLICATE_READER)
                SC_ERR(SCARD_E_FILE_NOT_FOUND)
                SC_ERR(SCARD_E_ICC_CREATEORDER)
                SC_ERR(SCARD_E_ICC_INSTALLATION)
                SC_ERR(SCARD_E_INSUFFICIENT_BUFFER)
                SC_ERR(SCARD_E_INVALID_ATR)
                SC_ERR(SCARD_E_INVALID_CHV)
                SC_ERR(SCARD_E_INVALID_HANDLE)
                SC_ERR(SCARD_E_INVALID_PARAMETER)
                SC_ERR(SCARD_E_INVALID_TARGET)
                SC_ERR(SCARD_E_INVALID_VALUE)
                SC_ERR(SCARD_E_NO_ACCESS)
                SC_ERR(SCARD_E_NO_DIR)
                SC_ERR(SCARD_E_NO_FILE)
                SC_ERR(SCARD_E_NO_KEY_CONTAINER)
                SC_ERR(SCARD_E_NO_MEMORY)
                SC_ERR(SCARD_E_NO_READERS_AVAILABLE)
                SC_ERR(SCARD_E_NO_SERVICE)
                SC_ERR(SCARD_E_NO_SMARTCARD)
                SC_ERR(SCARD_E_NO_SUCH_CERTIFICATE)
                SC_ERR(SCARD_E_NOT_READY)
                SC_ERR(SCARD_E_NOT_TRANSACTED)
                SC_ERR(SCARD_E_PCI_TOO_SMALL)
                SC_ERR(SCARD_E_PROTO_MISMATCH)
                SC_ERR(SCARD_E_READER_UNAVAILABLE)
                SC_ERR(SCARD_E_READER_UNSUPPORTED)
                SC_ERR(SCARD_E_SERVER_TOO_BUSY)
                SC_ERR(SCARD_E_SERVICE_STOPPED)
                SC_ERR(SCARD_E_SHARING_VIOLATION)
                SC_ERR(SCARD_E_SYSTEM_CANCELLED)
                SC_ERR(SCARD_E_TIMEOUT)
                SC_ERR(SCARD_E_UNEXPECTED)
                SC_ERR(SCARD_E_UNKNOWN_CARD)
                SC_ERR(SCARD_E_UNKNOWN_READER)
                SC_ERR(SCARD_E_UNKNOWN_RES_MNG)
                SC_ERR(SCARD_E_UNSUPPORTED_FEATURE)
                SC_ERR(SCARD_E_WRITE_TOO_MANY)
                SC_ERR(SCARD_F_COMM_ERROR)
                SC_ERR(SCARD_F_INTERNAL_ERROR)
                SC_ERR(SCARD_F_UNKNOWN_ERROR)
                SC_ERR(SCARD_W_CANCELLED_BY_USER)
                SC_ERR(SCARD_W_CARD_NOT_AUTHENTICATED)
                SC_ERR(SCARD_W_CHV_BLOCKED)
                SC_ERR(SCARD_W_EOF)
                SC_ERR(SCARD_W_REMOVED_CARD)
                SC_ERR(SCARD_W_RESET_CARD)
                SC_ERR(SCARD_W_SECURITY_VIOLATION)
                SC_ERR(SCARD_W_UNPOWERED_CARD)
                SC_ERR(SCARD_W_UNRESPONSIVE_CARD)
                SC_ERR(SCARD_W_UNSUPPORTED_CARD)
                SC_ERR(SCARD_W_WRONG_CHV)
#undef SC_ERR
		};

		for (size_t i = 0; i < array_capacity(ErrorStrings); ++i)
		{
			if (ErrorStrings[i].ErrorCode == ErrorCode)
				return ErrorStrings[i].ErrorString;
		}

		stringstream s;
		s << "0x" << ErrorCode;
		return s.str();
	}

	#ifdef TC_HEADER_Common_Exception
	void PCSCException::Show(HWND parent) const
	{
		string errorString = string(*this);

		if (!errorString.empty())
		{
			wstringstream subjectErrorCode;
			if (SubjectErrorCodeValid)
				subjectErrorCode << L": " << SubjectErrorCode;

			if (!GetDictionaryValue(errorString.c_str()))
			{
				if (errorString.find("SCARD_E_") == 0 || errorString.find("SCARD_F_") == 0 || errorString.find("SCARD_W_") == 0)
				{
					errorString = errorString.substr(8);
					for (size_t i = 0; i < errorString.size(); ++i)
					{
						if (errorString[i] == '_')
							errorString[i] = ' ';
					}
				}
				wchar_t err[8192];
				StringCbPrintfW(err, sizeof(err), L"%s:\n\n%hs%s", GetString("PCSC_ERROR"), errorString.c_str(), subjectErrorCode.str().c_str());
				ErrorDirect(err, parent);
			}
			else
			{
				wstring err = GetString(errorString.c_str());

				if (SubjectErrorCodeValid)
					err += L"\n\nError code" + subjectErrorCode.str();

				ErrorDirect(err.c_str(), parent);
			}
		}
	}
	#endif // TC_HEADER_Common_Exception

#ifdef TC_HEADER_Platform_Exception

    void PCSCException::Deserialize(shared_ptr <Stream> stream)
	{
		Exception::Deserialize(stream);
		Serializer sr(stream);
		uint64 code;
		sr.Deserialize("ErrorCode", code);
		sr.Deserialize("SubjectErrorCodeValid", SubjectErrorCodeValid);
		sr.Deserialize("SubjectErrorCode", SubjectErrorCode);
		ErrorCode = (LONG)code;
	}

	void PCSCException::Serialize(shared_ptr <Stream> stream) const
	{
		Exception::Serialize(stream);
		Serializer sr(stream);
		sr.Serialize("ErrorCode", (uint64)ErrorCode);
		sr.Serialize("SubjectErrorCodeValid", SubjectErrorCodeValid);
		sr.Serialize("SubjectErrorCode", SubjectErrorCode);
	}

#	define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#	undef TC_EXCEPTION_NODECL
#	define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET(PCSCTokenException);

#endif

}