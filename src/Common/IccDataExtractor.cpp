//
// Created by bshp on 1/14/23.
//

#include "IccDataExtractor.h"

namespace VeraCrypt
{
	//using namespace std;
	const BYTE IccDataExtractor::SELECT_MASTERCARD[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x04, 0x10, 0x10};
	const BYTE IccDataExtractor::SELECT_VISA[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x03, 0x10, 0x10};
	const BYTE IccDataExtractor::SELECT_AMEX[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 00, 0x25, 0x10};
	const BYTE * IccDataExtractor::SELECT_TYPES[]={SELECT_MASTERCARD,  SELECT_VISA, SELECT_AMEX};

	IccDataExtractor::IccDataExtractor(){
		#ifdef TC_WINDOWS
		InitLibrary();
		#endif
	}

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

		#ifdef TC_WINDOWS
		FreeLibrary(WinscardLibraryHandle);
		#endif
	}

	#ifdef TC_WINDOWS
	void IccDataExtractor::InitLibrary(){
		
		/* Getting the System32 directory */
		char sysDir[MAX_PATH];
		GetSystemDirectoryA(sysDir, MAX_PATH);
		
		/* Getting the winscard dll path directory */
		char winscardPath[MAX_PATH];
		sprintf_s(winscardPath, "%s\\Winscard.dll", sysDir);

		/* Loading the winscard dll from System32 */
		WinscardLibraryHandle = LoadLibraryA(winscardPath);
		throw_sys_if(!WinscardLibraryHandle);

		/* Fetching the functions pointers from the dll */
		WSCardEstablishContext = (SCardEstablishContextPtr) GetProcAddress(WinscardLibraryHandle,"SCardEstablishContext");
		WSCardReleaseContext= (SCardReleaseContextPtr) GetProcAddress(WinscardLibraryHandle,"SCardReleaseContext");
		WSCardConnectA = (SCardConnectAPtr) GetProcAddress(WinscardLibraryHandle,"SCardConnectA");
		WSCardDisconnect = (SCardDisconnectPtr) GetProcAddress(WinscardLibraryHandle,"SCardDisconnect");
		WSCardFreeMemory = ( SCardFreeMemoryPtr) GetProcAddress(WinscardLibraryHandle,"SCardFreeMemory");
		WSCardListReadersA =  (SCardListReadersAPtr) GetProcAddress(WinscardLibraryHandle,"SCardListReadersA");
		WSCardTransmit = ( SCardTransmitPtr) GetProcAddress(WinscardLibraryHandle,"SCardTransmit");
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
			throw ICCExtractionException("Error when fetching readers: " + PCSCException(returnValue).ErrorMessage());
 
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
			throw ICCExtractionException("Wrong reader index: "+std::to_string(static_cast<long long>(reader_nb)));

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
			throw ICCExtractionException("Testing card type response not recognisable");

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
					throw ICCExtractionException("Getting folder data response not recognisable");

				/* Parsing the TLV */
				node = TLVParser::TLV_Parse(pbRecvBufferFat,sizeof(pbRecvBufferFat));

				/* Finding the ICC_Public_Key_Certificate */
				ICC_Public_Key_Certificate = TLVParser::TLV_Find(node, 0x9F46);
				if(ICC_Public_Key_Certificate) {
					iccFound=true;
					for (int i = 0; i < ICC_Public_Key_Certificate->Length;i++) {
						CERTS.push_back(static_cast<byte>(ICC_Public_Key_Certificate->Value[i]));
					}
				}

				/* Finding the Issuer_Public_Key_Certificate */
				Issuer_PK_Certificate = TLVParser::TLV_Find(node, 0x90);
				if(Issuer_PK_Certificate) {
					issuerFound=true;
					for (int i = 0; i < Issuer_PK_Certificate->Length;i++) {
						CERTS.push_back(static_cast<byte>(Issuer_PK_Certificate->Value[i]));
					}
				}

				/* Limiting the search to at least one occurrence of both PKs to speed up the process.
				* There might be more certificates tho */
				if(iccFound && issuerFound) return;
			}
		}

		throw ICCExtractionException("At least one of the PK is missing in this application");
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
			throw ICCExtractionException("Not the correct APDU response code when checking for CPCL data");

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
			throw ICCExtractionException("Getting CPCl data response not recognisable");

		/* We add CPCL data and crop the TAG and the data length at the start and the trailer at the end */
		for (unsigned long i = 3; i < dwRecvLength-2; i++) {
			v.push_back(static_cast<byte>(pbRecvBufferFat[i]));
		}
	}

	/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates for the first application with the cpcl
	* data present on the card and finally merge it into one byte array */
	void IccDataExtractor::GettingAllCerts(int readerNumber, vector<byte> &v){
		bool isEMV= false;
		bool hasCerts=false;

		try{
			ConnectCard(readerNumber);
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when connecting to card. " + ex.ErrorMessage());
		}

		/* Test all the type of applications and get the certificates from the first one found */
		for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){

			try{
				/* The card does not contain this application (0:Mastercard, 1:Visa, 2:Amex) */
				if(!TestingCardType(i)) continue;
				isEMV= true;
				GetCerts(v);
				hasCerts=true;
				break;
			}catch(const TLVException &ex){
				throw ICCExtractionException("Error when parsing the TLV when getting the certificates:" + ex.ErrorMessage());
			}catch(const PCSCException &ex){
				throw ICCExtractionException("Error when fetching the certificates. " + ex.ErrorMessage());
			}

		}

		/* Need to disconnect reconnect the card to access CPLC data (not located in any application) */
		try{
			DisconnectCard();
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when disconnecting the card. " + ex.ErrorMessage());
		}

		/* Check if the card is not an EMV one */
		if(!isEMV)
			throw ICCExtractionException("Unknown card type");

		/* Not enough data to act as a keyfile (CPLC data is not enough) */
		if (!hasCerts)
			throw ICCExtractionException("No certificates on the card");

		try{
			ConnectCard(readerNumber);
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when connecting to card. " + ex.ErrorMessage());
		}

		try{
			GetCPCL(v);
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when fetching the CPCL data. " + ex.ErrorMessage());
		}

		try{
			DisconnectCard();
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when disconnecting the card. " + ex.ErrorMessage());
		}
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
					throw ICCExtractionException("Getting folder data response not recognisable");

				/* Parsing the TLV */
				node = TLVParser::TLV_Parse(pbRecvBufferFat,sizeof(pbRecvBufferFat));

				/* Finding the PAN */
				PAN = TLVParser::TLV_Find(node, 0x5A);
				if(PAN) {
					PANFound=true;
					for (int i = 0; i < PAN->Length;i++) {
						v.push_back(static_cast<byte>(PAN->Value[i]));
					}
				}
				if(PANFound) return ;
			}
		}

		throw ICCExtractionException("PAN not found");
	}

	template<typename TInputIter>
	string IccDataExtractor::make_hex_string(TInputIter first, TInputIter last, bool use_uppercase, bool insert_spaces) {
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
		return ss.str();
	}

	string IccDataExtractor::GettingPAN(int readerNumber) {
		vector<byte> PAN;

		bool isEMV= false;

		try{
			ConnectCard(readerNumber);
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when connecting to card. " + ex.ErrorMessage());
		}

		/* Test all the type of applications and get the PAN from the first one found */
		for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){
			try{
				/* The card does not contain this application (0:Mastercard, 1:Visa, 2:Amex) */
				if(!TestingCardType(i)) continue;
				isEMV=true;
				GetPAN(PAN);
				break;
			}catch(const TLVException &ex){
				throw ICCExtractionException("Error when parsing the TLV when getting the PAN:" + ex.ErrorMessage());
			}catch(const PCSCException &ex){
				throw ICCExtractionException("Error when fetching the PAN. " + ex.ErrorMessage());
			}
		}

		try{
			DisconnectCard();
		}catch(const PCSCException &ex){
			throw ICCExtractionException("Error when disconnecting the card. " + ex.ErrorMessage());
		}

		/* Check if the card is not an EMV one */
		if(!isEMV)
			throw ICCExtractionException("Unknown card type");

		return make_hex_string(PAN.begin(),PAN.end());
	}
}