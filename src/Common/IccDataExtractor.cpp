//
// Created by bshp on 1/14/23.
//

#include "IccDataExtractor.h"
using namespace std;
const BYTE IccDataExtractor::SELECT_MASTERCARD[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x04, 0x10, 0x10};
const BYTE IccDataExtractor::SELECT_VISA[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x03, 0x10, 0x10};
const BYTE IccDataExtractor::SELECT_AMEX[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 00, 0x25, 0x10};
const BYTE * IccDataExtractor::SELECT_TYPES[]={SELECT_MASTERCARD,  SELECT_VISA, SELECT_AMEX};

IccDataExtractor::IccDataExtractor(){}

IccDataExtractor::~IccDataExtractor(){
	/* Disconnect card if connected */
	if(hCard) SCardDisconnect(hContext,hCard);

	/* Closing the established resource manager context freeing any resources allocated under that context
	* including SCARDHANDLE objects and memory allocated using the SCARD_AUTOALLOCATE length designator*/
	if(hContext) SCardReleaseContext(hContext);

	/* Release memory that has been returned from the resource manager using the SCARD_AUTOALLOCATE length
	* designator*/
	if (mszReaders) SCardFreeMemory(hContext, mszReaders);

}

/* Establishing the resource manager context (the scope) within which database operations are performed.
* The module of the smart card subsystem that manages access to multiple readers and smart cards. The
* resource manager identifies and tracks resources, allocates readers and resources across multiple
* applications,and supports transaction primitives for accessing services available on a given card.*/
int IccDataExtractor::EstablishRSContext(){

	//if(hContext==NULL){
	LONG returnValue = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

	/* Check if the establishment of the context was unsuccessful  */
	if (returnValue != SCARD_S_SUCCESS)
		throw PCSCException(returnValue);

	return EXIT_SUCCESS;
	//}
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
	long returnValue = SCardListReadersA(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
#else
	long returnValue = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
#endif

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

	/* Check if there is at least one reader connected */
	if (nbReaders == 0)
		throw ICCExtractionException("No reader found");

	return nbReaders;
}

/* Connecting to the card in the given reader*/
int IccDataExtractor::ConnectCard(unsigned long int reader_nb){

	/* Check if the given reader slot number is possible */
	if (reader_nb < 0 || reader_nb >= nbReaders)
		throw ;//ICCExtractionException("Wrong reader index: "+to_string(reader_nb));

	dwActiveProtocol = SCARD_PROTOCOL_UNDEFINED;

#ifdef TC_WINDOWS
	LONG returnValue = SCardConnectA(hContext, readers[reader_nb], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
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
	LONG returnValue = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);

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

	LONG returnValue = SCardTransmit(hCard, &ioRequest, SELECTED_TYPE, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);

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
			returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);

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
			returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,
				NULL, pbRecvBufferFat, &dwRecvLength);

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

			/* Finding the ICC_Public_Key_Certificate */
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
	LONG returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength,
		NULL, pbRecvBuffer, &dwRecvLength);

	/* Check if the transmission was unsuccessful  */
	if (returnValue != SCARD_S_SUCCESS)
		throw PCSCException(returnValue);

	/* Not the correct APDU response code */
	if (pbRecvBuffer[0] != 0x6C)
		throw APDUException(&pbRecvBuffer[0]);

	/* It set the proper expected length of the data in the APDU */
	SELECT_APDU_CPCL[4] = pbRecvBuffer[1];

	dwRecvLength = sizeof(pbRecvBufferFat);

	/* Get the CPCL data */
	returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_CPCL, dwSendLength,
		NULL, pbRecvBufferFat, &dwRecvLength);

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

	ConnectCard(readerNumber);

	/* Test all the type of applications and get the certificates from the first one found */
	for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){

		/* The card does not contain this application (0:Mastercard, 1:Visa, 2:Amex) */
		if(!TestingCardType(i)) continue;
		isEMV= true;
		GetCerts(v);
		hasCerts=true;
		break;
	}

	/* Need to disconnect reconnect the card to access CPLC data (not located in any application) */
	DisconnectCard();

	/* Check if the card is not an EMV one */
	if(!isEMV)
		throw ICCExtractionException("Unknown card type");

	/* Not enough data to act as a keyfile (CPLC data is not enough) */
	if (!hasCerts)
		throw ICCExtractionException("No Certs on the card");

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
			returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,NULL, pbRecvBuffer, &dwRecvLength);

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
			returnValue = SCardTransmit(hCard, &ioRequest, SELECT_APDU_FILE, dwSendLength,
				NULL, pbRecvBufferFat, &dwRecvLength);

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
string IccDataExtractor::make_hex_string(TInputIter first, TInputIter last, bool use_uppercase, bool insert_spaces)
{
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
		throw ICCExtractionException("Unknown card type");

	return make_hex_string(PAN.begin(),PAN.end());
}
