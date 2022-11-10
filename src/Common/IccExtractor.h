
#ifndef TC_HEADER_Common_IccExtractor
#define TC_HEADER_Common_IccExtractor

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TC_WINDOWS
	#include <winscard.h>
#endif

#ifdef TC_UNIX
	//#include <stdbool.h> //Works without on windows
	#undef BOOL
	#include <PCSC/winscard.h>
	#define BOOL int
	//#include <unistd.h> //Works without on windows
#endif

#include "Tlv.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN64
#define ssize_t __int64
#else
#define ssize_t long
#endif


#define MAX_ATR_SIZE   33
#define MAX_READERNAME   128

#define SELECT_TYPE_SIZE 12      /* Size of the SELECT_TYPE APDU */


/* Cleaning function in case of error*/
int ErrorClean();

/* Printing PCSC error message | TODO : WARNING Veracrypt lock stdout so we can't write in it*/
void PCSC_ERROR(LONG rv, char* text);


/* Establishing the resource manager context (the scope) within which database operations are performed.
 * The module of the smart card subsystem that manages access to multiple readers and smart cards. The
 * resource manager identifies and tracks resources, allocates readers and resources across multiple
 * applications,and supports transaction primitives for accessing services available on a given card.*/
int EstablishRSContext();

/* Detecting available readers and filling the reader table */
int GetReaders();

/* Selecting the reader number (index in the table)*/
int SelectReaderNumber(int argc, char * readerNumber);

/* Connecting to the card*/
int ConnectCard(int reader_nb);

/* Getting the status of the card connected */
int StatusCard();

/* Testing if the card contains the application of the given EMV type */
int TestingCardType(BYTE * SELECT_TYPE);

/* Getting the ICC Public Key Certificates and the Issuer Public Key Certificates by parsing the application and put it into a reference */
int GetCerts(unsigned char* iccCert, unsigned char* issuerCert, int* iccCertSize, int* issuerCertSize);

/* Getting CPCL data from the card and put it into a reference*/
int GetCPCL(unsigned char* cpcl, int* cpcl_size);

/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates per application with the cpcl data present on the card and finally merge it into one byte array */
int GettingAllCerts(unsigned char* ICC_DATA, int* ICC_DATA_SIZE);

/* Cleaning function to end properly the protocol*/
int FinishClean();

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_Common_IccExtractor