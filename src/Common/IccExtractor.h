
#ifndef TC_HEADER_Common_IccExtractor
#define TC_HEADER_Common_IccExtractor

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#undef BOOL
#include <PCSC/winscard.h> // TODO : verify that this is the same for linux and windows
#define BOOL int
#include <unistd.h>
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

/* SELECT_TYPES FOR DIFFERENT AIDs*/
BYTE SELECT_MASTERCARD[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x04, 0x10, 0x10};
BYTE SELECT_VISA[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x03, 0x10, 0x10};
BYTE SELECT_AMEX[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 00, 0x25, 0x10};
BYTE SELECT_CB[]={00, 0xA4, 0x04, 00, 0x07,0xA0, 00, 00, 00, 0x42, 0x10, 0x10, };
BYTE * SELECT_TYPES[]={SELECT_MASTERCARD, SELECT_AMEX, SELECT_VISA,SELECT_CB};


LONG returnValue;           /* Return value of SCard functions */
SCARDCONTEXT hContext;      /* Handle that identifies the resource manager context.*/
char **readers = NULL;      /* Card reader table */
int nbReaders;
LPSTR mszReaders = NULL;    /* Names of the reader groups defined to the system, as a multi-string. Use a NULL value to
                             * list all readers in the system */

DWORD dwReaders;            /* Length of the mszReaders buffer in characters. If the buffer length is specified as
                             * SCARD_AUTOALLOCATE, then mszReaders is converted to a pointer to a byte pointer, and
                             * receives the address of a block of memory containing the multi-string structure */

SCARDHANDLE hCard;          /* A handle that identifies the connection to the smart card in the designated reader*/

DWORD dwActiveProtocol;       /* A flag that indicates the established active protocol.
                             * SCARD_PROTOCOL_T0: An asynchronous, character-oriented half-duplex transmission protocol.
                             * SCARD_PROTOCOL_T1: An asynchronous, block-oriented half-duplex transmission protocol.*/

char pbReader[MAX_READERNAME] = ""; /* List of display names (multiple string) by which the currently connected reader
                                     * is known.*/

BYTE pbAtr[MAX_ATR_SIZE] = ""; /* Pointer to a 32-byte buffer that receives the ATR string from the currently inserted
                                * card, if available. ATR string : A sequence of bytes returned from a smart card when
                                * it is turned on. These bytes are used to identify the card to the system. */

DWORD dwAtrLen,dwReaderLen; /* Respectively the length of pbAtr and pbReader */
DWORD dwState;              /* Current state of the smart card in the reader*/
DWORD dwProt;               /* Current protocol, if any*/

SCARD_IO_REQUEST pioSendPci;
SCARD_IO_REQUEST pioRecvPci;

BYTE pbRecvBuffer[64];      /* Buffer to receive the card response */
BYTE pbRecvBufferFat[256];  /* Bigger buffer to receive the card response */
DWORD dwSendLength, dwRecvLength; /* Respectively the current length of the sender buffer and the reception buffer */


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

/* Getting the ICC Public Key Certificates and the Issuer Public Key Certificates by parsing the application */
int GetCerts(unsigned char* icc, unsigned char* issuer);

/* Getting CPCL data from the card*/
int GetCPCL(unsigned char* cpcl);

/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates per application with the cpcl data present on the card and finally merge it into one byte array */
int GettingAllCerts(unsigned char* data);

/* Cleaning function to end properly the protocol*/
int FinishClean();

#endif // TC_HEADER_Common_IccExtractor