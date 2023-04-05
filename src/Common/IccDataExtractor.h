//
// Created by bshp on 1/14/23.
//

#ifndef NEWEMV_ICCDATAEXTRACTOR_H
#define NEWEMV_ICCDATAEXTRACTOR_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <vector>
#include <iomanip>
#include <memory>
#include "Platform/PlatformBase.h"
#include "TLVParser.h"

#ifdef  __linux__
#include <unistd.h>
#endif

#ifdef TC_WINDOWS
#include <winscard.h>
#include "Exception.h"
#include <windows.h>
#endif
#ifdef TC_UNIX
#undef BOOL
#include <PCSC/winscard.h>
using VeraCrypt::byte;
#define BOOL int
//#include <unistd.h> //Works without on windows
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN64
#define ssize_t __int64
#else
#define ssize_t long
#endif

#define SELECT_TYPE_SIZE 12      /* Size of the SELECT_TYPE APDU */

/* Winscard function pointers definitions for windows import */
#ifdef TC_WINDOWS
typedef	LONG (WINAPI *SCardEstablishContextPtr)(DWORD dwScope,LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
typedef LONG (WINAPI *SCardReleaseContextPtr)(SCARDCONTEXT hContext);
typedef LONG (WINAPI *SCardConnectAPtr)(SCARDCONTEXT hContext,LPCSTR szReader,DWORD dwShareMode,DWORD dwPreferredProtocols,LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
typedef LONG (WINAPI *SCardDisconnectPtr)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (WINAPI *SCardTransmitPtr)(SCARDHANDLE hCard,LPCSCARD_IO_REQUEST pioSendPci,const BYTE* pbSendBuffer, DWORD cbSendLength,LPSCARD_IO_REQUEST pioRecvPci,BYTE* pbRecvBuffer, LPDWORD pcbRecvLength);
typedef LONG (WINAPI *SCardListReadersAPtr)(SCARDCONTEXT hContext,LPCSTR mszGroups,LPSTR mszReaders, LPDWORD pcchReaders);
typedef LONG (WINAPI *SCardFreeMemoryPtr)(SCARDCONTEXT hContext,LPCVOID pvMem);
#endif

namespace VeraCrypt
{
	class IccDataExtractor {
	private:

		/* Used for loading winscard on windows */
		#ifdef TC_WINDOWS
		/* Winscard Library Handle */
		HMODULE WinscardLibraryHandle;

		/* Winscard function pointers */
		SCardEstablishContextPtr WSCardEstablishContext;
		SCardReleaseContextPtr WSCardReleaseContext;
		SCardConnectAPtr WSCardConnectA;
		SCardDisconnectPtr WSCardDisconnect;
		SCardFreeMemoryPtr WSCardFreeMemory;
		SCardListReadersAPtr WSCardListReadersA;
		SCardTransmitPtr WSCardTransmit;
		#endif

		/* SELECT_TYPES FOR DIFFERENT AIDs*/
		const static BYTE SELECT_MASTERCARD[SELECT_TYPE_SIZE];
		const static BYTE SELECT_VISA[SELECT_TYPE_SIZE];
		const static BYTE SELECT_AMEX[SELECT_TYPE_SIZE];
		const static BYTE * SELECT_TYPES[3];


		SCARDCONTEXT hContext;      /* Handle that identifies the resource manager context.*/

		SCARDHANDLE hCard;          /* A handle that identifies the connection to the smart card in the designated reader*/

		std::vector<char*> readers;  /* Card reader list */

		unsigned long int nbReaders;              /* Number of connected (available) readers */

		LPSTR mszReaders;           /* Names of the reader groups defined to the system, as a multi-string. Use a NULL value to
									 * list all readers in the system */

		DWORD dwActiveProtocol;       /* A flag that indicates the established active protocol.
									  * SCARD_PROTOCOL_T0: An asynchronous, character-oriented half-duplex transmission protocol.
									  * SCARD_PROTOCOL_T1: An asynchronous, block-oriented half-duplex transmission protocol.*/

		/* Used to initialize the winscard library on windows to make sure the dll is in System32 */
		#ifdef TC_WINDOWS
		void IccDataExtractor::InitLibrary();
		#endif

		/* Establishing the resource manager context (the scope) within which database operations are performed.
		* The module of the smart card subsystem that manages access to multiple readers and smart cards. The
		* resource manager identifies and tracks resources, allocates readers and resources across multiple
		* applications,and supports transaction primitives for accessing services available on a given card.*/
		int EstablishRSContext();

		/* Connecting to the card in the given reader*/
		int ConnectCard(unsigned long int reader_nb);

		/* Disconnect the card currently connected*/
		int DisconnectCard();

		/* Testing if the card contains the application of the given EMV type */
		bool TestingCardType(const int SELECT_TYPE_NUMBER);

		/* Getting the ICC Public Key Certificates and the Issuer Public Key Certificates by parsing the application
		* (!NEED TO TEST CARD TYPE TO SELECT APPLICATION FIRST!)*/
		void GetCerts(vector<byte> &CERTS);

		/* Getting CPCL data from the card and put it into a reference*/
		void GetCPCL(vector<byte> &v);

		/* Getting the PAN  by parsing the application
		* (!NEED TO TEST CARD TYPE TO SELECT APPLICATION FIRST!)*/
		void GetPAN(vector<byte> &v);

		/* Helper function to make a string from plain arrays and various standard containers of bytes */
		template<typename TInputIter>
		std::string make_hex_string(TInputIter first, TInputIter last, bool use_uppercase = true, bool insert_spaces = false);

	public:
		IccDataExtractor();

		~IccDataExtractor();

		/* Detecting available readers and filling the reader table. Returns
		* the number of available readers */
		unsigned long GetReaders();


		/* Getting an ICC Public Key Certificates, an Issuer Public Key Certificates and the CPCL data
		* from the card designated by the reader number. Appending them into a byte vector */
		void GettingAllCerts(int readerNumber, vector<byte> &v);

		/* Getting the PAN from the card designated by the reader number */
		std::string GettingPAN(int readerNumber);
	};


	/* The definition of the exception class related to PCSC Library */
	class PCSCException
	{
	public:
		PCSCException(LONG errorCode): m_errorCode(errorCode){}

		/* Get the error code */
		inline std::string ErrorMessage() const
		{
			return "Winscard error: "+ std::to_string(static_cast<long long>(m_errorCode));
		}

	protected:
		LONG m_errorCode;
	};

	/* The definition of the exception class related to ICC data extraction */
	class ICCExtractionException
	{
	public:
		ICCExtractionException(std::string errormessage): m_errormessage(errormessage){}

		/* Get the error message */
		inline std::string ErrorMessage() const
		{
			return "<EMV> "+ m_errormessage;
		}

	protected:
		std::string m_errormessage;
	};
}

#endif //NEWEMV_ICCDATAEXTRACTOR_H
