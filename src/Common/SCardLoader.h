#ifndef TC_HEADER_Common_SCardLoader
#define TC_HEADER_Common_SCardLoader

#include "Platform/PlatformBase.h"

#ifdef TC_WINDOWS
#include <winscard.h>
#include <windows.h>
#else
#ifdef TC_MACOSX
#undef BOOL
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include "reader.h"
typedef LPSCARD_READERSTATE_A LPSCARD_READERSTATE;
using VeraCrypt::byte;
#define BOOL int
#else
#undef BOOL
#include "pcsclite.h"
#include <winscard.h>
#include <wintypes.h>
#include <reader.h>
using VeraCrypt::byte;
#define BOOL int
#endif
#endif

#ifndef TC_WINDOWS
typedef void* HMODULE;
#define SCARD_CALL_SPEC
#else
#define SCARD_CALL_SPEC	WINAPI
#endif

namespace VeraCrypt
{
	typedef LONG (SCARD_CALL_SPEC *SCardEstablishContextPtr)(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
	typedef LONG (SCARD_CALL_SPEC *SCardReleaseContextPtr)(SCARDCONTEXT hContext);
	typedef LONG (SCARD_CALL_SPEC *SCardIsValidContextPtr)(SCARDCONTEXT hContext);
#ifndef TC_MACOSX
	typedef LONG (SCARD_CALL_SPEC *SCardFreeMemoryPtr)(SCARDCONTEXT hContext, LPCVOID pvMem);
#endif
	typedef LONG (SCARD_CALL_SPEC *SCardConnectPtr)(SCARDCONTEXT hContext, LPCTSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
	typedef LONG (SCARD_CALL_SPEC *SCardReconnectPtr)(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol);
	typedef LONG (SCARD_CALL_SPEC *SCardDisconnectPtr)(SCARDHANDLE hCard, DWORD dwDisposition);
	typedef LONG (SCARD_CALL_SPEC *SCardBeginTransactionPtr)(SCARDHANDLE hCard);
	typedef LONG (SCARD_CALL_SPEC *SCardEndTransactionPtr)(SCARDHANDLE hCard, DWORD dwDisposition);
	typedef LONG (SCARD_CALL_SPEC *SCardStatusPtr)(SCARDHANDLE hCard, LPTSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, BYTE* pbAtr, LPDWORD pcbAtrLen);
	typedef LONG (SCARD_CALL_SPEC *SCardGetStatusChangePtr)(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATE rgReaderStates, DWORD cReaders);
	typedef LONG (SCARD_CALL_SPEC *SCardControlPtr)(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned);
	typedef LONG (SCARD_CALL_SPEC *SCardTransmitPtr)(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci, const BYTE* pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci, BYTE* pbRecvBuffer, LPDWORD pcbRecvLength);
	typedef LONG (SCARD_CALL_SPEC *SCardListReaderGroupsPtr)(SCARDCONTEXT hContext, LPTSTR mszGroups, LPDWORD pcchGroups);
	typedef LONG (SCARD_CALL_SPEC *SCardListReadersPtr)(SCARDCONTEXT hContext, LPCTSTR mszGroups, LPTSTR mszReaders, LPDWORD pcchReaders);
	typedef LONG (SCARD_CALL_SPEC *SCardCancelPtr)(SCARDCONTEXT hContext);
	typedef LONG (SCARD_CALL_SPEC *SCardGetAttribPtr)(SCARDHANDLE hCard, DWORD dwAttrId, BYTE* pbAttr, LPDWORD pcbAttrLen);
	typedef LONG (SCARD_CALL_SPEC *SCardSetAttribPtr)(SCARDHANDLE hCard, DWORD dwAttrId, const BYTE* pbAttr, DWORD cbAttrLen);

	class SCardLoader 
	{
	protected:
		static HMODULE						hScardModule;
		static SCARDCONTEXT					hScardContext;
		static SCardEstablishContextPtr     scardEstablishContext;
		static SCardReleaseContextPtr		scardReleaseContext;
		static SCardIsValidContextPtr		scardIsValidContext;
#ifndef TC_MACOSX
		static SCardFreeMemoryPtr			scardFreeMemory;
#endif
		static SCardConnectPtr				scardConnect;
		static SCardReconnectPtr            scardReconnect;
		static SCardDisconnectPtr			scardDisconnect;     
		static SCardBeginTransactionPtr		scardBeginTransaction;
		static SCardEndTransactionPtr		scardEndTransaction;
		static SCardStatusPtr				scardStatus;
		static SCardGetStatusChangePtr		scardGetStatusChange;
		static SCardControlPtr				scardControl;
		static SCardTransmitPtr				scardTransmit;
		static SCardListReaderGroupsPtr		scardListReaderGroups;
		static SCardListReadersPtr			scardListReaders;
		static SCardCancelPtr				scardCancel;
		static SCardGetAttribPtr            scardGetAttrib;
		static SCardSetAttribPtr            scardSetAttrib;
		static bool							bInitialized;

	public:
		static SCARD_IO_REQUEST*			scardT0Pci;
		static SCARD_IO_REQUEST*			scardT1Pci;
		static SCARD_IO_REQUEST*			scardRawPci;

		SCardLoader() { };
		static void Initialize();
		static void Finalize();
#ifdef TC_WINDOWS
		static wstring GetSCardPath();
#else
		static string GetSCardPath();
#endif
		static SCARDCONTEXT GetSCardContext();

		static LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
		static LONG SCardReleaseContext(SCARDCONTEXT hContext);
		static LONG SCardIsValidContext(SCARDCONTEXT hContext);
#ifndef TC_MACOSX
		static LONG SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem);
#endif
		static LONG SCardConnect(SCARDCONTEXT hContext, LPCTSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
		static LONG SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol);
		static LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition);
		static LONG SCardBeginTransaction(SCARDHANDLE hCard);
		static LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition);
		static LONG SCardStatus(SCARDHANDLE hCard, LPTSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, BYTE* pbAtr, LPDWORD pcbAtrLen);
		static LONG SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATE rgReaderStates, DWORD cReaders);
		static LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned);
		static LONG SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci, const BYTE* pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci, BYTE* pbRecvBuffer, LPDWORD pcbRecvLength);
		static LONG SCardListReaderGroups(SCARDCONTEXT hContext, LPTSTR mszGroups, LPDWORD pcchGroups);
		static LONG SCardListReaders(SCARDCONTEXT hContext, LPCTSTR mszGroups, LPTSTR mszReaders, LPDWORD pcchReaders);
		static LONG SCardCancel(SCARDCONTEXT hContext);
		static LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, BYTE* pbAttr, LPDWORD pcbAttrLen);
		static LONG SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, const BYTE* pbAttr, DWORD cbAttrLen);
	};
};

#endif // TC_HEADER_Common_SCardLoader