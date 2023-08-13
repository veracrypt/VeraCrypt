#include "SCardLoader.h"
#include "PCSCException.h"

#ifndef TC_WINDOWS
#include <dlfcn.h>
#define LoadLibrary(x) dlopen(x, RTLD_NOW | RTLD_LOCAL)
#define FreeLibrary(x) dlclose(x)
#define GetProcAddress(x, y) dlsym(x, y)
typedef void* HMODULE;
#ifdef TC_MACOSX
#if !defined(USE_SCARD_CONTROL_112)
#define SCardControlName "SCardControl132"
#else
#define SCardControlName "SCardControl"
#endif
#else
#define SCardControlName "SCardControl"
#endif
#define SCardConnectName "SCardConnect"
#define SCardStatusName "SCardStatus"
#define SCardGetStatusChangeName "SCardGetStatusChange"
#define SCardListReaderGroupsName "SCardListReaderGroups"
#define SCardListReadersName "SCardListReaders"
#else
#define SCardControlName "SCardControl"
#define SCardConnectName "SCardConnectW"
#define SCardStatusName "SCardStatusW"
#define SCardGetStatusChangeName "SCardGetStatusChangeW"
#define SCardListReaderGroupsName "SCardListReaderGroupsW"
#define SCardListReadersName "SCardListReadersW"
#endif

using namespace std;

namespace VeraCrypt
{
	HMODULE SCardLoader::hScardModule = NULL;
	SCARDCONTEXT SCardLoader::hScardContext = 0;
	SCardEstablishContextPtr SCardLoader::scardEstablishContext = NULL;
	SCardReleaseContextPtr SCardLoader::scardReleaseContext = NULL;
	SCardIsValidContextPtr SCardLoader::scardIsValidContext = NULL;
#ifndef TC_MACOSX
	SCardFreeMemoryPtr SCardLoader::scardFreeMemory = NULL;
#endif
	SCardConnectPtr SCardLoader::scardConnect = NULL;
	SCardReconnectPtr SCardLoader::scardReconnect = NULL;
	SCardDisconnectPtr SCardLoader::scardDisconnect = NULL;     
	SCardBeginTransactionPtr SCardLoader::scardBeginTransaction = NULL;
	SCardEndTransactionPtr SCardLoader::scardEndTransaction = NULL;
	SCardStatusPtr SCardLoader::scardStatus = NULL;
	SCardGetStatusChangePtr SCardLoader::scardGetStatusChange = NULL;
	SCardControlPtr SCardLoader::scardControl = NULL;
	SCardTransmitPtr SCardLoader::scardTransmit = NULL;
	SCardListReaderGroupsPtr SCardLoader::scardListReaderGroups = NULL;
	SCardListReadersPtr SCardLoader::scardListReaders = NULL;
	SCardCancelPtr SCardLoader::scardCancel = NULL;
	SCardGetAttribPtr SCardLoader::scardGetAttrib = NULL;
	SCardSetAttribPtr SCardLoader::scardSetAttrib = NULL;
	SCARD_IO_REQUEST* SCardLoader::scardT0Pci = NULL;
	SCARD_IO_REQUEST* SCardLoader::scardT1Pci = NULL;
	SCARD_IO_REQUEST* SCardLoader::scardRawPci = NULL;
	bool SCardLoader::bInitialized = false;

#ifdef TC_WINDOWS
	wstring SCardLoader::GetSCardPath()
#else
	string SCardLoader::GetSCardPath()
#endif
	{
#ifdef TC_WINDOWS
		wchar_t winscardPath[TC_MAX_PATH];
		if (GetSystemDirectory(winscardPath, TC_MAX_PATH))
		{
			StringCbCat(winscardPath, sizeof(winscardPath), L"\\Winscard.dll");
		}
		else
			StringCbCopy(winscardPath, sizeof(winscardPath), L"C:\\Windows\\System32\\Winscard.dll");
		return winscardPath;
#elif TC_MACOSX
		return "/System/Library/Frameworks/PCSC.framework/PCSC";
#else
		string pcscPath = "";
		FILE* pipe = 
#ifdef TC_LINUX
			popen("ldconfig -p 2>&1", "r");
#else
			popen("ldconfig -r 2>&1", "r"); // FreeBSD
#endif
		if (pipe)
		{
			char buffer[128];
			while (!feof(pipe))
			{
				if (fgets(buffer, 128, pipe) != NULL)
				{
					string line(buffer);
					if (line.find("libpcsclite.so") != string::npos)
					{
						size_t pos = line.find("=>");
						if (pos != string::npos)
						{
							pcscPath = line.substr(pos + 3);
							pos = pcscPath.find_first_of(" \t\r\n");
							if (pos != string::npos)
								pcscPath = pcscPath.substr(0, pos);
							break;
						}
					}
				}
			}
			pclose(pipe);
		}

		if (pcscPath == "")
		{
			pcscPath = "libpcsclite.so";
		}
		
		return pcscPath;
#endif
	}

	void SCardLoader::Initialize()
	{
		if (bInitialized)
			return;

		hScardModule = LoadLibrary(GetSCardPath().c_str());
		if (hScardModule)
		{
			scardEstablishContext = (SCardEstablishContextPtr)GetProcAddress(hScardModule, "SCardEstablishContext");
			scardReleaseContext = (SCardReleaseContextPtr)GetProcAddress(hScardModule, "SCardReleaseContext");
			scardIsValidContext = (SCardIsValidContextPtr)GetProcAddress(hScardModule, "SCardIsValidContext");
#ifndef TC_MACOSX
			scardFreeMemory = (SCardFreeMemoryPtr)GetProcAddress(hScardModule, "SCardFreeMemory");
#endif
			scardConnect = (SCardConnectPtr)GetProcAddress(hScardModule, SCardConnectName);
			scardReconnect = (SCardReconnectPtr)GetProcAddress(hScardModule, "SCardReconnect");
			scardDisconnect = (SCardDisconnectPtr)GetProcAddress(hScardModule, "SCardDisconnect");
			scardBeginTransaction = (SCardBeginTransactionPtr)GetProcAddress(hScardModule, "SCardBeginTransaction");
			scardEndTransaction = (SCardEndTransactionPtr)GetProcAddress(hScardModule, "SCardEndTransaction");
			scardStatus = (SCardStatusPtr)GetProcAddress(hScardModule, SCardStatusName);
			scardGetStatusChange = (SCardGetStatusChangePtr)GetProcAddress(hScardModule, SCardGetStatusChangeName);
			scardControl = (SCardControlPtr)GetProcAddress(hScardModule, SCardControlName);
			scardTransmit = (SCardTransmitPtr)GetProcAddress(hScardModule, "SCardTransmit");
			scardListReaderGroups = (SCardListReaderGroupsPtr)GetProcAddress(hScardModule, SCardListReaderGroupsName);
			scardListReaders = (SCardListReadersPtr)GetProcAddress(hScardModule, SCardListReadersName);
			scardCancel = (SCardCancelPtr)GetProcAddress(hScardModule, "SCardCancel");
			scardGetAttrib = (SCardGetAttribPtr)GetProcAddress(hScardModule, "SCardGetAttrib");
			scardSetAttrib = (SCardSetAttribPtr)GetProcAddress(hScardModule, "SCardSetAttrib");
			scardT0Pci = (SCARD_IO_REQUEST*)GetProcAddress(hScardModule, "g_rgSCardT0Pci");
			scardT1Pci = (SCARD_IO_REQUEST*)GetProcAddress(hScardModule, "g_rgSCardT1Pci");
			scardRawPci = (SCARD_IO_REQUEST*)GetProcAddress(hScardModule, "g_rgSCardRawPci");
			if (
#ifndef TC_MACOSX
				scardFreeMemory &&
#endif
				scardEstablishContext && scardReleaseContext && scardIsValidContext && scardConnect && scardReconnect && scardDisconnect &&
				scardBeginTransaction && scardEndTransaction && scardStatus && scardGetStatusChange && scardControl && scardTransmit &&
				scardListReaderGroups && scardListReaders && scardCancel && scardGetAttrib && scardSetAttrib && scardT0Pci && scardT1Pci && scardRawPci)
			{
				if (SCARD_S_SUCCESS == scardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hScardContext))
				{
					bInitialized = true;
				}
			}
		}

		if (!bInitialized)
		{
			Finalize();
		}
	}

	void SCardLoader::Finalize()
	{
		if (hScardContext)
		{
			scardReleaseContext(hScardContext);
			hScardContext = 0;
		}

		if (hScardModule)
		{
			FreeLibrary(hScardModule);
			hScardModule = NULL;
		}

		scardEstablishContext = NULL;
		scardReleaseContext = NULL;
		scardIsValidContext = NULL;
#ifndef TC_MACOSX
		scardFreeMemory = NULL;
#endif
		scardConnect = NULL;
		scardReconnect = NULL;
		scardDisconnect = NULL;
		scardBeginTransaction = NULL;
		scardEndTransaction = NULL;
		scardStatus = NULL;
		scardGetStatusChange = NULL;
		scardControl = NULL;
		scardTransmit = NULL;
		scardListReaderGroups = NULL;
		scardListReaders = NULL;
		scardCancel = NULL;
		scardGetAttrib = NULL;
		scardSetAttrib = NULL;
		scardT0Pci = NULL;
		scardT1Pci = NULL;
		scardRawPci = NULL;

		bInitialized = false;
	}

	SCARDCONTEXT SCardLoader::GetSCardContext()
	{
		return hScardContext;
	}

	LONG SCardLoader::SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
	}

	LONG SCardLoader::SCardReleaseContext(SCARDCONTEXT hContext)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardReleaseContext(hContext);
	}

	LONG SCardLoader::SCardIsValidContext(SCARDCONTEXT hContext)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardIsValidContext(hContext);
	}

#ifndef TC_MACOSX
	LONG SCardLoader::SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardFreeMemory(hContext, pvMem);
	}
#endif

	LONG SCardLoader::SCardConnect(SCARDCONTEXT hContext, LPCTSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol);
	}
	
	LONG SCardLoader::SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardReconnect(hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol);
	}
	
	LONG SCardLoader::SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardDisconnect(hCard, dwDisposition);
	}
	
	LONG SCardLoader::SCardBeginTransaction(SCARDHANDLE hCard)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardBeginTransaction(hCard);
	}
	
	LONG SCardLoader::SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardEndTransaction(hCard, dwDisposition);
	}
	
	LONG SCardLoader::SCardStatus(SCARDHANDLE hCard, LPTSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, BYTE* pbAtr, LPDWORD pcbAtrLen)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardStatus(hCard, mszReaderNames, pcchReaderLen, pdwState, pdwProtocol, pbAtr, pcbAtrLen);
	}
	
	LONG SCardLoader::SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATE rgReaderStates, DWORD cReaders)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders);
	}
	
	LONG SCardLoader::SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardControl(hCard, dwControlCode, pbSendBuffer, cbSendLength, pbRecvBuffer, cbRecvLength, lpBytesReturned);
	}
	
	LONG SCardLoader::SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci, const BYTE* pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci, BYTE* pbRecvBuffer, LPDWORD pcbRecvLength)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength);
	}
	
	LONG SCardLoader::SCardListReaderGroups(SCARDCONTEXT hContext, LPTSTR mszGroups, LPDWORD pcchGroups)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardListReaderGroups(hContext, mszGroups, pcchGroups);
	}
	
	LONG SCardLoader::SCardListReaders(SCARDCONTEXT hContext, LPCTSTR mszGroups, LPTSTR mszReaders, LPDWORD pcchReaders)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardListReaders(hContext, mszGroups, mszReaders, pcchReaders);
	}
	
	LONG SCardLoader::SCardCancel(SCARDCONTEXT hContext)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardCancel(hContext);
	}
	
	LONG SCardLoader::SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, BYTE* pbAttr, LPDWORD pcbAttrLen)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardGetAttrib(hCard, dwAttrId, pbAttr, pcbAttrLen);
	}
	
	LONG SCardLoader::SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, const BYTE* pbAttr, DWORD cbAttrLen)
	{
		Initialize();

		if (!bInitialized)
			throw ScardLibraryInitializationFailed();

		return scardSetAttrib(hCard, dwAttrId, pbAttr, cbAttrLen);
	}
}