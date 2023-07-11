#include "SCardManager.h"
#include "PCSCException.h"

namespace VeraCrypt
{
	shared_ptr<SCardLoader> SCardManager::loader = make_shared<SCardLoader>();

	SCardManager::SCardManager()
	{
		loader->Initialize();
	}

	SCardManager::~SCardManager()
	{
		loader->Finalize();
	}

	vector<wstring> SCardManager::GetReaders()
	{
		vector<wstring> readers;
		LPTSTR mszReaders = NULL;
		LPTSTR ptr = NULL;
		DWORD dwReaders = 0;
		SCARDCONTEXT hScardContext = 0;
		LONG lRet = SCARD_S_SUCCESS;

		hScardContext = loader->GetSCardContext();
		lRet = loader->SCardIsValidContext(hScardContext);
		if (SCARD_S_SUCCESS != lRet)
		{
			loader->SCardReleaseContext(hScardContext);
			lRet = loader->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hScardContext);
			if (lRet != SCARD_S_SUCCESS)
				throw PCSCException(lRet);
		}

#ifdef SCARD_AUTOALLOCATE
		dwReaders = SCARD_AUTOALLOCATE;
		lRet = loader->SCardListReaders(hScardContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
#else
		lRet = loader->SCardListReaders(hScardContext, NULL, NULL, &dwReaders);
		if (lRet == SCARD_S_SUCCESS)
		{
			mszReaders = (LPTSTR)calloc(dwReaders, sizeof(char));
			lRet = loader->SCardListReaders(hScardContext, NULL, mszReaders, &dwReaders);
		}
#endif

		if (lRet == SCARD_S_SUCCESS && !mszReaders)
		{
			lRet = SCARD_E_NO_READERS_AVAILABLE;
		}
		if (lRet == SCARD_E_NO_READERS_AVAILABLE)
		{
			readers.clear();
			lRet = SCARD_S_SUCCESS;
		}

		if (lRet == SCARD_S_SUCCESS && mszReaders)
		{
			ptr = mszReaders;
			while (*ptr)
			{
#ifdef TC_WINDOWS
				readers.push_back(ptr);
#else
				readers.push_back(StringConverter::ToWide(ptr));
#endif
				ptr += 
#ifdef TC_WINDOWS
				wcslen(ptr) + 1;
#else
				strlen(ptr) + 1;
#endif
			}

#ifdef SCARD_AUTOALLOCATE
			loader->SCardFreeMemory(hScardContext, mszReaders);
#else
			free(mszReaders);
#endif
		}

		if (lRet != SCARD_S_SUCCESS)
			throw PCSCException(lRet);

		return readers;
	}

	shared_ptr<SCardReader> SCardManager::GetReader(size_t readerNumber)
	{
		vector<wstring> readers;
		shared_ptr<SCardReader> smartCardReader;

		loader->Initialize();

		readers = GetReaders();
		if (readerNumber < readers.size())
		{
			smartCardReader = make_shared<SCardReader>(readers[readerNumber], loader);
			if (smartCardReader)
			{
				return smartCardReader;
			}
		}

		throw InvalidEMVPath();
	}
}