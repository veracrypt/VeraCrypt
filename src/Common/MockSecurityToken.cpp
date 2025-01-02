#include "MockSecurityToken.h"


using namespace std;

namespace VeraCrypt
{
#ifdef TC_WINDOWS
	void MockSecurityTokenImpl::InitLibrary (const wstring &pkcs11LibraryPath, shared_ptr <GetPinFunctor> pinCallback, shared_ptr <SendExceptionFunctor> warningCallback)
#else
	void MockSecurityTokenImpl::InitLibrary (const string &pkcs11LibraryPath, shared_ptr <GetPinFunctor> pinCallback, shared_ptr <SendExceptionFunctor> warningCallback)
#endif
	{
		if (Initialized)
			CloseLibrary();

		PinCallback = pinCallback;
		WarningCallback = warningCallback;

		Initialized = true;
	}

	vector <SecurityTokenKeyfile> MockSecurityTokenImpl::GetAvailableKeyfiles (CK_SLOT_ID *slotIdFilter, const wstring keyfileIdFilter)
	{
		return vector<SecurityTokenKeyfile>();
	}

	vector <SecurityTokenKey> MockSecurityTokenImpl::GetAvailablePrivateKeys(CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter)
	{
		return vector<SecurityTokenKey>();
	}

	vector <SecurityTokenKey> MockSecurityTokenImpl::GetAvailablePublicKeys(CK_SLOT_ID *slotIdFilterm, const wstring keyIdFilter)
	{
		return vector<SecurityTokenKey>();
	}

	void MockSecurityTokenImpl::GetSecurityTokenKey(wstring tokenKeyDescriptor, SecurityTokenKey &key, SecurityTokenKeyOperation mode)
	{
		shared_ptr<SecurityTokenKey> testKey(new SecurityTokenKey());
		testKey->maxDecryptBufferSize = 128;
		testKey->maxEncryptBufferSize = 128;
		testKey->Id = L"Mock key";
		testKey->SlotId = 1;
		testKey->Token = SecurityTokenInfo();
		testKey->Token.Label = L"Mock security token";
		key = *testKey;
	}
	void MockSecurityTokenImpl::GetDecryptedData(SecurityTokenKey key, vector<uint8> tokenDataToDecrypt, vector<uint8> &decryptedData)
	{
		decryptedData = tokenDataToDecrypt;
	}

	void MockSecurityTokenImpl::GetEncryptedData(SecurityTokenKey key, vector<uint8> plaintext, vector<uint8> &ciphertext)
	{
		ciphertext = plaintext;
	}
	list <SecurityTokenInfo> MockSecurityTokenImpl::GetAvailableTokens ()
	{
		return list<SecurityTokenInfo>();
	}
	SecurityTokenInfo MockSecurityTokenImpl::GetTokenInfo (CK_SLOT_ID slotId)
	{
		return SecurityTokenInfo();
	}
	bool MockSecurityTokenImpl::IsKeyfilePathValid (const wstring &securityTokenKeyfilePath) {
		return false;
	}
}