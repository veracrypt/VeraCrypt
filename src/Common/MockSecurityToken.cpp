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

	vector<uint8> MockSecurityTokenImpl::LatestPlaintext;

	vector <SecurityTokenKeyfile> MockSecurityTokenImpl::GetAvailableKeyfiles (CK_SLOT_ID *slotIdFilter, const wstring keyfileIdFilter)
	{
		return vector<SecurityTokenKeyfile>();
	}

	vector <SecurityTokenScheme> MockSecurityTokenImpl::GetAvailablePrivateKeys(CK_SLOT_ID *slotIdFilter, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		return vector<SecurityTokenScheme>();
	}

	vector <SecurityTokenScheme> MockSecurityTokenImpl::GetAvailablePublicKeys(CK_SLOT_ID *slotIdFilterm, const wstring keyIdFilter, const wstring mechanismLabel)
	{
		return vector<SecurityTokenScheme>();
	}

	void MockSecurityTokenImpl::GetSecurityTokenScheme(wstring tokenKeyDescriptor, SecurityTokenScheme &key, SecurityTokenKeyOperation mode)
	{
		shared_ptr<SecurityTokenScheme> testKey(new SecurityTokenScheme());
		testKey->DecryptOutputSize = GetPlaintextSize();
		testKey->EncryptOutputSize = GetCiphertextSize();
		testKey->Id = L"Mock key";
		testKey->SlotId = 1;
		testKey->Token = SecurityTokenInfo();
		testKey->Token.Label = L"Mock security token";
		testKey->MechanismLabel = RSAOAEPSecurityTokenMechanism::GetLabel();
		key = *testKey;
	}
	void MockSecurityTokenImpl::GetDecryptedData(SecurityTokenScheme key, vector<uint8> ciphertext, vector<uint8> &plaintext)
	{
		if (ciphertext.size() != GetCiphertextSize()) {
			throw Pkcs11Exception(CKR_FUNCTION_FAILED);
		}
		plaintext = LatestPlaintext;
	}

	void MockSecurityTokenImpl::GetEncryptedData(SecurityTokenScheme key, vector<uint8> plaintext, vector<uint8> &ciphertext)
	{
		if (plaintext.size() != GetPlaintextSize()) {
			throw Pkcs11Exception(CKR_FUNCTION_FAILED);
		}
		LatestPlaintext = plaintext;
		if (plaintext.size() > GetCiphertextSize()) {
			ciphertext = vector<uint8> (plaintext.data(), plaintext.data() + GetCiphertextSize());	
		} else if (plaintext.size() < GetCiphertextSize()) {
			ciphertext = vector<uint8> (GetCiphertextSize(), 0);
			std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());
		} else {
			ciphertext = plaintext;
		}
	}
	list <SecurityTokenInfo> MockSecurityTokenImpl::GetAvailableTokens ()
	{
		return list<SecurityTokenInfo>();
	}
	SecurityTokenInfo MockSecurityTokenImpl::GetTokenInfo (CK_SLOT_ID slotId)
	{
		return SecurityTokenInfo();
	}
	bool MockSecurityTokenImpl::IsKeyfilePathValid (const wstring &SecurityTokenSchemefilePath) {
		return false;
	}

	void MockSecurityTokenImpl::GetObjectAttribute(SecurityTokenScheme &key, CK_ATTRIBUTE_TYPE attributeType, vector<uint8> &attributeValue)
	{
		switch (attributeType)
		{
		case CKA_PRIVATE:
			attributeValue = vector<uint8>(1, CK_TRUE);
			break;
		case CKA_DECRYPT:
			attributeValue = vector<uint8>(1, CK_TRUE);
			break;
		case CKA_ENCRYPT:
			attributeValue = vector<uint8>(1, CK_TRUE);
			break;
		case CKA_KEY_TYPE:
			attributeValue = vector<uint8>(1, CKK_RSA);
			break;
		case CKA_MODULUS_BITS:
			attributeValue = vector<uint8>(1, (uint8)2048);
			break;
		default:
			throw Pkcs11Exception(CKR_ATTRIBUTE_TYPE_INVALID);
		}
	}

	bool MockSecurityTokenImpl::GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
	{
		CK_MECHANISM_INFO mi;
		mi.flags = CKF_DECRYPT;
		mi.ulMaxKeySize = 1024;
		mi.ulMaxKeySize = 2048;
		*info = mi;
		return true;
	}
}