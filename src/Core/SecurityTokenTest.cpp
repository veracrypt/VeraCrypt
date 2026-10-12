/*
 Copyright (c) 2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

// Regression tests for the production PKCS #11 adapter. The function table below
// models provider responses; it deliberately does not implement RSA cryptography.
#include <Testing.h>
#include "Common/SecurityToken.h"
#include "Platform/SerializerFactory.h"
#include <algorithm>
#include <cstring>
#include <functional>
#include <map>

using namespace VeraCrypt;
using namespace std;

namespace
{
    template<class T> vector<uint8> Bytes(const T &value)
    {
        const uint8 *begin = reinterpret_cast<const uint8 *>(&value);
        return vector<uint8>(begin, begin + sizeof(value));
    }

    struct TestPin : GetPinFunctor
    {
        int Calls = 0;
        int Incorrect = 0;
        void operator()(string &pin) { ++Calls; pin = "1234"; }
        void notifyIncorrectPin() { ++Incorrect; }
    };

    class TestToken : public SecurityTokenImpl
    {
    public:
        typedef map<CK_ATTRIBUTE_TYPE, vector<uint8> > Attributes;
        map<CK_OBJECT_HANDLE, Attributes> Objects;
        map<CK_OBJECT_HANDLE, CK_SLOT_ID> ObjectSlots;
        map<CK_SESSION_HANDLE, CK_SLOT_ID> SessionSlots;
        map<CK_SLOT_ID, CK_RV> TokenInfoStatus;
        map<CK_SESSION_HANDLE, bool> ModuleSessions;
        CK_FUNCTION_LIST Functions;
        CK_SLOT_ID SlotCount = 1;
        string Serial = "SERIAL";
        CK_FLAGS TokenFlags = CKF_LOGIN_REQUIRED;
        CK_FLAGS MechanismFlags = CKF_ENCRYPT | CKF_DECRYPT;
        bool OaepSupported = true;
        CK_RV MechanismStatus = CKR_OK;
        CK_ATTRIBUTE_TYPE UnavailableLengthAttribute = CK_UNAVAILABLE_INFORMATION;
        CK_ATTRIBUTE_TYPE GrowingAttribute = CK_UNAVAILABLE_INFORMATION;
        CK_RV EncryptStatus = CKR_OK;
        CK_RV DecryptStatus = CKR_OK;
        CK_RV InitStatus = CKR_OK;
        CK_ULONG EncryptLength = 256;
        CK_ULONG DecryptLength = 190;
        int BadPins = 0;
        int UserLogins = 0;
        int ContextLogins = 0;
        int EncryptCalls = 0;
        int DecryptCalls = 0;
        int ClosedSessions = 0;
        bool DecryptInitialized = false;
        bool ContextAfterInit = false;
        bool ProtectedPinWasNull = false;
        bool ReuseSessionHandle = false;
        shared_ptr<TestPin> Pin;

        TestToken() : Pin(new TestPin())
        {
            Active = this;
            memset(&Functions, 0, sizeof(Functions));
            Functions.version.major = 2;
            Functions.version.minor = 40;
            Functions.C_GetSlotList = GetSlotList;
            Functions.C_GetSlotInfo = GetSlotInfo;
            Functions.C_GetTokenInfo = ProviderTokenInfo;
            Functions.C_GetMechanismInfo = ProviderMechanismInfo;
            Functions.C_OpenSession = OpenSession;
            Functions.C_CloseSession = CloseSession;
            Functions.C_GetSessionInfo = GetSessionInfo;
            Functions.C_Login = Login;
            Functions.C_FindObjectsInit = FindObjectsInit;
            Functions.C_FindObjects = FindObjects;
            Functions.C_FindObjectsFinal = FindObjectsFinal;
            Functions.C_GetAttributeValue = GetAttributeValue;
            Functions.C_CreateObject = CreateObject;
            Functions.C_DestroyObject = DestroyObject;
            Functions.C_EncryptInit = EncryptInit;
            Functions.C_Encrypt = Encrypt;
            Functions.C_DecryptInit = DecryptInit;
            Functions.C_Decrypt = Decrypt;
            Pkcs11Functions = &Functions;
            PinCallback = Pin;
            Initialized = true;
            AddKey(1, CKO_PUBLIC_KEY);
            AddKey(2, CKO_PRIVATE_KEY);
        }

        ~TestToken()
        {
            CloseAllSessions();
            Initialized = false; // The table is injected; there is no dlopen handle.
            Pkcs11Functions = NULL_PTR;
            Active = NULL_PTR;
        }

        void AddKey(CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS objectClass)
        {
            Attributes &attributes = Objects[handle];
            attributes[CKA_CLASS] = Bytes(objectClass);
            attributes[CKA_KEY_TYPE] = Bytes(CK_KEY_TYPE(CKK_RSA));
            attributes[CKA_ENCRYPT] = Bytes(CK_BBOOL(CK_TRUE));
            attributes[CKA_DECRYPT] = Bytes(CK_BBOOL(CK_TRUE));
            attributes[CKA_ALWAYS_AUTHENTICATE] = Bytes(CK_BBOOL(CK_FALSE));
            attributes[CKA_ID] = vector<uint8>(1, 0x42);
            const string label = "test:key";
            attributes[CKA_LABEL] = vector<uint8>(label.begin(), label.end());
            attributes[CKA_MODULUS] = vector<uint8>(256, 0xff);
        }

    private:
        static TestToken *Active;
        vector<CK_OBJECT_HANDLE> Search;
        size_t SearchIndex = 0;
        CK_SESSION_HANDLE NextSession = 10;

        static CK_RV GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
        {
            if (slots) {
                if (*count < Active->SlotCount) return CKR_BUFFER_TOO_SMALL;
                for (CK_SLOT_ID i = 0; i < Active->SlotCount; ++i) slots[i] = i + 1;
            }
            *count = Active->SlotCount;
            return CKR_OK;
        }
        static CK_RV GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR info)
        {
            memset(info, 0, sizeof(*info));
            info->flags = CKF_TOKEN_PRESENT;
            return CKR_OK;
        }
        static CK_RV ProviderTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
        {
            if (Active->TokenInfoStatus.count(slot)) return Active->TokenInfoStatus.at(slot);
            memset(info, 0, sizeof(*info));
            memset(info->label, ' ', sizeof(info->label));
            memcpy(info->label, "test token", 10);
            memset(info->serialNumber, ' ', sizeof(info->serialNumber));
            memcpy(info->serialNumber, Active->Serial.data(), min(Active->Serial.size(), sizeof(info->serialNumber)));
            info->flags = Active->TokenFlags;
            return CKR_OK;
        }
        static CK_RV ProviderMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
        {
            if (Active->MechanismStatus != CKR_OK) return Active->MechanismStatus;
            if (type != CKM_RSA_PKCS_OAEP || !Active->OaepSupported) return CKR_MECHANISM_INVALID;
            info->ulMinKeySize = 2048;
            info->ulMaxKeySize = 16384;
            info->flags = Active->MechanismFlags;
            return CKR_OK;
        }
        static CK_RV OpenSession(CK_SLOT_ID slot, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR handle)
        {
            *handle = Active->ReuseSessionHandle ? 10 : Active->NextSession++;
            Active->ModuleSessions[*handle] = false;
            Active->SessionSlots[*handle] = slot;
            return CKR_OK;
        }
        static CK_RV CloseSession(CK_SESSION_HANDLE handle)
        {
            ++Active->ClosedSessions;
            Active->ModuleSessions.erase(handle);
            return CKR_OK;
        }
        static CK_RV GetSessionInfo(CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info)
        {
            if (!Active->ModuleSessions.count(handle)) return CKR_SESSION_HANDLE_INVALID;
            memset(info, 0, sizeof(*info));
            info->state = Active->ModuleSessions[handle] ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
            return CKR_OK;
        }
        static CK_RV Login(CK_SESSION_HANDLE handle, CK_USER_TYPE type, CK_UTF8CHAR_PTR pin, CK_ULONG size)
        {
            if (type == CKU_CONTEXT_SPECIFIC) {
                ++Active->ContextLogins;
                Active->ContextAfterInit = Active->DecryptInitialized;
                if (!Active->DecryptInitialized) return CKR_OPERATION_NOT_INITIALIZED;
            } else {
                ++Active->UserLogins;
            }
            Active->ProtectedPinWasNull = !pin && size == 0;
            if (Active->BadPins > 0) {
                --Active->BadPins;
                return CKR_PIN_INCORRECT;
            }
            if (type == CKU_USER) Active->ModuleSessions[handle] = true;
            return CKR_OK;
        }
        static CK_RV FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
        {
            if (count != 1 || attributes[0].type != CKA_CLASS) return CKR_ARGUMENTS_BAD;
            vector<uint8> objectClass(static_cast<uint8 *>(attributes[0].pValue),
                static_cast<uint8 *>(attributes[0].pValue) + attributes[0].ulValueLen);
            Active->Search.clear();
            Active->SearchIndex = 0;
            for (const auto &object : Active->Objects)
                if (object.second.at(CKA_CLASS) == objectClass
                    && (!Active->ObjectSlots.count(object.first) || Active->ObjectSlots.at(object.first) == Active->SessionSlots.at(session)))
                    Active->Search.push_back(object.first);
            return CKR_OK;
        }
        static CK_RV FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR handles, CK_ULONG capacity, CK_ULONG_PTR count)
        {
            *count = 0;
            while (*count < capacity && Active->SearchIndex < Active->Search.size())
                handles[(*count)++] = Active->Search[Active->SearchIndex++];
            return CKR_OK;
        }
        static CK_RV FindObjectsFinal(CK_SESSION_HANDLE) { return CKR_OK; }
        static CK_RV CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR attributes, CK_ULONG count, CK_OBJECT_HANDLE_PTR handle)
        {
            *handle = Active->Objects.empty() ? 1 : Active->Objects.rbegin()->first + 1;
            Attributes &object = Active->Objects[*handle];
            for (CK_ULONG i = 0; i < count; ++i) {
                const uint8 *begin = static_cast<const uint8 *>(attributes[i].pValue);
                object[attributes[i].type] = vector<uint8>(begin, begin + attributes[i].ulValueLen);
            }
            return CKR_OK;
        }
        static CK_RV DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE handle)
        {
            Active->Objects.erase(handle);
            return CKR_OK;
        }
        static CK_RV GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
        {
            for (CK_ULONG i = 0; i < count; ++i) {
                CK_ATTRIBUTE &attribute = attributes[i];
                if (attribute.type == Active->UnavailableLengthAttribute) {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    return CKR_OK;
                }
                const Attributes &values = Active->Objects.at(handle);
                auto entry = values.find(attribute.type);
                if (entry == values.end()) return CKR_ATTRIBUTE_TYPE_INVALID;
                if (attribute.pValue) {
                    if (attribute.ulValueLen < entry->second.size()) return CKR_BUFFER_TOO_SMALL;
                    memcpy(attribute.pValue, entry->second.data(), entry->second.size());
                    if (attribute.type == Active->GrowingAttribute) {
                        attribute.ulValueLen = entry->second.size() + 1;
                        return CKR_OK;
                    }
                }
                attribute.ulValueLen = entry->second.size();
            }
            return CKR_OK;
        }
        static CK_RV CheckMechanism(CK_MECHANISM_PTR mechanism)
        {
            if (mechanism->mechanism != CKM_RSA_PKCS_OAEP || mechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_INVALID;
            const CK_RSA_PKCS_OAEP_PARAMS &params = *static_cast<CK_RSA_PKCS_OAEP_PARAMS *>(mechanism->pParameter);
            if (params.hashAlg != CKM_SHA256 || params.mgf != CKG_MGF1_SHA256 || params.source != CKZ_DATA_SPECIFIED
                || params.pSourceData || params.ulSourceDataLen)
                return CKR_MECHANISM_PARAM_INVALID;
            return Active->InitStatus;
        }
        static CK_RV EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE)
        {
            return CheckMechanism(mechanism);
        }
        static CK_RV DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE)
        {
            CK_RV status = CheckMechanism(mechanism);
            Active->DecryptInitialized = status == CKR_OK;
            return status;
        }
        static CK_RV Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR output, CK_ULONG_PTR size)
        {
            ++Active->EncryptCalls;
            if (!output) return CKR_ARGUMENTS_BAD; // No extra touch-consuming size query.
            memset(output, 0xa5, min(*size, Active->EncryptLength));
            *size = Active->EncryptLength;
            return Active->EncryptStatus;
        }
        static CK_RV Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR output, CK_ULONG_PTR size)
        {
            ++Active->DecryptCalls;
            if (!output) return CKR_ARGUMENTS_BAD;
            memset(output, 0x5a, min(*size, Active->DecryptLength));
            *size = Active->DecryptLength;
            return Active->DecryptStatus;
        }
    };
    TestToken *TestToken::Active = NULL_PTR;

    struct Fixture
    {
        shared_ptr<TestToken> Token;
        Fixture() : Token(new TestToken()) { SecurityToken::UseImpl(Token); }
        ~Fixture() { SecurityToken::UseImpl(shared_ptr<SecurityTokenIface>()); }
        SecurityTokenScheme Key(SecurityTokenKeyOperation operation)
        {
            vector<SecurityTokenScheme> keys = operation == SecurityTokenKeyOperation::Encrypt ? SecurityToken::GetAvailablePublicKeys() : SecurityToken::GetAvailablePrivateKeys();
            if (keys.size() != 1) throw runtime_error("Expected one test key");
            return keys.front();
        }
    };

    void Require(shared_ptr<TestResult> result, bool condition, const string &message)
    {
        if (!condition) result->Failed(message);
    }

    void ExpectPkcs11(shared_ptr<TestResult> result, CK_RV expected, const function<void()> &operation)
    {
        try { operation(); }
        catch (const Pkcs11Exception &error) {
            Require(result, error.GetErrorCode() == expected, "Unexpected PKCS #11 error code");
            return;
        }
        result->Failed("Expected PKCS #11 error");
    }

    template<class Expected> void ExpectException(shared_ptr<TestResult> result, const function<void()> &operation)
    {
        try { operation(); }
        catch (const Expected &) { return; }
        result->Failed("Expected typed exception");
    }

    void SlotResolution(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt), selected;
        Require(result, key.GetSpec(true) == L"slot-key:1:42:RSA PKCS#1 OAEP", "Explicit slot fallback is missing");
        fixture.Token->SlotCount = 2;
        fixture.Token->TokenInfoStatus[1] = CKR_TOKEN_NOT_RECOGNIZED;
        SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt);
        Require(result, selected.SlotId == 2, "An unrelated unsupported reader hid the selected key");
        fixture.Token->TokenInfoStatus.clear();
        fixture.Token->ObjectSlots[2] = 2;
        SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt);
        Require(result, selected.SlotId == 2, "Lookup stopped before the slot containing the key");
        fixture.Token->ObjectSlots.clear();
        ExpectException<SecurityTokenKeyAmbiguous>(result, [&] {
            SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt);
        });
        SecurityToken::GetSecurityTokenScheme(key.GetSpec(true), selected, SecurityTokenKeyOperation::Decrypt);
        Require(result, selected.SlotId == 1, "Explicit slot did not disambiguate mirrored keys");
        ExpectException<SecurityTokenKeyNotFound>(result, [&] {
            SecurityToken::GetSecurityTokenScheme(L"slot-key:1:43:RSA PKCS#1 OAEP", selected, SecurityTokenKeyOperation::Decrypt);
        });
    }

    void PublicModulusFallback(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->Objects[2].erase(CKA_MODULUS);
        fixture.Token->MechanismFlags = CKF_DECRYPT;
        fixture.Token->Objects[1][CKA_ENCRYPT] = Bytes(CK_BBOOL(CK_FALSE));
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        Require(result, key.RsaKeyBits == 2048 && key.EncryptOutputSize == 256, "Public RSA modulus fallback failed");
        fixture.Token->AddKey(3, CKO_PUBLIC_KEY);
        Require(result, SecurityToken::GetAvailablePrivateKeys().empty(), "Ambiguous public-key pairing was accepted");
    }

    void LegacyLargeDataKeyfile(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        vector<uint8> original(1024 * 1024 + 257);
        for (size_t i = 0; i < original.size(); ++i) original[i] = static_cast<uint8>(i * 29 + 7);
        SecurityToken::CreateKeyfile(1, original, "large data keyfile");
        vector<SecurityTokenKeyfile> keyfiles = SecurityToken::GetAvailableKeyfiles();
        Require(result, keyfiles.size() == 1 && keyfiles.front().Id == L"large data keyfile",
            "Legacy token-stored data keyfile could not be imported or listed");
        vector<uint8> exported;
        keyfiles.front().GetKeyfileData(exported);
        Require(result, exported == original, "Legacy token keyfile exceeding one MiB was rejected or truncated");
        SecurityToken::DeleteKeyfile(keyfiles.front());
        Require(result, SecurityToken::GetAvailableKeyfiles().empty(), "Legacy data keyfile deletion failed");
    }

    void DiscoverMixedKeys(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        TestToken &token = *fixture.Token;
        token.AddKey(3, CKO_PUBLIC_KEY);
        token.Objects[3][CKA_KEY_TYPE] = Bytes(CK_KEY_TYPE(CKK_EC));
        token.AddKey(4, CKO_PUBLIC_KEY);
        token.Objects[4].erase(CKA_ENCRYPT);
        token.AddKey(5, CKO_PUBLIC_KEY);
        token.Objects[5][CKA_KEY_TYPE] = vector<uint8>(1, 0);
        token.AddKey(6, CKO_PUBLIC_KEY);
        token.Objects[6][CKA_MODULUS] = vector<uint8>(128, 0xff);
        token.AddKey(7, CKO_PUBLIC_KEY);
        token.Objects[7].erase(CKA_MODULUS);
        token.AddKey(8, CKO_PUBLIC_KEY);
        token.Objects[8][CKA_ENCRYPT] = Bytes(CK_BBOOL(CK_FALSE));
        token.AddKey(9, CKO_PUBLIC_KEY);
        token.Objects[9][CKA_ENCRYPT].clear();
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Encrypt);
        Require(result, key.Handle == 1 && key.EncryptOutputSize == 256 && key.DecryptOutputSize == 190,
            "Mixed unsupported keys hid or changed the usable RSA OAEP key");
        token.Objects[2].erase(CKA_ALWAYS_AUTHENTICATE);
        SecurityTokenScheme privateKey = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        vector<uint8> plaintext;
        SecurityToken::GetDecryptedData(privateKey, vector<uint8>(256), plaintext);
        Require(result, plaintext.size() == 190, "Optional ALWAYS_AUTHENTICATE attribute was required");
    }

    void UnavailableMechanisms(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->OaepSupported = false;
        Require(result, SecurityToken::GetAvailablePublicKeys().empty(), "Unsupported OAEP advertised a key");
        fixture.Token->OaepSupported = true;
        fixture.Token->MechanismFlags = CKF_SIGN;
        Require(result, SecurityToken::GetAvailablePrivateKeys().empty(), "Signing-only mechanism advertised a decrypt key");
        fixture.Token->MechanismStatus = CKR_DEVICE_ERROR;
        ExpectPkcs11(result, CKR_DEVICE_ERROR, [] { SecurityToken::GetAvailablePublicKeys(); });
    }

    void AttributeLengths(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->UnavailableLengthAttribute = CKA_ID;
        ExpectPkcs11(result, CKR_ATTRIBUTE_VALUE_INVALID, [] { SecurityToken::GetAvailablePublicKeys(); });
        fixture.Token->UnavailableLengthAttribute = CK_UNAVAILABLE_INFORMATION;
        fixture.Token->GrowingAttribute = CKA_ID;
        ExpectPkcs11(result, CKR_ATTRIBUTE_VALUE_INVALID, [] { SecurityToken::GetAvailablePublicKeys(); });
    }

    void Descriptors(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Encrypt), selected;
        Require(result, key.GetSpec() == L"token-key:53455249414c:42:RSA PKCS#1 OAEP", "Serial/ID descriptor changed");
        SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt);
        Require(result, selected.Handle == 2, "Public descriptor did not select paired private key");
        SecurityToken::GetSecurityTokenScheme(L"1:test:key:RSA PKCS#1 OAEP", selected, SecurityTokenKeyOperation::Decrypt);
        Require(result, selected.Handle == 2, "Legacy label containing a colon did not resolve");
        fixture.Token->AddKey(3, CKO_PRIVATE_KEY);
        ExpectException<SecurityTokenKeyAmbiguous>(result, [&] { SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt); });
        fixture.Token->Objects.erase(3);
        fixture.Token->SlotCount = 2;
        ExpectException<SecurityTokenKeyAmbiguous>(result, [&] { SecurityToken::GetSecurityTokenScheme(key.GetSpec(), selected, SecurityTokenKeyOperation::Decrypt); });
        fixture.Token->SlotCount = 1;
        fixture.Token->Serial.clear();
        key = fixture.Key(SecurityTokenKeyOperation::Encrypt);
        Require(result, key.GetSpec() == L"slot-key:1:42:RSA PKCS#1 OAEP", "Empty serial did not use explicit slot identity");
        const wchar_t *invalid[] = { L"slot-key:-1:42:RSA PKCS#1 OAEP", L"slot-key:1:4x:RSA PKCS#1 OAEP", L"slot-key:1:4:RSA PKCS#1 OAEP" };
        for (const wchar_t *descriptor : invalid) {
            bool rejected = false;
            try { SecurityToken::GetSecurityTokenScheme(descriptor, selected, SecurityTokenKeyOperation::Decrypt); }
            catch (const InvalidSecurityTokenKeyDescriptor &) { rejected = true; }
            Require(result, rejected, "Malformed descriptor accepted");
        }
    }

    void PinAndContextAuthentication(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->BadPins = 1;
        fixture.Token->Objects[2][CKA_ALWAYS_AUTHENTICATE] = Bytes(CK_BBOOL(CK_TRUE));
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        Require(result, fixture.Token->Pin->Calls == 2 && fixture.Token->Pin->Incorrect == 1, "Incorrect user PIN was not retried and reported");
        vector<uint8> output;
        SecurityToken::GetDecryptedData(key, vector<uint8>(256), output);
        Require(result, fixture.Token->ContextLogins == 1 && fixture.Token->ContextAfterInit && fixture.Token->Pin->Calls == 3,
            "ALWAYS_AUTHENTICATE did not request a context PIN after decrypt initialization");
        Require(result, fixture.Token->DecryptCalls == 1 && output == vector<uint8>(190, 0x5a), "Decrypt output or call count changed");
    }

    void ProtectedAuthentication(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->TokenFlags |= CKF_PROTECTED_AUTHENTICATION_PATH;
        fixture.Token->Objects[2][CKA_ALWAYS_AUTHENTICATE] = Bytes(CK_BBOOL(CK_TRUE));
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        vector<uint8> output;
        SecurityToken::GetDecryptedData(key, vector<uint8>(256), output);
        Require(result, fixture.Token->Pin->Calls == 0 && fixture.Token->ProtectedPinWasNull && fixture.Token->ContextAfterInit,
            "Protected authentication path incorrectly requested a software PIN");
    }

    void EncryptOutputChecks(shared_ptr<TestResult> result)
    {
        const CK_ULONG lengths[] = { 0, 255, 256, 257 };
        for (CK_ULONG length : lengths) {
            Fixture fixture;
            fixture.Token->EncryptLength = length;
            SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Encrypt);
            vector<uint8> output;
            if (length == 256) {
                SecurityToken::GetEncryptedData(key, vector<uint8>(190, 0x5a), output);
                Require(result, output == vector<uint8>(256, 0xa5) && fixture.Token->EncryptCalls == 1, "Encryption output or call count changed");
            } else {
                ExpectPkcs11(result, CKR_DATA_LEN_RANGE, [&] { SecurityToken::GetEncryptedData(key, vector<uint8>(190), output); });
                Require(result, output.empty() && fixture.Token->ClosedSessions == 1, "Invalid encryption output remained usable");
            }
        }
    }

    void DecryptOutputChecks(shared_ptr<TestResult> result)
    {
        const CK_ULONG lengths[] = { 0, 1, 190, 191, 257 };
        for (CK_ULONG length : lengths) {
            Fixture fixture;
            fixture.Token->DecryptLength = length;
            SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
            vector<uint8> output(20, 0x33);
            if (length == 1 || length == 190) {
                SecurityToken::GetDecryptedData(key, vector<uint8>(256), output);
                Require(result, output == vector<uint8>(length, 0x5a), "Valid decryption output changed");
            } else {
                ExpectPkcs11(result, CKR_ENCRYPTED_DATA_LEN_RANGE, [&] { SecurityToken::GetDecryptedData(key, vector<uint8>(256), output); });
                Require(result, output.empty() && fixture.Token->ClosedSessions == 1, "Invalid plaintext remained usable");
            }
        }
    }

    void OperationFailureAndStaleSession(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        fixture.Token->DecryptStatus = CKR_ENCRYPTED_DATA_INVALID;
        vector<uint8> output(20, 0x33);
        ExpectPkcs11(result, CKR_ENCRYPTED_DATA_INVALID, [&] { SecurityToken::GetDecryptedData(key, vector<uint8>(256), output); });
        Require(result, output.empty() && fixture.Token->ClosedSessions == 1, "Failed decrypt did not clear output and session");
        ExpectPkcs11(result, CKR_KEY_CHANGED, [&] { SecurityToken::GetDecryptedData(key, vector<uint8>(256), output); });
        Require(result, fixture.Token->DecryptCalls == 1, "Stale key reached the provider after session replacement");
    }

    void ReusedSessionHandle(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        fixture.Token->ReuseSessionHandle = true;
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        SecurityToken::CloseAllSessions();
        vector<uint8> output;
        ExpectPkcs11(result, CKR_KEY_CHANGED, [&] { SecurityToken::GetDecryptedData(key, vector<uint8>(256), output); });
        Require(result, fixture.Token->DecryptCalls == 0, "Reused numeric session handle accepted a stale key");
    }

    void InvalidContextAuthenticationAttribute(shared_ptr<TestResult> result)
    {
        const vector<uint8> invalid[] = { vector<uint8>(), vector<uint8>(2, 0), Bytes(CK_BBOOL(2)) };
        for (const vector<uint8> &attribute : invalid) {
            Fixture fixture;
            fixture.Token->Objects[2][CKA_ALWAYS_AUTHENTICATE] = attribute;
            SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Decrypt);
            vector<uint8> output;
            ExpectPkcs11(result, CKR_ATTRIBUTE_VALUE_INVALID, [&] { SecurityToken::GetDecryptedData(key, vector<uint8>(256), output); });
            Require(result, fixture.Token->DecryptCalls == 0, "Malformed authentication attribute reached decryption");
        }
    }

    void InvalidOperationInputs(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecurityTokenScheme encryptKey = fixture.Key(SecurityTokenKeyOperation::Encrypt), decryptKey = fixture.Key(SecurityTokenKeyOperation::Decrypt);
        vector<uint8> output;
        ExpectPkcs11(result, CKR_DATA_LEN_RANGE, [&] { SecurityToken::GetEncryptedData(encryptKey, vector<uint8>(), output); });
        ExpectPkcs11(result, CKR_DATA_LEN_RANGE, [&] { SecurityToken::GetEncryptedData(encryptKey, vector<uint8>(191), output); });
        ExpectPkcs11(result, CKR_DATA_LEN_RANGE, [&] { SecurityToken::GetEncryptedData(decryptKey, vector<uint8>(190), output); });
        ExpectPkcs11(result, CKR_ENCRYPTED_DATA_LEN_RANGE, [&] { SecurityToken::GetDecryptedData(decryptKey, vector<uint8>(255), output); });
        ExpectPkcs11(result, CKR_ENCRYPTED_DATA_LEN_RANGE, [&] { SecurityToken::GetDecryptedData(decryptKey, vector<uint8>(257), output); });
        Require(result, fixture.Token->EncryptCalls == 0 && fixture.Token->DecryptCalls == 0,
            "Invalid input reached provider cryptographic operations");
    }

    void RejectedOaepParameters(shared_ptr<TestResult> result)
    {
        Fixture fixture;
        SecurityTokenScheme key = fixture.Key(SecurityTokenKeyOperation::Encrypt);
        fixture.Token->InitStatus = CKR_MECHANISM_PARAM_INVALID;
        vector<uint8> output;
        ExpectPkcs11(result, CKR_MECHANISM_PARAM_INVALID, [&] { SecurityToken::GetEncryptedData(key, vector<uint8>(190), output); });
        Require(result, fixture.Token->EncryptCalls == 0 && fixture.Token->ClosedSessions == 1,
            "Rejected OAEP parameters did not stop the operation");
    }
}

int main()
{
    SerializerFactory::Initialize();
    Testing tests;
    tests.AddTest("resolve key identity across token slots", SlotResolution);
    tests.AddTest("private-key modulus from unique public key", PublicModulusFallback);
    tests.AddTest("legacy data keyfiles larger than one MiB", LegacyLargeDataKeyfile);
    tests.AddTest("mixed RSA, EC, malformed and unavailable key attributes", DiscoverMixedKeys);
    tests.AddTest("unsupported OAEP and operation flags", UnavailableMechanisms);
    tests.AddTest("unavailable and inconsistent attribute lengths", AttributeLengths);
    tests.AddTest("stable descriptors, malformed selectors and ambiguity", Descriptors);
    tests.AddTest("PIN retry and context authentication ordering", PinAndContextAuthentication);
    tests.AddTest("protected authentication path", ProtectedAuthentication);
    tests.AddTest("RSA encryption output bounds", EncryptOutputChecks);
    tests.AddTest("RSA decryption output bounds", DecryptOutputChecks);
    tests.AddTest("operation cleanup and stale sessions", OperationFailureAndStaleSession);
    tests.AddTest("provider rejection of OAEP parameters", RejectedOaepParameters);
    tests.AddTest("stale keys after numeric session handle reuse", ReusedSessionHandle);
    tests.AddTest("malformed context authentication attributes", InvalidContextAuthenticationAttribute);
    tests.AddTest("invalid operation inputs", InvalidOperationInputs);
    int status = tests.Main();
    SerializerFactory::Deinitialize();
    return status;
}
