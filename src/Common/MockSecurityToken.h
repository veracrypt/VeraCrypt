#ifndef TC_HEADER_Common_MockSecurityToken
#define TC_HEADER_Common_MockSecurityToken

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

#include "SecurityToken.h"
namespace VeraCrypt
{

    class MockSecurityTokenImpl : public SecurityTokenIface {
            public:
                MockSecurityTokenImpl() : Initialized(false) {} ;
                virtual ~MockSecurityTokenImpl() {};
                void CloseAllSessions () throw () {};
                void CloseLibrary () {};
                void CreateKeyfile (CK_SLOT_ID slotId, vector <uint8> &keyfileData, const string &name) {};
                void DeleteKeyfile (const SecurityTokenKeyfile &keyfile) {};
                vector <SecurityTokenKeyfile> GetAvailableKeyfiles (CK_SLOT_ID *slotIdFilter = nullptr, const wstring keyfileIdFilter = wstring());

                vector <SecurityTokenKey> GetAvailablePrivateKeys(CK_SLOT_ID *slotIdFilterm = nullptr, const wstring keyIdFilter = wstring());
                vector <SecurityTokenKey> GetAvailablePublicKeys(CK_SLOT_ID *slotIdFilterm = nullptr, const wstring keyIdFilter = wstring());
                void GetSecurityTokenKey(wstring tokenKeyDescriptor, SecurityTokenKey &key, SecurityTokenKeyOperation mode);
                void GetDecryptedData(SecurityTokenKey key, vector<uint8> tokenDataToDecrypt, vector<uint8> &decryptedData);
                void GetEncryptedData(SecurityTokenKey key, vector<uint8> plaintext, vector<uint8> &ciphertext);


                void GetKeyfileData (const SecurityTokenKeyfile &keyfile, vector <uint8> &keyfileData) {};
                list <SecurityTokenInfo> GetAvailableTokens ();
                SecurityTokenInfo GetTokenInfo (CK_SLOT_ID slotId);
    #ifdef TC_WINDOWS
                void InitLibrary (const wstring &pkcs11LibraryPath, unique_ptr <GetPinFunctor> pinCallback, unique_ptr <SendExceptionFunctor> warningCallback) {};
    #else
                virtual void InitLibrary (const string &pkcs11LibraryPath, shared_ptr <GetPinFunctor> pinCallback, shared_ptr <SendExceptionFunctor> warningCallback);
    #endif
                bool IsInitialized () { return Initialized; }
                bool IsKeyfilePathValid (const wstring &securityTokenKeyfilePath);

        protected:
                bool Initialized;
                shared_ptr <GetPinFunctor> PinCallback;
                shared_ptr <SendExceptionFunctor> WarningCallback;
        };
}
#endif // TC_HEADER_Common_MockSecurityToken