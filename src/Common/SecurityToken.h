/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Common_SecurityToken
#define TC_HEADER_Common_SecurityToken

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

#ifndef NULL_PTR
#	define NULL_PTR 0
#endif
#define CK_PTR *
#define CK_CALLBACK_FUNCTION(RET_TYPE, NAME) RET_TYPE (* NAME)

#ifdef TC_WINDOWS

#	include <windows.h>

#	define CK_DEFINE_FUNCTION(RET_TYPE, NAME) RET_TYPE __declspec(dllexport) NAME
#	define CK_DECLARE_FUNCTION(RET_TYPE, NAME) RET_TYPE __declspec(dllimport) NAME
#	define CK_DECLARE_FUNCTION_POINTER(RET_TYPE, NAME) RET_TYPE __declspec(dllimport) (* NAME)

#	pragma pack(push, cryptoki, 1)
#	include <pkcs11.h>
#	pragma pack(pop, cryptoki)

#else // !TC_WINDOWS

#	define CK_DEFINE_FUNCTION(RET_TYPE, NAME) RET_TYPE NAME
#	define CK_DECLARE_FUNCTION(RET_TYPE, NAME) RET_TYPE NAME
#	define CK_DECLARE_FUNCTION_POINTER(RET_TYPE, NAME) RET_TYPE (* NAME)

#	include <pkcs11.h>

#endif // !TC_WINDOWS


#define TC_SECURITY_TOKEN_KEYFILE_URL_PREFIX L"token://"
#define TC_SECURITY_TOKEN_KEYFILE_URL_SLOT L"slot"
#define TC_SECURITY_TOKEN_KEYFILE_URL_FILE L"file"

#include "Token.h"

namespace VeraCrypt
{
	struct SecurityTokenInfo: TokenInfo
	{
		virtual ~SecurityTokenInfo() {};
		virtual BOOL isEditable() const {return true;}

		CK_FLAGS Flags;
		string LabelUtf8;
	};

	struct SecurityTokenKeyfile: TokenKeyfile
	{
		SecurityTokenKeyfile();

		SecurityTokenKeyfile(const TokenKeyfilePath& path);

		virtual ~SecurityTokenKeyfile() {}

		operator TokenKeyfilePath () const;

		void GetKeyfileData(vector<uint8>& keyfileData) const;

		string IdUtf8;
		CK_OBJECT_HANDLE Handle;
	};

	struct Pkcs11Exception: public Exception
	{
		Pkcs11Exception(CK_RV errorCode = (CK_RV)-1)
			: ErrorCode(errorCode),
			SubjectErrorCodeValid(false),
			SubjectErrorCode((uint64)-1)
		{
		}

		Pkcs11Exception(CK_RV errorCode, uint64 subjectErrorCode)
			: ErrorCode(errorCode),
			SubjectErrorCodeValid(true),
			SubjectErrorCode(subjectErrorCode)
		{
		}

#ifdef TC_HEADER_Platform_Exception
		virtual ~Pkcs11Exception() throw () { }
		TC_SERIALIZABLE_EXCEPTION(Pkcs11Exception);
#else
		void Show(HWND parent) const;
#endif
		operator string () const;
		CK_RV GetErrorCode() const { return ErrorCode; }

	protected:
		CK_RV ErrorCode;
		bool SubjectErrorCodeValid;
		uint64 SubjectErrorCode;
	};


#ifdef TC_HEADER_Platform_Exception

#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,Exception)

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (Pkcs11Exception); \
	TC_EXCEPTION (InvalidSecurityTokenKeyfilePath); \
	TC_EXCEPTION (SecurityTokenLibraryNotInitialized); \
	TC_EXCEPTION (SecurityTokenKeyfileAlreadyExists); \
	TC_EXCEPTION (SecurityTokenKeyfileNotFound);

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION

#else // !TC_HEADER_Platform_Exception

	struct SecurityTokenLibraryNotInitialized: public Exception
	{
		void Show(HWND parent) const { Error(SecurityTokenLibraryPath[0] == 0 ? "NO_PKCS11_MODULE_SPECIFIED" : "PKCS11_MODULE_INIT_FAILED", parent); }
	};

	struct InvalidSecurityTokenKeyfilePath: public Exception
	{
		void Show(HWND parent) const { Error("INVALID_TOKEN_KEYFILE_PATH", parent); }
	};

	struct SecurityTokenKeyfileAlreadyExists: public Exception
	{
		void Show(HWND parent) const { Error("TOKEN_KEYFILE_ALREADY_EXISTS", parent); }
	};

	struct SecurityTokenKeyfileNotFound: public Exception
	{
		void Show(HWND parent) const { Error("TOKEN_KEYFILE_NOT_FOUND", parent); }
	};

#endif // !TC_HEADER_Platform_Exception


	struct Pkcs11Session
	{
		Pkcs11Session(): Handle(CK_UNAVAILABLE_INFORMATION), UserLoggedIn(false) { }

		CK_SESSION_HANDLE Handle;
		bool UserLoggedIn;
	};

	struct GetPinFunctor
	{
		virtual ~GetPinFunctor() { }
		virtual void operator() (string& str) = 0;
		virtual void notifyIncorrectPin() = 0;
	};

	struct SendExceptionFunctor
	{
		virtual ~SendExceptionFunctor() { }
		virtual void operator() (const Exception& e) = 0;
	};

	class SecurityToken
	{
	public:
		static void CloseAllSessions() throw ();
		static void CloseLibrary();
		static void CreateKeyfile(CK_SLOT_ID slotId, vector <uint8>& keyfileData, const string& name);
		static void DeleteKeyfile(const SecurityTokenKeyfile& keyfile);
		static vector <SecurityTokenKeyfile> GetAvailableKeyfiles(CK_SLOT_ID* slotIdFilter = nullptr, const wstring keyfileIdFilter = wstring());
		static list <SecurityTokenInfo> GetAvailableTokens();
		static SecurityTokenInfo GetTokenInfo(CK_SLOT_ID slotId);
#ifdef TC_WINDOWS
		static void InitLibrary(const wstring& pkcs11LibraryPath, unique_ptr <GetPinFunctor> pinCallback, unique_ptr <SendExceptionFunctor> warningCallback);
#else
		static void InitLibrary(const string& pkcs11LibraryPath, unique_ptr <GetPinFunctor> pinCallback, unique_ptr <SendExceptionFunctor> warningCallback);
#endif
		static bool IsInitialized() { return Initialized; }
		static bool IsKeyfilePathValid(const wstring& securityTokenKeyfilePath);

		static const size_t MaxPasswordLength = 128;

	protected:
		static void CloseSession(CK_SLOT_ID slotId);
		static vector <CK_OBJECT_HANDLE> GetObjects(CK_SLOT_ID slotId, CK_ATTRIBUTE_TYPE objectClass);
		static void GetObjectAttribute(CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_ATTRIBUTE_TYPE attributeType, vector <uint8>& attributeValue);
		static list <CK_SLOT_ID> GetTokenSlots();
		static void Login(CK_SLOT_ID slotId, const char* pin);
		static void LoginUserIfRequired(CK_SLOT_ID slotId);
		static void OpenSession(CK_SLOT_ID slotId);
		static void CheckLibraryStatus();

		static bool Initialized;
		static unique_ptr <GetPinFunctor> PinCallback;
		static CK_FUNCTION_LIST_PTR Pkcs11Functions;
#ifdef TC_WINDOWS
		static HMODULE Pkcs11LibraryHandle;
#else
		static void* Pkcs11LibraryHandle;
#endif
		static map <CK_SLOT_ID, Pkcs11Session> Sessions;
		static unique_ptr <SendExceptionFunctor> WarningCallback;

		friend void SecurityTokenKeyfile::GetKeyfileData(vector <uint8>& keyfileData) const;
	};
}

#endif // TC_HEADER_Common_SecurityToken
