/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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

namespace VeraCrypt
{
	struct SecurityTokenInfo
	{
		CK_SLOT_ID SlotId;
		CK_FLAGS Flags;
		wstring Label;
		string LabelUtf8;
	};

	struct SecurityTokenKeyfilePath
	{
		SecurityTokenKeyfilePath () { }
		SecurityTokenKeyfilePath (const wstring &path) : Path (path) { }
		operator wstring () const { return Path; }
		wstring Path;
	};

	struct SecurityTokenKeyfile
	{
		SecurityTokenKeyfile () { }
		SecurityTokenKeyfile (const SecurityTokenKeyfilePath &path);

		operator SecurityTokenKeyfilePath () const;

		CK_OBJECT_HANDLE Handle;
		wstring Id;
		string IdUtf8;
		CK_SLOT_ID SlotId;
		SecurityTokenInfo Token;
	};

	struct Pkcs11Exception : public Exception
	{
		Pkcs11Exception (CK_RV errorCode = (CK_RV) -1)
			: ErrorCode (errorCode),
			SubjectErrorCodeValid (false)
		{
		}

		Pkcs11Exception (CK_RV errorCode, uint64 subjectErrorCode)
			: ErrorCode (errorCode),
			SubjectErrorCodeValid (true),
			SubjectErrorCode (subjectErrorCode)
		{
		}

#ifdef TC_HEADER_Platform_Exception
		virtual ~Pkcs11Exception () throw () { }
		TC_SERIALIZABLE_EXCEPTION (Pkcs11Exception);
#else
		void Show (HWND parent) const;
#endif
		operator string () const;
		CK_RV GetErrorCode () const { return ErrorCode; }

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

	struct SecurityTokenLibraryNotInitialized : public Exception
	{
		void Show (HWND parent) const { Error (SecurityTokenLibraryPath[0] == 0 ? "NO_PKCS11_MODULE_SPECIFIED" : "PKCS11_MODULE_INIT_FAILED"); }
	};
	
	struct InvalidSecurityTokenKeyfilePath : public Exception
	{
		void Show (HWND parent) const { Error ("INVALID_TOKEN_KEYFILE_PATH"); }
	};

	struct SecurityTokenKeyfileAlreadyExists : public Exception
	{
		void Show (HWND parent) const { Error ("TOKEN_KEYFILE_ALREADY_EXISTS"); }
	};

	struct SecurityTokenKeyfileNotFound : public Exception
	{
		void Show (HWND parent) const { Error ("TOKEN_KEYFILE_NOT_FOUND"); }
	};

#endif // !TC_HEADER_Platform_Exception


	struct Pkcs11Session
	{
		Pkcs11Session () : UserLoggedIn (false) { }

		CK_SESSION_HANDLE Handle;
		bool UserLoggedIn;
	};

	struct GetPinFunctor
	{
		virtual ~GetPinFunctor () { }
		virtual void operator() (string &str) = 0;
	};

	struct SendExceptionFunctor
	{
		virtual ~SendExceptionFunctor () { }
		virtual void operator() (const Exception &e) = 0;
	};

	class SecurityToken
	{
	public:
		static void CloseAllSessions () throw ();
		static void CloseLibrary ();
		static void CreateKeyfile (CK_SLOT_ID slotId, vector <byte> &keyfileData, const string &name);
		static void DeleteKeyfile (const SecurityTokenKeyfile &keyfile);
		static vector <SecurityTokenKeyfile> GetAvailableKeyfiles (CK_SLOT_ID *slotIdFilter = nullptr, const wstring keyfileIdFilter = wstring());
		static void GetKeyfileData (const SecurityTokenKeyfile &keyfile, vector <byte> &keyfileData);
		static list <SecurityTokenInfo> GetAvailableTokens ();
		static SecurityTokenInfo GetTokenInfo (CK_SLOT_ID slotId);
		static void InitLibrary (const string &pkcs11LibraryPath, auto_ptr <GetPinFunctor> pinCallback, auto_ptr <SendExceptionFunctor> warningCallback);
		static bool IsInitialized () { return Initialized; }
		static bool IsKeyfilePathValid (const wstring &securityTokenKeyfilePath);
	
		static const size_t MaxPasswordLength = 128;

	protected:
		static void CloseSession (CK_SLOT_ID slotId);
		static vector <CK_OBJECT_HANDLE> GetObjects (CK_SLOT_ID slotId, CK_ATTRIBUTE_TYPE objectClass);
		static void GetObjectAttribute (CK_SLOT_ID slotId, CK_OBJECT_HANDLE tokenObject, CK_ATTRIBUTE_TYPE attributeType, vector <byte> &attributeValue);
		static list <CK_SLOT_ID> GetTokenSlots ();
		static void Login (CK_SLOT_ID slotId, const string &pin);
		static void LoginUserIfRequired (CK_SLOT_ID slotId);
		static void OpenSession (CK_SLOT_ID slotId);
		static void CheckLibraryStatus ();

		static bool Initialized;
		static auto_ptr <GetPinFunctor> PinCallback;
		static CK_FUNCTION_LIST_PTR Pkcs11Functions;
#ifdef TC_WINDOWS
		static HMODULE Pkcs11LibraryHandle;
#else
		static void *Pkcs11LibraryHandle;
#endif
		static map <CK_SLOT_ID, Pkcs11Session> Sessions;
		static auto_ptr <SendExceptionFunctor> WarningCallback;
	};
}

#endif // TC_HEADER_Common_SecurityToken
