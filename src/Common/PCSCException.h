#ifndef TC_HEADER_Common_PCSCException
#define TC_HEADER_Common_PCSCException

#include "Platform/PlatformBase.h"
#if defined (TC_WINDOWS) && !defined (TC_PROTOTYPE)
#	include "Exception.h"
#else
#	include "Platform/Exception.h"
#endif

#include "SCardLoader.h"

#ifdef TC_MACOSX
#define LONG_PCSC uint32_t
#else
#define LONG_PCSC LONG
#endif

namespace VeraCrypt
{
	struct PCSCException: public Exception
	{
		PCSCException(LONG_PCSC errorCode = (LONG_PCSC)-1): ErrorCode(errorCode){}

#ifdef TC_HEADER_Platform_Exception
		virtual ~PCSCException() throw () { }
		TC_SERIALIZABLE_EXCEPTION(PCSCException);
#else
		void Show(HWND parent) const;
#endif

		operator string () const;
		LONG_PCSC GetErrorCode() const { return ErrorCode; }

	protected:
		LONG_PCSC ErrorCode;
	};

	struct CommandAPDUNotValid: public Exception
	{
		CommandAPDUNotValid() : SrcPos (""), ErrorStr ("") { }
		CommandAPDUNotValid(const string& srcPos, const string& errorStr) : SrcPos (srcPos), ErrorStr(errorStr) { }

#ifdef TC_HEADER_Platform_Exception
		virtual ~CommandAPDUNotValid() throw () { }
		TC_SERIALIZABLE_EXCEPTION(CommandAPDUNotValid);
#else
		void Show(HWND parent) const;
#endif

		operator string () const;

	protected:
		string SrcPos;
		string ErrorStr;
	};

#ifdef TC_HEADER_Platform_Exception

	#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,Exception)

	#undef TC_EXCEPTION_SET
	#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (PCSCException); \
	TC_EXCEPTION_NODECL (CommandAPDUNotValid); \
	TC_EXCEPTION (ExtendedAPDUNotSupported); \
	TC_EXCEPTION (ScardLibraryInitializationFailed); \
	TC_EXCEPTION (EMVUnknownCardType); \
	TC_EXCEPTION (EMVSelectAIDFailed); \
	TC_EXCEPTION (EMVIccCertNotFound); \
	TC_EXCEPTION (EMVIssuerCertNotFound); \
	TC_EXCEPTION (EMVCPLCNotFound); \
	TC_EXCEPTION (InvalidEMVPath); \
	TC_EXCEPTION (EMVKeyfileDataNotFound); \
	TC_EXCEPTION (EMVPANNotFound); \
	
	TC_EXCEPTION_SET;

	#undef TC_EXCEPTION

#else // !TC_HEADER_Platform_Exception	

	struct ExtendedAPDUNotSupported: public Exception
	{
		void Show(HWND parent) const { Error("EXTENDED_APDU_UNSUPPORTED", parent); }
	};

	struct ScardLibraryInitializationFailed: public Exception
	{
		void Show(HWND parent) const { Error("SCARD_MODULE_INIT_FAILED", parent); }
	};

	struct EMVUnknownCardType: public Exception
	{
		void Show(HWND parent) const { Error("EMV_UNKNOWN_CARD_TYPE", parent); }
	};

	struct EMVSelectAIDFailed: public Exception
	{
		void Show(HWND parent) const { Error("EMV_SELECT_AID_FAILED", parent); }
	};

	struct EMVIccCertNotFound: public Exception
	{
		void Show(HWND parent) const { Error("EMV_ICC_CERT_NOTFOUND", parent); }
	};

	struct EMVIssuerCertNotFound: public Exception
	{
		void Show(HWND parent) const { Error("EMV_ISSUER_CERT_NOTFOUND", parent); }
	};

	struct EMVCPLCNotFound: public Exception
	{
		void Show(HWND parent) const { Error("EMV_CPLC_NOTFOUND", parent); }
	};

	struct EMVPANNotFound: public Exception
	{
		void Show(HWND parent) const { Error("EMV_PAN_NOTFOUND", parent); }
	};

	struct InvalidEMVPath: public Exception
	{
		void Show(HWND parent) const { Error("INVALID_EMV_PATH", parent); }
	};

	struct EMVKeyfileDataNotFound: public Exception
	{
		void Show(HWND parent) const { Error("EMV_KEYFILE_DATA_NOTFOUND", parent); }
	};

#endif // !TC_HEADER_Platform_Exception
}

#endif // TC_HEADER_Common_PCSCException