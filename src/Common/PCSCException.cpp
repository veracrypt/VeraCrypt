#include "PCSCException.h"

#if !defined(TC_WINDOWS) || defined(TC_PROTOTYPE)
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"
#include "Platform/SystemException.h"
#else
#include "Dictionary.h"
#include "Language.h"
#endif

namespace VeraCrypt
{
	PCSCException::operator string() const
	{
		if (ErrorCode == SCARD_S_SUCCESS)
			return string();

		static const struct{
			LONG_PCSC ErrorCode;
			const char* ErrorString;
		} ErrorStrings[] = {
#define SC_ERR(CODE) { CODE, #CODE },
#ifdef TC_WINDOWS
				SC_ERR(ERROR_BROKEN_PIPE)
				SC_ERR(SCARD_E_NO_PIN_CACHE)
				SC_ERR(SCARD_E_PIN_CACHE_EXPIRED)
				SC_ERR(SCARD_E_READ_ONLY_CARD)
				SC_ERR(SCARD_W_CACHE_ITEM_NOT_FOUND)
				SC_ERR(SCARD_W_CACHE_ITEM_STALE)
				SC_ERR(SCARD_W_CACHE_ITEM_TOO_BIG)
#endif
				SC_ERR(SCARD_E_BAD_SEEK)
				SC_ERR(SCARD_E_CANCELLED)
				SC_ERR(SCARD_E_CANT_DISPOSE)
				SC_ERR(SCARD_E_CARD_UNSUPPORTED)
				SC_ERR(SCARD_E_CERTIFICATE_UNAVAILABLE)
				SC_ERR(SCARD_E_COMM_DATA_LOST)
				SC_ERR(SCARD_E_COMM_DATA_LOST)
				SC_ERR(SCARD_E_DIR_NOT_FOUND)
				SC_ERR(SCARD_E_DUPLICATE_READER)
				SC_ERR(SCARD_E_FILE_NOT_FOUND)
				SC_ERR(SCARD_E_ICC_CREATEORDER)
				SC_ERR(SCARD_E_ICC_INSTALLATION)
				SC_ERR(SCARD_E_INSUFFICIENT_BUFFER)
				SC_ERR(SCARD_E_INVALID_ATR)
				SC_ERR(SCARD_E_INVALID_CHV)
				SC_ERR(SCARD_E_INVALID_HANDLE)
				SC_ERR(SCARD_E_INVALID_PARAMETER)
				SC_ERR(SCARD_E_INVALID_TARGET)
				SC_ERR(SCARD_E_INVALID_VALUE)
				SC_ERR(SCARD_E_NO_ACCESS)
				SC_ERR(SCARD_E_NO_DIR)
				SC_ERR(SCARD_E_NO_FILE)
				SC_ERR(SCARD_E_NO_KEY_CONTAINER)
				SC_ERR(SCARD_E_NO_MEMORY)
				SC_ERR(SCARD_E_NO_READERS_AVAILABLE)
				SC_ERR(SCARD_E_NO_SERVICE)
				SC_ERR(SCARD_E_NO_SMARTCARD)
				SC_ERR(SCARD_E_NO_SUCH_CERTIFICATE)
				SC_ERR(SCARD_E_NOT_READY)
				SC_ERR(SCARD_E_NOT_TRANSACTED)
				SC_ERR(SCARD_E_PCI_TOO_SMALL)
				SC_ERR(SCARD_E_PROTO_MISMATCH)
				SC_ERR(SCARD_E_READER_UNAVAILABLE)
				SC_ERR(SCARD_E_READER_UNSUPPORTED)
				SC_ERR(SCARD_E_SERVER_TOO_BUSY)
				SC_ERR(SCARD_E_SERVICE_STOPPED)
				SC_ERR(SCARD_E_SHARING_VIOLATION)
				SC_ERR(SCARD_E_SYSTEM_CANCELLED)
				SC_ERR(SCARD_E_TIMEOUT)
				SC_ERR(SCARD_E_UNEXPECTED)
				SC_ERR(SCARD_E_UNKNOWN_CARD)
				SC_ERR(SCARD_E_UNKNOWN_READER)
				SC_ERR(SCARD_E_UNKNOWN_RES_MNG)
				SC_ERR(SCARD_E_UNSUPPORTED_FEATURE)
				SC_ERR(SCARD_E_WRITE_TOO_MANY)
				SC_ERR(SCARD_F_COMM_ERROR)
				SC_ERR(SCARD_F_INTERNAL_ERROR)
				SC_ERR(SCARD_F_UNKNOWN_ERROR)
				SC_ERR(SCARD_W_CANCELLED_BY_USER)
				SC_ERR(SCARD_W_CARD_NOT_AUTHENTICATED)
				SC_ERR(SCARD_W_CHV_BLOCKED)
				SC_ERR(SCARD_W_EOF)
				SC_ERR(SCARD_W_REMOVED_CARD)
				SC_ERR(SCARD_W_RESET_CARD)
				SC_ERR(SCARD_W_SECURITY_VIOLATION)
				SC_ERR(SCARD_W_UNPOWERED_CARD)
				SC_ERR(SCARD_W_UNRESPONSIVE_CARD)
				SC_ERR(SCARD_W_UNSUPPORTED_CARD)
				SC_ERR(SCARD_W_WRONG_CHV)
#undef SC_ERR
		};

		for (size_t i = 0; i < array_capacity(ErrorStrings); ++i)
		{
			if (ErrorStrings[i].ErrorCode == ErrorCode)
				return ErrorStrings[i].ErrorString;
		}

		stringstream s;
		s << "0x" << ErrorCode;
		return s.str();
	}

#ifdef TC_HEADER_Common_Exception
	void PCSCException::Show(HWND parent) const
	{
		string errorString = string(*this);

		if (!errorString.empty())
		{
			if (!GetDictionaryValue(errorString.c_str()))
			{
				if (errorString.find("SCARD_E_") == 0 || errorString.find("SCARD_F_") == 0 || errorString.find("SCARD_W_") == 0)
				{
					errorString = errorString.substr(8);
					for (size_t i = 0; i < errorString.size(); ++i)
					{
						if (errorString[i] == '_')
							errorString[i] = ' ';
					}
				}
				wchar_t err[8192];
				StringCbPrintfW(err, sizeof(err), L"%s:\n\n%hs%s", GetString("PCSC_ERROR"), errorString.c_str());
				ErrorDirect(err, parent);
			}
			else
			{
				wstring err = GetString(errorString.c_str());
				ErrorDirect(err.c_str(), parent);
			}
		}
	}
#endif // TC_HEADER_Common_Exception

#ifdef TC_HEADER_Platform_Exception

	void PCSCException::Deserialize(shared_ptr <Stream> stream)
	{
		Exception::Deserialize(stream);
		Serializer sr(stream);
		int64 v;
		sr.Deserialize("ErrorCode", v);
		ErrorCode = (LONG_PCSC)v;
	}

	void PCSCException::Serialize(shared_ptr <Stream> stream) const
	{
		Exception::Serialize(stream);
		Serializer sr(stream);
		int64 v = (int64)ErrorCode;
		sr.Serialize("ErrorCode", v);
	}

#	define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#	undef TC_EXCEPTION_NODECL
#	define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET(PCSCException);

#endif

	CommandAPDUNotValid::operator string() const
	{
		return string(ErrorStr);
	}

#ifdef TC_HEADER_Common_Exception
	void CommandAPDUNotValid::Show(HWND parent) const
	{
		string msgBody = "Command APDU invalid.\n\n\n(If you report a bug in connection with this, please include the following technical information in the bug report:\n" + SrcPos + "\nLast Error = " + ErrorStr + ")";
		MessageBoxA (parent, msgBody.c_str(), "VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND);
	}
#endif // TC_HEADER_Common_Exception

#ifdef TC_HEADER_Platform_Exception

	void CommandAPDUNotValid::Deserialize(shared_ptr <Stream> stream)
	{
		Exception::Deserialize(stream);
		Serializer sr(stream);
		sr.Deserialize("SrcPos", SrcPos);
		sr.Deserialize("ErrorStr", ErrorStr);
	}

	void CommandAPDUNotValid::Serialize(shared_ptr <Stream> stream) const
	{
		Exception::Serialize(stream);
		Serializer sr(stream);
		sr.Serialize("SrcPos", SrcPos);
		sr.Serialize("ErrorStr", ErrorStr);
	}

#	define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#	undef TC_EXCEPTION_NODECL
#	define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET(CommandAPDUNotValid);

#endif
}