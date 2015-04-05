/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Common_Exception
#define TC_HEADER_Common_Exception

#include "Platform/PlatformBase.h"
#include "Dlgcode.h"
#include <strsafe.h>

namespace VeraCrypt
{
	struct Exception
	{
		virtual void Show (HWND parent) const = 0;
	};

	struct SystemException : public Exception
	{
		SystemException () : ErrorCode (GetLastError()) { }

		void Show (HWND parent) const
		{
			SetLastError (ErrorCode);
			handleWin32Error (parent);
		}

		DWORD ErrorCode;
	};

	struct ErrorException : public Exception
	{
		ErrorException (char *langId) : ErrLangId (langId) { }
		ErrorException (const wstring &errMsg) : ErrLangId(NULL), ErrMsg (errMsg) { }

		void Show (HWND parent) const
		{
			if (ErrMsg.empty())
				::Error (ErrLangId? ErrLangId : "", parent);
			else
				::ErrorDirect (ErrMsg.c_str(), parent);
		}

		char *ErrLangId;
		wstring ErrMsg;
	};

	struct ParameterIncorrect : public Exception
	{
		ParameterIncorrect (const char *srcPos) : SrcPos (srcPos) { }

		void Show (HWND parent) const
		{
			string msgBody = "Parameter incorrect.\n\n\n(If you report a bug in connection with this, please include the following technical information in the bug report:\n" + string (SrcPos) + ")";
			MessageBox (parent, msgBody.c_str(), "VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND);
		}

		const char *SrcPos;
	};

	struct RandInitFailed : public Exception
	{
		RandInitFailed (const char *srcPos, DWORD dwLastError) : SrcPos (srcPos), LastError (dwLastError) { }

		void Show (HWND parent) const
		{
			char szErrCode[16];
			StringCbPrintf (szErrCode, sizeof(szErrCode), "0x%.8X", LastError);
			string msgBody = "The Random Generator initialization failed.\n\n\n(If you report a bug in connection with this, please include the following technical information in the bug report:\n" + string (SrcPos) + "\nLast Error = " + string (szErrCode) + ")";
			MessageBox (parent, msgBody.c_str(), "VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND);
		}

		const char *SrcPos;
		DWORD LastError;
	};

	struct CryptoApiFailed : public Exception
	{
		CryptoApiFailed (const char *srcPos, DWORD dwLastError) : SrcPos (srcPos), LastError (dwLastError) { }

		void Show (HWND parent) const
		{
			char szErrCode[16];
			StringCbPrintf (szErrCode, sizeof(szErrCode), "0x%.8X", LastError);
			string msgBody = "Windows Crypto API failed.\n\n\n(If you report a bug in connection with this, please include the following technical information in the bug report:\n" + string (SrcPos) + "\nLast Error = " + string (szErrCode) + ")";
			MessageBox (parent, msgBody.c_str(), "VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND);
		}

		const char *SrcPos;
		DWORD LastError;
	};

	struct TimeOut : public Exception
	{
		TimeOut (const char *srcPos) { }
		void Show (HWND parent) const { ErrorDirect (L"Timeout", parent); }
	};

	struct UserAbort : public Exception
	{
		UserAbort (const char *srcPos) { }
		void Show (HWND parent) const { }
	};
}

#define throw_sys_if(condition) do { if (condition) throw SystemException(); } while (false)


#endif // TC_HEADER_Common_Exception
