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

#ifndef TC_HEADER_Main_UserInterfaceException
#define TC_HEADER_Main_UserInterfaceException

#include "Platform/Platform.h"

namespace VeraCrypt
{
	TC_EXCEPTION_DECL (UserInterfaceException, Exception);
	TC_EXCEPTION_DECL (MissingArgument, UserInterfaceException);
	TC_EXCEPTION_DECL (NoItemSelected, UserInterfaceException);
	TC_EXCEPTION_DECL (StringFormatterException, UserInterfaceException);

	struct ErrorMessage : public UserInterfaceException
	{
		ErrorMessage (const string &exceptionMessage, const wxString &errorMessage) : UserInterfaceException (exceptionMessage), Text (errorMessage) { }
		virtual ~ErrorMessage () throw () { }

		operator wstring () const { return wstring (Text); }
		operator wxString () const { return Text; }

	protected:
		wxString Text;
	};

#define throw_err(message) throw ErrorMessage (SRC_POS, (message))
}

#endif // TC_HEADER_Main_UserInterfaceException
