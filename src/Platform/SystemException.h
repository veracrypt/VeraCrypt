/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_SystemException
#define TC_HEADER_Platform_SystemException

#include "PlatformBase.h"
#include "Exception.h"

namespace VeraCrypt
{
	class SystemException : public Exception
	{
	public:
		SystemException ();
		SystemException (const string &message);
		SystemException (const string &message, const string &subject);
		SystemException (const string &message, const wstring &subject);
		SystemException (const string &message, int64 errorCode)
			: Exception (message), ErrorCode (errorCode) { }
		virtual ~SystemException () throw () { }

		TC_SERIALIZABLE_EXCEPTION (SystemException);

		int64 GetErrorCode () const { return ErrorCode; }
		bool IsError () const;
		wstring SystemText () const;

	protected:
		int64 ErrorCode;
	};

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (SystemException);
}

#define throw_sys_if(condition) do { if (condition) throw SystemException (SRC_POS); } while (false)
#define throw_sys_sub_if(condition,subject) do { if (condition) throw SystemException (SRC_POS, (subject)); } while (false)

#endif // TC_HEADER_Platform_SystemException
