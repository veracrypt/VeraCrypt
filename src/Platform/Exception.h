/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Exception
#define TC_HEADER_Platform_Exception

#include <exception>
#include "PlatformBase.h"
#include "Serializable.h"

namespace VeraCrypt
{
#define TC_SERIALIZABLE_EXCEPTION(TYPE) TC_SERIALIZABLE (TYPE); \
	virtual Exception *CloneNew () { return new TYPE (*this); } \
	virtual void Throw () const { throw *this; }

	struct Exception : public exception, public Serializable
	{
	public:
		Exception () { }
		Exception (const string &message) : Message (message) { }
		Exception (const string &message, const wstring &subject) : Message (message), Subject (subject) { }
		virtual ~Exception () throw () { }

		TC_SERIALIZABLE_EXCEPTION (Exception);

		virtual const char *what () const throw () { return Message.c_str(); }
		virtual const wstring &GetSubject() const { return Subject; }

	protected:
		string Message;
		wstring Subject;
	};

	struct ExecutedProcessFailed : public Exception
	{
		ExecutedProcessFailed () { }
		ExecutedProcessFailed (const string &message, const string &command, int exitCode, const string &errorOutput)
			: Exception (message), Command (command), ExitCode (exitCode), ErrorOutput (errorOutput) { }
		virtual ~ExecutedProcessFailed () throw () { }

		TC_SERIALIZABLE_EXCEPTION (ExecutedProcessFailed);

		string GetCommand () const { return Command; }
		int64 GetExitCode () const { return ExitCode; }
		string GetErrorOutput () const { return ErrorOutput; }

	protected:
		string Command;
		int64 ExitCode;
		string ErrorOutput;
	};

#define TC_EXCEPTION_DECL(NAME,BASE) \
	struct NAME  : public BASE \
	{ \
		NAME () { } \
		NAME (const string &message) : BASE (message) { } \
		NAME (const string &message, const wstring &subject) : BASE (message, subject) { } \
		virtual Exception *CloneNew () { return new NAME (*this); } \
		static Serializable *GetNewSerializable () { return new NAME (); } \
		virtual void Throw () const { throw *this; } \
	}

#define TC_EXCEPTION_NODECL(dummy) //
#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,Exception)

#ifdef TC_EXCEPTION_SET
#undef TC_EXCEPTION_SET
#endif
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (Exception); \
	TC_EXCEPTION_NODECL (ExecutedProcessFailed); \
	TC_EXCEPTION (AlreadyInitialized); \
	TC_EXCEPTION (AssertionFailed); \
	TC_EXCEPTION (ExternalException); \
	TC_EXCEPTION (InsufficientData); \
	TC_EXCEPTION (NotApplicable); \
	TC_EXCEPTION (NotImplemented); \
	TC_EXCEPTION (NotInitialized); \
	TC_EXCEPTION (ParameterIncorrect); \
	TC_EXCEPTION (ParameterTooLarge); \
	TC_EXCEPTION (PartitionDeviceRequired); \
	TC_EXCEPTION (StringConversionFailed); \
	TC_EXCEPTION (TestFailed); \
	TC_EXCEPTION (TimeOut); \
	TC_EXCEPTION (UnknownException); \
	TC_EXCEPTION (UserAbort)

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION
}

#ifdef assert
#	undef assert
#endif

#ifdef DEBUG
#	define assert(condition) do { if (!(condition)) throw AssertionFailed (SRC_POS); } while (false)
#else
#	define assert(condition) ((void) 0)
#endif

#endif // TC_HEADER_Platform_Exception
