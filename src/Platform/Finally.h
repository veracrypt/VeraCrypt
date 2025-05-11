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

#ifndef TC_HEADER_Platform_Finally
#define TC_HEADER_Platform_Finally

#include "PlatformBase.h"

// Execute code when leaving scope
#define finally_do(code) \
struct TC_JOIN(Finally,__LINE__) \
{ \
	TC_JOIN(~Finally,__LINE__) () { try { code } catch (...) { } } \
} \
TC_UNUSED_VAR \
TC_JOIN(finally,__LINE__)

// Execute code with argument 'finally_arg' when leaving scope
#define finally_do_arg(argType, arg, code) \
struct TC_JOIN(Finally,__LINE__) \
{ \
	TC_JOIN(Finally,__LINE__) (argType a) : finally_arg (a) { } \
	TC_JOIN(~Finally,__LINE__) () { try { code } catch (...) { } } \
	argType finally_arg; \
} \
TC_UNUSED_VAR \
TC_JOIN(finally,__LINE__) (arg)

#define finally_do_arg2(argType, arg, argType2, arg2, code) \
struct TC_JOIN(Finally,__LINE__) \
{ \
	TC_JOIN(Finally,__LINE__) (argType a, argType2 a2) : finally_arg (a), finally_arg2 (a2) { } \
	TC_JOIN(~Finally,__LINE__) () { try { code } catch (...) { } } \
	argType finally_arg; \
	argType2 finally_arg2; \
} \
TC_UNUSED_VAR \
TC_JOIN(finally,__LINE__) (arg, arg2)


#endif // TC_HEADER_Platform_Finally
