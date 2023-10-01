/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_SharedPtr
#define TC_HEADER_Platform_SharedPtr

#include <stdexcept>
#include <memory>
#include "SharedVal.h"

#ifdef nullptr

namespace VeraCrypt
{
#if (__cplusplus >= 201103L) || defined(__GXX_EXPERIMENTAL_CXX0X__)
	#define VC_USE_NATIVE_PTR	1
#endif

#ifdef VC_USE_NATIVE_PTR

#define shared_ptr std::shared_ptr
#define make_shared std::make_shared
#define move_ptr	std::move

#else

	template <class T>
	class SharedPtr
	{
	public:
		explicit SharedPtr ()
			: Pointer (nullptr), UseCount (nullptr) { }

		explicit SharedPtr (T *pointer)
			: Pointer (pointer), UseCount (new SharedVal <uint64> (1)) { }

		SharedPtr (const SharedPtr &source)
		{
			CopyFrom (source);
		}

		~SharedPtr ()
		{
			Release();
		}

		SharedPtr &operator= (const SharedPtr &source)
		{
			if (&source == this)
				return *this;

			Release();
			CopyFrom (source);
			return *this;
		}

		bool operator == (const SharedPtr &other)
		{
			return get() == other.get();
		}

		bool operator != (const SharedPtr &other)
		{
			return get() != other.get();
		}

		T &operator* () const
		{
#ifdef DEBUG
			if (Pointer == nullptr)
				throw std::runtime_error (SRC_POS);
#endif
			return *Pointer;
		}

		T *operator-> () const
		{
#ifdef DEBUG
			if (Pointer == nullptr)
				throw std::runtime_error (SRC_POS);
#endif
			return Pointer;
		}

		operator bool () const
		{
			return Pointer != nullptr;
		}

		T *get () const
		{
			return Pointer;
		}

		void reset ()
		{
			Release();
		}

		void reset (T *pointer)
		{
			*this = SharedPtr (pointer);
		}

		uint64 use_count () const
		{
			if (!UseCount)
				return 0;

			return *UseCount;
		}

	protected:
		void CopyFrom (const SharedPtr &source)
		{
			Pointer = source.Pointer;
			UseCount = source.UseCount;

			if (UseCount)
				UseCount->Increment();
		}

		void Release ()
		{
			if (UseCount != nullptr)
			{
				if (UseCount->Decrement() == 0)
				{
					if (Pointer != nullptr)
						delete Pointer;
					delete UseCount;
				}

				Pointer = nullptr;
				UseCount = nullptr;
			}
		}

		T *Pointer;
		SharedVal <uint64> *UseCount;
	};

#ifdef shared_ptr
#undef shared_ptr
#endif
#define shared_ptr VeraCrypt::SharedPtr

#ifdef make_shared
#undef make_shared
#endif

	template <class T> shared_ptr <T> make_shared ()
	{
		return shared_ptr <T> (new T ());
	}

	template <class T, class A> shared_ptr <T> make_shared (const A &arg)
	{
		return shared_ptr <T> (new T (arg));
	}

#define make_shared VeraCrypt::make_shared

#define unique_ptr auto_ptr
#define move_ptr(p)	p

#endif
}

#endif // nullptr

#define make_shared_auto(typeName,instanceName) shared_ptr <typeName> instanceName (new typeName ())

#endif // TC_HEADER_Platform_SharedPtr
