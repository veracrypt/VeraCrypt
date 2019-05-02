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

#ifndef TC_HEADER_Platform_ForEach
#define TC_HEADER_Platform_ForEach

#include <iterator>
#include <utility>

namespace VeraCrypt
{
	namespace ForEach
	{
		template <class C> class Reversed
		{
		public:

				using iterator = std::reverse_iterator<decltype(std::begin(std::declval<C&>()))>;

				Reversed(C&& container): container_(std::forward<C>(container)) { }

				iterator begin() {return iterator(std::end(container_));}
				iterator end() {return iterator(std::begin(container_));}

		private:

				C container_;
		};

		template <class C> class Dereferenced
		{
		public:

				using base_iterator = decltype(std::begin(std::declval<C&>()));
				using value_type = decltype(**std::declval<base_iterator>());

				class iterator
				{
				public:

						iterator(base_iterator base): base_(base) { }

						value_type& operator* () const {return **base_;}
						iterator operator++ () {return ++base_;}

						bool operator== (const iterator& other) const {return base_ == other.base_;}
						bool operator!= (const iterator& other) const {return base_ != other.base_;}

				private:

						base_iterator base_;
				};

				Dereferenced(C&& container): container_(std::forward<C>(container)) { }

				iterator begin() {return std::begin(container_);}
				iterator end() {return std::end(container_);}

		private:

				C container_;
		};

		template <typename C> static Reversed<C> reverse(C&& c) {return std::forward<C>(c);}

		template <typename C> static Dereferenced<C> dereference(C&& c) {return std::forward<C>(c);}

	};
}

#define foreach(variable,listInstance) for (variable: listInstance)
#define foreach_ref(variable,listInstance) for (variable: ForEach::dereference(listInstance))
#define foreach_reverse(variable,listInstance) for (variable: ForEach::reverse(listInstance))
#define foreach_reverse_ref(variable,listInstance) for (variable: ForEach::dereference(ForEach::reverse(listInstance)))

#endif // TC_HEADER_Platform_ForEach
