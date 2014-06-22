/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_ForEach
#define TC_HEADER_Platform_ForEach

namespace VeraCrypt
{
	class ForEach
	{
	public:
		struct Container
		{
			Container () : InnerContinue (true), InnerEndCondition (false) { }
			virtual ~Container () { }

			void Continue () const { InnerContinue = true; }
			bool InnerIsNotEnd () const { return InnerEndCondition = !InnerEndCondition; }
			virtual bool IsNotEnd () const = 0;
			virtual void Next () const = 0;

			mutable bool InnerContinue;
			mutable bool InnerEndCondition;
		};

	protected:
		template <class T>
		struct ContainerForward : Container
		{
			ContainerForward (const T &container)
				: ContainerCopy (container), EndIterator (ContainerCopy.end()), Iterator (ContainerCopy.begin()) { }

			virtual bool IsNotEnd () const { bool r = InnerContinue && Iterator != EndIterator; InnerContinue = false; return r; }
			virtual void Next () const { ++Iterator; }

			const T ContainerCopy;	// Support for temporary objects
			typename T::const_iterator EndIterator;
			mutable typename T::const_iterator Iterator;

		private:
			ContainerForward &operator= (const ContainerForward &);
		};

		template <class T>
		struct ContainerReverse : Container
		{
			ContainerReverse (const T &container)
				: ContainerCopy (container), EndIterator (ContainerCopy.rend()), Iterator (ContainerCopy.rbegin()) { }

			virtual bool IsNotEnd () const { bool r = InnerContinue && Iterator != EndIterator; InnerContinue = false; return r; }
			virtual void Next () const { ++Iterator; }

			const T ContainerCopy;
			typename T::const_reverse_iterator EndIterator;
			mutable typename T::const_reverse_iterator Iterator;
			
		private:
			ContainerReverse &operator= (const ContainerReverse &);
		};

	public:
		template <class T>
		static ContainerForward <T> GetContainerForward (const T &container)
		{
			return ContainerForward <T> (container);
		}

		template <class T>
		static ContainerReverse <T> GetContainerReverse (const T &container)
		{
			return ContainerReverse <T> (container);
		}

	protected:
		template <class T>
		struct TypeWrapper { };

	public:
		template <class T>
		static TypeWrapper <T> ToTypeWrapper (const T &x) { return TypeWrapper <T> (); }

		struct TypeWrapperDummy
		{
			template <class T>
			operator TypeWrapper <T> () const { return TypeWrapper <T> (); }
		};

		template <class T>
		static const ContainerForward <T> &GetContainerForward (const Container &forEachContainer, const TypeWrapper <T> &)
		{
			return static_cast <const ContainerForward <T> &> (forEachContainer);
		}

		template <class T>
		static const ContainerReverse <T> &GetContainerReverse (const Container &forEachContainer, const TypeWrapper <T> &)
		{
			return static_cast <const ContainerReverse <T> &> (forEachContainer);
		}
	};
}


#define FOREACH_TEMPLATE(dereference,listType,variable,listInstance) \
	for (const ForEach::Container &forEachContainer = ForEach::GetContainer##listType (listInstance); forEachContainer.IsNotEnd(); forEachContainer.Next()) \
		for (variable = dereference(ForEach::GetContainer##listType (forEachContainer, (true ? ForEach::TypeWrapperDummy() : ForEach::ToTypeWrapper (listInstance))).Iterator); forEachContainer.InnerIsNotEnd(); forEachContainer.Continue())

#define foreach(variable,listInstance) FOREACH_TEMPLATE(*, Forward, variable, listInstance)
#define foreach_ref(variable,listInstance) FOREACH_TEMPLATE(**, Forward, variable, listInstance)
#define foreach_reverse(variable,listInstance) FOREACH_TEMPLATE(*, Reverse, variable, listInstance)
#define foreach_reverse_ref(variable,listInstance) FOREACH_TEMPLATE(**, Reverse, variable, listInstance)


#endif // TC_HEADER_Platform_ForEach
