/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Buffer
#define TC_HEADER_Platform_Buffer

#include "PlatformBase.h"
#include "Memory.h"

namespace VeraCrypt
{

	class ConstBufferPtr
	{
	public:
		ConstBufferPtr ()
			: DataPtr (nullptr), DataSize (0) { }
		ConstBufferPtr (const byte *data, size_t size)
			: DataPtr (data), DataSize (size) { }
		virtual ~ConstBufferPtr () { }

		operator const byte * () const { return DataPtr; }

		bool IsDataEqual (const ConstBufferPtr &other) const { return Memory::Compare (DataPtr, DataSize, other.DataPtr, other.DataSize) == 0; }
		const byte *Get () const { return DataPtr; }
		ConstBufferPtr GetRange (size_t offset, size_t size) const;
		void Set (const byte *data, size_t size) { DataPtr = data; DataSize = size; }
		size_t Size () const { return DataSize; }

	protected:
		const byte *DataPtr;
		size_t DataSize;
	};


	class BufferPtr
	{
	public:
		BufferPtr ()
			: DataPtr (nullptr), DataSize (0) { }
		BufferPtr (byte *data, size_t size)
			: DataPtr (data), DataSize (size) { }
		virtual ~BufferPtr () { }

		operator byte * () const { return DataPtr; }
		void CopyFrom (const ConstBufferPtr &bufferPtr) const;
		void Erase () const { Zero(); }
		byte *Get () const { return DataPtr; }
		BufferPtr GetRange (size_t offset, size_t size) const;
		void Set (byte *data, size_t size) { DataPtr = data; DataSize = size; }
		size_t Size () const { return DataSize; }
		void Zero () const { Memory::Zero (DataPtr, DataSize); }

		operator ConstBufferPtr () const { return ConstBufferPtr (DataPtr, DataSize); }

	protected:
		byte *DataPtr;
		size_t DataSize;
	};

	class Buffer
	{
	public:
		Buffer ();
		Buffer (size_t size);
		Buffer (const ConstBufferPtr &bufferPtr) { CopyFrom (bufferPtr); }
		virtual ~Buffer ();

		virtual void Allocate (size_t size);
		virtual void CopyFrom (const ConstBufferPtr &bufferPtr);
		virtual byte *Ptr () const { return DataPtr; }
		virtual void Erase ();
		virtual void Free ();
		virtual BufferPtr GetRange (size_t offset, size_t size) const;
		virtual size_t Size () const { return DataSize; }
		virtual bool IsAllocated () const { return DataSize != 0; }
		virtual void Zero ();

		virtual operator byte * () const { return DataPtr; }
		virtual operator BufferPtr () const { return BufferPtr (DataPtr, DataSize); }
		virtual operator ConstBufferPtr () const { return ConstBufferPtr (DataPtr, DataSize); }

	protected:
		byte *DataPtr;
		size_t DataSize;

	private:
		Buffer (const Buffer &);
		Buffer &operator= (const Buffer &);
	};

	class SecureBuffer : public Buffer
	{
	public:
		SecureBuffer () { }
		SecureBuffer (size_t size);
		SecureBuffer (const ConstBufferPtr &bufferPtr) { CopyFrom (bufferPtr); }
		virtual ~SecureBuffer ();

		virtual void Allocate (size_t size);
		virtual void Free ();

	private:
		SecureBuffer (const SecureBuffer &);
		SecureBuffer &operator= (const SecureBuffer &);
	};

}

#endif // TC_HEADER_Platform_Buffer
