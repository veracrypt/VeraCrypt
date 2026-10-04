/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "PlatformTest.h"
#include "Exception.h"
#include "FileStream.h"
#include "Finally.h"
#include "ForEach.h"
#include "MemoryStream.h"
#include "Mutex.h"
#include "Serializable.h"
#include "SharedPtr.h"
#include "StringConverter.h"
#include "SyncEvent.h"
#include "Thread.h"
#include "Common/Tcdefs.h"

namespace VeraCrypt
{
	class TestSerializer : public Serializer
	{
	public:
		TestSerializer (shared_ptr <Stream> stream) : Serializer (stream) { }
		string ReadString () { return DeserializeString (); }
		wstring ReadWString () { return DeserializeWString (); }
	};

	static shared_ptr <Stream> CreateStringTestStream (uint64 declaredSize, const ConstBufferPtr &data)
	{
		shared_ptr <Stream> stream (new MemoryStream);
		uint64 fieldSize = Endian::Big (uint64 (sizeof (declaredSize)));
		uint64 size = Endian::Big (declaredSize);
		stream->Write (ConstBufferPtr ((uint8 *) &fieldSize, sizeof (fieldSize)));
		stream->Write (ConstBufferPtr ((uint8 *) &size, sizeof (size)));
		if (data.Size() > 0)
			stream->Write (data);
		return stream;
	}

	static void SerializerFailureTest ()
	{
		bool exceptionThrown = false;
		try
		{
			TestSerializer ser (CreateStringTestStream (0, ConstBufferPtr()));
			ser.ReadString ();
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);

		exceptionThrown = false;
		try
		{
			TestSerializer ser (CreateStringTestStream (1024 * 1024 + 1, ConstBufferPtr()));
			ser.ReadString ();
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);

		uint8 unterminatedString = 'x';
		exceptionThrown = false;
		try
		{
			TestSerializer ser (CreateStringTestStream (1, ConstBufferPtr (&unterminatedString, 1)));
			ser.ReadString ();
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);

		exceptionThrown = false;
		try
		{
			TestSerializer ser (CreateStringTestStream (sizeof (wchar_t) - 1, ConstBufferPtr()));
			ser.ReadWString ();
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);

		wchar_t unterminatedWString = L'x';
		exceptionThrown = false;
		try
		{
			TestSerializer ser (CreateStringTestStream (sizeof (unterminatedWString), ConstBufferPtr ((uint8 *) &unterminatedWString, sizeof (unterminatedWString))));
			ser.ReadWString ();
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);

		exceptionThrown = false;
		try
		{
			Serializer::ValidateCollectionSize (65537);
		}
		catch (ParameterIncorrect &) { exceptionThrown = true; }
		if (!exceptionThrown)
			throw TestFailed (SRC_POS);
	}

	static void SerializerStringPolicyTest ()
	{
		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);
		const string strings[] = { "", "text", string ((size_t) Serializer::MaxStringSize - 1, 'x') };
		const wstring wstrings[] = { L"", L"text", wstring ((size_t) Serializer::MaxStringSize / sizeof (wchar_t) - 1, L'x') };
		for (size_t i = 0; i < array_capacity (strings); ++i)
		{
			sr.Serialize ("String", strings[i]);
			sr.Serialize ("WString", wstrings[i]);
			if (sr.DeserializeString ("String") != strings[i] || sr.DeserializeWString ("WString") != wstrings[i])
				throw TestFailed (SRC_POS);
		}

		const string invalidStrings[] = { string ("x\0y", 3), string (1, '\0'), string ((size_t) Serializer::MaxStringSize, 'x') };
		const wstring invalidWStrings[] = { wstring (L"x\0y", 3), wstring (1, L'\0'), wstring ((size_t) Serializer::MaxStringSize / sizeof (wchar_t), L'x') };
		for (size_t i = 0; i < array_capacity (invalidStrings); ++i)
		{
			try
			{
				sr.Serialize ("String", invalidStrings[i]);
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }
			try
			{
				sr.Serialize ("WString", invalidWStrings[i]);
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }

			try
			{
				TestSerializer reader (CreateStringTestStream (invalidStrings[i].size() + 1,
					ConstBufferPtr ((const uint8 *) invalidStrings[i].c_str(), invalidStrings[i].size() + 1)));
				reader.ReadString();
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }
			try
			{
				size_t size = (invalidWStrings[i].size() + 1) * sizeof (wchar_t);
				TestSerializer reader (CreateStringTestStream (size, ConstBufferPtr ((const uint8 *) invalidWStrings[i].c_str(), size)));
				reader.ReadWString();
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }
		}

		try
		{
			TestSerializer reader (CreateStringTestStream (0, ConstBufferPtr()));
			reader.ReadWString();
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
	}

	static void SerializerCollectionTest ()
	{
		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);
		list <string> strings ((size_t) Serializer::MaxCollectionSize + 1);
		list <wstring> wstrings ((size_t) Serializer::MaxCollectionSize + 1);
		list < shared_ptr <Exception> > objects ((size_t) Serializer::MaxCollectionSize + 1);
		try
		{
			sr.Serialize ("Strings", strings);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		try
		{
			sr.Serialize ("WStrings", wstrings);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		try
		{
			Serializable::SerializeList (stream, objects);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }

		strings.pop_back();
		wstrings.pop_back();
		sr.Serialize ("Strings", strings);
		sr.Serialize ("WStrings", wstrings);
		if (sr.DeserializeStringList ("Strings") != strings || sr.DeserializeWStringList ("WStrings") != wstrings)
			throw TestFailed (SRC_POS);

		sr.Serialize ("Strings", Serializer::MaxCollectionSize + 1);
		try
		{
			sr.DeserializeStringList ("Strings");
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		sr.Serialize ("WStrings", Serializer::MaxCollectionSize + 1);
		try
		{
			sr.DeserializeWStringList ("WStrings");
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		Serializable::SerializeHeader (sr, "list<Exception>");
		sr.Serialize ("ListSize", Serializer::MaxCollectionSize + 1);
		objects.clear();
		try
		{
			Serializable::DeserializeList (stream, objects);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
	}

	// Registered only for this test; counters check that rejection happens before parsing
	// and that failed reads release the object, including through the raw-pointer API.
	class SerializerTestObject : public Serializable
	{
	public:
		SerializerTestObject () { ++LiveCount; }
		virtual ~SerializerTestObject () { --LiveCount; }
		static Serializable *GetNewSerializable () { return new SerializerTestObject; }
		virtual void DeserializeData (shared_ptr <Stream> stream)
		{
			++ParseCount;
			Serializer sr (stream);
			sr.DeserializeUInt32 ("Value");
		}
		static int LiveCount;
		static int ParseCount;
	};

	int SerializerTestObject::LiveCount = 0;
	int SerializerTestObject::ParseCount = 0;

	static void SerializableTypeTest ()
	{
		TC_SERIALIZER_FACTORY_ADD (SerializerTestObject);
		finally_do ({
			SerializerFactory::NameToTypeMap->erase ("SerializerTestObject");
			SerializerFactory::TypeToNameMap->erase (StringConverter::GetTypeName (typeid (SerializerTestObject)));
		});
		SerializerTestObject::ParseCount = 0;

		shared_ptr <Stream> stream (new MemoryStream);
		Serializer sr (stream);
		Serializable::SerializeHeader (sr, "SerializerTestObject");
		try
		{
			Serializable::DeserializeNew <Exception> (stream);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		if (SerializerTestObject::LiveCount != 0 || SerializerTestObject::ParseCount != 0)
			throw TestFailed (SRC_POS);

		Serializable::SerializeHeader (sr, "list<Exception>");
		sr.Serialize ("ListSize", uint64 (1));
		Serializable::SerializeHeader (sr, "SerializerTestObject");
		list < shared_ptr <Exception> > objects;
		try
		{
			Serializable::DeserializeList (stream, objects);
			throw TestFailed (SRC_POS);
		}
		catch (ParameterIncorrect &) { }
		if (SerializerTestObject::LiveCount != 0 || SerializerTestObject::ParseCount != 0 || !objects.empty())
			throw TestFailed (SRC_POS);

		for (int i = 0; i < 2; ++i)
		{
			Serializable::SerializeHeader (sr, "SerializerTestObject");
			try
			{
				if (i == 0)
				{
					unique_ptr <Serializable> object (Serializable::DeserializeNew (stream));
				}
				else
					Serializable::DeserializeNew <SerializerTestObject> (stream);
				throw TestFailed (SRC_POS);
			}
			catch (InsufficientData &) { }
			if (SerializerTestObject::LiveCount != 0 || SerializerTestObject::ParseCount != i + 1)
				throw TestFailed (SRC_POS);
		}

		ExecutedProcessFailed exception ("message", "command", 1, "output");
		exception.Serialize (stream);
		shared_ptr <Exception> result = Serializable::DeserializeNew <Exception> (stream);
		if (!dynamic_cast <ExecutedProcessFailed *> (result.get()))
			throw TestFailed (SRC_POS);
	}

	static void SerializerNestingTest ()
	{
		shared_ptr <Stream> stream (new MemoryStream);
		for (int attempt = 0; attempt < 2; ++attempt)
		{
			vector < shared_ptr <SerializationScope> > scopes;
			for (unsigned int i = 0; i < Serializer::MaxNestingDepth; ++i)
				scopes.push_back (shared_ptr <SerializationScope> (new SerializationScope (stream)));
			try
			{
				SerializationScope excess (stream);
				throw TestFailed (SRC_POS);
			}
			catch (ParameterIncorrect &) { }

			// Nesting is local to a stream and is restored when scopes unwind.
			shared_ptr <Stream> otherStream (new MemoryStream);
			SerializationScope other (otherStream);
			scopes.clear();
			Serializer sr (stream);
			sr.Serialize ("Value", uint32 (7));
			if (sr.DeserializeUInt32 ("Value") != 7)
				throw TestFailed (SRC_POS);
		}
	}

	// make_shared_auto, File, Stream, MemoryStream, Endian, Serializer, Serializable
	void PlatformTest::SerializerTest ()
	{
		shared_ptr <Stream> stream (new MemoryStream);

#if 0
		make_shared_auto (File, file);
		finally_do_arg (File&, *file, { if (finally_arg.IsOpen()) finally_arg.Delete(); });

		try
		{
			file->Open ("veracrypt-serializer-test.tmp", File::CreateReadWrite);
			stream = shared_ptr <Stream> (new FileStream (file));
		}
		catch (...) { }
#endif

		Serializer ser (stream);

		uint32 i32 = 0x12345678;
		uint64 i64 = 0x0123456789abcdefULL;
		string str = "string test";
		wstring wstr = L"wstring test";

		string convStr = "test";
		StringConverter::ToSingle (wstr, convStr);
		if (convStr != "wstring test")
			throw TestFailed (SRC_POS);

		StringConverter::Erase (convStr);
		if (convStr != "            ")
			throw TestFailed (SRC_POS);

		wstring wEraseTest = L"erase test";
		StringConverter::Erase (wEraseTest);
		if (wEraseTest != L"          ")
			throw TestFailed (SRC_POS);

		list <string> stringList;
		stringList.push_back (str + "1");
		stringList.push_back (str + "2");
		stringList.push_back (str + "3");

		list <wstring> wstringList;
		wstringList.push_back (wstr + L"1");
		wstringList.push_back (wstr + L"2");
		wstringList.push_back (wstr + L"3");

		Buffer buffer (10);
		for (size_t i = 0; i < buffer.Size(); i++)
			buffer[i] = (uint8) i;

		ser.Serialize ("int32", i32);
		ser.Serialize ("int64", i64);
		ser.Serialize ("string", str);
		ser.Serialize ("wstring", wstr);
		ser.Serialize ("stringList", stringList);
		ser.Serialize ("wstringList", wstringList);
		ser.Serialize ("buffer", ConstBufferPtr (buffer));

		ExecutedProcessFailed ex (SRC_POS, "cmd", -123, "error output");
		ex.Serialize (stream);

		list < shared_ptr <ExecutedProcessFailed> > exList;
		exList.push_back (make_shared <ExecutedProcessFailed> (ExecutedProcessFailed (SRC_POS, "cmd", -123, "error output1")));
		exList.push_back (make_shared <ExecutedProcessFailed> (ExecutedProcessFailed (SRC_POS, "cmd", -234, "error output2")));
		exList.push_back (make_shared <ExecutedProcessFailed> (ExecutedProcessFailed (SRC_POS, "cmd", -567, "error output3")));
		Serializable::SerializeList (stream, exList);

#if 0
		if (file->IsOpen())
			file->SeekAt (0);
#endif

		uint32 di32;
		ser.Deserialize ("int32", di32);
		if (i32 != di32)
			throw TestFailed (SRC_POS);

		uint64 di64;
		ser.Deserialize ("int64", di64);
		if (i64 != di64)
			throw TestFailed (SRC_POS);

		string dstr;
		ser.Deserialize ("string", dstr);
		if (str != dstr)
			throw TestFailed (SRC_POS);

		wstring dwstr;
		ser.Deserialize ("wstring", dwstr);
		if (str != dstr)
			throw TestFailed (SRC_POS);

		int i = 1;
		foreach (string item, ser.DeserializeStringList ("stringList"))
		{
			stringstream s;
			s << str << i++;
			if (item != s.str())
				throw TestFailed (SRC_POS);
		}

		i = 1;
		foreach (wstring item, ser.DeserializeWStringList ("wstringList"))
		{
			wstringstream s;
			s << wstr << i++;
			if (item != s.str())
				throw TestFailed (SRC_POS);
		}

		Buffer dbuffer (10);
		ser.Deserialize ("buffer", buffer);
		for (size_t i = 0; i < buffer.Size(); i++)
			if (buffer[i] != (uint8) i)
				throw TestFailed (SRC_POS);

		shared_ptr <ExecutedProcessFailed> dex = Serializable::DeserializeNew <ExecutedProcessFailed> (stream);
		if (!dex
			|| dex->GetCommand() != "cmd"
			|| dex->GetExitCode() != -123
			|| dex->GetErrorOutput() != "error output")
			throw TestFailed (SRC_POS);

		list < shared_ptr <ExecutedProcessFailed> > dexList;
		Serializable::DeserializeList (stream, dexList);
		i = 1;
		foreach_ref (const ExecutedProcessFailed &ex, dexList)
		{
			stringstream s;
			s << "error output" << i++;
			if (ex.GetErrorOutput() != s.str())
				throw TestFailed (SRC_POS);
		}
	}

	// shared_ptr, Mutex, ScopeLock, SyncEvent, Thread
	static struct
	{
		shared_ptr <int> SharedIntPtr;
		Mutex IntMutex;
		SyncEvent ExitAllowedEvent;
	} ThreadTestData;

	void PlatformTest::ThreadTest ()
	{
		Mutex mutex;
		mutex.Lock();
		mutex.Unlock();

		const int maxThreads = 3;
		ThreadTestData.SharedIntPtr.reset (new int (0));

		for (int i = 0; i < maxThreads; i++)
		{
			Thread t;
			t.Start (&ThreadTestProc, (void *) &ThreadTestData);
		}

		for (int i = 0; i < 50; i++)
		{
			{
				ScopeLock sl (ThreadTestData.IntMutex);
				if (*ThreadTestData.SharedIntPtr == maxThreads)
					break;
			}

			Thread::Sleep(100);
		}

		if (*ThreadTestData.SharedIntPtr != maxThreads)
			throw TestFailed (SRC_POS);

		for (int i = 0; i < 60000; i++)
		{
			ThreadTestData.ExitAllowedEvent.Signal();
			Thread::Sleep(1);

			ScopeLock sl (ThreadTestData.IntMutex);
			if (*ThreadTestData.SharedIntPtr == 0)
				break;
		}

		if (*ThreadTestData.SharedIntPtr != 0)
			throw TestFailed (SRC_POS);
	}

	TC_THREAD_PROC PlatformTest::ThreadTestProc (void *arg)
	{

		if (arg != (void *) &ThreadTestData)
			return 0;

		{
			ScopeLock sl (ThreadTestData.IntMutex);
			++(*ThreadTestData.SharedIntPtr);
		}

		ThreadTestData.ExitAllowedEvent.Wait();

		{
			ScopeLock sl (ThreadTestData.IntMutex);
			--(*ThreadTestData.SharedIntPtr);
		}

		return 0;
	}

	bool PlatformTest::TestAll ()
	{
		// Integer types
		if (sizeof (uint8)   != 1 || sizeof (int8)  != 1 || sizeof (__int8)  != 1) throw TestFailed (SRC_POS);
		if (sizeof (uint16) != 2 || sizeof (int16) != 2 || sizeof (__int16) != 2) throw TestFailed (SRC_POS);
		if (sizeof (uint32) != 4 || sizeof (int32) != 4 || sizeof (__int32) != 4) throw TestFailed (SRC_POS);
		if (sizeof (uint64) != 8 || sizeof (int64) != 8) throw TestFailed (SRC_POS);

		// Exception handling
		TestFlag = false;
		try
		{
			try
			{
				throw TestFailed (SRC_POS);
			}
			catch (...)
			{
				throw;
			}
			return false;
		}
		catch (Exception &)
		{
			TestFlag = true;
		}
		if (!TestFlag)
			return false;

		// RTTI
		RttiTest rtti;
		RttiTestBase &rttiBaseRef = rtti;
		RttiTestBase *rttiBasePtr = &rtti;

		if (typeid (rttiBaseRef) != typeid (rtti))
			throw TestFailed (SRC_POS);

		if (typeid (*rttiBasePtr) != typeid (rtti))
			throw TestFailed (SRC_POS);

		if (dynamic_cast <RttiTest *> (rttiBasePtr) == nullptr)
			throw TestFailed (SRC_POS);

		try
		{
			dynamic_cast <RttiTest &> (rttiBaseRef);
		}
		catch (...)
		{
			throw TestFailed (SRC_POS);
		}

		// finally
		TestFlag = false;
		{
			finally_do ({ TestFlag = true; });
			if (TestFlag)
				throw TestFailed (SRC_POS);
		}
		if (!TestFlag)
			throw TestFailed (SRC_POS);

		TestFlag = false;
		{
			finally_do_arg (bool*, &TestFlag, { *finally_arg = true; });
			if (TestFlag)
				throw TestFailed (SRC_POS);
		}
		if (!TestFlag)
			throw TestFailed (SRC_POS);

		TestFlag = false;
		int tesFlag2 = 0;
		{
			finally_do_arg2 (bool*, &TestFlag, int*, &tesFlag2, { *finally_arg = true; *finally_arg2 = 2; });
			if (TestFlag || tesFlag2 != 0)
				throw TestFailed (SRC_POS);
		}
		if (!TestFlag || tesFlag2 != 2)
			throw TestFailed (SRC_POS);

		// uint64, vector, list, string, wstring, stringstream, wstringstream
		// shared_ptr, make_shared, StringConverter, foreach
		list <shared_ptr <uint64> > numList;

		numList.push_front (make_shared <uint64> (StringConverter::ToUInt64 (StringConverter::FromNumber ((uint64) 0xFFFFffffFFFFfffeULL))));
		numList.push_front (make_shared <uint64> (StringConverter::ToUInt32 (StringConverter::GetTrailingNumber ("str2"))));
		numList.push_front (make_shared <uint64> (3));

		list <wstring> testList;
		wstringstream wstream (L"test");
		foreach_reverse_ref (uint64 n, numList)
		{
			wstream.str (L"");
			wstream << L"str" << n;
			testList.push_back (wstream.str());
		}

		stringstream sstream;
		sstream << "dummy";
		sstream.str ("");
		sstream << "str18446744073709551614,str2" << " str" << StringConverter::Trim (StringConverter::ToSingle (L"\t 3 \r\n"));
		foreach (const string &s, StringConverter::Split (sstream.str(), ", "))
		{
			if (testList.front() != StringConverter::ToWide (s))
				throw TestFailed (SRC_POS);
			testList.pop_front();
		}

		SerializerTest();
		SerializerFailureTest();
		SerializerStringPolicyTest();
		SerializerCollectionTest();
		SerializableTypeTest();
		SerializerNestingTest();
		ThreadTest();

		return true;
	}

	bool PlatformTest::TestFlag;
}
