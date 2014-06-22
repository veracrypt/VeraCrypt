/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
			buffer[i] = (byte) i;

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
			if (buffer[i] != (byte) i)
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
		if (sizeof (byte)   != 1 || sizeof (int8)  != 1 || sizeof (__int8)  != 1) throw TestFailed (SRC_POS);
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
		ThreadTest();

		return true;
	}

	bool PlatformTest::TestFlag;
}
