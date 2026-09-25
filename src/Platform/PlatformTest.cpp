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
		ThreadTest();
		BufferTest();
		StringConverterTest();
		FileTest();
		ExceptionTransportTest();

		return true;
	}

	// File::Copy is what moves keyfiles and header backups around, and ReadCompleteBuffer is
	// used wherever a short read would be a silent truncation. Neither had coverage.
	void PlatformTest::FileTest ()
	{
		const char *sourcePath = "veracrypt-test-file-src.tmp";
		const char *copyPath   = "veracrypt-test-file-dst.tmp";

		struct TempFiles
		{
			const char *A, *B;
			~TempFiles ()
			{
				const char *paths[] = { A, B };
				for (size_t i = 0; i < 2; i++)
				{
					try { File f; f.Open (FilePath (paths[i]), File::OpenReadWrite); f.Delete(); }
					catch (...) { }
				}
			}
		} cleanup = { sourcePath, copyPath };

		Buffer content (4096);
		for (size_t i = 0; i < content.Size(); i++)
			content[i] = (uint8) (i * 11 + 3);

		{
			File source;
			source.Open (FilePath (sourcePath), File::CreateReadWrite);
			source.Write (content);

			if (source.Length() != (uint64) content.Size())
				throw TestFailed (SRC_POS);

			if (string (source.GetPath()) != string (sourcePath))
				throw TestFailed (SRC_POS);
		}

		// A copy has to reproduce the source byte for byte
		File::Copy (FilePath (sourcePath), FilePath (copyPath));

		{
			File copy;
			copy.Open (FilePath (copyPath), File::OpenRead);

			if (copy.Length() != (uint64) content.Size())
				throw TestFailed (SRC_POS);

			Buffer readBack (content.Size());
			copy.ReadCompleteBuffer (readBack);

			if (memcmp (readBack.Ptr(), content.Ptr(), content.Size()) != 0)
				throw TestFailed (SRC_POS);
		}

		// Asking for more than the file holds must fail rather than return a partial buffer
		{
			File copy;
			copy.Open (FilePath (copyPath), File::OpenRead);

			Buffer tooLarge (content.Size() * 2);
			bool rejected = false;
			try { copy.ReadCompleteBuffer (tooLarge); }
			catch (InsufficientData&) { rejected = true; }
			catch (ParameterIncorrect&) { rejected = true; }

			if (!rejected)
				throw TestFailed (SRC_POS);
		}

		// A default-constructed File reports itself as not open. Note that the accessors do
		// NOT enforce this: every ValidateState() call in Platform/Unix/File.cpp sits behind
		// if_debug and is compiled out of release builds, so Length() on a closed file runs
		// lseek on an uninitialised handle rather than throwing. Only the flag is contractual.
		{
			File closed;
			if (closed.IsOpen())
				throw TestFailed (SRC_POS);
		}

		// Opening a path that does not exist must fail rather than yield an unusable handle
		{
			File missing;
			bool rejected = false;
			try { missing.Open (FilePath ("veracrypt-test-no-such-file.tmp"), File::OpenRead); }
			catch (SystemException&) { rejected = true; }
			catch (Exception&) { rejected = true; }

			if (!rejected || missing.IsOpen())
				throw TestFailed (SRC_POS);
		}
	}

	// When the privileged core service fails, it serialises the exception to its stderr and
	// the unprivileged side reconstructs and rethrows it (CoreService.cpp:582-590). If a type
	// is missing from the factory the real cause is replaced by a generic failure, so this
	// checks that the dynamic type and the message both survive the round trip.
	void PlatformTest::ExceptionTransportTest ()
	{
		// A plain Exception carrying a subject
		{
			Exception original (SRC_POS, L"subject-text");

			shared_ptr <Stream> stream (new MemoryStream);
			original.Serialize (stream);

			unique_ptr <Serializable> restored (Serializable::DeserializeNew (stream));
			if (!restored)
				throw TestFailed (SRC_POS);

			Exception *asException = dynamic_cast <Exception *> (restored.get());
			if (!asException)
				throw TestFailed (SRC_POS);

			if (asException->GetSubject() != original.GetSubject())
				throw TestFailed (SRC_POS);
		}

		// A derived type must come back as that same type, not as its base
		{
			ParameterIncorrect original (SRC_POS);

			shared_ptr <Stream> stream (new MemoryStream);
			original.Serialize (stream);

			unique_ptr <Serializable> restored (Serializable::DeserializeNew (stream));
			if (!restored)
				throw TestFailed (SRC_POS);

			if (dynamic_cast <ParameterIncorrect *> (restored.get()) == nullptr)
				throw TestFailed (SRC_POS);
		}

		// ... and the same for one carrying extra state
		{
			ExecutedProcessFailed original (SRC_POS, "/bin/false", 1, "stderr text");

			shared_ptr <Stream> stream (new MemoryStream);
			original.Serialize (stream);

			unique_ptr <Serializable> restored (Serializable::DeserializeNew (stream));
			ExecutedProcessFailed *typed = dynamic_cast <ExecutedProcessFailed *> (restored.get());

			if (!typed)
				throw TestFailed (SRC_POS);

			if (typed->GetCommand() != original.GetCommand()
				|| typed->GetExitCode() != original.GetExitCode()
				|| typed->GetErrorOutput() != original.GetErrorOutput())
				throw TestFailed (SRC_POS);
		}
	}

	// StringConverter parses command-line input: the PIM, volume sizes, favourite-volume
	// attributes and hotkey codes all pass through here. The behaviour on malformed input was
	// never pinned down, so this records what the parsers actually do -- including the
	// deliberate rejection of the all-ones value, which CommandLineInterface uses as its
	// "maximum available size" marker and which user input must therefore never produce.
	void PlatformTest::StringConverterTest ()
	{
		// Well-formed input round-trips
		if (StringConverter::ToUInt32 ("4294967294") != 4294967294U)
			throw TestFailed (SRC_POS);
		if (StringConverter::ToUInt64 ("18446744073709551614") != 18446744073709551614ULL)
			throw TestFailed (SRC_POS);
		if (StringConverter::ToInt32 ("-42") != -42)
			throw TestFailed (SRC_POS);
		if (StringConverter::FromNumber ((uint32) 4294967295U) != L"4294967295")
			throw TestFailed (SRC_POS);
		if (StringConverter::FromNumber ((int64) -9223372036854775807LL) != L"-9223372036854775807")
			throw TestFailed (SRC_POS);

		// Empty and non-numeric input is refused
		const char *rejected[] = { "", "abc", "4294967296" };
		for (size_t i = 0; i < array_capacity (rejected); i++)
		{
			bool threw = false;
			try { StringConverter::ToUInt32 (rejected[i]); } catch (ParameterIncorrect&) { threw = true; }
			if (!threw)
				throw TestFailed (SRC_POS);
		}

		// The all-ones sentinel must never come out of user input
		{
			bool threw = false;
			try { StringConverter::ToUInt64 ("18446744073709551615"); } catch (ParameterIncorrect&) { threw = true; }
			if (!threw)
				throw TestFailed (SRC_POS);

			threw = false;
			try { StringConverter::ToUInt32 ("4294967295"); } catch (ParameterIncorrect&) { threw = true; }
			if (!threw)
				throw TestFailed (SRC_POS);
		}

		// Splitting and trimming, as used when parsing option lists
		vector <string> parts = StringConverter::Split ("a,b,,c", ",");
		if (parts.size() != 3 || parts[0] != "a" || parts[1] != "b" || parts[2] != "c")
			throw TestFailed (SRC_POS);

		parts = StringConverter::Split ("a,b,,c", ",", true);
		if (parts.size() != 4 || !parts[2].empty())
			throw TestFailed (SRC_POS);

		if (StringConverter::Trim ("\t hello \r\n") != "hello")
			throw TestFailed (SRC_POS);

		if (StringConverter::ToLower ("MiXeD") != "mixed")
			throw TestFailed (SRC_POS);

		// GetTrailingNumber / StripTrailingNumber are a pair and must agree
		if (StringConverter::GetTrailingNumber ("sda12") != "12")
			throw TestFailed (SRC_POS);
		if (StringConverter::StripTrailingNumber ("sda12") != "sda")
			throw TestFailed (SRC_POS);

		{
			bool threw = false;
			try { StringConverter::GetTrailingNumber ("sda"); } catch (ParameterIncorrect&) { threw = true; }
			if (!threw)
				throw TestFailed (SRC_POS);
		}

		// Erase must actually clear the string, not just resize it
		{
			string s = "secret";
			StringConverter::Erase (s);
			for (size_t i = 0; i < s.size(); i++)
			{
				if (s[i] != ' ' && s[i] != 0)
					throw TestFailed (SRC_POS);
			}
		}
	}

	// Buffer and SecureBuffer hold key material, so the properties that matter are that a
	// SecureBuffer wipes itself before releasing memory and that every out-of-range access
	// is refused rather than silently truncated. None of the rejection paths, neither
	// destructor and none of Memory::Compare had ever been executed by the test suite.
	void PlatformTest::BufferTest ()
	{
		// A zero-sized allocation is not a valid request
		bool rejected = false;
		try { Memory::Allocate (0); } catch (ParameterIncorrect&) { rejected = true; }
		if (!rejected)
			throw TestFailed (SRC_POS);

		rejected = false;
		try { Memory::AllocateAligned (0, 16); } catch (ParameterIncorrect&) { rejected = true; }
		if (!rejected)
			throw TestFailed (SRC_POS);

		// Memory::Compare orders by size first, then by content
		const uint8 a[] = { 1, 2, 3 };
		const uint8 b[] = { 1, 2, 4 };

		if (Memory::Compare (a, sizeof (a), b, sizeof (b) - 1) <= 0)	// longer  -> positive
			throw TestFailed (SRC_POS);
		if (Memory::Compare (a, sizeof (a) - 1, b, sizeof (b)) >= 0)	// shorter -> negative
			throw TestFailed (SRC_POS);
		if (Memory::Compare (a, sizeof (a), a, sizeof (a)) != 0)		// identical
			throw TestFailed (SRC_POS);
		if (Memory::Compare (a, sizeof (a), b, sizeof (b)) >= 0)		// same size, a < b
			throw TestFailed (SRC_POS);

		// An unallocated buffer must not pretend to hold data, and releasing one is an error
		{
			Buffer buffer;
			if (buffer.Size() != 0 || buffer.IsAllocated())
				throw TestFailed (SRC_POS);

			rejected = false;
			try { buffer.Free(); } catch (NotInitialized&) { rejected = true; }
			if (!rejected)
				throw TestFailed (SRC_POS);
		}

		// Out-of-range access is refused, not truncated
		{
			Buffer buffer (64);

			rejected = false;
			try { buffer.GetRange (32, 64); } catch (ParameterIncorrect&) { rejected = true; }
			if (!rejected)
				throw TestFailed (SRC_POS);

			Buffer oversized (128);
			rejected = false;
			try { buffer.CopyFrom (oversized); } catch (ParameterTooLarge&) { rejected = true; }
			if (!rejected)
				throw TestFailed (SRC_POS);

			// A range fully inside the buffer must work and must alias the same memory
			BufferPtr range = buffer.GetRange (16, 16);
			if (range.Size() != 16 || range.Get() != buffer.Ptr() + 16)
				throw TestFailed (SRC_POS);
		}

		// Erase() must actually clear the bytes, and SecureBuffer::Free() must erase first
		{
			SecureBuffer secure (64);
			memset (secure.Ptr(), 0xA5, secure.Size());

			bool anyNonZero = false;
			for (size_t i = 0; i < secure.Size(); i++)
			{
				if (secure[i] != 0)
				{
					anyNonZero = true;
					break;
				}
			}
			if (!anyNonZero)
				throw TestFailed (SRC_POS);

			secure.Erase();

			for (size_t i = 0; i < secure.Size(); i++)
			{
				if (secure[i] != 0)
					throw TestFailed (SRC_POS);
			}
		}

		// Freeing a SecureBuffer that owns nothing is a programming error, not a no-op
		{
			SecureBuffer secure;
			rejected = false;
			try { secure.Free(); } catch (NotInitialized&) { rejected = true; }
			if (!rejected)
				throw TestFailed (SRC_POS);
		}
	}

	bool PlatformTest::TestFlag;
}
