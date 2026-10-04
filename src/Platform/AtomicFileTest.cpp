/*
 Copyright (c) 2026 AM Crypto. All rights reserved.
 Governed by the Apache License 2.0.
*/

#include "Testing.h"
#include "AtomicFile.h"
#include "Finally.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace VeraCrypt;

namespace
{
    enum Fault { None, FileSync, Rename, DirectorySync };
    Fault Failure = None;
    vector<char> Operations;
    bool Track = false;

    ConstBufferPtr Bytes (const string &text)
    {
        return ConstBufferPtr (reinterpret_cast<const uint8 *> (text.data()), text.size());
    }

    class Fixture
    {
    public:
        Fixture ()
        {
            char path[] = "/tmp/veracrypt-atomic-file-test-XXXXXX";
            char *directory = mkdtemp (path);
            if (!directory) throw SystemException (SRC_POS);
            Directory = directory;
            File file;
            file.Open (Path(), File::CreateWrite);
            file.Write (Bytes ("previous backup"));
            file.Close();
            throw_sys_if (chmod (string (Path()).c_str(), 0644) != 0);
            Failure = None;
            Operations.clear();
            Track = true;
        }
        ~Fixture ()
        {
            Track = false;
            Failure = None;
            DIR *directory = opendir (Directory.c_str());
            if (directory)
            {
                while (dirent *entry = readdir (directory))
                {
                    string name = entry->d_name;
                    if (name != "." && name != "..") unlink ((Directory + "/" + name).c_str());
                }
                closedir (directory);
            }
            rmdir (Directory.c_str());
        }
        FilePath Path () const { return Directory + "/backup"; }
        bool HasTemporaryFiles () const
        {
            DIR *directory = opendir (Directory.c_str());
            if (!directory) throw SystemException (SRC_POS);
            bool found = false;
            while (dirent *entry = readdir (directory))
                if (string (entry->d_name).find (".tmp-") != string::npos) found = true;
            closedir (directory);
            return found;
        }
        bool Contains (const string &expected) const
        {
            File file;
            file.Open (Path());
            if (file.Length() != expected.size()) return false;
            Buffer data (expected.size());
            file.ReadCompleteBuffer (data);
            return ConstBufferPtr (data).IsDataEqual (Bytes (expected));
        }
        string Directory;
    };

    void Require (shared_ptr<TestResult> result, bool condition, const string &message)
    {
        if (!condition) result->Failed (message);
    }

    void AbandonedWrite (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        try
        {
            AtomicFile output (fixture.Path());
            output.GetFile().Write (Bytes ("incomplete"));
            throw UserAbort (SRC_POS);
        }
        catch (const UserAbort &) { }
        Require (result, fixture.Contains ("previous backup"), "Cancellation replaced the previous backup");
        Require (result, !fixture.HasTemporaryFiles(), "Cancellation left a temporary file");
    }

    void CompleteWrite (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        {
            AtomicFile output (fixture.Path());
            output.GetFile().Write (Bytes ("outer"));
            output.GetFile().Write (Bytes ("hidden"));
            Require (result, fixture.Contains ("previous backup"), "An uncommitted write changed the destination");
            output.Commit();
        }
        Require (result, fixture.Contains ("outerhidden") && !fixture.HasTemporaryFiles(), "Incomplete replacement");
        struct stat info;
        throw_sys_if (stat (string (fixture.Path()).c_str(), &info) != 0);
        Require (result, (info.st_mode & 0777) == 0600, "Replacement retained the old permissive mode");
#ifdef TC_LINUX
        Require (result, Operations == vector<char> ({'F', 'R', 'D'}), "Publication was not synchronized in order");
#endif
    }

    void RelativeDestination (shared_ptr<TestResult> result)
    {
        Fixture fixture;
        int previousDirectory = open (".", O_RDONLY);
        throw_sys_if (previousDirectory < 0);
        finally_do_arg (int, previousDirectory, { if (fchdir (finally_arg) != 0) std::terminate(); close (finally_arg); });
        throw_sys_if (chdir (fixture.Directory.c_str()) != 0);
        AtomicFile output (FilePath ("backup"));
        output.GetFile().Write (Bytes ("relative"));
        output.Commit();
        Require (result, fixture.Contains ("relative"), "Relative destination was not published");
    }

#ifdef TC_LINUX
    void FailedPublication (shared_ptr<TestResult> result, Fault fault)
    {
        Fixture fixture;
        Failure = fault;
        bool failed = false;
        try
        {
            AtomicFile output (fixture.Path());
            output.GetFile().Write (Bytes ("complete replacement"));
            output.Commit();
        }
        catch (const SystemException &e) { failed = e.GetErrorCode() == EIO; }
        Require (result, failed, "Publication error was not propagated");
        Require (result, fixture.Contains (fault == DirectorySync ? "complete replacement" : "previous backup"),
            "Failure discarded the last complete file");
        Require (result, !fixture.HasTemporaryFiles(), "Failed publication left a temporary file");
        vector<char> expected = fault == FileSync ? vector<char> ({'F'})
            : fault == Rename ? vector<char> ({'F', 'R'}) : vector<char> ({'F', 'R', 'D'});
        Require (result, Operations == expected, "Publication continued after a failed step");
    }
    void FileSyncFailure (shared_ptr<TestResult> result) { FailedPublication (result, FileSync); }
    void RenameFailure (shared_ptr<TestResult> result) { FailedPublication (result, Rename); }
    void DirectorySyncFailure (shared_ptr<TestResult> result) { FailedPublication (result, DirectorySync); }
#endif
}

#ifdef TC_LINUX
extern "C" int __real_fsync (int handle);
extern "C" int __real_rename (const char *source, const char *destination);
extern "C" int __wrap_fsync (int handle)
{
    struct stat info;
    if (Track && fstat (handle, &info) == 0)
    {
        bool directory = S_ISDIR (info.st_mode);
        Operations.push_back (directory ? 'D' : 'F');
        if (Failure == (directory ? DirectorySync : FileSync)) { errno = EIO; return -1; }
    }
    return __real_fsync (handle);
}
extern "C" int __wrap_rename (const char *source, const char *destination)
{
    if (Track)
    {
        Operations.push_back ('R');
        if (Failure == Rename) { errno = EIO; return -1; }
    }
    return __real_rename (source, destination);
}
#endif

int main ()
{
    Testing tests;
    tests.AddTest ("cancelled output preserves the previous file", AbandonedWrite);
    tests.AddTest ("complete output is private and durably published", CompleteWrite);
    tests.AddTest ("relative destination", RelativeDestination);
#ifdef TC_LINUX
    tests.AddTest ("file sync failure preserves the previous file", FileSyncFailure);
    tests.AddTest ("rename failure preserves the previous file", RenameFailure);
    tests.AddTest ("directory sync failure is reported after publication", DirectorySyncFailure);
#endif
    return tests.Main();
}
