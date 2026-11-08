// Exercise the production File and Process code using temporary regular files.
#include "Platform/File.h"
#include "Platform/MemoryStream.h"
#include "Platform/SystemException.h"
#include "Platform/Unix/Process.h"
#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

using namespace VeraCrypt;
typedef std::chrono::steady_clock Clock;

static void Require (bool ok, const char *message)
{
    if (!ok) throw std::runtime_error (message);
}

static void WriteAll (int fd, const void *data, size_t size)
{
    const char *bytes = static_cast <const char *> (data);
    while (size)
    {
        ssize_t count = write (fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        Require (count > 0, "write failed");
        bytes += count;
        size -= count;
    }
}

static vector <int> ExtraDescriptors ()
{
    DIR *directory = opendir ("/proc/self/fd");
    Require (directory != NULL, "cannot list descriptors");
    vector <int> descriptors;
    while (struct dirent *entry = readdir (directory))
    {
        int fd = std::atoi (entry->d_name);
        if (fd > STDERR_FILENO && fd != dirfd (directory)) descriptors.push_back (fd);
    }
    closedir (directory);
    return descriptors;
}

struct TestFile : File
{
    int Descriptor () const { return FileHandle; }
};

static int Child (const string &mode, int argc, char **argv)
{
    if (mode == "file")
    {
        Require (argc == 6, "file probe arguments");
        struct stat info;
        bool inherited = fstat (std::atoi (argv[3]), &info) == 0
            && info.st_dev == std::strtoull (argv[4], NULL, 10)
            && info.st_ino == std::strtoull (argv[5], NULL, 10);
        std::cout << (inherited ? "inherited" : "closed");
    }
    else if (mode == "descriptors")
    {
        for (int fd : ExtraDescriptors ()) std::cout << fd << ' ';
    }
    else if (mode == "forged")
    {
        shared_ptr <Stream> stream (new MemoryStream);
        ExternalException ("Forged by the launched program").Serialize (stream);
        ConstBufferPtr data = dynamic_cast <MemoryStream &> (*stream);
        for (int fd : ExtraDescriptors ())
        {
            struct stat info;
            int flags = fcntl (fd, F_GETFL);
            if (flags >= 0 && (flags & O_ACCMODE) != O_RDONLY
                && fstat (fd, &info) == 0 && S_ISFIFO (info.st_mode))
                WriteAll (fd, data, data.Size());
        }
        std::cout << "ok";
    }
    else if (mode == "output")
    {
        string block (4096, 'x');
        for (int i = 0; i < 256; ++i)
        {
            WriteAll (STDOUT_FILENO, block.data(), block.size());
            WriteAll (STDERR_FILENO, block.data(), block.size());
        }
    }
    else if (mode == "error")
    {
        close (STDOUT_FILENO);
        usleep (100000);
        WriteAll (STDERR_FILENO, "later error", 11);
        return 7;
    }
    else if (mode == "echo")
    {
        char buffer[256];
        ssize_t count;
        while ((count = read (STDIN_FILENO, buffer, sizeof (buffer))) > 0)
            WriteAll (STDOUT_FILENO, buffer, count);
        Require (count == 0, "stdin read failed");
    }
    else if (mode == "quiet" || mode == "redirect" || mode == "close" || mode == "busy")
    {
        int pidFile = open (argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        Require (pidFile >= 0, "cannot write child pid");
        string pid = std::to_string (getpid());
        WriteAll (pidFile, pid.data(), pid.size());
        close (pidFile);
        if (mode == "redirect")
        {
            int nullFd = open ("/dev/null", O_WRONLY);
            Require (nullFd >= 0 && dup2 (nullFd, 1) == 1 && dup2 (nullFd, 2) == 2, "redirect failed");
            close (nullFd);
        }
        if (mode == "close") { close (1); close (2); }
        for (int i = 0; i < 400; ++i)
        {
            if (mode == "busy") WriteAll (STDOUT_FILENO, "x", 1);
            usleep (10000);
        }
    }
    else throw std::runtime_error ("unknown child mode");
    return 0;
}

static string Run (const string &self, const string &mode, const Buffer *input = NULL)
{
    return Process::Execute (self, { "--child", mode }, 3000, NULL, input);
}

static void OnAlarm (int) { }

static void CheckTimeout (const string &self, const string &directory, const string &mode, bool interrupt)
{
    struct sigaction action = {}, oldAction;
    action.sa_handler = OnAlarm;
    Require (sigaction (SIGALRM, &action, &oldAction) == 0, "sigaction failed");
    struct itimerval timer = {};
    if (interrupt)
    {
        timer.it_interval.tv_usec = timer.it_value.tv_usec = 10000;
        Require (setitimer (ITIMER_REAL, &timer, NULL) == 0, "setitimer failed");
    }
    string pidPath = directory + "/child-pid";
    auto start = Clock::now();
    bool timedOut = false;
    try { Process::Execute (self, { "--child", mode, pidPath }, 400); }
    catch (const TimeOut &) { timedOut = true; }
    auto elapsed = std::chrono::duration_cast <std::chrono::milliseconds> (Clock::now() - start).count();
    timer = {};
    setitimer (ITIMER_REAL, &timer, NULL);
    sigaction (SIGALRM, &oldAction, NULL);
    Require (timedOut && elapsed >= 350 && elapsed < 2000, "timeout was lost or extended");
    int fd = open (pidPath.c_str(), O_RDONLY);
    char pidText[32] = {};
    Require (fd >= 0 && read (fd, pidText, sizeof (pidText) - 1) > 0, "missing child pid");
    close (fd);
    pid_t child = std::atoi (pidText);
    int status;
    Require (child > 1 && waitpid (child, &status, WNOHANG) == 0, "timeout killed or reaped the running child");
    kill (child, SIGKILL);
    while (waitpid (child, &status, 0) < 0 && errno == EINTR) { }
}

struct ForkCallback : ProcessExecFunctor
{
    TestFile &file;
    bool daemon;
    ForkCallback (TestFile &f, bool d) : file (f), daemon (d) { }
    void operator() (int, char **)
    {
        uint8 byte;
        Require (file.ReadAt (BufferPtr (&byte, 1), 0) == 1 && byte == 'v', "fork lost the open file");
        if (daemon)
        {
            pid_t pid = fork();
            Require (pid >= 0, "callback fork failed");
            if (pid == 0) { sleep (10); _exit (0); }
        }
        WriteAll (STDOUT_FILENO, "fork ok", 7);
        _exit (0);
    }
};

struct ThrowCallback : ProcessExecFunctor
{
    void operator() (int, char **) { throw ExternalException ("callback error"); }
};

struct BackgroundOutput : ProcessExecFunctor
{
    int outputFd;
    explicit BackgroundOutput (int fd) : outputFd (fd) { }
    void operator() (int, char **)
    {
        pid_t callbackPid = getpid();
        pid_t child = fork();
        Require (child >= 0, "background fork failed");
        if (child == 0)
        {
            if (outputFd < 0) sleep (2);
            else
            {
                // Only write after the direct child exits, so the test does not
                // limit output that legitimately arrives while it is running.
                while (getppid() == callbackPid) usleep (1000);
                string block (16384, 'b');
                for (int i = 0; i < 4096; ++i) WriteAll (outputFd, block.data(), block.size());
            }
            _exit (0);
        }
        if (outputFd < 0)
        {
            // Leave output in the pipe while the caller is paused past the deadline.
            usleep (50000);
            string block (60000, 'e');
            WriteAll (STDOUT_FILENO, block.data(), block.size());
            usleep (50000);
        }
        else usleep (10000);
        _exit (outputFd == STDERR_FILENO ? 7 : 0);
    }
};

static void PauseForExit (int)
{
    // Model a delayed caller while the launched program finishes.
    struct timespec delay = { 0, 300000000 };
    while (nanosleep (&delay, &delay) < 0 && errno == EINTR) { }
}

int main (int argc, char **argv)
{
    try
    {
        Require (argc >= 3, "missing arguments");
        string self = argv[0], name = argv[1], directory = argv[2];
        if (name == "--child") return Child (directory, argc, argv);
        if (name == "file" || name == "fork")
        {
            TestFile file;
            file.Open (directory + "/volume", File::CreateReadWrite);
            const uint8 byte = 'v';
            file.Write (ConstBufferPtr (&byte, 1));
            if (name == "file")
            {
                struct stat info;
                Require (fstat (file.Descriptor(), &info) == 0, "fstat failed");
                string result = Process::Execute (self, { "--child", "file", std::to_string (file.Descriptor()),
                    std::to_string (info.st_dev), std::to_string (info.st_ino) }, 3000);
                Require (result == "closed", "exec inherited an open file");
            }
            else
            {
                for (bool daemon : {false, true})
                {
                    ForkCallback callback (file, daemon);
                    auto start = Clock::now();
                    Require (Process::Execute ("callback", {}, daemon ? -1 : 1500, &callback) == "fork ok", "callback output lost");
                    Require (Clock::now() - start < std::chrono::seconds (1), "waited for a callback descendant");
                }
            }
        }
        else if (name == "descriptors") Require (Run (self, name).empty(), "exec inherited spare descriptors");
        else if (name == "forged") Require (Run (self, name) == "ok", "child injected an exception");
        else if (name == "output") Require (Run (self, name) == string (1024 * 1024, 'x'), "output was truncated");
        else if (name == "errors")
        {
            bool caught = false;
            try { Run (self, "error"); }
            catch (const ExecutedProcessFailed &e) { caught = e.GetExitCode() == 7 && e.GetErrorOutput() == "later error"; }
            Require (caught, "exit status or stderr lost after stdout closed");
            caught = false;
            try { Process::Execute (directory + "/missing-program", {}, 3000); }
            catch (const SystemException &e) { caught = e.GetErrorCode() == ENOENT; }
            Require (caught, "exec failure was not reported");
            ThrowCallback callback;
            caught = false;
            try { Process::Execute ("callback", {}, 3000, &callback); }
            catch (const ExternalException &e) { caught = string (e.what()) == "callback error"; }
            Require (caught, "callback exception was not reported");
        }
        else if (name == "timeouts")
        {
            for (const char *mode : {"quiet", "redirect", "close", "busy"}) CheckTimeout (self, directory, mode, false);
            CheckTimeout (self, directory, "quiet", true);
        }
        else if (name == "background-output")
        {
            for (int timeout : {-1, 2000})
                for (int fd : {STDOUT_FILENO, STDERR_FILENO})
                {
                    BackgroundOutput callback (fd);
                    auto start = Clock::now();
                    string output;
                    try { output = Process::Execute ("callback", {}, timeout, &callback); }
                    catch (const ExecutedProcessFailed &e)
                    {
                        Require (fd == STDERR_FILENO && e.GetExitCode() == 7, "background writer changed exit status");
                        output = e.GetErrorOutput();
                    }
                    Require (Clock::now() - start < std::chrono::seconds (1), "waited for background output");
                    // Allow a small amount read before the callback's exit is observed.
                    Require (output.size() <= 2 * 1024 * 1024, "background output exceeded the drain limit");
                }
        }
        else if (name == "exit-deadline")
        {
            struct sigaction action = {};
            action.sa_handler = PauseForExit;
            Require (sigaction (SIGALRM, &action, NULL) == 0, "sigaction failed");
            struct itimerval timer = {};
            timer.it_value.tv_usec = 25000;
            Require (setitimer (ITIMER_REAL, &timer, NULL) == 0, "setitimer failed");
            BackgroundOutput callback (-1);
            auto start = Clock::now();
            string output = Process::Execute ("callback", {}, 200, &callback);
            auto elapsed = Clock::now() - start;
            Require (output == string (60000, 'e'), "output was lost after the deadline");
            Require (elapsed >= std::chrono::milliseconds (300) && elapsed < std::chrono::seconds (1),
                "exit was not observed after the deadline");
        }
        else if (name == "input" || name == "closed-stdio")
        {
            string text (1024, 'i');
            Buffer input (text.size());
            input.CopyFrom (ConstBufferPtr (reinterpret_cast <const uint8 *> (text.data()), text.size()));
            if (name == "input")
            {
                Require (Run (self, "echo", &input) == text, "stdin transfer failed");
                Require (Run (self, "echo").empty(), "default stdin is not empty");
            }
            else for (int mask = 1; mask < 8; ++mask)
            {
                pid_t child = fork();
                Require (child >= 0, "fork failed");
                if (child == 0)
                {
                    for (int fd = 0; fd < 3; ++fd) if (mask & (1 << fd)) close (fd);
                    _exit (Run (self, "echo", &input) == text && Run (self, "echo").empty() ? 0 : 1);
                }
                int status;
                Require (waitpid (child, &status, 0) == child && WIFEXITED (status) && WEXITSTATUS (status) == 0,
                    "closed standard descriptors broke execution");
            }
        }
        else throw std::runtime_error ("unknown test");
        std::cout << "PASS: " << name << '\n';
        return 0;
    }
    catch (const std::exception &e) { std::cerr << "FAIL: " << argv[1] << ": " << e.what() << '\n'; return 1; }
}
