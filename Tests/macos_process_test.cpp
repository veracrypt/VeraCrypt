// Read-only subprocess tests. Every child is this test executable; no mounts,
// privilege changes, or installed VeraCrypt services are involved.
#include "Platform/Platform.h"
#include "Platform/Unix/Process.h"
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace VeraCrypt;

static void Require (bool condition, const char *message)
{
	if (!condition) throw std::runtime_error (message);
}

static int DescriptorCount ()
{
	int count = 0;
	for (int fd = 0; fd < 256; ++fd)
		if (fcntl (fd, F_GETFD) != -1) ++count;
	return count;
}

int main (int argc, char **argv)
{
	if (argc > 1)
	{
		std::string mode = argv[1];
		if (mode == "success")
		{
			char byte;
			if (read (STDIN_FILENO, &byte, 1) != 0 || fcntl (80, F_GETFD) != -1) return 9;
			write (STDOUT_FILENO, "complete", 8);
			return 0;
		}
		if (mode == "failure") { write (STDERR_FILENO, "expected", 8); return 7; }
		if (mode == "closed") { close (STDOUT_FILENO); close (STDERR_FILENO); sleep (5); return 0; }
		if (mode == "stream")
		{
			for (;;) { write (STDOUT_FILENO, ".", 1); usleep (100); }
		}
		if (mode == "large")
		{
			char data[8192] = {};
			for (;;) write (STDOUT_FILENO, data, sizeof (data));
		}
		sleep (5);
		return 0;
	}
	try
	{
		uint64 startTime = Process::GetProcessStartTime (getpid());
		Require (startTime != 0 && Process::IsProcessRunning (getpid(), startTime), "own process instance not recognized");
		Require (!Process::IsProcessRunning (getpid(), startTime + 1), "different process instance accepted");
		Require (Process::IsProcessRunning (getpid()), "unknown birth time discarded a live process");
		int nullFd = open ("/dev/null", O_RDONLY);
		Require (nullFd >= 0 && dup2 (nullFd, 80) == 80, "test descriptor setup");
		close (nullFd);
		int before = DescriptorCount();
		std::cout << "process: success" << std::endl;
		Require (Process::ExecuteBounded (argv[0], { "success" }, 1000) == "complete", "output/descriptor isolation");
		std::cout << "process: failure" << std::endl;
		try { Process::ExecuteBounded (argv[0], { "failure" }, 1000); throw std::runtime_error ("missing child error"); }
		catch (ExecutedProcessFailed &e) { Require (e.GetExitCode() == 7 && e.GetErrorOutput() == "expected", "child error details"); }
		for (const auto &mode : { "silent", "closed", "stream" })
		{
			std::cout << "process: " << mode << std::endl;
			auto start = std::chrono::steady_clock::now();
			try { Process::ExecuteBounded (argv[0], { mode }, 150); throw std::runtime_error ("missing timeout"); }
			catch (TimeOut &) { }
			Require (std::chrono::steady_clock::now() - start < std::chrono::seconds (2), "deadline overrun");
			int status;
			Require (waitpid (-1, &status, WNOHANG) == -1 && errno == ECHILD, "timed-out child not reaped");
		}
		std::cout << "process: output cap" << std::endl;
		try { Process::ExecuteBounded (argv[0], { "large" }, 1000, 64); throw std::runtime_error ("missing output cap"); }
		catch (ParameterTooLarge &) { }
		int status;
		Require (waitpid (-1, &status, WNOHANG) == -1 && errno == ECHILD, "output-limited child not reaped");
		Require (DescriptorCount() == before, "descriptor leak");
		close (80);
		std::cout << "PASS: output, errors, descriptor isolation, silent/closed/stream deadlines, output cap, reaping\n";
	}
	catch (std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
	return 0;
}
