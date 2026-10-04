#!/usr/bin/env python3
"""Exercise the production CLI/GUI mount loops with scripted backend outcomes.

Run after building VeraCrypt: python3 Tests/test_backup_header_retry.py
--build-dir may point to another matching build's src directory. Requires a C++11
compiler and Python 3 on macOS or Linux; no GUI, mounted volumes or sudo needed.
The real option, credential and exception types are linked from that build.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "Core/MountOptions.h"
#include "Core/CoreException.h"
struct wxString : std::wstring { using std::wstring::wstring; };
#include "Main/UserInterfaceException.h"
#include "Volume/VolumeInfo.h"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>

namespace VeraCrypt {
static void Require (bool condition, const char *message) {
    if (!condition) throw std::runtime_error (message);
}
enum Outcome { Success, Incorrect, KeyfilesIncorrect, MountOptionsIncorrect,
    ProtectionIncorrect, ProtectionKeyfilesIncorrect, BackendFailure, IoFailure,
    Cancelled, StandardFailure, UnknownFailure };
struct UnknownError { int Code; };
struct Attempt {
    bool Backup, Cached;
    shared_ptr<VolumePassword> Password;
    int Pim;
    shared_ptr<KeyfileList> Keyfiles;
};
static struct {
    vector<Outcome> Plan;
    vector<Attempt> Calls;
    vector<string> Messages;
    vector<size_t> BackupWarnings;
    std::exception_ptr Error;
    bool Cache = false;
    int OuterPrompts = 0, HiddenPrompts = 0;
} State;

static shared_ptr<VolumePassword> Password () {
    return make_shared<VolumePassword> (reinterpret_cast<const uint8*> ("test"), 4);
}
static struct {
    bool IsVolumeMounted (const VolumePath &) const { return false; }
    bool IsPasswordCacheEmpty () const { return !State.Cache; }
} CoreInstance, *Core = &CoreInstance;
static struct { bool ArgNoHiddenVolumeProtection = true; } CommandLine, *CmdLine = &CommandLine;
static struct {
    wstring operator[] (const char *key) const { string s (key); return wstring (s.begin(), s.end()); }
} LangString;
static wstring StringFormatter (const wstring &format, const wstring &argument) { return format + argument; }
#define _(s) L##s
struct wxBusyCursor {};
static const int wxID_OK = 1;
struct UserPreferences {
    bool NonInteractive = false, DisableKernelEncryptionModeWarning = true, UseKeyfiles = false;
    KeyfileList DefaultKeyfiles;
};
class UserInterface {
public:
    UserPreferences Preferences;
    const UserPreferences &GetPreferences () const { return Preferences; }
    void CheckRequirementsForMountingVolume () const {}
    void ShowInfo (const exception &e) const { State.Messages.push_back (e.what()); }
    void ShowInfo (const wstring &) const {}
    void ShowWarning (const exception &e) const { ShowInfo (e); }
    void ShowWarning (const wstring &) const {}
    void ShowWarning (const char *key) const {
        if (string (key) == "HEADER_DAMAGED_AUTO_USED_HEADER_BAK")
            State.BackupWarnings.push_back (State.Calls.size());
    }
    void ShowError (const exception &) const { State.Error = std::current_exception(); }
    void ShowString (const wstring &) const {}
    bool AskYesNo (const wstring &, bool = false, bool = false) const { return false; }
    shared_ptr<VolumePassword> AskPassword (const wstring &prompt) const {
        if (prompt.find (L"hidden") != wstring::npos) ++State.HiddenPrompts;
        else ++State.OuterPrompts;
        return Password();
    }
    int AskPim (const wstring &) const { return 7; }
    shared_ptr<KeyfileList> AskKeyfiles (const wstring & = L"") const { return make_shared<KeyfileList>(); }
    wstring AskString (const wstring &) const { return L""; }
    wstring AskSecurityTokenSchemeSpec (const wstring & = L"") const { return L""; }
    shared_ptr<VolumePath> AskVolumePath () const { throw std::runtime_error ("unexpected path prompt"); }
    shared_ptr<VolumeInfo> MountVolume (MountOptions &options) const {
        Require (State.Calls.size() < State.Plan.size(), "unexpected additional mount attempt");
        bool cached = State.Cache && (!options.Password || options.Password->IsEmpty())
            && (!options.Keyfiles || options.Keyfiles->empty());
        Outcome outcome = State.Plan[State.Calls.size()];
        State.Calls.push_back ({options.UseBackupHeaders, cached, options.Password, options.Pim, options.Keyfiles});
        // Match CoreServiceProxy's cleanup after trying cached outer credentials.
        if (cached) options.Password.reset();
        string message = options.UseBackupHeaders ? "backup" : "primary";
        switch (outcome) {
        case Success: return make_shared<VolumeInfo>();
        case Incorrect: throw PasswordIncorrect (message);
        case KeyfilesIncorrect: throw PasswordKeyfilesIncorrect (message);
        case MountOptionsIncorrect: throw PasswordOrMountOptionsIncorrect (message);
        case ProtectionIncorrect: throw ProtectionPasswordIncorrect ("protection");
        case ProtectionKeyfilesIncorrect: throw ProtectionPasswordKeyfilesIncorrect ("protection-keyfiles");
        case BackendFailure: throw ExecutedProcessFailed (message, "mount", 37, "backend details");
        case IoFailure: throw SystemException (message, EIO);
        case Cancelled: throw UserAbort (message, L"cancelled mount");
        case StandardFailure: throw std::runtime_error (message);
        case UnknownFailure: throw UnknownError {42};
        }
        throw std::runtime_error ("invalid outcome");
    }
};
class TextUserInterface : public UserInterface {
public:
    shared_ptr<VolumeInfo> MountVolume (MountOptions &, bool) const;
};
class GraphicUserInterface : public UserInterface {
public:
    shared_ptr<VolumeInfo> MountVolumeInternal (MountOptions &, bool, bool) const;
    int GetActiveWindow () const { return 0; }
    int GetTopWindow () const { return 0; }
    VolumePath SelectVolumeFile (int) const { throw std::runtime_error ("unexpected file dialog"); }
    void SetPreferences (const UserPreferences &) {}
};
static GraphicUserInterface *Gui;
class MountOptionsDialog {
    MountOptions &Options;
    bool ProtectionRecovery = false;
public:
    MountOptionsDialog (int, MountOptions &options) : Options (options) {}
    void Hide () {}
    void SetProtectionRecovery (bool recovery) { ProtectionRecovery = recovery; }
    int ShowModal () {
        Require (State.Calls.size() < 12, "unexpected credential retry loop");
        if (!ProtectionRecovery) {
            ++State.OuterPrompts;
            Options.Password = Password();
            Options.Pim = 7;
            if (!Options.Keyfiles) Options.Keyfiles = make_shared<KeyfileList>();
        } else {
            ++State.HiddenPrompts;
            Options.ProtectionPassword = Password();
            Options.ProtectionPim = 7;
            Options.ProtectionKeyfiles = make_shared<KeyfileList>();
        }
        return wxID_OK;
    }
};

// PRODUCTION_METHODS

static shared_ptr<VolumeInfo> Mount (bool gui, MountOptions &options, bool cached = false) {
    try {
        if (gui) return GraphicUserInterface().MountVolumeInternal (options, cached, false);
        return TextUserInterface().MountVolume (options, cached);
    } catch (...) { State.Error = std::current_exception(); }
    return shared_ptr<VolumeInfo>();
}
static void Reset (MountOptions &options, const char *path, vector<Outcome> plan) {
    State = decltype(State)();
    State.Plan = plan;
    options.Path = make_shared<VolumePath> (string (path));
    options.NoFilesystem = true;
    options.Keyfiles = make_shared<KeyfileList>();
}
static void CheckFailure (Outcome failure) {
    Require (bool (State.Error), "backup failure was swallowed");
    try { std::rethrow_exception (State.Error); }
    catch (ExecutedProcessFailed &e) {
        Require (failure == BackendFailure && string (e.what()) == "backup"
            && e.GetCommand() == "mount" && e.GetExitCode() == 37 && e.GetErrorOutput() == "backend details",
            "backend failure details changed");
    } catch (SystemException &e) {
        Require (failure == IoFailure && e.GetErrorCode() == EIO && string (e.what()) == "backup",
            "I/O failure details changed");
    } catch (UserAbort &e) {
        Require (failure == Cancelled && string (e.what()) == "backup" && e.GetSubject() == L"cancelled mount",
            "cancellation changed");
    } catch (std::runtime_error &e) {
        Require (failure == StandardFailure && string (e.what()) == "backup", "standard exception changed");
    } catch (UnknownError &e) {
        Require (failure == UnknownFailure && e.Code == 42, "unknown exception changed");
    }
}
static void CheckHeaders (std::initializer_list<bool> expected) {
    Require (State.Calls.size() == expected.size(), "wrong number of mount attempts");
    size_t i = 0;
    for (bool backup : expected) Require (State.Calls[i++].Backup == backup, "wrong header selected");
}
static void Run (bool gui, const char *path) {
    for (Outcome failure : {BackendFailure, IoFailure, Cancelled, StandardFailure, UnknownFailure}) {
        MountOptions options;
        Reset (options, path, {Incorrect, Incorrect, Incorrect, failure, Success});
        Require (!Mount (gui, options), "backup failure retried until success");
        CheckFailure (failure);
        CheckHeaders ({false, false, false, true});
        Require (!options.UseBackupHeaders, "temporary backup selection leaked after failure");
        Require (options.Password == State.Calls.back().Password && options.Pim == State.Calls.back().Pim,
            "unrelated failure discarded credentials");
        Require (State.Messages == vector<string> ({"primary", "primary"}), "failure misreported as bad credentials");
        Require (State.OuterPrompts == 3 && State.BackupWarnings.empty(), "failure prompted again or warned of success");
    }
    for (Outcome failure : {Incorrect, KeyfilesIncorrect, MountOptionsIncorrect}) {
        MountOptions options;
        Reset (options, path, {Incorrect, Incorrect, Incorrect, failure, Success});
        Require (bool (Mount (gui, options)) && !State.Error, "credential retry failed");
        CheckHeaders ({false, false, false, true, false});
        Require (!options.UseBackupHeaders && State.BackupWarnings.empty(), "failed fallback reported as successful");
        Require (State.OuterPrompts == 4 && State.Messages == vector<string> ({"primary", "primary", "primary"}),
            "credential retry reporting changed");
    }
    for (Outcome outcome : {Success, ProtectionIncorrect, ProtectionKeyfilesIncorrect}) {
        MountOptions options;
        Reset (options, path, {Incorrect, Incorrect, Incorrect, outcome, Success});
        options.Protection = VolumeProtection::HiddenVolumeReadOnly;
        options.ProtectionPassword = Password();
        options.ProtectionPim = 7;
        options.ProtectionKeyfiles = make_shared<KeyfileList>();
        Require (bool (Mount (gui, options)) && !State.Error, "backup/protection recovery failed");
        if (outcome == Success) CheckHeaders ({false, false, false, true});
        else {
            CheckHeaders ({false, false, false, true, true});
            Require (State.Calls[3].Password == State.Calls[4].Password
                && State.Calls[3].Pim == State.Calls[4].Pim && State.Calls[3].Keyfiles == State.Calls[4].Keyfiles,
                "protection recovery replaced accepted outer credentials");
            Require (State.HiddenPrompts == 1, "hidden credentials were not recovered");
        }
        Require (State.OuterPrompts == 3 && options.UseBackupHeaders, "accepted backup selection lost");
        Require (State.BackupWarnings == vector<size_t> ({State.Calls.size()}), "backup warning not deferred until success");
    }
    for (Outcome outcome : {Success, BackendFailure, Cancelled}) {
        MountOptions options;
        Reset (options, path, {outcome});
        options.UseBackupHeaders = true;
        shared_ptr<VolumeInfo> volume = Mount (gui, options);
        if (outcome != Success) CheckFailure (outcome);
        else Require (bool (volume) && !State.Error, "explicit backup mount failed");
        CheckHeaders ({true});
        Require (options.UseBackupHeaders && State.BackupWarnings.empty(), "explicit backup option changed");
    }
    for (Outcome outcome : {Success, ProtectionIncorrect, ProtectionKeyfilesIncorrect}) {
        MountOptions options;
        Reset (options, path, {outcome, Success});
        State.Cache = true;
        options.Protection = VolumeProtection::HiddenVolumeReadOnly;
        options.ProtectionPassword = Password();
        options.ProtectionPim = 7;
        options.ProtectionKeyfiles = make_shared<KeyfileList>();
        Require (bool (Mount (gui, options, true)) && !State.Error, "cached credential recovery failed");
        Require (State.Calls.size() == (outcome == Success ? 1 : 2), "unexpected cache retry");
        for (const Attempt &attempt : State.Calls) Require (attempt.Cached && !attempt.Backup, "cached source changed");
        Require (State.OuterPrompts == 0 && State.BackupWarnings.empty(), "cache recovery asked for outer password");
    }
    std::cout << "PASS: " << (gui ? "GUI" : "CLI") << " backup failures, cancellation, credential retries, protection and cache recovery\n";
}
}
int main (int argc, char **argv) {
    if (argc != 2) return 2;
    int failures = 0;
    for (bool gui : {false, true}) {
        try { VeraCrypt::Run (gui, argv[1]); }
        catch (const std::exception &e) {
            std::cerr << (gui ? "GUI: " : "CLI: ") << e.what() << '\n';
            ++failures;
        }
        catch (...) { std::cerr << "unexpected exception\n"; ++failures; }
    }
    return failures ? 1 : 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    args = parser.parse_args()
    methods = []
    for filename, start, end in (
        ("TextUserInterface.cpp", "\tshared_ptr <VolumeInfo> TextUserInterface::MountVolume (", "\tbool TextUserInterface::OnInit"),
        ("GraphicUserInterface.cpp", "\tshared_ptr <VolumeInfo> GraphicUserInterface::MountVolumeInternal (", "\tvoid GraphicUserInterface::OnAutoDismountAllEvent"),
    ):
        source = (ROOT / "src/Main" / filename).read_text()
        methods.append(source[source.index(start):source.index(end)])
    with tempfile.TemporaryDirectory(prefix="vc-backup-retry-") as temporary:
        work = Path(temporary)
        unit = work / "backup_retry.cpp"
        unit.write_text(HARNESS.replace("// PRODUCTION_METHODS", "\n".join(methods)))
        command = shlex.split(os.environ.get("CXX", "c++")) + ["-std=c++11", "-DTC_UNIX"]
        command += ["-DTC_MACOSX"] if sys.platform == "darwin" else ["-DTC_LINUX"]
        command += ["-I" + str(ROOT / p) for p in ("src", "src/Crypto", "src/Crypto/Argon2/include")]
        command += [str(unit)] + [str(args.build_dir.resolve() / p) for p in ("Core/Core.a", "Volume/Volume.a", "Platform/Platform.a")]
        command += ["-Wl,-dead_strip"] if sys.platform == "darwin" else ["-Wl,--gc-sections", "-pthread", "-ldl"]
        command += ["-o", str(work / "backup_retry")]
        subprocess.run(command, check=True, timeout=120)
        volume = work / "volume.hc"
        volume.touch()
        subprocess.run([str(work / "backup_retry"), str(volume)], check=True, timeout=20)


if __name__ == "__main__":
    main()
