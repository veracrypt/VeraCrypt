#!/usr/bin/env python3
"""Check token credential and backup workflows without mounting any volumes.

Run after `make WITHFUSE3=1 test`. Requires Python 3, a C++11 compiler and
wx-config. The CLI parser is compiled unchanged. Wizard validation and backup
publication use the production method bodies with scripted UI/token outcomes;
keyfile mixing, credential types and filesystem publication are real.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

COMMON = r'''
#include "Core/MountOptions.h"
#include "Platform/AtomicFile.h"
#include "Common/MockSecurityToken.h"
#include <iostream>
#include <stdexcept>
#include <unistd.h>
using namespace VeraCrypt;
static void Require (bool condition, const char *message) {
    if (!condition) throw std::runtime_error (message);
}
static shared_ptr<VolumePassword> MakePassword (const string &text) {
    return make_shared<VolumePassword> (reinterpret_cast<const uint8 *>(text.data()), text.size());
}
static void WriteFile (const FilePath &path, const string &text) {
    File file;
    file.Open (path, File::CreateWrite);
    file.Write (ConstBufferPtr (reinterpret_cast<const uint8 *>(text.data()), text.size()));
}
static string ReadFile (const FilePath &path) {
    File file;
    file.Open (path);
    string text (file.Length(), '\0');
    if (!text.empty()) file.ReadCompleteBuffer (BufferPtr (reinterpret_cast<uint8 *> (&text[0]), text.size()));
    return text;
}
'''

CLI = r'''
#include "Main/CommandLineInterface.h"
#include "Main/LanguageStrings.h"
#include "Main/Application.h"
#include <wx/init.h>
namespace VeraCrypt {
LanguageStrings::LanguageStrings () {}
LanguageStrings::~LanguageStrings () {}
wxString LanguageStrings::operator[] (const string &key) const { return wxString::FromUTF8 (key.c_str()); }
LanguageStrings LangString;
UserInterfaceType::Enum Application::mUserInterfaceType = UserInterfaceType::Text;
// These parser-only cases must not contact a core service.
unique_ptr<CoreBase> Core;
void UserPreferences::Load () { throw std::runtime_error ("Unexpected preferences access"); }
}
static MountOptions Parse (std::initializer_list<wstring> options) {
    vector<wstring> arguments {L"credential-test", L"--text", L"--non-interactive", L"--mount"};
    arguments.insert (arguments.end(), options.begin(), options.end());
    vector<wchar_t *> argv;
    for (auto &argument : arguments) argv.push_back (&argument[0]);
    CommandLineInterface cli (argv.size(), argv.data(), UserInterfaceType::Text);
    return cli.ArgMountOptions;
}
int main () {
    wxInitializer wx;
    Require (wx.IsOk(), "wxWidgets initialization failed");
    auto selected = Parse ({L"--protection-security-token-key=test"});
    Require (selected.Protection == VolumeProtection::HiddenVolumeReadOnly
        && selected.ProtectionSecurityTokenSchemeSpec == L"test", "Selector did not request hidden protection");
    Require (Parse ({L"--protection-security-token-key=test", L"--mount-options=ro"}).Protection
        == VolumeProtection::ReadOnly, "Selector overrode a read-only mount");
    Require (Parse ({L"--protection-security-token-key="}).Protection == VolumeProtection::None,
        "Empty selector unexpectedly enabled protection");
    Require (Parse ({L"--protection-security-token-key=", L"--protection-password=hidden"}).Protection
        == VolumeProtection::HiddenVolumeReadOnly, "Empty selector disabled requested protection");
    std::cout << "PASS: protection selector parsing and read-only precedence\n";
}
'''

WIZARD = r'''
namespace VeraCrypt {
static struct {
    struct Preferences { bool EMVSupportEnabled = false; } Settings;
    const Preferences &GetPreferences () const { return Settings; }
    void ShowError (const exception &) { ++Errors; }
    void ShowError (const wstring &) { ++Errors; }
    int Errors = 0;
} GuiInstance, *Gui = &GuiInstance;
static struct { wstring operator[] (const char *) const { return L"same credentials"; } } LangString;
class VolumeCreationWizard {
public:
    shared_ptr<VolumePassword> GetPasswordKey ();
    bool ValidateHiddenVolumePassword ();
    shared_ptr<VolumePassword> Password, PasswordKey, OuterPassword;
    shared_ptr<KeyfileList> Keyfiles;
    wstring SecurityTokenSchemeSpec = L"test";
    int Pim = 0, OuterPim = 0;
};
// WIZARD_METHODS
}
class TestToken : public MockSecurityTokenImpl {
public:
    int Failure = 0, DecryptCalls = 0;
    void GetDecryptedData (const SecurityTokenScheme &key, const vector<uint8> &input, vector<uint8> &output) {
        ++DecryptCalls;
        if (Failure == 1) throw UserAbort (SRC_POS);
        if (Failure == 2) throw Pkcs11Exception (CKR_DEVICE_REMOVED);
        MockSecurityTokenImpl::GetDecryptedData (key, input, output);
    }
};
int main (int argc, char **argv) {
    Require (argc == 2, "Missing scratch directory");
    auto token = make_shared<TestToken>();
    SecurityToken::UseImpl (token);
    FilePath path (string (argv[1]) + "/encrypted-keyfile");
    SecureBuffer data (256);
    for (size_t i = 0; i < data.Size(); ++i) data[i] = static_cast<uint8> (i * 17 + 9);
    Keyfile::CreateBluekey (path, L"test", data);
    VolumeCreationWizard wizard;
    wizard.Password = MakePassword ("volume password");
    wizard.Keyfiles = make_shared<KeyfileList>();
    wizard.Keyfiles->push_back (make_shared<Keyfile> (path));
    wizard.OuterPassword = Keyfile::ApplyListToPassword (wizard.Keyfiles, wizard.Password, L"test");
    for (int fault : {1, 2}) {
        token->Failure = fault;
        Require (!wizard.ValidateHiddenVolumePassword(), "A failed token operation accepted hidden credentials");
        Require (!wizard.PasswordKey, "Failed derivation cached substitute credentials");
    }
    token->Failure = 0;
    Require (!wizard.ValidateHiddenVolumePassword(), "Identical effective outer/hidden credentials were accepted");
    wizard.Pim = 1;
    Require (wizard.ValidateHiddenVolumePassword(), "Different PIM was rejected");
    auto accepted = wizard.GetPasswordKey();
    int calls = token->DecryptCalls;
    token->Failure = 2;
    Require (wizard.GetPasswordKey() == accepted && token->DecryptCalls == calls,
        "Validated credentials were derived again before creation");
    // Editing credentials invalidates the wizard's per-operation result.
    wizard.PasswordKey.reset();
    wizard.Password = MakePassword ("different volume password");
    Require (!wizard.ValidateHiddenVolumePassword() && !wizard.PasswordKey,
        "A credential edit retained the previous effective password after failure");
    token->Failure = 0;
    Require (wizard.ValidateHiddenVolumePassword() && *wizard.GetPasswordKey() != *accepted,
        "Changed credentials did not produce a fresh effective password");
    std::cout << "PASS: wizard cancellation, token errors, equality checks and credential reuse\n";
}
'''

BACKUP = r'''
#include <wx/string.h>
namespace BackupWorkflow {
static string Destination;
static int FailureStage, CurrentStage;
static bool TokenFailure, IncludeHidden;
static void Step () {
    if (CurrentStage++ == FailureStage) {
        if (TokenFailure) throw Pkcs11Exception (CKR_DEVICE_REMOVED);
        throw UserAbort (SRC_POS);
    }
}
struct Layout { size_t GetHeaderSize () const { return 256; } };
struct Header { explicit Header (uint8 value) : Value (value) {} uint8 Value; };
struct EncryptionAlgorithm { void Encrypt (const BufferPtr &buffer) { memset (buffer.Get(), 99, buffer.Size()); } };
struct Volume {
    explicit Volume (uint8 value) : Value (value) {}
    shared_ptr<Layout> GetLayout () const { return make_shared<Layout>(); }
    shared_ptr<Header> GetHeader () const { return make_shared<Header> (Value); }
    shared_ptr<EncryptionAlgorithm> GetEncryptionAlgorithm () const { return make_shared<EncryptionAlgorithm>(); }
    uint8 Value;
};
static struct {
    void ReEncryptVolumeHeaderWithNewSalt (const BufferPtr &buffer, shared_ptr<Header> header,
        shared_ptr<VolumePassword>, int, shared_ptr<KeyfileList>, wstring, bool) {
        Step();
        memset (buffer.Get(), header->Value, buffer.Size());
    }
    void RandomizeEncryptionAlgorithmKey (shared_ptr<EncryptionAlgorithm>) {}
} CoreInstance, *Core = &CoreInstance;
struct ReEncryptHeaderThreadRoutine {
    ReEncryptHeaderThreadRoutine (const BufferPtr &buffer, shared_ptr<Header> header,
        shared_ptr<VolumePassword> password, int pim, shared_ptr<KeyfileList> files, wstring descriptor, bool emv)
        : Buffer (buffer), H (header), Password (password), Pim (pim), Files (files), Descriptor (descriptor), Emv (emv) {}
    BufferPtr Buffer; shared_ptr<Header> H; shared_ptr<VolumePassword> Password; int Pim;
    shared_ptr<KeyfileList> Files; wstring Descriptor; bool Emv;
    void Execute () { Core->ReEncryptVolumeHeaderWithNewSalt (Buffer, H, Password, Pim, Files, Descriptor, Emv); }
};
struct RandomNumberGenerator {
    static void Start () {}
    static void SetEnrichedByUserStatus (bool) {}
};
struct wxBusyCursor {};
static struct { wxString operator[] (const char *) const { return L"Backup %s?"; } } LangString;
class UI {
public:
    bool AskYesNo (const wxString &, bool) const { return true; }
    void ShowString (const wxString &) const {}
    void ShowInfo (const wxString &) const {}
    void ShowWarning (const wxString &) const {}
    FilePath AskFilePath () const { return FilePath (Destination); }
    FilePathList SelectFiles (int, const wxString &, bool, bool) const {
        FilePathList files; files.push_back (make_shared<FilePath> (Destination)); return files;
    }
    void UserEnrichRandomPool (void * = nullptr) const { Step(); }
    void ExecuteWaitThreadRoutine (int, ReEncryptHeaderThreadRoutine *routine) const { routine->Execute(); }
};
class TextUserInterface : public UI { public: void BackupVolumeHeaders (shared_ptr<VolumePath>) const; };
class GraphicUserInterface : public UI { public: void BackupVolumeHeaders (shared_ptr<VolumePath>) const; };
void TextUserInterface::BackupVolumeHeaders (shared_ptr<VolumePath> volumePath) const {
    auto normalVolume = make_shared<Volume> (17);
    auto hiddenVolume = IncludeHidden ? make_shared<Volume> (33) : shared_ptr<Volume>();
    MountOptions normalVolumeMountOptions, hiddenVolumeMountOptions;
    bool masterKeyVulnerable = false;
    // TEXT_BACKUP_TAIL
void GraphicUserInterface::BackupVolumeHeaders (shared_ptr<VolumePath> volumePath) const {
    auto normalVolume = make_shared<Volume> (17);
    auto hiddenVolume = IncludeHidden ? make_shared<Volume> (33) : shared_ptr<Volume>();
    MountOptions normalVolumeMountOptions, hiddenVolumeMountOptions;
    bool masterKeyVulnerable = false;
    int parent = 0;
    // GUI_BACKUP_TAIL
static void Run (bool gui, bool existing) {
    if (existing) WriteFile (FilePath (Destination), "previous backup");
    else unlink (Destination.c_str());
    CurrentStage = 0;
    bool failed = false;
    try {
        auto path = make_shared<VolumePath> (wstring (L"unused-volume-path"));
        if (gui) GraphicUserInterface().BackupVolumeHeaders (path);
        else TextUserInterface().BackupVolumeHeaders (path);
    } catch (const UserAbort &) { failed = true; }
    catch (const Pkcs11Exception &) { failed = true; }
    Require (failed == (FailureStage >= 0), "Backup did not report the injected cancellation/token failure");
    if (failed) {
        Require (existing ? ReadFile (FilePath (Destination)) == "previous backup" : access (Destination.c_str(), F_OK) != 0,
            "Failed backup modified the destination");
    } else {
        Require (ReadFile (FilePath (Destination)) == string (256, 17) + string (256, IncludeHidden ? 33 : 99),
            "Backup did not publish both complete header blocks");
    }
}
}
int main (int argc, char **argv) {
    Require (argc == 2, "Missing scratch directory");
    using namespace BackupWorkflow;
    Destination = string (argv[1]) + "/header-backup";
    for (bool gui : {false, true}) for (bool hidden : {false, true}) for (bool existing : {false, true}) {
        IncludeHidden = hidden;
        for (int stage = -1; stage <= (hidden ? 2 : 1); ++stage) for (bool token : {false, true}) {
            FailureStage = stage; TokenFailure = token; Run (gui, existing);
        }
    }
    std::cout << "PASS: GUI/CLI backup cancellation and token errors preserve existing/absent destinations\n";
}
'''


CREATOR = r'''
#include "Core/Core.h"
#include "Core/VolumeCreator.h"
namespace VeraCrypt { unique_ptr<CoreBase> Core; }
class FailingToken : public MockSecurityTokenImpl {
public:
    void GetDecryptedData (const SecurityTokenScheme &, const vector<uint8> &, vector<uint8> &) {
        throw UserAbort ("cancelled token operation");
    }
};
int main (int argc, char **argv) {
    Require (argc == 2, "Missing scratch directory");
    const FilePath keyfile (string (argv[1]) + "/creator-keyfile");
    WriteFile (keyfile, string (256, 'x'));
    SecurityToken::UseImpl (make_shared<FailingToken>());
    for (bool existing : {false, true}) {
        const FilePath destination (string (argv[1]) + (existing ? "/creator-existing" : "/creator-new"));
        if (existing) WriteFile (destination, "existing contents");
        auto options = make_shared<VolumeCreationOptions>();
        options->Path = VolumePath (wstring (destination));
        options->Keyfiles = make_shared<KeyfileList>();
        options->Keyfiles->push_back (make_shared<Keyfile> (keyfile));
        options->SecurityTokenSchemeSpec = L"test";
        bool cancelled = false;
        try { VolumeCreator creator; creator.CreateVolume (options); }
        catch (const UserAbort &) { cancelled = true; }
        Require (cancelled, "Creation did not resolve credentials before contacting the core");
        Require (existing ? ReadFile (destination) == "existing contents" : !destination.IsFile(),
            "Credential failure modified the creation destination");
    }
    SecurityToken::UseImpl (shared_ptr<SecurityTokenIface>());
    std::cout << "PASS: common volume creator preflights credentials before opening existing/new destinations\n";
}
'''


def method(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    args = parser.parse_args()
    source = (ROOT / "src/Main/Forms/VolumeCreationWizard.cpp").read_text()
    wizard = WIZARD.replace("// WIZARD_METHODS", "\n".join(method(source, signature) for signature in (
        "shared_ptr <VolumePassword> VolumeCreationWizard::GetPasswordKey ()",
        "bool VolumeCreationWizard::ValidateHiddenVolumePassword ()")))
    backup = BACKUP
    for kind, filename, classname in (("TEXT", "TextUserInterface.cpp", "TextUserInterface"),
                                      ("GUI", "GraphicUserInterface.cpp", "GraphicUserInterface")):
        source = (ROOT / "src/Main" / filename).read_text()
        body = method(source, "void " + classname + "::BackupVolumeHeaders (")
        tail = body[body.index("// Ask user to select backup file path"):]
        backup = backup.replace("// " + kind + "_BACKUP_TAIL", tail)
    flags = shlex.split(os.environ.get("CXX", "c++")) + ["-std=c++11", "-DTC_UNIX", "-DTC_NO_GUI", "-DwxUSE_GUI=0"]
    flags += ["-DTC_MACOSX"] if sys.platform == "darwin" else ["-DTC_LINUX"]
    flags += ["-I" + str(ROOT / p) for p in ("src", "src/Main", "src/PKCS11", "src/Crypto", "src/Crypto/Argon2/include")]
    flags += shlex.split(subprocess.check_output(["wx-config", "--cxxflags"], text=True))
    libraries = [str(args.build_dir.resolve() / p) for p in ("Core/Core.a", "Volume/VolumeTest.a", "Volume/Volume.a", "Platform/Platform.a")]
    libraries += shlex.split(subprocess.check_output(["wx-config", "--libs", "base"], text=True))
    libraries += ["-Wl,-dead_strip"] if sys.platform == "darwin" else ["-Wl,--gc-sections", "-pthread", "-ldl"]
    with tempfile.TemporaryDirectory(prefix="vc-token-workflows-") as temporary:
        work = Path(temporary)
        for name, harness, extra in (("cli", CLI, [str(ROOT / "src/Main/CommandLineInterface.cpp")]),
                                     ("wizard", wizard, []), ("backup", backup, []), ("creator", CREATOR, [])):
            unit, executable = work / (name + ".cpp"), work / name
            unit.write_text(COMMON + harness)
            subprocess.run(flags + [str(unit)] + extra + libraries + ["-o", str(executable)], check=True, timeout=120)
            subprocess.run([str(executable), str(work)], check=True, timeout=30)


if __name__ == "__main__":
    main()
