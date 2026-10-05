#!/usr/bin/env python3
# Copyright (c) 2026 AM Crypto. All rights reserved.
# Governed by the Apache License 2.0; see src/License.txt.

"""Check token inheritance and deliberate removal using the real wxWidgets dialogs.

Run after a Linux GUI make test build. Requires wx-config and Xvfb. No volume is opened,
no token is used, and the confirmation test declines the credential change.
"""

import argparse
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "Main/GraphicUserInterface.h"
#include "Main/Forms/ChangePasswordDialog.h"
#include <iostream>
#include <stdexcept>
using namespace VeraCrypt;
static void Require (bool value, const char *message) {
    if (!value) throw std::runtime_error (message);
}
class TestGui : public GraphicUserInterface {
public:
    mutable int Confirmations = 0;
    bool AskYesNo (const wxString &message, bool defaultYes, bool) const override {
        Require (message == LangString["TOKEN_KEY_REMOVAL_CONFIRM"] && !defaultYes,
            "Token removal did not ask a default-no confirmation");
        ++Confirmations;
        return false;
    }
};
class Dialog : public ChangePasswordDialog {
public:
    Dialog (shared_ptr<KeyfileList> files) : ChangePasswordDialog (nullptr,
        make_shared<VolumePath>("unused-volume"), Mode::ChangeKeyfiles,
        shared_ptr<VolumePassword>(), files, L"current-token", shared_ptr<VolumePassword>(), files) {}
    VolumePasswordPanel *Current () { return CurrentPasswordPanel; }
    VolumePasswordPanel *New () { return NewPasswordPanel; }
    void RefreshCredentials () { OnPasswordPanelUpdate(); }
    void Submit () { wxCommandEvent event; OnOKButtonClick (event); }
};
static wxTextCtrl *TokenField (VolumePasswordPanel *panel) {
    for (wxWindow *child : panel->GetChildren()) {
        auto text = dynamic_cast<wxTextCtrl *>(child);
        if (text && text->GetHint() == LangString["TOKEN_KEY_ORDINARY_MODE"]) return text;
    }
    throw std::runtime_error ("Token field is missing");
}
int main (int argc, char **argv) {
    auto gui = new TestGui;
    wxApp::SetInstance (gui);
    Require (wxEntryStart (argc, argv), "wxWidgets initialization failed");
    Gui = gui;
    LangString.Init();
    wchar_t program[] = L"panel-test", command[] = L"--change", path[] = L"unused-volume";
    wchar_t *arguments[] = {program, command, path};
    CmdLine.reset (new CommandLineInterface (3, arguments, UserInterfaceType::Graphic));
    auto files = make_shared<KeyfileList>();
    files->push_back (make_shared<Keyfile>(FilePath("unused-keyfile")));
    {
        Dialog dialog (files);
        Require (dialog.New()->GetSecurityTokenSchemeSpec() == L"current-token", "Initial token was not inherited");
        dialog.Current()->SetSecurityTokenSchemeSpec (L"changed-current-token");
        dialog.RefreshCredentials();
        Require (dialog.New()->GetSecurityTokenSchemeSpec() == L"changed-current-token", "Current token change was not followed");
        TokenField (dialog.New())->SetValue (wxEmptyString);
        wxTheApp->ProcessPendingEvents();
        Require (dialog.New()->IsSecurityTokenSchemeEdited(), "Explicit empty choice was not recorded");
        dialog.Current()->SetSecurityTokenSchemeSpec (L"another-current-token");
        dialog.RefreshCredentials();
        Require (dialog.New()->GetSecurityTokenSchemeSpec().empty(), "User's ordinary-mode choice was overwritten");
        dialog.Submit();
        Require (gui->Confirmations == 1, "Token removal did not require confirmation");
        TokenField (dialog.New())->SetValue (L"new-token");
        wxTheApp->ProcessPendingEvents();
        dialog.Current()->SetSecurityTokenSchemeSpec (L"yet-another-current-token");
        dialog.RefreshCredentials();
        Require (dialog.New()->GetSecurityTokenSchemeSpec() == L"new-token", "Explicit new token was overwritten");
    }
    CmdLine->ArgNewSecurityTokenSchemeSpecified = true;
    {
        Dialog dialog (files);
        Require (dialog.New()->GetSecurityTokenSchemeSpec().empty(), "Explicit CLI opt-out was overwritten");
    }
    CmdLine.reset();
    wxEntryCleanup();
    Gui = nullptr;
    std::cout << "PASS: real GUI token inheritance, explicit empty/new selections and removal confirmation\n";
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "src")
    parser.add_argument("--xvfb", default=shutil.which("Xvfb"))
    args = parser.parse_args()
    if not args.xvfb:
        parser.error("Xvfb is required; use --xvfb /path/to/Xvfb")
    build = args.build_dir.resolve()
    objects = sorted((build / "Main").glob("*.o")) + sorted((build / "Main/Forms").glob("*.o"))
    if not (build / "Main/GraphicUserInterface.o").exists():
        parser.error("A GUI build is required")
    flags = shlex.split(os.environ.get("CXX", "c++")) + ["-std=c++11", "-DTC_UNIX", "-DTC_LINUX"]
    flags += ["-I" + str(ROOT / p) for p in ("src", "src/Main", "src/PKCS11", "src/Crypto", "src/Crypto/Argon2/include")]
    flags += shlex.split(subprocess.check_output(["wx-config", "--cxxflags"], text=True))
    libraries = [str(build / p) for p in ("Core/Core.a", "Driver/Fuse/Driver.a", "Volume/Volume.a", "Platform/Platform.a")]
    libraries += shlex.split(subprocess.check_output(["wx-config", "--libs", "adv,core,base"], text=True))
    libraries += shlex.split(subprocess.check_output(["pkg-config", "--libs", "fuse3"], text=True))
    libraries += ["-pthread", "-ldl"]
    with tempfile.TemporaryDirectory(prefix="vc-token-panel-") as temporary:
        work = Path(temporary)
        source, executable = work / "panel.cpp", work / "panel"
        source.write_text(HARNESS)
        subprocess.run(flags + [str(source)] + list(map(str, objects)) + libraries + ["-o", str(executable)], check=True, timeout=120)
        reader, writer = os.pipe()
        server = subprocess.Popen([args.xvfb, "-displayfd", str(writer), "-screen", "0", "1600x1200x24", "-nolisten", "tcp"], pass_fds=(writer,))
        os.close(writer)
        try:
            if not select.select([reader], [], [], 20)[0]:
                raise RuntimeError("Xvfb did not start")
            display = os.read(reader, 32).decode().strip()
            if not display:
                raise RuntimeError("Xvfb failed to allocate a display")
            env = dict(os.environ, DISPLAY=":" + display, LANG="C", LC_ALL="C", XDG_CONFIG_HOME=str(work / "config"))
            subprocess.run([str(executable)], env=env, check=True, timeout=30)
        finally:
            os.close(reader)
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
