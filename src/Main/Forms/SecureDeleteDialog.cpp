/*
 Copyright (c) 2025 Ömer Can VURAL
*/

#include "SecureDeleteDialog.h"
#include "Main/GraphicUserInterface.h"
#include <wx/filename.h>
#include <wx/wfstream.h>

namespace VeraCrypt
{
    // --- Algoritma Listesi (Windows RC dosyasındaki sıraya sadık kalındı) ---
    const wxString SecureDialogBase::AlgorithmChoices[] = {
        L"Zero (1-pass zeros) - Fast, basic",
        L"Random (1-pass random) - Good balance",
        L"DoD 3-pass - US DoD standard",
        L"DoD 7-pass - Highest DoD standard",
        L"NIST (1-pass random) - NIST recommendation",
        L"Gutmann (35-pass) - Maximum security",
        L"SSD (Encrypt + TRIM) - Optimized for SSD"
    };

    // =========================
    // SecureDialogBase (Ortak)
    // =========================
    SecureDialogBase::SecureDialogBase(wxWindow* parent, const wxString& title)
        : wxDialog(parent, wxID_ANY, title, wxDefaultPosition, wxDefaultSize, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
    {
        // Varsayılan olarak ortada aç
        Center();
    }

    ve_algorithm_t SecureDialogBase::GetSelectedAlgorithm() const
    {
        int sel = m_algoRadioBox->GetSelection();
        switch (sel)
        {
            case 0: return VE_ALG_ZERO;
            case 1: return VE_ALG_RANDOM;
            case 2: return VE_ALG_DOD3;
            case 3: return VE_ALG_DOD7;
            case 4: return VE_ALG_NIST;
            case 5: return VE_ALG_GUTMANN;
            case 6: return VE_ALG_SSD;
            default: return VE_ALG_NIST;
        }
    }

    // =========================
    // SecureDeleteDialog
    // =========================
    BEGIN_EVENT_TABLE(SecureDeleteDialog, SecureDialogBase)
        EVT_BUTTON(wxID_OK, SecureDeleteDialog::OnOK)
    END_EVENT_TABLE()

    SecureDeleteDialog::SecureDeleteDialog(wxWindow* parent)
        : SecureDialogBase(parent, _("Secure Delete"))
    {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
        
        // Açıklama
        mainSizer->Add(new wxStaticText(this, wxID_ANY, _("Secure Delete: Permanently erases file using selected secure deletion algorithm.")), 0, wxALL, 10);

        // Hedef Seçimi
        wxBoxSizer* rowSizer = new wxBoxSizer(wxHORIZONTAL);
        m_browseButton = new wxButton(this, wxID_ANY, _("Target..."));
        m_targetPathText = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
        
        rowSizer->Add(m_browseButton, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, 5);
        rowSizer->Add(m_targetPathText, 1, wxALIGN_CENTER_VERTICAL);
        mainSizer->Add(rowSizer, 0, wxALL | wxEXPAND, 10);

        m_browseButton->Connect(wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(SecureDeleteDialog::OnBrowse), NULL, this);

        // Algoritmalar (RadioBox)
        m_algoRadioBox = new wxRadioBox(this, wxID_ANY, _("Secure Deletion Algorithm"), 
            wxDefaultPosition, wxDefaultSize, 7, AlgorithmChoices, 1, wxRA_SPECIFY_COLS);
        
        // Windows kodunda varsayılan NIST idi
        m_algoRadioBox->SetSelection(4); 
        mainSizer->Add(m_algoRadioBox, 0, wxALL | wxEXPAND, 10);

        // Butonlar
        wxStdDialogButtonSizer* buttonSizer = new wxStdDialogButtonSizer();
        m_stdOKButton = new wxButton(this, wxID_OK);
        m_stdCancelButton = new wxButton(this, wxID_CANCEL);
        buttonSizer->AddButton(m_stdOKButton);
        buttonSizer->AddButton(m_stdCancelButton);
        buttonSizer->Realize();
        mainSizer->Add(buttonSizer, 0, wxALL | wxALIGN_RIGHT, 10);

        SetSizerAndFit(mainSizer);
    }

    void SecureDeleteDialog::OnBrowse(wxCommandEvent& event)
    {
        wxFileDialog dialog(this, _("Select File to Delete"), wxEmptyString, wxEmptyString, 
            _("All Files (*.*)|*.*"), wxFD_OPEN | wxFD_FILE_MUST_EXIST);

        if (dialog.ShowModal() == wxID_OK)
        {
            m_targetPathText->SetValue(dialog.GetPath());
        }
    }

    void SecureDeleteDialog::OnOK(wxCommandEvent& event)
    {
        wxString pathStr = m_targetPathText->GetValue();
        if (pathStr.IsEmpty())
        {
            Gui->ShowWarning(_("Please select a target file first."));
            return;
        }

        if (!Gui->AskYesNo(_("Are you sure you want to permanently delete this file?\nThis operation cannot be undone."), false, true))
            return;

        // Yapılandırma
        ve_options_t options;
        memset(&options, 0, sizeof(options));
        options.algorithm = GetSelectedAlgorithm();
        options.trim_mode = 0; // Auto
        options.quiet = 1;

        // İşlem Başlıyor (Wait Cursor)
        wxBusyCursor busy;

        // wxString -> UTF-8 char* dönüşümü (Linux için kritik)
        ve_status_t status = ve_erase_path(pathStr.ToUTF8().data(), &options);

        if (status == VE_SUCCESS)
        {
            Gui->ShowInfo(_("Secure deletion completed successfully!"));
            EndModal(wxID_OK);
        }
        else
        {
            const char* err = ve_last_error_message();
            wxString errMsg = err ? wxString::FromUTF8(err) : _("Unknown error");
            Gui->ShowError(_("Secure deletion failed:\n") + errMsg);
        }
    }


    // =========================
    // SecureCopyDialog
    // =========================
    BEGIN_EVENT_TABLE(SecureCopyDialog, SecureDialogBase)
        EVT_BUTTON(wxID_OK, SecureCopyDialog::OnOK)
    END_EVENT_TABLE()

    SecureCopyDialog::SecureCopyDialog(wxWindow* parent)
        : SecureDialogBase(parent, _("Secure Copy"))
    {
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // Açıklama
        mainSizer->Add(new wxStaticText(this, wxID_ANY, _("Secure Copy: Copies file to destination then securely deletes original using selected algorithm.")), 0, wxALL, 10);

        // Kaynak (Source)
        wxBoxSizer* rowSrc = new wxBoxSizer(wxHORIZONTAL);
        m_btnSource = new wxButton(this, wxID_ANY, _("Source..."));
        m_sourcePathText = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
        rowSrc->Add(m_btnSource, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, 5);
        rowSrc->Add(m_sourcePathText, 1, wxALIGN_CENTER_VERTICAL);
        mainSizer->Add(rowSrc, 0, wxALL | wxEXPAND, 5);

        m_btnSource->Connect(wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(SecureCopyDialog::OnBrowseSource), NULL, this);

        // Hedef (Destination) - Klasör seçimi
        wxBoxSizer* rowDst = new wxBoxSizer(wxHORIZONTAL);
        m_btnDest = new wxButton(this, wxID_ANY, _("Destination..."));
        m_destPathText = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
        rowDst->Add(m_btnDest, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, 5);
        rowDst->Add(m_destPathText, 1, wxALIGN_CENTER_VERTICAL);
        mainSizer->Add(rowDst, 0, wxALL | wxEXPAND, 5);

        m_btnDest->Connect(wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(SecureCopyDialog::OnBrowseDest), NULL, this);

        // Algoritmalar
        m_algoRadioBox = new wxRadioBox(this, wxID_ANY, _("Secure Deletion Algorithm (for Original File)"), 
            wxDefaultPosition, wxDefaultSize, 7, AlgorithmChoices, 1, wxRA_SPECIFY_COLS);
        m_algoRadioBox->SetSelection(4); // Default NIST
        mainSizer->Add(m_algoRadioBox, 0, wxALL | wxEXPAND, 10);
        
        // Not
        mainSizer->Add(new wxStaticText(this, wxID_ANY, _("Note: Original file will be securely deleted after copy.")), 0, wxALL, 10);

        // Butonlar
        wxStdDialogButtonSizer* buttonSizer = new wxStdDialogButtonSizer();
        m_stdOKButton = new wxButton(this, wxID_OK);
        m_stdCancelButton = new wxButton(this, wxID_CANCEL);
        buttonSizer->AddButton(m_stdOKButton);
        buttonSizer->AddButton(m_stdCancelButton);
        buttonSizer->Realize();
        mainSizer->Add(buttonSizer, 0, wxALL | wxALIGN_RIGHT, 10);

        SetSizerAndFit(mainSizer);
    }

    void SecureCopyDialog::OnBrowseSource(wxCommandEvent& event)
    {
        wxFileDialog dialog(this, _("Select Source File"), wxEmptyString, wxEmptyString, 
            _("All Files (*.*)|*.*"), wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (dialog.ShowModal() == wxID_OK)
            m_sourcePathText->SetValue(dialog.GetPath());
    }

    void SecureCopyDialog::OnBrowseDest(wxCommandEvent& event)
    {
        // Windows kodunda klasör seçici kullanılmış (SHBrowseForFolder)
        wxDirDialog dialog(this, _("Select Destination Folder"), wxEmptyString, wxDD_DEFAULT_STYLE | wxDD_DIR_MUST_EXIST);
        if (dialog.ShowModal() == wxID_OK)
            m_destPathText->SetValue(dialog.GetPath());
    }

    void SecureCopyDialog::OnOK(wxCommandEvent& event)
    {
        wxString srcPath = m_sourcePathText->GetValue();
        wxString dstDir = m_destPathText->GetValue();

        if (srcPath.IsEmpty() || dstDir.IsEmpty())
        {
            Gui->ShowWarning(_("Please select both source file and destination folder."));
            return;
        }

        // Hedef dosya yolunu oluştur (Klasör + Dosya Adı)
        wxFileName fn(srcPath);
        wxString dstPath = dstDir + wxFileName::GetPathSeparator() + fn.GetFullName();

        // Kopyalama İşlemi (wxWidgets ile)
        wxBusyCursor busy;
        
        if (!wxCopyFile(srcPath, dstPath))
        {
            Gui->ShowError(_("File copy failed!"));
            return;
        }

        // Kopyalama başarılı, şimdi orijinali güvenli sil
        ve_options_t options;
        memset(&options, 0, sizeof(options));
        options.algorithm = GetSelectedAlgorithm();
        options.trim_mode = 0;
        options.quiet = 1;

        ve_status_t status = ve_erase_path(srcPath.ToUTF8().data(), &options);

        if (status == VE_SUCCESS)
        {
            Gui->ShowInfo(_("Secure copy completed successfully!"));
            EndModal(wxID_OK);
        }
        else
        {
            const char* err = ve_last_error_message();
            wxString errMsg = err ? wxString::FromUTF8(err) : _("Unknown error");
            Gui->ShowError(_("Copy succeeded, but secure deletion of original failed:\n") + errMsg);
        }
    }
}