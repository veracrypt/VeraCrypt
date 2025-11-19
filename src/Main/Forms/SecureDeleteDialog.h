/*
 Copyright (c) 2025 Ömer Can VURAL
*/

#ifndef TC_HEADER_Main_Forms_SecureDeleteDialog
#define TC_HEADER_Main_Forms_SecureDeleteDialog

#include "Forms.h"
#include "Main/Main.h"
#include <wx/valgen.h>

// Veraser C motorunu dahil ediyoruz (C++ içinden C çağırmak için)
extern "C" {
#include "../../Mount/veraser.h"
}

namespace VeraCrypt
{
    // --- Ortak Temel Sınıf (Algoritma seçimi vb. ortak olduğu için) ---
    class SecureDialogBase : public wxDialog
    {
    public:
        SecureDialogBase(wxWindow* parent, const wxString& title);

    protected:
        // Windows'taki algoritma listesiyle birebir eşleşen yardımcı fonksiyon
        ve_algorithm_t GetSelectedAlgorithm() const;
        
        // GUI Elemanları
        wxRadioBox* m_algoRadioBox;
        wxButton* m_stdOKButton;
        wxButton* m_stdCancelButton;
        
        // Algoritma isimleri listesi (RC dosyasındaki sıraya göre)
        static const wxString AlgorithmChoices[];
    };

    // --- Secure Delete Dialog ---
    class SecureDeleteDialog : public SecureDialogBase
    {
    public:
        SecureDeleteDialog(wxWindow* parent);

    protected:
        void OnBrowse(wxCommandEvent& event);
        void OnOK(wxCommandEvent& event);

        wxTextCtrl* m_targetPathText;
        wxButton* m_browseButton;

        DECLARE_EVENT_TABLE()
    };

    // --- Secure Copy Dialog ---
    class SecureCopyDialog : public SecureDialogBase
    {
    public:
        SecureCopyDialog(wxWindow* parent);

    protected:
        void OnBrowseSource(wxCommandEvent& event);
        void OnBrowseDest(wxCommandEvent& event);
        void OnOK(wxCommandEvent& event);

        wxTextCtrl* m_sourcePathText;
        wxTextCtrl* m_destPathText;
        wxButton* m_btnSource;
        wxButton* m_btnDest;

        DECLARE_EVENT_TABLE()
    };
}

#endif // TC_HEADER_Main_Forms_SecureDeleteDialog