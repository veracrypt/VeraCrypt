/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include <Shlobj.h>
#include <Richedit.h>
#include <io.h>
#include <stdio.h>
#include <time.h>
#include "SelfExtract.h"
#include "Wizard.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Common/Resource.h"
#include "Resource.h"
#include "Setup.h"
#include <tchar.h>
#include <Strsafe.h>

using namespace std;

enum wizard_pages
{
	INTRO_PAGE,
	WIZARD_MODE_PAGE,
	INSTALL_OPTIONS_PAGE,
	INSTALL_PROGRESS_PAGE,
	EXTRACTION_OPTIONS_PAGE,
	EXTRACTION_PROGRESS_PAGE,
	DONATIONS_PAGE
};

HWND hCurPage = NULL;		/* Handle to current wizard page */
int nCurPageNo = -1;		/* The current wizard page */
wchar_t WizardDestInstallPath [TC_MAX_PATH];
wchar_t WizardDestExtractPath [TC_MAX_PATH];
wchar_t SelfFile [TC_MAX_PATH];

HBITMAP hbmWizardBitmapRescaled = NULL;

BOOL bExtractOnly = FALSE;
BOOL bLicenseAccepted = FALSE;
BOOL bOpenContainingFolder = TRUE;
BOOL bExtractionSuccessful = FALSE;
BOOL bStartInstall = FALSE;
BOOL bStartExtraction = FALSE;
BOOL bInProgress = FALSE;
BOOL bPromptTutorial = FALSE;
BOOL bPromptReleaseNotes = FALSE;

int nPbar = 0;			/* Control ID of progress bar */

static HFONT hDonTextFont;
static BOOL OsPrngAvailable;
static HCRYPTPROV hCryptProv;
static int DonColorSchemeId;
static COLORREF DonTextColor;
static COLORREF DonBkgColor;

wstring DonText = L"";

void localcleanupwiz (void)
{
	/* Delete buffered bitmaps (if any) */
	if (hbmWizardBitmapRescaled != NULL)
	{
		DeleteObject ((HGDIOBJ) hbmWizardBitmapRescaled);
		hbmWizardBitmapRescaled = NULL;
	}

	if (hCryptProv != 0)
	{
		OsPrngAvailable = FALSE;
		CryptReleaseContext (hCryptProv, 0);
		hCryptProv = 0;
	}

	if (hDonTextFont != NULL)
	{
		DeleteObject (hDonTextFont);
		hDonTextFont = NULL;
	}
}

static void InitWizardDestInstallPath (void)
{
	if (wcslen (WizardDestInstallPath) < 2)
	{
		StringCbCopyW (WizardDestInstallPath, sizeof(WizardDestInstallPath), InstallationPath);
		if (WizardDestInstallPath [wcslen (WizardDestInstallPath) - 1] != L'\\')
		{
			StringCbCatW (WizardDestInstallPath, sizeof(WizardDestInstallPath), L"\\");
		}
	}
}

void LoadPage (HWND hwndDlg, int nPageNo)
{
	RECT rD, rW;

	if (hCurPage != NULL)
	{
		DestroyWindow (hCurPage);
	}

	InvalidateRect (GetDlgItem (MainDlg, IDC_MAIN_CONTENT_CANVAS), NULL, TRUE);

	GetWindowRect (GetDlgItem (hwndDlg, IDC_POS_BOX), &rW);

	nCurPageNo = nPageNo;

	switch (nPageNo)
	{
	case INTRO_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INTRO_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case WIZARD_MODE_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_WIZARD_MODE_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case INSTALL_OPTIONS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_INSTALL_OPTIONS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case INSTALL_PROGRESS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PROGRESS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case EXTRACTION_OPTIONS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_EXTRACTION_OPTIONS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case EXTRACTION_PROGRESS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_PROGRESS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;

	case DONATIONS_PAGE:
		hCurPage = CreateDialogW (hInst, MAKEINTRESOURCEW (IDD_DONATIONS_PAGE_DLG), hwndDlg,
					 (DLGPROC) PageDialogProc);
		break;
	}

	rD.left = 15;
	rD.top = 45;
	rD.right = 0;
	rD.bottom = 0;
	MapDialogRect (hwndDlg, &rD);

	if (hCurPage != NULL)
	{
		MoveWindow (hCurPage, rD.left, rD.top, rW.right - rW.left, rW.bottom - rW.top, TRUE);
		ShowWindow (hCurPage, SW_SHOWNORMAL);
	}

	/* Refresh the graphics (white background of some texts, etc.) */
	RefreshUIGFX ();
}


static int GetDonVal (int minVal, int maxVal)
{
	static BOOL prngInitialized = FALSE;
	static unsigned __int8 buffer [2];

	if (!prngInitialized)
	{
		if (!CryptAcquireContext (&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
			OsPrngAvailable = FALSE;
		else
			OsPrngAvailable = TRUE;

		prngInitialized = TRUE;
	}

	if (OsPrngAvailable && CryptGenRandom (hCryptProv, sizeof (buffer), buffer) != 0)
	{
		return  ((int) ((double) *((uint16 *) buffer) / (0xFFFF+1) * (maxVal + 1 - minVal)) + minVal);
	}
	else
		return maxVal;
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK PageDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static char PageDebugId[128];
	WORD lw = LOWORD (wParam);
	WORD hw = HIWORD (wParam);

	hCurPage = hwndDlg;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		LocalizeDialog (hwndDlg, "IDD_INSTL_DLG");

		StringCbPrintfA (PageDebugId, sizeof(PageDebugId), "SETUP_WIZARD_PAGE_%d", nCurPageNo);
		LastDialogId = PageDebugId;

		switch (nCurPageNo)
		{
		case INTRO_PAGE:
			{
				char *licenseText = NULL;

				// increase size limit of rich edit control
				SendMessage (GetDlgItem (hwndDlg, IDC_LICENSE_TEXT), EM_EXLIMITTEXT, 0, -1);
				// Left margin for license text
				SendMessage (GetDlgItem (hwndDlg, IDC_LICENSE_TEXT), EM_SETMARGINS, (WPARAM) EC_LEFTMARGIN, (LPARAM) CompensateXDPI (4));

				licenseText = GetLegalNotices ();
				if (licenseText != NULL)
				{
					SETTEXTEX TextInfo = {0};

					TextInfo.flags = ST_SELECTION;
					TextInfo.codepage = CP_ACP;

					SendMessage(GetDlgItem (hwndDlg, IDC_LICENSE_TEXT), EM_SETTEXTEX, (WPARAM)&TextInfo, (LPARAM)licenseText);
					free (licenseText);
				}
				else
				{
					Error("CANNOT_DISPLAY_LICENSE", hwndDlg);
					exit (1);
				}

				/* For legal reasons, some of the following texts cannot be localized by third parties. */

				SetCheckBox (hwndDlg, IDC_AGREE, bLicenseAccepted);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), L"Please read the license terms");
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), L"You must accept these license terms before you can use, extract, or install VeraCrypt.");
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), L"IMPORTANT: By checking the checkbox below, you accept these license terms and signify that you understand and agree to them. Please click the 'arrow down' icon to see the rest of the license.");	// Cannot be localized by third parties (for legal reasons).
				//SendMessage (GetDlgItem (hwndDlg, IDC_BOX_HELP), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_AGREE), L"I &accept the license terms");	// Cannot be localized by third parties (for legal reasons).
				//SetWindowTextW (GetDlgItem (hwndDlg, IDC_DISAGREE), L"I &do not accept the license terms");

				//SendMessage (GetDlgItem (hwndDlg, IDC_AGREE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
				//SendMessage (GetDlgItem (hwndDlg, IDC_DISAGREE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

				EnableWindow (GetDlgItem (hwndDlg, IDC_AGREE), TRUE);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), bLicenseAccepted);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), bLicenseAccepted);
			}
			return 1;

		case WIZARD_MODE_PAGE:
			{
				LONG driverVersion;

				DetermineUpgradeDowngradeStatus (TRUE, &driverVersion);

				if (bRepairMode || bReinstallMode)
				{
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), GetString ("REPAIR_REINSTALL"));
					bExtractOnly = FALSE;
				}
				else if (bUpgrade)
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), GetString ("UPGRADE"));

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_MODE_TITLE"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_MODE_INFO"));

				SendMessage (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);
				SendMessage (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_EXTRACT_ONLY), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

				CheckButton (GetDlgItem (hwndDlg, bExtractOnly ? IDC_WIZARD_MODE_EXTRACT_ONLY : IDC_WIZARD_MODE_INSTALL));

				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("SETUP_MODE_HELP_EXTRACT"));

				if (!bRepairMode)
					SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP2), GetString (bUpgrade ? "SETUP_MODE_HELP_UPGRADE" : "SETUP_MODE_HELP_INSTALL"));

				EnableWindow (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_EXTRACT_ONLY), !bRepairMode);
				EnableWindow (GetDlgItem (hwndDlg, IDC_BOX_HELP), !bRepairMode);
				EnableWindow (GetDlgItem (hwndDlg, IDC_WIZARD_MODE_INSTALL), TRUE);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDCANCEL), GetString ("CANCEL"));
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			}
			return 1;

		case EXTRACTION_OPTIONS_PAGE:

			if (wcslen(WizardDestExtractPath) < 2)
			{
				StringCbCopyW (WizardDestExtractPath, sizeof(WizardDestExtractPath), SetupFilesDir);
				StringCbCatNW (WizardDestExtractPath, sizeof(WizardDestExtractPath), L"VeraCrypt\\", ARRAYSIZE (WizardDestExtractPath) - wcslen (WizardDestExtractPath) - 1);
			}

			SendMessage (GetDlgItem (hwndDlg, IDC_DESTINATION), EM_LIMITTEXT, TC_MAX_PATH - 1, 0);

			SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestExtractPath);

			SetCheckBox (hwndDlg, IDC_OPEN_CONTAINING_FOLDER, bOpenContainingFolder);

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("EXTRACTION_OPTIONS_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("EXTRACTION_OPTIONS_INFO"));
			SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AUTO_FOLDER_CREATION"));

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("EXTRACT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			return 1;

		case EXTRACTION_PROGRESS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("EXTRACTING_VERB"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("EXTRACTION_PROGRESS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));

			if (bStartExtraction)
			{
				/* Start extraction */

				LastDialogId = "EXTRACTION_IN_PROGRESS";

				WaitCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);

				if (WizardDestExtractPath [wcslen(WizardDestExtractPath)-1] != L'\\')
					StringCbCatW (WizardDestExtractPath, sizeof(WizardDestExtractPath), L"\\");

				StringCbCopyW (DestExtractPath, sizeof(DestExtractPath), WizardDestExtractPath);

				InitProgressBar ();

				bInProgress = TRUE;
				bStartExtraction = FALSE;

				_beginthread (ExtractAllFilesThread, 0, (void *) hwndDlg);
			}
			else
			{
				NormalCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			}

			return 1;

		case INSTALL_OPTIONS_PAGE:
			{
				LONG driverVersion;

				DetermineUpgradeDowngradeStatus (TRUE, &driverVersion);

				if (!bDesktopIconStatusDetermined)
				{
					bDesktopIcon = !bUpgrade;
					bDesktopIconStatusDetermined = TRUE;
				}

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_OPTIONS_TITLE"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_OPTIONS_INFO"));
				SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_HELP), GetString ("AUTO_FOLDER_CREATION"));

				InitWizardDestInstallPath ();

				SendMessage (GetDlgItem (hwndDlg, IDC_DESTINATION), EM_LIMITTEXT, TC_MAX_PATH - 1, 0);

				SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestInstallPath);

				if (bUpgrade)
				{
					SetWindowTextW (GetDlgItem (hwndDlg, IDT_INSTALL_DESTINATION), GetString ("SETUP_UPGRADE_DESTINATION"));
					EnableWindow (GetDlgItem (hwndDlg, IDC_DESTINATION), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_BROWSE), FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_ALL_USERS), FALSE);

					wchar_t path[MAX_PATH];
					SHGetSpecialFolderPath (hwndDlg, path, CSIDL_COMMON_PROGRAMS, 0);
					bForAllUsers = (_waccess ((wstring (path) + L"\\" _T(TC_APP_NAME)).c_str(), 0) == 0);
				}

				// System Restore
				SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, bSystemRestore);
				if (SystemRestoreDll == 0)
				{
					SetCheckBox (hwndDlg, IDC_SYSTEM_RESTORE, FALSE);
					EnableWindow (GetDlgItem (hwndDlg, IDC_SYSTEM_RESTORE), FALSE);
				}

				SetCheckBox (hwndDlg, IDC_ALL_USERS, bForAllUsers);
				SetCheckBox (hwndDlg, IDC_FILE_TYPE, bRegisterFileExt);
				SetCheckBox (hwndDlg, IDC_PROG_GROUP, bAddToStartMenu);
				SetCheckBox (hwndDlg, IDC_DESKTOP_ICON, bDesktopIcon);

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString (bUpgrade ? "UPGRADE" : "INSTALL"));
				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);
			}
			return 1;

		case INSTALL_PROGRESS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString ("SETUP_PROGRESS_TITLE"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_PROGRESS_INFO"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_PREV), GetString ("PREV"));

			if (bStartInstall)
			{
				/* Start install */

				LastDialogId = "INSTALL_IN_PROGRESS";

				SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), GetString ("NEXT"));

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), FALSE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), FALSE);

				InitProgressBar ();

				if (WizardDestInstallPath [wcslen(WizardDestInstallPath)-1] != L'\\')
					StringCbCatW (WizardDestInstallPath, sizeof(WizardDestInstallPath), L"\\");

				StringCbCopyW (InstallationPath, sizeof(InstallationPath), WizardDestInstallPath);

				WaitCursor ();

				bInProgress = TRUE;
				bStartInstall = FALSE;

				_beginthread (DoInstall, 0, (void *) hwndDlg);
			}
			else
			{
				NormalCursor ();

				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_PREV), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDHELP), TRUE);
				EnableWindow (GetDlgItem (GetParent (hwndDlg), IDCANCEL), TRUE);

			}

			return 1;

		case DONATIONS_PAGE:

			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_TITLE), GetString (bExtractOnly ? "EXTRACTION_FINISHED_TITLE_DON" : (bUpgrade ? "SETUP_FINISHED_UPGRADE_TITLE_DON" : "SETUP_FINISHED_TITLE_DON")));
			SetWindowTextW (GetDlgItem (GetParent (hwndDlg), IDC_BOX_INFO), GetString ("SETUP_FINISHED_INFO_DON"));

			DonText = L"Please consider making a donation.";


			// Colors

			switch (DonColorSchemeId)
			{
			case 2:
				// NOP - Default OS colors (foreground and background)
				break;

			case 3:
				// Red
				DonTextColor = RGB (255, 255, 255);
				DonBkgColor = RGB (255, 0, 0);
				break;

			case 4:
				// Yellow
				DonTextColor = RGB (255, 15, 49);
				DonBkgColor = RGB (255, 255, 0);
				break;

			case 5:
				// Light red
				DonTextColor = RGB (255, 255, 255);
				DonBkgColor = RGB (255, 141, 144);
				break;

			case 6:
				// Pink
				DonTextColor = RGB (255, 255, 255);
				DonBkgColor = RGB (248, 148, 207);
				break;

			case 7:
				// White + red text
				DonTextColor = RGB (255, 15, 49);
				DonBkgColor = RGB (255, 255, 255);
				break;

			case 8:
				// Blue
				DonTextColor = RGB (255, 255, 255);
				DonBkgColor = RGB (54, 140, 255);
				break;

			case 9:
				// Green
				DonTextColor = RGB (255, 255, 255);
				DonBkgColor = RGB (70, 180, 80);
				break;
			}

			{
				// Font

				LOGFONTW lf;
				memset (&lf, 0, sizeof(lf));

				// Main font
				StringCbCopyW (lf.lfFaceName, sizeof (lf.lfFaceName),L"Times New Roman");
				lf.lfHeight = CompensateDPIFont (-21);
				lf.lfWeight = FW_NORMAL;
				lf.lfWidth = 0;
				lf.lfEscapement = 0;
				lf.lfOrientation = 0;
				lf.lfItalic = FALSE;
				lf.lfUnderline = FALSE;
				lf.lfStrikeOut = FALSE;
				lf.lfCharSet = DEFAULT_CHARSET;
				lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
				lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
				lf.lfQuality = PROOF_QUALITY;
				lf.lfPitchAndFamily = FF_DONTCARE;
				hDonTextFont = CreateFontIndirectW (&lf);

				if (hDonTextFont == NULL)
					AbortProcessSilent ();
			}

			return 1;
		}

		return 0;

	case WM_HELP:
		if (bLicenseAccepted)
			OpenPageHelp (GetParent (hwndDlg), nCurPageNo);

		return 1;

	case WM_ENDSESSION:

		bPromptTutorial = FALSE;
		bPromptReleaseNotes = FALSE;

		EndDialog (MainDlg, 0);
		localcleanup ();
		return 0;


	case WM_COMMAND:

		if (lw == IDC_AGREE && nCurPageNo == INTRO_PAGE)
		{
			EnableWindow (GetDlgItem (GetParent (hwndDlg), IDC_NEXT), IsButtonChecked (GetDlgItem (hwndDlg, IDC_AGREE)));
			return 1;
		}

		if (lw == IDC_WIZARD_MODE_EXTRACT_ONLY && nCurPageNo == WIZARD_MODE_PAGE)
		{
			bExtractOnly = TRUE;
			return 1;
		}

		if (lw == IDC_WIZARD_MODE_INSTALL && nCurPageNo == WIZARD_MODE_PAGE)
		{
			bExtractOnly = FALSE;
			return 1;
		}

		if ( nCurPageNo == EXTRACTION_OPTIONS_PAGE && hw == EN_CHANGE )
		{
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hCurPage, IDC_DESTINATION)) > 1));
			return 1;
		}

		if ( nCurPageNo == INSTALL_OPTIONS_PAGE && hw == EN_CHANGE )
		{
			EnableWindow (GetDlgItem (MainDlg, IDC_NEXT), (GetWindowTextLength (GetDlgItem (hCurPage, IDC_DESTINATION)) > 1));
			return 1;
		}

		if ( nCurPageNo == EXTRACTION_OPTIONS_PAGE )
		{
			switch (lw)
			{
			case IDC_BROWSE:
				if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", WizardDestExtractPath))
				{
					if (WizardDestExtractPath [wcslen(WizardDestExtractPath)-1] != L'\\')
					{
						StringCbCatW (WizardDestExtractPath, sizeof(WizardDestExtractPath), L"\\");
					}
					SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestExtractPath);
				}
				return 1;

			case IDC_OPEN_CONTAINING_FOLDER:
				bOpenContainingFolder = IsButtonChecked (GetDlgItem (hCurPage, IDC_OPEN_CONTAINING_FOLDER));
				return 1;
			}
		}

		if ( nCurPageNo == INSTALL_OPTIONS_PAGE )
		{
			switch (lw)
			{
			case IDC_BROWSE:
				if (BrowseDirectories (hwndDlg, "SELECT_DEST_DIR", WizardDestInstallPath))
				{
					if (WizardDestInstallPath [wcslen(WizardDestInstallPath)-1] != L'\\')
					{
						StringCbCatW (WizardDestInstallPath, sizeof(WizardDestInstallPath), L"\\");
					}
					SetDlgItemText (hwndDlg, IDC_DESTINATION, WizardDestInstallPath);
				}
				return 1;

			case IDC_SYSTEM_RESTORE:
				bSystemRestore = IsButtonChecked (GetDlgItem (hCurPage, IDC_SYSTEM_RESTORE));
				return 1;

			case IDC_ALL_USERS:
				bForAllUsers = IsButtonChecked (GetDlgItem (hCurPage, IDC_ALL_USERS));
				return 1;

			case IDC_FILE_TYPE:
				bRegisterFileExt = IsButtonChecked (GetDlgItem (hCurPage, IDC_FILE_TYPE));
				return 1;

			case IDC_PROG_GROUP:
				bAddToStartMenu = IsButtonChecked (GetDlgItem (hCurPage, IDC_PROG_GROUP));
				return 1;

			case IDC_DESKTOP_ICON:
				bDesktopIcon = IsButtonChecked (GetDlgItem (hCurPage, IDC_DESKTOP_ICON));
				return 1;

			}
		}

		if (nCurPageNo == DONATIONS_PAGE)
		{
			switch (lw)
			{
			case IDC_DONATE:
				{
					Applink ("donate");
				}
				return 1;
			}
		}

		return 0;


	case WM_PAINT:

		if (nCurPageNo == DONATIONS_PAGE)
		{
			PAINTSTRUCT tmpPaintStruct;
			HDC hdc = BeginPaint (hCurPage, &tmpPaintStruct);

			if (hdc == NULL)
				AbortProcessSilent ();

			SelectObject (hdc, hDonTextFont);

			if (DonColorSchemeId != 2)
			{
				HBRUSH tmpBrush = CreateSolidBrush (DonBkgColor);

				if (tmpBrush == NULL)
					AbortProcessSilent ();

				RECT trect;

				trect.left = 0;
				trect.right = CompensateXDPI (526);
				trect.top  = 0;
				trect.bottom = CompensateYDPI (246);

				FillRect (hdc, &trect, tmpBrush);

				SetTextColor (hdc, DonTextColor);
				SetBkColor (hdc, DonBkgColor);
			}

			SetTextAlign(hdc, TA_CENTER);

			TextOutW (hdc,
				CompensateXDPI (258),
				CompensateYDPI (70),
				DonText.c_str(),
				DonText.length());

			EndPaint (hCurPage, &tmpPaintStruct);
			ReleaseDC (hCurPage, hdc);
		}
		return 0;

	}

	return 0;
}

void InitProgressBar (void)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETRANGE32, 0, 100);
	SendMessage (hProgressBar, PBM_SETSTEP, 1, 0);
	InvalidateRect (hProgressBar, NULL, TRUE);
}

// Must always return TRUE
BOOL UpdateProgressBarProc (int nPercent)
{
	HWND hProgressBar = GetDlgItem (hCurPage, nPbar);
	SendMessage (hProgressBar, PBM_SETPOS, (int) (100.0 * nPercent / 100), 0);
	InvalidateRect (hProgressBar, NULL, TRUE);
	ShowWindow(hProgressBar, SW_HIDE);
	ShowWindow(hProgressBar, SW_SHOW);
	// Prevent the IDC_LOG_WINDOW item from partially disappearing at higher DPIs
	ShowWindow(GetDlgItem (hCurPage, IDC_LOG_WINDOW), SW_HIDE);
	ShowWindow(GetDlgItem (hCurPage, IDC_LOG_WINDOW), SW_SHOW);
	RefreshUIGFX();
	return TRUE;
}

void RefreshUIGFX (void)
{
	InvalidateRect (GetDlgItem (MainDlg, IDC_SETUP_WIZARD_BKG), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BOX_TITLE), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BOX_INFO), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_BITMAP_SETUP_WIZARD), NULL, TRUE);
	InvalidateRect (GetDlgItem (MainDlg, IDC_HR), NULL, TRUE);
	// Prevent these items from disappearing at higher DPIs
	ShowWindow(GetDlgItem(MainDlg, IDC_HR), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR_BOTTOM), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_HR_BOTTOM), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_INFO), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_INFO), SW_SHOW);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_TITLE), SW_HIDE);
	ShowWindow(GetDlgItem(MainDlg, IDC_BOX_TITLE), SW_SHOW);
}


/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK MainDialogProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD lw = LOWORD (wParam);

	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			RECT rec;

			GetModuleFileName (NULL, SelfFile, ARRAYSIZE (SelfFile));

			MainDlg = hwndDlg;

			if (!CreateAppSetupMutex ())
				AbortProcess ("TC_INSTALLER_IS_RUNNING");

			InitDialog (hwndDlg);
			LocalizeDialog (hwndDlg, "IDD_INSTL_DLG");

			// Resize the bitmap if the user has a non-default DPI
			if (ScreenDPI != USER_DEFAULT_SCREEN_DPI)
			{
				hbmWizardBitmapRescaled = RenderBitmap (MAKEINTRESOURCE (IDB_SETUP_WIZARD),
					GetDlgItem (hwndDlg, IDC_BITMAP_SETUP_WIZARD),
					0, 0, 0, 0, FALSE, TRUE);
			}

			// Gfx area background (must not keep aspect ratio; must retain Windows-imposed distortion)
			GetClientRect (GetDlgItem (hwndDlg, IDC_SETUP_WIZARD_GFX_AREA), &rec);
			SetWindowPos (GetDlgItem (hwndDlg, IDC_SETUP_WIZARD_BKG), HWND_TOP, 0, 0, rec.right, rec.bottom, SWP_NOMOVE);

			nPbar = IDC_PROGRESS_BAR;

			SendMessage (GetDlgItem (hwndDlg, IDC_BOX_TITLE), WM_SETFONT, (WPARAM) hUserBoldFont, (LPARAM) TRUE);

			SetWindowText (hwndDlg, L"VeraCrypt Setup " _T(VERSION_STRING));

			DonColorSchemeId = GetDonVal (2, 9);

			if (bDevm)
			{
				InitWizardDestInstallPath ();
				bSystemRestore = FALSE;
				bRegisterFileExt = FALSE;
				bAddToStartMenu = FALSE;
				bDesktopIcon = TRUE;
				bLicenseAccepted = TRUE;
				bStartInstall = TRUE;
				LoadPage (hwndDlg, INSTALL_PROGRESS_PAGE);
			}
			else
				LoadPage (hwndDlg, INTRO_PAGE);

		}
		return 0;

	case WM_SYSCOMMAND:
		if (lw == IDC_ABOUT)
		{
			if (bLicenseAccepted)
				DialogBoxW (hInst, MAKEINTRESOURCEW (IDD_ABOUT_DLG), hwndDlg, (DLGPROC) AboutDlgProc);

			return 1;
		}
		return 0;

	case WM_HELP:
		if (bLicenseAccepted)
			OpenPageHelp (hwndDlg, nCurPageNo);

		return 1;


	case WM_COMMAND:
		if (lw == IDHELP)
		{
			if (bLicenseAccepted)
				OpenPageHelp (hwndDlg, nCurPageNo);

			return 1;
		}
		if (lw == IDCANCEL)
		{
			PostMessage (hwndDlg, WM_CLOSE, 0, 0);
			return 1;
		}
		if (lw == IDC_NEXT)
		{
			if (nCurPageNo == INTRO_PAGE)
			{
				if (!IsButtonChecked (GetDlgItem (hCurPage, IDC_AGREE)))
				{
					bLicenseAccepted = FALSE;
					return 1;
				}
				bLicenseAccepted = TRUE;
				EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);

				if (nCurrentOS == WIN_2000)
				{
					WarningDirect (L"Warning: Please note that this may be the last version of VeraCrypt that supports Windows 2000. If you want to be able to upgrade to future versions of VeraCrypt (which is highly recommended), you will need to upgrade to Windows XP or a later version of Windows.\n\nNote: Microsoft stopped issuing security updates for Windows 2000 to the general public on 7/13/2010 (the last non-security update for Windows 2000 was issued to the general public in 2005).", hwndDlg);


					HKEY hkey;

					if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Updates\\Windows 2000\\SP5\\Update Rollup 1", 0, KEY_READ, &hkey) != ERROR_SUCCESS)
					{
						ErrorDirect (L"VeraCrypt requires Update Rollup 1 for Windows 2000 SP4 to be installed.\n\nFor more information, see http://support.microsoft.com/kb/891861", hwndDlg);
						AbortProcessSilent ();
					}

					RegCloseKey (hkey);
				}
			}

			else if (nCurPageNo == WIZARD_MODE_PAGE)
			{
				if (IsButtonChecked (GetDlgItem (hCurPage, IDC_WIZARD_MODE_EXTRACT_ONLY)))
				{
					Info ("TRAVELER_LIMITATIONS_NOTE", hwndDlg);

					if (IsUacSupported()
						&& AskWarnYesNo ("TRAVELER_UAC_NOTE", hwndDlg) == IDNO)
					{
						return 1;
					}

					bExtractOnly = TRUE;
					nCurPageNo = EXTRACTION_OPTIONS_PAGE - 1;
				}
			}

			else if (nCurPageNo == EXTRACTION_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestExtractPath, ARRAYSIZE (WizardDestExtractPath));

				bStartExtraction = TRUE;
			}

			else if (nCurPageNo == INSTALL_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestInstallPath, ARRAYSIZE (WizardDestInstallPath));

				bStartInstall = TRUE;
			}

			else if (nCurPageNo == INSTALL_PROGRESS_PAGE)
			{
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			else if (nCurPageNo == EXTRACTION_PROGRESS_PAGE)
			{
				PostMessage (hwndDlg, WM_CLOSE, 0, 0);
				return 1;
			}

			else if (nCurPageNo == DONATIONS_PAGE)
			{
				// 'Finish' button clicked

				PostMessage (hwndDlg, WM_CLOSE, 0, 0);

				return 1;
			}

			LoadPage (hwndDlg, ++nCurPageNo);

			return 1;
		}

		if (lw == IDC_PREV)
		{
			if (nCurPageNo == WIZARD_MODE_PAGE)
			{
				bExtractOnly = IsButtonChecked (GetDlgItem (hCurPage, IDC_WIZARD_MODE_EXTRACT_ONLY));
			}

			else if (nCurPageNo == EXTRACTION_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestExtractPath, ARRAYSIZE (WizardDestExtractPath));
				nCurPageNo = WIZARD_MODE_PAGE + 1;
			}

			else if (nCurPageNo == INSTALL_OPTIONS_PAGE)
			{
				GetWindowText (GetDlgItem (hCurPage, IDC_DESTINATION), WizardDestInstallPath, ARRAYSIZE (WizardDestInstallPath));
			}

			LoadPage (hwndDlg, --nCurPageNo);

			return 1;
		}

		return 0;



	case WM_PAINT:

		if (nCurPageNo == DONATIONS_PAGE && DonColorSchemeId != 2)
		{
			HWND hwndItem = GetDlgItem (MainDlg, IDC_MAIN_CONTENT_CANVAS);

			PAINTSTRUCT tmpPaintStruct;
			HDC hdc = BeginPaint (hwndItem, &tmpPaintStruct);

			if (DonColorSchemeId != 2)
			{
				HBRUSH tmpBrush = CreateSolidBrush (DonBkgColor);

				RECT trect;

				trect.left = CompensateXDPI (1);
				trect.right = CompensateXDPI (560);
				trect.top  = CompensateYDPI (DonColorSchemeId == 7 ? 11 : 0);
				trect.bottom = CompensateYDPI (260);

				FillRect (hdc, &trect, tmpBrush);
			}

			EndPaint(hwndItem, &tmpPaintStruct);
			ReleaseDC (hwndItem, hdc);
		}
		return 0;



	case WM_CTLCOLORSTATIC:

		if ((HWND) lParam != GetDlgItem (MainDlg, IDC_MAIN_CONTENT_CANVAS))
		{
			/* This maintains the background under the transparent-backround texts. The above 'if' statement allows
			colored background to be erased automatically when leaving a page that uses it. */

			SetBkMode ((HDC) wParam, TRANSPARENT);
			return ((LONG) (HBRUSH) (GetStockObject (NULL_BRUSH)));
		}


	case WM_ERASEBKGND:

		return 0;



	case TC_APPMSG_INSTALL_SUCCESS:

		/* Installation completed successfully */

		bInProgress = FALSE;

		nCurPageNo = DONATIONS_PAGE;
		LoadPage (hwndDlg, DONATIONS_PAGE);

		NormalCursor ();

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));

		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);


		RefreshUIGFX ();
		return 1;

	case TC_APPMSG_INSTALL_FAILURE:

		/* Installation failed */

		bInProgress = FALSE;

		NormalCursor ();

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_TITLE), GetString ("INSTALL_FAILED"));
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_INFO), L"");

		SetWindowTextW (GetDlgItem (hwndDlg, IDCANCEL), GetString ("IDCLOSE"));
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);

		RefreshUIGFX();

		return 1;

	case TC_APPMSG_EXTRACTION_SUCCESS:

		/* Extraction completed successfully */

		UpdateProgressBarProc(100);

		bInProgress = FALSE;
		bExtractionSuccessful = TRUE;

		NormalCursor ();

		StatusMessage (hCurPage, "EXTRACTION_FINISHED_INFO");

		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), FALSE);

		RefreshUIGFX ();

		Info ("EXTRACTION_FINISHED_INFO", hwndDlg);

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_NEXT), GetString ("FINALIZE"));

		nCurPageNo = DONATIONS_PAGE;
		LoadPage (hwndDlg, DONATIONS_PAGE);

		return 1;

	case TC_APPMSG_EXTRACTION_FAILURE:

		/* Extraction failed */

		bInProgress = FALSE;

		NormalCursor ();

		StatusMessage (hCurPage, "EXTRACTION_FAILED");

		UpdateProgressBarProc(0);

		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_TITLE), GetString ("EXTRACTION_FAILED"));
		SetWindowTextW (GetDlgItem (hwndDlg, IDC_BOX_INFO), L"");

		SetWindowTextW (GetDlgItem (hwndDlg, IDCANCEL), GetString ("IDCLOSE"));
		EnableWindow (GetDlgItem (hwndDlg, IDHELP), TRUE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_PREV), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDC_NEXT), FALSE);
		EnableWindow (GetDlgItem (hwndDlg, IDCANCEL), TRUE);

		RefreshUIGFX();

		Error ("EXTRACTION_FAILED", hwndDlg);

		return 1;

	case WM_CLOSE:

		if (!bDevm)
		{
			if (bInProgress)
			{
				NormalCursor();
				if (AskNoYes("CONFIRM_EXIT_UNIVERSAL", hwndDlg) == IDNO)
				{
					return 1;
				}
				WaitCursor ();
			}

			if (bOpenContainingFolder && bExtractOnly && bExtractionSuccessful)
			{
				ShellExecute (NULL, L"open", WizardDestExtractPath, NULL, NULL, SW_SHOWNORMAL);
			}
			else
			{
				if (bPromptReleaseNotes
					&& AskYesNo ("AFTER_UPGRADE_RELEASE_NOTES", hwndDlg) == IDYES)
				{
					Applink ("releasenotes");
				}

				bPromptReleaseNotes = FALSE;

				if (bPromptTutorial
					&& AskYesNo ("AFTER_INSTALL_TUTORIAL", hwndDlg) == IDYES)
				{
					Applink ("beginnerstutorial");
				}

				bPromptTutorial = FALSE;
			}

			if (bRestartRequired
				&& AskYesNo (bUpgrade ? "UPGRADE_OK_REBOOT_REQUIRED" : "CONFIRM_RESTART", hwndDlg) == IDYES)
			{
				RestartComputer(FALSE);
			}
		}

		EndDialog (hwndDlg, IDCANCEL);
		return 1;
	}

	return 0;
}


