/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Tcdefs.h"
#include "Keyfiles.h"
#include "Crc.h"

#include <io.h>
#include "Dlgcode.h"
#include "Language.h"
#include "SecurityToken.h"
#include "EMVToken.h"
#include "Common/resource.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#ifdef TCMOUNT
#include "Mount/Mount.h"
#endif

#include <Strsafe.h>

using namespace VeraCrypt;

#define stat _stat
#define S_IFDIR _S_IFDIR


BOOL HiddenFilesPresentInKeyfilePath = FALSE;

#ifdef TCMOUNT
extern BOOL UsePreferences;
#endif

KeyFile *KeyFileAdd (KeyFile *firstKeyFile, KeyFile *keyFile)
{
	KeyFile *kf = firstKeyFile;

	if (firstKeyFile != NULL)
	{
		while (kf->Next)
			kf = kf->Next;

		kf->Next = keyFile;
	}
	else
		firstKeyFile = keyFile;

	keyFile->Next = NULL;

	return firstKeyFile;
}


// Returns first keyfile, NULL if last keyfile was removed
static KeyFile *KeyFileRemove (KeyFile *firstKeyFile, KeyFile *keyFile)
{
	KeyFile *prevkf = NULL, *kf = firstKeyFile;

	if (firstKeyFile == NULL) return NULL;
	do
	{
		if (kf == keyFile)
		{
			if (prevkf == NULL)
				firstKeyFile = kf->Next;
			else
				prevkf->Next = kf->Next;

			burn (keyFile, sizeof(*keyFile));	// wipe
			free (keyFile);
			break;
		}
		prevkf = kf;
	}
	while (kf = kf->Next);

	return firstKeyFile;
}


void KeyFileRemoveAll (KeyFile **firstKeyFile)
{
	KeyFile *kf = *firstKeyFile;
	while (kf != NULL)
	{
		KeyFile *d = kf;
		kf = kf->Next;
		burn (d, sizeof(*d));	// wipe
		free (d);
	}

	*firstKeyFile = NULL;
}


KeyFile *KeyFileClone (KeyFile *keyFile)
{
	KeyFile *clone = NULL;

	if (keyFile == NULL) return NULL;

	clone = (KeyFile *) malloc (sizeof (KeyFile));
	if (clone)
	{
		StringCbCopyW (clone->FileName, sizeof(clone->FileName), keyFile->FileName);
		clone->Next = NULL;
	}
	return clone;
}


void KeyFileCloneAll (KeyFile *firstKeyFile, KeyFile **outputKeyFile)
{
	if (outputKeyFile)
	{
		KeyFile *cloneFirstKeyFile = KeyFileClone (firstKeyFile);
		KeyFile *kf;

		// free output only if different from input
		if (*outputKeyFile != firstKeyFile)
			KeyFileRemoveAll (outputKeyFile);
		if (firstKeyFile)
		{
			kf = firstKeyFile->Next;
			while (kf != NULL)
			{
				KeyFileAdd (cloneFirstKeyFile, KeyFileClone (kf));
				kf = kf->Next;
			}

			*outputKeyFile = cloneFirstKeyFile;
		}
	}
}


static BOOL KeyFileProcess (unsigned __int8 *keyPool, unsigned __int32 keyPoolSize, KeyFile *keyFile)
{
	unsigned __int8 buffer[64 * 1024];
	unsigned __int32 crc = 0xffffffff;
	unsigned __int32 writePos = 0;
	DWORD bytesRead, totalRead = 0;
	int status = TRUE;
	HANDLE src;
	BOOL bReadStatus = FALSE;

	src = CreateFile (keyFile->FileName,
		GENERIC_READ | FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src != INVALID_HANDLE_VALUE)
	{
		/* We tell Windows not to update the Last Access timestamp in order to prevent
		an adversary from determining which file may have been used as keyfile. */
		FILETIME ftLastAccessTime;
		ftLastAccessTime.dwHighDateTime = 0xFFFFFFFF;
		ftLastAccessTime.dwLowDateTime = 0xFFFFFFFF;

		SetFileTime (src, NULL, &ftLastAccessTime, NULL);
	}
	else
	{
		/* try to open without FILE_WRITE_ATTRIBUTES in case we are in a ReadOnly filesystem (e.g. CD)                                                                                                                                                                                                                                         */
		src = CreateFile (keyFile->FileName,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (src == INVALID_HANDLE_VALUE)
			return FALSE;
	}

	while ((bReadStatus = ReadFile (src, buffer, sizeof (buffer), &bytesRead, NULL)) && (bytesRead > 0))
	{
		DWORD i;

		for (i = 0; i < bytesRead; i++)
		{
			crc = UPDC32 (buffer[i], crc);

			keyPool[writePos++] += (unsigned __int8) (crc >> 24);
			keyPool[writePos++] += (unsigned __int8) (crc >> 16);
			keyPool[writePos++] += (unsigned __int8) (crc >> 8);
			keyPool[writePos++] += (unsigned __int8) crc;

			if (writePos >= keyPoolSize)
				writePos = 0;

			if (++totalRead >= KEYFILE_MAX_READ_LEN)
				goto close;
		}
	}

	if (!bReadStatus)
	{
		status = FALSE;
	}
	else if (totalRead == 0)
	{
		status = FALSE;
		SetLastError (ERROR_HANDLE_EOF);
	}

close:
	DWORD err = GetLastError();

	CloseHandle (src);
	burn (buffer, sizeof (buffer));

	SetLastError (err);
	return status;
}


BOOL KeyFilesApply (HWND hwndDlg, Password *password, KeyFile *firstKeyFile, const wchar_t* volumeFileName)
{
	BOOL status = TRUE;
	KeyFile kfSubStruct;
	KeyFile *kf;
	KeyFile *kfSub = &kfSubStruct;
	static unsigned __int8 keyPool [KEYFILE_POOL_SIZE];
	size_t i;
	struct stat statStruct;
	wchar_t searchPath [TC_MAX_PATH*2];
	struct _wfinddata_t fBuf;
	intptr_t searchHandle;
	unsigned __int32 keyPoolSize = password->Length <= MAX_LEGACY_PASSWORD? KEYFILE_POOL_LEGACY_SIZE : KEYFILE_POOL_SIZE;

	HiddenFilesPresentInKeyfilePath = FALSE;

	if (firstKeyFile == NULL) return TRUE;

	VirtualLock (keyPool, sizeof (keyPool));
	memset (keyPool, 0, sizeof (keyPool));

	for (kf = firstKeyFile; kf != NULL; kf = kf->Next)
	{
		// Determine whether it's a security token path
		try
		{
			if (Token::IsKeyfilePathValid (kf->FileName, EMVSupportEnabled? true : false))
			{
				// Apply security token keyfile
				vector <byte> keyfileData;
				TokenKeyfilePath secPath (kf->FileName);
				Token::getTokenKeyfile (secPath)->GetKeyfileData (keyfileData);

				if (keyfileData.empty())
				{
					SetLastError (ERROR_HANDLE_EOF);
					handleWin32Error (hwndDlg, SRC_POS);
					Error ("ERR_PROCESS_KEYFILE", hwndDlg);
					status = FALSE;
					continue;
				}

				unsigned __int32 crc = 0xffffffff;
				unsigned __int32 writePos = 0;
				size_t totalRead = 0;

				for (size_t i = 0; i < keyfileData.size(); i++)
				{
					crc = UPDC32 (keyfileData[i], crc);

					keyPool[writePos++] += (unsigned __int8) (crc >> 24);
					keyPool[writePos++] += (unsigned __int8) (crc >> 16);
					keyPool[writePos++] += (unsigned __int8) (crc >> 8);
					keyPool[writePos++] += (unsigned __int8) crc;

					if (writePos >= keyPoolSize)
						writePos = 0;

					if (++totalRead >= KEYFILE_MAX_READ_LEN)
						break;
				}

				burn (&keyfileData.front(), keyfileData.size());
				continue;
			}
		}
		catch (Exception &e)
		{
			e.Show (NULL);
			return FALSE;
		}

		// Determine whether it's a path or a file
		if (_wstat (kf->FileName, &statStruct) != 0)
		{
			handleWin32Error (hwndDlg, SRC_POS);
			Error ("ERR_PROCESS_KEYFILE", hwndDlg);
			status = FALSE;
			continue;
		}

		if (statStruct.st_mode & S_IFDIR)		// If it's a directory
		{
			/* Find and process all keyfiles in the directory */
			int keyfileCount = 0;

			StringCbPrintfW (searchPath, sizeof (searchPath), L"%s\\*.*", kf->FileName);
			if ((searchHandle = _wfindfirst (searchPath, &fBuf)) == -1)
			{
				handleWin32Error (hwndDlg, SRC_POS);
				Error ("ERR_PROCESS_KEYFILE_PATH", hwndDlg);
				status = FALSE;
				continue;
			}

			do
			{
				WIN32_FILE_ATTRIBUTE_DATA fileAttributes;

				StringCbPrintfW (kfSub->FileName, sizeof(kfSub->FileName), L"%s%c%s", kf->FileName,
					L'\\',
					fBuf.name
					);

				// Determine whether it's a path or a file
				if (_wstat (kfSub->FileName, &statStruct) != 0)
				{
					handleWin32Error (hwndDlg, SRC_POS);
					Error ("ERR_PROCESS_KEYFILE", hwndDlg);
					status = FALSE;
					continue;
				}
				else if (statStruct.st_mode & S_IFDIR)		// If it's a directory
				{
					// Prevent recursive folder scanning
					continue;
				}

				// Skip hidden files
				if (GetFileAttributesExW (kfSub->FileName, GetFileExInfoStandard, &fileAttributes)
					&& (fileAttributes.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0)
				{
					HiddenFilesPresentInKeyfilePath = TRUE;
					continue;
				}

				CorrectFileName (kfSub->FileName);
				if (volumeFileName && (_wcsicmp (volumeFileName, kfSub->FileName) == 0))
				{
					// skip if it is the current container file name
					continue;
				}

				++keyfileCount;

				// Apply keyfile to the pool
				if (!KeyFileProcess (keyPool, keyPoolSize, kfSub))
				{
					handleWin32Error (hwndDlg, SRC_POS);
					Error ("ERR_PROCESS_KEYFILE", hwndDlg);
					status = FALSE;
				}

			} while (_wfindnext (searchHandle, &fBuf) != -1);
			_findclose (searchHandle);

			burn (&kfSubStruct, sizeof (kfSubStruct));

			if (keyfileCount == 0)
			{
				ErrorDirect ((wstring (GetString ("ERR_KEYFILE_PATH_EMPTY")) + L"\n\n" + wstring (kf->FileName)).c_str(), hwndDlg);
				status = FALSE;
			}
		}
		// Apply keyfile to the pool
		else if (!KeyFileProcess (keyPool, keyPoolSize, kf))
		{
			handleWin32Error (hwndDlg, SRC_POS);
			Error ("ERR_PROCESS_KEYFILE", hwndDlg);
			status = FALSE;
		}
	}

	/* Mix the keyfile pool contents into the password */

	for (i = 0; i < keyPoolSize; i++)
	{
		if (i < password->Length)
			password->Text[i] += keyPool[i];
		else
			password->Text[i] = keyPool[i];
	}

	if (password->Length < keyPoolSize)
        password->Length = keyPoolSize;

	burn (keyPool, sizeof (keyPool));

	return status;
}


static void LoadKeyList (HWND hwndDlg, KeyFile *firstKeyFile)
{
	KeyFile *kf;
	LVITEM LvItem;
	int line = 0;
	HWND hList = GetDlgItem (hwndDlg, IDC_KEYLIST);

	ListView_DeleteAllItems (hList);
	EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVE), FALSE);
	EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVEALL), firstKeyFile != NULL);
	SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, firstKeyFile != NULL);

	for (kf = firstKeyFile; kf != NULL; kf = kf->Next)
	{
		memset (&LvItem,0,sizeof(LvItem));
		LvItem.mask = LVIF_TEXT|LVIF_PARAM;
		LvItem.iItem = line++;
		LvItem.iSubItem = 0;
		LvItem.pszText = kf->FileName;
		LvItem.lParam = (LPARAM) kf;
		SendMessage (hList, LVM_INSERTITEM, 0, (LPARAM)&LvItem);
	}
}

#if KEYFILE_POOL_SIZE % 4 != 0
#error KEYFILE_POOL_SIZE must be a multiple of 4
#endif

BOOL CALLBACK KeyFilesDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static KeyFilesDlgParam *param;
	static KeyFilesDlgParam origParam;

	WORD lw = LOWORD (wParam);

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			LVCOLUMNW LvCol;
			HWND hList = GetDlgItem (hwndDlg, IDC_KEYLIST);

			param = (KeyFilesDlgParam *) lParam;
			origParam = *(KeyFilesDlgParam *) lParam;

			KeyFileCloneAll (param->FirstKeyFile, &param->FirstKeyFile);

			LocalizeDialog (hwndDlg, "IDD_KEYFILES");
			DragAcceptFiles (hwndDlg, TRUE);

			SendMessageW (hList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,
				LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP
				);

			memset (&LvCol,0,sizeof(LvCol));
			LvCol.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM|LVCF_FMT;
			LvCol.pszText = GetString ("KEYFILE");
			LvCol.cx = CompensateXDPI (374);
			LvCol.fmt = LVCFMT_LEFT;
			SendMessageW (hList, LVM_INSERTCOLUMNW, 0, (LPARAM)&LvCol);

			LoadKeyList (hwndDlg, param->FirstKeyFile);
			SetCheckBox (hwndDlg, IDC_KEYFILES_ENABLE, param->EnableKeyFiles);

#ifdef TCMOUNT
			if (	(origParam.EnableKeyFiles == defaultKeyFilesParam.EnableKeyFiles)
				&&	(origParam.FirstKeyFile == defaultKeyFilesParam.FirstKeyFile)
				)
			{
				/* default keyfile dialog case */
				SetCheckBox (hwndDlg, IDC_KEYFILES_TRY_EMPTY_PASSWORD, bTryEmptyPasswordWhenKeyfileUsed);
				ShowWindow(GetDlgItem(hwndDlg, IDC_KEYFILES_TRY_EMPTY_PASSWORD), SW_SHOW);
			}
#endif

			SetWindowTextW(GetDlgItem(hwndDlg, IDT_KEYFILES_NOTE), GetString ("KEYFILES_NOTE"));

			ToHyperlink (hwndDlg, IDC_LINK_KEYFILES_INFO);
			ToHyperlink (hwndDlg, IDC_LINK_KEYFILES_EXTENSIONS_WARNING);
		}
		return 1;

	case WM_CTLCOLORSTATIC:
		{
			if (((HWND)lParam == GetDlgItem(hwndDlg, IDT_KEYFILE_WARNING)) )
			{
				// we're about to draw the static
				// set the text colour in (HDC)wParam
				SetBkMode((HDC)wParam,TRANSPARENT);
				SetTextColor((HDC)wParam, RGB(255,0,0));
				return (BOOL)GetSysColorBrush(COLOR_MENU);
			}
		}
		return 0;

	case WM_COMMAND:

		if (lw == IDC_KEYADD)
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
			if (kf)
			{
				std::vector<std::wstring> filesList;
				if (SelectMultipleFiles (hwndDlg, "SELECT_KEYFILE", bHistory, filesList))
				{
					bool containerFileSkipped = false;
					for	(std::vector<std::wstring>::const_iterator it = filesList.begin();
							it != filesList.end();
							++it)
					{
						StringCbCopyW (kf->FileName, sizeof (kf->FileName), it->c_str());
						CorrectFileName (kf->FileName);
						if (_wcsicmp (param->VolumeFileName, kf->FileName) == 0)
							containerFileSkipped = true;
						else
						{
							param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
							LoadKeyList (hwndDlg, param->FirstKeyFile);

							kf = (KeyFile *) malloc (sizeof (KeyFile));
							if (!kf)
							{
								Warning ("ERR_MEM_ALLOC", hwndDlg);
								break;
							}
						}
					}

					if (containerFileSkipped)
					{
						Warning ("SELECTED_KEYFILE_IS_CONTAINER_FILE", hwndDlg);
					}
				}

                if (kf)
				    free (kf);
			}
			return 1;
		}

		if (lw == IDC_ADD_KEYFILE_PATH)
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
            if (kf)
            {
			    if (BrowseDirectories (hwndDlg,"SELECT_KEYFILE_PATH", kf->FileName, NULL))
			    {
				    param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
				    LoadKeyList (hwndDlg, param->FirstKeyFile);
			    }
			    else
			    {
				    free (kf);
			    }
            }
            else
            {
                Warning ("ERR_MEM_ALLOC", hwndDlg);
            }
			return 1;
		}

		if (lw == IDC_TOKEN_FILES_ADD)
		{
			list <TokenKeyfilePath> selectedTokenKeyfiles;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_KEYFILES), hwndDlg, (DLGPROC) SecurityTokenKeyfileDlgProc, (LPARAM) &selectedTokenKeyfiles) == IDOK)
			{
				foreach (const TokenKeyfilePath &keyPath, selectedTokenKeyfiles)
				{
					KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						StringCbCopyW (kf->FileName, sizeof (kf->FileName), wstring(keyPath).c_str ());

						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						LoadKeyList (hwndDlg, param->FirstKeyFile);
					}
				}
			}

			return 1;
		}

		if (lw == IDC_KEYREMOVE)
		{
			HWND list = GetDlgItem (hwndDlg, IDC_KEYLIST);
			LVITEM LvItem;
			memset (&LvItem, 0, sizeof(LvItem));
			LvItem.mask = LVIF_PARAM;
			LvItem.iItem = -1;

			while (-1 != (LvItem.iItem = ListView_GetNextItem (list, LvItem.iItem, LVIS_SELECTED)))
			{
				ListView_GetItem (list, &LvItem);
				param->FirstKeyFile = KeyFileRemove (param->FirstKeyFile, (KeyFile *) LvItem.lParam);
			}

			LoadKeyList (hwndDlg, param->FirstKeyFile);
			return 1;
		}

		if (lw == IDC_KEYREMOVEALL)
		{
			KeyFileRemoveAll (&param->FirstKeyFile);
			LoadKeyList (hwndDlg, NULL);
			return 1;
		}

		if (lw == IDC_GENERATE_KEYFILE)
		{
			DialogBoxParamW (hInst,
				MAKEINTRESOURCEW (IDD_KEYFILE_GENERATOR), hwndDlg,
				(DLGPROC) KeyfileGeneratorDlgProc, (LPARAM) 0);
			return 1;
		}

		if (lw == IDC_LINK_KEYFILES_INFO)
		{
			Applink ("keyfiles");
			return 1;
		}

		if (lw == IDC_LINK_KEYFILES_EXTENSIONS_WARNING)
		{
			Applink ("keyfilesextensions");
			return 1;
		}

		if (lw == IDOK)
		{
			param->EnableKeyFiles = IsButtonChecked (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE));

#ifdef TCMOUNT
			if (IsWindowVisible (GetDlgItem (hwndDlg, IDC_KEYFILES_TRY_EMPTY_PASSWORD)))
			{
				bTryEmptyPasswordWhenKeyfileUsed = IsButtonChecked (GetDlgItem (hwndDlg, IDC_KEYFILES_TRY_EMPTY_PASSWORD));

				if (UsePreferences)
				{
					WaitCursor ();
					SaveSettings (hwndDlg);
					NormalCursor ();
				}
			}
#endif
			EndDialog (hwndDlg, IDOK);
			return 1;
		}

		if (lw == IDCANCEL)
		{
			KeyFileRemoveAll (&param->FirstKeyFile);
			*param = origParam;

			EndDialog (hwndDlg, IDCLOSE);
			return 1;
		}
		break;

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;

			int i = 0, count = DragQueryFile (hdrop, 0xFFFFFFFF, NULL, 0);

			while (count-- > 0)
			{
				KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
				if (kf)
				{
					DragQueryFile (hdrop, i++, kf->FileName, ARRAYSIZE (kf->FileName));
					param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
					LoadKeyList (hwndDlg, param->FirstKeyFile);
				}
			}

			DragFinish (hdrop);
		}
		return 1;

	case WM_NOTIFY:
		if (((LPNMHDR) lParam)->code == LVN_ITEMCHANGED)
		{
			EnableWindow (GetDlgItem (hwndDlg, IDC_KEYREMOVE),
				ListView_GetNextItem (GetDlgItem (hwndDlg, IDC_KEYLIST), -1, LVIS_SELECTED) != -1);
			return 1;
		}
		break;

	case WM_CLOSE:
		KeyFileRemoveAll (&param->FirstKeyFile);
		*param = origParam;

		EndDialog (hwndDlg, IDCLOSE);
		return 1;

		break;

	}

	return 0;
}


#define IDM_KEYFILES_POPUP_ADD_FILES		9001
#define IDM_KEYFILES_POPUP_ADD_DIR			9002
#define IDM_KEYFILES_POPUP_ADD_TOKEN_FILES	9003

BOOL KeyfilesPopupMenu (HWND hwndDlg, POINT popupPosition, KeyFilesDlgParam *param)
{
	HMENU popup = CreatePopupMenu ();
	if (!popup)
		return FALSE;
	int sel;
	BOOL status = FALSE;

	AppendMenuW (popup, MF_STRING, IDM_KEYFILES_POPUP_ADD_FILES, GetString ("IDC_KEYADD"));
	AppendMenuW (popup, MF_STRING, IDM_KEYFILES_POPUP_ADD_DIR, GetString ("IDC_ADD_KEYFILE_PATH"));
	AppendMenuW (popup, MF_STRING, IDM_KEYFILES_POPUP_ADD_TOKEN_FILES, GetString ("IDC_TOKEN_FILES_ADD"));

	sel = TrackPopupMenu (popup, TPM_RETURNCMD | TPM_LEFTBUTTON, popupPosition.x, popupPosition.y, 0, hwndDlg, NULL);

	switch (sel)
	{
	case IDM_KEYFILES_POPUP_ADD_FILES:
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
			if (kf)
			{
				std::vector<std::wstring> filesList;
				if (SelectMultipleFiles (hwndDlg, "SELECT_KEYFILE", bHistory, filesList))
				{
					for	(std::vector<std::wstring>::const_iterator it = filesList.begin();
							it != filesList.end();
							++it)
					{
						StringCbCopyW (kf->FileName, sizeof (kf->FileName), it->c_str());
						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						kf = (KeyFile *) malloc (sizeof (KeyFile));
                        if (!kf)
                        {
                            Warning ("ERR_MEM_ALLOC", hwndDlg);
                            break;
                        }
					}

					param->EnableKeyFiles = TRUE;
					status = TRUE;
				}

                if (kf)
				    free (kf);
			}
		}
		break;

	case IDM_KEYFILES_POPUP_ADD_DIR:
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
			if (kf)
			{
				if (BrowseDirectories (hwndDlg,"SELECT_KEYFILE_PATH", kf->FileName, NULL))
				{
					param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
					param->EnableKeyFiles = TRUE;
					status = TRUE;
				}
				else
				{
					free (kf);
				}
			}
            else
            {
                Warning ("ERR_MEM_ALLOC", hwndDlg);
            }
		}
		break;

	case IDM_KEYFILES_POPUP_ADD_TOKEN_FILES:
		{
			list <TokenKeyfilePath> selectedTokenKeyfiles;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_KEYFILES), hwndDlg, (DLGPROC) SecurityTokenKeyfileDlgProc, (LPARAM) &selectedTokenKeyfiles) == IDOK)
			{
				foreach (const TokenKeyfilePath &keyPath, selectedTokenKeyfiles)
				{
					KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						StringCbCopyW (kf->FileName, sizeof (kf->FileName), wstring (keyPath).c_str());

						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						param->EnableKeyFiles = TRUE;
						status = TRUE;
					}
                    else
                    {
                        Warning ("ERR_MEM_ALLOC", hwndDlg);
                        break;
                    }
				}
			}
		}
		break;
	}

	DestroyMenu (popup);
	return status;
}
