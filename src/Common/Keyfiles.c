/*
 Copyright (c) 2005-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
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
#include "Common/resource.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"

#include <Strsafe.h>

using namespace VeraCrypt;

#define stat _stat
#define S_IFDIR _S_IFDIR


BOOL HiddenFilesPresentInKeyfilePath = FALSE;


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
		StringCbCopyA (clone->FileName, sizeof(clone->FileName), keyFile->FileName);
		clone->Next = NULL;
	}
	return clone;
}


KeyFile *KeyFileCloneAll (KeyFile *firstKeyFile)
{
	KeyFile *cloneFirstKeyFile = KeyFileClone (firstKeyFile);
	KeyFile *kf;

	if (firstKeyFile == NULL) return NULL;
	kf = firstKeyFile->Next;
	while (kf != NULL)
	{
		KeyFileAdd (cloneFirstKeyFile, KeyFileClone (kf));
		kf = kf->Next;
	}

	return cloneFirstKeyFile;
}


static BOOL KeyFileProcess (unsigned __int8 *keyPool, KeyFile *keyFile)
{
	FILE *f;
	unsigned __int8 buffer[64 * 1024];
	unsigned __int32 crc = 0xffffffff;
	int writePos = 0;
	size_t bytesRead, totalRead = 0;
	int status = TRUE;

	HANDLE src;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;

	BOOL bTimeStampValid = FALSE;

	/* Remember the last access time of the keyfile. It will be preserved in order to prevent
	an adversary from determining which file may have been used as keyfile. */
	src = CreateFile (keyFile->FileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (src != INVALID_HANDLE_VALUE)
	{
		if (GetFileTime ((HANDLE) src, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime))
			bTimeStampValid = TRUE;
	}

	finally_do_arg (HANDLE, src,
	{
		if (finally_arg != INVALID_HANDLE_VALUE)
			CloseHandle (finally_arg);
	});

	f = fopen (keyFile->FileName, "rb");
	if (f == NULL) return FALSE;

	while ((bytesRead = fread (buffer, 1, sizeof (buffer), f)) > 0)
	{
		size_t i;

		if (ferror (f))
		{
			status = FALSE;
			goto close;
		}

		for (i = 0; i < bytesRead; i++)
		{
			crc = UPDC32 (buffer[i], crc);

			keyPool[writePos++] += (unsigned __int8) (crc >> 24);
			keyPool[writePos++] += (unsigned __int8) (crc >> 16);
			keyPool[writePos++] += (unsigned __int8) (crc >> 8);
			keyPool[writePos++] += (unsigned __int8) crc;

			if (writePos >= KEYFILE_POOL_SIZE)
				writePos = 0;

			if (++totalRead >= KEYFILE_MAX_READ_LEN)
				goto close;
		}
	}

	if (ferror (f))
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
	fclose (f);

	if (bTimeStampValid && !IsFileOnReadOnlyFilesystem (keyFile->FileName))
	{
		// Restore the keyfile timestamp
		SetFileTime (src, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);
	}

	SetLastError (err);
	return status;
}


BOOL KeyFilesApply (Password *password, KeyFile *firstKeyFile)
{
	BOOL status = TRUE;
	KeyFile kfSubStruct;
	KeyFile *kf;
	KeyFile *kfSub = &kfSubStruct;
	static unsigned __int8 keyPool [KEYFILE_POOL_SIZE];
	size_t i;
	struct stat statStruct;
	char searchPath [TC_MAX_PATH*2];
	struct _finddata_t fBuf;
	intptr_t searchHandle;

	HiddenFilesPresentInKeyfilePath = FALSE;

	if (firstKeyFile == NULL) return TRUE;

	VirtualLock (keyPool, sizeof (keyPool));
	memset (keyPool, 0, sizeof (keyPool));

	for (kf = firstKeyFile; kf != NULL; kf = kf->Next)
	{
		// Determine whether it's a security token path
		try
		{
			if (SecurityToken::IsKeyfilePathValid (SingleStringToWide (kf->FileName)))
			{
				// Apply security token keyfile
				vector <byte> keyfileData;
				SecurityToken::GetKeyfileData (SecurityTokenKeyfile (SingleStringToWide (kf->FileName)), keyfileData);

				if (keyfileData.empty())
				{
					SetLastError (ERROR_HANDLE_EOF); 
					handleWin32Error (MainDlg);
					Error ("ERR_PROCESS_KEYFILE");
					status = FALSE;
					continue;
				}

				unsigned __int32 crc = 0xffffffff;
				int writePos = 0;
				size_t totalRead = 0;

				for (size_t i = 0; i < keyfileData.size(); i++)
				{
					crc = UPDC32 (keyfileData[i], crc);

					keyPool[writePos++] += (unsigned __int8) (crc >> 24);
					keyPool[writePos++] += (unsigned __int8) (crc >> 16);
					keyPool[writePos++] += (unsigned __int8) (crc >> 8);
					keyPool[writePos++] += (unsigned __int8) crc;

					if (writePos >= KEYFILE_POOL_SIZE)
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
		if (stat (kf->FileName, &statStruct) != 0)
		{
			handleWin32Error (MainDlg);
			Error ("ERR_PROCESS_KEYFILE");
			status = FALSE;
			continue;
		}

		if (statStruct.st_mode & S_IFDIR)		// If it's a directory
		{
			/* Find and process all keyfiles in the directory */
			int keyfileCount = 0;

			StringCbPrintfA (searchPath, sizeof (searchPath), "%s\\*.*", kf->FileName);
			if ((searchHandle = _findfirst (searchPath, &fBuf)) == -1)
			{
				handleWin32Error (MainDlg);
				Error ("ERR_PROCESS_KEYFILE_PATH");
				status = FALSE;
				continue;
			}

			do
			{
				WIN32_FILE_ATTRIBUTE_DATA fileAttributes;

				StringCbPrintfA (kfSub->FileName, sizeof(kfSub->FileName), "%s%c%s", kf->FileName,
					'\\',
					fBuf.name
					);

				// Determine whether it's a path or a file
				if (stat (kfSub->FileName, &statStruct) != 0)
				{
					handleWin32Error (MainDlg);
					Error ("ERR_PROCESS_KEYFILE");
					status = FALSE;
					continue;
				}
				else if (statStruct.st_mode & S_IFDIR)		// If it's a directory
				{
					// Prevent recursive folder scanning
					continue;	 
				}

				// Skip hidden files
				if (GetFileAttributesEx (kfSub->FileName, GetFileExInfoStandard, &fileAttributes)
					&& (fileAttributes.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0)
				{
					HiddenFilesPresentInKeyfilePath = TRUE;
					continue;	 
				}

				++keyfileCount;

				// Apply keyfile to the pool
				if (!KeyFileProcess (keyPool, kfSub))
				{
					handleWin32Error (MainDlg);
					Error ("ERR_PROCESS_KEYFILE");
					status = FALSE;
				}

			} while (_findnext (searchHandle, &fBuf) != -1);
			_findclose (searchHandle);

			burn (&kfSubStruct, sizeof (kfSubStruct));

			if (keyfileCount == 0)
			{
				ErrorDirect ((wstring (GetString ("ERR_KEYFILE_PATH_EMPTY")) + L"\n\n" + SingleStringToWide (kf->FileName)).c_str());
				status = FALSE;
			}
		}
		// Apply keyfile to the pool
		else if (!KeyFileProcess (keyPool, kf))
		{
			handleWin32Error (MainDlg);
			Error ("ERR_PROCESS_KEYFILE");
			status = FALSE;
		}
	}

	/* Mix the keyfile pool contents into the password */

	for (i = 0; i < sizeof (keyPool); i++)
	{
		if (i < password->Length)
			password->Text[i] += keyPool[i];
		else
			password->Text[i] = keyPool[i];
	}

	if (password->Length < (int)sizeof (keyPool))
        password->Length = sizeof (keyPool);

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

			param->FirstKeyFile = KeyFileCloneAll (param->FirstKeyFile);

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

			SetWindowTextW(GetDlgItem(hwndDlg, IDT_KEYFILES_NOTE), GetString ("KEYFILES_NOTE"));

			ToHyperlink (hwndDlg, IDC_LINK_KEYFILES_INFO);
		}
		return 1;

	case WM_COMMAND:

		if (lw == IDC_KEYADD)
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
			if (kf)
			{
				if (SelectMultipleFiles (hwndDlg, "SELECT_KEYFILE", kf->FileName, sizeof(kf->FileName),bHistory))
				{
					do
					{
						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						LoadKeyList (hwndDlg, param->FirstKeyFile);

						kf = (KeyFile *) malloc (sizeof (KeyFile));
					} while (SelectMultipleFilesNext (kf->FileName, sizeof(kf->FileName)));
				}

				free (kf);
			}
			return 1;
		}

		if (lw == IDC_ADD_KEYFILE_PATH)
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));

			if (BrowseDirectories (hwndDlg,"SELECT_KEYFILE_PATH", kf->FileName))
			{
				param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
				LoadKeyList (hwndDlg, param->FirstKeyFile);
			}
			else
			{
				free (kf);
			}
			return 1;
		}

		if (lw == IDC_TOKEN_FILES_ADD)
		{
			list <SecurityTokenKeyfilePath> selectedTokenKeyfiles;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_KEYFILES), hwndDlg, (DLGPROC) SecurityTokenKeyfileDlgProc, (LPARAM) &selectedTokenKeyfiles) == IDOK)
			{
				foreach (const SecurityTokenKeyfilePath &keyPath, selectedTokenKeyfiles)
				{
					KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						strcpy_s (kf->FileName, sizeof (kf->FileName), WideToSingleString (keyPath).c_str());

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
			Applink ("keyfiles", TRUE, "");
		}

		if (lw == IDOK)
		{
			param->EnableKeyFiles = IsButtonChecked (GetDlgItem (hwndDlg, IDC_KEYFILES_ENABLE));
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

	case WM_DROPFILES:
		{
			HDROP hdrop = (HDROP) wParam;

			int i = 0, count = DragQueryFile (hdrop, 0xFFFFFFFF, NULL, 0);

			while (count-- > 0)
			{
				KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
				if (kf)
				{
					DragQueryFile (hdrop, i++, kf->FileName, sizeof (kf->FileName));
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
				if (SelectMultipleFiles (hwndDlg, "SELECT_KEYFILE", kf->FileName, sizeof(kf->FileName),bHistory))
				{
					do
					{
						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						kf = (KeyFile *) malloc (sizeof (KeyFile));
					} while (SelectMultipleFilesNext (kf->FileName, sizeof(kf->FileName)));

					param->EnableKeyFiles = TRUE;
					status = TRUE;
				}

				free (kf);
			}
		}
		break;

	case IDM_KEYFILES_POPUP_ADD_DIR:
		{
			KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
			if (kf)
			{
				if (BrowseDirectories (hwndDlg,"SELECT_KEYFILE_PATH", kf->FileName))
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
		}
		break;

	case IDM_KEYFILES_POPUP_ADD_TOKEN_FILES:
		{
			list <SecurityTokenKeyfilePath> selectedTokenKeyfiles;
			if (DialogBoxParamW (hInst, MAKEINTRESOURCEW (IDD_TOKEN_KEYFILES), hwndDlg, (DLGPROC) SecurityTokenKeyfileDlgProc, (LPARAM) &selectedTokenKeyfiles) == IDOK)
			{
				foreach (const SecurityTokenKeyfilePath &keyPath, selectedTokenKeyfiles)
				{
					KeyFile *kf = (KeyFile *) malloc (sizeof (KeyFile));
					if (kf)
					{
						strcpy_s (kf->FileName, sizeof (kf->FileName), WideToSingleString (keyPath).c_str());

						param->FirstKeyFile = KeyFileAdd (param->FirstKeyFile, kf);
						param->EnableKeyFiles = TRUE;
						status = TRUE;
					}
				}
			}
		}
		break;
	}

	DestroyMenu (popup);
	return status;
}
