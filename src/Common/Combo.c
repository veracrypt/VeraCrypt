/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include "Combo.h"
#include "Dlgcode.h"
#include "Xml.h"

#include <time.h>

#define SIZEOF_MRU_LIST 20

void AddComboItem (HWND hComboBox, const wchar_t *lpszFileName, BOOL saveHistory)
{
	LPARAM nIndex;

	if (!saveHistory)
	{
		SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
		SetWindowText (hComboBox, lpszFileName);
		return;
	}

	nIndex = SendMessage (hComboBox, CB_FINDSTRINGEXACT, (WPARAM) - 1, (LPARAM) & lpszFileName[0]);

	if (nIndex == CB_ERR && *lpszFileName)
	{
		time_t lTime = time (NULL);
		nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) & lpszFileName[0]);
		if (nIndex != CB_ERR)
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (LPARAM) lTime);
	}

	if (nIndex != CB_ERR && *lpszFileName)
		nIndex = SendMessage (hComboBox, CB_SETCURSEL, nIndex, 0);

	if (*lpszFileName == 0)
	{
		SendMessage (hComboBox, CB_SETCURSEL, (WPARAM) - 1, 0);
	}
}


LPARAM MoveEditToCombo (HWND hComboBox, BOOL saveHistory)
{
	wchar_t szTmp[TC_MAX_PATH] = {0};

	if (!saveHistory)
	{
		GetWindowText (hComboBox, szTmp, ARRAYSIZE (szTmp));
		SendMessage (hComboBox, CB_RESETCONTENT, 0, 0);
		SetWindowText (hComboBox, szTmp);
		return 0;
	}

	GetWindowText (hComboBox, szTmp, ARRAYSIZE (szTmp));

	if (wcslen (szTmp) > 0)
	{
		LPARAM nIndex = SendMessage (hComboBox, CB_FINDSTRINGEXACT, (WPARAM) - 1,
					     (LPARAM) & szTmp[0]);
		if (nIndex == CB_ERR)
		{
			time_t lTime = time (NULL);
			nIndex = SendMessage (hComboBox, CB_ADDSTRING, 0, (LPARAM) & szTmp[0]);
			if (nIndex != CB_ERR)
				SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (DWORD) lTime);
		}
		else
		{
			time_t lTime = time (NULL);
			SendMessage (hComboBox, CB_SETITEMDATA, nIndex, (DWORD) lTime);
		}

		return nIndex;
	}

	return SendMessage (hComboBox, CB_GETCURSEL, 0, 0);
}

int GetOrderComboIdx (HWND hComboBox, int *nIdxList, int nElems)
{
	int x = (int) SendMessage (hComboBox, CB_GETCOUNT, 0, 0);
	if (x != CB_ERR)
	{
		int i, nHighIdx = CB_ERR;
		time_t lHighTime = -1;

		for (i = 0; i < x; i++)
		{
			time_t lTime = SendMessage (hComboBox, CB_GETITEMDATA, (WPARAM) i, 0);
			if (lTime > lHighTime)
			{
				int n;
				for (n = 0; n < nElems; n++)
					if (nIdxList[n] == i)
						break;
				if (n == nElems)
				{
					lHighTime = lTime;
					nHighIdx = i;
				}
			}
		}

		return nHighIdx;
	}

	return CB_ERR;
}

LPARAM UpdateComboOrder (HWND hComboBox)
{
	LPARAM nIndex;

	nIndex = SendMessage (hComboBox, CB_GETCURSEL, 0, 0);

	if (nIndex != CB_ERR)
	{
		time_t lTime = time (NULL);
		nIndex = SendMessage (hComboBox, CB_SETITEMDATA, (WPARAM) nIndex,
				      (LPARAM) lTime);
	}

	return nIndex;
}

void LoadCombo (HWND hComboBox, BOOL bEnabled, BOOL bOnlyCheckModified, BOOL *pbModified)
{
	DWORD size;
	char *history = LoadFile (GetConfigPath (TC_APPD_FILENAME_HISTORY), &size);
	char *xml = history;
	char volume[MAX_PATH];
	int i, nComboIdx[SIZEOF_MRU_LIST] = {0};
	int count = (int) SendMessage (hComboBox, CB_GETCOUNT, 0, 0);

	if (xml == NULL)
	{
		// No history XML file but history is enabled
		if (bEnabled && pbModified)
		*pbModified = TRUE;
		return;
	}

	if (!bEnabled && bOnlyCheckModified)
	{
		// History is disable but there is a history XML file
		if (pbModified)
			*pbModified = TRUE;
		free (history);
		return;
	}


	/* combo list part:- get mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
		nComboIdx[i] = GetOrderComboIdx (hComboBox, &nComboIdx[0], i);

	i = 0;
	while (xml = XmlFindElement (xml, "volume"))
	{
		wchar_t szTmp[MAX_PATH] = { 0 };
		wchar_t wszVolume[MAX_PATH] = {0};

		if (i < count)
		{
			if (SendMessage (hComboBox, CB_GETLBTEXTLEN, nComboIdx[i], 0) < ARRAYSIZE (szTmp))
				SendMessage (hComboBox, CB_GETLBTEXT, nComboIdx[i], (LPARAM) & szTmp[0]);
		}

		XmlGetNodeText (xml, volume, sizeof (volume));
		if (0 == MultiByteToWideChar (CP_UTF8, 0, volume, -1, wszVolume, MAX_PATH))
			wszVolume [0] = 0;
		if (!bOnlyCheckModified)
			AddComboItem (hComboBox, wszVolume, TRUE);

		if (pbModified && wcscmp (wszVolume, szTmp))
			*pbModified = TRUE;

		xml++;
		i++;
	}

	if (pbModified && (i != count))
		*pbModified = TRUE;

	if (!bOnlyCheckModified)
		SendMessage (hComboBox, CB_SETCURSEL, 0, 0);

	free (history);
}

void DumpCombo (HWND hComboBox, int bClear)
{
	FILE *f;
	int i, nComboIdx[SIZEOF_MRU_LIST] = {0};

	if (bClear)
	{
		DeleteFile (GetConfigPath (TC_APPD_FILENAME_HISTORY));
		return;
	}

	f = _wfopen (GetConfigPath (TC_APPD_FILENAME_HISTORY), L"w,ccs=UTF-8");
	if (f == NULL) return;

	XmlWriteHeader (f);
	fputws (L"\n\t<history>", f);

	/* combo list part:- get mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
		nComboIdx[i] = GetOrderComboIdx (hComboBox, &nComboIdx[0], i);

	/* combo list part:- write out mru items */
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		wchar_t szTmp[MAX_PATH] = { 0 };

		if (SendMessage (hComboBox, CB_GETLBTEXTLEN, nComboIdx[i], 0) < ARRAYSIZE (szTmp))
			SendMessage (hComboBox, CB_GETLBTEXT, nComboIdx[i], (LPARAM) & szTmp[0]);

		if (szTmp[0] != 0)
		{
			wchar_t q[MAX_PATH * 2] = { 0 };
			XmlQuoteTextW (szTmp, q, ARRAYSIZE (q));

			fwprintf (f, L"\n\t\t<volume>%s</volume>", q);
		}
	}

	fputws (L"\n\t</history>", f);
	XmlWriteFooter (f);
	fclose (f);
}

void ClearCombo (HWND hComboBox)
{
	int i;
	for (i = 0; i < SIZEOF_MRU_LIST; i++)
	{
		SendMessage (hComboBox, CB_DELETESTRING, 0, 0);
	}
}

int IsComboEmpty (HWND hComboBox)
{
	return SendMessage (hComboBox, CB_GETCOUNT, 0, 0) < 1;
}
