/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <malloc.h>
#include <ctype.h>
#include "Cmdline.h"

#include "Resource.h"
#include "Crypto.h"
#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"

/* Except in response to the WM_INITDIALOG message, the dialog box procedure
   should return nonzero if it processes the message, and zero if it does
   not. - see DialogProc */
BOOL CALLBACK CommandHelpDlgProc (HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (lParam);		/* remove warning */
	if (wParam);		/* remove warning */

	switch (msg)
	{
	case WM_INITDIALOG:
		{
		char * tmp = err_malloc(8192);
		char tmp2[MAX_PATH * 2];
		argumentspec *as;
		int i;

		LocalizeDialog (hwndDlg, "IDD_COMMANDHELP_DLG");

		as = (argumentspec*) lParam;

		*tmp = 0;

		strcpy (tmp, "Command line options:\n\n");
		for (i = 0; i < as->arg_cnt; i ++)
		{
			if (!as->args[i].Internal)
			{
				sprintf(tmp2, "%s\t%s\n", as->args[i].short_name, as->args[i].long_name);
				strcat(tmp,tmp2);
			}
		}

		SetWindowText (GetDlgItem (hwndDlg, IDC_COMMANDHELP_TEXT), (char*) tmp);
		
		TCfree(tmp);
		return 1;
		}

	case WM_COMMAND:
		EndDialog (hwndDlg, IDOK);
		return 1;
	case WM_CLOSE:
		EndDialog (hwndDlg, 0);
		return 1;
	}

	return 0;
}

int Win32CommandLine (char *lpszCommandLine, char ***lpszArgs)
{
	int argumentCount;
	int i;

	LPWSTR *arguments = CommandLineToArgvW (GetCommandLineW(), &argumentCount);
	if (!arguments)
	{
		handleWin32Error (NULL);
		return 0;
	}

	--argumentCount;
	if (argumentCount < 1)
	{
		LocalFree (arguments);
		return 0;
	}

	*lpszArgs = malloc (sizeof (char *) * argumentCount);
	if (!*lpszArgs)
		AbortProcess ("OUTOFMEMORY");

	for (i = 0; i < argumentCount; ++i)
	{
		size_t argLen = wcslen (arguments[i + 1]);

		char *arg = malloc (argLen + 1);
		if (!arg)
			AbortProcess ("OUTOFMEMORY");

		if (argLen > 0)
		{
			int len = WideCharToMultiByte (CP_ACP, 0, arguments[i + 1], -1, arg, argLen + 1, NULL, NULL);
			if (len == 0)
			{
				handleWin32Error (NULL);
				AbortProcessSilent();
			}
		}
		else
			arg[0] = 0;

		(*lpszArgs)[i] = arg;
	}

	LocalFree (arguments);
	return argumentCount;
}

int GetArgSepPosOffset (char *lpszArgument)
{
	if (lpszArgument[0] == '/')
		return 1;

	return 0;
}

int GetArgumentID (argumentspec *as, char *lpszArgument, int *nArgPos)
{
	char szTmp[MAX_PATH * 2];
	int i;

	i = strlen (lpszArgument);
	szTmp[i] = 0;
	while (--i >= 0)
	{
		szTmp[i] = (char) tolower (lpszArgument[i]);
	}

	for (i = 0; i < as->arg_cnt; i++)
	{
		size_t k;

		k = strlen (as->args[i].long_name);
		if (memcmp (as->args[i].long_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < as->arg_cnt; x++)
			{
				size_t m;

				m = strlen (as->args[x].long_name);
				if (memcmp (as->args[x].long_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == as->arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return as->args[i].Id;
			}
		}
	}

	for (i = 0; i < as->arg_cnt; i++)
	{
		size_t k;

		if (as->args[i].short_name[0] == 0)
			continue;

		k = strlen (as->args[i].short_name);
		if (memcmp (as->args[i].short_name, szTmp, k * sizeof (char)) == 0)
		{
			int x;
			for (x = i + 1; x < as->arg_cnt; x++)
			{
				size_t m;

				if (as->args[x].short_name[0] == 0)
					continue;

				m = strlen (as->args[x].short_name);
				if (memcmp (as->args[x].short_name, szTmp, m * sizeof (char)) == 0)
				{
					break;
				}
			}

			if (x == as->arg_cnt)
			{
				if (strlen (lpszArgument) != k)
					*nArgPos = k;
				else
					*nArgPos = 0;
				return as->args[i].Id;
			}
		}
	}


	return -1;
}

int GetArgumentValue (char **lpszCommandLineArgs, int nArgPos, int *nArgIdx,
		  int nNoCommandLineArgs, char *lpszValue, int nValueSize)
{
	*lpszValue = 0;

	if (nArgPos)
	{
		/* Handles the case of no space between parameter code and
		   value */
		strncpy (lpszValue, &lpszCommandLineArgs[*nArgIdx][nArgPos], nValueSize);
		lpszValue[nValueSize - 1] = 0;
		return HAS_ARGUMENT;
	}
	else if (*nArgIdx + 1 < nNoCommandLineArgs)
	{
		int x = GetArgSepPosOffset (lpszCommandLineArgs[*nArgIdx + 1]);
		if (x == 0)
		{
			/* Handles the case of space between parameter code
			   and value */
			strncpy (lpszValue, &lpszCommandLineArgs[*nArgIdx + 1][x], nValueSize);
			lpszValue[nValueSize - 1] = 0;
			(*nArgIdx)++;
			return HAS_ARGUMENT;
		}
	}

	return HAS_NO_ARGUMENT;
}
