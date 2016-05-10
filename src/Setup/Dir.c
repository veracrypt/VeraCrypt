/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <Strsafe.h>

#include "Dir.h"

/* create full directory tree. returns 0 for success, -1 if failure */
int
mkfulldir (wchar_t *oriPath, BOOL bCheckonly)
{
	struct _stat st;
	wchar_t *uniq_file;
	wchar_t path [TC_MAX_PATH];

	StringCbCopyW (path, TC_MAX_PATH, oriPath);

	if (wcslen (path) == 3 && path[1] == L':')
		goto is_root;	/* keep final slash in root if present */

	/* strip final forward or backslash if we have one! */
	uniq_file = wcsrchr (path, L'\\');
	if (uniq_file && uniq_file[1] == L'\0')
		uniq_file[0] = L'\0';
	else
	{
		uniq_file = wcsrchr (path, L'/');
		if (uniq_file && uniq_file[1] == L'\0')
			uniq_file[0] = L'\0';
	}

      is_root:
	if (bCheckonly)
		return _wstat (path, &st);

	if (_wstat (path, &st))
		return mkfulldir_internal (path);
	else
		return 0;
}


int
mkfulldir_internal (wchar_t *path)
{
	wchar_t *token;
	struct _stat st;
	static wchar_t tokpath[_MAX_PATH];
	static wchar_t trail[_MAX_PATH];

	StringCbCopyW (tokpath, _MAX_PATH, path);
	trail[0] = L'\0';

	token = wcstok (tokpath, L"\\/");

	if (tokpath[0] == L'\\' && tokpath[1] == L'\\')
	{			/* unc */
		trail[0] = tokpath[0];
		trail[1] = tokpath[1];
		trail[2] = L'\0';
		if (token)
		{
			StringCbCatW (trail, _MAX_PATH, token);
			StringCbCatW (trail, _MAX_PATH, L"\\");
			token = wcstok (NULL, L"\\/");
			if (token)
			{		/* get share name */
				StringCbCatW (trail, _MAX_PATH, token);
				StringCbCatW (trail, _MAX_PATH, L"\\");
			}
			token = wcstok (NULL, L"\\/");
		}
	}

	if (tokpath[1] == L':')
	{			/* drive letter */
		StringCbCatW (trail, _MAX_PATH, tokpath);
		StringCbCatW (trail, _MAX_PATH, L"\\");
		token = wcstok (NULL, L"\\/");
	}

	while (token != NULL)
	{
		int x;
		StringCbCatW (trail, _MAX_PATH, token);
		x = _wmkdir (trail);
		StringCbCatW (trail, _MAX_PATH, L"\\");
		token = wcstok (NULL, L"\\/");
	}

	return _wstat (path, &st);
}
