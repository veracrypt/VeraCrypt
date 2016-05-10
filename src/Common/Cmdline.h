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

#ifdef __cplusplus
extern "C" {
#endif

#define HAS_ARGUMENT	1
#define HAS_NO_ARGUMENT !HAS_ARGUMENT

typedef struct argument_t
{
	int Id;
	wchar_t long_name[32];
	wchar_t short_name[8];
	BOOL Internal;
} argument;

typedef struct argumentspec_t
{
	argument *args;
	int		 arg_cnt;
} argumentspec;

BOOL CALLBACK CommandHelpDlgProc ( HWND hwndDlg , UINT msg , WPARAM wParam , LPARAM lParam );
int Win32CommandLine ( wchar_t ***lpszArgs );
int GetArgSepPosOffset ( wchar_t *lpszArgument );
int GetArgumentID ( argumentspec *as , wchar_t *lpszArgument );
int GetArgumentValue ( wchar_t **lpszCommandLineArgs , int *nArgIdx , int nNoCommandLineArgs , wchar_t *lpszValue , int nValueSize );

#ifdef __cplusplus
}
#endif
