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

void AddComboItem (HWND hComboBox, const wchar_t *lpszFileName, BOOL saveHistory);
LPARAM MoveEditToCombo (HWND hComboBox, BOOL saveHistory);
int GetOrderComboIdx ( HWND hComboBox , int *nIdxList , int nElems );
LPARAM UpdateComboOrder ( HWND hComboBox );
void LoadCombo (HWND hComboBox, BOOL bEnabled, BOOL bOnlyCheckModified, BOOL *pbModified);
void DumpCombo ( HWND hComboBox , int bClear );
void ClearCombo (HWND hComboBox);
int IsComboEmpty (HWND hComboBox);

#ifdef __cplusplus
}
#endif
