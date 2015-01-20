/*

Most of the source code contained in this file is taken from the source code of
TrueCrypt 7.0a, which is governed by the TrueCrypt License 3.0 that can be found
in the file 'License.txt' in the folder 'TrueCrypt-License'.

Modifications and additions to the original source code (contained in this file)
and all other portions of this file are Copyright (c) 2009-2010 by Kih-Oskh or
Copyright (c) 2012-2013 Josef Schneider <josef@netpage.dk>

-------------------------------------------------------------------------------

Original legal notice of the TrueCrypt source:

 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_InitDataArea
#define TC_HEADER_InitDataArea

#ifdef __cplusplus
extern "C" {
#endif

void SetFormatSectorSize (uint32 sector_size);
int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, __int64 num_sectors, void *dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);
BOOL WriteSector ( void *dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , PCRYPTO_INFO cryptoInfo );
BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo);
BOOL StartFormatWriteThread ();
void StopFormatWriteThread ();


#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_InitDataArea