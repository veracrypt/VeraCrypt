/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned char ks_tmp[MAX_EXPANDED_KEY]; 

void CipherInit2(int cipher, void* key, void* ks, int key_len);
BOOL test_hmac_sha512 (void);
BOOL test_hmac_sha1 (void);
BOOL test_hmac_ripemd160 (void);
BOOL test_hmac_whirlpool (void);
BOOL test_pkcs5 (void);
BOOL TestSectorBufEncryption ();
BOOL TestLegacySectorBufEncryption ();
BOOL AutoTestAlgorithms (void);

#ifdef __cplusplus
}
#endif
