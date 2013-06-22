/* Deprecated/legacy */


#ifndef TC_HEADER_Crypto_Blowfish
#define TC_HEADER_Crypto_Blowfish

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct BF_KEY_STRUCT
{
	unsigned __int32 pbox[18];
	unsigned __int32 pbox_dec[18];
	unsigned __int32 sbox[4*256];
} BF_KEY;

void BlowfishSetKey (BF_KEY *key, int keylength, unsigned char *key_string);
void BlowfishEncryptLE (unsigned char *in, unsigned char *out, BF_KEY *ks, int encrypt);

#ifdef  __cplusplus
}
#endif

#endif // TC_HEADER_Crypto_Blowfish
