/* Deprecated/legacy */


#ifndef HEADER_CAST_H
#define HEADER_CAST_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct CAST_KEY_STRUCT
{
	unsigned __int32 K[32];
} CAST_KEY;

void Cast5Decrypt (const byte *inBlock, byte *outBlock, CAST_KEY *key);
void Cast5Encrypt (const byte *inBlock, byte *outBlock, CAST_KEY *key);
void Cast5SetKey (CAST_KEY *key, unsigned int keylength, const byte *userKey);

#ifdef  __cplusplus
}
#endif

#endif
