/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

/* Adapted for VeraCrypt */

#include <stdlib.h>
#include <STRING.H>

#include "blake2.h"

#pragma optimize ("tl", on)

#pragma intrinsic(_lrotr)
#pragma intrinsic( memcpy )
#pragma intrinsic( memset )

static const uint32 blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8 blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static void blake2s_set_lastnode( blake2s_state *S )
{
  S->f[1] = (uint32)-1;
}

/* Some helper functions, not necessarily useful */
static int blake2s_is_lastblock( const blake2s_state *S )
{
  return S->f[0] != 0;
}

static void blake2s_set_lastblock( blake2s_state *S )
{
  if( S->last_node ) blake2s_set_lastnode( S );

  S->f[0] = (uint32)-1;
}

static void blake2s_increment_counter( blake2s_state *S, const uint32 inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void blake2s_init0( blake2s_state *S )
{
  size_t i;
  memset( S, 0, sizeof( blake2s_state ) );

  for( i = 0; i < 8; ++i ) S->h[i] = blake2s_IV[i];
}

/* init2 xors IV with input parameter block */
void blake2s_init_param( blake2s_state *S, const blake2s_param *P )
{
  const unsigned char *p = ( const unsigned char * )( P );
  size_t i;
  uint32 w;

  blake2s_init0( S );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
  {
	memcpy (&w, &p[i * 4], sizeof (w));
    S->h[i] ^= w;
  }

  S->outlen = P->digest_length;
}


/* Sequential blake2s initialization */
void blake2s_init( blake2s_state *S )
{
  blake2s_param P[1];

  P->digest_length = 32;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  P->leaf_length = 0;
  P->node_offset = 0;
  P->xof_length = 0;
  P->node_depth    = 0;
  P->inner_length  = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  blake2s_init_param( S, P );
}

#ifndef TC_MINIMIZE_CODE_SIZE
#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = _lrotr(d ^ a, 16);                  \
    c = c + d;                              \
    b = _lrotr(b ^ c, 12);                  \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = _lrotr(d ^ a, 8);                   \
    c = c + d;                              \
    b = _lrotr(b ^ c, 7);                   \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)
#else
#define G_BASE(r,i,a,b,c,d)                      \
  do {                                      \
    v[a] = v[a] + v[b] + m[blake2s_sigma[r][2*i+0]]; \
    v[d] = _lrotr(v[d] ^ v[a], 16);                  \
    v[c] = v[c] + v[d];                              \
    v[b] = _lrotr(v[b] ^ v[c], 12);                  \
    v[a] = v[a] + v[b] + m[blake2s_sigma[r][2*i+1]]; \
    v[d] = _lrotr(v[d] ^ v[a], 8);                   \
    v[c] = v[c] + v[d];                              \
    v[b] = _lrotr(v[b] ^ v[c], 7);                   \
  } while(0)

static void G(unsigned char r, unsigned char i, uint32* m, uint32* v, unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
	G_BASE(r,i,a,b,c,d);
}

static void round_base (unsigned char r, uint32* m, uint32* v)
{
	G(r,0,m,v, 0, 4, 8, 12);
	G(r,1,m,v, 1, 5, 9,13);
	G(r,2,m,v, 2, 6,10,14);
	G(r,3,m,v, 3, 7,11,15);
	G(r,4,m,v, 0, 5,10,15);
	G(r,5,m,v, 1, 6,11,12);
	G(r,6,m,v, 2, 7, 8,13);
	G(r,7,m,v, 3, 4, 9,14);
}

#define ROUND(r)  round_base(r,m,v)
#endif
static void blake2s_compress( blake2s_state *S, const uint8 in[BLAKE2S_BLOCKBYTES] )
{
  uint32 m[16];
  uint32 v[16];
  int i;

  for( i = 0; i < 16; ++i ) {
	memcpy (&m[i], in + i * sizeof( m[i] ), sizeof(uint32));
  }

  for( i = 0; i < 8; ++i ) {
    v[i] = S->h[i];
  }

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );

  for( i = 0; i < 8; ++i ) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

void blake2s_update( blake2s_state *S, const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  if( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;
    if( inlen > fill )
    {
      S->buflen = 0;
      memcpy( S->buf + left, in, fill ); /* Fill buffer */
      blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );
      blake2s_compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > BLAKE2S_BLOCKBYTES) {
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
        blake2s_compress( S, in );
        in += BLAKE2S_BLOCKBYTES;
        inlen -= BLAKE2S_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
}

int blake2s_final( blake2s_state *S, unsigned char *out )
{
  int i;

  if( blake2s_is_lastblock( S ) )
    return -1;

  blake2s_increment_counter( S, ( uint32 )S->buflen );
  blake2s_set_lastblock( S );
  memset( S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen ); /* Padding */
  blake2s_compress( S, S->buf );

  for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    memcpy( out + sizeof( S->h[i] ) * i, &S->h[i], sizeof(uint32) );

  return 0;
}

#if defined(SUPERCOP)
int crypto_hash( unsigned char *out, unsigned char *in, unsigned long long inlen )
{
  return blake2s( out, BLAKE2S_OUTBYTES, in, inlen, NULL, 0 );
}
#endif

#if defined(BLAKE2S_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main( void )
{
  uint8 key[BLAKE2S_KEYBYTES];
  uint8 buf[BLAKE2_KAT_LENGTH];
  size_t i, step;

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
    key[i] = ( uint8 )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
    buf[i] = ( uint8 )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    uint8 hash[BLAKE2S_OUTBYTES];
    blake2s( hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES );

    if( 0 != memcmp( hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8 hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8 * p = buf;
      size_t mlen = i;
      int err = 0;

      if( (err = blake2s_init_key(&S, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = blake2s_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = blake2s_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = blake2s_final(&S, hash, BLAKE2S_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
#endif
