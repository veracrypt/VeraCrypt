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

#ifndef BLAKE2_H
#define BLAKE2_H
#include "Common/Tcdefs.h"

#if defined(_MSC_VER)
#ifdef TC_WINDOWS_BOOT
#define BLAKE2_PACKED(x) x
#else
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#endif

#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

  enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

  typedef struct blake2s_state__
  {
    uint32 h[8];
    uint32 t[2];
    uint32 f[2];
    uint8  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8  last_node;
  } blake2s_state;

#ifdef TC_WINDOWS_BOOT
  #pragma pack(1)
#endif

  BLAKE2_PACKED(struct blake2s_param__
  {
    uint8  digest_length; /* 1 */
    uint8  key_length;    /* 2 */
    uint8  fanout;        /* 3 */
    uint8  depth;         /* 4 */
    uint32 leaf_length;   /* 8 */
    uint32 node_offset;  /* 12 */
    uint16 xof_length;    /* 14 */
    uint8  node_depth;    /* 15 */
    uint8  inner_length;  /* 16 */
    /* uint8  reserved[0]; */
    uint8  salt[BLAKE2S_SALTBYTES]; /* 24 */
    uint8  personal[BLAKE2S_PERSONALBYTES];  /* 32 */
  });

#ifdef TC_WINDOWS_BOOT
  #pragma pack()
#endif

  typedef struct blake2s_param__ blake2s_param;


  /* Padded structs result in a compile-time error */
  enum {
    BLAKE2_DUMMY_1 = 1/(int)(sizeof(blake2s_param) == BLAKE2S_OUTBYTES)
  };

  /* Streaming API */
  void blake2s_init( blake2s_state *S );
  void blake2s_init_param( blake2s_state *S, const blake2s_param *P );
  void blake2s_update( blake2s_state *S, const void *in, size_t inlen );
  int blake2s_final( blake2s_state *S, unsigned char *out );

  /* Simple API */
  int blake2s( void *out, const void *in, size_t inlen );

#if defined(__cplusplus)
}
#endif

#endif
